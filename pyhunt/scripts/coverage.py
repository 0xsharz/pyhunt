"""The completeness ledger: every enumerated input reaches a disposition.

This is differentiator #1. A scanner that hunts hard and reports only what it
found is indistinguishable, from the outside, from a scanner that silently
skipped half the attack surface — both hand you a list of findings and say
nothing about the inputs they never looked at. The ledger closes that gap: Phase
1 enumerates every attacker-controllable input, and before the report is written
each one must carry a *disposition* — ``covered`` or ``uncovered`` — with
human-readable evidence for why.

``uncovered`` is a first-class, honest answer. The point is not that everything
gets hunted; it is that nothing disappears without being counted.

Ported from ``pyhunt_old/orchestrator.py:82-144``, which held this logic inside
the async, SQLite-backed pipeline driver that the skill-first restructure
deletes. The rules are unchanged; the storage is now the results directory:

* ``inputs.json``            — what Phase 1 enumerated
* ``tasks.json``             — what Phase 1b queued
* ``findings/<id>.json``     — what Phase 2 found
* ``coverage.json``          — what this module writes

Coverage rule, preserved verbatim from the original: an input is **covered** if
some finding's file basename matches the input's location file basename, OR the
input's ``entry_point`` appears in a task's ``scope_hint`` or ``target_files``;
otherwise **uncovered**.

Three subcommands, and the split between them is deliberate:

``classify``
    Fail-OPEN, exactly as ``_reconcile_inputs`` was. A malformed individual
    input record becomes ``uncovered`` with evidence saying the record was
    unreadable, rather than crashing the run. The original reasoning holds: a
    bug in the completeness pass must never destroy an otherwise-good scan.

``reconcile``
    Emits up to ``RECONCILE_CAP`` synthesized hunt tasks, one per uncovered
    input, for the skill to re-queue. Bounded so a target with hundreds of
    unreached inputs cannot fan out without limit. It prints tasks and mutates
    nothing — appending to ``tasks.json`` is the skill's decision.

``assert-complete``
    Fail-CLOSED. This is the release gate, and a gate that swallows errors is
    not a gate. Any unreadable artifact, any enumerated input without a
    disposition in the ledger, exits 2 naming the offenders.

Honesty about the cap: when ``RECONCILE_CAP`` truncates the re-queue,
``coverage.json`` records how many uncovered inputs were dropped beyond it.
A truncated run says so; it never looks complete.

Deliberately pure stdlib and deliberately clock-free — the ledger is a
reproducible function of the results directory alone, so a disputed
``coverage.json`` can be recomputed and diffed byte-for-byte. That also means
this module does not need ``_bootstrap``: the release gate must not be able to
fail because the bundled venv did not resolve.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Upper bound on how many uncovered inputs the reconciliation pass will re-queue
# as hunt tasks in a single run. Keeps the completeness pass bounded (a target
# with hundreds of unreached inputs must not fan out unboundedly). Whatever the
# cap discards stays `uncovered` in the ledger and is counted in
# `reconcile.dropped_beyond_cap` — bounding the work is allowed, hiding it is
# not.
RECONCILE_CAP = 20

#: The complete disposition vocabulary. Two values, on purpose: this ledger
#: answers "did anything look at this input?", not "is it vulnerable?" — that
#: question belongs to the findings and the execution gate.
DISPOSITIONS = ("covered", "uncovered")

# Sensible per-source default attack class for a synthesized reconcile hunt
# task. Substring-matched against the input's source_type; falls back to a broad
# taint trace. Order matters: "file upload" must be tested before "file".
_RECONCILE_ATTACK_CLASS: tuple[tuple[str, str], ...] = (
    ("file upload", "path_traversal"),
    ("file", "path_traversal"),
    ("deserial", "deserialization_pickle"),
    ("pickle", "deserialization_pickle"),
    ("yaml", "deserialization_yaml"),
    ("queue", "deserialization_pickle"),
    ("cookie", "session_tampering"),
    ("header", "header_injection"),
    ("env", "command_injection"),
    ("cli", "command_injection"),
    ("db", "sql_injection"),
    ("sql", "sql_injection"),
)

#: Reconcile task ids are ``t_rc_<n>``; used to continue numbering past any
#: reconcile tasks a previous pass already appended to ``tasks.json``.
_RC_TASK_ID = re.compile(r"^t_rc_(\d+)$")


class ContractViolation(RuntimeError):
    """A violation of the results-directory contract.

    Raised only where the skill must NOT route around the problem; ``main``
    turns it into exit code 2. Never raised from ``classify``, which is
    fail-open by design.
    """


# ---------------------------------------------------------------------------
# Pure helpers — ported unchanged from orchestrator.py
# ---------------------------------------------------------------------------


def _default_attack_class(source_type: str | None) -> str:
    """Best-guess attack class for an input we are re-queuing blind.

    The reconcile task exists precisely because nothing hunted this input, so
    there is no evidence to reason from — only the source type. The table is a
    prior, not a claim; the hunter is free to conclude the class is wrong.
    """
    st = (source_type or "").lower()
    for key, cls in _RECONCILE_ATTACK_CLASS:
        if key in st:
            return cls
    return "injection"


def _location_file(location: str | None) -> str:
    """Basename of the file portion of a ``file:line`` location string.

    Trailing numeric segments are stripped one at a time so ``app.py:12:5``
    (file:line:col) reduces to ``app.py`` while a path that genuinely ends in
    digits survives.
    """
    loc = (location or "").strip()
    if not loc:
        return ""
    parts = loc.split(":")
    while len(parts) > 1 and parts[-1].strip().isdigit():
        parts.pop()
    return os.path.basename(":".join(parts)).strip()


def _task_haystack(task: Mapping[str, Any]) -> str:
    """The text of a task an entry point may be mentioned in.

    Scoped to ``scope_hint`` + ``target_files``, matching the original rule
    exactly. Tasks in the new contract also carry a structured ``entry_point``
    field; it is NOT consulted here, because widening what counts as "covered"
    is the one direction in which this module can lie.
    """
    scope = task.get("scope_hint")
    scope = scope if isinstance(scope, str) else ""
    files = task.get("target_files") or []
    if isinstance(files, str):  # tolerate a single path written unwrapped
        files = [files]
    if not isinstance(files, (list, tuple)):
        files = []
    return scope + " " + " ".join(str(f) for f in files)


def _task_id(task: Mapping[str, Any]) -> str:
    tid = task.get("task_id")
    return tid if isinstance(tid, str) and tid else "<unnamed task>"


#: Sources whose tasks are *created because an input was uncovered*. Crediting
#: coverage from one of these before it has run is circular — see
#: :func:`_is_unrun_requeue`.
RECALL_SOURCES = frozenset({"reconcile", "dismissal", "probe_gap"})


def _is_unrun_requeue(
    task: Mapping[str, Any], hunted_task_ids: frozenset[str]
) -> bool:
    """True for a re-queue task that has not been hunted yet.

    This closes a circularity that silently reported a complete scan. The
    sequence `phase3_sweep.md` prescribes is classify → reconcile → classify,
    and `_synthesize_reconcile_task` writes the uncovered input's own entry
    point verbatim into the new task's `scope_hint`. The entry-point rule below
    then matched that task and marked the input **covered** — on the strength of
    a task created *because* it was uncovered, which nobody had run.

    Measured on a real run: an honest ledger of 146 covered / 7 uncovered became
    153 / 0 on the second classify, with evidence strings reading
    ``task t_rc_1 scope references '_error_code_from_int'``. The phase 3 agent
    caught it and declined to re-run the step; nothing in the code stopped it.

    `lens_matrix` (`dismissal`) and `coverage probe-gap` (`probe_gap`) have the
    same shape — both re-queue a surface precisely because the first pass did
    not settle it — so all three sources are excluded until a ledger says they
    ran.

    A re-queue task that *has* run is fine and is credited normally: the point
    is not the source, it is whether the work happened.
    """
    if str(task.get("source") or "") not in RECALL_SOURCES:
        return False
    return _task_id(task) not in hunted_task_ids


def _classify_input(
    inp: Mapping[str, Any],
    finding_basenames: set[str],
    tasks: Sequence[Mapping[str, Any]],
    hunted_task_ids: frozenset[str] = frozenset(),
) -> tuple[str, str]:
    """Decide one input's disposition. Returns ``(disposition, evidence)``.

    Rule (unchanged from ``orchestrator._classify_input``): an input is
    **covered** if some finding's file matches the input's location file
    (basename match) OR the input's ``entry_point`` appears in a task's scope
    (``scope_hint`` or ``target_files``); otherwise **uncovered**.

    Basename rather than full-path matching is intentional: recon records
    locations as the target sees them and findings record them repo-relative,
    so full paths disagree far more often than the files actually differ. The
    cost is the occasional same-named file in two packages counted as covered —
    an over-count of coverage that Phase 3's sweep is there to catch, and which
    the evidence string makes visible to a reader.
    """
    loc_base = _location_file(inp.get("location"))
    if loc_base and loc_base in finding_basenames:
        return "covered", f"finding touches {loc_base}"

    # A task that named this input and was actually hunted covers it, whatever
    # file its findings landed in.
    #
    # File matching alone is wrong for any multi-hop path, and it produced a
    # visibly silly result: a proven critical finding about a Jinja template
    # left `in_generated_code_exec` — the input describing the very attack path
    # it proved — recorded as `uncovered`, because the finding's file was the
    # template and the input's file was `dynamic.py`. Coverage then understates
    # itself exactly where the analysis did its best work.
    input_id = str(inp.get("input_id") or inp.get("id") or "").strip()
    if input_id and hunted_task_ids:
        for t in tasks:
            if _task_id(t) in hunted_task_ids and input_id in _task_haystack(t):
                return "covered", (
                    f"task {_task_id(t)} named this input and was hunted"
                )

    entry = inp.get("entry_point")
    entry = entry.strip() if isinstance(entry, str) else ""
    if entry:
        for t in tasks:
            if _is_unrun_requeue(t, hunted_task_ids):
                continue
            if entry in _task_haystack(t):
                return "covered", f"task {_task_id(t)} scope references '{entry}'"
    return "uncovered", "no finding file or task scope reached this input"


def _synthesize_reconcile_task(inp: Mapping[str, Any], n: int) -> dict[str, Any]:
    """One hunt task that re-queues an uncovered input for a forward trace.

    Shape matches ``schemas/hunt_task.schema.json`` and is byte-for-byte the
    shape the deleted orchestrator emitted, so a phase reading these tasks needs
    no special case. ``source="reconcile"`` is what makes the extra work
    attributable in the report.
    """
    iid = inp.get("id") or inp.get("input_id") or f"input_{n}"
    source_type = inp.get("source_type") or "input"
    location = inp.get("location") or "?"
    entry = inp.get("entry_point") or "unknown entry point"
    target = str(location).split(":")[0].strip() or _location_file(location) or "."
    return {
        "task_id": f"t_rc_{n}",
        "source": "reconcile",
        "attack_class": _default_attack_class(source_type),
        "scope_hint": (
            f"Completeness reconciliation for uncovered input {iid}: "
            f"{source_type} at {location} (entry point {entry}). Trace this "
            f"attacker-controllable value forward to any dangerous sink."
        ),
        "target_files": [target],
        "rationale": (
            f"Input {iid} ({source_type}) reached no disposition during the "
            f"Hunt/Validate loop; reconciliation re-queues it so every "
            f"enumerated input is traced to a sink or explicitly cleared."
        ),
        "priority": 2,
    }


def _input_id(inp: Any, index: int) -> str:
    """The ledger key for one input record.

    ``input_id`` is the results-directory contract's field and wins here.
    ``_synthesize_reconcile_task`` prefers the opposite order (``id`` first)
    because that string is what a human reads in the task's prose, and recon's
    own short id ("in_3") is more legible there than a composite. The ledger
    needs the identifier the rest of the run joins on; the task needs the one an
    operator recognises.

    A record with neither gets a positional fallback so it can still be counted
    — an unidentifiable input is still an input, and dropping it here would be
    exactly the silent gap this module exists to prevent.
    """
    if isinstance(inp, Mapping):
        for key in ("input_id", "id"):
            value = inp.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, int):
                return str(value)
    return f"input_{index}"


# ---------------------------------------------------------------------------
# Reading the results directory
# ---------------------------------------------------------------------------


def _read_json(path: Path) -> Any:
    """Parse one JSON artifact, raising ContractViolation on anything unusable.

    Callers that must be fail-open catch this; ``assert-complete`` lets it
    escape.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ContractViolation(f"{path} does not exist") from exc
    except OSError as exc:
        raise ContractViolation(f"{path} could not be read: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ContractViolation(f"{path} is not valid JSON: {exc}") from exc


#: Where a hunted task records that it was hunted.
TASK_OUTCOMES_FILE = "task_outcomes.json"

#: Outcomes a task may report. ``clean`` is the whole reason this file exists.
TASK_OUTCOMES = ("findings", "clean", "skipped", "error")


def record_task_outcome(results_dir: str | Path, task_id: str, outcome: str, *,
                        findings: int = 0, note: str = "") -> dict:
    """Record that one hunt task actually ran, and what it concluded.

    **"Hunted and found nothing" and "never hunted" used to be the same
    thing**, because nothing wrote down which tasks had run. `tasks.json`
    listed 88 queued tasks and no outcome for any of them, so every report
    carried the caveat

        88 hunt task(s) were queued but tasks.json records no per-task
        outcome, so it is not known whether every one completed

    and `coverage_complete` could never be true no matter how thorough the hunt
    had been. A clean sweep and an abandoned one were indistinguishable, which
    makes the completeness ledger — the thing this module exists for —
    unfinishable by construction.

    Appended, never rewritten: a second record for the same task is kept, so a
    task hunted twice with different conclusions is visible rather than
    silently resolved to the last writer.
    """
    path = Path(results_dir) / TASK_OUTCOMES_FILE
    if outcome not in TASK_OUTCOMES:
        raise ContractViolation(
            f"unknown task outcome {outcome!r}; expected one of {TASK_OUTCOMES}")
    try:
        payload = _read_json(path)
    except ContractViolation:
        payload = None
    if not isinstance(payload, Mapping):
        payload = {"schema": "pyhunt.task_outcomes/1", "outcomes": []}
    entries = list(payload.get("outcomes") or [])
    entries.append({
        "task_id": str(task_id),
        "outcome": outcome,
        "findings": int(findings),
        "note": note,
        "at": _utc_now(),
    })
    payload = dict(payload)
    payload["outcomes"] = entries
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return entries[-1]


def load_task_outcomes(results_dir: Path) -> dict[str, list[dict]]:
    """``{task_id: [outcome record, ...]}``. Missing file is an empty dict."""
    try:
        payload = _read_json(Path(results_dir) / TASK_OUTCOMES_FILE)
    except ContractViolation:
        return {}
    if not isinstance(payload, Mapping):
        return {}
    out: dict[str, list[dict]] = {}
    for entry in payload.get("outcomes") or []:
        if isinstance(entry, Mapping) and entry.get("task_id"):
            out.setdefault(str(entry["task_id"]), []).append(dict(entry))
    return out


def load_completed_task_ids(results_dir: Path) -> tuple[frozenset[str], bool]:
    """Task ids belonging to phase 2 units that actually **completed**.

    Returns ``(ids, ledger_present)``. ``ledger_present`` is False when
    ``logs/hunt/dispatch.json`` is missing or unreadable, which a caller must
    treat as *unknown*, never as *nothing ran*.

    `phase2_hunt.md` §8 states the rule this implements: "only a unit with
    ``status: "completed"`` may contribute coverage", and notes that a truncated
    or failed unit's `inputs_covered` records what it *would* have covered. That
    rule was written down and never wired up — `coverage.py` only knew about the
    `task-done` outcomes file, which no phase writes during a normal run. So on
    every real run the hunted set was empty and the ledger fell back to matching
    task *scopes*, which cannot distinguish a task that ran from one that was
    merely written.
    """
    path = Path(results_dir) / "logs" / "hunt" / "dispatch.json"
    try:
        payload = _read_json(path)
    except ContractViolation:
        return frozenset(), False
    if not isinstance(payload, Mapping):
        return frozenset(), False
    ids: set[str] = set()
    for unit in payload.get("units") or []:
        if not isinstance(unit, Mapping):
            continue
        if str(unit.get("status") or "") != "completed":
            continue
        for tid in unit.get("task_ids") or []:
            if tid:
                ids.add(str(tid))
    return frozenset(ids), True


def load_inputs(results_dir: Path) -> tuple[list[Any], list[str]]:
    """Read ``inputs.json``. Returns ``(records, notes)``; never raises.

    Accepts the contract shape ``{"inputs": [...]}`` and, tolerantly, a bare
    list — a partially-written artifact should degrade to a note in the ledger,
    not an exception in the gate's own input path.
    """
    path = results_dir / "inputs.json"
    notes: list[str] = []
    try:
        payload = _read_json(path)
    except ContractViolation as exc:
        return [], [f"inputs.json unusable ({exc}); 0 inputs enumerated"]
    if isinstance(payload, Mapping):
        records = payload.get("inputs")
    else:
        records = payload
    if records is None:
        return [], ["inputs.json carries no 'inputs' array; 0 inputs enumerated"]
    if not isinstance(records, list):
        return [], [f"inputs.json 'inputs' is {type(records).__name__}, not a list"]
    return list(records), notes


def load_tasks(results_dir: Path) -> tuple[list[Mapping[str, Any]], list[str]]:
    """Read ``tasks.json``. Returns ``(tasks, notes)``; never raises.

    An absent ``tasks.json`` is normal early in a run and simply means no task
    scope can cover anything yet.
    """
    path = results_dir / "tasks.json"
    if not path.exists():
        return [], ["tasks.json absent; no task scope consulted"]
    try:
        payload = _read_json(path)
    except ContractViolation as exc:
        return [], [f"tasks.json unusable ({exc}); no task scope consulted"]
    records = payload.get("tasks") if isinstance(payload, Mapping) else payload
    if not isinstance(records, list):
        return [], ["tasks.json carries no 'tasks' array; no task scope consulted"]
    return [t for t in records if isinstance(t, Mapping)], []


def _iter_finding_records(payload: Any) -> Iterator[Mapping[str, Any]]:
    """Yield finding objects out of one ``findings/*.json`` file.

    Three shapes are accepted because three are plausible on disk: a bare
    finding object (the per-finding file the results contract describes), a hunt
    output wrapper ``{"task_id":…, "findings":[…]}`` (``finding.schema.json``'s
    top level), and a bare list. Guessing wrong here would silently under-count
    coverage, so all three are handled rather than assumed away.
    """
    if isinstance(payload, Mapping):
        nested = payload.get("findings")
        if isinstance(nested, list):
            for item in nested:
                if isinstance(item, Mapping):
                    yield item
        else:
            yield payload
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, Mapping):
                yield item


def load_finding_basenames(results_dir: Path) -> tuple[set[str], int, list[str]]:
    """Basenames of every file any finding points at.

    Returns ``(basenames, files_read, notes)``. One unreadable finding file
    costs its own basenames and nothing else — it must not take the whole
    ledger down with it.
    """
    findings_dir = results_dir / "findings"
    notes: list[str] = []
    if not findings_dir.is_dir():
        return set(), 0, ["findings/ absent; no finding file covered any input"]
    basenames: set[str] = set()
    files_read = 0
    for path in sorted(findings_dir.glob("*.json")):
        try:
            payload = _read_json(path)
        except ContractViolation as exc:
            notes.append(f"finding file skipped ({exc})")
            continue
        files_read += 1
        for record in _iter_finding_records(payload):
            value = record.get("file")
            if isinstance(value, str) and value.strip():
                base = os.path.basename(value.strip())
                if base:
                    basenames.add(base)
    return basenames, files_read, notes


# ---------------------------------------------------------------------------
# classify — build the ledger (fail-open)
# ---------------------------------------------------------------------------


def classify_inputs(
    inputs: Sequence[Any],
    finding_basenames: set[str],
    tasks: Sequence[Mapping[str, Any]],
    hunted_task_ids: frozenset[str] = frozenset(),
) -> tuple[list[dict[str, Any]], int]:
    """Give every enumerated input a disposition. Returns ``(ledger, unreadable)``.

    **Fail-open per record.** A record that is not a mapping, or that raises
    while being classified, becomes ``uncovered`` with evidence saying so. That
    is the honest answer — nothing demonstrably looked at it — and it keeps the
    single guarantee this module makes intact: the ledger has exactly one row
    per enumerated input, always.
    """
    ledger: list[dict[str, Any]] = []
    unreadable = 0
    for index, inp in enumerate(inputs, 1):
        input_id = _input_id(inp, index)
        if not isinstance(inp, Mapping):
            unreadable += 1
            ledger.append({
                "input_id": input_id,
                "disposition": "uncovered",
                "evidence": (
                    f"input record was unreadable "
                    f"({type(inp).__name__}, expected an object)"
                ),
            })
            continue
        try:
            disposition, evidence = _classify_input(
                inp, finding_basenames, tasks, hunted_task_ids)
        except Exception as exc:  # fail-open — one bad record, not a dead run
            unreadable += 1
            disposition, evidence = (
                "uncovered",
                f"input record was unreadable ({type(exc).__name__}: {exc})",
            )
        ledger.append({
            "input_id": input_id,
            "disposition": disposition,
            "evidence": evidence,
        })
    return ledger, unreadable


def _reconcile_plan(
    inputs: Sequence[Any],
    ledger: Sequence[Mapping[str, Any]],
    cap: int,
) -> tuple[list[Mapping[str, Any]], dict[str, Any]]:
    """What the bounded re-queue will actually do. Returns ``(records, plan)``.

    Shared by ``build_coverage`` and ``reconcile`` so the numbers
    ``coverage.json`` projects and the tasks ``reconcile`` emits can never drift
    apart — a ledger that promises 20 re-queues while reconcile emits 18 is the
    same class of quiet dishonesty the cap disclosure exists to prevent.

    ``inputs`` and ``ledger`` are positionally 1:1 (``classify_inputs`` builds
    exactly one row per record, in order), so they are zipped rather than joined
    on ``input_id`` — a join would mis-handle duplicate ids.
    """
    effective_cap = max(0, int(cap))
    uncovered_pairs = [
        (inp, row) for inp, row in zip(inputs, ledger)
        if row["disposition"] == "uncovered"
    ]
    # A record too malformed to read is still uncovered, but there is nothing to
    # build a hunt task out of. Counted on its own line rather than folded into
    # the cap, because the two have different fixes.
    synthesizable = [inp for inp, _ in uncovered_pairs if isinstance(inp, Mapping)]
    unsynthesizable = len(uncovered_pairs) - len(synthesizable)
    capped = synthesizable[:effective_cap]
    dropped = len(synthesizable) - len(capped)
    plan = {
        "cap": effective_cap,
        "uncovered": len(uncovered_pairs),
        "requeued": len(capped),
        "dropped_beyond_cap": dropped,
        "unsynthesizable": unsynthesizable,
        "not_requeued": len(uncovered_pairs) - len(capped),
        "truncated": dropped > 0,
    }
    return capped, plan


def _plan_notes(plan: Mapping[str, Any]) -> list[str]:
    """The disclosures a re-queue plan owes the reader.

    This is the honest half of the cap. Without these lines a truncated run
    reads as a finished one.
    """
    notes: list[str] = []
    if plan["dropped_beyond_cap"]:
        notes.append(
            f"{plan['dropped_beyond_cap']} uncovered input(s) are beyond the "
            f"reconcile cap ({plan['cap']}) and were NOT re-queued; they remain "
            "uncovered and this run's coverage is incomplete by that many inputs."
        )
    if plan["unsynthesizable"]:
        notes.append(
            f"{plan['unsynthesizable']} uncovered input(s) were too malformed to "
            "synthesize a reconcile task from and were NOT re-queued."
        )
    return notes


def build_coverage(results_dir: Path, *, cap: int = RECONCILE_CAP) -> dict[str, Any]:
    """The full ``coverage.json`` payload for a results directory.

    Pure: same directory in, same bytes out. No timestamp is recorded here
    (``manifest.json`` owns run timing) so a disputed ledger can be recomputed
    and diffed.
    """
    inputs, input_notes = load_inputs(results_dir)
    tasks, task_notes = load_tasks(results_dir)
    basenames, finding_files, finding_notes = load_finding_basenames(results_dir)
    notes = [*input_notes, *task_notes, *finding_notes]

    completed, ledger_present = load_completed_task_ids(results_dir)
    hunted = frozenset(load_task_outcomes(results_dir)) | completed
    if not ledger_present:
        notes.append(
            "logs/hunt/dispatch.json is absent, so which tasks actually ran is "
            "UNKNOWN; re-queue tasks (reconcile/dismissal/probe_gap) are "
            "excluded from coverage regardless, but a task that ran and one "
            "that was only written cannot otherwise be told apart here"
        )
    ledger, unreadable = classify_inputs(inputs, basenames, tasks, hunted)
    covered = sum(1 for row in ledger if row["disposition"] == "covered")
    uncovered = len(ledger) - covered

    _, plan = _reconcile_plan(inputs, ledger, cap)
    notes.extend(_plan_notes(plan))

    counts = Counter(row["input_id"] for row in ledger)
    duplicates = sorted(iid for iid, n in counts.items() if n > 1)
    if duplicates:
        notes.append(
            f"{len(duplicates)} input_id(s) appear more than once in "
            f"inputs.json: {', '.join(duplicates[:10])}"
            + (" …" if len(duplicates) > 10 else "")
        )

    # How each credit was earned. "Covered" is not one thing: a finding citing
    # the input's own file is strong, a repo-wide lens-sweep task whose scope
    # mentions its entry point is weak, and a single number hides the
    # difference. On one run three specialist units legitimately named every
    # file in scope, so 149 of 153 inputs matched on scope alone — a true
    # number that does not mean what a reader will take it to mean.
    by_rule: Counter[str] = Counter()
    for row in ledger:
        evidence = str(row.get("evidence") or "")
        if row["disposition"] != "covered":
            by_rule["uncovered"] += 1
        elif evidence.startswith("finding touches"):
            by_rule["finding_cites_this_file"] += 1
        elif "was hunted" in evidence:
            by_rule["hunted_task_named_this_input"] += 1
        else:
            by_rule["task_scope_mentions_entry_point"] += 1

    return {
        "inputs": ledger,
        "totals": {
            "enumerated": len(ledger),
            "covered": covered,
            "uncovered": uncovered,
        },
        # Beside `totals`, not inside it: `totals` is compared exactly by
        # tests and read by report_build, and widening it silently would be
        # the same shape of breakage this file is trying to fix.
        "coverage_by_rule": dict(by_rule),
        "reconcile": plan,
        "unreadable_input_records": unreadable,
        "duplicate_input_ids": duplicates,
        "seen": {"tasks": len(tasks), "finding_files": finding_files},
        "hunted": {
            "ledger_present": ledger_present,
            "completed_task_ids": len(completed),
            "outcome_task_ids": len(load_task_outcomes(results_dir)),
        },
        "notes": notes,
    }


def write_coverage(results_dir: Path, payload: Mapping[str, Any]) -> Path:
    """Persist ``coverage.json`` and return its path."""
    path = results_dir / "coverage.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def run_classify(results_dir: Path, *, cap: int = RECONCILE_CAP) -> dict[str, Any]:
    """``classify`` subcommand body. Writes coverage.json, returns the summary."""
    payload = build_coverage(results_dir, cap=cap)
    path = write_coverage(results_dir, payload)
    return {
        "coverage_path": str(path),
        "totals": payload["totals"],
        "reconcile": payload["reconcile"],
        "unreadable_input_records": payload["unreadable_input_records"],
        "uncovered_input_ids": [
            row["input_id"] for row in payload["inputs"]
            if row["disposition"] == "uncovered"
        ],
        "notes": payload["notes"],
    }


# ---------------------------------------------------------------------------
# reconcile — synthesize bounded re-queue tasks (fail-open)
# ---------------------------------------------------------------------------


def _next_reconcile_index(tasks: Sequence[Mapping[str, Any]]) -> int:
    """First unused ``t_rc_<n>`` number.

    On a fresh run this is 1, identical to the deleted orchestrator's numbering.
    On a resumed run that already appended reconcile tasks it continues past
    them, because ``tasks.json`` is now an append-target the skill owns and two
    tasks sharing a ``task_id`` would make findings unattributable.
    """
    highest = 0
    for task in tasks:
        match = _RC_TASK_ID.match(_task_id(task))
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def reconcile(results_dir: Path, *, cap: int = RECONCILE_CAP,
              write: bool = True) -> dict[str, Any]:
    """Synthesize up to ``cap`` hunt tasks, one per uncovered input, and append them.

    Classification is recomputed here rather than read back from
    ``coverage.json`` on purpose: the tasks must be derived from the *current*
    state of the results directory, and a stale ledger left by an earlier phase
    would otherwise re-queue work that has since been covered.

    **This writes ``tasks.json``.** It used to print the tasks on stdout, exit
    0, and mutate nothing, with no phase file saying who was supposed to perform
    the append — so the re-queue step could silently do nothing while every
    downstream gate still passed, because ``uncovered`` is a legal disposition.
    A run in that state reports an honest-looking ledger over work that was
    never done. Observed: 54 uncovered inputs, 20 tasks emitted, ``tasks.json``
    unchanged.

    The append is additive and idempotent by task id, a timestamped backup is
    written beside the file first, and ``written``/``backup_path`` come back in
    the result so the caller can assert the write landed. Pass ``write=False``
    for the old preview behaviour.
    """
    inputs, _ = load_inputs(results_dir)
    tasks, _ = load_tasks(results_dir)
    basenames, _, _ = load_finding_basenames(results_dir)
    ledger, _ = classify_inputs(
        inputs, basenames, tasks, frozenset(load_task_outcomes(results_dir)))

    capped, plan = _reconcile_plan(inputs, ledger, cap)
    start = _next_reconcile_index(tasks)
    synthesized = [
        _synthesize_reconcile_task(inp, start + offset)
        for offset, inp in enumerate(capped)
    ]
    result: dict[str, Any] = {"tasks": synthesized, **plan,
                              "notes": _plan_notes(plan)}
    if write and synthesized:
        result.update(append_tasks(results_dir, synthesized))
    else:
        result["written"] = 0
        result["backup_path"] = None
        if synthesized and not write:
            result["notes"] = list(result["notes"]) + [
                f"{len(synthesized)} task(s) were NOT written (write=False). "
                "Nothing downstream will hunt them."
            ]
    return result


def append_tasks(results_dir: Path,
                 new_tasks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Append tasks to ``tasks.json``, preserving its shape and backing it up.

    Both shapes ``load_tasks`` accepts are preserved on write — a bare array
    stays a bare array, ``{"tasks": [...]}`` keeps its wrapper and its sibling
    keys. Rewriting one into the other would be a silent contract change to a
    file three later phases read.

    Duplicate task ids are skipped rather than appended twice: two tasks sharing
    an id make every finding they produce unattributable, which is the failure
    ``_next_reconcile_index`` already exists to avoid on resumed runs.
    """
    path = results_dir / "tasks.json"
    existing_payload: Any
    if path.exists():
        existing_payload = _read_json(path)
    else:
        existing_payload = {"tasks": []}

    if isinstance(existing_payload, Mapping):
        records = list(existing_payload.get("tasks") or [])
        container = "object"
    elif isinstance(existing_payload, list):
        records = list(existing_payload)
        container = "array"
    else:
        raise ContractViolation(
            f"tasks.json is a {type(existing_payload).__name__}; expected an "
            "array of tasks or an object carrying a 'tasks' array"
        )

    known = {_task_id(t) for t in records if isinstance(t, Mapping)}
    appended = [t for t in new_tasks if _task_id(t) not in known]

    backup_path: Path | None = None
    if path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = path.with_suffix(f".json.before_reconcile.{stamp}.bak")
        backup_path.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    records.extend(appended)
    if container == "object":
        payload: Any = dict(existing_payload)
        payload["tasks"] = records
    else:
        payload = records
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # Read back rather than trust the write. The whole defect this function
    # exists to close was "the step reported success and the file was unchanged".
    verify, _ = load_tasks(results_dir)
    landed = {_task_id(t) for t in verify}
    missing = [_task_id(t) for t in appended if _task_id(t) not in landed]
    if missing:
        raise ContractViolation(
            "tasks.json was written but does not contain "
            f"{len(missing)} of the appended task(s): {', '.join(missing[:10])}"
        )
    return {
        "written": len(appended),
        "skipped_duplicate_ids": len(list(new_tasks)) - len(appended),
        "tasks_total": len(records),
        "backup_path": str(backup_path) if backup_path else None,
        "tasks_path": str(path),
    }


# ---------------------------------------------------------------------------
# probe-gap — findings the second oracle could settle and was never asked to
# ---------------------------------------------------------------------------

_PG_TASK_ID = re.compile(r"^t_pg_(\d+)$")


def _next_probe_index(tasks: Sequence[Mapping[str, Any]]) -> int:
    highest = 0
    for task in tasks:
        match = _PG_TASK_ID.match(_task_id(task))
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def probe_gap(results_dir: Path, *, cap: int = RECONCILE_CAP,
              write: bool = True) -> dict[str, Any]:
    """Re-queue every finding the structural oracle could settle and was not asked to.

    The oracle works — verified `demonstrated` end to end against a real
    generator. On the recorded run **1 of 74** observer-blind findings would
    have carried a probe, because declaring one is optional. An optional oracle
    produces exactly the same report as no oracle, and the same shape of defect
    as `reconcile` printing tasks nobody appended: everything downstream still
    passes and the work silently did not happen.

    So a finding whose class the audit hook cannot see, carrying no
    `structural_probe`, becomes a task whose job is to author one — bounded,
    written, and read back, like every other re-queue in this phase.
    """
    try:
        from oracle.structural import probe_kind_for
    except ImportError:  # pragma: no cover - a half-installed tree
        return {"eligible": 0, "missing": 0, "tasks": [], "written": 0,
                "notes": ["oracle.structural is unavailable; no probe gap computed"]}

    findings = _load_findings_for_probe_gap(results_dir)
    tasks_existing, _ = load_tasks(results_dir)

    eligible: list[Mapping[str, Any]] = []
    for finding in findings:
        if not probe_kind_for(str(finding.get("vuln_class") or "")):
            continue
        eligible.append(finding)

    missing = [f for f in eligible if not f.get("structural_probe")]
    # One task per SITE, not per finding: five duplicates of one defect need one
    # probe between them, and five identical tasks would burn the cap.
    seen: set[tuple[str, str]] = set()
    unique: list[Mapping[str, Any]] = []
    for finding in missing:
        key = (str(finding.get("file") or ""), str(finding.get("vuln_class") or ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    capped = unique[:cap]
    dropped = len(unique) - len(capped)
    start = _next_probe_index(tasks_existing)
    synthesized = [
        _synthesize_probe_task(finding, start + offset, probe_kind_for(
            str(finding.get("vuln_class") or "")))
        for offset, finding in enumerate(capped)
    ]

    notes: list[str] = []
    if dropped:
        notes.append(
            f"{dropped} finding site(s) eligible for a structural probe exceeded "
            f"the cap ({cap}) and were NOT re-queued. They will be reported on "
            "their static argument alone.")
    if not missing:
        notes.append("every probe-eligible finding already carries a probe")

    result: dict[str, Any] = {
        "eligible": len(eligible),
        "already_probed": len(eligible) - len(missing),
        "missing": len(missing),
        "unique_sites": len(unique),
        "requeued": len(synthesized),
        "dropped_beyond_cap": dropped,
        "cap": cap,
        "tasks": synthesized,
        "notes": notes,
    }
    if write and synthesized:
        result.update(append_tasks(results_dir, synthesized))
    else:
        result["written"] = 0
        result["backup_path"] = None
    return result


def _load_findings_for_probe_gap(results_dir: Path) -> list[Mapping[str, Any]]:
    out: list[Mapping[str, Any]] = []
    directory = results_dir / "findings"
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.json")):
        try:
            payload = _read_json(path)
        except ContractViolation:
            continue
        if isinstance(payload, Mapping) and isinstance(payload.get("findings"), list):
            out.extend(f for f in payload["findings"] if isinstance(f, Mapping))
        elif isinstance(payload, Mapping) and payload.get("finding_id"):
            out.append(payload)
    return out


def _synthesize_probe_task(finding: Mapping[str, Any], n: int,
                           probe_kind: str | None) -> dict[str, Any]:
    file = str(finding.get("file") or "")
    return {
        "task_id": f"t_pg_{n}",
        "source": "probe_gap",
        "attack_class": str(finding.get("vuln_class") or "improper_input_handling"),
        "target_files": [file] if file else [],
        "priority": 2,
        "scope_hint": (
            f"Author a `{probe_kind}` structural_probe for {finding.get('finding_id')} "
            f"at {file}:{finding.get('line_start')}. Do not re-file the finding — "
            "it already exists. Emit only the probe spec, per phase2_shared.md §6.8."
        ),
        "rationale": (
            "this finding is in a class the audit-hook observer has no event for, "
            "so execution can never settle it, and no structural probe was "
            "declared — it would be reported on its static argument alone"
        ),
    }


# ---------------------------------------------------------------------------
# read-ledger — W4.2
#
# The coverage ledger is INPUT-level: it proves every enumerated input reached a
# disposition. It says nothing about whether the agent that answered a task
# actually opened the files the task named. A unit assigned five files can
# report "no findings" having read two, and every downstream check still passes
# — the task has an outcome, the inputs have dispositions, the coverage number
# is full. The gap has no name and produces no warning.
#
# `files_read` on the hunt output closes that. This function joins it against
# `tasks.json` and reports, per task, which target files were never opened.
#
# It is a REPORT, not a gate. A file legitimately goes unread — the task was
# answered from another file, or the file turned out to be generated — and
# failing the run for it would push agents toward inflating the list, which
# converts a measurable gap into an unmeasurable lie. Naming it is what makes it
# actionable; `phase3_sweep.md` re-queues what this surfaces.
# ---------------------------------------------------------------------------


def _norm_path(path: str) -> str:
    """Repo-relative, forward slashes, no leading `./`.

    Not `lstrip("./")`: that strips any leading run of `.` and `/`, so
    `.github/workflows/publish.yaml` becomes `github/...` and matches nothing.
    """
    text = str(path or "").replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def load_files_read(results_dir: Path) -> tuple[dict[str, set[str]], list[str]]:
    """`{task_id: {path, ...}}` from every hunt output that reported one."""
    by_task: dict[str, set[str]] = {}
    silent: list[str] = []
    directory = results_dir / "findings"
    if not directory.is_dir():
        return by_task, silent
    for path in sorted(directory.glob("*.json")):
        try:
            payload = _read_json(path)
        except ContractViolation:
            continue
        if not isinstance(payload, Mapping):
            continue
        task_id = payload.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            continue
        read = payload.get("files_read")
        if not isinstance(read, list):
            silent.append(task_id)
            continue
        by_task.setdefault(task_id, set()).update(
            _norm_path(p) for p in read if isinstance(p, str) and p)
    return by_task, silent


def read_ledger(results_dir: Path) -> dict[str, Any]:
    """Which assigned files were never opened, per task."""
    tasks, notes = load_tasks(results_dir)
    by_task, silent = load_files_read(results_dir)

    rows: list[dict[str, Any]] = []
    unread_files: set[str] = set()
    unknown_files: set[str] = set()
    fully_read = 0
    # A file some finding cites was demonstrably opened, whatever the (absent)
    # self-report says. This is the only positive evidence available when no
    # unit declares `files_read`, and it is what keeps the "unknown" list from
    # naming files the run visibly analysed.
    cited_basenames, _cited_count, _cited_notes = load_finding_basenames(results_dir)
    for task in tasks:
        task_id = str(task.get("task_id") or "")
        assigned = {
            _norm_path(p)
            for p in (task.get("target_files") or []) if isinstance(p, str) and p
        }
        if not task_id or not assigned:
            continue
        opened = by_task.get(task_id)
        if opened is None:
            # UNKNOWN, not unread. These are different claims and conflating
            # them made this report assert the opposite of what happened: with
            # no hunt unit declaring `files_read` (none currently does), every
            # task landed here and the command announced "12 file(s) assigned
            # and never opened" — listing every in-scope file — on a run whose
            # 53 findings cited line ranges in 8 of them.
            rows.append({
                "task_id": task_id,
                "assigned": sorted(assigned),
                "unread": [],
                "unknown": sorted(assigned),
                "status": "not_reported",
            })
            unknown_files |= assigned
            continue
        missing = assigned - opened
        if missing:
            rows.append({
                "task_id": task_id,
                "assigned": sorted(assigned),
                "unread": sorted(missing),
                "status": "partial",
            })
            unread_files |= missing
        else:
            fully_read += 1

    def _cited(path: str) -> bool:
        return path.rsplit("/", 1)[-1] in cited_basenames

    demonstrably_read = sorted(p for p in unknown_files if _cited(p))
    unknown_files = {p for p in unknown_files if not _cited(p)}

    not_reporting = sum(1 for r in rows if r["status"] == "not_reported")
    payload: dict[str, Any] = {
        "tasks_with_targets": sum(1 for t in tasks if t.get("target_files")),
        "tasks_fully_read": fully_read,
        "tasks_partially_read": sum(1 for r in rows if r["status"] == "partial"),
        "tasks_not_reporting": not_reporting,
        # Known unread: a unit reported what it opened and this was not in it.
        "unread_files": sorted(unread_files),
        # Unknown: assigned, nobody reported, and no finding cites them.
        "unknown_files": sorted(unknown_files),
        # Assigned by a silent task but cited by a finding, so read regardless.
        "files_read_per_findings": demonstrably_read,
        "reporting_available": bool(by_task),
        "rows": rows,
        "notes": notes,
    }
    if silent:
        payload["outputs_without_files_read"] = sorted(set(silent))[:50]
    if not by_task:
        payload["notes"] = list(notes) + [
            "no hunt unit declared `files_read`, so per-task read coverage is "
            "UNKNOWN rather than zero; `unread_files` is empty by construction "
            "here and `unknown_files` is the honest list"
        ]
    payload["interpretation"] = (
        "A file in scope and never opened is a gap with a name. This is a "
        "report, not a gate: failing a run for an unread file would push units "
        "toward inflating the list, which converts a measurable gap into an "
        "unmeasurable one. `unread_files` and `unknown_files` are kept apart on "
        "purpose — merging them once made this command claim every in-scope "
        "file was never opened on a run that had produced findings citing line "
        "ranges in most of them."
    )
    return payload


# ---------------------------------------------------------------------------
# assert-complete — the release gate (fail-closed)
# ---------------------------------------------------------------------------


def _format_ids(ids: Sequence[str], limit: int = 50) -> str:
    shown = ", ".join(ids[:limit])
    if len(ids) > limit:
        shown += f", … and {len(ids) - limit} more"
    return shown


def assert_complete(results_dir: Path) -> dict[str, Any]:
    """Fail unless every enumerated input carries a disposition.

    **Fail-closed.** Every readable-but-wrong and every unreadable artifact
    raises :class:`ContractViolation`, which the caller turns into exit 2. The
    fail-open licence granted to ``classify`` stops here: a gate that swallows
    errors reports success on a run it never checked.

    The check is a multiset comparison, not a set one. If ``inputs.json``
    enumerates the same ``input_id`` twice, the ledger must carry two rows for
    it — otherwise one real input would borrow the other's disposition and the
    gate would pass over a genuine hole.

    ``uncovered`` passes. It is a disposition, and an honest one; this gate
    asserts that nothing went uncounted, not that everything got hunted. What a
    truncated re-queue costs is recorded in ``reconcile.dropped_beyond_cap`` and
    re-surfaced in the returned summary.
    """
    if not results_dir.is_dir():
        raise ContractViolation(f"results directory {results_dir} does not exist")

    inputs_payload = _read_json(results_dir / "inputs.json")
    if isinstance(inputs_payload, Mapping):
        inputs = inputs_payload.get("inputs")
    else:
        inputs = inputs_payload
    if not isinstance(inputs, list):
        raise ContractViolation(
            "inputs.json does not carry an 'inputs' array — the enumeration "
            "phase 1 is supposed to have written is missing, so completeness "
            "cannot be asserted"
        )

    coverage_payload = _read_json(results_dir / "coverage.json")
    if not isinstance(coverage_payload, Mapping):
        raise ContractViolation(
            f"coverage.json is a {type(coverage_payload).__name__}, not an object"
        )
    ledger = coverage_payload.get("inputs")
    if not isinstance(ledger, list):
        raise ContractViolation(
            "coverage.json does not carry an 'inputs' array — no ledger to check"
        )

    required = Counter(_input_id(inp, index) for index, inp in enumerate(inputs, 1))

    recorded: Counter[str] = Counter()
    bad_rows: list[str] = []
    missing_evidence: list[str] = []
    for position, row in enumerate(ledger, 1):
        if not isinstance(row, Mapping):
            bad_rows.append(f"row {position} is a {type(row).__name__}, not an object")
            continue
        input_id = row.get("input_id")
        if not isinstance(input_id, str) or not input_id.strip():
            bad_rows.append(f"row {position} has no input_id")
            continue
        disposition = row.get("disposition")
        if disposition not in DISPOSITIONS:
            bad_rows.append(
                f"row {position} ({input_id}) has disposition {disposition!r}, "
                f"which is not one of {DISPOSITIONS}"
            )
            continue
        evidence = row.get("evidence")
        if not isinstance(evidence, str) or not evidence.strip():
            missing_evidence.append(input_id)
        recorded[input_id.strip()] += 1

    if bad_rows:
        raise ContractViolation(
            "coverage.json contains "
            f"{len(bad_rows)} malformed ledger row(s): " + "; ".join(bad_rows[:20])
            + (" …" if len(bad_rows) > 20 else "")
        )

    missing = sorted(iid for iid, n in required.items() if recorded[iid] < n)
    if missing:
        raise ContractViolation(
            f"{len(missing)} of {sum(required.values())} enumerated input(s) carry "
            f"no disposition in coverage.json: {_format_ids(missing)}. "
            "Every enumerated input must reach a disposition before a report is "
            "written — run `coverage.py classify --results-dir "
            f"{results_dir}` and re-check."
        )

    totals = coverage_payload.get("totals")
    totals = totals if isinstance(totals, Mapping) else {}
    reconcile_block = coverage_payload.get("reconcile")
    reconcile_block = reconcile_block if isinstance(reconcile_block, Mapping) else {}
    covered = sum(
        1 for row in ledger
        if isinstance(row, Mapping) and row.get("disposition") == "covered"
    )
    return {
        "complete": True,
        "enumerated": sum(required.values()),
        "ledger_rows": len(ledger),
        "covered": covered,
        "uncovered": len(ledger) - covered,
        "dropped_beyond_cap": reconcile_block.get("dropped_beyond_cap", 0),
        "not_requeued": reconcile_block.get("not_requeued", 0),
        "truncated": bool(reconcile_block.get("truncated", False)),
        "rows_without_evidence": missing_evidence,
        "totals_recorded": dict(totals),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coverage.py",
        description=(
            "The completeness ledger: give every enumerated input a "
            "disposition, and refuse to call a run complete until it has one."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    classify_cmd = sub.add_parser(
        "classify",
        help="give every enumerated input a disposition; write coverage.json",
    )
    classify_cmd.add_argument("--results-dir", required=True, type=Path)
    classify_cmd.add_argument(
        "--cap", type=int, default=RECONCILE_CAP,
        help=(
            "reconcile fan-out cap recorded in coverage.json "
            f"(default {RECONCILE_CAP}); uncovered inputs beyond it are "
            "reported as dropped"
        ),
    )

    reconcile_cmd = sub.add_parser(
        "reconcile",
        help="emit up to --cap synthesized hunt tasks for uncovered inputs",
    )
    reconcile_cmd.add_argument("--results-dir", required=True, type=Path)
    reconcile_cmd.add_argument("--cap", type=int, default=RECONCILE_CAP)
    probe_cmd = sub.add_parser(
        "probe-gap",
        help="re-queue findings the structural oracle could settle and was not asked to",
    )
    probe_cmd.add_argument("--results-dir", required=True, type=Path)
    probe_cmd.add_argument("--cap", type=int, default=RECONCILE_CAP)
    probe_cmd.add_argument("--dry-run", action="store_true")

    reconcile_cmd.add_argument(
        "--dry-run", action="store_true",
        help=("print the synthesized tasks without appending them to "
              "tasks.json. The default is to WRITE: a re-queue step that emits "
              "tasks nobody appends leaves the ledger honest and the work "
              "undone, and every downstream gate still passes."))

    read_cmd = sub.add_parser(
        "read-ledger",
        help=("report which assigned files a hunt unit never opened. A report, "
              "not a gate — see the module note on why failing here would make "
              "the number worse"),
    )
    read_cmd.add_argument("--results-dir", required=True, type=Path)

    assert_cmd = sub.add_parser(
        "assert-complete",
        help="exit 2 unless every enumerated input carries a disposition",
    )
    assert_cmd.add_argument("--results-dir", required=True, type=Path)

    task_cmd = sub.add_parser(
        "task-done",
        help=(
            "record that a hunt task ran. Use `--outcome clean` when it found "
            "nothing: without it, a clean sweep is indistinguishable from a "
            "task nobody hunted"
        ),
    )
    task_cmd.add_argument("--results-dir", required=True, type=Path)
    task_cmd.add_argument("--task-id", required=True)
    task_cmd.add_argument(
        "--outcome", default="clean", choices=list(TASK_OUTCOMES),
        help="`findings` is written for you by findings_io record; you want "
             "`clean`, or `skipped`/`error` with a note",
    )
    task_cmd.add_argument("--findings", type=int, default=0)
    task_cmd.add_argument("--note", default="")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results_dir: Path = args.results_dir

    try:
        if args.command == "task-done":
            if not results_dir.is_dir():
                raise ContractViolation(
                    f"results directory {results_dir} does not exist"
                )
            entry = record_task_outcome(
                results_dir, args.task_id, args.outcome,
                findings=args.findings, note=args.note,
            )
            print(f"coverage: task {args.task_id} -> {args.outcome}",
                  file=sys.stderr)
            json.dump(entry, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0

        if args.command == "read-ledger":
            if not results_dir.is_dir():
                raise ContractViolation(
                    f"results directory {results_dir} does not exist"
                )
            payload = read_ledger(results_dir)
            if not payload["reporting_available"]:
                print(
                    "coverage: no hunt unit declared `files_read`, so per-task "
                    "read coverage is UNKNOWN, not zero. "
                    f"{len(payload['unknown_files'])} assigned file(s) have no "
                    "evidence either way; "
                    f"{len(payload['files_read_per_findings'])} were read "
                    "regardless (a finding cites them).",
                    file=sys.stderr,
                )
            else:
                print(
                    f"coverage: {payload['tasks_fully_read']} task(s) read every "
                    f"assigned file, {payload['tasks_partially_read']} partially, "
                    f"{payload['tasks_not_reporting']} reported nothing; "
                    f"{len(payload['unread_files'])} file(s) assigned and never "
                    f"opened, {len(payload['unknown_files'])} unknown",
                    file=sys.stderr,
                )
            json.dump(payload, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0

        if args.command == "classify":
            if not results_dir.is_dir():
                raise ContractViolation(
                    f"results directory {results_dir} does not exist"
                )
            summary = run_classify(results_dir, cap=args.cap)
            for note in summary["notes"]:
                print(f"coverage: {note}", file=sys.stderr)
            totals = summary["totals"]
            print(
                f"coverage: {totals['enumerated']} input(s) — "
                f"{totals['covered']} covered, {totals['uncovered']} uncovered "
                f"-> {summary['coverage_path']}",
                file=sys.stderr,
            )
            json.dump(summary, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0

        if args.command == "reconcile":
            if not results_dir.is_dir():
                raise ContractViolation(
                    f"results directory {results_dir} does not exist"
                )
            result = reconcile(results_dir, cap=args.cap,
                               write=not args.dry_run)
            print(
                f"coverage: {result['uncovered']} uncovered input(s); "
                f"{result['requeued']} re-queued as hunt tasks "
                f"(cap={result['cap']})",
                file=sys.stderr,
            )
            if args.dry_run:
                print("coverage: --dry-run — tasks.json was NOT written",
                      file=sys.stderr)
            else:
                print(
                    f"coverage: appended {result.get('written', 0)} task(s) to "
                    f"{result.get('tasks_path')} "
                    f"(backup: {result.get('backup_path')})",
                    file=sys.stderr,
                )
            for note in result["notes"]:
                print(f"coverage: {note}", file=sys.stderr)
            json.dump(result, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0

        if args.command == "probe-gap":
            if not results_dir.is_dir():
                raise ContractViolation(
                    f"results directory {results_dir} does not exist"
                )
            result = probe_gap(results_dir, cap=args.cap, write=not args.dry_run)
            print(
                f"coverage: {result['missing']} of {result['eligible']} "
                f"probe-eligible finding(s) carry no structural probe; "
                f"{result['requeued']} site(s) re-queued "
                f"(wrote {result.get('written', 0)})",
                file=sys.stderr,
            )
            for note in result["notes"]:
                print(f"coverage: {note}", file=sys.stderr)
            json.dump(result, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0

        if args.command == "assert-complete":
            summary = assert_complete(results_dir)
            if summary["truncated"]:
                print(
                    f"coverage: complete ledger, but {summary['dropped_beyond_cap']} "
                    "uncovered input(s) were dropped by the reconcile cap",
                    file=sys.stderr,
                )
            if summary["rows_without_evidence"]:
                print(
                    "coverage: "
                    f"{len(summary['rows_without_evidence'])} disposition(s) carry "
                    "no evidence string: "
                    f"{_format_ids(summary['rows_without_evidence'], 10)}",
                    file=sys.stderr,
                )
            print(
                f"coverage: all {summary['enumerated']} enumerated input(s) carry "
                f"a disposition ({summary['covered']} covered, "
                f"{summary['uncovered']} uncovered)",
                file=sys.stderr,
            )
            json.dump(summary, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0

    except ContractViolation as exc:
        print(f"coverage: CONTRACT VIOLATION: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # internal error — distinct from a contract failure
        print(f"coverage: internal error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1

    print(f"coverage: unknown subcommand {args.command!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
