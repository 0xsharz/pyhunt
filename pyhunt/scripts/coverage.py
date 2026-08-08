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

    hunted = frozenset(load_task_outcomes(results_dir))
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

    return {
        "inputs": ledger,
        "totals": {
            "enumerated": len(ledger),
            "covered": covered,
            "uncovered": uncovered,
        },
        "reconcile": plan,
        "unreadable_input_records": unreadable,
        "duplicate_input_ids": duplicates,
        "seen": {"tasks": len(tasks), "finding_files": finding_files},
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


def reconcile(results_dir: Path, *, cap: int = RECONCILE_CAP) -> dict[str, Any]:
    """Synthesize up to ``cap`` hunt tasks, one per uncovered input.

    Classification is recomputed here rather than read back from
    ``coverage.json`` on purpose: the tasks must be derived from the *current*
    state of the results directory, and a stale ledger left by an earlier phase
    would otherwise re-queue work that has since been covered.

    Mutates nothing. The skill decides whether these tasks are appended to
    ``tasks.json``.
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
    return {"tasks": synthesized, **plan, "notes": _plan_notes(plan)}


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
            result = reconcile(results_dir, cap=args.cap)
            print(
                f"coverage: {result['uncovered']} uncovered input(s); "
                f"{result['requeued']} re-queued as hunt tasks "
                f"(cap={result['cap']})",
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
