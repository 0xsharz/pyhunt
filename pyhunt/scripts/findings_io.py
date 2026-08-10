"""The findings ledger: read, write, and gate findings in a results directory.

This is the module that replaced ``state.py``'s ``add_finding``. There is no
database any more — a run's state is the timestamped results directory beside
the target — but the one rule ``add_finding`` enforced has to survive the move
intact, because it is the product:

    ``poc_succeeded`` comes from the execution gate, never from the model.

VASH stored ``poc.succeeded`` — a boolean the same agent that wrote and ran the
exploit had set about its own work — straight into the findings table. Every
downstream consumer read that column as "confirmed by execution", so the
zero-false-positive claim rested entirely on a model obeying a prompt. Here the
observer output is re-read by :mod:`oracle` and judged in Python, and
:func:`poc_succeeded` reads only what the gate wrote.

One deliberate divergence from ``state.py``, and it tightens rather than
loosens. ``add_finding`` fell back to the model's ``poc.succeeded`` when no
gate verdict was present, to cover rows that predated the gate. In the skill
there is no such row: :func:`record_finding` attaches a placeholder verdict on
the way in (``not_attempted``), and :func:`apply_proof` replaces it with the
real one once phase 2b has replayed the PoC. So a finding reaching this
module with no ``execution`` block means the gate never ran at all — a harness
failure, not a static run — and treating a model's boolean as proof in that
situation is precisely the laundering the gate exists to stop. The old
behaviour is still reachable via ``allow_model_claim=True``, for anyone
importing archived VASH rows, and it is never the default.

The other half of the contract is the asymmetry: **nothing here may delete a
finding.** A PoC that failed to reproduce, a missing dependency, a silent
observer, and an unprovable class each get their own outcome and the finding
stays on disk. Only ``proven`` promotes; nothing demotes.

Storage layout, inside ``<target>_PYHUNT_RESULTS_<stamp>/``::

    findings/<finding_id>.json   the finding, as the hunter emitted it, plus
                                 the fields PyHunt owns (see below)
    proof/<finding_id>.json      replay transcript + gate verdict (phase 2b)
    verify/<finding_id>.json     adversarial disproof result (phase 2c)
    gaps.json                    what the hunters could not examine

A stored finding is the hunter's own object with four PyHunt-owned keys added.
They are declared in the validation schema this module derives, so a stored
record still validates:

``task_id``       which hunt task produced it — provenance the schema's
                  envelope carries per-task and the per-finding file would
                  otherwise lose.
``execution``     the gate's verdict. Schema-declared, ``readOnly``, and
                  overwritten on every gating: a value a model supplied here is
                  discarded.
``group_id``      dedupe/sibling group, when phase 3 has clustered.
``is_canonical``  whether this finding is its group's delivered representative.
"""

from __future__ import annotations

import _bootstrap  # noqa: F401  (must precede any third-party import)

import argparse
import copy
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from jsonschema import Draft7Validator

from oracle import taxonomy
from oracle.finding import placeholder_verdict
from oracle.nonce import nonce_for

#: Keys PyHunt writes onto a stored finding that the hunter never emits. Kept
#: as data so the derived schema, the round-trip test, and anyone auditing the
#: file format all read the same list.
PYHUNT_OWNED_KEYS: dict[str, dict] = {
    "task_id": {"type": "string"},
    "group_id": {"type": ["string", "null"]},
    "is_canonical": {"type": "boolean"},
    "recorded_at": {
        "type": "string",
        "description": "UTC ISO-8601 stamp of when PyHunt wrote this record.",
    },
}


# --------------------------------------------------------------------------
# Results-directory layout
# --------------------------------------------------------------------------

def findings_dir(results_dir: str | Path) -> Path:
    return Path(results_dir) / "findings"


def proof_dir(results_dir: str | Path) -> Path:
    return Path(results_dir) / "proof"


def verify_dir(results_dir: str | Path) -> Path:
    return Path(results_dir) / "verify"


def manifest_path(results_dir: str | Path) -> Path:
    return Path(results_dir) / "manifest.json"


def gaps_path(results_dir: str | Path) -> Path:
    return Path(results_dir) / "gaps.json"


def load_manifest(results_dir: str | Path) -> dict:
    """The run's manifest, or ``{}`` when the run has not written one yet.

    Never raises on a missing file: several scripts want ``run_id`` or
    ``target`` as a *default* for an explicitly-passed flag, and a phase that
    has not reached manifest-writing yet is a normal state, not an error.
    """
    return _read_json(manifest_path(results_dir), default={})


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

def _hunt_output_schema(schemas_dir: str | Path | None = None) -> dict:
    path = Path(schemas_dir or _bootstrap.SCHEMAS_DIR) / "finding.schema.json"
    return json.loads(path.read_text())


def finding_item_schema(schemas_dir: str | Path | None = None) -> dict:
    """The schema for ONE stored finding.

    ``finding.schema.json`` describes a hunt task's whole output — ``task_id``,
    ``findings[]``, ``gaps_observed[]`` — because that is what a hunter
    returns. On disk we keep one file per finding, so the schema that applies
    to a file is the envelope's ``findings.items`` subschema, extended with the
    PyHunt-owned keys in :data:`PYHUNT_OWNED_KEYS`.

    Derived in memory rather than duplicated as a second schema file: two
    copies of the same finding shape would drift, and the drift would show up
    as a validation failure on a finding that is actually fine.
    """
    schema = _hunt_output_schema(schemas_dir)
    item = copy.deepcopy(schema["properties"]["findings"]["items"])
    item.setdefault("properties", {}).update(copy.deepcopy(PYHUNT_OWNED_KEYS))
    item["title"] = "StoredFinding"
    return item


def _schema_errors(payload: Any, schema: dict) -> list[str]:
    """Human-readable validation errors; empty means valid. Same formatting as
    :func:`json_utils.validate_schema` so failures read identically wherever
    they surface."""
    validator = Draft7Validator(schema)
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator.iter_errors(payload), key=lambda e: e.path)
    ]


def validate_finding(finding: dict, schemas_dir: str | Path | None = None) -> list[str]:
    """Validate one finding (stored or freshly emitted). Empty list = valid."""
    return _schema_errors(finding, finding_item_schema(schemas_dir))


def validate_hunt_output(payload: Any, schemas_dir: str | Path | None = None) -> list[str]:
    """Validate a whole hunt-task output against ``finding.schema.json``."""
    return _schema_errors(payload, _hunt_output_schema(schemas_dir))


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

def gate_finding(
    finding: dict,
    *,
    run_id: str,
    task_id: str,
    repo: str | Path,
    scratch_dir: str | Path,
    execution_available: bool,
) -> dict:
    """Attach the *placeholder* execution block to a freshly-emitted finding.

    **This function used to judge, and that was defect C-1.** It fed
    ``poc.run_output`` — the hunt agent's own account of its own run — to
    ``gate.judge`` and stored the result in the one field every consumer reads
    as "confirmed by execution". The gate is a good gate; it was simply being
    shown forgeable text.

    Nothing is judged here now. The finding gets ``not_attempted`` and a reason
    saying so, and the only route to a real verdict is
    :func:`apply_proof`, whose input comes from ``replay.py``'s own container.

    Any ``execution`` value already on the finding is still discarded: the
    schema marks the field ``readOnly``, and a hunter that emitted one anyway
    must not be able to pre-load its own verdict.

    ``run_id``/``task_id``/``repo``/``scratch_dir``/``execution_available`` are
    kept in the signature because callers pass them and because the nonce is
    worth recording — but none of them can now produce a promotion.
    """
    finding.pop("execution", None)
    poc = finding.get("poc") or {}
    verdict = placeholder_verdict(
        nonce=nonce_for(run_id, task_id),
        # Recorded next to the gate's later verdict so a divergence is
        # auditable. Never believed: `proven` does not consult it.
        model_claimed_success=poc.get("succeeded") if poc else None,
    )
    finding["execution"] = verdict.to_dict()
    return finding["execution"]


#: Outcome that promotes. Kept as a set so the merge below reads as the rule it
#: is rather than a string comparison.
_PROMOTING_OUTCOMES = frozenset({"proven"})


def _decisive_verdict(proof: dict, outcome: str) -> dict:
    """The per-run verdict that explains the record's aggregate outcome.

    A proof record holds one verdict per repeat. The run that matches the
    aggregate outcome is the one whose evidence explains it; if none matches
    (a record written by something other than ``replay.py``), the first run
    will do, and an empty ``runs`` list yields ``{}`` rather than raising.
    """
    runs = proof.get("runs")
    if not isinstance(runs, list):
        return {}
    verdicts = [
        run.get("verdict") for run in runs
        if isinstance(run, dict) and isinstance(run.get("verdict"), dict)
    ]
    for verdict in verdicts:
        if verdict.get("outcome") == outcome:
            return verdict
    return verdicts[0] if verdicts else {}


def apply_proof(finding: dict, proof: dict | None) -> dict:
    """Merge ``proof/<id>.json``'s verdict into ``finding["execution"]``.

    This is the seam C-1 was missing. ``replay.py`` produced a verdict from a
    transcript it captured itself and wrote it to ``proof/<id>.json``; nothing
    read it back, so the report kept quoting the placeholder — or, before this
    fix, the verdict derived from agent-authored text.

    **Promotion-only, by construction.** The merge may:

    * raise an outcome to ``proven`` (the whole point);
    * replace a placeholder with a better-evidenced non-proven outcome;

    and it may **never**:

    * delete the finding — a failed PoC is a fact about the PoC, a missing
      dependency is a fact about the environment, and neither is a reason to
      lose a candidate vulnerability;
    * demote an existing ``proven`` to anything weaker.

    A missing or malformed proof record leaves the finding exactly as it was.
    That is the ``not_attempted`` case and it is not an error: phase 2b may
    simply not have run.

    Returns the finding (mutated in place) for convenient chaining.
    """
    if not isinstance(proof, dict) or not proof:
        return finding

    current = finding.get("execution") or {}
    if current.get("outcome") in _PROMOTING_OUTCOMES:
        # Nothing demotes. A second, weaker replay does not erase the first
        # proof; it is recorded in the proof file and visible there.
        return finding

    outcome = proof.get("outcome")
    if not isinstance(outcome, str) or not outcome:
        return finding

    # `replay.ProofRecord.to_dict()` carries the AGGREGATE outcome at the top
    # level, but the per-verdict detail — the marker lines that carried the
    # decision, the event counts, whether the observer armed — lives on each
    # run's own verdict. Reading those from the top level alone silently
    # produced an empty evidence list and zero counts for every real replay
    # record, so the decisive run is consulted as a fallback.
    detail = _decisive_verdict(proof, outcome)

    def field(name, default):
        if name in proof:
            return proof[name]
        return detail.get(name, default)

    proven = outcome in _PROMOTING_OUTCOMES
    execution = {
        "outcome": outcome,
        # Never `proof["proven"]` — `proven` is derived from the outcome so the
        # two cannot disagree. A proof record claiming `proven: true` under an
        # outcome of `no_event` promotes nothing.
        "proven": proven,
        "reason": str(proof.get("reason") or ""),
        "evidence": list(field("evidence", []) or []),
        "events_seen": int(field("events_seen", 0) or 0),
        "events_attributed": int(field("events_attributed", 0) or 0),
        "observer_armed": bool(field("observer_armed", False)),
        "nonce": proof.get("nonce"),
        # What the agent claimed survives the merge: the gate replaces the
        # verdict, not the record of the disagreement.
        "model_claimed_success": current.get("model_claimed_success"),
        # Contract A's counter-forgery signal, carried from the proof record so
        # `report_build` can surface it without re-reading proof/.
        "forged_lines": int(proof.get("forged_marker_lines") or 0),
        "markers_signed": bool(proof.get("markers_verified")),
        # Provenance, so "where did this verdict come from" is answerable from
        # the finding alone.
        "source": "replay",
        "repeats_completed": int(proof.get("repeats_completed") or 0),
        "unanimous": bool(proof.get("unanimous")),
        "promotion_blocked": list(proof.get("promotion_blocked") or []),
    }
    execution["contradicts_model"] = bool(
        execution["model_claimed_success"]) and not proven
    finding["execution"] = execution
    return finding


def apply_proofs(results_dir: str | Path) -> dict[str, str]:
    """Apply every stored proof record to its finding, and persist.

    Phase 2b writes proof records per finding; this is the batch that folds them
    into the findings the report reads. Returns ``{finding_id: outcome}`` for
    what changed, so a caller can print it.
    """
    proofs = load_proofs(results_dir)
    applied: dict[str, str] = {}
    for finding_id, proof in proofs.items():
        finding = load_finding(results_dir, finding_id)
        if finding is None:
            continue
        before = (finding.get("execution") or {}).get("outcome")
        before_class = finding.get("vuln_class")
        apply_proof(finding, proof)
        # D-18. The gate knows what it observed; the label did not. A `proven`
        # verdict carrying an exec/compile event IS a code execution whatever
        # the hunter called it, and the run's single proven finding was filed
        # as `improper_input_handling` for want of this feedback. Only ever
        # moves a catch-all label toward the evidence, and records the original.
        upgraded = taxonomy.upgrade_for_evidence(finding, proof)
        after = (finding.get("execution") or {}).get("outcome")
        if after != before or upgraded:
            write_finding(results_dir, finding)
            applied[finding_id] = after or ""
            if upgraded:
                print(f"class upgraded on evidence: {finding_id} "
                      f"{before_class!r} -> {upgraded!r}", file=sys.stderr)
    return applied


def repair_classes(results_dir: str | Path) -> list[dict]:
    """Replace catch-all classes with the class their own CWE names.

    Recall matters here, not tidiness: nine findings on the recorded run were
    `improper_input_handling` + CWE-674, which is `uncontrolled_recursion` — a
    class that routes to the resource lens and is eligible for a `growth_curve`
    probe. They were outside the second oracle's reach purely because of a
    label.
    """
    changed: list[dict] = []
    for finding in load_findings(results_dir):
        before = finding.get("vuln_class")
        after = taxonomy.repair_class(finding)
        if after:
            write_finding(results_dir, finding)
            changed.append({"finding_id": finding.get("finding_id"),
                            "from": before, "to": after,
                            "cwe": finding.get("cwe")})
    return changed


def check_class_consistency(results_dir: str | Path) -> list[dict]:
    """Every finding whose label disagrees with its own CWE. Advisory.

    Never deletes and never blocks: a finding whose class was guessed is still
    a real defect. But the disagreement has to surface while the run is going,
    because by report time it has already corrupted routing, dedupe grouping
    and every CWE-keyed consumer downstream.
    """
    out: list[dict] = []
    for finding in load_findings(results_dir):
        problems = taxonomy.consistency_errors(finding)
        if problems:
            out.append({
                "finding_id": finding.get("finding_id"),
                "file": finding.get("file"),
                "vuln_class": finding.get("vuln_class"),
                "cwe": finding.get("cwe"),
                "problems": problems,
            })
    return out


def structural_dir(results_dir: str | Path) -> Path:
    return Path(results_dir) / "structural"


def load_structural(results_dir: str | Path) -> dict[str, dict]:
    """Every stored structural verdict, keyed by finding_id."""
    directory = structural_dir(results_dir)
    out: dict[str, dict] = {}
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.json")):
        record = _read_json(path, default=None)
        if isinstance(record, dict):
            out[record.get("finding_id") or path.stem] = record
    return out


#: Structural outcomes that raise a finding's standing. One, deliberately —
#: `oracle.structural.CORROBORATING` says the same thing on the oracle side.
_CORROBORATING_STRUCTURAL = frozenset({"demonstrated"})


def apply_structural(finding: dict, record: dict | None) -> dict:
    """Merge ``structural/<id>.json``'s verdict into ``finding["structural"]``.

    Same discipline as :func:`apply_proof`, and one extra rule that matters:

    * a ``demonstrated`` verdict is **never** written into ``execution``. It is
      not ``proven`` and it must not be countable as ``proven`` by a consumer
      that reads only one field. The two live in separate keys because they are
      separate claims, and ``report_build`` counts them under separate
      denominators.
    * ``refuted`` is recorded rather than dropped. It is evidence *against* the
      finding, it never deletes anything, and ``phase2c_verify.md`` requires a
      verifier confirming past it to say why in writing.
    * nothing demotes: an existing ``demonstrated`` survives a later
      ``probe_error`` (a container that would not start says nothing).
    """
    if not isinstance(record, dict) or not record:
        return finding

    verdict = record.get("verdict") if isinstance(record.get("verdict"), dict) else record
    outcome = verdict.get("outcome")
    if not isinstance(outcome, str) or not outcome:
        return finding

    current = finding.get("structural") or {}
    if current.get("outcome") in _CORROBORATING_STRUCTURAL:
        return finding

    finding["structural"] = {
        "outcome": outcome,
        # Derived from the outcome so the two cannot disagree, exactly as
        # `execution.proven` is.
        "demonstrated": outcome in _CORROBORATING_STRUCTURAL,
        "refuted": outcome == "refuted",
        "probe_kind": verdict.get("probe_kind") or record.get("probe_kind"),
        "reason": str(verdict.get("reason") or ""),
        "conditions": dict(verdict.get("conditions") or {}),
        "measurements": dict(verdict.get("measurements") or {}),
        "evidence": list(verdict.get("evidence") or []),
    }
    return finding


def apply_structurals(results_dir: str | Path) -> dict[str, str]:
    """Apply every stored structural verdict to its finding, and persist."""
    applied: dict[str, str] = {}
    for finding_id, record in load_structural(results_dir).items():
        finding = load_finding(results_dir, finding_id)
        if finding is None:
            continue
        before = (finding.get("structural") or {}).get("outcome")
        apply_structural(finding, record)
        after = (finding.get("structural") or {}).get("outcome")
        if after != before:
            write_finding(results_dir, finding)
            applied[finding_id] = after or ""
    return applied


def structural_outcome(finding: dict) -> str | None:
    """The structural oracle's outcome, or None if no probe ever ran."""
    outcome = (finding.get("structural") or {}).get("outcome")
    return str(outcome) if outcome else None


def structurally_demonstrated(finding: dict) -> bool:
    """Deterministically demonstrated — **not** proven. Never merge the two."""
    return bool((finding.get("structural") or {}).get("demonstrated"))


def poc_succeeded(finding: dict, *, allow_model_claim: bool = False) -> bool:
    """Was this finding proven by execution?

    The one field every downstream consumer reads as "confirmed by execution".
    It is the gate's ``execution.proven`` and nothing else.

    ``allow_model_claim`` restores ``state.py``'s narrow fallback to the
    hunter's own ``poc.succeeded`` for findings that never passed a gate. It
    exists for importing archived VASH rows and must stay off for anything this
    skill produced — see the module docstring.
    """
    execution = finding.get("execution") or {}
    if execution:
        return bool(execution.get("proven"))
    if allow_model_claim:
        return bool((finding.get("poc") or {}).get("succeeded"))
    return False


def execution_outcome(finding: dict) -> str | None:
    """The gate's outcome for this finding, or None if it never ran.

    None is a distinct answer from any of the eight outcomes and must stay
    distinct: ``not_attempted`` means "the environment could not run a PoC",
    while None means "the harness never asked the gate" — a bug in PyHunt, not
    a fact about the target. Collapsing them hides the bug.
    """
    execution = finding.get("execution") or {}
    outcome = execution.get("outcome")
    return str(outcome) if outcome else None


def contradicts_model(finding: dict) -> bool:
    """The hunter claimed a successful PoC and the gate disagreed.

    Not an error — the model may be reading assertions the observer cannot see.
    Worth counting: a rising rate means either the payload templates stopped
    embedding the nonce or the prompt has drifted into over-claiming, and
    neither is visible from a single finding.
    """
    return bool((finding.get("execution") or {}).get("contradicts_model"))


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def _unwrap(record: Any) -> list[dict]:
    """Findings out of whatever shape phase 2 actually wrote.

    Two shapes are in circulation and both are documented somewhere:

    * the **flat** finding, which :func:`record_finding` emits and every test
      fixture uses;
    * the **HuntOutput envelope** ``{"task_id":…, "findings":[…],
      "gaps_observed":[…]}``, which ``phases/phase2_hunt.md`` and
      ``references/output-contracts.md`` instruct the hunting agent to write.

    Reading only the first silently discards every finding a hunt agent wrote
    exactly as specified — the reader and the specification disagreeing while
    both look correct in isolation. ``replay.load_poc`` already accepts both;
    this is the other half.
    """
    if not isinstance(record, dict):
        return []
    if record.get("finding_id"):
        return [record]
    nested = record.get("findings")
    if isinstance(nested, list):
        # The envelope's `task_id` is carried DOWN into each finding it wraps.
        # Unwrapping without it silently deleted provenance the schema names
        # and three consumers read: `coverage.py` attributes findings to tasks
        # through `task_id`, and the payload nonce is derived from
        # (run_id, task_id), so a finding that loses it becomes both
        # uncountable and unreplayable. `record_finding` injects the same field
        # on the write path; this is the read path agreeing with it.
        envelope_task = record.get("task_id")
        out = []
        for finding in nested:
            if not isinstance(finding, dict) or not finding.get("finding_id"):
                continue
            if envelope_task and not finding.get("task_id"):
                finding = {**finding, "task_id": envelope_task}
            out.append(finding)
        return out
    return []


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: unreadable JSON ({exc})") from exc


def _write_json(path: Path, payload: Any) -> Path:
    """Write atomically: a phase may be reading this directory concurrently,
    and a half-written findings file is indistinguishable from a corrupt one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")
    os.replace(tmp, path)
    return path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def finding_path(results_dir: str | Path, finding_id: str) -> Path:
    return findings_dir(results_dir) / f"{_safe_id(finding_id)}.json"


def _safe_id(finding_id: str) -> str:
    """Reject an id that would escape the findings directory.

    ``finding_id`` is model-authored. The schema constrains it to
    ``^f_[a-z0-9_-]{1,64}$``, but this module is also called on findings that
    have not been validated yet (validation reports errors, it does not stop
    the record from being written — nothing may delete a finding). So the path
    join is guarded here rather than trusting the schema to have run.
    """
    ident = str(finding_id or "").strip()
    if not ident or "/" in ident or "\\" in ident or ident.startswith("."):
        raise ValueError(f"unusable finding_id for a filename: {finding_id!r}")
    return ident


def write_finding(results_dir: str | Path, finding: dict) -> Path:
    """Persist a finding record verbatim. No gating, no validation.

    The raw persist, used when something other than the hunt is updating an
    existing record — a severity re-derived from CVSS, a dedupe group
    assignment. :func:`record_finding` is the one that attaches the placeholder
    execution block; :func:`apply_proof` is the one that can promote.
    """
    finding = dict(finding)
    finding["recorded_at"] = _now()
    return _write_json(finding_path(results_dir, finding["finding_id"]), finding)


def record_finding(
    results_dir: str | Path,
    finding: dict,
    *,
    task_id: str,
    run_id: str,
    repo: str | Path,
    scratch_dir: str | Path,
    execution_available: bool,
    schemas_dir: str | Path | None = None,
) -> dict:
    """Record a freshly-emitted finding with an unjudged execution block.

    Returns ``{"finding_id", "path", "outcome", "proven", "contradicts_model",
    "schema_errors", "gate_error"}``. ``proven`` is always False here: nothing
    a hunt agent submits can promote itself, because the only text this
    function has access to is text that agent wrote. Promotion happens later,
    in :func:`apply_proof`, from ``replay.py``'s own observer transcript.

    A schema error is *reported*, never fatal — a hunter that
    wrote a 19-character description has produced a slightly malformed record
    of a possibly-real vulnerability, and dropping it to keep the corpus tidy
    is the failure mode this whole tool is built against.
    """
    finding = dict(finding)
    finding["task_id"] = task_id
    gate_error = ""
    try:
        gate_finding(
            finding,
            run_id=run_id,
            task_id=task_id,
            repo=repo,
            scratch_dir=scratch_dir,
            execution_available=execution_available,
        )
    except Exception as exc:  # gate must never lose a finding
        gate_error = f"{type(exc).__name__}: {exc}"

    errors = validate_finding(finding, schemas_dir)
    path = write_finding(results_dir, finding)
    return {
        "finding_id": finding.get("finding_id"),
        "path": str(path),
        "outcome": execution_outcome(finding),
        "proven": poc_succeeded(finding),
        "contradicts_model": contradicts_model(finding),
        "schema_errors": errors,
        "gate_error": gate_error,
    }


def record_hunt_output(
    results_dir: str | Path,
    payload: dict,
    *,
    run_id: str,
    repo: str | Path,
    scratch_dir: str | Path,
    execution_available: bool,
    task_id: str | None = None,
    schemas_dir: str | Path | None = None,
) -> dict:
    """Record one hunt task's whole output: every finding, plus its gaps.

    ``gaps_observed`` is not optional politeness — an empty array asserts the
    hunter examined everything in scope, and the sweep phase believes it. It is
    appended to ``gaps.json`` so a gap that was reported cannot be lost between
    phases, which would turn a disclosed limitation into implied coverage.
    """
    envelope_errors = validate_hunt_output(payload, schemas_dir)
    task = str(task_id or payload.get("task_id") or "")
    if not task:
        raise ValueError(
            "hunt output has no task_id and none was supplied — the nonce is "
            "derived from (run_id, task_id), so the gate cannot judge without it"
        )

    recorded = [
        record_finding(
            results_dir,
            finding,
            task_id=task,
            run_id=run_id,
            repo=repo,
            scratch_dir=scratch_dir,
            execution_available=execution_available,
            schemas_dir=schemas_dir,
        )
        for finding in (payload.get("findings") or [])
    ]
    gaps = append_gaps(results_dir, task, payload.get("gaps_observed") or [])
    return {
        "task_id": task,
        "recorded": recorded,
        "findings": len(recorded),
        "proven": sum(1 for r in recorded if r["proven"]),
        "overclaimed": sum(1 for r in recorded if r["contradicts_model"]),
        "gaps_recorded": gaps,
        "envelope_schema_errors": envelope_errors,
    }


def append_gaps(results_dir: str | Path, task_id: str, gaps: list[dict]) -> int:
    """Append this task's coverage gaps to ``gaps.json``. Returns how many."""
    path = gaps_path(results_dir)
    doc = _read_json(path, default={"gaps": []}) or {"gaps": []}
    existing = doc.get("gaps") or []
    for gap in gaps:
        existing.append({**gap, "task_id": task_id})
    doc["gaps"] = existing
    _write_json(path, doc)
    return len(gaps)


def load_finding(results_dir: str | Path, finding_id: str) -> dict | None:
    """One finding by id, from either on-disk shape (see :func:`_unwrap`).

    Falls back to a scan when the file named for the id holds an envelope whose
    findings carry different ids — a hunt agent may legitimately write several
    findings for one task into one file named after the task.
    """
    try:
        record = _read_json(finding_path(results_dir, finding_id), default=None)
    except ValueError:
        record = None
    for finding in _unwrap(record):
        if finding.get("finding_id") == finding_id:
            return finding
    for finding in iter_findings(results_dir):
        if finding.get("finding_id") == finding_id:
            return finding
    return None


def iter_findings(results_dir: str | Path) -> Iterator[dict]:
    """Every stored finding, in a stable (filename-sorted) order.

    Deterministic order matters: it decides the representative in duplicate
    partitioning and the order findings appear in the report, and a run that
    reorders its own output between invocations is impossible to diff.

    Files whose name starts with ``_`` are skipped, so a future index or
    sidecar can live in the same directory without being mistaken for a
    finding.
    """
    directory = findings_dir(results_dir)
    if not directory.is_dir():
        return
    seen: dict[str, dict] = {}
    order: list[str] = []
    for path in sorted(directory.glob("*.json")):
        if path.name.startswith("_"):
            continue
        try:
            record = _read_json(path, default=None)
        except ValueError:
            # A corrupt file is one unreadable finding, not a dead run. Losing
            # every other finding — and the whole report — because one file was
            # half-written is the "nothing may delete a finding" rule failing in
            # the most expensive possible way.
            continue
        for finding in _unwrap(record):
            fid = finding["finding_id"]
            previous = seen.get(fid)
            if previous is None:
                seen[fid] = finding
                order.append(fid)
            elif finding.get("execution") and not previous.get("execution"):
                # The same finding reached disk twice: once inside the hunt
                # agent's envelope and once flat, after a phase wrote it back.
                # The gated copy is the one the report must read.
                seen[fid] = finding
    for fid in order:
        yield seen[fid]


def load_findings(results_dir: str | Path) -> list[dict]:
    return list(iter_findings(results_dir))


def set_group(
    results_dir: str | Path, finding_id: str, group_id: str | None, is_canonical: bool
) -> dict:
    """Assign a finding to a dedupe/sibling group. Replaces
    ``state.py``'s ``assign_finding_group``.

    A demoted (non-canonical) member is not deleted and not hidden — the report
    renders it under its canonical's "Also at:", so every co-located confirmed
    site stays visible without inflating the headline count.
    """
    record = load_finding(results_dir, finding_id)
    if record is None:
        raise ValueError(f"no such finding: {finding_id}")
    record["group_id"] = group_id
    record["is_canonical"] = bool(is_canonical)
    write_finding(results_dir, record)
    return record


def apply_dedupe_groups(results_dir: str | Path, groups: list[dict]) -> dict:
    """Assign every finding to its cluster, promoting one canonical PER FILE.

    The clustering itself is a semantic judgement and stays with the model. The
    promotion rule is not, and it is the part that was getting findings buried:
    a dedupe agent picks ONE canonical per group, and when a group spans files
    that silently drops a confirmed match living in a different file from the
    canonical — never delivered, never even mentioned. So a distinct file
    inside a group earns its own canonical.

    Two details that look like fussiness and are not:

    * Member ids are de-duplicated first (``dict.fromkeys``, order-preserving).
      The promotion is stateful in ``files_seen``, so a repeated id would be
      evaluated twice and its second pass could re-bury a finding the first
      pass had just promoted.
    * A member with no known file is never promoted on the strength of its
      absence — ``file is not None`` is load-bearing, or every unknown-file
      member in a group would become a headline.

    Safe by construction: promotion never invents a finding, and a promoted
    member is one the clusterer already placed in this group.
    """
    by_id = {f["finding_id"]: f for f in iter_findings(results_dir)}
    assigned = 0
    canonicals = 0
    for group in groups:
        group_id = group["group_id"]
        canonical = group.get("canonical_finding_id")
        files_seen = {(by_id.get(canonical) or {}).get("file")}
        for finding_id in dict.fromkeys(group.get("member_finding_ids") or []):
            file = (by_id.get(finding_id) or {}).get("file")
            is_canon = finding_id == canonical or (
                file is not None and file not in files_seen
            )
            if is_canon:
                files_seen.add(file)
                canonicals += 1
            if finding_id in by_id:
                set_group(results_dir, finding_id, group_id, is_canon)
                assigned += 1
    return {"groups": len(groups), "findings_assigned": assigned,
            "canonicals_promoted": canonicals}


def dedupe_fallback_groups(findings: list[dict]) -> list[dict]:
    """One group per finding, every one canonical.

    What to apply when clustering could not run. Deliberately the
    least-destructive fallback available: over-reporting duplicates is a
    readability cost, while collapsing findings on a guess loses them.
    """
    groups = []
    for finding in findings:
        finding_id = finding["finding_id"]
        suffix = finding_id[2:] if finding_id.startswith("f_") else finding_id
        groups.append({
            "group_id": f"g_{suffix}",
            "root_cause": str(finding.get("description") or "")[:200],
            "canonical_finding_id": finding_id,
            "member_finding_ids": [finding_id],
        })
    return groups


def set_severity(results_dir: str | Path, finding_id: str, severity: str) -> dict:
    """Overwrite a finding's severity.

    Used when a confirmed finding's CVSS vector yields a mapped qualitative
    band: that band supersedes the hunter's own (model-assigned) severity as
    the authoritative value the report reads. Arithmetic decided in Python
    beats a model's adjective — see ``validate_gates.py``.
    """
    record = load_finding(results_dir, finding_id)
    if record is None:
        raise ValueError(f"no such finding: {finding_id}")
    record["severity"] = severity
    write_finding(results_dir, record)
    return record


# --------------------------------------------------------------------------
# Sidecar artifacts: proof (phase 2b) and verification (phase 2c)
# --------------------------------------------------------------------------

def save_proof(results_dir: str | Path, finding_id: str, payload: dict) -> Path:
    """Store phase 2b's replay transcript + gate verdict for one finding."""
    return _write_json(proof_dir(results_dir) / f"{_safe_id(finding_id)}.json", payload)


def load_proof(results_dir: str | Path, finding_id: str) -> dict | None:
    return _read_json(proof_dir(results_dir) / f"{_safe_id(finding_id)}.json", default=None)


def save_verification(results_dir: str | Path, finding_id: str, payload: dict) -> Path:
    """Store phase 2c's adversarial-disproof verdict for one finding."""
    return _write_json(verify_dir(results_dir) / f"{_safe_id(finding_id)}.json", payload)


def load_verification(results_dir: str | Path, finding_id: str) -> dict | None:
    return _read_json(verify_dir(results_dir) / f"{_safe_id(finding_id)}.json", default=None)


def load_verifications(results_dir: str | Path) -> dict[str, dict]:
    """Every stored verification, keyed by finding_id."""
    directory = verify_dir(results_dir)
    out: dict[str, dict] = {}
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.json")):
        record = _read_json(path, default=None)
        if isinstance(record, dict):
            out[record.get("finding_id") or path.stem] = record
    return out


def load_proofs(results_dir: str | Path) -> dict[str, dict]:
    """Every stored proof transcript, keyed by finding_id."""
    directory = proof_dir(results_dir)
    out: dict[str, dict] = {}
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.json")):
        record = _read_json(path, default=None)
        if isinstance(record, dict):
            out[record.get("finding_id") or path.stem] = record
    return out


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _summarise(record: dict) -> dict:
    return {
        "finding_id": record.get("finding_id"),
        "task_id": record.get("task_id"),
        "file": record.get("file"),
        "line_start": record.get("line_start"),
        "vuln_class": record.get("vuln_class"),
        "severity": record.get("severity"),
        "outcome": execution_outcome(record),
        "proven": poc_succeeded(record),
        "group_id": record.get("group_id"),
        "is_canonical": record.get("is_canonical"),
    }


def _cmd_record(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.results_dir)
    run_id = args.run_id or manifest.get("run_id")
    repo = args.repo or manifest.get("target")
    if not run_id:
        print("--run-id is required (no run_id in manifest.json)", file=sys.stderr)
        return 2
    if not repo:
        print("--repo is required (no target in manifest.json)", file=sys.stderr)
        return 2

    raw = sys.stdin.read() if args.hunt_output == "-" else Path(args.hunt_output).read_text()
    payload = json.loads(raw)
    result = record_hunt_output(
        args.results_dir,
        payload,
        run_id=run_id,
        repo=repo,
        scratch_dir=args.scratch or Path(args.results_dir) / "logs",
        execution_available=args.execution_available,
        task_id=args.task_id,
    )

    for entry in result["recorded"]:
        if entry["gate_error"]:
            print(
                f"gate failed for {entry['finding_id']} ({entry['gate_error']}) "
                f"— finding kept, unpromoted",
                file=sys.stderr,
            )
        if entry["schema_errors"]:
            print(
                f"{entry['finding_id']}: schema errors {entry['schema_errors']} "
                f"— finding kept",
                file=sys.stderr,
            )
    if result["overclaimed"]:
        print(
            f"{result['overclaimed']}/{result['findings']} findings claimed an "
            f"executed PoC the evidence did not support",
            file=sys.stderr,
        )
    # A hunted task must say so, even when it found nothing. Without this the
    # coverage ledger cannot tell a clean sweep from a task nobody ran, and
    # `coverage_complete` stays false however thorough the hunt was.
    task_id = args.task_id or payload.get("task_id")
    if task_id:
        try:
            from coverage import record_task_outcome

            record_task_outcome(
                args.results_dir, str(task_id),
                "findings" if result["findings"] else "clean",
                findings=int(result["findings"]),
                note="recorded by findings_io record",
            )
        except Exception as exc:  # never fail a recorded finding over bookkeeping
            print(f"could not record task outcome for {task_id}: {exc}",
                  file=sys.stderr)

    print(json.dumps(result, indent=2))
    return 0


def _cmd_class_repair(args: argparse.Namespace) -> int:
    changed = repair_classes(args.results_dir)
    print(json.dumps({"repaired": len(changed), "changes": changed}, indent=2))
    if changed:
        print(f"{len(changed)} finding(s) re-labelled from a catch-all to the "
              "class their CWE names. Re-run dedupe and the probe gate: routing "
              "and probe eligibility both key on vuln_class.", file=sys.stderr)
    return 0


def _cmd_class_check(args: argparse.Namespace) -> int:
    """Advisory, never fatal. A mislabelled finding is still a real finding."""
    problems = check_class_consistency(args.results_dir)
    print(json.dumps({"inconsistent": len(problems), "findings": problems},
                     indent=2))
    if problems:
        print(f"{len(problems)} finding(s) carry a class that disagrees with "
              "their own CWE. This corrupts routing, dedupe grouping and every "
              "CWE-keyed consumer downstream — fix the labels before phase 4.",
              file=sys.stderr)
    return 0


def _cmd_apply_structural(args: argparse.Namespace) -> int:
    """Phase 2b's second step: make the structural verdicts count.

    Exit 0 even when nothing changed — a run whose findings declared no probes
    is a run with no structural evidence, which is a result and not a failure.
    Note that `refuted` counts as "changed": a deterministic demonstration that
    a defence works is exactly as much a result as a demonstration that it does
    not, and phase 2c is required to read it.
    """
    applied = apply_structurals(args.results_dir)
    demonstrated = sorted(k for k, v in applied.items() if v == "demonstrated")
    refuted = sorted(k for k, v in applied.items() if v == "refuted")
    print(json.dumps({
        "applied": applied,
        "demonstrated": demonstrated,
        "refuted": refuted,
        "demonstrated_count": len(demonstrated),
        "refuted_count": len(refuted),
        "updated": len(applied),
        "note": ("`demonstrated` is not `proven`. It is never written into "
                 "`execution`, and the report counts it under its own "
                 "denominator."),
    }, indent=2))
    if refuted:
        print(f"{len(refuted)} finding(s) were structurally REFUTED — phase 2c "
              "must address each in writing before confirming it",
              file=sys.stderr)
    return 0


def _cmd_apply_proofs(args: argparse.Namespace) -> int:
    """Phase 2b's last step: make the proof records count.

    Without this, `proof/<id>.json` is an artifact nobody reads and the report
    quotes a placeholder — which was defect C-1. Exit 0 even when nothing
    changed: a run with no proof records is a run that did not replay, not a
    failure of this command.
    """
    applied = apply_proofs(args.results_dir)
    promoted = sorted(k for k, v in applied.items() if v == "proven")
    print(json.dumps({
        "applied": applied,
        "promoted": promoted,
        "proven": len(promoted),
        "updated": len(applied),
    }, indent=2))
    if not applied:
        print("no proof record changed a finding — if phase 2b ran, check that "
              "proof/ is populated and that its finding_ids match findings/",
              file=sys.stderr)
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    findings = load_findings(args.results_dir)
    print(json.dumps(
        {"findings": [_summarise(f) for f in findings], "total": len(findings)},
        indent=2,
    ))
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    record = load_finding(args.results_dir, args.finding_id)
    if record is None:
        print(f"no such finding: {args.finding_id}", file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2))
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    problems = {}
    findings = load_findings(args.results_dir)
    for record in findings:
        errors = validate_finding(record)
        if errors:
            problems[record["finding_id"]] = errors
    print(json.dumps(
        {"checked": len(findings), "invalid": len(problems), "errors": problems},
        indent=2,
    ))
    if problems:
        print(f"{len(problems)} of {len(findings)} stored findings do not match "
              f"the schema", file=sys.stderr)
        return 2
    return 0


def _cmd_set_group(args: argparse.Namespace) -> int:
    record = set_group(args.results_dir, args.finding_id, args.group_id, args.canonical)
    print(json.dumps(_summarise(record), indent=2))
    return 0


def _cmd_dedupe(args: argparse.Namespace) -> int:
    if args.groups:
        raw = sys.stdin.read() if args.groups == "-" else Path(args.groups).read_text()
        payload = json.loads(raw)
        groups = payload.get("groups") if isinstance(payload, dict) else payload
    else:
        groups = dedupe_fallback_groups(load_findings(args.results_dir))
        print("no clusters supplied — falling back to one group per finding, all "
              "canonical (over-reporting duplicates beats losing findings)",
              file=sys.stderr)
    result = apply_dedupe_groups(args.results_dir, groups or [])
    print(json.dumps(result, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="findings_io.py",
        description="Read, write, and gate findings in a PyHunt results directory.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    record = sub.add_parser(
        "record",
        help="gate a hunt task's output and store each finding",
    )
    record.add_argument("--results-dir", required=True)
    record.add_argument("--hunt-output", required=True,
                        help="path to the hunt task's JSON output, or - for stdin")
    record.add_argument("--repo", help="target repo path (default: manifest.target)")
    record.add_argument("--run-id", help="default: manifest.run_id")
    record.add_argument("--task-id", help="default: the output's own task_id")
    record.add_argument("--scratch", help="the task's scratch dir, where its PoC was written")
    record.add_argument("--execution-available", action="store_true",
                        help="PoCs actually ran in a sandbox; without this the "
                             "gate records not_attempted, which is never a "
                             "verdict about the code")
    record.set_defaults(func=_cmd_record)

    listing = sub.add_parser("list", help="summarise every stored finding")
    listing.add_argument("--results-dir", required=True)
    listing.set_defaults(func=_cmd_list)

    apply_p = sub.add_parser(
        "apply-proofs",
        help="fold phase 2b's proof records into their findings (promotion-only)",
    )
    apply_p.add_argument("--results-dir", required=True)
    apply_p.set_defaults(func=_cmd_apply_proofs)

    apply_s = sub.add_parser(
        "apply-structural",
        help=("fold the structural oracle's verdicts into their findings "
              "(corroboration-only; never writes `execution`)"),
    )
    apply_s.add_argument("--results-dir", required=True)
    apply_s.set_defaults(func=_cmd_apply_structural)

    class_check = sub.add_parser(
        "class-check",
        help="list findings whose vuln_class disagrees with their CWE (D-18)",
    )
    class_check.add_argument("--results-dir", required=True)
    class_check.set_defaults(func=_cmd_class_check)

    class_repair = sub.add_parser(
        "class-repair",
        help="rewrite catch-all classes to the class their CWE names (D-18)",
    )
    class_repair.add_argument("--results-dir", required=True)
    class_repair.set_defaults(func=_cmd_class_repair)

    show = sub.add_parser("show", help="print one stored finding verbatim")
    show.add_argument("--results-dir", required=True)
    show.add_argument("--finding-id", required=True)
    show.set_defaults(func=_cmd_show)

    validate = sub.add_parser("validate", help="schema-check every stored finding")
    validate.add_argument("--results-dir", required=True)
    validate.set_defaults(func=_cmd_validate)

    group = sub.add_parser("set-group", help="assign a finding to a dedupe group")
    group.add_argument("--results-dir", required=True)
    group.add_argument("--finding-id", required=True)
    group.add_argument("--group-id", required=True)
    group.add_argument("--canonical", action="store_true")
    group.set_defaults(func=_cmd_set_group)

    dedupe = sub.add_parser(
        "dedupe",
        help="apply clusters, promoting one canonical per distinct file",
    )
    dedupe.add_argument("--results-dir", required=True)
    dedupe.add_argument("--groups", help="clusters JSON ({groups:[...]} or a bare "
                                         "list), or - for stdin. Omit to fall "
                                         "back to one group per finding.")
    dedupe.set_defaults(func=_cmd_dedupe)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
