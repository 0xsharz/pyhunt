"""Assemble ``report.json`` from a results directory. Every number, in Python.

Phase 4 writes the advisory's prose. This module produces the object that prose
describes, and the division is not stylistic: **no figure in the report may
originate in a model.** Counts, CVSS scores, coverage denominators, the
proven/provable split and the achieved isolation tier are all computed here,
from files on disk, so a report cannot claim a scan did more than it did.

That rule is inherited from the stage this module replaces. ``stages/report.py``
handed the whole payload to a report agent and then *overwrote* the parts that
mattered with values re-read from run state — a long sequence of ``_attach_*``
calls, each with a comment explaining which disclosure the agent had dropped or
misrepresented on a real run. Measured examples from that file's history:

* five delivered findings, every one with a successful executed PoC, and **zero
  observer lines anywhere in the report** — the agent never emitted ``poc``, so
  the reproduction evidence that is this tool's entire differentiator was
  invisible;
* ``done=54 failed=1`` — one hunt task died to a repeated API error, meaning an
  entire attack angle was never examined, and **nothing in the delivered report
  said so**. The reader saw "source_files: 161, covered_files: 159" and would
  reasonably have concluded the sweep was complete.

Both are the same failure: silence reads as coverage. So every disclosure the
old ``_attach_*`` helpers injected post-hoc is computed here up front, and the
model never has the opportunity to leave one out.

Two honest notes about what this build cannot know, stated here rather than
emitted as a confident zero:

* **There is no cost or token ledger.** That lived in the deleted runner's
  SQLite ``costs`` table. ``scan_metrics`` therefore omits ``cost_usd`` and
  ``tokens_by_phase`` rather than reporting them as 0.0.
* **Task outcomes are only as good as ``tasks.json``.** If task records carry
  no ``status``, coverage cannot be asserted complete, and the report says
  exactly that instead of assuming success.

Delivery selection, and the one place it deliberately overrules everything
else: a finding whose execution gate returned ``proven`` is **always**
delivered — not overridden by an adversarial verifier that rejected it, and
not demoted by dedupe for losing a canonical coin-toss. The gate saw a
nonce-attributed, target-framed, interpreted dangerous operation in this
finding's own file. Nothing downstream gets to erase that; a disagreement is
disclosed on the finding instead.

Model prose enters through exactly one door, ``merge_narrative``, and it is a
whitelist: ``title``/``description``/``impact``/``exploit_scenario``/
``preconditions``/``how_to_fix``/``recommendation`` per finding, plus
``threat_model``. Everything else in the payload is computed here, and a
narrative that carries a computed field has it discarded and reported. The
merge happens BEFORE redaction, so prose is masked like every other field.
"""

from __future__ import annotations

import _bootstrap  # noqa: F401  (must precede any third-party import)

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import findings_io
from cvss import rating as cvss_rating
from cvss import score as cvss_base_score
from json_utils import validate_schema
from validate_gates import severity_from_cvss_rating
from oracle import classes as vuln_classes
from oracle.markers import MARKER as OBSERVER_MARKER
from redact import redact_json

# How much executed-PoC material the report carries per finding. The PoC code
# is the reproduction recipe, so it is kept nearly whole. The observer marker
# lines are the proof, so they are extracted separately and bounded generously
# — by line count (``MAX_OBSERVER_MARKERS``) and by total characters
# (``POC_OUTPUT_CHARS``), because a marker line's length is attacker-influenced
# and an unbounded ``evidence`` string is an unbounded report. Both bounds
# announce themselves in the rendered text when they bite: a truncation nobody
# is told about would silently unprove the finding.
POC_CODE_CHARS = 4000
POC_OUTPUT_CHARS = 2000
MAX_OBSERVER_MARKERS = 40

#: The report fields phase 4's model owns, per the division-of-labour table in
#: ``phases/phase4_report.md``. The narrative merge is a WHITELIST over these
#: names and nothing else: a blacklist of computed fields would silently admit
#: every field added to the schema later, which is how a model-authored number
#: ends up in a report that promises none.
NARRATIVE_FINDING_FIELDS = (
    "title", "description", "impact", "exploit_scenario",
    "preconditions", "how_to_fix", "recommendation",
)

#: Top-level narrative sections. ``threat_model`` is listed as the model's in
#: the phase table, is renderable by ``reporting/markdown.py``, and has a home
#: in ``report.schema.json`` — but nothing computed it, so before the narrative
#: merge existed the Threat Model section rendered "_Not determined_" on every
#: run of a tool whose whole point is describing what it found.
NARRATIVE_TOP_LEVEL_FIELDS = ("threat_model",)

#: Fields the report computes. A narrative that carries one is not merely
#: ignored — it is reported, and under ``--strict`` it exits 2. The phase says
#: "supplying one is still a bug, because it means you believed you were
#: computing something you were not", and a bug nobody is told about is a bug
#: that ships.
COMPUTED_FINDING_FIELDS = ("cvss", "execution", "fingerprint", "variants",
                           "validation", "confidence", "evidence", "trace")
COMPUTED_TOP_LEVEL_FIELDS = ("summary", "coverage", "input_inventory",
                             "scan_metrics", "verification")

#: Fallback CWE by vulnerability class, used only when a finding carries no CWE
#: of its own. Hunters emit one; findings that lost it reached CWE-matching
#: scorers bare, which reads as "no weakness identified".
# The class -> CWE vocabulary lives in `oracle/taxonomy.py`, which is also
# where the D18 consistency check and the evidence-driven class upgrade
# live. Two tables that drift apart is how one class ends up with two CWEs
# depending on which module asked.
from oracle.taxonomy import CLASS_CWE  # noqa: E402,F401

#: Baseline CVSS 3.1 (score, vector) by severity band. A backfill FLOOR for a
#: finding that reached the report with no vector of its own — never an
#: override. A real vector computed by ``validate_gates.apply_cvss`` from the
#: verifier's own assessment always wins.
CVSS_BASELINE = {
    "critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "medium": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "low": (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "informational": (0.0, "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
}

#: The same bands for a target with **no network entry point** — a CLI, a
#: library, a batch job.
#:
#: ``AV:N`` was applied unconditionally, so a code generator a developer runs
#: over a file they chose was scored 9.8 with
#: ``AV:N/AC:L/PR:N/UI:N``. Every term of that is wrong for such a target: the
#: attacker is not on the network, and the victim must run the tool and then use
#: its output. The honest vector is ``AV:L`` with ``UI:R``, which lands the same
#: finding at 7.8 — still critical-adjacent, and defensible.
#:
#: Overstating severity is not a safe direction to err in. A report full of
#: 9.8s trains its reader to discount the number, and the first real 9.8 is
#: discounted with the rest.
CVSS_BASELINE_LOCAL = {
    "critical": (7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
    "high": (7.3, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "medium": (4.4, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "low": (2.5, "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "informational": (0.0, "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
}

#: Entry-point kinds that put an attacker on the network side of the target.
#: Mirrors the gating `tasks.py` already applies to the access-control
#: specialist, so the two cannot disagree about what "reachable" means.
NETWORK_ENTRY_KINDS = frozenset({
    "http_route", "rpc", "grpc", "webhook", "message_queue",
})


def network_reachable(inputs: dict | None) -> bool:
    """Did recon enumerate any entry point an attacker reaches over a network?

    Absent or unreadable inventory returns True — the network baseline is the
    higher score, and guessing downward on missing evidence would quietly
    deflate severities.
    """
    if not isinstance(inputs, dict):
        return True
    records = inputs.get("inputs")
    if not isinstance(records, list) or not records:
        return True
    for record in records:
        if not isinstance(record, dict):
            continue
        kind = str(record.get("kind") or "").strip().lower().replace("-", "_")
        if kind in NETWORK_ENTRY_KINDS:
            return True
    return False

DEFAULT_RECOMMENDATION = (
    "Review the sink and add input validation / use a safe API."
)

#: Severity order used for tallies, so two runs over the same data produce
#: byte-identical output.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


# --------------------------------------------------------------------------
# Classes THIS observer can never prove — the fourth denominator (L-2)
# --------------------------------------------------------------------------
#
# `oracle/classes.py` holds two tables, and merging them is exactly the
# dishonesty L-2 describes:
#
#   UNDECIDABLE_BY_EXECUTION      — no instrument could settle this. IDOR,
#                                   access control, business logic: policy
#                                   questions, and the runtime holds no policy.
#   NOT_PROVABLE_BY_THIS_OBSERVER — execution COULD settle this; PyHunt's
#                                   observer cannot see it. WATCHED_EVENTS has
#                                   no DB-cursor and no response-write event,
#                                   so SQL/NoSQL injection, XSS and open
#                                   redirect can never reach `proven` here.
#
# `classes.is_undecidable` is the union, because the gate's answer is the same
# for both (`not_applicable`, finding left standing). The REPORT must not merge
# them: "no instrument could prove this" is a fact about the vulnerability
# class, and "our instrument is deaf here" is a fact about PyHunt. Folding the
# second into the first bills PyHunt's own blind spot to the target, and
# folding either into `provable_by_execution` measures the tool against a
# denominator containing findings it structurally cannot prove — understating
# the tool and misleading the reader in the same breath.
#
# So the report calls `observer_blind_reason` and `undecidable_by_policy`
# directly rather than `is_undecidable`, and publishes four numbers.
#
# Note what is deliberately NOT observer-blind: template injection. Jinja2 and
# friends render through `compile(source, filename, "exec")`, which IS a
# watched event, so a real SSTI reaches `proven` legitimately. That subtlety
# lives in `oracle/classes.py` with the evidence for it; this module must not
# keep a second opinion about the vocabulary.

# --------------------------------------------------------------------------
# Loading the results directory
# --------------------------------------------------------------------------

def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return default


def _task_outcomes(root: Path) -> dict[str, list[dict]]:
    """``{task_id: [outcome, ...]}`` from ``task_outcomes.json``.

    Imported lazily and defensively: `coverage.py` is the release gate and must
    not be able to fail the report if it is mid-edit, and a report that cannot
    read the outcome ledger should fall back to "unknown" rather than refuse to
    build.
    """
    try:
        from coverage import load_task_outcomes

        return load_task_outcomes(root)
    except Exception:  # pragma: no cover - defensive
        return {}


def _flatten_verifications(records: dict[str, dict]) -> dict[str, dict]:
    """Accept both shapes a phase 2c record is written in.

    `phases/phase2c_verify.md` specifies an **envelope** — `model`,
    `hunt_model`, `model_diversity`, `execution_outcome`, `gate_dissent`, and
    an inner `verdict` object that validates against `validation.schema.json`.
    Everything in this module was written against the **flat** shape, where
    `verdict` is the string `confirmed`/`rejected`/`needs_more_info` and
    `rationale`, `validator_confidence` and `cvss_vector` sit beside it.

    Fed an envelope, `attach_validation` copied a dict into a field the schema
    types as a string, `select_delivered` compared a dict against `"confirmed"`
    and delivered nothing, and `attach_coverage` used a dict as a dict key and
    raised `TypeError: unhashable type: 'dict'`. So the mismatch did not
    degrade quietly — but it did stop the phase that produces the advisory.

    Flattening here rather than at each of the six call sites keeps one shape
    downstream. Envelope-only keys are preserved under an `envelope_` prefix so
    nothing is lost, and a record already flat is returned untouched.
    """
    out: dict[str, dict] = {}
    for finding_id, record in (records or {}).items():
        if not isinstance(record, dict):
            continue
        inner = record.get("verdict")
        if not isinstance(inner, dict):
            out[finding_id] = record          # already flat
            continue
        merged = dict(inner)
        for key, value in record.items():
            if key == "verdict":
                continue
            merged.setdefault(f"envelope_{key}" if key in merged else key, value)
        out[finding_id] = merged
    return out


def load_run(results_dir: str | Path) -> dict:
    """Everything the report is built from, read once.

    Every file is optional. A run that stopped after phase 2 still gets a
    report — a partial scan with disclosed gaps is useful; a scan that refuses
    to report because one artifact is missing is not.
    """
    root = Path(results_dir)
    return {
        "results_dir": str(root),
        "manifest": findings_io.load_manifest(root),
        "findings": findings_io.load_findings(root),
        "verifications": _flatten_verifications(findings_io.load_verifications(root)),
        "proofs": findings_io.load_proofs(root),
        "inputs": _read_json(root / "inputs.json", {}),
        "coverage": _read_json(root / "coverage.json", {}),
        "tasks": _read_json(root / "tasks.json", {}),
        # Which queued tasks were actually hunted, and what they concluded.
        # `tasks.json` is the queue and records no outcome, so without this a
        # clean sweep and a task nobody ran are the same thing to the report.
        # Written by `findings_io record` and `coverage.py task-done`.
        "task_outcomes": _task_outcomes(root),
        "preflight": _read_json(root / "preflight.json", {}),
        "gaps": _read_json(root / "gaps.json", {}),
        # Optional: phase 1 may record its architecture map separately from the
        # input inventory. Absent is normal and costs only the subsystem
        # breakdown.
        "recon": _read_json(root / "recon.json", {}),
    }


# --------------------------------------------------------------------------
# Delivery selection
# --------------------------------------------------------------------------

def is_canonical(finding: dict) -> bool:
    """Is this finding its group's delivered representative?

    An ungrouped finding is its own canonical: dedupe not having run is not a
    reason to withhold a finding.
    """
    if finding.get("group_id"):
        return bool(finding.get("is_canonical"))
    return True


def select_delivered(findings: list[dict], verifications: dict[str, dict]) -> tuple[list[dict], list[dict]]:
    """Split findings into ``(delivered, withheld)``.

    Withheld is not deleted: every withheld finding is counted in
    ``coverage.findings_by_status`` and in the verification funnel, and each
    carries the reason it was withheld. The report's headline count is the
    delivered set; the denominators disclose the rest.

    A finding the execution gate proved is never withheld — not by the
    adversarial verifier, and not by dedupe. The gate observed the target's own
    frame interpret this PoC's nonce-carrying payload; a model's later re-read
    is an opinion about that observation, not a replacement for it.

    The docstring and the code used to disagree here (L-1): ``proven`` was
    computed and then not consulted on the canonicality branch, so a proven
    finding that lost the canonical coin-toss to an UNPROVEN sibling was
    demoted to a bare "Also at `file:line`" reference — losing its PoC, its
    observer marker lines, its CVSS block and its execution outcome. The
    headline then showed the finding with no receipt and hid the one with one.
    That is the report equivalent of every other defect in this pass: the
    evidence existed and the output did not show it.

    The docstring was the intended contract, so the code now matches it.
    Delivering a proven duplicate does not inflate the headline dishonestly —
    the gate's locality check means a ``proven`` verdict is tied to that
    finding's OWN file, so two proven siblings are two genuinely distinct
    observed sites, not one fact counted twice. ``attach_variants`` is kept in
    step: a finding delivered on its own merits is never also listed as
    somebody else's "Also at" reference.
    """
    delivered: list[dict] = []
    withheld: list[dict] = []
    for finding in findings:
        proven = findings_io.poc_succeeded(finding)
        verdict = (verifications.get(finding["finding_id"]) or {}).get("verdict")
        if proven:
            delivered.append(finding)
            continue
        if not is_canonical(finding):
            withheld.append({**finding, "_withheld_reason": "duplicate_of_canonical"})
            continue
        if verdict == "rejected":
            withheld.append({**finding, "_withheld_reason": "verifier_rejected"})
            continue
        delivered.append(finding)
    return delivered, withheld


# --------------------------------------------------------------------------
# The base payload
# --------------------------------------------------------------------------

def _report_description(finding: dict) -> str:
    """A description that satisfies the report schema without inventing claims.

    ``report.schema.json`` requires 30 characters; ``finding.schema.json``
    requires 20. A hunter can therefore emit a valid finding whose description
    is too short for the report. The gap is closed by appending the finding's
    own location — factual, deterministic, and derived from fields already on
    the record — rather than by asking a model to pad it or by dropping the
    finding.
    """
    description = str(finding.get("description") or "").strip()
    location = (
        f"{finding.get('vuln_class')} at {finding.get('file')}:"
        f"{finding.get('line_start')}-{finding.get('line_end')}"
    )
    if len(description) >= 30:
        return description
    if description:
        return f"{description} ({location})"
    return f"{location}. The hunter recorded no description for this finding."


def _trace_for(finding: dict, tasks_by_id: dict[str, dict]) -> dict:
    """The entry-point/call-chain block, from the task that raised the finding.

    Two task shapes are supported on purpose. ``hunt_task.schema.json`` — what
    ``taint.py`` actually emits today — has no structured path, only a prose
    ``scope_hint`` naming the trust boundary above the sink. The results-dir
    contract for ``tasks.json`` describes richer ``entry_point``/``path``
    fields. Whichever is present is used; neither is fabricated when absent,
    because an invented call chain is a claim about code nobody read.
    """
    task = tasks_by_id.get(finding.get("task_id") or "") or {}
    entry_points: list[dict] = []
    entry = task.get("entry_point")
    if isinstance(entry, dict) and entry.get("location"):
        entry_points.append({
            "kind": str(entry.get("kind") or "entry_point"),
            "location": str(entry["location"]),
            **({"controllable_by": str(entry["controllable_by"])}
               if entry.get("controllable_by") else {}),
        })
    elif isinstance(entry, str) and entry.strip():
        entry_points.append({"kind": "entry_point", "location": entry.strip()})

    call_chain: list[dict] = []
    for hop in task.get("path") or []:
        if isinstance(hop, dict) and hop.get("file") and hop.get("line"):
            call_chain.append({
                "file": str(hop["file"]),
                "function": str(hop.get("function") or "?"),
                "line": int(hop["line"]),
            })
    return {"entry_points": entry_points, "call_chain": call_chain}


def build_report_payload(
    run: dict, delivered: list[dict], tasks_by_id: dict[str, dict]
) -> dict:
    """The report skeleton: identity, tally, and one entry per delivered finding.

    Everything richer than this — CWE, CVSS, PoC evidence, variants, coverage —
    is attached afterwards from run state, so that a field's presence never
    depends on a model having remembered to emit it.
    """
    manifest = run.get("manifest") or {}
    by_severity: dict[str, int] = {}
    findings_out = []
    for finding in delivered:
        severity = str(finding.get("severity") or "informational")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        findings_out.append({
            "finding_id": finding["finding_id"],
            "title": f"{finding.get('vuln_class')} in {finding.get('file')}",
            "severity": severity,
            "vuln_class": str(finding.get("vuln_class") or "unknown"),
            "file": str(finding.get("file") or ""),
            "line_start": int(finding.get("line_start") or 1),
            "line_end": int(finding.get("line_end") or finding.get("line_start") or 1),
            "description": _report_description(finding),
            "evidence": str(finding.get("evidence_snippet") or ""),
            "trace": _trace_for(finding, tasks_by_id),
            "recommendation": DEFAULT_RECOMMENDATION,
        })

    target: dict[str, str] = {"repo_path": str(manifest.get("target") or "")}
    if manifest.get("commit"):
        target["commit"] = str(manifest["commit"])

    return {
        "run_id": str(manifest.get("run_id") or Path(run["results_dir"]).name),
        "target": target,
        "summary": {
            "total": len(findings_out),
            "by_severity": {
                sev: by_severity[sev] for sev in SEVERITY_ORDER if sev in by_severity
            },
        },
        "findings": findings_out,
    }


# --------------------------------------------------------------------------
# The attaches — each one a disclosure the report must never be able to drop
# --------------------------------------------------------------------------

def attach_cwe(payload: dict, findings_by_id: dict[str, dict]) -> None:
    """Backfill a ``cwe`` onto each report finding.

    Prefer the finding's own CWE from run state; else map from ``vuln_class``.
    Without this, a CWE-class-matching consumer (SARIF, a benchmark scorer)
    sees a bare finding and cannot class it at all.
    """
    for entry in payload.get("findings", []):
        if entry.get("cwe"):
            continue
        stored = findings_by_id.get(entry["finding_id"]) or {}
        cwe = stored.get("cwe") or CLASS_CWE.get(entry.get("vuln_class") or "")
        if cwe:
            entry["cwe"] = cwe


def attach_structural(payload: dict, findings_by_id: dict[str, dict]) -> None:
    """Carry each finding's structural verdict onto its report entry.

    Kept in its own key rather than folded into ``validation`` or ``poc``,
    because a reader scanning one column must not be able to mistake
    ``demonstrated`` for ``proven``. They are different claims from different
    oracles and the report says so at every level it appears.
    """
    for entry in payload.get("findings", []):
        stored = findings_by_id.get(entry["finding_id"]) or {}
        record = stored.get("structural")
        if isinstance(record, dict) and record.get("outcome"):
            entry["structural"] = record


def _norm_report_path(path: object) -> str:
    """Repo-relative, forward slashes, no leading `./`. See dedupe._norm_file
    for why `lstrip("./")` is the wrong tool."""
    text = str(path or "").replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def attach_reachability(payload: dict, results_dir: Path) -> None:
    """Stamp each finding with the tier of the file it lives in (W5.2).

    `recon_enumerate.py` already classifies every file as `public_api`,
    `internal`, `ci`, `build`, `example` or `test`. Joining that onto findings
    lets a reader sort by reachability **without anything being dropped**,
    which is the whole disagreement this field settles.

    The recorded run found 44 sites a comparison tool did not, and they were
    not homogeneous: a `publish.yaml` tag trigger that is real and severe, and
    several test-harness issues that are real and less urgent. Presenting those
    as one undifferentiated list invites the reader to discount all of them;
    dropping the test-tier ones would have discarded the run's **only proven
    finding**, which lives in `tests/documentation/test_documentation.py`.

    So: sort by it, never filter by it. Absent enumeration leaves the field off
    entirely rather than guessing a tier from a path.
    """
    path = results_dir / "logs" / "recon_enumeration.json"
    if not path.is_file():
        return
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    tiers = {
        str(row.get("path")): row.get("reachable_from")
        for row in doc.get("files", []) or []
        if isinstance(row, dict) and row.get("path") and row.get("reachable_from")
    }
    if not tiers:
        return

    counts: dict[str, int] = {}
    for entry in payload.get("findings", []):
        file = _norm_report_path(entry.get("file"))
        tier = tiers.get(file)
        if not tier:
            continue
        entry["reachable_from"] = tier
        counts[tier] = counts.get(tier, 0) + 1
    if counts:
        payload["reachability"] = {
            "by_tier": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
            "note": (
                "The tier of the file each finding lives in, from the phase 1 "
                "enumeration. Sort by it; do not filter by it. This run's only "
                "proven finding is in a `test` file."
            ),
        }


_ADVISORY_SUFFIX_RX = re.compile(
    r"\s*—\s*and \d+ more site\(s\) of the same cause\s*$")


def _retitle_for_site_count(title: object, site_count: int) -> str:
    """Rewrite an advisory title's "and N more sites" tail to match reality."""
    base = _ADVISORY_SUFFIX_RX.sub("", str(title or "")).rstrip()
    if site_count > 1:
        return f"{base} — and {site_count - 1} more site(s) of the same cause"
    return base


def attach_advisories(payload: dict, results_dir: Path) -> None:
    """Carry the root-cause advisories onto the report (W5.1).

    ``cluster.py`` writes ``logs/clusters.json``; this copies its entries in
    and records the reduction. Absent is a normal outcome — an older run, or a
    run where phase 3 did not reach the clustering step — and the report is
    simply built without the section rather than failing.

    The advisories are a **view**. ``findings[]`` is unchanged and every
    advisory names its member ``finding_ids``, so nothing is collapsed away: a
    reader who wants the eight call sites still gets eight rows with their own
    ids, verdicts and CVSS. What changes is that a reader who wants to know how
    many *defects* there are can now read one number instead of doing the
    clustering themselves, which was the job the tool was leaving to them.
    """
    path = results_dir / "logs" / "clusters.json"
    if not path.is_file():
        return
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        return

    delivered = {f.get("finding_id") for f in payload.get("findings", [])}
    kept = []
    for advisory in entries:
        if not isinstance(advisory, dict):
            continue
        members = [f for f in advisory.get("finding_ids", []) if f in delivered]
        if not members:
            # Every site in this cluster was withheld or rejected downstream.
            # Reporting the advisory anyway would name findings the report does
            # not contain.
            continue
        locations = [
            loc for loc in advisory.get("locations", [])
            if isinstance(loc, dict) and loc.get("finding_id") in delivered
        ]
        kept.append({
            **advisory,
            "finding_ids": members,
            "locations": locations,
            "site_count": len(members),
            # The title was written against the pre-filter membership. Left
            # alone it says "and 4 more site(s)" beside a Sites column reading
            # 1, because sites withheld or rejected downstream are dropped
            # here. Re-derive the suffix from what actually survived.
            "title": _retitle_for_site_count(advisory.get("title"), len(members)),
        })

    if not kept:
        return
    payload["advisories"] = kept
    payload["advisory_summary"] = {
        "advisories": len(kept),
        "sites": len(delivered),
        "sites_per_advisory": round(len(delivered) / len(kept), 3),
        "settled_advisories": sum(
            1 for a in kept if a.get("proven") or a.get("demonstrated")),
        "largest_advisory": max((a["site_count"] for a in kept), default=0),
        "order_note": doc.get("order_note", ""),
        "note": (
            "One entry per root cause, each naming every location it occurs "
            "at. `findings[]` is unchanged — this is a view over it, not a "
            "replacement for it."
        ),
    }


def attach_execution(payload: dict, findings_by_id: dict[str, dict]) -> None:
    """Carry each finding's **execution-gate outcome** onto its report entry.

    D20. Until this existed, ``report.json``'s finding objects carried
    ``validation`` — phase 2c's adversarial verdict — and nothing from the gate.
    The gate's tally was present, but only in aggregate under
    ``coverage.execution.by_outcome``, so a consumer of ``report.json`` could
    read that a run had one ``proven`` finding and had **no way to tell which
    one it was**. Sorting the machine-settled findings to the top, filtering
    them in CI, or diffing two runs' settlements were all impossible from the
    document the tool holds out as its output.

    ``outcome`` is the gate's word, unmodified. Nothing here re-judges anything;
    it is a join, and the aggregate above is still computed from the same
    source, so the two cannot drift.
    """
    for entry in payload.get("findings", []):
        stored = findings_by_id.get(entry["finding_id"]) or {}
        outcome = findings_io.execution_outcome(stored)
        if not outcome:
            continue
        block: dict[str, Any] = {"outcome": outcome}
        proof = stored.get("proof")
        if isinstance(proof, dict):
            for key in ("isolation_tier", "unanimous", "repeats"):
                value = proof.get(key)
                if value is not None:
                    block[key] = value
        entry["execution"] = block


def attach_independent_units(payload: dict, findings_by_id: dict[str, dict]) -> None:
    """Carry the convergence count onto each report entry.

    ``dedupe.py`` records how many independent hunt tasks reached a site without
    seeing each other's work. That number was being computed and thrown away by
    the very step that collapsed the duplicates — 21 of 55 sites in one real run
    were filed by two or more units, which is corroboration a reader should be
    told about rather than a redundancy to be silently swallowed.
    """
    for entry in payload.get("findings", []):
        stored = findings_by_id.get(entry["finding_id"]) or {}
        try:
            units = int(stored.get("independent_units") or 0)
        except (TypeError, ValueError):
            continue
        if units > 1:
            entry["independent_units"] = units


def observer_markers(run_output: str | None) -> list[str]:
    """The observer evidence lines from a PoC's output.

    These are the record that the dangerous operation was actually *seen* to
    happen — a process spawned, a socket opened — as opposed to a PoC that
    merely exited 0. When a finding is proven, one of these lines is the proof,
    and the report must quote it.
    """
    return [
        line.strip()
        for line in (run_output or "").splitlines()
        if OBSERVER_MARKER in line
    ][:MAX_OBSERVER_MARKERS]


def replay_transcript(proof: dict | None) -> str:
    """The observer transcript out of a ``proof/<id>.json`` record.

    ``replay.ProofRecord.to_dict()`` writes **no top-level ``run_output``**: the
    captured text lives per repeat, under ``runs[i]["markers"]`` (the signed
    private channel the gate judged) with ``stdout``/``stderr`` beside it. This
    module used to read ``proof["run_output"]``, so the documented preference
    for the replay transcript over the hunter's own account never once fired —
    every "Observer evidence" block in every report was quoting text the hunt
    agent wrote. That is defect C-1 wearing the report's clothes.

    ``markers`` is preferred over ``stdout``/``stderr`` because it is the
    channel Contract A signs; the others are included after it so a stderr
    fallback still yields evidence. ``run_output`` is still honoured when
    present, for records written by something other than ``replay.py``.
    """
    if not isinstance(proof, dict) or not proof:
        return ""
    if proof.get("run_output"):
        return str(proof["run_output"])
    chunks: list[str] = []
    for run in proof.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for key in ("markers", "stdout", "stderr"):
            text = run.get(key)
            if text:
                chunks.append(str(text))
    return "\n".join(chunks)


def bounded_marker_block(markers: list[str]) -> str:
    """The observer marker lines as one text block, bounded and loud about it.

    ``MAX_OBSERVER_MARKERS`` bounds the line COUNT; nothing bounded the line
    LENGTH, and a marker line's contents are influenced by whatever the PoC
    passed to the dangerous operation. One pathological argument therefore put
    an arbitrarily large string into a schema field with no maximum, in a
    document that is redacted and re-serialised whole.

    Every truncation announces itself in the rendered text. A silent one would
    be the worst possible bug in this specific function: these lines ARE the
    proof, and quietly dropping the one that carried the attribution would
    unprove the finding while leaving the report looking complete.
    """
    kept: list[str] = []
    truncated_lines = 0
    used = 0
    for line in markers:
        clipped = line[:POC_OUTPUT_CHARS]
        if clipped != line:
            truncated_lines += 1
        if kept and used + len(clipped) + 1 > POC_OUTPUT_CHARS:
            break
        kept.append(clipped)
        used += len(clipped) + 1

    body = "\n".join(kept)
    notes: list[str] = []
    dropped = len(markers) - len(kept)
    if dropped:
        notes.append(
            f"{dropped} further observer line(s) omitted here — the block "
            f"exceeded {POC_OUTPUT_CHARS} characters"
        )
    if truncated_lines:
        notes.append(
            f"{truncated_lines} line(s) were individually longer than "
            f"{POC_OUTPUT_CHARS} characters and were cut"
        )
    if notes:
        body += (
            "\n[... " + "; ".join(notes)
            + ". The complete transcript is in proof/<finding_id>.json.]"
        )
    return body


def attach_poc_evidence(
    payload: dict, findings_by_id: dict[str, dict], proofs: dict[str, dict]
) -> None:
    """Attach each finding's executed-PoC evidence.

    A confirmed PyHunt finding was not merely reasoned about: a real PoC was
    written and run in the sandbox, and a runtime observer recorded the
    dangerous operation as it fired. If that evidence does not reach the
    report, the tool's differentiator is invisible in its only output.

    The replay transcript (phase 2b, ``proof/<id>.json``) is preferred over the
    hunter's own account when both exist — the replay is the run the gate
    actually judged, and only the PoC crossed into that container.

    ``poc.succeeded`` in the report is the GATE's value, never the model's.
    """
    for entry in payload.get("findings", []):
        finding = findings_by_id.get(entry["finding_id"])
        if finding is None:
            continue
        proof = proofs.get(entry["finding_id"]) or {}
        poc = dict(finding.get("poc") or {})
        # The replay transcript when there is one, the hunter's account only
        # when there is not. `replay_transcript` is what makes that preference
        # real — reading `proof["run_output"]` directly never found anything.
        run_output = replay_transcript(proof) or str(poc.get("run_output") or "")
        if not poc.get("code"):
            continue
        block: dict[str, Any] = {
            "language": str(poc.get("language") or "python"),
            "code": str(poc.get("code"))[:POC_CODE_CHARS],
            "succeeded": findings_io.poc_succeeded(finding),
        }
        entry["poc"] = block
        # `run_output`, `notes` and `observer_evidence` are not in
        # report.schema.json's `poc` block (which allows only
        # language/code/succeeded), so the marker lines ride in `evidence`
        # instead of being silently dropped: they are the proof, and the
        # renderer must be able to quote them.
        markers = observer_markers(run_output)
        if markers:
            entry["evidence"] = (
                f"{entry.get('evidence', '')}\n\n"
                f"Observer evidence ({len(markers)} line(s)):\n"
                + bounded_marker_block(markers)
            ).strip()


def group_members_excluding(
    group: list[dict],
    exclude_id: str,
    *,
    delivered_ids: frozenset[str] | set[str] = frozenset(),
) -> list[dict]:
    """Located references to a finding's deduped siblings ("Also at:").

    A deduped sibling is demoted to a LOCATED reference, never dropped, so
    every co-located confirmed site stays visible without inflating the
    headline count.

    Dedupe may promote one canonical PER FILE in a cross-file group, so a group
    can have several headline findings. A sibling belongs in ``exclude_id``'s
    variants only if it is genuinely demoted AND it is actually *this*
    canonical's demoted sibling: either it shares this canonical's file, or (the
    single-canonical case) no other canonical in the group claims its file at
    all. Without that test, every headline in a multi-canonical group would
    list every other headline's duplicates too.

    ``delivered_ids`` names the findings that got their own headline entry.
    Since the L-1 fix, a non-canonical finding the gate PROVED is delivered on
    its own merits, so "not canonical" no longer implies "demoted". A delivered
    finding listed here would appear twice in the same report — once with its
    evidence, once as a bare location — so it is excluded.
    """
    exclude_file = next(
        (f.get("file") for f in group if f.get("finding_id") == exclude_id), None
    )
    canonical_files = {f.get("file") for f in group if f.get("is_canonical")}
    return [
        {
            "finding_id": f.get("finding_id"),
            "file": f.get("file"),
            "line_start": f.get("line_start"),
            "line_end": f.get("line_end"),
            "vuln_class": f.get("vuln_class"),
        }
        for f in group
        if f.get("finding_id") != exclude_id
        and not f.get("is_canonical")
        and f.get("finding_id") not in delivered_ids
        and (f.get("file") == exclude_file or f.get("file") not in canonical_files)
    ]


def attach_variants(payload: dict, findings: list[dict]) -> None:
    """Attach located deduped-sibling references to each report finding.

    The delivered set is read off ``payload["findings"]`` rather than passed in:
    those entries ARE the delivered findings, so the two can never drift apart
    and no caller has to remember to keep them in sync.
    """
    groups: dict[str, list[dict]] = {}
    for finding in findings:
        gid = finding.get("group_id")
        if gid:
            groups.setdefault(gid, []).append(finding)
    by_id = {f["finding_id"]: f for f in findings}
    delivered_ids = frozenset(
        str(e["finding_id"]) for e in payload.get("findings", []) if e.get("finding_id")
    )
    for entry in payload.get("findings", []):
        gid = (by_id.get(entry["finding_id"]) or {}).get("group_id")
        if not gid:
            continue
        variants = group_members_excluding(
            groups.get(gid, []), entry["finding_id"], delivered_ids=delivered_ids
        )
        if variants:
            entry["variants"] = variants


def attach_validation(
    payload: dict, findings_by_id: dict[str, dict], verifications: dict[str, dict]
) -> None:
    """Attach each finding's adversarial-verification outcome and the hunter's
    own confidence.

    Only the keys the verifier actually emitted are copied — a
    ``needs_more_info`` verdict carries no ``cvss_vector``, and inventing one
    would make an unresolved finding look assessed.
    """
    for entry in payload.get("findings", []):
        finding = findings_by_id.get(entry["finding_id"]) or {}
        verification = verifications.get(entry["finding_id"]) or {}
        block: dict[str, Any] = {}
        if verification.get("verdict"):
            block["verdict"] = verification["verdict"]
        if "rationale" in verification:
            block["rationale"] = verification["rationale"]
        if "validator_confidence" in verification:
            block["validator_confidence"] = verification["validator_confidence"]
        if block:
            entry["validation"] = block
        if finding.get("confidence") is not None:
            entry["confidence"] = finding["confidence"]


def attach_cvss(payload: dict, verifications: dict[str, dict],
                inputs: dict | None = None) -> None:
    """Give every report finding a CVSS block.

    Priority: the vector the verifier assessed (with the score computed in
    Python by ``validate_gates.apply_cvss``), then a severity-keyed baseline
    floor. The baseline never overwrites a real vector — a generic 9.8 standing
    in for an assessed 7.5 is a wrong number presented with the same authority
    as a right one.

    The baseline's **attack vector is chosen from the inventory**, not assumed.
    When recon enumerated no network entry point, ``AV:L``/``UI:R`` is used, so
    a CLI code generator is not scored as though an unauthenticated stranger
    could reach it across the internet. See :data:`CVSS_BASELINE_LOCAL`.
    """
    table = CVSS_BASELINE if network_reachable(inputs) else CVSS_BASELINE_LOCAL
    for entry in payload.get("findings", []):
        if entry.get("cvss"):
            continue
        verification = verifications.get(entry["finding_id"]) or {}
        vector = verification.get("cvss_vector")
        score = verification.get("cvss_score")
        # The score is computed here when the verifier supplied only a vector,
        # which is the normal case: `phase2c_verify.md` asks the verifier for a
        # vector and forbids it the arithmetic, and nothing between there and
        # here ran `validate_gates.apply_cvss`. Requiring BOTH fields meant the
        # assessed vector was silently discarded and a severity-keyed baseline
        # floor stood in for it — on the recorded h2 run, all 18 delivered
        # findings rendered the identical `AV:L/.../UI:R` 4.4, describing a
        # remotely reachable HTTP/2 protocol defect as local and
        # user-interaction-gated. A wrong number carrying the same authority as
        # a right one is the exact failure `cvss.py` exists to prevent.
        if vector and score is None:
            score = cvss_base_score(vector)
        if vector and score is not None:
            band = severity_from_cvss_rating(cvss_rating(score))
            entry["cvss"] = {
                "score": score,
                # The CVSS band, not the finding's recorded severity. Where the
                # two differ the report shows both rather than reconciling them
                # silently: the recorded severity is what phase 2 filed and
                # phase 3 ranked on, and the band is what the verifier's own
                # vector computes to.
                "severity": band or entry.get("severity"),
                "vector": vector,
            }
            continue
        baseline_score, baseline_vector = table.get(
            str(entry.get("severity") or "").lower(), (0.0, "")
        )
        entry["cvss"] = {
            "score": baseline_score,
            "severity": entry.get("severity"),
            "vector": baseline_vector,
        }


def attach_input_inventory(payload: dict, inputs: dict, coverage: dict) -> None:
    """Attach the resolved input inventory — the completeness ledger.

    Every attacker-controllable input Recon enumerated appears here with the
    disposition the sweep reconciled it to. This is what makes "we looked at
    everything" checkable rather than asserted, and it is sourced from run
    state so the report cannot quietly enumerate fewer inputs than the scan
    found.
    """
    dispositions = {
        str(row.get("input_id") or row.get("id")): row
        for row in (coverage.get("inputs") or [])
    }
    inventory = []
    for row in inputs.get("inputs") or []:
        input_id = str(row.get("input_id") or row.get("id") or "")
        resolved = dispositions.get(input_id, {})
        inventory.append({
            "id": input_id,
            "source_type": row.get("source_type"),
            "location": row.get("location"),
            "variable": row.get("variable"),
            "entry_point": row.get("entry_point"),
            "trust_level": row.get("trust_level"),
            "disposition": resolved.get("disposition"),
            "disposition_evidence": resolved.get("evidence")
            or resolved.get("disposition_evidence"),
        })
    payload["input_inventory"] = inventory


def _parse_stamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def attach_scan_metrics(payload: dict, coverage: dict, manifest: dict) -> None:
    """Attach run-level scan metrics.

    A metric that is not knowable is OMITTED, never emitted as a cheerful zero.
    Cost and per-phase tokens are unknowable in the skill form — they lived in
    the deleted runner's SQLite ledger — so those two keys never appear, rather
    than reporting a $0.00 scan.
    """
    files = coverage.get("files") if isinstance(coverage.get("files"), dict) else coverage
    metrics: dict[str, Any] = {}
    source_files = files.get("source_files")
    covered_files = files.get("covered_files")
    if isinstance(source_files, int):
        metrics["files_in_scope"] = source_files
    if isinstance(covered_files, int):
        metrics["files_analyzed"] = covered_files
    if isinstance(source_files, int) and isinstance(covered_files, int) and source_files:
        metrics["coverage_pct"] = round(100 * covered_files / source_files, 1)
    started = _parse_stamp(manifest.get("started_at"))
    finished = _parse_stamp(manifest.get("finished_at"))
    if started and finished:
        metrics["duration_sec"] = round((finished - started).total_seconds(), 1)
    if metrics:
        payload["scan_metrics"] = metrics


def attach_verification(
    payload: dict, findings: list[dict], verifications: dict[str, dict]
) -> None:
    """Attach the verification funnel over EVERY finding the run recorded.

    Not just the delivered ones. A precision figure computed over the survivors
    is meaningless — it would be 100% by construction.
    """
    raw = len(findings)
    verdicts = [
        (verifications.get(f["finding_id"]) or {}).get("verdict") for f in findings
    ]
    confirmed = sum(1 for v in verdicts if v == "confirmed")
    rejected = sum(1 for v in verdicts if v == "rejected")
    judged = sum(1 for v in verdicts if v)

    # **Precision is UNDEFINED when phase 2c did not run, and undefined is not
    # zero.** With no verifications recorded, `confirmed` and `rejected` are
    # both 0, and dividing gave `0.0` — so a run with three good findings and
    # not one rejection reported "Verification precision: 0.0%", which reads as
    # "everything here is junk". That is the same defect this project exists to
    # prevent, pointed the other way: a number stated with more confidence than
    # the evidence carries. The denominator is what was actually judged, and
    # when nothing was judged the answer is None.
    payload["verification"] = {
        "raw_findings": raw,
        "true_positives": confirmed,
        "false_positives": rejected,
        "needs_more_info": sum(1 for v in verdicts if v == "needs_more_info"),
        "duplicates_collapsed": sum(
            1 for f in findings if f.get("group_id") and not f.get("is_canonical")
        ),
        "findings_judged": judged,
        "precision_pct": (
            round(100 * confirmed / (confirmed + rejected), 1)
            if (confirmed + rejected) else None
        ),
        "precision_note": (
            "" if (confirmed + rejected) else
            "adversarial verification (phase 2c) recorded no verdict for any "
            "finding, so there is no confirmed/rejected split to take a ratio "
            "of. This is not a precision of zero."
        ),
    }


#: Rendered next to ``not_provable_by_observer``. Plain language, because the
#: number is meaningless to a reader who does not know what an audit hook is.
NOT_PROVABLE_BY_OBSERVER_NOTE = (
    "These findings are in classes PyHunt's runtime observer has no event for. "
    "It watches process spawn, file open, network connect, exec/compile, "
    "pickle and marshal; CPython raises no audit event when a database cursor "
    "executes a query or when a response body or header is written, so a fully "
    "successful SQL injection, NoSQL injection, XSS or open redirect produces "
    "nothing for the gate to attribute. They could not have reached 'proven' "
    "however sound they are, so they are excluded from the provable "
    "denominator rather than counted as failures to prove. This is a "
    "limitation of PyHunt, not a weakness in the findings: they stand on their "
    "static source-to-sink argument, and each one below carries the specific "
    "reason its class is invisible here."
)


def execution_summary(findings: list[dict], manifest: dict) -> dict:
    """proven / provable / not-provable-by-observer / total: four denominators.

    A merged "18/25 confirmed" that buries six access-control findings in the
    denominator is a misleading number: those six could never have been settled
    by running code, so counting them as failures to prove understates the tool
    and counting them as proven overstates it. Every denominator is published
    separately, and none of them is derivable from another by subtraction alone.

    The fourth number closes L-2. ``provable_by_execution`` used to be "total
    minus ``not_applicable``", which counted SQL injection, NoSQL injection,
    XSS and template injection as provable — classes ``WATCHED_EVENTS`` has no
    event for and which therefore can never reach ``proven``. The tool was
    measuring itself against a denominator containing findings it structurally
    cannot prove: it understated its own hit rate AND told the reader those
    findings had been tried and failed. Both halves were wrong.

    The four buckets partition the findings exactly — they sum to ``total`` —
    and are assigned in this precedence:

    1. outcome ``proven`` -> provable. An observed fact outranks any table. A
       template injection that escalated to a process spawn WAS witnessed, so
       claiming its class is unobservable would contradict the evidence sitting
       next to it in the report. This ordering is also what guarantees
       ``proven <= provable``, an invariant a reader will assume and which a
       table-first ordering could violate.
    2. class is observer-blind -> not_provable_by_observer. Checked BEFORE the
       ``not_applicable`` outcome, because the gate reaches that outcome via
       ``classes.is_undecidable``, which is the UNION of the two tables — so an
       outcome-first ordering would bury every observer-blind finding inside
       ``not_applicable`` and the third number would always read 0. That is the
       merge L-2 exists to prevent, one layer down.
    3. outcome ``not_applicable``, or a policy-undecidable class -> not
       applicable. No instrument could settle it.
    4. everything else -> provable.

    ``by_outcome`` keeps the eight gate outcomes distinct, plus ``ungated`` for
    a finding the gate never saw. ``ungated`` is a PyHunt bug, not a fact about
    the target, and folding it into ``not_attempted`` would hide it.
    """
    by_outcome: dict[str, int] = {}
    provable = 0
    not_applicable = 0
    blind = 0
    blind_classes: dict[str, int] = {}
    blind_reasons: dict[str, str] = {}

    for finding in findings:
        outcome = findings_io.execution_outcome(finding) or "ungated"
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1

        vuln_class = str(finding.get("vuln_class") or "unknown")
        reason = vuln_classes.observer_blind_reason(vuln_class)
        if outcome == "proven":
            provable += 1
        elif reason:
            blind += 1
            blind_classes[vuln_class] = blind_classes.get(vuln_class, 0) + 1
            blind_reasons.setdefault(vuln_class, reason)
        elif outcome == "not_applicable" or vuln_classes.undecidable_by_policy(
            vuln_class
        ):
            not_applicable += 1
        else:
            provable += 1

    summary: dict[str, Any] = {
        "total": len(findings),
        "provable_by_execution": provable,
        "proven_by_execution": by_outcome.get("proven", 0),
        "not_applicable": not_applicable,
        "not_provable_by_observer": blind,
        "ungated": by_outcome.get("ungated", 0),
        "overclaimed": sum(1 for f in findings if findings_io.contradicts_model(f)),
        "by_outcome": dict(sorted(by_outcome.items())),
        "isolation_tier": manifest.get("isolation_tier"),
        "mode": manifest.get("mode"),
    }
    if blind:
        summary["not_provable_by_observer_note"] = NOT_PROVABLE_BY_OBSERVER_NOTE
        summary["not_provable_by_observer_classes"] = dict(sorted(blind_classes.items()))
        summary["not_provable_by_observer_reasons"] = dict(sorted(blind_reasons.items()))
    summary["structural"] = structural_summary(findings)
    return summary


def structural_summary(findings: list[dict]) -> dict:
    """The second oracle's denominators — kept strictly beside the first, never merged.

    ``demonstrated`` and ``proven`` are different claims and get different
    numbers. Merging them would be the same dishonesty as merging
    ``not_applicable`` into "not proven", one layer along: a reader who sees a
    single "confirmed" column cannot tell a nonce-attributed process spawn in a
    fresh container from an AST differential over generated source, and those
    are not equally strong.

    Where this number earns its place is the ``not_provable_by_observer``
    bucket. On a real run that bucket held 74 of 145 findings, every one of them
    honest and every one of them useless to a reader: "no execution could settle
    this" is true and says nothing about whether the defect is real. A
    ``demonstrated`` count against that same bucket is what turns "we could not
    check" into "we checked another way, deterministically, and here is what the
    predicate saw".

    ``refuted`` is reported as loudly as ``demonstrated``. It is a deterministic
    demonstration that a defence works, it never deletes a finding, and a report
    that hid it would be publishing findings whose own evidence contradicts them.
    """
    by_outcome: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    demonstrated_classes: dict[str, int] = {}
    refuted_ids: list[str] = []

    probed = 0
    for finding in findings:
        record = finding.get("structural") or {}
        outcome = record.get("outcome")
        if not outcome:
            continue
        probed += 1
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        kind = record.get("probe_kind") or "unknown"
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if outcome == "demonstrated":
            vuln_class = str(finding.get("vuln_class") or "unknown")
            demonstrated_classes[vuln_class] = demonstrated_classes.get(vuln_class, 0) + 1
        elif outcome == "refuted":
            refuted_ids.append(str(finding.get("finding_id")))

    # How many of the findings the audit hook is blind to actually got a second
    # look. This ratio is the honest measure of whether the structural oracle is
    # being used, and a report that omitted it would let "0 demonstrated" mean
    # either "we probed and found nothing" or "we never probed".
    blind_total = sum(
        1 for f in findings
        if vuln_classes.observer_blind_reason(str(f.get("vuln_class") or ""))
    )
    blind_probed = sum(
        1 for f in findings
        if vuln_classes.observer_blind_reason(str(f.get("vuln_class") or ""))
        and (f.get("structural") or {}).get("outcome")
    )

    return {
        "probed": probed,
        "unprobed": len(findings) - probed,
        "demonstrated": by_outcome.get("demonstrated", 0),
        "refuted": by_outcome.get("refuted", 0),
        "inconclusive": by_outcome.get("inconclusive", 0),
        "probe_error": by_outcome.get("probe_error", 0),
        "probe_absent": by_outcome.get("probe_absent", 0),
        "not_attempted": by_outcome.get("not_attempted", 0),
        "by_outcome": dict(sorted(by_outcome.items())),
        "by_probe_kind": dict(sorted(by_kind.items())),
        "demonstrated_classes": dict(sorted(demonstrated_classes.items())),
        "refuted_finding_ids": sorted(refuted_ids),
        "observer_blind_total": blind_total,
        "observer_blind_probed": blind_probed,
        "note": (
            "A structural probe shows that the "
            "target's own code turned attacker-controlled text into an "
            "executable construct — or breached a stated resource bound, or "
            "mutated shared state — under a benign/hostile differential, "
            "measured by a harness the hunter did not write. The execution gate "
            "shows a dangerous operation firing, carrying this PoC's nonce, "
            "from the target's own frame, with the payload interpreted. Both "
            "are real; they are not the same claim, and they are never summed."
        ),
    }


def _oracle_conflicts(findings: list[dict], verifications: dict[str, dict]) -> dict:
    """Where the two oracles and the adversarial verifier disagree, by name.

    Three oracles run over the same finding — the execution gate, the
    structural probe, and a second model re-reading the source — and the
    report is only worth its denominators if it says when they contradicted
    each other rather than printing whichever one it reached last.

    * ``demonstrated_but_rejected`` is the case that keeps ``demonstrated``
      honest. A probe can hold on a predicate that is true and still be about a
      defect no attacker can reach: on the recorded h2 run,
      ``WindowManager.window_opened``'s check-before-mutate ordering bug was
      demonstrated in 2/2 runs and then rejected in 2c because no call site
      carries an attacker-supplied value. Both facts are true and the second is
      the one that decides whether to fix it today.
    * ``refuted_but_confirmed`` is the reverse, and it is a claim about the
      tool: the verifier read the probe's own carrier path and showed the
      "transform" was a content-preserving encode. A refutation that is
      overturned must be printed as an overturned refutation, not deleted.
    * ``proven_but_rejected`` outranks the verifier and is delivered anyway
      (``select_delivered``), so it is disclosed rather than silently resolved.
    """
    demonstrated_but_rejected: list[str] = []
    refuted_but_confirmed: list[str] = []
    proven_but_rejected: list[str] = []
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "")
        verdict = (verifications.get(finding_id) or {}).get("verdict")
        structural = finding.get("structural") or {}
        outcome = str(structural.get("outcome") or "")
        if outcome == "demonstrated" and verdict == "rejected":
            demonstrated_but_rejected.append(finding_id)
        if outcome == "refuted" and verdict == "confirmed":
            refuted_but_confirmed.append(finding_id)
        if findings_io.poc_succeeded(finding) and verdict == "rejected":
            proven_but_rejected.append(finding_id)
    conflicts: dict[str, Any] = {}
    if demonstrated_but_rejected:
        conflicts["demonstrated_but_rejected"] = sorted(demonstrated_but_rejected)
    if refuted_but_confirmed:
        conflicts["refuted_but_confirmed"] = sorted(refuted_but_confirmed)
    if proven_but_rejected:
        conflicts["proven_but_rejected"] = sorted(proven_but_rejected)
    return conflicts


#: The frame-walk signature of a `self_attributed` verdict that is a harness
#: artefact rather than a PoC that cheated. On CPython >= 3.11
#: `traceback.print_exc()` renders PEP-657 carets, which calls `ast.parse` on
#: the offending source segment and raises a watched `compile` event from the
#: PoC's own frame. The PoC never called `compile`; it printed a traceback.
_PEP657_MARKER = "audit:compile"


def _self_attribution_artefacts(findings: list[dict]) -> dict:
    """`self_attributed` verdicts whose only events are PEP-657 caret renders.

    The gate's word for this outcome is "the PoC reached the sink directly and
    did not exercise the target's path", which is the right reading of a PoC
    that cheated and the wrong reading of a PoC that printed a traceback. The
    distinction is checkable: an artefact's attributed-event list is entirely
    `compile` events and nothing was attributed to the target, so the verdict
    should be read as `no_event`. Counted and named here rather than left for a
    reader to infer from four identical-looking rows.
    """
    ids: list[str] = []
    for finding in findings:
        execution = finding.get("execution") or {}
        if str(execution.get("outcome") or "") != "self_attributed":
            continue
        evidence = [str(line) for line in (execution.get("evidence") or [])]
        if not evidence:
            continue
        if all(_PEP657_MARKER in line for line in evidence) and not int(
            execution.get("events_attributed") or 0
        ):
            ids.append(str(finding.get("finding_id") or ""))
    if not ids:
        return {}
    return {
        "count": len(ids),
        "finding_ids": sorted(ids),
        "note": (
            "Every runtime event these PoCs produced is a `compile` event "
            "raised from the PoC's own frame, and none was attributed to the "
            "target. That is the signature of PEP-657 caret rendering: on "
            "CPython 3.11+ `traceback.print_exc()` calls `ast.parse` on the "
            "offending source segment, which raises a watched `compile` event "
            "the observer's frame walk credits to the PoC. The PoC never "
            "called `compile`; it printed a traceback. Read these as "
            "`no_event` — a defect in PyHunt's observer, not a PoC that "
            "bypassed the code under test."
        ),
    }


def _sites_led_by_a_rejected_finding(
    findings: list[dict], verifications: dict[str, dict]
) -> dict:
    """Dedupe groups whose canonical record the verifier rejected.

    `dedupe.py` now prefers a deliverable sibling for the canonical slot, so a
    group in this list is one where EVERY member was rejected — the site is
    rendered by a rejected record or not at all, and a reader should be able to
    count those without opening `verify/`. Before that fix the list also caught
    groups where a confirmed finding was hidden behind a rejected canonical and
    withheld twice, which is how `settings.py:162-174` went missing.
    """
    groups: dict[str, list[dict]] = {}
    for finding in findings:
        group_id = str(finding.get("group_id") or "")
        if group_id:
            groups.setdefault(group_id, []).append(finding)
    rows: list[dict] = []
    for group_id, members in sorted(groups.items()):
        canonical = next((m for m in members if m.get("is_canonical")), None)
        if canonical is None:
            continue
        finding_id = str(canonical.get("finding_id") or "")
        if (verifications.get(finding_id) or {}).get("verdict") != "rejected":
            continue
        rows.append({
            "group_id": group_id,
            "canonical": finding_id,
            "file": canonical.get("file"),
            "line_start": canonical.get("line_start"),
            "members": len(members),
            "confirmed_members": sum(
                1 for m in members
                if (verifications.get(str(m.get("finding_id") or "")) or {}).get(
                    "verdict") == "confirmed"
            ),
        })
    if not rows:
        return {}
    return {
        "count": len(rows),
        "with_a_confirmed_member_hidden": sum(
            1 for r in rows if r["confirmed_members"]),
        "sites": rows,
        "note": (
            "Sites whose canonical record the adversarial verifier rejected. "
            "The whole group is withheld from the delivered set, which is "
            "correct only when no member survived verification — so "
            "`with_a_confirmed_member_hidden` must read 0. A non-zero value "
            "means a confirmed finding was withheld twice, once as rejected "
            "and once as a duplicate of the rejected record."
        ),
    }


def _run_context(manifest: dict) -> dict:
    """The header facts `phase4_report.md` prescribes, straight from the manifest.

    Mode, achieved isolation tier, scan date, the target's commit, and the
    model each phase ran as. The last one is the reason this function exists:
    "Model transparency" is a required section of the phase file — the pin that
    used to enforce model diversity mechanically is gone, and printing
    `model_used` per phase is the only thing left that makes a same-model
    verification visible. Nothing rendered it, so it was invisible on every
    run, including the runs where it would have mattered.

    Everything here is copied, never derived: a report that computes its own
    idea of which model ran is a report that can disagree with the manifest.
    """
    vcs = manifest.get("target_vcs") if isinstance(manifest.get("target_vcs"), dict) else {}
    context: dict[str, Any] = {}
    for key in ("mode", "isolation_tier", "isolation_verified", "target_scope",
                "started_at", "finished_at", "authorisation"):
        if manifest.get(key) not in (None, ""):
            context[key] = manifest[key]
    for key in ("repo", "tag", "commit"):
        if vcs.get(key):
            context[f"target_{key}"] = vcs[key]
    if isinstance(manifest.get("model_used"), dict):
        context["models"] = dict(manifest["model_used"])
    deviations = manifest.get("harness_deviations")
    if isinstance(deviations, list) and deviations:
        context["harness_deviations"] = len(deviations)
    phases = manifest.get("phases_completed")
    if isinstance(phases, list) and phases:
        context["phases_completed"] = list(phases)
    return context


def attach_coverage(payload: dict, run: dict, withheld: list[dict]) -> None:
    """Attach the consolidated coverage disclosure.

    ``coverage_complete`` is False whenever anything is unaccounted for: an
    enumerated input that never reached a disposition, a hunt task that failed
    or never finished, files the sweep cap dropped, or — importantly — task
    outcomes that were never recorded at all. An operator must never be told
    coverage is complete when it is merely unmeasured.

    The block also carries the execution summary and the preflight caveat.
    ``report.schema.json`` deliberately leaves ``coverage`` permissive
    (``additionalProperties`` allowed) so these disclosures have a schema-legal
    home; a future schema revision should promote ``coverage.execution`` to a
    top-level ``execution_summary``.
    """
    coverage_file = run.get("coverage") or {}
    inputs = coverage_file.get("inputs") or []
    totals = coverage_file.get("totals") or {}
    tasks = (run.get("tasks") or {}).get("tasks") or []
    verifications = run.get("verifications") or {}
    findings = run.get("findings") or []

    tasks_by_source: dict[str, int] = {}
    for task in tasks:
        source = str(task.get("source") or "unknown")
        tasks_by_source[source] = tasks_by_source.get(source, 0) + 1

    findings_by_status: dict[str, int] = {}
    for finding in findings:
        status = (verifications.get(finding["finding_id"]) or {}).get(
            "verdict"
        ) or "unverified"
        findings_by_status[status] = findings_by_status.get(status, 0) + 1

    coverage: dict[str, Any] = {
        "inputs_enumerated": int(totals.get("enumerated", len(inputs))),
        "inputs_covered": int(
            totals.get("covered", sum(1 for i in inputs if i.get("disposition") == "covered"))
        ),
        "inputs_uncovered": int(
            totals.get("uncovered", sum(1 for i in inputs if i.get("disposition") == "uncovered"))
        ),
        "tasks_by_source": tasks_by_source,
        "findings_by_status": findings_by_status,
    }
    for key in ("source_files", "covered_files", "catchall_tasks", "catchall_dropped"):
        if isinstance(coverage_file.get(key), int):
            coverage[key] = coverage_file[key]

    caveats: list[str] = []

    # A task's status comes from `tasks.json` when the queue itself recorded
    # one, and otherwise from the `task_outcomes.json` ledger that the hunter
    # appends to as it works. Without the second source nothing ever wrote a
    # status down, so `statuses_known` was false on every run ever made and the
    # caveat below fired unconditionally — which meant a thorough hunt and an
    # abandoned one produced the same report.
    outcomes = run.get("task_outcomes") or {}

    def _status(task: dict) -> str:
        recorded = task.get("status")
        if recorded:
            return str(recorded)
        entries = outcomes.get(str(task.get("task_id") or ""))
        if not entries:
            return ""
        last = entries[-1].get("outcome")
        return {"findings": "done", "clean": "done",
                "skipped": "skipped", "error": "failed"}.get(str(last), "")

    statuses = [_status(t) for t in tasks]
    statuses_known = bool(tasks) and all(s for s in statuses)
    if statuses_known:
        failed = sum(1 for s in statuses if s == "failed")
        incomplete = sum(1 for s in statuses if s not in ("done", "failed"))
        coverage["tasks_failed"] = failed
        coverage["tasks_incomplete"] = incomplete
        if failed or incomplete:
            caveats.append(
                f"{failed} hunt task(s) FAILED and {incomplete} never completed — "
                "the attack angles they covered were not examined. Absence of a "
                "finding in those areas is not evidence that none exists."
            )
    elif tasks:
        coverage["tasks_status_known"] = False
        caveats.append(
            f"{len(tasks)} hunt task(s) were queued but tasks.json records no "
            "per-task outcome, so it is not known whether every one completed. "
            "Coverage cannot be asserted complete on unmeasured tasks."
        )

    unreconciled = [
        i for i in inputs if not i.get("disposition")
    ] if inputs else []
    if unreconciled:
        caveats.append(
            f"{len(unreconciled)} enumerated input(s) never reached a disposition "
            "— they were neither hunted nor explicitly ruled out."
        )

    if withheld:
        reasons: dict[str, int] = {}
        for finding in withheld:
            reason = finding.get("_withheld_reason") or "unknown"
            reasons[reason] = reasons.get(reason, 0) + 1
        coverage["findings_withheld"] = reasons

    # The uncovered inputs BY NAME, not just as a count. `phase4_report.md`
    # disclosure 3 asks for "the uncovered ones listed by location and reason";
    # `report.json` carried them inside `input_inventory` and `report.md`
    # rendered only the integer, so the one number that names a gap arrived
    # with the gap itself stripped out. A reader of the advisory could see that
    # seven inputs were missed and had no way to learn which.
    inputs_by_id = {
        str(row.get("input_id") or row.get("id")): row
        for row in ((run.get("inputs") or {}).get("inputs") or [])
    }
    uncovered_rows = []
    for row in inputs:
        if row.get("disposition") == "covered":
            continue
        input_id = str(row.get("input_id") or row.get("id") or "")
        source = inputs_by_id.get(input_id, {})
        uncovered_rows.append({
            "id": input_id,
            "disposition": row.get("disposition") or "unreconciled",
            "location": source.get("location"),
            "entry_point": source.get("entry_point"),
            "trust_level": source.get("trust_level"),
            "source_type": source.get("source_type"),
            "reason": row.get("evidence") or row.get("disposition_evidence"),
            "note": source.get("notes"),
        })
    if uncovered_rows:
        coverage["uncovered_inputs"] = uncovered_rows

    coverage["run_context"] = _run_context(run.get("manifest") or {})
    coverage["execution"] = execution_summary(findings, run.get("manifest") or {})
    conflicts = _oracle_conflicts(findings, verifications)
    if conflicts:
        coverage["execution"]["oracle_conflicts"] = conflicts
    artefact = _self_attribution_artefacts(findings)
    if artefact:
        coverage["execution"]["self_attribution_artefacts"] = artefact
    rejected_canonicals = _sites_led_by_a_rejected_finding(findings, verifications)
    if rejected_canonicals:
        coverage["sites_canonicalised_by_a_rejected_finding"] = rejected_canonicals

    coverage["coverage_complete"] = bool(
        coverage.get("catchall_dropped", 0) == 0
        and not unreconciled
        and statuses_known
        and coverage.get("tasks_failed", 0) == 0
        and coverage.get("tasks_incomplete", 0) == 0
    )
    if caveats:
        coverage["caveats"] = caveats
    payload["coverage"] = coverage


def attach_preflight(payload: dict, preflight: dict) -> None:
    """Record what the run could ACTUALLY do, and caveat it where it could not.

    A scan whose container lacks the target's dependencies still emits findings
    — they are just static guesses that read like executed proof. The caveat is
    the part that matters: it puts the limitation where someone reading the
    findings will actually meet it, instead of in a log nobody opens.
    """
    if not preflight:
        return
    coverage = payload.setdefault("coverage", {})
    coverage["preflight"] = preflight
    if preflight.get("execution_enabled") and not preflight.get(
        "poc_confirmation_available"
    ):
        missing = ", ".join(preflight.get("degraded") or []) or "unknown"
        coverage.setdefault("caveats", []).append(
            "Executed-PoC confirmation was requested but NOT fully available in "
            f"this container (missing: {missing}). Findings below may not have "
            "been proven by execution, and a finding that could not be proven "
            "here must NOT be read as disproven."
        )
        coverage["coverage_complete"] = False


def subsystem_for(subsystems: list[dict], path: str | None) -> str:
    """Which recon subsystem owns a file.

    The rule is the one ``stages/_common.py`` and ``stages/gapfill.py`` both
    used, kept in one place this time: a subsystem matches when its ``name`` is
    the path exactly, or when the path sits under its ``path`` prefix. Anything
    unmatched is ``"unknown"`` — an honest label, and never silently folded
    into a neighbouring subsystem.
    """
    if not path:
        return "unknown"
    for subsystem in subsystems or []:
        prefix = str(subsystem.get("path") or "")
        if subsystem.get("name") == path or (prefix and path.startswith(prefix)):
            return str(subsystem.get("name") or "unknown")
    return "unknown"


def attach_subsystem_breakdown(payload: dict, findings: list[dict], run: dict) -> None:
    """Where the findings clustered, by recon subsystem.

    A count per subsystem answers the question an operator actually asks of a
    scan result — "which part of my system is the problem?" — and it is a
    read of data already on disk, so it costs nothing and cannot be wrong in a
    way the finding list is not. Omitted entirely when recon recorded no
    subsystems: an inventory of one bucket called "unknown" is noise.
    """
    subsystems = (
        (run.get("inputs") or {}).get("subsystems")
        or (run.get("recon") or {}).get("subsystems")
        or []
    )
    if not subsystems:
        return
    breakdown: dict[str, int] = {}
    for finding in findings:
        name = subsystem_for(subsystems, finding.get("file"))
        breakdown[name] = breakdown.get(name, 0) + 1
    payload.setdefault("coverage", {})["findings_by_subsystem"] = dict(
        sorted(breakdown.items())
    )


def attach_gaps(payload: dict, gaps: dict) -> None:
    """Carry the hunters' self-reported coverage gaps into the report.

    ``gaps_observed`` is not optional politeness: an empty array asserts the
    hunter examined everything in scope. A gap that a hunter reported and the
    report omitted is a disclosed limitation turned back into implied coverage.
    """
    entries = gaps.get("gaps") or []
    if entries:
        payload.setdefault("coverage", {})["gaps_observed"] = entries


# --------------------------------------------------------------------------
# The narrative merge — the one place model prose enters the payload
# --------------------------------------------------------------------------

def merge_narrative(payload: dict, narrative: dict) -> dict:
    """Join phase 4's prose to the computed payload. Prose only, by whitelist.

    This is the half of the phase-4 contract that was missing (5c). The phase
    tells the model to write ``logs/report_narrative.json`` and then to run
    ``report_build.py build --narrative …``; the flag did not exist, so the
    command failed outright at the end of a long, expensive run. Worse, had it
    merely been dropped from the phase, the prose would have had nowhere to go:
    ``impact``, ``exploit_scenario``, ``how_to_fix``, ``preconditions`` and
    ``threat_model`` are all in ``report.schema.json``, all rendered by
    ``reporting/markdown.py``, and NOTHING computed them — so every advisory
    printed "_Not determined (static run)._" for all of them, and every finding
    carried the same boilerplate ``DEFAULT_RECOMMENDATION``. The flag is the
    right side of the disagreement, so it is implemented here.

    Two rules make this safe:

    * **Whitelist, never blacklist.** Only ``NARRATIVE_FINDING_FIELDS`` and
      ``NARRATIVE_TOP_LEVEL_FIELDS`` are copied. A blacklist would silently
      admit every field a later schema revision adds, which is exactly how a
      model-authored number reaches a report that promises none.
    * **Key presence, not truthiness.** An explicitly empty ``preconditions``
      array is a CLAIM ("there are no preconditions") and the phase says to
      mean it, so it must survive the merge. Truthiness would discard it and
      the finding would render "_Not determined_" instead — a claim quietly
      converted into a gap.

    Findings join on ``finding_id``. A narrative entry naming a finding that
    was not delivered is not an error (the verifier may have rejected it after
    the model wrote its prose) but it IS reported, because the alternative is
    prose vanishing with no trace.

    Returns a report of what happened, for the CLI to print and for ``--strict``
    to fail on. Nothing here mutates a computed field, so a violation cannot
    corrupt the payload — but it is still surfaced, because supplying one means
    the model believed it was computing something it was not.
    """
    applied_fields = 0
    findings_with_prose = 0
    unmatched: list[str] = []
    computed_supplied: set[str] = set()

    for field in COMPUTED_TOP_LEVEL_FIELDS:
        if field in narrative:
            computed_supplied.add(field)
    for field in NARRATIVE_TOP_LEVEL_FIELDS:
        if field in narrative:
            payload[field] = narrative[field]
            applied_fields += 1

    entries_by_id = {
        str(e["finding_id"]): e
        for e in payload.get("findings", [])
        if e.get("finding_id")
    }
    for index, item in enumerate(narrative.get("findings") or []):
        if not isinstance(item, dict):
            unmatched.append(f"<narrative findings[{index}]: not an object>")
            continue
        # Checked BEFORE the unmatched short-circuit: supplying a computed
        # field is a statement about what the model thought it was doing, and
        # that belief is just as wrong on a finding that happened not to be
        # delivered. Skipping the check there would make the violation report
        # depend on delivery, which is unrelated.
        for field in COMPUTED_FINDING_FIELDS + COMPUTED_TOP_LEVEL_FIELDS:
            if field in item:
                computed_supplied.add(f"findings[].{field}")

        finding_id = str(item.get("finding_id") or "")
        entry = entries_by_id.get(finding_id)
        if entry is None:
            unmatched.append(finding_id or f"<narrative findings[{index}]: no finding_id>")
            continue
        touched = False
        for field in NARRATIVE_FINDING_FIELDS:
            if field in item:
                entry[field] = item[field]
                applied_fields += 1
                touched = True
        if touched:
            findings_with_prose += 1

    return {
        "narrative_findings_with_prose": findings_with_prose,
        "narrative_fields_applied": applied_fields,
        "narrative_unmatched_finding_ids": unmatched,
        "narrative_computed_fields_supplied": sorted(computed_supplied),
    }


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

def build(
    results_dir: str | Path,
    *,
    redact: bool = True,
    narrative: dict | None = None,
    merge_report: dict | None = None,
) -> dict:
    """Assemble the complete report payload for a results directory.

    ``narrative`` is phase 4's prose document, merged BEFORE redaction so the
    model's sentences pass through ``redact_json`` like everything else. A
    merge done after redaction would route model prose around the one masking
    boundary the design relies on — and prose is where a quoted secret is most
    likely to appear, since the model has read the source. ``merge_report``, if
    given, is updated in place with what the merge did.
    """
    run = load_run(results_dir)
    findings = run["findings"]
    verifications = run["verifications"]
    findings_by_id = {f["finding_id"]: f for f in findings}
    tasks_by_id = {
        str(t.get("task_id")): t for t in ((run.get("tasks") or {}).get("tasks") or [])
    }

    delivered, withheld = select_delivered(findings, verifications)
    payload = build_report_payload(run, delivered, tasks_by_id)

    attach_cwe(payload, findings_by_id)
    attach_poc_evidence(payload, findings_by_id, run["proofs"])
    attach_structural(payload, findings_by_id)
    attach_execution(payload, findings_by_id)
    attach_independent_units(payload, findings_by_id)
    attach_reachability(payload, Path(results_dir))
    attach_advisories(payload, Path(results_dir))
    attach_variants(payload, findings)
    attach_validation(payload, findings_by_id, verifications)
    attach_cvss(payload, verifications, run["inputs"])
    attach_input_inventory(payload, run["inputs"], run["coverage"])
    attach_coverage(payload, run, withheld)
    attach_subsystem_breakdown(payload, findings, run)
    attach_preflight(payload, run["preflight"])
    attach_gaps(payload, run["gaps"])
    attach_scan_metrics(payload, run["coverage"], run["manifest"])
    attach_verification(payload, findings, verifications)

    if narrative is not None:
        report = merge_narrative(payload, narrative)
        if merge_report is not None:
            merge_report.update(report)

    return redact_json(payload) if redact else payload


def report_stats(payload: dict) -> dict:
    """The handful of numbers phase 4's prose must quote, pulled out so the
    renderer does not have to re-derive (and so re-derive differently) any of
    them."""
    execution = (payload.get("coverage") or {}).get("execution") or {}
    stats = {
        "delivered": payload.get("summary", {}).get("total", 0),
        "by_severity": payload.get("summary", {}).get("by_severity", {}),
        "total_findings": execution.get("total", 0),
        "provable_by_execution": execution.get("provable_by_execution", 0),
        "proven_by_execution": execution.get("proven_by_execution", 0),
        "not_applicable": execution.get("not_applicable", 0),
        "not_provable_by_observer": execution.get("not_provable_by_observer", 0),
        "isolation_tier": execution.get("isolation_tier"),
        "mode": execution.get("mode"),
        "coverage_complete": (payload.get("coverage") or {}).get("coverage_complete"),
        "caveats": (payload.get("coverage") or {}).get("caveats", []),
    }
    # The plain-language sentence rides with the number it explains. A bare
    # "not_provable_by_observer: 4" invites the reader to hear "4 findings we
    # tried and failed to prove", which is the opposite of what it means.
    if execution.get("not_provable_by_observer_note"):
        stats["not_provable_by_observer_note"] = execution[
            "not_provable_by_observer_note"
        ]
        stats["not_provable_by_observer_classes"] = execution.get(
            "not_provable_by_observer_classes", {}
        )
    return stats


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _load_narrative(path_str: str) -> dict:
    """Read phase 4's narrative document, refusing anything else.

    A missing or malformed narrative is a hard error, never a silent skip: the
    caller asked for prose to be merged, and a report that quietly omits the
    model's entire narrative while exiting 0 is precisely the "silence reads as
    coverage" failure this module was built to stop.
    """
    path = Path(path_str)
    try:
        loaded = json.loads(path.read_text())
    except FileNotFoundError:
        raise ValueError(f"--narrative {path}: no such file") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"--narrative {path}: unreadable JSON ({exc})") from None
    if not isinstance(loaded, dict):
        raise ValueError(f"--narrative {path}: expected a JSON object")
    return loaded


def _cmd_build(args: argparse.Namespace) -> int:
    narrative = _load_narrative(args.narrative) if args.narrative else None
    merge_report: dict[str, Any] = {}
    payload = build(
        args.results_dir,
        redact=not args.no_redact,
        narrative=narrative,
        merge_report=merge_report,
    )
    errors = validate_schema(payload, Path(_bootstrap.schema_path("report")))

    out_path = Path(args.out or Path(args.results_dir) / "report.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n")

    markdown_path = None
    if args.markdown:
        # A deterministic Markdown rendering. Phase 4 passes --markdown
        # explicitly so that report.md is produced by this code path and never
        # hand-written; it stays opt-in rather than defaulting to
        # <results-dir>/report.md so that no other caller has a file clobbered
        # out from under it by a flag it did not pass.
        from reporting.markdown import render_report

        markdown_path = Path(args.markdown)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(render_report(payload))

    result = {
        "report_path": str(out_path),
        "markdown_path": str(markdown_path) if markdown_path else None,
        "schema_errors": errors,
        **merge_report,
        **report_stats(payload),
    }
    for error in errors:
        print(f"report.json does not match report.schema.json: {error}", file=sys.stderr)

    # A narrative that carried a computed field is a contract violation, not a
    # cosmetic one: it means the model believed it was computing a number this
    # report guarantees it never computes. The value was discarded by the
    # whitelist, so the payload is sound — but the belief needs correcting, and
    # `--strict` is where the phase says that surfaces.
    violations = merge_report.get("narrative_computed_fields_supplied") or []
    for field in violations:
        print(
            f"narrative supplied a computed field and it was discarded: {field}",
            file=sys.stderr,
        )
    for finding_id in merge_report.get("narrative_unmatched_finding_ids") or []:
        print(
            f"narrative prose for {finding_id} was dropped: not a delivered finding",
            file=sys.stderr,
        )

    print(json.dumps(result, indent=2))
    if args.strict and (errors or violations):
        return 2
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    print(json.dumps(report_stats(build(args.results_dir)), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="report_build.py",
        description="Assemble report.json from a PyHunt results directory. "
                    "Every number in the advisory comes from here.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build_cmd = sub.add_parser("build", help="write report.json")
    build_cmd.add_argument("--results-dir", required=True)
    build_cmd.add_argument("--out", help="default: <results-dir>/report.json")
    build_cmd.add_argument("--markdown", help="also render a deterministic "
                                              "Markdown advisory to this path")
    build_cmd.add_argument("--narrative",
                           help="phase 4's prose document "
                                "(logs/report_narrative.json). Only the "
                                "narrative fields are merged; computed fields "
                                "it carries are discarded and reported")
    build_cmd.add_argument("--strict", action="store_true",
                           help="exit 2 on a contract violation — the report "
                                "does not match report.schema.json, or the "
                                "narrative supplied a computed field (the "
                                "report is still written either way)")
    build_cmd.add_argument("--no-redact", action="store_true",
                           help="skip secret redaction — for local debugging only")
    build_cmd.set_defaults(func=_cmd_build)

    stats = sub.add_parser(
        "stats",
        help="the numbers phase 4's prose must quote, without writing anything",
    )
    stats.add_argument("--results-dir", required=True)
    stats.set_defaults(func=_cmd_stats)

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
