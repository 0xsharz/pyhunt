"""The deterministic half of adversarial verification.

Phase 2c asks a model, on a different model than the hunt, to try to *disprove*
each finding. That judgement is genuinely a model's job. Three things around it
are not, and each of them used to live inside ``stages/validate.py`` next to
the agent dispatch that is being deleted:

**1. CVSS is arithmetic, not an adjective.** A verifier that confirms a finding
emits a CVSS 3.1 *vector*. The base score is then computed by
:mod:`cvss` — the FIRST.org formula, in Python — and the qualitative band it
lands in supersedes the hunter's original severity. A model asked for a score
instead of a vector will produce a plausible number that does not follow from
its own vector, and nobody downstream can tell.

**2. Exact duplicates must not buy their own agent call.** Hunt legitimately
raises the identical finding from two different tasks, because taint,
specialist and catch-all sweeps all target the same file for different attack
classes. Measured on real targets: 7 exact duplicates on one repo (~$3.31 of
verification) and 3 on another (~$1.13). The representative is verified; its
duplicates inherit the verdict, marked ``inherited_from`` so a reviewer can see
that no validator looked at that particular record.

The identity key is deliberately the strictest possible one — same file, same
exact line range, same class. It involves no judgement, no similarity
threshold, and no model call, so collapsing on it cannot merge two things a
human would call different. Anything looser (same file, overlapping ranges,
related classes) is a semantic decision that belongs to the sweep phase, which
has a model and a prompt for exactly that.

**3. A verifier that fails is not a verifier that confirmed.** When the
verification agent cannot produce a schema-valid verdict, the finding is
recorded ``needs_more_info`` with the failure as its rationale — never
confirmed by default, and never dropped.

Nothing here deletes a finding. A ``rejected`` verdict is recorded as the
verifier's opinion; the report discloses it alongside the execution gate's
verdict, and an execution-proven finding is delivered regardless (see
``report_build.py``). A model does not get to overrule a nonce-attributed,
interpreted, target-frame event.
"""

from __future__ import annotations

import _bootstrap  # noqa: F401  (must precede any third-party import)

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

import findings_io
from cvss import rating as cvss_rating, score as cvss_score
from json_utils import validate_schema

#: CVSS 3.1 qualitative band -> the finding-severity enum in
#: ``finding.schema.json``. ``None`` and ``Unknown`` are deliberately absent:
#: they mean "no mapped band", and the caller must then KEEP the finding's
#: existing severity rather than overwrite it with a guess.
CVSS_RATING_TO_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

#: Rationale stamped on an inherited verdict, so the inheritance is legible in
#: the stored record and not just in this module's history.
INHERITED_REASON = (
    "exact duplicate of the representative finding: same file, same line "
    "range, same vuln_class"
)


def severity_from_cvss_rating(rating_label: str | None) -> str | None:
    """Map a CVSS 3.1 qualitative rating onto the finding severity enum.

    Returns None for ``None``/``Unknown``/absent so the caller falls back to
    (that is: keeps) the finding's existing severity.
    """
    return CVSS_RATING_TO_SEVERITY.get((rating_label or "").strip().lower())


def apply_cvss(payload: dict) -> tuple[dict, str | None]:
    """Fold a computed CVSS score and band into a verification payload.

    Returns ``(payload, severity_or_None)``. The payload is a new dict; the
    severity is the band-derived value the caller should write onto the
    finding, or None when there was no usable vector.

    Fail-open: an absent or unparseable vector (``cvss.score()`` returns None)
    leaves the payload untouched and yields no severity. A verification must
    never fail because a vector was malformed — the verdict still stands.
    """
    computed = cvss_score(payload.get("cvss_vector"))
    if computed is None:
        return payload, None
    label = cvss_rating(computed)
    enriched = {**payload, "cvss_score": computed, "cvss_rating": label}
    return enriched, severity_from_cvss_rating(label)


def identity_key(finding: dict) -> tuple:
    """The tuple that makes two findings PROVABLY the same finding."""
    return (
        finding.get("file"),
        finding.get("line_start"),
        finding.get("line_end"),
        finding.get("vuln_class"),
    )


def partition_duplicates(
    findings: Iterable[dict],
) -> tuple[list[dict], dict[str, list[dict]]]:
    """Split findings into ``(representatives, {rep_id: [duplicates]})``.

    Order is preserved and the representative is the first occurrence, so the
    partition is deterministic across runs given a deterministic input order
    (``findings_io.iter_findings`` sorts by filename for exactly this reason).
    """
    representatives: list[dict] = []
    duplicates: dict[str, list[dict]] = {}
    seen: dict[tuple, dict] = {}
    for finding in findings:
        key = identity_key(finding)
        representative = seen.get(key)
        if representative is None:
            seen[key] = finding
            representatives.append(finding)
        else:
            duplicates.setdefault(representative["finding_id"], []).append(finding)
    return representatives, duplicates


def duplicate_skip_plan(findings: Iterable[dict]) -> dict:
    """What verification would cost with and without the duplicate skip."""
    findings = list(findings)
    representatives, duplicates = partition_duplicates(findings)
    n_duplicates = sum(len(v) for v in duplicates.values())
    return {
        "findings": len(findings),
        "representatives": [f["finding_id"] for f in representatives],
        "duplicates": {
            rep: [d["finding_id"] for d in dupes] for rep, dupes in duplicates.items()
        },
        "agent_calls": len(representatives),
        "agent_calls_saved": n_duplicates,
    }


def inherited_verdict(representative_payload: dict, rep_id: str, duplicate_id: str) -> dict:
    """The verdict a duplicate inherits from its representative.

    Marked rather than copied silently: a reviewer reading a stored
    verification must be able to tell that no validator looked at THIS record,
    and which record it did look at.
    """
    return {
        **representative_payload,
        "finding_id": duplicate_id,
        "inherited_from": rep_id,
        "inherited_reason": INHERITED_REASON,
    }


def failed_verdict(finding_id: str, reason: str) -> dict:
    """The verdict for a verification that could not be produced.

    ``needs_more_info``, never ``confirmed``: a verifier that crashed has not
    confirmed anything, and defaulting the other way would silently promote
    every finding whose verification hit a transient error.
    """
    return {
        "finding_id": finding_id,
        "verdict": "needs_more_info",
        "rationale": (
            "the adversarial verification did not produce a schema-valid "
            f"verdict, so this finding has not been independently reviewed: {reason}"
        ),
        "validator_confidence": 0.0,
    }


def record_verdict(
    results_dir: str | Path,
    payload: dict,
    *,
    model: str | None = None,
    duplicates: list[dict] | None = None,
) -> dict:
    """Store a verification verdict, apply its CVSS, and propagate it.

    Returns a summary of everything written. The severity write-back is the
    part that must not be skipped: without it a `critical` CVSS vector sits in
    the verification payload while the report still renders the hunter's
    `medium`, and the two disagree in the delivered document.
    """
    finding_id = payload.get("finding_id")
    if not finding_id:
        raise ValueError("verification payload has no finding_id")

    enriched, severity = apply_cvss(payload)
    if model:
        enriched["model_used"] = model

    findings_io.save_verification(results_dir, finding_id, enriched)
    written = [finding_id]
    rescored: list[str] = []
    if severity and payload.get("verdict") == "confirmed":
        findings_io.set_severity(results_dir, finding_id, severity)
        rescored.append(finding_id)

    for duplicate in duplicates or []:
        dup_id = duplicate["finding_id"]
        findings_io.save_verification(
            results_dir, dup_id, inherited_verdict(enriched, finding_id, dup_id)
        )
        written.append(dup_id)
        # Re-derive from the same band rather than copying the representative's
        # stored severity, so a duplicate can never end up rated differently
        # from the record whose verdict it inherited.
        if severity and payload.get("verdict") == "confirmed":
            findings_io.set_severity(results_dir, dup_id, severity)
            rescored.append(dup_id)

    return {
        "finding_id": finding_id,
        "verdict": payload.get("verdict"),
        "cvss_score": enriched.get("cvss_score"),
        "cvss_rating": enriched.get("cvss_rating"),
        "severity_applied": severity,
        "verifications_written": written,
        "severities_updated": rescored,
        "inherited_by": [d["finding_id"] for d in duplicates or []],
        "model_used": model,
    }


def model_diversity(manifest: dict, model: str | None) -> dict:
    """Was the verification run on a different model than the hunt?

    In the CLI this was pinned in ``config/stages.yaml`` with a comment saying
    it was load-bearing. A skill cannot pin it — Claude Code chooses the model
    — so it became an instruction, and an instruction that nothing checks is a
    suggestion. This is the check: it cannot enforce diversity, but it makes a
    same-model verification a recorded fact rather than an invisible one.

    A verifier sharing the producer's model shares its blind spots. That is the
    whole reason the rule exists; it is not a cost knob.
    """
    hunt_model = (manifest.get("model_used") or {}).get("phase2_hunt")
    if not model or not hunt_model:
        return {"known": False, "diverse": None, "hunt_model": hunt_model,
                "verify_model": model}
    return {
        "known": True,
        "diverse": model != hunt_model,
        "hunt_model": hunt_model,
        "verify_model": model,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _load_payload(source: str) -> Any:
    return json.loads(sys.stdin.read() if source == "-" else Path(source).read_text())


def _cmd_plan(args: argparse.Namespace) -> int:
    findings = findings_io.load_findings(args.results_dir)
    plan = duplicate_skip_plan(findings)
    if plan["agent_calls_saved"]:
        print(
            f"{plan['agent_calls_saved']} of {plan['findings']} findings are exact "
            f"duplicates (same file+lines+class) — {plan['agent_calls']} "
            f"verification calls instead of {plan['findings']}",
            file=sys.stderr,
        )
    print(json.dumps(plan, indent=2))
    return 0


def _cmd_apply(args: argparse.Namespace) -> int:
    payload = _load_payload(args.verdict)
    errors = validate_schema(payload, Path(_bootstrap.schema_path("validation")))
    if errors:
        print(f"verdict does not match validation.schema.json: {errors}", file=sys.stderr)
        return 2

    findings = findings_io.load_findings(args.results_dir)
    _representatives, duplicates = partition_duplicates(findings)
    result = record_verdict(
        args.results_dir,
        payload,
        model=args.model,
        duplicates=duplicates.get(payload["finding_id"], []),
    )
    diversity = model_diversity(findings_io.load_manifest(args.results_dir), args.model)
    result["model_diversity"] = diversity
    if diversity.get("diverse") is False:
        print(
            f"verification ran on the same model as the hunt ({args.model}) — a "
            f"verifier sharing the producer's model shares its blind spots",
            file=sys.stderr,
        )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_fail(args: argparse.Namespace) -> int:
    findings = findings_io.load_findings(args.results_dir)
    _representatives, duplicates = partition_duplicates(findings)
    result = record_verdict(
        args.results_dir,
        failed_verdict(args.finding_id, args.reason),
        model=args.model,
        duplicates=duplicates.get(args.finding_id, []),
    )
    print(f"{args.finding_id}: verification failed, recorded needs_more_info "
          f"(the finding is kept)", file=sys.stderr)
    print(json.dumps(result, indent=2))
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    computed = cvss_score(args.vector)
    label = cvss_rating(computed)
    print(json.dumps({
        "vector": args.vector,
        "score": computed,
        "rating": label,
        "severity": severity_from_cvss_rating(label),
    }, indent=2))
    return 0 if computed is not None else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validate_gates.py",
        description="Deterministic gates around adversarial verification: CVSS "
                    "arithmetic, exact-duplicate skip, verdict propagation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser(
        "plan",
        help="which findings need a verification call, and which inherit one",
    )
    plan.add_argument("--results-dir", required=True)
    plan.set_defaults(func=_cmd_plan)

    apply_ = sub.add_parser(
        "apply",
        help="store one verification verdict, compute its CVSS, propagate to duplicates",
    )
    apply_.add_argument("--results-dir", required=True)
    apply_.add_argument("--verdict", required=True,
                        help="path to the verdict JSON, or - for stdin")
    apply_.add_argument("--model", help="the model the verification ran on — "
                                        "recorded so a same-model verification "
                                        "is detectable after the fact")
    apply_.set_defaults(func=_cmd_apply)

    fail = sub.add_parser(
        "fail",
        help="record a verification that could not be produced as needs_more_info",
    )
    fail.add_argument("--results-dir", required=True)
    fail.add_argument("--finding-id", required=True)
    fail.add_argument("--reason", required=True)
    fail.add_argument("--model")
    fail.set_defaults(func=_cmd_fail)

    score = sub.add_parser("score", help="compute a CVSS 3.1 base score from a vector")
    score.add_argument("--vector", required=True)
    score.set_defaults(func=_cmd_score)

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
