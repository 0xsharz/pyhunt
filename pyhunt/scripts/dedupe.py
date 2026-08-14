"""Collapse same-site findings, and keep the convergence as a confidence signal.

Two numbers from a real run make the case for this file existing.

**127 delivered findings across 81 distinct sites — 1.57 records per site.**
``base.py:240`` was filed five separate times. Phase 3 was supposed to collapse
those on root cause and effectively did not, because "group them" was an
instruction to a model rather than a computation. A reader handed that report
has to do the deduplication the tool should have done, and next to a comparison
run that shipped 18 actionable rows for the same package it is the difference
between a report you can act on in an afternoon and a report you have to
process first.

**21 of 55 sites were filed independently by two or more hunt units that could
not see each other's work.** That convergence is real evidence — several Opus
agents, each reading only its own task scope, landing on the same line — and the
old collapse threw it away. So the canonical record keeps
``independent_units``: the number of distinct hunt tasks that reached this site
without knowing the others had.

Three rules, and the first is the one that matters:

1. **Nothing is deleted.** A duplicate is marked ``is_canonical: false`` and
   keeps its file, its PoC and its verdict. ``report_build`` already demotes
   non-canonical findings to located "also at" references rather than dropping
   them, and phase 2b's proof records stay valid for every id.
2. **The canonical is chosen by evidence, not by luck.** Proven beats
   demonstrated beats severity beats a longer evidence snippet, and the final
   tie-break is the sorted finding id — so the same inputs always produce the
   same canonical, which is what makes a re-run comparable to the run before it.
3. **Grouping is mechanical and conservative.** Same file, same class family,
   and line ranges that overlap or sit within a small window. Two different
   defects on the same line stay separate because their classes differ; the same
   defect reported at ``:240`` and ``:242`` by two agents collapses.

Usage::

    python3 scripts/dedupe.py run --results-dir DIR [--window 3] [--dry-run]
    python3 scripts/dedupe.py report --results-dir DIR

Writes by default. A step that computes a grouping and leaves it on stdout is
the same defect as a re-queue nobody appends: everything downstream still
passes, and the work silently did not happen.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

try:  # pragma: no cover - bundled-venv shim
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:
    pass

import findings_io

#: Lines apart, inclusive, at which two findings in the same file and class are
#: still "the same site". Three is deliberately small: it absorbs one agent
#: pointing at the `def` and another at the `return` two lines down, and it does
#: not absorb two unrelated calls in the same function.
DEFAULT_WINDOW = 3

#: The window a *pre-verification* grouping may use. Zero, and it is not a knob.
#:
#: Windowed, class-family grouping is right for the report: by then every member
#: has its own verdict and the grouping only decides how the rows are presented.
#: It is wrong upstream of phase 2c, because there the group's canonical is the
#: only member anyone verifies and the rest inherit its verdict — so a merge that
#: is wrong deletes a finding instead of formatting one.
#:
#: That failure is not hypothetical. On the RealVuln run `app/config.py:13` and
#: `:15` were two different committed secrets; a window of 3 and a shared class
#: family merged them, and the benchmark scored the second as a miss. Verifying
#: only the canonical would have meant nobody ever read it.
VERIFY_WINDOW = 0

#: Class strings drift ("codegen_injection", "codegen-injection", "code
#: generation injection"). Grouping on the raw string would leave the same
#: defect in two groups, which is the failure this file exists to fix, so the
#: string is folded to a family first.
_CLASS_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("codegen_injection", ("codegen", "template_injection_into_generated")),
    ("code_injection", ("code_injection", "eval", "exec_injection", "untrusted_code")),
    ("command_injection", ("command_injection", "os_command", "shell_injection")),
    ("sql_injection", ("sql",)),
    ("deserialization", ("deserial", "pickle", "unmarshal")),
    ("path_traversal", ("path_traversal", "directory_traversal", "zip_slip")),
    ("ssrf", ("ssrf", "server_side_request")),
    ("resource_exhaustion", ("resource_exhaustion", "dos", "denial_of_service",
                             "algorithmic_complexity", "redos", "recursion",
                             "memory_exhaustion", "unbounded")),
    ("access_control", ("access_control", "authz", "authorization", "idor",
                        "privilege_escalation", "auth_bypass")),
    ("insecure_design", ("insecure_design", "insecure_default", "misconfig")),
    ("business_logic", ("business_logic", "logic_error", "logic_bug", "workflow")),
    ("input_handling", ("improper_input", "validation", "input_handling")),
    ("crypto", ("crypto", "weak_random", "hardcoded_secret")),
    ("state_mutation", ("state_mutation", "global_state", "race")),
    ("supply_chain", ("supply_chain", "dependency")),
)


def class_family(vuln_class: str | None) -> str:
    """Fold a class string onto a family key. Unknown strings keep themselves."""
    needle = re.sub(r"[^a-z0-9]+", "_", str(vuln_class or "").lower()).strip("_")
    if not needle:
        return "unknown"
    for family, markers in _CLASS_FAMILIES:
        if any(marker in needle for marker in markers):
            return family
    return needle


def _norm_file(path: str | None) -> str:
    """Repo-relative, forward slashes, no leading `./`.

    `lstrip("./")` is NOT the way to do this: it strips any leading run of `.`
    and `/` characters, so `.github/workflows/publish.yaml` normalises to
    `github/workflows/publish.yaml` — a path that matches nothing. That silently
    cost every CI finding its reachability tier, and would have split a dedupe
    group had one hunter written the dotted form and another the stripped one.
    """
    text = str(path or "").replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _line_range(finding: dict) -> tuple[int, int]:
    try:
        start = int(finding.get("line_start") or 0)
    except (TypeError, ValueError):
        start = 0
    try:
        end = int(finding.get("line_end") or start)
    except (TypeError, ValueError):
        end = start
    return (start, max(start, end))


def _adjacent(a: tuple[int, int], b: tuple[int, int], window: int) -> bool:
    """Overlapping, or within ``window`` lines of each other."""
    return not (a[1] + window < b[0] or b[1] + window < a[0])


def group_findings(findings: Sequence[dict], window: int = DEFAULT_WINDOW,
                   ) -> list[list[dict]]:
    """Partition findings into same-site groups.

    Single-linkage within (file, class family): a finding joins a group if it is
    adjacent to *any* member. That is what lets a chain at :240, :242, :244
    become one site rather than three, which is how the real duplicates
    presented.
    """
    buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for finding in findings:
        key = (_norm_file(finding.get("file")),
               class_family(finding.get("vuln_class")))
        buckets[key].append(finding)

    groups: list[list[dict]] = []
    for key in sorted(buckets):
        members = sorted(buckets[key], key=lambda f: (_line_range(f),
                                                      str(f.get("finding_id"))))
        current: list[dict] = []
        span: tuple[int, int] | None = None
        for finding in members:
            here = _line_range(finding)
            if current and span is not None and _adjacent(span, here, window):
                current.append(finding)
                span = (min(span[0], here[0]), max(span[1], here[1]))
            else:
                if current:
                    groups.append(current)
                current = [finding]
                span = here
        if current:
            groups.append(current)
    return groups


def exact_site_groups(findings: Sequence[dict]) -> list[list[dict]]:
    """Group only findings that are *certainly* the same defect.

    Same normalised file, same exact line span, same exact ``vuln_class`` — no
    window, no class-family folding. Two findings that satisfy all three are the
    same line described twice by two agents that could not see each other; there
    is no reading of the evidence on which they are separate defects.

    This is the grouping a verification plan may use. :func:`group_findings` is
    the grouping a *report* may use, and the two must not be swapped: see
    :data:`VERIFY_WINDOW` for the finding that cost.
    """
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for finding in findings:
        buckets[(_norm_file(finding.get("file")),
                 _line_range(finding),
                 str(finding.get("vuln_class") or "").strip().lower())].append(finding)
    return [sorted(members, key=lambda f: str(f.get("finding_id")))
            for _, members in sorted(buckets.items(), key=lambda kv: str(kv[0]))]


def verify_plan(results_dir: str | Path) -> dict:
    """One verification dispatch per exact site, with its members named.

    Phase 2c dispatches one adversarial verifier per *finding*, and site dedupe
    has historically run in phase 3 — after it. On a real run that meant asking
    eight separate agents, on eight separate dispatches, whether the same line of
    the same file was really a defect: 273 findings over 125 sites, 88 of them in
    one file.

    This returns the canonical each verifier should be given and the members that
    inherit its verdict, so the phase can be run per site instead of per row. The
    saving is the duplicate work and nothing else — every member keeps its own
    id, its own record, and its own row in the report.
    """
    findings = findings_io.load_findings(results_dir)
    groups = exact_site_groups(findings)
    plan: list[dict] = []
    for members in groups:
        canonical = max(members, key=lambda f: (
            1 if (f.get("poc") or {}).get("code") else 0,
            1 if f.get("structural_probe") else 0,
            _CONFIDENCE_RANK.get(str(f.get("confidence") or "").lower(), 0),
            str(f.get("finding_id")),
        ))
        plan.append({
            "site": f"{_norm_file(canonical.get('file'))}:{canonical.get('line_start')}",
            "vuln_class": canonical.get("vuln_class"),
            "canonical_id": canonical.get("finding_id"),
            "member_ids": [f.get("finding_id") for f in members],
            "independent_units": len(members),
        })
    return {
        "findings": len(findings),
        "verify_dispatches": len(plan),
        "duplicate_dispatches_avoided": len(findings) - len(plan),
        "window": VERIFY_WINDOW,
        "grouping": "exact site: same file, same line span, same vuln_class",
        "sites": plan,
    }


#: Confidence ordering for picking which member of an exact site a verifier reads.
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

#: Evidence rank for choosing the canonical. Higher wins.
_OUTCOME_RANK = {
    "proven": 100,
    "sink_reached_unproven": 40,
    "self_attributed": 20,
    "nonce_mismatch": 15,
    "no_event": 10,
    "observer_absent": 5,
    "not_attempted": 4,
    "not_applicable": 3,
}
_STRUCTURAL_RANK = {"demonstrated": 50, "inconclusive": 8, "probe_error": 2,
                    "probe_absent": 1, "refuted": 0, "not_attempted": 0}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def verdict_of(record: Any) -> str:
    """The phase 2c verdict string, from either record shape.

    `phases/phase2c_verify.md` writes an envelope whose `verdict` key holds an
    object; older records write the string directly. Both are read here so the
    canonical choice cannot depend on which shape the verifier happened to
    emit.
    """
    if not isinstance(record, dict):
        return ""
    inner = record.get("verdict")
    if isinstance(inner, dict):
        inner = inner.get("verdict")
    return str(inner or "").strip().lower()


def _deliverable_rank(finding: dict, verdicts: dict[str, str] | None) -> int:
    """0 if `report_build.select_delivered` would withhold this record.

    This is the first component of the canonical key, and it exists because of
    a defect this ordering used to have. `select_delivered` withholds a
    `rejected` finding, and separately withholds every non-canonical finding as
    `duplicate_of_canonical`. So a group whose canonical the verifier rejected
    disappears from the report *entirely* — taking a CONFIRMED sibling with it,
    withheld twice for two different reasons, neither of which is "the evidence
    was weak". On the recorded h2 run that happened at `settings.py:162-174`:
    `g_0019` canonicalised the rejected `f_taint_06_1` over the confirmed
    `f_sinkback_01_1`, and the site vanished.

    A `proven` finding is never withheld — `select_delivered` delivers it
    ahead of both checks — so it keeps rank 1 whatever the verifier concluded,
    and rule 2's "proven beats everything" is unchanged. Only a finding that
    is both unproven and rejected drops below its group.
    """
    execution = finding.get("execution") or {}
    if bool(execution.get("proven")) or str(execution.get("outcome")) == "proven":
        return 1
    verdict = (verdicts or {}).get(str(finding.get("finding_id") or ""), "")
    return 0 if verdict == "rejected" else 1


def _canonical_key(finding: dict, verdicts: dict[str, str] | None = None) -> tuple:
    execution = finding.get("execution") or {}
    structural = finding.get("structural") or {}
    return (
        _deliverable_rank(finding, verdicts),
        _OUTCOME_RANK.get(str(execution.get("outcome") or ""), 0),
        _STRUCTURAL_RANK.get(str(structural.get("outcome") or ""), 0),
        _SEVERITY_RANK.get(str(finding.get("severity") or "").lower(), 0),
        len(str(finding.get("evidence_snippet") or "")),
        len(str(finding.get("description") or "")),
        # Deterministic tie-break. Without it the canonical could flip between
        # two runs over identical inputs, and two reports of the same scan would
        # not be comparable.
        _inverse_id(str(finding.get("finding_id") or "")),
    )


def _inverse_id(finding_id: str) -> tuple:
    """Sort key that makes the lexicographically FIRST id win a tie."""
    return tuple(-ord(ch) for ch in finding_id)


def assign_groups(groups: Iterable[Sequence[dict]],
                  verdicts: dict[str, str] | None = None) -> list[dict]:
    """Stamp ``group_id`` / ``is_canonical`` / ``independent_units`` in place."""
    summary: list[dict] = []
    for index, group in enumerate(groups, 1):
        ordered = sorted(group, key=lambda f: _canonical_key(f, verdicts),
                         reverse=True)
        canonical = ordered[0]
        group_id = f"g_{index:04d}"
        units = sorted({str(f.get("task_id")) for f in group if f.get("task_id")})

        for finding in group:
            finding["group_id"] = group_id
            finding["is_canonical"] = finding is canonical
            if finding is canonical:
                # The convergence, kept rather than discarded. N independent
                # hunt tasks reaching the same site without seeing each other's
                # work is corroboration, and it used to be thrown away by the
                # very step that noticed it.
                finding["independent_units"] = len(units) or 1
                finding["duplicate_finding_ids"] = sorted(
                    str(f.get("finding_id")) for f in group if f is not canonical)
            else:
                finding["duplicate_of"] = str(canonical.get("finding_id"))
                finding.pop("independent_units", None)
                finding.pop("duplicate_finding_ids", None)

        summary.append({
            "group_id": group_id,
            "file": _norm_file(canonical.get("file")),
            "line_start": canonical.get("line_start"),
            "class_family": class_family(canonical.get("vuln_class")),
            "canonical": canonical.get("finding_id"),
            "canonical_verdict": (verdicts or {}).get(
                str(canonical.get("finding_id") or "")) or None,
            "members": sorted(str(f.get("finding_id")) for f in group),
            "size": len(group),
            "independent_units": len(units) or 1,
            "task_ids": units,
        })
    return summary


def run(results_dir: str | Path, *, window: int = DEFAULT_WINDOW,
        write: bool = True) -> dict:
    results = Path(results_dir)
    findings = findings_io.load_findings(results)
    # The verifier's verdicts are consulted for canonical choice only. Nothing
    # here rejects, deletes or reorders a finding on a verdict; a rejected
    # record stays in the group with its own file, PoC and verdict intact. It
    # simply stops being the one the report renders when a deliverable sibling
    # exists at the same site.
    verdicts = {
        finding_id: verdict_of(record)
        for finding_id, record in findings_io.load_verifications(results).items()
    }
    groups = group_findings(findings, window)
    summary = assign_groups(groups, verdicts)

    written = 0
    if write:
        for finding in findings:
            findings_io.write_finding(results, finding)
            written += 1

    multi = [row for row in summary if row["size"] > 1]
    converged = [row for row in summary if row["independent_units"] > 1]
    payload = {
        "findings": len(findings),
        "sites": len(summary),
        "records_per_site": round(len(findings) / len(summary), 2) if summary else 0,
        "collapsed": sum(row["size"] - 1 for row in summary),
        "sites_with_duplicates": len(multi),
        "sites_found_by_multiple_units": len(converged),
        # Disclosed rather than assumed away: a site whose only records the
        # verifier rejected is still rendered by its rejected canonical, and a
        # reader should be able to count those without opening `verify/`.
        "sites_canonicalised_by_a_rejected_finding": sum(
            1 for row in summary if row.get("canonical_verdict") == "rejected"),
        "window": window,
        "written": written,
        "groups": summary,
    }
    if not write:
        payload["note"] = ("--dry-run: nothing was written, so every downstream "
                           "phase will still see the ungrouped findings")
    return payload


def report(results_dir: str | Path) -> dict:
    """Read back what the grouping did, without recomputing it."""
    findings = findings_io.load_findings(Path(results_dir))
    by_group: dict[str, list[dict]] = defaultdict(list)
    ungrouped = 0
    for finding in findings:
        group_id = finding.get("group_id")
        if group_id:
            by_group[str(group_id)].append(finding)
        else:
            ungrouped += 1
    rows = []
    for group_id in sorted(by_group):
        members = by_group[group_id]
        canonical = next((f for f in members if f.get("is_canonical")), None)
        rows.append({
            "group_id": group_id,
            "size": len(members),
            "canonical": (canonical or {}).get("finding_id"),
            "independent_units": (canonical or {}).get("independent_units"),
            "file": _norm_file((canonical or {}).get("file")),
        })
    return {"groups": len(rows), "ungrouped": ungrouped, "rows": rows}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dedupe.py",
        description="Collapse same-site findings onto one canonical record and "
                    "record how many independent hunt units reached each site.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_cmd = sub.add_parser("run", help="group and stamp every finding")
    run_cmd.add_argument("--results-dir", required=True)
    run_cmd.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    run_cmd.add_argument("--dry-run", action="store_true",
                         help="compute the grouping without writing it")

    report_cmd = sub.add_parser("report", help="show the current grouping")
    report_cmd.add_argument("--results-dir", required=True)

    verify_cmd = sub.add_parser(
        "verify-plan",
        help="one verification dispatch per EXACT site (same file, line and "
             "class), with the members that inherit each verdict")
    verify_cmd.add_argument("--results-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "report":
            print(json.dumps(report(args.results_dir), indent=2))
            return 0
        if args.cmd == "verify-plan":
            payload = verify_plan(args.results_dir)
            print(json.dumps(payload, indent=2))
            sys.stderr.write(
                f"dedupe: {payload['findings']} finding(s) -> "
                f"{payload['verify_dispatches']} verification dispatch(es); "
                f"{payload['duplicate_dispatches_avoided']} duplicate "
                f"dispatch(es) avoided, exact-site grouping only\n")
            return 0
        payload = run(args.results_dir, window=args.window, write=not args.dry_run)
        printable = {k: v for k, v in payload.items() if k != "groups"}
        print(json.dumps(printable, indent=2))
        Path(args.results_dir, "logs").mkdir(parents=True, exist_ok=True)
        Path(args.results_dir, "logs", "dedupe_groups.json").write_text(
            json.dumps(payload["groups"], indent=2) + "\n", encoding="utf-8")
        sys.stderr.write(
            f"dedupe: {payload['findings']} finding(s) -> {payload['sites']} site(s) "
            f"({payload['records_per_site']} per site); "
            f"{payload['sites_found_by_multiple_units']} site(s) found "
            "independently by more than one unit\n")
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"internal error: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
