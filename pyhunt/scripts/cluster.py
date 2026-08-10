"""Root-cause clustering — the tier above site dedupe (W5.1).

`dedupe.py` answers "is this the same *line*". This answers "is this the same
*defect*", which is a different question and the one a maintainer actually has.

The evidence is blunt. A real run delivered **127 rows over 81 sites** against a
comparison tool's 18 actionable entries. Site dedupe took that to 55 rows over
69 sites — better, and still **eight separate rows for one bug** in
`model_generator/lang/python/base.py`, where untrusted schema text is
interpolated into emitted source at eight call sites of the same template
helper. Eight rows is eight fixes to schedule, eight tickets to triage, and one
actual defect. The reader was left to do the clustering, which is the work the
tool is for.

So this module emits **advisories**: one entry per root cause, carrying every
location it occurs at.

    "Untrusted schema text is interpolated into emitted source without
     escaping" — 8 locations, 1 proven, 3 demonstrated

**Nothing is deleted, and this is the load-bearing part.** Sites stay
individually patchable in `report.json.findings[]` with their own ids, verdicts,
CVSS and proof records. The advisory is a *view* over them, and every advisory
names its member finding ids. A reader who wants the eight lines gets the eight
lines; a reader who wants to know how many bugs there are gets one. Collapsing
the underlying rows would trade a readability problem for a coverage lie, which
is the trade this whole pipeline refuses everywhere else.

**How a root cause is identified.** Two findings share a root cause when they
share a class family AND a *cause signature*, computed in this order:

1. **The dangerous call itself.** `taint.py`'s sink tables already name the
   idioms — `.render(`, `subprocess.run(`, `yaml.load(` — and a match in the
   evidence snippet is the strongest available signal that two findings are the
   same defect rather than two defects in one class.
2. **The enclosing symbol**, when the findings name one. Eight call sites in one
   helper are one defect; the same call in two unrelated functions may not be.
3. **The file**, as the fallback. Same class, same file, no other signal — the
   base.py case, and the one that motivated the module.

A finding that shares no signature with anything is its own cluster of one, and
its advisory reads exactly like a single finding. Clustering must never make a
lone finding harder to see.

**Severity, settlement, and the arithmetic that must not be faked.** An
advisory's severity is the **maximum** over its members, never an average — one
proven RCE among seven unproven siblings is a proven RCE. Its `proven` and
`demonstrated` counts stay separate all the way to the renderer, per SKILL.md
§1: they are different claims from different oracles and are never summed.

Contract:

    python3 scripts/cluster.py run --results-dir DIR [--dry-run]
    python3 scripts/cluster.py report --results-dir DIR

JSON to stdout; human notes to stderr; exit 0 normally, 2 on a contract
violation, 1 on an internal error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

import findings_io
from dedupe import class_family, _norm_file

try:  # taint imports the sink tables; a missing one degrades, never aborts
    from taint import PYTHON_SINKS
except Exception:  # pragma: no cover - defensive
    PYTHON_SINKS = {}

SCHEMA_ID = "pyhunt.clusters/1"

# How a signature was derived, strongest first. Emitted on every advisory so a
# reader can tell "these share a dangerous call" from "these are merely in the
# same file", which are very different levels of confidence that two findings
# are one defect.
SIGNATURE_KINDS = ("sink_call", "enclosing_symbol", "file")

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_SEVERITY_BY_RANK = {v: k for k, v in _SEVERITY_RANK.items()}

# Where a finding might name the function it lives in. Hunters are inconsistent
# about this and the schema does not require it, so several spellings are tried
# before falling back a tier.
_SYMBOL_KEYS = ("symbol", "function", "enclosing_symbol", "sink_symbol")

_IDENT_RX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ContractViolation(Exception):
    """A caller error the skill must not route around — surfaces as exit 2."""


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------
def _evidence_text(finding: dict) -> str:
    """The finding's quoted CODE, and only that.

    Deliberately excludes `description` and `title`. The first version searched
    the prose too and clustered thirteen codegen findings under ``__import__(``
    — a call that appears nowhere in their code and everywhere in a hunter's
    explanation of why code generation is dangerous. A signature drawn from
    prose describes how the finding was written up, not what it is.
    """
    parts = [finding.get("evidence_snippet"), finding.get("evidence")]
    return "\n".join(str(p) for p in parts if p)


def sink_token(finding: dict) -> str | None:
    """The dangerous call this finding is about, from the sink tables.

    Returns a stable, readable token (the matched text, whitespace stripped)
    rather than the regex, so an advisory can say *why* its members are one
    defect in words a reader recognises.
    """
    text = _evidence_text(finding)
    if not text:
        return None
    family = class_family(finding.get("vuln_class"))
    # Prefer the table for this finding's own class; fall back to all tables,
    # because a mislabelled class should not cost the clustering.
    ordered = []
    if family in PYTHON_SINKS:
        ordered.append((family, PYTHON_SINKS[family]))
    ordered.extend((k, v) for k, v in PYTHON_SINKS.items() if k != family)

    for _class_name, patterns in ordered:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                token = re.sub(r"\s+", "", match.group(0))
                return token.rstrip("(") + "("
    return None


def enclosing_symbol(finding: dict) -> str | None:
    for key in _SYMBOL_KEYS:
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def cause_signature(finding: dict) -> tuple[str, str, str]:
    """``(class_family, kind, key)`` — the root cause this finding belongs to."""
    family = class_family(finding.get("vuln_class"))
    token = sink_token(finding)
    if token:
        return (family, "sink_call", token)
    symbol = enclosing_symbol(finding)
    if symbol:
        return (family, "enclosing_symbol", symbol)
    return (family, "file", _norm_file(finding.get("file")))


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------
def cluster_findings(findings: Sequence[dict]) -> list[list[dict]]:
    """Partition canonical findings into root-cause clusters.

    Only canonical findings participate. A duplicate already belongs to a site
    group, and letting it into a cluster would count one line twice.
    """
    buckets: dict[tuple[str, str, str], list[dict]] = {}
    order: list[tuple[str, str, str]] = []
    for finding in findings:
        if finding.get("is_canonical") is False:
            continue
        key = cause_signature(finding)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(finding)
    return [buckets[key] for key in order]


def _execution_outcome(finding: dict) -> str | None:
    """The gate's verdict for a STORED finding.

    `report.json` rows carry an `execution` block (D20); the stored records in
    `findings/` do not, and reading for one there silently returns `proven: 0`
    for a run that proved something. `findings_io` owns this lookup.
    """
    try:
        return findings_io.execution_outcome(finding)
    except Exception:  # pragma: no cover - defensive
        block = finding.get("execution")
        if isinstance(block, dict) and isinstance(block.get("outcome"), str):
            return block["outcome"]
        return None


def _structural_outcome(finding: dict) -> str | None:
    block = finding.get("structural")
    if isinstance(block, dict) and isinstance(block.get("outcome"), str):
        return block["outcome"]
    return None


def _max_severity(members: Sequence[dict]) -> str:
    """The maximum, never an average.

    One proven RCE among seven unproven siblings is a proven RCE, and an
    advisory that averaged it into "medium" would be actively misleading about
    the most important row in the report.
    """
    best = 0
    for finding in members:
        best = max(best, _SEVERITY_RANK.get(
            str(finding.get("severity") or "").lower(), 0))
    return _SEVERITY_BY_RANK.get(best, "info")


def _title_for(members: Sequence[dict], kind: str, key: str) -> str:
    """A one-line statement of the defect, borrowed from the best member."""
    ranked = sorted(
        members,
        key=lambda f: (
            _execution_outcome(f) == "proven",
            _structural_outcome(f) == "demonstrated",
            _SEVERITY_RANK.get(str(f.get("severity") or "").lower(), 0),
            len(str(f.get("title") or "")),
        ),
        reverse=True,
    )
    best = ranked[0]
    title = str(best.get("title") or "").strip()
    if not title:
        # Stored findings carry `description`, not `title` — `title` is added
        # at report time. Falling straight through to "<class> at <file>" threw
        # away the one sentence that actually says what the defect is.
        description = str(best.get("description") or "").strip()
        if description:
            first = re.split(r"(?<=[.!?])\s+", description)[0].strip()
            title = first if len(first) <= 180 else first[:177].rstrip() + "…"
    if not title:
        family = class_family(best.get("vuln_class")).replace("_", " ")
        title = f"{family} at {_norm_file(best.get('file'))}"
    if len(members) > 1:
        return f"{title} — and {len(members) - 1} more site(s) of the same cause"
    return title


def build_advisories(clusters: Iterable[Sequence[dict]]) -> list[dict]:
    """One advisory per root cause, with every location it occurs at."""
    advisories: list[dict] = []
    for index, members in enumerate(clusters, 1):
        family, kind, key = cause_signature(members[0])
        locations = sorted(
            {
                (
                    _norm_file(f.get("file")),
                    int(f.get("line_start") or 0),
                    str(f.get("finding_id") or ""),
                )
                for f in members
            },
            key=lambda row: (row[0], row[1]),
        )
        proven = sum(1 for f in members if _execution_outcome(f) == "proven")
        demonstrated = sum(
            1 for f in members if _structural_outcome(f) == "demonstrated")
        refuted = sum(
            1 for f in members if _structural_outcome(f) == "refuted")
        units = sum(int(f.get("independent_units") or 1) for f in members)
        cwes = sorted({str(f.get("cwe")) for f in members if f.get("cwe")})

        advisories.append({
            "advisory_id": f"a_{index:04d}",
            "title": _title_for(members, kind, key),
            "class_family": family,
            "cwe": cwes[0] if len(cwes) == 1 else None,
            "cwes": cwes,
            "severity": _max_severity(members),
            "site_count": len(members),
            "signature": {"kind": kind, "key": key},
            "signature_note": _SIGNATURE_NOTES[kind],
            "locations": [
                {"file": f, "line": line, "finding_id": fid}
                for f, line, fid in locations
            ],
            "finding_ids": sorted(str(f.get("finding_id")) for f in members),
            # Never summed. Two oracles, two claims — see SKILL.md §1.
            "proven": proven,
            "demonstrated": demonstrated,
            "refuted": refuted,
            "independent_units": units,
        })

    # **Machine-settled first, then severity.**
    #
    # The first version sorted on severity alone, and on the recorded run that
    # buried the single `proven` finding — a medium — beneath fifteen unproven
    # highs. That is exactly backwards for this tool. Severity is a *claim* a
    # model made about impact; `proven` is *evidence* that a container observed
    # the dangerous operation fire with the payload interpreted. A report whose
    # top rows are unproven claims, with the one thing it actually demonstrated
    # sixteen rows down, has buried its own strongest result.
    #
    # Within each band the order is the ordinary one, so severity still does
    # the triage work it is good at.
    advisories.sort(key=lambda a: (
        0 if a["proven"] else (1 if a["demonstrated"] else 2),
        -_SEVERITY_RANK.get(a["severity"], 0),
        -a["proven"], -a["demonstrated"], -a["site_count"], a["advisory_id"],
    ))
    return advisories


_SIGNATURE_NOTES = {
    "sink_call": ("these sites share the same dangerous call, which is the "
                  "strongest available signal that they are one defect"),
    "enclosing_symbol": ("these sites share the enclosing symbol, so one fix "
                         "in that function most likely closes all of them"),
    "file": ("these sites share a class and a file and nothing stronger — "
             "treat the grouping as a reading aid, not as proof that one fix "
             "closes all of them"),
}


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
def _atomic_write_json(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def run(results_dir: str | Path, *, write: bool = True) -> dict:
    results = Path(results_dir)
    if not results.is_dir():
        raise ContractViolation(f"results directory {results} does not exist")

    findings = findings_io.load_findings(results)
    canonical = [f for f in findings if f.get("is_canonical") is not False]
    clusters = cluster_findings(canonical)
    advisories = build_advisories(clusters)

    multi = [a for a in advisories if a["site_count"] > 1]
    payload = {
        "schema": SCHEMA_ID,
        "findings_total": len(findings),
        "canonical_sites": len(canonical),
        "advisories": len(advisories),
        "advisories_with_multiple_sites": len(multi),
        "largest_advisory": max((a["site_count"] for a in advisories), default=0),
        "sites_per_advisory": (
            round(len(canonical) / len(advisories), 3) if advisories else 0.0),
        "by_signature_kind": {
            kind: sum(1 for a in advisories if a["signature"]["kind"] == kind)
            for kind in SIGNATURE_KINDS
        },
        "settled_advisories": sum(
            1 for a in advisories if a["proven"] or a["demonstrated"]),
        "order_note": (
            "Machine-settled advisories first (proven, then demonstrated), "
            "then by severity. Severity is a claim about impact; `proven` is "
            "evidence that a container observed the dangerous operation fire. "
            "Sorting on severity alone buried this run's one proven finding "
            "beneath fifteen unproven highs."
        ),
        "entries": advisories,
    }
    if write:
        _atomic_write_json(results / "logs" / "clusters.json", payload)
        payload["written"] = str(results / "logs" / "clusters.json")
    return payload


def report(results_dir: str | Path) -> dict:
    path = Path(results_dir) / "logs" / "clusters.json"
    if not path.is_file():
        raise ContractViolation(
            f"{path} does not exist — run `cluster.py run` first")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cluster.py",
        description="Group same-root-cause findings into advisories (W5.1).")
    sub = parser.add_subparsers(dest="command", required=True)
    run_cmd = sub.add_parser("run", help="compute advisories and write them")
    run_cmd.add_argument("--results-dir", required=True)
    run_cmd.add_argument("--dry-run", action="store_true",
                         help="compute without writing logs/clusters.json")
    report_cmd = sub.add_parser("report", help="print the stored advisories")
    report_cmd.add_argument("--results-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            payload = run(args.results_dir, write=not args.dry_run)
            print(
                f"cluster: {payload['canonical_sites']} site(s) -> "
                f"{payload['advisories']} advisory entries "
                f"({payload['advisories_with_multiple_sites']} covering more "
                f"than one site, largest {payload['largest_advisory']})",
                file=sys.stderr)
        else:
            payload = report(args.results_dir)
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    except ContractViolation as exc:
        print(f"cluster: contract violation: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive
        print(f"cluster: internal error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
