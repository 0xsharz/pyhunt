"""SARIF 2.1.0 export (W5.3) — the difference between a document and a gate.

`report.md` is read once by a person. SARIF is consumed by GitHub code
scanning, the VS Code SARIF viewer, Azure DevOps, and any CI that wants to fail
a build. Emitting it is cheap and it changes what the tool can be *used for*.

**The one thing this module refuses to do.** SARIF has no field for "a container
observed this fire". Every other scanner's SARIF is a list of static claims, so
the format's `level` and `rank` carry only severity. If PyHunt exported the same
shape, the single most important thing it knows — that one of these findings was
*proven by execution* and 94 were `not_applicable` — would vanish at the export
boundary, and its output would be indistinguishable from a linter's.

So the settlement travels in three places SARIF does define:

- **`properties.execution` / `properties.structural`** on every result, carrying
  the gate's outcome verbatim.
- **`rank`**, which SARIF defines as 0.0–100.0 with higher meaning more
  important. Proven results rank 100; demonstrated 90; everything else takes its
  severity's rank. A viewer that sorts by rank puts the evidence first, which is
  the same ordering `cluster.py` applies for the same reason.
- **`message`**, which is prefixed with the settlement in words, because that is
  the one field every consumer displays.

`proven` and `demonstrated` are never merged into one field, here as everywhere.

**Partial fingerprints.** `partialFingerprints.pyhuntFindingId` is the finding
id, so GitHub can track a result across commits and line drift without
re-alerting. Without it every re-scan reads as a new alert and the integration
is worse than useless.

Contract:

    python3 scripts/sarif_export.py write --results-dir DIR [--out PATH]

JSON to stdout; human notes to stderr; exit 0 normally, 2 on a contract
violation, 1 on an internal error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemata/sarif-schema-2.1.0.json")

# SARIF defines exactly these four. Anything else is rejected by strict
# consumers, so the mapping is total and its fallback is explicit.
_LEVEL_BY_SEVERITY = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}
_DEFAULT_LEVEL = "warning"

# 0.0–100.0, higher is more important (SARIF §3.27.15).
_RANK_BY_SEVERITY = {
    "critical": 80.0, "high": 70.0, "medium": 50.0, "low": 30.0, "info": 10.0,
}
_RANK_PROVEN = 100.0
_RANK_DEMONSTRATED = 90.0
_DEFAULT_RANK = 40.0


class ContractViolation(Exception):
    """A caller error the skill must not route around — surfaces as exit 2."""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContractViolation(f"{path} does not exist") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractViolation(f"{path} could not be read: {exc}") from exc


def _outcome(finding: dict, key: str) -> str | None:
    block = finding.get(key)
    if isinstance(block, dict) and isinstance(block.get("outcome"), str):
        return block["outcome"]
    return None


def _level(finding: dict) -> str:
    return _LEVEL_BY_SEVERITY.get(
        str(finding.get("severity") or "").lower(), _DEFAULT_LEVEL)


def _rank(finding: dict) -> float:
    """Evidence outranks a claim about impact. See the module docstring."""
    if _outcome(finding, "execution") == "proven":
        return _RANK_PROVEN
    if _outcome(finding, "structural") == "demonstrated":
        return _RANK_DEMONSTRATED
    return _RANK_BY_SEVERITY.get(
        str(finding.get("severity") or "").lower(), _DEFAULT_RANK)


def _message_prefix(finding: dict) -> str:
    """Settlement in words, in the field every consumer displays."""
    execution = _outcome(finding, "execution")
    structural = _outcome(finding, "structural")
    if execution == "proven":
        return ("[PROVEN BY EXECUTION — a fresh container observed the "
                "dangerous operation fire with the payload interpreted] ")
    if structural == "demonstrated":
        return ("[STRUCTURALLY DEMONSTRATED — a probe showed the condition "
                "holds. This is NOT `proven`.] ")
    if structural == "refuted":
        # A refutation the adversarial verifier argued past is still printed,
        # but it must not read as an unopposed one: a pipeline that
        # auto-dismisses on this prefix would drop a finding two independent
        # verifiers upheld. Both facts go in the sentence.
        validation = finding.get("validation")
        verdict = (validation or {}).get("verdict") if isinstance(
            validation, dict) else None
        if verdict == "confirmed":
            return ("[STRUCTURALLY REFUTED, AND THE REFUTATION WAS OVERTURNED — "
                    "a probe ran and the condition did not hold, and adversarial "
                    "verification confirmed the finding anyway, in writing. Read "
                    "both before dismissing.] ")
        return ("[STRUCTURALLY REFUTED — a probe ran and the condition did not "
                "hold. Treat this finding as counter-evidenced.] ")
    if execution:
        return f"[not settled by execution: {execution}] "
    return ""


def _rules(findings: Sequence[dict]) -> tuple[list[dict], dict[str, int]]:
    """One SARIF rule per vulnerability class, and the id → index map."""
    rules: list[dict] = []
    index: dict[str, int] = {}
    for finding in findings:
        rule_id = str(finding.get("vuln_class") or "unknown")
        if rule_id in index:
            continue
        index[rule_id] = len(rules)
        cwe = str(finding.get("cwe") or "").strip()
        rule: dict[str, Any] = {
            "id": rule_id,
            "name": rule_id.replace("_", " ").title().replace(" ", ""),
            "shortDescription": {"text": rule_id.replace("_", " ")},
            "properties": {"tags": ["security"]},
        }
        if cwe:
            rule["properties"]["tags"].append(cwe)
            rule["properties"]["security-severity"] = _security_severity(finding)
            rule["helpUri"] = (
                f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html")
        rules.append(rule)
    return rules, index


def _security_severity(finding: dict) -> str:
    """GitHub reads this string (0.0–10.0) to bucket an alert.

    Prefer the CVSS score phase 2c actually assessed; fall back to a
    severity-keyed value rather than inventing precision.
    """
    cvss = finding.get("cvss")
    if isinstance(cvss, dict):
        score = cvss.get("score")
        if isinstance(score, (int, float)):
            return f"{float(score):.1f}"
    return {"critical": "9.5", "high": "7.5", "medium": "5.0",
            "low": "3.0", "info": "1.0"}.get(
                str(finding.get("severity") or "").lower(), "5.0")


def _region(finding: dict) -> dict:
    try:
        start = int(finding.get("line_start") or 1)
    except (TypeError, ValueError):
        start = 1
    try:
        end = int(finding.get("line_end") or start)
    except (TypeError, ValueError):
        end = start
    return {"startLine": max(1, start), "endLine": max(1, max(start, end))}


def _result(finding: dict, rule_index: dict[str, int]) -> dict:
    rule_id = str(finding.get("vuln_class") or "unknown")
    finding_id = str(finding.get("finding_id") or "")
    body = str(finding.get("description") or finding.get("title") or rule_id)

    properties: dict[str, Any] = {"pyhuntFindingId": finding_id}
    for key in ("execution", "structural"):
        outcome = _outcome(finding, key)
        if outcome:
            # Kept as two separate properties. They are different claims from
            # different oracles and are never summed — see SKILL.md §1.
            properties[key] = outcome
    for key in ("reachable_from", "independent_units", "cwe"):
        if finding.get(key) is not None:
            properties[key] = finding[key]
    validation = finding.get("validation")
    if isinstance(validation, dict) and validation.get("verdict"):
        properties["verifierVerdict"] = validation["verdict"]

    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index.get(rule_id, 0),
        "level": _level(finding),
        "rank": _rank(finding),
        "message": {"text": _message_prefix(finding) + body},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": str(finding.get("file") or ""),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": _region(finding),
            }
        }],
        # Without a stable fingerprint every re-scan reads as a brand new alert
        # and the integration is worse than not having one.
        "partialFingerprints": {"pyhuntFindingId": finding_id},
        "properties": properties,
    }


def build_sarif(report: dict, manifest: dict | None = None) -> dict:
    findings = [f for f in report.get("findings", []) if isinstance(f, dict)]
    rules, rule_index = _rules(findings)
    manifest = manifest or {}

    execution = ((report.get("coverage") or {}).get("execution") or {})
    invocation: dict[str, Any] = {"executionSuccessful": True}
    properties: dict[str, Any] = {
        "isolationTier": manifest.get("isolation_tier"),
        "mode": manifest.get("mode"),
        "blindScan": manifest.get("blind_scan"),
        "provenByExecution": execution.get("by_outcome", {}).get("proven", 0),
        "settlementNote": (
            "`provenByExecution` counts findings a fresh container observed "
            "firing. SARIF has no field for this, so it also travels in each "
            "result's `rank`, `message` prefix and `properties.execution`. "
            "`demonstrated` is a different, weaker claim and is never summed "
            "with it."
        ),
    }
    if report.get("advisory_summary"):
        properties["rootCauseAdvisories"] = report["advisory_summary"].get(
            "advisories")

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "PyHunt",
                "informationUri": "https://github.com/0xsharz/pyhunt",
                "semanticVersion": str(manifest.get("pyhunt_version") or "0.0.0"),
                "rules": rules,
            }},
            "automationDetails": {"id": str(report.get("run_id") or "")},
            "invocations": [invocation],
            "properties": properties,
            "results": [_result(f, rule_index) for f in findings],
        }],
    }


def write(results_dir: Path, out: Path | None = None) -> tuple[dict, Path]:
    report = _read_json(results_dir / "report.json")
    if not isinstance(report, dict):
        raise ContractViolation("report.json is not a JSON object")
    manifest_path = results_dir / "manifest.json"
    manifest = _read_json(manifest_path) if manifest_path.is_file() else {}
    sarif = build_sarif(report, manifest if isinstance(manifest, dict) else {})

    target = out or (results_dir / "report.sarif")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, target)
    return sarif, target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sarif_export.py",
        description="Export report.json as SARIF 2.1.0.")
    sub = parser.add_subparsers(dest="command", required=True)
    write_cmd = sub.add_parser("write", help="write report.sarif")
    write_cmd.add_argument("--results-dir", required=True)
    write_cmd.add_argument("--out")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        results_dir = Path(args.results_dir).expanduser().resolve()
        if not results_dir.is_dir():
            raise ContractViolation(
                f"--results-dir is not a directory: {results_dir}")
        sarif, target = write(
            results_dir, Path(args.out).expanduser() if args.out else None)
        results = sarif["runs"][0]["results"]
        proven = sum(1 for r in results if r["rank"] == _RANK_PROVEN)
        print(f"sarif: {len(results)} result(s), {proven} ranked as proven "
              f"-> {target}", file=sys.stderr)
        json.dump({"results": len(results), "written": str(target)},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    except ContractViolation as exc:
        print(f"sarif: contract violation: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive
        print(f"sarif: internal error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
