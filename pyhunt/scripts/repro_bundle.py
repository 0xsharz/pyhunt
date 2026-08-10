"""One command that re-runs every piece of evidence in the report.

This is the thing PyHunt did not have and VASH did, and the gap was not
analytical — it was packaging. VASH ships ``run_all.sh`` plus a ``poc.py`` and a
recorded ``output.txt`` per finding; a reader clones the results directory and
re-runs the whole set in one command. PyHunt buried its PoCs inside
``findings/*.json`` and its transcripts inside ``logs/replay/``, so a reader
holding 127 findings had no way to re-run any of them without writing a script
first. Benchmarked head to head on the same package, that is the one column
where VASH won outright.

What this writes::

    repro/
      README.md              what the outcomes mean, what a re-run does and does not prove
      run_all.sh             re-runs everything through PyHunt's own gate
      manifest.json          machine-readable index: id, outcome, file, paths
      <finding_id>/
        poc.py               the exploit, verbatim, as replay ran it
        probe_spec.json      the structural probe's declarative spec, when there is one
        recorded.txt         the observer transcript this run actually captured
        verdict.txt          the gate's outcome and its reason, in words
        run.sh               re-run just this one

Two rules shaped it.

**Re-running goes through the gate, not around it.** ``run.sh`` invokes
``replay.py`` / ``structural.py`` — the same code path, the same container, the
same deterministic verdict. A bundle that shipped a bespoke runner would be
shipping a second, untested oracle, and the first time the two disagreed the
report would be wrong in a way nobody could see. The raw ``poc.py`` is there
too, for a reader who wants to read it or run it under their own interpreter,
with a header saying plainly that doing so proves nothing to the gate.

**Nothing that failed is hidden.** Every finding gets a directory, including the
ones whose outcome was ``not_applicable``, ``probe_error`` or ``refuted``. A
bundle containing only the wins is marketing; the interesting question a reader
asks is "what did you try that did not work", and the answer has to be one
directory listing away.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

try:  # pragma: no cover - bundled-venv shim
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:
    pass

BUNDLE_DIR = "repro"

_POC_HEADER = '''\
# ─────────────────────────────────────────────────────────────────────────────
# PyHunt proof-of-concept — finding {finding_id}
#
#   target file : {file}
#   class       : {vuln_class}
#   gate outcome: {outcome}
#
# This file is the exploit exactly as PyHunt's replay harness ran it, in a fresh
# container built from the provisioned image, with the PEP-578 audit-hook
# observer armed and a per-container HMAC key it never saw.
#
# RUNNING THIS SCRIPT YOURSELF PROVES NOTHING TO THE GATE. The verdict in
# verdict.txt was computed from a transcript the harness captured on a private
# file descriptor and verified by signature; output you produce on your own
# machine is not that. Use ./run.sh to re-run it the way it was judged.
#
# The payload embeds this run's nonce ({nonce}) as a literal. That is
# deliberate: reading PYHUNT_NONCE from the environment always yields None
# inside a PoC, because the observer deletes it before any PoC code runs.
# ─────────────────────────────────────────────────────────────────────────────

'''

_RUN_ONE = '''\
#!/bin/sh
# Re-run finding {finding_id} through PyHunt's own gate.
#
# Same container, same observer, same deterministic verdict — this is not a
# reimplementation of the harness, it is the harness.
set -eu
RESULTS_DIR="${{PYHUNT_RESULTS_DIR:-{results_dir}}}"
SKILL_DIR="${{PYHUNT_SKILL_DIR:-{skill_dir}}}"
PY="${{PYHUNT_PYTHON:-python3}}"

exec "$PY" "$SKILL_DIR/scripts/{script}" run \\
    --results-dir "$RESULTS_DIR" \\
    --finding-id {finding_id}
'''

_RUN_ALL = '''\
#!/bin/sh
# Re-run every recorded piece of evidence in this report.
#
#   ./run_all.sh              everything
#   ./run_all.sh f_abc_1 ...  only the named findings
#
# Override the paths with PYHUNT_RESULTS_DIR / PYHUNT_SKILL_DIR / PYHUNT_PYTHON
# if you have moved the results directory or the skill.
#
# Exit status is the number of findings whose re-run ERRORED — not the number
# that failed to prove. An unproven finding is a result, and a bundle that
# exited non-zero on one would train its reader to ignore the exit code.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
failures=0
total=0

run_one() {{
    id="$1"
    if [ ! -x "$here/$id/run.sh" ]; then
        printf 'skip %s (no run.sh)\\n' "$id"
        return 0
    fi
    total=$((total + 1))
    printf '\\n=== %s ===\\n' "$id"
    if "$here/$id/run.sh" >"$here/$id/rerun.json" 2>"$here/$id/rerun.log"; then
        outcome=$(sed -n 's/.*"outcome": "\\([a-z_]*\\)".*/\\1/p' "$here/$id/rerun.json" | head -1)
        printf 'outcome: %s\\n' "${{outcome:-unknown}}"
    else
        failures=$((failures + 1))
        printf 'ERROR — see %s/rerun.log\\n' "$id"
        tail -3 "$here/$id/rerun.log" 2>/dev/null || true
    fi
}}

if [ "$#" -gt 0 ]; then
    for id in "$@"; do run_one "$id"; done
else
    for dir in "$here"/*/; do
        run_one "$(basename "$dir")"
    done
fi

printf '\\n%s re-run, %s errored\\n' "$total" "$failures"
exit "$failures"
'''


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _findings(results: Path) -> list[dict]:
    out: list[dict] = []
    directory = results / "findings"
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.json")):
        document = _load_json(path)
        if not isinstance(document, dict):
            continue
        if isinstance(document.get("findings"), list):
            task_id = document.get("task_id")
            for finding in document["findings"]:
                if isinstance(finding, dict) and finding.get("finding_id"):
                    finding.setdefault("task_id", task_id)
                    out.append(finding)
        elif document.get("finding_id"):
            out.append(document)
    return out


def _recorded_transcript(results: Path, finding_id: str) -> tuple[str, str | None]:
    """The observer output this run actually captured, and where it came from.

    Preference order matters: the replay stage's own capture is the text the
    gate read. Falling back to the proof record's evidence list is second best —
    it is the decisive lines rather than the whole transcript — and saying which
    one a reader is holding is the difference between evidence and a quotation.
    """
    stage_root = results / "logs" / "replay" / finding_id
    if stage_root.is_dir():
        chunks = []
        for run_dir in sorted(stage_root.glob("run*")):
            for name in ("observer_output.txt", "markers.txt", "transcript.txt"):
                candidate = run_dir / name
                if candidate.is_file():
                    chunks.append(f"----- {run_dir.name}/{name} -----\n"
                                  + candidate.read_text(encoding="utf-8", errors="replace"))
        if chunks:
            return "\n".join(chunks), f"logs/replay/{finding_id}/"

    probe_root = results / "logs" / "structural" / finding_id
    if probe_root.is_dir():
        chunks = []
        for run_dir in sorted(probe_root.glob("run*")):
            candidate = run_dir / "probe_output.txt"
            if candidate.is_file():
                chunks.append(f"----- {run_dir.name} -----\n"
                              + candidate.read_text(encoding="utf-8", errors="replace"))
        if chunks:
            return "\n".join(chunks), f"logs/structural/{finding_id}/"

    proof = _load_json(results / "proof" / f"{finding_id}.json")
    if isinstance(proof, dict):
        lines = []
        for run in proof.get("runs") or []:
            for line in (run.get("verdict") or {}).get("evidence") or []:
                lines.append(line)
        if lines:
            return "\n".join(lines), f"proof/{finding_id}.json (decisive lines only)"
    return "", None


def _verdict_text(finding: dict, proof: dict | None, structural: dict | None) -> str:
    execution = finding.get("execution") or {}
    struct = finding.get("structural") or {}
    lines = [
        f"finding      : {finding.get('finding_id')}",
        f"file         : {finding.get('file')}:{finding.get('line_start')}",
        f"class        : {finding.get('vuln_class')}",
        f"severity     : {finding.get('severity')}",
        "",
        "EXECUTION GATE (oracle/gate.py — five conditions, computed in Python)",
        f"  outcome    : {execution.get('outcome') or 'never ran'}",
        f"  proven     : {bool(execution.get('proven'))}",
        f"  reason     : {execution.get('reason') or '-'}",
    ]
    if isinstance(proof, dict):
        lines += [
            f"  repeats    : {proof.get('repeats_completed')} of "
            f"{proof.get('repeats_requested')} (floor {proof.get('repeat_floor')})",
            f"  unanimous  : {proof.get('unanimous')}",
            f"  image      : {proof.get('image')} {proof.get('image_digest') or ''}".rstrip(),
            f"  isolation  : {proof.get('isolation_tier')}",
            f"  forged     : {proof.get('forged_marker_lines')} marker line(s) failed signature",
        ]
        if proof.get("nonce_in_poc") is False:
            lines.append(
                "  NOTE       : the PoC's source carried neither the nonce nor "
                "its canary path, so condition 3 was unsatisfiable from the "
                "payload side. An unproven outcome here says nothing about the "
                "target's defences.")
        for note in proof.get("promotion_blocked") or []:
            lines.append(f"  BLOCKED    : {note}")
    if struct:
        lines += [
            "",
            "STRUCTURAL ORACLE (oracle/structural.py — five conditions, differential)",
            f"  outcome    : {struct.get('outcome')}",
            f"  probe      : {struct.get('probe_kind')}",
            f"  reason     : {struct.get('reason') or '-'}",
        ]
        conditions = struct.get("conditions") or {}
        if conditions:
            lines.append("  conditions : " + ", ".join(
                f"{k}={v}" for k, v in sorted(conditions.items())))
    lines += [
        "",
        "`demonstrated` is not `proven`. The first means a deterministic",
        "predicate over the target's own output held under a benign/hostile",
        "differential; the second means a dangerous operation fired, carried",
        "this PoC's nonce, came from the target's own frame, and was",
        "interpreted rather than merely carried. The report counts them under",
        "separate denominators and so should you.",
    ]
    return "\n".join(lines) + "\n"


_README = """\
# Reproduction bundle

Every piece of evidence behind `report.md`, re-runnable in one command.

```sh
./run_all.sh            # re-run everything
./run_all.sh f_abc_1    # re-run one finding
```

Each `<finding_id>/` directory holds:

| file | what it is |
|---|---|
| `poc.py` | the exploit verbatim, as the harness ran it |
| `probe_spec.json` | the structural probe's declarative spec, where there is one |
| `recorded.txt` | the observer transcript **this run** captured |
| `verdict.txt` | the gate's outcome and its reasoning, in words |
| `run.sh` | re-run this one finding through PyHunt's own gate |

## What a re-run does and does not establish

`run.sh` calls `replay.py` (or `structural.py`), which starts a fresh container
from the provisioned image, arms the observer itself, captures the transcript on
a private file descriptor, and hands **that** to the gate. It is the same code
path that produced the numbers in the report, not a reimplementation — so a
re-run either agrees with the report or reveals that something about the
environment changed, and both are useful.

Running `poc.py` by hand under your own interpreter is fine for reading the
exploit, and it establishes nothing about the verdict: the gate judges a signed
transcript from a container it controls, and your terminal is not that.

## Outcomes you will see, and what each one means

| outcome | meaning |
|---|---|
| `proven` | the vulnerable operation fired, carried this PoC's nonce, was caused by the target's own frame, and the payload was interpreted. Three fresh containers, unanimous |
| `demonstrated` | a deterministic differential showed the target turning attacker text into an executable construct (or breaching a stated resource bound). Real, and **not** the same claim as `proven` |
| `refuted` | the differential ran and the defence held. Evidence *against* the finding; it never deletes one |
| `sink_reached_unproven` | the sink fired with the payload present and nothing interpreted it. Also what a working defence looks like |
| `not_applicable` | no execution could settle this class — a policy question, or a sink this observer has no event for |
| `not_attempted` | the environment could not run it. An environment fact, never a verdict on the code |
| `observer_absent` / `probe_absent` | the harness failed. Says nothing about the code |

Findings whose evidence failed, errored, or was refuted are in this bundle too.
A bundle that shipped only the wins would answer the wrong question.
"""


def build_bundle(results_dir: str | Path, skill_dir: str | Path | None = None) -> dict:
    """Write ``repro/`` into the results directory. Returns a summary."""
    results = Path(results_dir).resolve()
    if not results.is_dir():
        raise FileNotFoundError(f"results directory {results} does not exist")
    skill = Path(skill_dir).resolve() if skill_dir else Path(__file__).resolve().parent.parent

    bundle = results / BUNDLE_DIR
    bundle.mkdir(parents=True, exist_ok=True)

    proofs = {p.stem: _load_json(p) for p in (results / "proof").glob("*.json")} \
        if (results / "proof").is_dir() else {}
    structurals = {p.stem: _load_json(p) for p in (results / "structural").glob("*.json")} \
        if (results / "structural").is_dir() else {}

    index: list[dict] = []
    for finding in _findings(results):
        finding_id = str(finding.get("finding_id"))
        directory = bundle / finding_id
        directory.mkdir(parents=True, exist_ok=True)

        execution = finding.get("execution") or {}
        proof = proofs.get(finding_id)
        structural = structurals.get(finding_id)

        poc = finding.get("poc") or {}
        code = poc.get("code")
        has_poc = isinstance(code, str) and code.strip()
        if has_poc:
            header = _POC_HEADER.format(
                finding_id=finding_id,
                file=finding.get("file"),
                vuln_class=finding.get("vuln_class"),
                outcome=execution.get("outcome") or "never ran",
                nonce=(proof or {}).get("nonce") or "not recorded",
            )
            (directory / "poc.py").write_text(header + code, encoding="utf-8")

        spec = finding.get("structural_probe")
        if isinstance(spec, dict) and spec:
            (directory / "probe_spec.json").write_text(
                json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        transcript, source = _recorded_transcript(results, finding_id)
        if transcript:
            (directory / "recorded.txt").write_text(
                f"# captured by PyHunt from {source}\n"
                f"# this is the text the gate read; it is not a re-run\n\n"
                + transcript, encoding="utf-8")

        (directory / "verdict.txt").write_text(
            _verdict_text(finding, proof, structural), encoding="utf-8")

        # Which script re-runs this one. A finding with a probe and no PoC is
        # re-run through the structural oracle; a finding with both gets the
        # replay, because that is the stronger claim and the one worth
        # re-checking first.
        script = "replay.py" if has_poc else (
            "structural.py" if isinstance(spec, dict) and spec else None)
        if script:
            _write_executable(directory / "run.sh", _RUN_ONE.format(
                finding_id=finding_id, results_dir=results, skill_dir=skill,
                script=script))

        index.append({
            "finding_id": finding_id,
            "file": finding.get("file"),
            "line_start": finding.get("line_start"),
            "vuln_class": finding.get("vuln_class"),
            "severity": finding.get("severity"),
            "execution_outcome": execution.get("outcome"),
            "structural_outcome": (finding.get("structural") or {}).get("outcome"),
            "rerun": f"{finding_id}/run.sh" if script else None,
            "has_poc": bool(has_poc),
            "has_probe": bool(isinstance(spec, dict) and spec),
            "has_recorded_transcript": bool(transcript),
        })

    _write_executable(bundle / "run_all.sh", _RUN_ALL)
    (bundle / "README.md").write_text(_README, encoding="utf-8")
    summary = {
        "bundle": str(bundle),
        "findings": len(index),
        "with_poc": sum(1 for row in index if row["has_poc"]),
        "with_probe": sum(1 for row in index if row["has_probe"]),
        "with_transcript": sum(1 for row in index if row["has_recorded_transcript"]),
        "rerunnable": sum(1 for row in index if row["rerun"]),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "index": index,
    }
    (bundle / "manifest.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repro_bundle.py",
        description="Write a one-command reproduction bundle into the results "
                    "directory.")
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--skill-dir", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = build_bundle(args.results_dir, args.skill_dir)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"internal error: {type(exc).__name__}: {exc}\n")
        return 1
    # The index is the bulk of the payload and a caller that wants it can read
    # manifest.json; stdout stays the summary so the orchestrator's context does
    # not absorb 127 rows.
    printable = {k: v for k, v in summary.items() if k != "index"}
    print(json.dumps(printable, indent=2))
    sys.stderr.write(
        f"repro_bundle: {summary['findings']} finding(s), "
        f"{summary['rerunnable']} re-runnable -> {summary['bundle']}/run_all.sh\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
