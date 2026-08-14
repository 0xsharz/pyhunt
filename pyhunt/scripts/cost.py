"""Run cost accounting — tokens and seconds measured, dollars derived.

The operator asked for cost in the report. The design decision that shapes this
whole module: **tokens and wall-clock are facts this run can observe; dollars
are not.** A price depends on a rate card that changes, varies by contract, and
is not visible from inside a scan. So:

- Token counts, agent dispatches, wall-clock and container seconds are
  **measured** and always emitted.
- Dollars appear **only** when the operator supplies a rate table with
  `--rates`, and every dollar figure is stamped with that table's `source` and
  `as_of`. No rate is compiled into this file.

That asymmetry is the point. A scanner that prints a confident dollar figure
from a hard-coded 2024 price list is making the same category of unfalsifiable
claim this tool exists to avoid — it just happens to be about money instead of
exploitability.

**Where the numbers come from.** Token usage is read from the Claude Code
session transcript (`--transcript`), which records a `usage` block per assistant
message: `input_tokens`, `output_tokens`, `cache_creation_input_tokens`,
`cache_read_input_tokens`, and the model that served it. Sub-agent turns appear
in the same transcript, so a phase that fanned out to twelve hunters is counted
in full rather than as one orchestrator turn.

**Phase attribution.** `cost.py mark` writes a timestamp into
`logs/phase_timing.json` at each phase boundary; `measure` then buckets
transcript entries into phases by time. If no timing file exists, the run
totals are still exact — only the per-phase split is unavailable, and the
payload says so rather than distributing the tokens by guesswork.

**Cost per outcome is the number that matters.** Total spend says nothing on
its own. Spend per `proven` finding, per settled finding, and per ground-truth
true positive is what tells an operator whether the second oracle earns its
container time. Those are computed when the corresponding artefacts exist.

Contract:

    python3 scripts/cost.py mark --results-dir DIR --phase NAME [--event start|end]
    python3 scripts/cost.py measure --results-dir DIR [--transcript PATH]
        [--rates PATH] [--ground-truth PATH] [--markdown]

JSON to stdout; human notes to stderr; exit 0 normally, 2 on a contract
violation, 1 on an internal error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_ID = "pyhunt.cost/1"

# Usage keys as Anthropic reports them. Cache reads and cache writes are priced
# differently from ordinary input on every rate card that mentions them at all,
# so they are kept separate all the way through rather than summed early.
_USAGE_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)

# Phases in pipeline order, so a report reads top to bottom.
_PHASE_ORDER = (
    "phase0_preflight", "phase1_recon", "phase1b_taint", "phase2_hunt",
    "phase2b_prove", "phase2c_verify", "phase3_sweep", "phase4_report",
)


class ContractViolation(Exception):
    """A caller error the skill must not route around — surfaces as exit 2."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _read_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _atomic_write_json(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Phase timing
# ---------------------------------------------------------------------------
def mark_phase(results_dir: Path, phase: str, event: str) -> dict:
    """Record a phase boundary. Append-only; a repeated mark is kept, not
    overwritten, so a resumed run shows both attempts."""
    path = results_dir / "logs" / "phase_timing.json"
    doc = _read_json(path)
    marks = doc.get("marks") if isinstance(doc, dict) else None
    if not isinstance(marks, list):
        marks = []
    marks.append({"phase": phase, "event": event, "at": _utc_now()})
    payload = {"schema": SCHEMA_ID, "marks": marks}
    _atomic_write_json(path, payload)
    return payload


def phase_windows(results_dir: Path) -> list[dict]:
    """Turn marks into [start, end) windows, in pipeline order.

    A phase with a start and no end is left open-ended and flagged: the run may
    have been interrupted, and pretending it closed would silently attribute
    every later token to it.
    """
    doc = _read_json(results_dir / "logs" / "phase_timing.json")
    marks = doc.get("marks") if isinstance(doc, dict) else None
    if not isinstance(marks, list):
        return []
    starts: dict[str, datetime] = {}
    ends: dict[str, datetime] = {}
    for mark in marks:
        if not isinstance(mark, dict):
            continue
        when = _parse_ts(mark.get("at"))
        phase = mark.get("phase")
        if when is None or not isinstance(phase, str):
            continue
        if mark.get("event") == "start":
            starts.setdefault(phase, when)
        elif mark.get("event") == "end":
            ends[phase] = when

    known = [p for p in _PHASE_ORDER if p in starts]
    known += sorted(p for p in starts if p not in _PHASE_ORDER)
    windows: list[dict] = []
    for phase in known:
        end = ends.get(phase)
        windows.append({
            "phase": phase,
            "start": starts[phase].isoformat(),
            "end": end.isoformat() if end else None,
            "closed": end is not None,
            "seconds": (end - starts[phase]).total_seconds() if end else None,
        })
    return windows


# ---------------------------------------------------------------------------
# Transcript
# ---------------------------------------------------------------------------
def read_transcript(path: Path) -> tuple[list[dict], list[str], float]:
    """Read a Claude Code session transcript into usage records.

    Malformed lines are counted, not fatal: a transcript is an append-only log
    that can be truncated mid-write by a crash, and losing the whole cost
    accounting to one bad line would be a poor trade.
    """
    problems: list[str] = []
    records: list[dict] = []
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ContractViolation(f"--transcript could not be read: {exc}") from exc

    bad = 0
    duration_ms_total = 0.0
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if not isinstance(entry, dict):
                continue
            # `durationMs` is stamped on the turn envelope, which is not always
            # the same entry that carries `usage` — so it is summed here rather
            # than off the usage records.
            duration = entry.get("durationMs")
            if isinstance(duration, (int, float)):
                duration_ms_total += float(duration)
            message = entry.get("message")
            if not isinstance(message, dict):
                continue
            usage = message.get("usage")
            if not isinstance(usage, dict):
                continue
            counted = {k: int(usage.get(k) or 0) for k in _USAGE_KEYS}
            if not any(counted.values()):
                continue
            duration = entry.get("durationMs")
            records.append({
                "at": _parse_ts(entry.get("timestamp")),
                "model": message.get("model") or "unknown",
                "is_sidechain": bool(entry.get("isSidechain")),
                "duration_ms": duration if isinstance(duration, (int, float)) else 0,
                "usage": counted,
            })
    if bad:
        problems.append(f"{bad} transcript line(s) did not parse and were skipped")
    return records, problems, duration_ms_total


def _empty_usage() -> dict[str, int]:
    return {k: 0 for k in _USAGE_KEYS}


def _add(into: dict[str, int], usage: dict[str, int]) -> None:
    for key in _USAGE_KEYS:
        into[key] += usage.get(key, 0)


def bucket_usage(records: list[dict], windows: list[dict]) -> dict:
    """Split usage by phase, by model, and by orchestrator vs sub-agent."""
    totals = _empty_usage()
    by_model: dict[str, dict[str, int]] = {}
    by_phase: dict[str, dict[str, int]] = {}
    by_actor = {"orchestrator": _empty_usage(), "subagent": _empty_usage()}
    unattributed = _empty_usage()
    turns = {"total": 0, "orchestrator": 0, "subagent": 0}

    parsed_windows = [
        (w["phase"], _parse_ts(w["start"]), _parse_ts(w["end"]))
        for w in windows
    ]

    for record in records:
        usage = record["usage"]
        _add(totals, usage)
        _add(by_model.setdefault(record["model"], _empty_usage()), usage)
        actor = "subagent" if record["is_sidechain"] else "orchestrator"
        _add(by_actor[actor], usage)
        turns["total"] += 1
        turns[actor] += 1

        when = record["at"]
        placed = False
        if when is not None:
            for phase, start, end in parsed_windows:
                if start is None or when < start:
                    continue
                if end is not None and when >= end:
                    continue
                _add(by_phase.setdefault(phase, _empty_usage()), usage)
                placed = True
                break
        if not placed:
            _add(unattributed, usage)

    ordered_phases = {
        phase: by_phase[phase]
        for phase in list(_PHASE_ORDER) + sorted(by_phase)
        if phase in by_phase
    }
    return {
        "totals": totals,
        "turns": turns,
        "by_model": dict(sorted(by_model.items())),
        "by_phase": ordered_phases,
        "by_actor": by_actor,
        "unattributed": unattributed,
    }


# ---------------------------------------------------------------------------
# Container time — compute that is not tokens
# ---------------------------------------------------------------------------
def container_cost(results_dir: Path) -> dict:
    """Count container runs and seconds from the proof and structural records.

    Replay runs each PoC three times and every structural probe runs twice, so
    this is not a rounding error against the token bill — and it is the part of
    the cost that buys the `proven` and `demonstrated` verdicts.
    """
    out = {
        "replay": {"records": 0, "runs": 0, "seconds": 0.0},
        "structural": {"records": 0, "runs": 0, "seconds": 0.0},
    }
    for kind, subdir in (("replay", "proof"), ("structural", "structural")):
        directory = results_dir / subdir
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            doc = _read_json(path)
            if not isinstance(doc, dict):
                continue
            out[kind]["records"] += 1
            runs = doc.get("runs") or doc.get("attempts") or doc.get("repeats")
            if isinstance(runs, list):
                out[kind]["runs"] += len(runs)
                for run in runs:
                    if isinstance(run, dict):
                        # `duration_ms` is what `replay.py` and `structural.py`
                        # actually record per run, and it was not in this list,
                        # so container seconds read 0.0 on every run ever made
                        # — the one cost figure that is not tokens, reported as
                        # if the containers had taken no time at all.
                        for key in ("duration_seconds", "elapsed_seconds",
                                    "seconds", "wall_seconds", "duration_ms"):
                            value = run.get(key)
                            if isinstance(value, (int, float)):
                                out[kind]["seconds"] += (
                                    float(value) / 1000.0 if key.endswith("_ms")
                                    else float(value))
                                break
            elif isinstance(runs, int):
                out[kind]["runs"] += runs
            for key in ("duration_seconds", "elapsed_seconds", "wall_seconds"):
                value = doc.get(key)
                if isinstance(value, (int, float)):
                    out[kind]["seconds"] += float(value)
                    break
    for block in out.values():
        block["seconds"] = round(block["seconds"], 2)
    return out


# ---------------------------------------------------------------------------
# Outcomes — what the spend bought
# ---------------------------------------------------------------------------
def outcome_counts(results_dir: Path) -> dict:
    """Findings, settlements, and delivered rows, from the run's own artefacts."""
    counts = {
        "findings_stored": 0,
        "delivered": 0,
        "proven": 0,
        "demonstrated": 0,
        "settled": 0,
    }
    findings_dir = results_dir / "findings"
    if findings_dir.is_dir():
        counts["findings_stored"] = len(list(findings_dir.glob("*.json")))

    report = _read_json(results_dir / "report.json")
    if isinstance(report, dict):
        rows = report.get("findings")
        if isinstance(rows, list):
            counts["delivered"] = len(rows)

        # The gate's tally lives in `coverage.execution`, not on the rows —
        # `report.json`'s finding objects carry `validation` (phase 2c's
        # verdict) but not the execution outcome. Read the aggregate, and read
        # it from the one place that owns it rather than recomputing.
        execution = ((report.get("coverage") or {}).get("execution") or {})
        if isinstance(execution, dict):
            by_outcome = execution.get("by_outcome")
            if isinstance(by_outcome, dict):
                counts["proven"] = int(by_outcome.get("proven") or 0)
            elif isinstance(execution.get("proven_by_execution"), int):
                counts["proven"] = execution["proven_by_execution"]

        # The structural tally lives beside the execution one, under
        # `coverage.execution.structural` — the same place `report_build`
        # writes it and the markdown renderer reads it. Looking for a
        # top-level `structural` key found nothing on every real report, so
        # `demonstrated` and therefore `settled` were always 0 and "cost per
        # settled finding" — the number the phase file calls the one worth
        # reading — could never be computed.
        structural = execution.get("structural") if isinstance(
            execution, dict) else None
        if not isinstance(structural, dict):
            structural = report.get("structural")
        if isinstance(structural, dict):
            by_outcome = structural.get("by_outcome")
            if isinstance(by_outcome, dict):
                counts["demonstrated"] = int(by_outcome.get("demonstrated") or 0)
            elif isinstance(structural.get("demonstrated"), int):
                counts["demonstrated"] = structural["demonstrated"]

    # Summed here for arithmetic only. `proven` and `demonstrated` are never
    # presented as one number — see SKILL.md §1 and the markdown renderer, which
    # keep them in separate rows.
    counts["settled"] = counts["proven"] + counts["demonstrated"]
    return counts


# ---------------------------------------------------------------------------
# Rates — supplied, never assumed
# ---------------------------------------------------------------------------
def load_rates(path: Path) -> dict:
    """Load an operator-supplied rate table.

    Shape:

        {
          "source": "where these prices came from",
          "as_of": "2026-08-10",
          "currency": "USD",
          "per_million_tokens": {
            "<model-id or prefix>": {
              "input": 0.0, "output": 0.0,
              "cache_write": 0.0, "cache_read": 0.0
            }
          }
        }

    `source` and `as_of` are required. A rate table with no provenance produces
    dollar figures nobody can check, which is worse than no dollar figures.
    """
    doc = _read_json(path)
    if not isinstance(doc, dict):
        raise ContractViolation(f"--rates is not a JSON object: {path}")
    table = doc.get("per_million_tokens")
    if not isinstance(table, dict) or not table:
        raise ContractViolation(
            "--rates must carry a non-empty 'per_million_tokens' object")
    for field in ("source", "as_of"):
        if not doc.get(field):
            raise ContractViolation(
                f"--rates must state '{field}' — a price with no provenance "
                f"produces a number nobody can check")
    return doc


def _rate_for(model: str, table: dict) -> dict | None:
    """Exact model id first, then the longest matching prefix."""
    if model in table and isinstance(table[model], dict):
        return table[model]
    best: tuple[int, dict] | None = None
    for key, value in table.items():
        if not isinstance(value, dict):
            continue
        if model.startswith(key) and (best is None or len(key) > best[0]):
            best = (len(key), value)
    return best[1] if best else None


def price(by_model: dict[str, dict[str, int]], rates: dict) -> dict:
    """Derive dollars from measured tokens. Unpriced models are named."""
    table = rates["per_million_tokens"]
    key_map = {
        "input_tokens": "input",
        "output_tokens": "output",
        "cache_creation_input_tokens": "cache_write",
        "cache_read_input_tokens": "cache_read",
    }
    per_model: dict[str, float] = {}
    unpriced: list[str] = []
    total = 0.0
    for model, usage in by_model.items():
        rate = _rate_for(model, table)
        if rate is None:
            unpriced.append(model)
            continue
        amount = 0.0
        for usage_key, rate_key in key_map.items():
            unit = rate.get(rate_key)
            if isinstance(unit, (int, float)):
                amount += (usage.get(usage_key, 0) / 1_000_000) * float(unit)
        per_model[model] = round(amount, 4)
        total += amount
    out = {
        "currency": rates.get("currency", "USD"),
        "rate_source": rates["source"],
        "rate_as_of": rates["as_of"],
        "total": round(total, 4),
        "by_model": dict(sorted(per_model.items())),
        "derived_not_measured": (
            "Token counts are measured; these amounts are those counts "
            "multiplied by an operator-supplied rate table. They are only as "
            "current as the table's as_of date."
        ),
    }
    if unpriced:
        out["unpriced_models"] = sorted(unpriced)
        out["unpriced_warning"] = (
            f"{len(unpriced)} model(s) had no matching rate and contribute "
            f"nothing to the total, which is therefore a floor, not the bill"
        )
    return out


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------
def _efficiency(totals: dict[str, int], counts: dict, dollars: dict | None) -> dict:
    """Cost per outcome. Division by zero is reported, never suppressed.

    Two token totals, deliberately. On a real run cache reads were **271M of
    274M tokens** — and cache reads are the cheapest line on every rate card
    that has one. A single summed "tokens" headline is therefore dominated by
    the cheapest component and tells an operator almost nothing about spend.
    `tokens_full_price` (fresh input + output + cache writes) is the number
    that tracks the bill; `tokens_all` is kept for completeness.
    """
    full_price = (totals["input_tokens"] + totals["output_tokens"]
                  + totals["cache_creation_input_tokens"])
    cached = totals["cache_read_input_tokens"]
    every = full_price + cached

    def per(label: str, denominator: int) -> dict:
        if denominator <= 0:
            return {"denominator": denominator,
                    "note": f"no {label} in this run — no rate to compute"}
        row = {
            "denominator": denominator,
            "full_price_tokens_each": round(full_price / denominator),
            "all_tokens_each": round(every / denominator),
        }
        if dollars is not None:
            row["cost_each"] = round(dollars["total"] / denominator, 4)
        return row

    return {
        "tokens_full_price": full_price,
        "tokens_cache_read": cached,
        "tokens_all": every,
        "cache_read_share_pct": round(100 * cached / every, 1) if every else 0.0,
        "per_delivered_finding": per("delivered finding", counts["delivered"]),
        "per_settled_finding": per("settled finding", counts["settled"]),
        "per_proven_finding": per("proven finding", counts["proven"]),
    }


def measure(
    results_dir: Path, *, transcript: Path | None = None,
    rates_path: Path | None = None,
) -> dict:
    problems: list[str] = []
    windows = phase_windows(results_dir)
    records: list[dict] = []
    turn_ms = 0.0
    if transcript is not None:
        records, transcript_problems, turn_ms = read_transcript(transcript)
        problems.extend(transcript_problems)
    else:
        problems.append(
            "no --transcript supplied: token counts are unavailable, so this "
            "report covers container time and outcomes only")

    usage = bucket_usage(records, windows)
    if not windows and records:
        problems.append(
            "logs/phase_timing.json absent: run totals are exact but the "
            "per-phase split is unavailable. Call `cost.py mark` at each phase "
            "boundary to get it. Tokens were NOT distributed by estimate.")
    open_phases = [w["phase"] for w in windows if not w["closed"]]
    if open_phases:
        problems.append(
            f"phase(s) {', '.join(open_phases)} were started and never closed — "
            f"their windows are open-ended and later usage may be attributed to "
            f"them")

    counts = outcome_counts(results_dir)
    containers = container_cost(results_dir)

    dollars: dict | None = None
    if rates_path is not None:
        dollars = price(usage["by_model"], load_rates(rates_path))
    elif records:
        problems.append(
            "no --rates supplied: tokens are reported, dollars are not. No "
            "rate card is compiled into PyHunt, by design.")

    manifest = _read_json(results_dir / "manifest.json")
    started = _parse_ts(manifest.get("started_at")) if isinstance(manifest, dict) else None
    wall_seconds = None
    if windows:
        closed = [w for w in windows if w["seconds"] is not None]
        if closed:
            wall_seconds = round(sum(w["seconds"] for w in closed), 2)

    payload = {
        "schema": SCHEMA_ID,
        "run_id": manifest.get("run_id") if isinstance(manifest, dict) else None,
        "measured_at": _utc_now(),
        "started_at": started.isoformat() if started else None,
        "wall_clock": {
            "phase_seconds_total": wall_seconds,
            # Summed model-turn time. Available whenever a transcript is, and
            # the only wall-clock figure a run gets if nobody marked the phase
            # boundaries. It undercounts: time spent in containers, in scripts,
            # or waiting on the operator falls between turns.
            "turn_seconds_total": round(turn_ms / 1000, 2),
            "phases": windows,
        },
        "tokens": usage,
        "containers": containers,
        "outcomes": counts,
        "efficiency": _efficiency(usage["totals"], counts, dollars),
        "problems": problems,
    }
    if dollars is not None:
        payload["cost"] = dollars
    return payload


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def _fmt_int(value: int | float | None) -> str:
    return "—" if value is None else f"{value:,.0f}"


def to_markdown(payload: dict) -> str:
    tokens = payload["tokens"]
    totals = tokens["totals"]
    lines: list[str] = ["## Cost", ""]

    efficiency = payload["efficiency"]
    lines.append(
        f"**{_fmt_int(efficiency['tokens_full_price'])} full-price tokens** "
        f"(fresh input + output + cache writes) across "
        f"{_fmt_int(tokens['turns']['total'])} model turns, "
        f"{_fmt_int(tokens['turns']['subagent'])} of them sub-agent.")
    lines.append(
        f"A further {_fmt_int(efficiency['tokens_cache_read'])} tokens were "
        f"cache reads — {efficiency['cache_read_share_pct']}% of all traffic, "
        f"and the cheapest line on any rate card. They are listed separately "
        f"rather than summed in, because a single total is dominated by them "
        f"and would misstate the spend.")
    wall = payload["wall_clock"]
    if wall.get("phase_seconds_total"):
        lines.append(
            f"**{wall['phase_seconds_total'] / 60:.1f} minutes** of measured "
            f"phase wall-clock.")
    elif wall.get("turn_seconds_total"):
        lines.append(
            f"**{wall['turn_seconds_total'] / 60:.1f} minutes** of model turn "
            f"time (summed from the transcript; phase boundaries were not "
            f"marked, so this excludes time spent outside a model turn).")
    lines.append("")

    lines += ["| | input | output | cache write | cache read |",
              "|---|---:|---:|---:|---:|"]
    lines.append(
        f"| **run total** | {_fmt_int(totals['input_tokens'])} | "
        f"{_fmt_int(totals['output_tokens'])} | "
        f"{_fmt_int(totals['cache_creation_input_tokens'])} | "
        f"{_fmt_int(totals['cache_read_input_tokens'])} |")
    for phase, usage in tokens["by_phase"].items():
        lines.append(
            f"| {phase} | {_fmt_int(usage['input_tokens'])} | "
            f"{_fmt_int(usage['output_tokens'])} | "
            f"{_fmt_int(usage['cache_creation_input_tokens'])} | "
            f"{_fmt_int(usage['cache_read_input_tokens'])} |")
    lines.append("")

    containers = payload["containers"]
    lines.append(
        f"Container compute, which is not tokens: "
        f"{containers['replay']['runs']} replay run(s) over "
        f"{containers['replay']['records']} PoC(s), "
        f"{containers['structural']['runs']} structural probe run(s) over "
        f"{containers['structural']['records']} probe(s).")
    # Seconds are stated per kind and never summed with the token line. A run
    # that records no per-run duration says so instead of contributing a zero,
    # because a measured 0.0 and an unrecorded 0.0 are different facts.
    for kind, label in (("replay", "replay"), ("structural", "structural probe")):
        block = containers[kind]
        if not block["records"]:
            continue
        if block["seconds"]:
            lines.append(
                f"- {label} container time: {block['seconds']:.1f}s "
                f"across {block['runs']} run(s).")
        else:
            lines.append(
                f"- {label} container time: not recorded — these run records "
                "carry no per-run duration, so the figure is unavailable "
                "rather than zero.")
    lines.append("")

    lines += ["| what the spend bought | count | full-price tokens each |",
              "|---|---:|---:|"]
    for label, key in (("delivered findings", "per_delivered_finding"),
                       ("machine-settled (proven + demonstrated)",
                        "per_settled_finding"),
                       ("proven", "per_proven_finding")):
        row = efficiency[key]
        each = (_fmt_int(row["full_price_tokens_each"])
                if "full_price_tokens_each" in row else "—")
        lines.append(f"| {label} | {_fmt_int(row['denominator'])} | {each} |")
    lines.append("")

    cost = payload.get("cost")
    if cost:
        lines.append(
            f"**{cost['currency']} {cost['total']:,.2f}**, derived from a rate "
            f"table supplied by the operator ({cost['rate_source']}, as of "
            f"{cost['rate_as_of']}). {cost['derived_not_measured']}")
        if cost.get("unpriced_warning"):
            lines.append(f"⚠ {cost['unpriced_warning']}.")
    else:
        lines.append(
            "No dollar figure is given: no rate table was supplied, and no "
            "rate card is compiled into PyHunt. Token counts above are "
            "measured and can be priced against whatever card applies.")
    lines.append("")

    if payload["problems"]:
        lines.append("Measurement caveats:")
        lines += [f"- {p}" for p in payload["problems"]]
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cost.py", description="Run cost accounting for a PyHunt scan.")
    sub = parser.add_subparsers(dest="command", required=True)

    mark = sub.add_parser("mark", help="record a phase boundary")
    mark.add_argument("--results-dir", required=True)
    mark.add_argument("--phase", required=True)
    mark.add_argument("--event", choices=("start", "end"), default="start")

    measure_cmd = sub.add_parser("measure", help="emit cost.json")
    measure_cmd.add_argument("--results-dir", required=True)
    measure_cmd.add_argument("--transcript")
    measure_cmd.add_argument("--rates")
    measure_cmd.add_argument("--markdown", action="store_true",
                             help="also write logs/cost.md")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        results_dir = Path(args.results_dir).expanduser().resolve()
        if not results_dir.is_dir():
            raise ContractViolation(
                f"--results-dir is not a directory: {results_dir}")

        if args.command == "mark":
            payload = mark_phase(results_dir, args.phase, args.event)
            json.dump(payload["marks"][-1], sys.stdout, indent=2)
            sys.stdout.write("\n")
            print(f"cost: marked {args.phase} {args.event}", file=sys.stderr)
            return 0

        transcript = Path(args.transcript).expanduser() if args.transcript else None
        if transcript is not None and not transcript.is_file():
            raise ContractViolation(f"--transcript does not exist: {transcript}")
        rates_path = Path(args.rates).expanduser() if args.rates else None
        if rates_path is not None and not rates_path.is_file():
            raise ContractViolation(f"--rates does not exist: {rates_path}")

        payload = measure(results_dir, transcript=transcript,
                          rates_path=rates_path)
        _atomic_write_json(results_dir / "logs" / "cost.json", payload)
        if args.markdown:
            (results_dir / "logs" / "cost.md").write_text(
                to_markdown(payload), encoding="utf-8")

        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        billable = payload["efficiency"]["tokens_full_price"]
        print(f"cost: {billable:,} full-price tokens "
              f"(+{payload['efficiency']['tokens_cache_read']:,} cache read), "
              f"{payload['outcomes']['delivered']} delivered findings, "
              f"{len(payload['problems'])} caveat(s)", file=sys.stderr)
        for problem in payload["problems"]:
            print(f"cost: caveat: {problem}", file=sys.stderr)
        return 0
    except ContractViolation as exc:
        print(f"cost: contract violation: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive
        print(f"cost: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
