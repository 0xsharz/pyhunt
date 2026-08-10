"""Phase 1b task generation — the deterministic substrate under the whole hunt.

`phases/phase1b_taint.md` names exactly one command, and this module is it:

    python3 "${SKILL_DIR}/scripts/tasks.py" generate \\
        --repo "${TARGET}" --results-dir "${RESULTS_DIR}"

It composes six task sources into `tasks.json`. One task is one
(entry point, sink, path) plus exactly the source needed to judge it — never
"here is the repo, find bugs". The six sources, **in this order**:

1. `taint`         — forward (input → sink) call-graph paths      (`taint.py`)
2. `sink_backward` — orphan sinks, hunted backward through callers (`taint.py`)
3. `entry_forward` — every enumerated entry point followed forward, queued
                     whether or not a sink was found behind it          (here)
4. `specialist`    — gated repo-wide lens sweeps            (`specialists.py`)
5. `history`       — sibling sites of a previously-patched idiom  (`history.py`
                     wrote them into `logs/history.json`; we merge them in)
6. `catchall`      — the terminal coverage net                 (`catchall.py`)

**Why there is a third source between the two taint ones.** Sources 1 and 2 are
both anchored on the sink tables: forward taint needs both ends known, and
sink-backward needs the sink known. Neither can reach a dangerous operation
nobody put in a table. On the recorded run that showed up as forward taint
producing **two** tasks against a 1022-edge, high-confidence graph, while the
phase-3 sweep and reconciliation later added 35 tasks that produced 49 of the
145 findings. A third of the run's output came from work the initial generator
never queued. `entry_forward` asks the opposite question — *what can this input
reach?* — and is gated on nothing, because gating it on the same reachability
signal that suppressed forward taint would reproduce the gap it exists to
close.

Ported from `pyhunt_old/orchestrator.py::_add_taint_tasks` /
`_add_sink_backward_tasks` / `_add_specialist_tasks` / `_sweepable_source_files`
/ `_add_catchall_tasks`, which held this sequencing inside the async,
SQLite-backed pipeline driver the skill-first restructure deletes (decision
D-2). The rules are unchanged; the storage is now the results directory.

Three properties are load-bearing, and each was a real bug at least once:

**The order is not stylistic.** Catch-all runs LAST because its `covered` set
is the union of `target_files` across every task the other four queued. Run it
earlier and `covered` is short, so the sweep re-hunts ground the specific
generators would have covered better — while still reporting full coverage.
That is a coverage claim that is wrong in the one direction that matters.

**The file universe is not `.py`.** `sweepable_source_files` (the D7 fix)
includes any file whose extension maps to a known language — which is where
`.jinja2` / `.j2` / `.mako` enter, and CWE-94 codegen injection with them — OR
that classifies as IaC/CI config. A `.py`-only allowlist made template
codegen-injection unreachable by the coverage net, and made the `iac` gate
literally unable to fire, because a Dockerfile has never had a `.py` suffix.
The same allowlist bug bit the catch-all sweep and the specialist wireup
independently, so the helper is shared by both and there is exactly one
definition of "a file this repo might hide a bug in".

**Fail-open is not fail-quiet.** Every source is independently fail-open — a
crash in the specialist gates must not lose the taint tasks already generated,
and task generation never aborts a run. But every source also records its own
`status` in `tasks.json`: `ok`, `skipped:<reason>`, or `failed:<error>`. A
source that produced no tasks and no status line is indistinguishable from a
source that ran and found nothing, and that ambiguity is the same shape as
treating a broken container as a clean scan. Phase 3's coverage ledger and
Phase 4's denominators are built on this file's honesty: a scan that generated
fewer tasks than it should have must say so rather than looking complete.

Exit codes (the phase file depends on these):
  0  success
  2  contract violation — `inputs.json` missing/unparseable, repo or results
     dir absent. The skill must not route around these.
  1  internal error — reported, not worked around.
"""

from __future__ import annotations

import _bootstrap  # noqa: F401  — resolve the bundled venv before jsonschema

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

from catchall import build_catchall_tasks
from graph import GraphQuery, build_or_load
from graph.config import safe_walk_files
from json_utils import validate_schema
from lang_hints import EXT_TO_LANG, SPECIALIST_HINTS, is_iac_file
from specialists import active_specialists, build_specialist_tasks
from taint import build_sink_backward_tasks, build_taint_tasks

log = logging.getLogger("pyhunt.tasks")


class ContractViolation(Exception):
    """An artifact the phase depends on is missing or unusable (exit 2)."""


# ---------------------------------------------------------------------------
# Tuning — mirrors the numbers `phases/phase1b_taint.md` documents.
# ---------------------------------------------------------------------------

TAINT_MAX_TASKS = 40
TAINT_MAX_HOPS = 8
SINKBACK_MAX_TASKS = 20
SINKBACK_MAX_BACK_HOPS = 3
SPECIALIST_MAX_FILES = 40
CATCHALL_MAX_FILES_PER_TASK = 25
CATCHALL_MAX_TASKS = 40

#: Directories the sweep never descends into. Build/VCS/venv noise only — an
#: exclusion here is invisible surface, so the list stays short and boring.
_SWEEP_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist",
    "vendor", "target", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".eggs",
})

#: Hard ceiling on the sweepable file universe. `build_catchall_tasks`'s own
#: `max_tasks` cap still bounds the actual task count and discloses any drop;
#: this only bounds the walk.
MAX_SWEEP_FILES = 20000

#: Why a specialist lens did not fire. `active_specialists` logs its gate
#: decisions but returns only the kept list, so the reason strings live here —
#: one per lens, phrased as the gate's own precondition. Phase 4 quotes these:
#: a specialist that did not run is a coverage fact, not an absence of one.
_GATED_OFF_REASON = {
    "crypto": "no crypto API names in source",
    "logic-bug": "always on — gated off only by an internal error",
    "access-control": (
        "no HTTP/RPC/gRPC/webhook entry point, no auth_required flag, no "
        "declared trust boundary, and no unauthenticated/authenticated input"
    ),
    "deserialization": "no JVM-style or Python-style deserializer in source",
    "batch-etl": "no CLI/file entry point and no batch/ETL signature in source",
    "iac": "no file classifies as IaC/CI config",
    "codegen": (
        "repo does not both emit source code and read free-text schema fields"
    ),
}


# ---------------------------------------------------------------------------
# Results-directory IO
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Any:
    """Read and parse `path`, raising ContractViolation with the reason."""
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


def load_inputs(results_dir: Path) -> dict:
    """Read `inputs.json`. **Fail-CLOSED** — this is the phase's one hard
    precondition.

    Unlike every other read in this module, a missing or unparseable
    `inputs.json` is a contract violation (exit 2), not a degradation. Phase 1
    is required to have written it, and generating tasks from an inventory that
    silently came back empty would produce a small task list with no stated
    cause — exactly the "small denominator presented as full coverage" failure
    the phase gate exists to prevent. An inventory that is *legitimately* empty
    is a different thing, and it degrades honestly: `taint` records
    `skipped:no_inputs`.
    """
    payload = _read_json(results_dir / "inputs.json")
    if isinstance(payload, list):
        # Tolerate a bare array; the contract shape is {"inputs": [...]}.
        return {"inputs": payload}
    if not isinstance(payload, dict):
        raise ContractViolation(
            f"inputs.json must be an object or array, got "
            f"{type(payload).__name__}"
        )
    return payload


def _input_records(payload: dict) -> list[dict]:
    """The `inputs` array, filtered to well-formed records. A malformed entry
    is dropped rather than crashing the generator — it still shows up as
    uncovered in Phase 3's ledger, which is where it belongs."""
    records = payload.get("inputs")
    if not isinstance(records, list):
        return []
    return [r for r in records if isinstance(r, dict)]


def _read_run_id(results_dir: Path) -> str:
    """`run_id` from `manifest.json`. Absent is survivable — the value is an
    identifier, not a precondition."""
    try:
        manifest = _read_json(results_dir / "manifest.json")
    except ContractViolation:
        return ""
    if isinstance(manifest, dict):
        value = manifest.get("run_id")
        if isinstance(value, str):
            return value
    return ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# The file universe (D7)
# ---------------------------------------------------------------------------

def sweepable_source_files(repo_path: Path, graph: Any = None) -> list[str]:
    """Repo-relative paths of every file the specialist gates and the catch-all
    sweep should consider.

    Include any file whose extension maps to a known language (`EXT_TO_LANG` —
    covers `.py` AND web templates `.jinja2`/`.j2`/`.mako`, where CWE-94
    codegen injection actually lives) **OR** that is IaC/CI config
    (`is_iac_file`). Deny-by-default by extension, mirroring VVAH's
    `s3_decompose.py::_is_source`.

    This replaced a `.py`-only allowlist (**the D7 fix**), and the allowlist is
    worth naming because it broke two things silently rather than loudly:
    template codegen-injection was unreachable by the coverage net, and the
    `iac` specialist gate could never fire, because a Dockerfile has never had
    a `.py` suffix. Both looked like "this repo has no such bugs".

    Skips VCS/build/venv noise dirs, unions the on-disk result with
    graph-known files so nothing the graph modeled is lost, and caps at
    `MAX_SWEEP_FILES`. Never raises: a walk that fails part way returns what it
    got, because a partial universe is a degraded sweep, not a dead run.

    **Noise directories are matched against the repo-RELATIVE path, never the
    absolute one.** `safe_walk_files` tests its `excluded_dir_parts` against
    every component of the absolute path, which silently deletes the entire
    file universe whenever the target happens to live under a directory named
    `target`, `build`, `dist`, `venv`, `vendor` or any other skip name — a
    checkout at `/home/me/build/app`, or a Rust/Maven workspace whose repo sits
    in `target/`, sweeps to ZERO files and reports a clean scan. So this walks
    with exclusion disabled and applies the skip list to `rel` itself.
    """
    def _sweepable(rel: str) -> bool:
        return PurePosixPath(rel).suffix.lower() in EXT_TO_LANG or is_iac_file(rel)

    def _noise(rel: str) -> bool:
        return any(part in _SWEEP_SKIP_DIRS for part in PurePosixPath(rel).parts)

    disk: list[str] = []
    try:
        # excluded_dir_parts=() disables safe_walk_files' own absolute-path
        # exclusion (see docstring). It costs nothing: the underlying rglob
        # already enumerates every path and post-filters, so there was never a
        # pruning benefit to lose.
        for p in safe_walk_files(repo_path, excluded_dir_parts=()):
            try:
                rel = str(p.relative_to(repo_path))
            except ValueError:
                continue
            if _noise(rel) or not _sweepable(rel):
                continue
            disk.append(rel)
            if len(disk) >= MAX_SWEEP_FILES:
                log.warning(
                    "sweepable file universe hit the %d-file cap; "
                    "later files were not considered", MAX_SWEEP_FILES,
                )
                break
    except Exception as exc:  # a partial universe beats no universe
        log.warning("sweepable walk failed part way (continuing): %s", exc)

    graph_src: list[str] = []
    by_file = getattr(graph, "_by_file", None) if graph is not None else None
    if by_file:
        graph_src = [
            f for f in by_file
            if isinstance(f, str) and not _noise(f) and _sweepable(f)
        ]

    return sorted(set(disk) | set(graph_src))


#: Back-compat alias for the orchestrator-era private name the ported tests and
#: the deleted module both referred to.
_sweepable_source_files = sweepable_source_files


# ---------------------------------------------------------------------------
# Graph construction and the reachability gate
# ---------------------------------------------------------------------------

def build_graph(repo_path: Path, cache_path: Path) -> tuple[Any, dict]:
    """Build (or load) the call graph. **Fail-open.**

    Returns `(GraphQuery | None, graph_info)`. A graph failure degrades the run
    to its graph-independent sources; it never aborts it. The degradation is
    recorded in `graph_info["status"]` so Phase 4 can say *why* the run had no
    reachability substrate, rather than showing a smaller task count with no
    explanation.
    """
    info: dict[str, Any] = {
        "backend": "none",
        "confidence": "low",
        "nodes": 0,
        "calls_edges": 0,
        "used_for_reachability": False,
        "status": "ok",
    }
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        doc = build_or_load(repo_path, cache_path)
    except Exception as exc:  # fail-open — a graph failure must not abort
        info["status"] = f"failed:{type(exc).__name__}: {exc}"
        log.warning("graph build failed (continuing run): %s", exc)
        return None, info

    calls_edges = sum(1 for e in doc.edges if e.kind == "calls")
    info.update({
        "backend": doc.backend,
        "confidence": doc.confidence,
        "nodes": len(doc.nodes),
        "calls_edges": calls_edges,
    })
    try:
        gq = GraphQuery(doc, repo_path)
    except Exception as exc:  # fail-open, same reasoning
        info["status"] = f"failed:GraphQuery: {exc}"
        log.warning("GraphQuery construction failed (continuing run): %s", exc)
        return None, info

    info["used_for_reachability"] = bool(
        doc.confidence != "low" and calls_edges > 0
    )
    return gq, info


def reachability_skip_reason(gq: Any, info: dict) -> str | None:
    """Why the two graph-derived sources must not run, or None if they may.

    The gate has three ways to fail and they are reported separately, because
    they call for different responses from whoever reads the report:

    * `no_graph` — the graph did not build at all; the run is degraded.
    * `low_confidence_graph` — the grep fallback built it. Its edges are
      guesses, and a false edge yields a task asserting a data flow that does
      not exist. A confident wrong task is worse than a missing one.
    * `no_call_edges` — nothing to walk, forward or backward. Emitting nothing
      is the correct answer, not a failure.
    """
    if gq is None:
        return "skipped:no_graph"
    if info.get("confidence") == "low":
        return "skipped:low_confidence_graph"
    if not info.get("calls_edges"):
        return "skipped:no_call_edges"
    return None


# ---------------------------------------------------------------------------
# Task validation
# ---------------------------------------------------------------------------

def _schema_path() -> Path:
    return Path(_bootstrap.SCHEMAS_DIR) / "hunt_task.schema.json"


def _validate_tasks(
    tasks: Iterable[Any], source: str, notes: list[str]
) -> tuple[list[dict], int]:
    """Keep only tasks that validate against `hunt_task.schema.json`.

    A task that fails validation would fail the phase gate for the whole run,
    so it is dropped here — and the drop is recorded in `notes` and counted
    into the source's status. Dropping loudly beats shipping a `tasks.json`
    that Phase 2 cannot read.
    """
    schema = _schema_path()
    kept: list[dict] = []
    dropped = 0
    for task in tasks:
        if not isinstance(task, dict):
            dropped += 1
            notes.append(f"{source}: dropped a non-object task entry")
            continue
        try:
            errors = validate_schema(task, schema)
        except Exception as exc:  # a validator failure must not lose the run
            notes.append(
                f"{source}: could not validate task "
                f"{task.get('task_id', '<no id>')!r} ({exc}); kept unvalidated"
            )
            kept.append(task)
            continue
        if errors:
            dropped += 1
            notes.append(
                f"{source}: dropped invalid task "
                f"{task.get('task_id', '<no id>')!r}: {'; '.join(errors[:3])}"
            )
            continue
        kept.append(task)
    return kept, dropped


def _dedupe_ids(tasks: list[dict], notes: list[str]) -> list[dict]:
    """Enforce the phase gate's "every task_id is unique" clause. A duplicate
    is dropped and named; ids are Phase 3's join key, so a collision silently
    merges two tasks' fates."""
    seen: set[str] = set()
    kept: list[dict] = []
    for task in tasks:
        tid = task.get("task_id")
        if tid in seen:
            notes.append(f"dropped duplicate task_id {tid!r}")
            continue
        seen.add(tid)
        kept.append(task)
    return kept


def _covered_files(tasks: Iterable[dict]) -> set[str]:
    """Union of `target_files` across the tasks queued so far — the input to
    the catch-all sweep's `covered` set."""
    covered: set[str] = set()
    for task in tasks:
        files = task.get("target_files")
        if isinstance(files, list):
            covered.update(f for f in files if isinstance(f, str))
    return covered


# ---------------------------------------------------------------------------
# The five sources. Each is fail-open and each returns (tasks, status_dict).
# ---------------------------------------------------------------------------

def gen_taint(
    gq: Any, graph_info: dict, inputs: list[dict], repo_path: Path,
    notes: list[str],
) -> tuple[list[dict], dict]:
    """Forward (input → sink) call-graph path tasks.

    **Fail-open**: every error is logged and swallowed — taint chunking must
    NEVER abort a run. **Gated** on the reachability gate: a grep-fallback
    graph gives unreliable reachability, and a graph with no `calls` edges
    cannot carry a forward path.
    """
    skip = reachability_skip_reason(gq, graph_info)
    if skip:
        return [], {"status": skip, "tasks": 0}
    if not inputs:
        return [], {"status": "skipped:no_inputs", "tasks": 0}
    try:
        tasks = build_taint_tasks(
            gq, inputs, repo_path,
            max_tasks=TAINT_MAX_TASKS, max_hops=TAINT_MAX_HOPS,
        )
    except Exception as exc:  # fail-open — taint must never abort a run
        log.warning("taint chunking failed (continuing run): %s", exc)
        return [], {"status": f"failed:{type(exc).__name__}: {exc}", "tasks": 0}
    kept, dropped = _validate_tasks(tasks, "taint", notes)
    status = {"status": "ok", "tasks": len(kept)}
    if dropped:
        status["dropped_invalid"] = dropped
    return kept, status


def gen_sink_backward(
    gq: Any, graph_info: dict, inputs: list[dict], repo_path: Path,
    notes: list[str],
) -> tuple[list[dict], dict]:
    """Orphan-sink backward audit tasks — dangerous sinks no enumerated input
    reaches forward, hunted backward through their callers.

    **Fail-open** and gated exactly like `gen_taint`; reuses the graph that
    was already built (no rebuild).

    Deliberately NOT gated on `inputs`: with an empty inventory every sink is
    an orphan, which is precisely the case this source exists to cover. It is
    the structural answer to under-enumeration in Phase 1 — it cannot repair a
    missing input in the ledger, but it means a missed input does not
    automatically mean a missed sink.
    """
    skip = reachability_skip_reason(gq, graph_info)
    if skip:
        return [], {"status": skip, "tasks": 0}
    try:
        tasks = build_sink_backward_tasks(
            gq, inputs, repo_path,
            max_tasks=SINKBACK_MAX_TASKS,
            max_back_hops=SINKBACK_MAX_BACK_HOPS,
        )
    except Exception as exc:  # fail-open — sink-backward must never abort
        log.warning("sink-backward failed (continuing run): %s", exc)
        return [], {"status": f"failed:{type(exc).__name__}: {exc}", "tasks": 0}
    kept, dropped = _validate_tasks(tasks, "sink_backward", notes)
    status = {"status": "ok", "tasks": len(kept)}
    if dropped:
        status["dropped_invalid"] = dropped
    return kept, status


# ---------------------------------------------------------------------------
# Entry-forward (W4.3)
#
# In the recorded run, 20 of 37 initial tasks were sink-backward and forward
# taint produced **two**, against a graph with 1022 call edges and high
# confidence. The sweep and reconciliation then added 35 more tasks which
# produced 49 of the 145 findings — a third of the total came from work the
# initial generator never queued. That is a measurable under-generation, and it
# has a structural cause:
#
#   Sink-backward finds what is reachable FROM a known sink. Forward taint
#   finds a path only when BOTH ends are already known. Neither can find a
#   sink the table does not carry — and `taint.py`'s tables are a list of the
#   dangerous idioms someone thought of.
#
# Entry-forward closes that: for every enumerated entry point, one task that
# follows it forward **regardless of whether a sink was found behind it**. The
# hunter is asked what this data can reach, not asked to confirm a path the
# generator already drew.
# ---------------------------------------------------------------------------
ENTRY_FORWARD_MAX_TASKS = 30
ENTRY_FORWARD_MAX_FILES_PER_TASK = 3

# What an entry point of this kind most plausibly reaches. Each value routes to
# a real class file (see `phase2_hunt.md`'s routing table); an entry point whose
# category implies nothing specific still gets a task, under the generic
# input-handling lens, because the point is that it gets looked at at all.
_CATEGORY_CLASS: dict[str, str] = {
    "deserialise": "deserialization",
    "message_queue": "deserialization",
    "template": "code_injection",
    "cli": "command_injection",
    "file_read": "path_traversal",
    "network_response": "ssrf",
    "http_flask": "improper_input_handling",
    "http_django": "improper_input_handling",
    "http_fastapi": "improper_input_handling",
    "http_other": "improper_input_handling",
    "websocket": "improper_input_handling",
    "webhook": "auth_bypass",
    "environment": "information_disclosure",
    "ci_trigger": "supply_chain",
}
_ENTRY_FORWARD_DEFAULT_CLASS = "improper_input_handling"

# Tier order for prioritisation. Nothing is dropped by tier; this only decides
# what gets queued first when the cap bites, and the cap is reported.
_TIER_PRIORITY: dict[str, int] = {
    "public_api": 0, "internal": 1, "ci": 2, "build": 3,
    "example": 4, "test": 5,
}


def load_recon_enumeration(results_dir: Path) -> dict:
    """Read `logs/recon_enumeration.json`, or an empty payload if absent.

    Absent is a normal outcome — an older run, or a repo where the enumerator
    could not run. Entry-forward then falls back to `inputs.json` alone, which
    is weaker but not nothing.
    """
    path = Path(results_dir) / "logs" / "recon_enumeration.json"
    if not path.is_file():
        return {}
    try:
        payload = _read_json(path)
    except Exception as exc:  # fail-open — never abort task generation
        log.warning("recon_enumeration.json unreadable (continuing): %s", exc)
        return {}
    return payload if isinstance(payload, dict) else {}


def _entry_points_by_file(
    recon: dict, inputs: list[dict], enumeration: dict,
) -> dict[str, dict]:
    """Collapse every known entry point into one record per file.

    Three sources, deliberately unioned rather than ranked: the recon agent's
    `inputs[]`, its `architecture.entry_points[]`, and the deterministic
    enumerator's `entry_point_candidates`. The agent sees things the regex
    cannot and the regex sees things the agent ran out of context for; taking
    the union is the only combination that does not silently prefer one.
    """
    by_file: dict[str, dict] = {}

    def note(path: str, category: str, location: str, tier: str) -> None:
        if not path:
            return
        row = by_file.setdefault(path, {
            "categories": set(), "locations": [], "tier": tier, "count": 0,
        })
        row["categories"].add(category)
        row["count"] += 1
        if len(row["locations"]) < 5:
            row["locations"].append(location)
        if _TIER_PRIORITY.get(tier, 9) < _TIER_PRIORITY.get(row["tier"], 9):
            row["tier"] = tier

    file_tier = {
        r.get("path"): r.get("reachable_from", "public_api")
        for r in enumeration.get("files", []) if isinstance(r, dict)
    }

    for record in inputs:
        location = str(record.get("location") or "")
        path = location.split(":", 1)[0]
        note(path, "recon_input", location, file_tier.get(path, "public_api"))

    architecture = recon.get("architecture") or {}
    for entry in architecture.get("entry_points", []) or []:
        if not isinstance(entry, dict):
            continue
        location = str(entry.get("location") or "")
        path = location.split(":", 1)[0]
        note(path, "recon_entry_point", location,
             file_tier.get(path, "public_api"))

    # Framework confidence is deliberately NOT consulted here. A candidate hit
    # is a line of this repository's own code that matched a source pattern —
    # `request.args` in a file is a real read whatever the lock file says. The
    # `transitive` grade exists to stop the recon *agent* enumerating a
    # framework's whole API surface from a dependency name; it is not a reason
    # to ignore code that is actually present.
    candidates = enumeration.get("entry_point_candidates") or {}
    for category, block in candidates.items():
        if not isinstance(block, dict):
            continue
        for hit in block.get("hits", []) or []:
            if not isinstance(hit, dict):
                continue
            location = str(hit.get("location") or "")
            path = location.split(":", 1)[0]
            note(path, category, location,
                 hit.get("reachable_from") or file_tier.get(path, "public_api"))

    # The public API of a library IS its attack surface. A file that exports
    # callables and matched no source pattern still gets an entry-forward task —
    # that is precisely the case forward taint cannot see.
    for symbol in enumeration.get("public_api", []) or []:
        if not isinstance(symbol, dict) or "symbol" not in symbol:
            continue
        path = str(symbol.get("path") or "")
        note(path, "public_api",
             f"{path}:{symbol.get('line', 0)} {symbol.get('symbol')}",
             symbol.get("reachable_from") or file_tier.get(path, "public_api"))

    return by_file


def build_entry_forward_tasks(
    recon: dict, inputs: list[dict], enumeration: dict, covered: set[str],
    *, max_tasks: int = ENTRY_FORWARD_MAX_TASKS,
) -> tuple[list[dict], dict]:
    """One task per entry-point file, uncovered and most-public first."""
    by_file = _entry_points_by_file(recon, inputs, enumeration)
    if not by_file:
        return [], {"status": "skipped:no_entry_points", "tasks": 0}

    ranked = sorted(
        by_file.items(),
        key=lambda kv: (
            kv[0] in covered,                        # uncovered files first
            _TIER_PRIORITY.get(kv[1]["tier"], 9),    # then most reachable
            -kv[1]["count"],                         # then densest surface
            kv[0],                                   # then stable by name
        ),
    )

    # Group rather than truncate. The first version of this capped at
    # `max_tasks` files and deferred the other 45 of 75 — which is the exact
    # failure this source exists to fix, reintroduced one layer down. Files
    # that share an attack class and a directory are read together anyway, so
    # bundling them costs a hunter almost nothing and covers every entry point.
    def class_of(row: dict) -> str:
        for category in sorted(row["categories"]):
            mapped = _CATEGORY_CLASS.get(category)
            if mapped:
                return mapped
        return _ENTRY_FORWARD_DEFAULT_CLASS

    groups: dict[tuple[str, str], list[tuple[str, dict]]] = {}
    order: list[tuple[str, str]] = []
    for path, row in ranked:
        key = (class_of(row), str(PurePosixPath(path).parent))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((path, row))

    tasks: list[dict] = []
    bundles: list[tuple[str, list[tuple[str, dict]]]] = []
    for attack_class, directory in order:
        members = groups[(attack_class, directory)]
        for start in range(0, len(members), ENTRY_FORWARD_MAX_FILES_PER_TASK):
            bundles.append(
                (attack_class, members[start:start + ENTRY_FORWARD_MAX_FILES_PER_TASK]))

    # If grouping still overflows, widen the bundles. Bundling stays within a
    # (class, directory) group even then: three files in one package read as
    # one coherent assignment, three scattered across the repo read as "here is
    # the repo, find bugs", which is the thing this generator exists to avoid.
    # So the cap is a *target*, not a ceiling — when coherent grouping cannot
    # reach it, the task count wins and the overflow is stated. Dropping a file
    # to hit a number would reintroduce the exact defect this source fixes.
    widened = False
    if len(bundles) > max_tasks:
        widened = True
        per_task = max(
            ENTRY_FORWARD_MAX_FILES_PER_TASK,
            -(-len(ranked) // max_tasks),  # ceil
        )
        bundles = []
        for attack_class, directory in order:
            members = groups[(attack_class, directory)]
            for start in range(0, len(members), per_task):
                bundles.append((attack_class, members[start:start + per_task]))

    for index, (attack_class, members) in enumerate(bundles, 1):
        paths = [p for p, _ in members]
        total_points = sum(r["count"] for _, r in members)
        categories = sorted({c for _, r in members for c in r["categories"]})
        uncovered = [p for p in paths if p not in covered]
        sample = "; ".join(
            loc for _, row in members[:2] for loc in row["locations"][:2])
        tasks.append({
            "task_id": f"t_ef_{index:02d}",
            "source": "entry_forward",
            "attack_class": attack_class,
            "target_files": paths,
            "scope_hint": (
                f"Follow every entry point in these {len(paths)} file(s) "
                f"FORWARD and report what attacker-influenced data can reach. "
                f"Entry points include: {sample}. Do not confine yourself to "
                f"{attack_class} — that is the class this surface suggests, "
                f"not a boundary. If the data reaches a dangerous operation of "
                f"any class, file it under that class."
            ),
            "rationale": (
                f"Entry-forward coverage (W4.3). {total_points} entry point(s) "
                f"across {', '.join(categories)}; "
                f"{len(uncovered)} of {len(paths)} file(s) reached by no other "
                f"task. Queued regardless of whether a sink was found behind "
                f"them, because sink-backward can only find what the sink "
                f"tables already name, and forward taint needs both ends known."
            ),
            "priority": 2 if uncovered else 3,
        })

    queued_files = {p for t in tasks for p in t["target_files"]}
    status = {
        "status": "ok",
        "tasks": len(tasks),
        "entry_point_files": len(by_file),
        "entry_point_files_queued": len(queued_files),
        "uncovered_queued": len(queued_files - covered),
    }
    if widened:
        over = len(tasks) - max_tasks
        status["note"] = (
            f"grouped {len(by_file)} entry-point files into {len(tasks)} tasks; "
            f"target was {max_tasks} and grouping is confined to one attack "
            f"class within one directory, so it landed "
            + (f"{over} over" if over > 0 else "at or under target")
            + ". No file was dropped — the count is the honest cost of covering "
              "every entry point."
        )
    missed = set(by_file) - queued_files
    if missed:
        # Should be unreachable — recorded rather than trusted, because a
        # silently shrinking denominator is the failure this source exists for.
        status["not_queued"] = sorted(missed)[:20]
    return tasks, status


def gen_entry_forward(
    recon: dict, inputs: list[dict], results_dir: Path, covered: set[str],
    notes: list[str],
) -> tuple[list[dict], dict]:
    """Entry-point-forward tasks. **Fail-open**, and gated on nothing.

    Deliberately not gated on the call graph: this source exists to cover the
    case where the graph, the sink tables, or both are the reason a finding was
    missed. Gating it on the same reachability signal that already suppressed
    forward taint would reproduce the gap it is here to close.
    """
    try:
        enumeration = load_recon_enumeration(results_dir)
        tasks, status = build_entry_forward_tasks(
            recon, inputs, enumeration, covered)
    except Exception as exc:  # fail-open — never abort a run
        log.warning("entry-forward failed (continuing run): %s", exc)
        return [], {"status": f"failed:{type(exc).__name__}: {exc}", "tasks": 0}
    if not enumeration:
        notes.append(
            "entry_forward: logs/recon_enumeration.json absent — entry points "
            "taken from inputs.json alone, so the public API surface was not "
            "covered. Run scripts/recon_enumerate.py before phase 1b."
        )
    kept, dropped = _validate_tasks(tasks, "entry_forward", notes)
    status["tasks"] = len(kept)
    if dropped:
        status["dropped_invalid"] = dropped
    return kept, status


def gen_specialist(
    recon: dict, inputs: list[dict], repo_path: Path, source_files: list[str],
    notes: list[str],
) -> tuple[list[dict], dict]:
    """Gated repo-wide specialist lens sweeps.

    **Fail-open**, and **NOT confidence-gated**: the specialist gates are
    static regex / recon-shape checks, not call-graph reachability, so a
    missing or low-confidence graph must not skip this source. The graph only
    ever changed how the file list was gathered.

    `source_files` is the D7 sweepable set, never `.py`-only. That regression
    has a name and a history: the original wireup fed `active_specialists` a
    `.py`-only list, so `codegen` (whose evidence lives in template files) and
    `iac` (a Dockerfile has no `.py` suffix) could never fire.

    Every gated-**off** lens is recorded with its reason, because a specialist
    that did not run is a coverage fact.
    """
    try:
        active = active_specialists(recon, inputs, repo_path, source_files)
    except Exception as exc:  # fail-open — the gate must never abort a run
        log.warning("specialist gating failed (continuing run): %s", exc)
        return [], {"status": f"failed:{type(exc).__name__}: {exc}", "tasks": 0}

    if not source_files:
        return [], {
            "status": "skipped:no_source_files",
            "tasks": 0,
            "active": list(active),
            "gated_off": {
                name: _GATED_OFF_REASON.get(name, "surface gate did not fire")
                for name in SPECIALIST_HINTS if name not in active
            },
        }

    try:
        tasks = build_specialist_tasks(
            active, source_files, repo_path, max_files=SPECIALIST_MAX_FILES,
        )
    except Exception as exc:  # fail-open — specialists must never abort a run
        log.warning("specialist tasks failed (continuing run): %s", exc)
        return [], {
            "status": f"failed:{type(exc).__name__}: {exc}",
            "tasks": 0,
            "active": list(active),
        }

    kept, dropped = _validate_tasks(tasks, "specialist", notes)
    status: dict[str, Any] = {
        "status": "ok",
        "tasks": len(kept),
        "active": list(active),
        "gated_off": {
            name: _GATED_OFF_REASON.get(name, "surface gate did not fire")
            for name in SPECIALIST_HINTS if name not in active
        },
    }
    if dropped:
        status["dropped_invalid"] = dropped
    return kept, status


def gen_history(results_dir: Path, notes: list[str]) -> tuple[list[dict], dict]:
    """Merge the history-seeded tasks `history.py` wrote into
    `logs/history.json` — the deterministic form of "this codebase patched this
    idiom once; here are the siblings that still carry it".

    **Fail-open** and additive: an absent history file is the normal case, not
    an error. These merge in **before** the catch-all sweep so their files
    count as covered.
    """
    path = results_dir / "logs" / "history.json"
    if not path.is_file():
        return [], {"status": "skipped:no_history_file", "tasks": 0}
    try:
        payload = _read_json(path)
    except ContractViolation as exc:
        log.warning("history.json unusable (continuing run): %s", exc)
        return [], {"status": f"failed:{exc}", "tasks": 0}
    except Exception as exc:  # fail-open
        log.warning("history read failed (continuing run): %s", exc)
        return [], {"status": f"failed:{type(exc).__name__}: {exc}", "tasks": 0}

    raw = payload.get("tasks") if isinstance(payload, dict) else None
    if not isinstance(raw, list) or not raw:
        return [], {"status": "skipped:no_history_tasks", "tasks": 0}

    kept, dropped = _validate_tasks(raw, "history", notes)
    status = {"status": "ok", "tasks": len(kept)}
    if dropped:
        status["dropped_invalid"] = dropped
    return kept, status


def gen_catchall(
    all_source_files: list[str], covered: set[str], gq: Any, notes: list[str],
    *, max_tasks: int = CATCHALL_MAX_TASKS,
    max_files_per_task: int = CATCHALL_MAX_FILES_PER_TASK,
) -> tuple[list[dict], dict, int]:
    """The terminal whole-repo coverage sweep. **This runs LAST.**

    `covered` is the union of `target_files` across every task the other four
    sources queued. Any eligible source file in neither set has been reached by
    nothing — no input, no sink, no specialist — and gets one low-priority
    sweep task, so the claim "every eligible file received at least one hunt"
    is actually true.

    **Fail-open** and **not confidence-gated** (graph-independent, like the
    specialists; the graph only changes GROUPING, never coverage).

    **Coverage honesty**: `build_catchall_tasks` returns the number of eligible
    files the `max_tasks` cap dropped. That count is not optional output — it
    goes into `coverage.catchall_dropped` and Phase 4 discloses it as
    unexamined surface. A dropped file that is never mentioned turns a capped
    sweep into a clean bill of health.

    Returns `(tasks, status, dropped)`.
    """
    try:
        tasks, dropped = build_catchall_tasks(
            all_source_files, covered, graph=gq,
            max_files_per_task=max_files_per_task,
            max_tasks=max_tasks,
        )
    except Exception as exc:  # fail-open — the sweep must never abort a run
        log.warning("catchall failed (continuing run): %s", exc)
        return [], {"status": f"failed:{type(exc).__name__}: {exc}", "tasks": 0}, 0

    kept, invalid = _validate_tasks(tasks, "catchall", notes)
    status: dict[str, Any] = {"status": "ok", "tasks": len(kept)}
    if invalid:
        status["dropped_invalid"] = invalid
    if dropped:
        notes.append(
            f"catchall: {dropped} eligible file(s) NOT swept (max_tasks cap "
            f"hit) — coverage is incomplete by that many files"
        )
        log.warning(
            "catchall: %d eligible files NOT swept (cap hit) — "
            "coverage incomplete", dropped,
        )
    return kept, status, dropped


# ---------------------------------------------------------------------------
# The generator
# ---------------------------------------------------------------------------

def generate(repo_path: Path, results_dir: Path, *,
             max_catchall_tasks: int = CATCHALL_MAX_TASKS,
             max_files_per_catchall_task: int = CATCHALL_MAX_FILES_PER_TASK,
             ) -> dict:
    """Run all five sources in order and return the `tasks.json` payload.

    Raises `ContractViolation` only for the phase's hard preconditions (the
    repo, the results dir, `inputs.json`). Everything after that degrades and
    records the degradation.
    """
    repo_path = Path(repo_path).resolve()
    results_dir = Path(results_dir)

    if not repo_path.is_dir():
        raise ContractViolation(f"target repo {repo_path} is not a directory")
    if not results_dir.is_dir():
        raise ContractViolation(
            f"results directory {results_dir} does not exist"
        )

    inputs_payload = load_inputs(results_dir)
    inputs = _input_records(inputs_payload)
    notes: list[str] = []

    # 1. The call graph, and the reachability gate over it.
    gq, graph_info = build_graph(
        repo_path, results_dir / "logs" / "graph.json"
    )
    if graph_info["status"] != "ok":
        notes.append(f"graph: {graph_info['status']}")
    elif not graph_info["used_for_reachability"]:
        notes.append(
            f"graph: built with backend={graph_info['backend']} "
            f"confidence={graph_info['confidence']} "
            f"calls_edges={graph_info['calls_edges']} — not trustworthy for "
            f"reachability, so taint and sink_backward were skipped"
        )

    sources: dict[str, dict] = {}
    queued: list[dict] = []

    # 2. Forward taint paths.
    taint_tasks, sources["taint"] = gen_taint(
        gq, graph_info, inputs, repo_path, notes
    )
    queued.extend(taint_tasks)

    # 3. Orphan sinks, backward.
    sinkback_tasks, sources["sink_backward"] = gen_sink_backward(
        gq, graph_info, inputs, repo_path, notes
    )
    queued.extend(sinkback_tasks)

    # The D7 file universe — shared by the specialist gates and the sweep.
    source_files = sweepable_source_files(repo_path, gq)
    if not source_files:
        notes.append(
            "sweepable file universe is empty — no file in the target matched "
            "a known language extension or IaC/CI shape"
        )

    # 4. Entry-point-forward coverage (W4.3). Placed after taint and
    #    sink-backward so `covered` is real, and before the specialist sweeps
    #    and catchall so those two see the files it claims. Gated on nothing:
    #    this source exists to cover the case where the graph or the sink
    #    tables are the reason something was missed.
    ef_covered = _covered_files(queued)
    entry_tasks, sources["entry_forward"] = gen_entry_forward(
        inputs_payload, inputs, results_dir, ef_covered, notes
    )
    queued.extend(entry_tasks)

    # 5. Gated repo-wide specialist sweeps.
    spec_tasks, sources["specialist"] = gen_specialist(
        inputs_payload, inputs, repo_path, source_files, notes
    )
    queued.extend(spec_tasks)

    # 6. History-seeded sibling tasks — merged BEFORE catchall so their files
    #    count as covered.
    hist_tasks, sources["history"] = gen_history(results_dir, notes)
    queued.extend(hist_tasks)

    # Ids must be unique across sources before `covered` is computed from them.
    queued = _dedupe_ids(queued, notes)

    # 7. The terminal coverage sweep. LAST, so `covered` is the union of
    #    everything above. Run it earlier and the sweep re-hunts covered ground
    #    while reporting full coverage.
    covered = _covered_files(queued)
    catchall_tasks, sources["catchall"], catchall_dropped = gen_catchall(
        source_files, covered, gq, notes,
        max_tasks=max_catchall_tasks,
        max_files_per_task=max_files_per_catchall_task,
    )

    all_tasks = _dedupe_ids(queued + catchall_tasks, notes)

    totals = {name: sources[name]["tasks"] for name in sources}
    totals["total"] = len(all_tasks)

    payload = {
        "run_id": _read_run_id(results_dir),
        "generated_at": _utc_now(),
        "repo": str(repo_path),
        "graph": graph_info,
        "sources": sources,
        "coverage": {
            "source_files": len(source_files),
            "covered_files": len(covered),
            "catchall_dropped": catchall_dropped,
        },
        "totals": totals,
        "notes": notes,
        "tasks": all_tasks,
    }
    return payload


def write_tasks(results_dir: Path, payload: dict) -> Path:
    path = Path(results_dir) / "tasks.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def summary_of(payload: dict, tasks_path: Path) -> dict:
    """The stdout block: everything in `tasks.json` except the task array,
    plus where it was written. The phase reads this; a 67-element array in the
    middle of it would bury the statuses that matter."""
    summary = {k: v for k, v in payload.items() if k != "tasks"}
    summary["tasks_path"] = str(tasks_path)
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tasks.py",
        description="Phase 1b — generate the deterministic hunt task list.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser(
        "generate",
        help="Build the call graph and write tasks.json from all five sources.",
    )
    gen.add_argument("--repo", required=True, type=Path,
                     help="Path to the target repository.")
    gen.add_argument(
        "--max-catchall-tasks", type=int, default=CATCHALL_MAX_TASKS,
        help=(
            f"cap on terminal sweep tasks (default {CATCHALL_MAX_TASKS}). The "
            "cap is the single largest recall limit on a big repository — on a "
            "1594-file target the default swept 54 files and disclosed 620 as "
            "unexamined. Raise it to trade cost for coverage; whatever it "
            "drops is still counted in coverage.catchall_dropped"
        ),
    )
    gen.add_argument(
        "--max-files-per-catchall-task", type=int,
        default=CATCHALL_MAX_FILES_PER_TASK,
        help=f"files per sweep task (default {CATCHALL_MAX_FILES_PER_TASK})",
    )
    gen.add_argument("--results-dir", required=True, type=Path,
                     help="The run's results directory.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="tasks: %(message)s", stream=sys.stderr,
    )
    args = build_parser().parse_args(argv)

    try:
        if args.command == "generate":
            payload = generate(
                args.repo, args.results_dir,
                max_catchall_tasks=args.max_catchall_tasks,
                max_files_per_catchall_task=args.max_files_per_catchall_task,
            )
            tasks_path = write_tasks(args.results_dir, payload)
            totals = payload["totals"]
            print(
                f"tasks: {totals['total']} task(s) — "
                + ", ".join(
                    f"{name}={payload['sources'][name]['tasks']}"
                    f"({payload['sources'][name]['status']})"
                    for name in payload["sources"]
                )
                + f" -> {tasks_path}",
                file=sys.stderr,
            )
            for note in payload["notes"]:
                print(f"tasks: {note}", file=sys.stderr)
            if totals["total"] == 0:
                print(
                    "tasks: ZERO tasks generated — do not proceed silently. "
                    "The graph failed, the inventory was empty, or the "
                    "sweepable file set came back empty. None of the three is "
                    "a clean scan.",
                    file=sys.stderr,
                )
            json.dump(summary_of(payload, tasks_path), sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0
    except ContractViolation as exc:
        print(f"tasks: CONTRACT VIOLATION: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # internal error — distinct from a contract fail
        print(f"tasks: internal error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1

    print(f"tasks: unknown subcommand {args.command!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
