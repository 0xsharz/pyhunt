"""Phase 2 unit planning, as a computation rather than an instruction.

`phase2_hunt.md` described this in prose: route each task to a class file, bucket
by (class group, location), split at five, sort, cap, build an assignment per
unit, mint a nonce per task. Every step is mechanical and every step was being
done by hand, per run, by the orchestrator.

That is the shape `PYHUNT-V3-PLAN.md` §W4 names as the cause of D11, D12 and the
`.fake()` miss — "a step that was an instruction to a model rather than a
computation" — and it failed here the same way: on the v3 run the orchestrator
wrote assignment files for the 40 units inside the fan-out cap and not for the 3
beyond it, so three subagents were dispatched at paths that did not exist. They
recovered by reading `tasks.json` themselves and said so; had they been execution
classes rather than LOG and RES, they would have authored PoCs with no minted
nonce, and gate condition 3 would have been unsatisfiable for every one of them.

So it is a script. It writes the plan and every assignment together or not at
all, which is the only arrangement in which "40 of 43 have one" cannot happen.

Two behaviours here are not reorganisation of what the phase file already said:

1. **A sink census is computed and recorded, and it does not move any task by
   default.** The temptation it exists to document is real: on the
   dca-avroschema run, 15 of 43 units were NAV — a third of the fan-out — and
   they filed **42 findings of which zero were a NAV class**, because
   `improper_input_handling` is the entry-forward generator's default and the
   routing table puts that class in the file about path traversal, SSRF and XXE,
   on a package importing no `os`, `socket`, `urllib` or `xml`.

   Re-aiming those tasks at the group whose sinks are actually present looks
   free and is not. Measured on that run's own output: **29 of the 39 sites
   those NAV units filed were found by no other group** — every
   `dacite_config.py` type hook, three `case.py` sites, `faust/parser.py:24`,
   `fields/base.py:104`. The lens was wrong and the *reading* was productive
   anyway, so moving the task moves the reader off files nobody else covers.

   So `--census-routing` is opt-in and off. The census ships in the plan as
   evidence for a future decision, not as a decision. What a wrong lens costs is
   agent time; what a re-aimed task costs is sites nobody looks at, and this
   pipeline trades the first for the second, never the reverse.

2. **Nothing is dropped for being unroutable, and no lens is silently skipped.**
   A group with no sinks still receives any task whose class explicitly names
   it: the generator asserted that class for a reason and this file does not
   overrule it.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Sequence

try:  # pragma: no cover - bundled-venv shim
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:
    pass

from oracle.nonce import ensure_durable_secret
from poc_runtime import poc_execution_block
from taint import SINKS_BY_LANG

#: class group -> (class file, the attack_class strings routed there)
ROUTES: dict[str, tuple[str, frozenset[str]]] = {
    "INJ": ("phase2_class_inj.md", frozenset({
        "command_injection", "sql_injection", "code_injection", "ssti",
        "codegen_injection", "log_injection", "xss_stored", "xss_reflected"})),
    "NAV": ("phase2_class_nav.md", frozenset({
        "path_traversal", "ssrf", "open_redirect", "xxe", "zip_slip"})),
    "DESER": ("phase2_class_deser.md", frozenset({
        "deserialization", "unsafe_reflection", "prototype_pollution"})),
    "RES": ("phase2_class_res.md", frozenset({
        "resource_exhaustion", "denial_of_service", "dos",
        "algorithmic_complexity", "regex_dos", "redos", "uncontrolled_recursion",
        "memory_exhaustion", "unbounded_allocation", "integer_overflow"})),
    "LOG": ("phase2_class_log.md", frozenset({
        "auth_bypass", "idor", "access_control", "authorization", "missing_auth",
        "privilege_escalation", "business_logic", "logic_error",
        "mass_assignment", "csrf", "rate_limit", "weak_crypto",
        "cryptographic_failure", "hardcoded_secret", "information_disclosure",
        "insecure_design", "insecure_default", "security_misconfiguration",
        "supply_chain", "state_mutation", "global_state_pollution",
        "validation_bypass", "race_condition"})),
}

#: Classes that say "something reaches this code" and not what happens when it
#: does. They carry no lens of their own, so they inherit one from the census.
#: `improper_input_handling` is the task generator's default for entry-forward
#: work, which makes it the single most common class in a run.
GENERIC_CLASSES = frozenset({
    "improper_input_handling", "unknown", "", "none", "generic",
})

#: Where a generic class goes when the census is silent — i.e. when the
#: repository has no sinks of any kind the tables recognise. NAV keeps the
#: default because its file is the one written for "untrusted value reaches an
#: operation that resolves it", which is the residual case.
GENERIC_FALLBACK = "NAV"

#: Which class group each sink-table attack class belongs to, derived from
#: ROUTES so the two cannot drift.
_GROUP_OF_CLASS = {cls: group for group, (_, classes) in ROUTES.items()
                   for cls in classes}

SOURCE_RANK = {"taint": 0, "sink_backward": 1, "recon": 2, "entry_forward": 2,
               "specialist": 3, "history": 4, "reconcile": 5, "feedback": 6,
               "gapfill": 7, "catchall": 8}

MAX_TASKS_PER_UNIT = 5
MAX_UNITS_PER_RUN = 40
MAX_CONCURRENT_UNITS = 6

_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", "build", "dist",
              "vendor", "target", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
_LANG_BY_SUFFIX = {".py": "python"}


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def sink_census(repo: Path, files: Sequence[str] | None = None) -> Counter:
    """Count sink hits per attack class, statically, without a call graph.

    `taint.find_sinks` needs a built graph; this needs to run before any unit is
    planned and only needs the counts, so it reads the same tables directly. The
    target's code is never executed and never written to.
    """
    census: Counter = Counter()
    if files is None:
        candidates = [p for p in repo.rglob("*")
                      if p.is_file() and p.suffix in _LANG_BY_SUFFIX
                      and not (set(p.relative_to(repo).parts) & _SKIP_DIRS)]
    else:
        candidates = [repo / f for f in files]
    for path in candidates:
        lang = _LANG_BY_SUFFIX.get(path.suffix)
        if lang is None or lang not in SINKS_BY_LANG:
            continue
        text = _read(path)
        if text is None:
            continue
        for line in text.splitlines():
            for attack_class, patterns in SINKS_BY_LANG[lang].items():
                if any(rx.search(line) for rx in patterns):
                    census[attack_class] += 1
                    break
    return census


def group_scores(census: Counter) -> Counter:
    """Fold a per-class census onto per-class-group weights."""
    scores: Counter = Counter()
    for attack_class, hits in census.items():
        group = _GROUP_OF_CLASS.get(attack_class)
        if group:
            scores[group] += hits
    return scores


def route(task: dict, repo: Path, repo_scores: Counter,
          census_cache: dict[tuple[str, ...], Counter] | None = None,
          *, census_routing: bool = False) -> dict:
    """Route one task to one class group, and say why.

    An explicit class always wins: the generator asserted it and this function
    does not overrule it. A *generic* class goes to :data:`GENERIC_FALLBACK`,
    which is where the routing table has always sent it.

    ``census_routing=True`` re-aims generic classes at the group whose sinks
    appear in the task's own files. It is off by default and the module
    docstring records the measurement that decided that: on the run where this
    looked like free speed, the tasks it would have moved had produced 29 sites
    no other group found.
    """
    attack_class = str(task.get("attack_class") or "").strip().lower()
    if attack_class in GENERIC_CLASSES and not census_routing:
        return {"group": GENERIC_FALLBACK, "routing": "table",
                "reason": ""}
    if attack_class not in GENERIC_CLASSES:
        for group, (_, classes) in ROUTES.items():
            if attack_class in classes:
                return {"group": group, "routing": "table", "reason": ""}
        hint = f"{task.get('scope_hint', '')} {task.get('rationale', '')}".lower()
        for group, needles in (
                ("INJ", ("eval", "exec(", "shell", "sql", "template", "compile")),
                ("NAV", ("path", "url", "xml", "redirect")),
                ("DESER", ("pickle", "yaml", "deserial", "getattr", "import_module")),
                ("RES", ("recursion", "depth", "unbounded", "size", "complexity"))):
            if any(n in hint for n in needles):
                return {"group": group, "routing": "fallback",
                        "reason": f"unknown class {attack_class!r}; sink family in hint"}
        return {"group": "LOG", "routing": "fallback",
                "reason": f"unknown class {attack_class!r}; no sink family in hint"}

    files = tuple(task.get("target_files") or ())
    local: Counter = Counter()
    if files:
        if census_cache is not None and files in census_cache:
            local = census_cache[files]
        else:
            local = group_scores(sink_census(repo, files))
            if census_cache is not None:
                census_cache[files] = local
    if local:
        group, hits = local.most_common(1)[0]
        return {"group": group, "routing": "census",
                "reason": f"generic class {attack_class!r} aimed at {group} — "
                          f"{hits} {group} sink hit(s) in this task's own files"}
    if repo_scores:
        group, hits = repo_scores.most_common(1)[0]
        return {"group": group, "routing": "census",
                "reason": f"generic class {attack_class!r}; no sink in this "
                          f"task's files, {hits} {group} hit(s) repo-wide"}
    return {"group": GENERIC_FALLBACK, "routing": "census",
            "reason": f"generic class {attack_class!r}; repository has no "
                      f"tabulated sink of any group"}


def _dirkey(path: str) -> str:
    parts = str(path).split("/")
    if len(parts) > 2:
        return "/".join(parts[:2])
    return parts[0] if len(parts) > 1 else "."


def _slug(location: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", location.lower()).strip("_") or "root"


def plan_units(results_dir: str | Path, repo: str | Path,
               *, max_tasks: int = MAX_TASKS_PER_UNIT,
               max_units: int = MAX_UNITS_PER_RUN,
               census_routing: bool = False) -> dict:
    """Route, bucket, split, sort and cap. Pure: writes nothing."""
    results_dir, repo = Path(results_dir), Path(repo)
    tasks = json.loads((results_dir / "tasks.json").read_text())["tasks"]
    repo_scores = group_scores(sink_census(repo))
    cache: dict[tuple[str, ...], Counter] = {}

    buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    decisions: dict[str, dict] = {}
    for task in tasks:
        decision = route(task, repo, repo_scores, cache,
                         census_routing=census_routing)
        decisions[task["task_id"]] = decision
        location = _dirkey(task["target_files"][0]) if task.get("target_files") else "."
        buckets[(decision["group"], location)].append(task)

    units: list[dict] = []
    for (group, location), members in sorted(buckets.items()):
        for i in range(0, len(members), max_tasks):
            chunk = members[i:i + max_tasks]
            routings = {decisions[t["task_id"]]["routing"] for t in chunk}
            units.append({
                "unit_id": f"h_{group.lower()}_{_slug(location)}_{i // max_tasks + 1:02d}",
                "class_group": group,
                "class_file": ROUTES[group][0],
                "location": location,
                "routing": ("table" if routings == {"table"}
                            else "census" if "census" in routings else "fallback"),
                "task_ids": [t["task_id"] for t in chunk],
                "route_reasons": sorted({decisions[t["task_id"]]["reason"]
                                         for t in chunk if decisions[t["task_id"]]["reason"]}),
            })

    by_id = {t["task_id"]: t for t in tasks}
    units.sort(key=lambda u: (
        min(by_id[t].get("priority", 9) for t in u["task_ids"]),
        min(SOURCE_RANK.get(by_id[t].get("source", ""), 9) for t in u["task_ids"]),
        u["unit_id"]))
    for index, unit in enumerate(units):
        unit["dispatch_order"] = index + 1
        unit["within_cap"] = index < max_units

    assert sum(len(u["task_ids"]) for u in units) == len(tasks), \
        "task lost while bucketing — refusing to plan"

    return {
        "tasks_total": len(tasks),
        "units_total": len(units),
        "units_within_cap": sum(1 for u in units if u["within_cap"]),
        "units_over_cap": sum(1 for u in units if not u["within_cap"]),
        "bounds": {"max_units_per_run": max_units,
                   "max_concurrent_units": MAX_CONCURRENT_UNITS,
                   "max_tasks_per_unit": max_tasks},
        "sink_census_by_group": dict(repo_scores),
        "census_routing": census_routing,
        "census_routing_note": (
            "advisory only — the census is recorded, not applied. See the module "
            "docstring for the measurement that decided that."
            if not census_routing else
            "APPLIED — generic classes were re-aimed by sink census. This can "
            "move a reader off files no other group covers; check unique-site "
            "yield per group before trusting the result."),
        "generic_tasks_rerouted": sum(
            1 for d in decisions.values() if d["routing"] == "census"),
        "units_by_group": dict(Counter(u["class_group"] for u in units)),
        "units": units,
    }


def write_plan(results_dir: str | Path, repo: str | Path, **kwargs) -> dict:
    """Plan, then write `logs/hunt_plan.json` and every assignment, together.

    Every unit gets an assignment file — including units beyond the fan-out cap,
    because a run may legitimately dispatch them as a continuation pass and a
    missing assignment is how a subagent ends up without a nonce.
    """
    results_dir, repo = Path(results_dir), Path(repo)
    plan = plan_units(results_dir, repo, **kwargs)

    manifest = json.loads((results_dir / "manifest.json").read_text())
    inputs_doc = json.loads((results_dir / "inputs.json").read_text())
    by_id = {t["task_id"]: t
             for t in json.loads((results_dir / "tasks.json").read_text())["tasks"]}

    ensure_durable_secret(results_dir)
    (results_dir / "logs" / "assignments").mkdir(parents=True, exist_ok=True)
    (results_dir / "findings").mkdir(exist_ok=True)

    proof = str(manifest.get("mode", "")).lower() == "proof"
    for unit in plan["units"]:
        tasks = [by_id[t] for t in unit["task_ids"]]
        scratch = results_dir / "logs" / "hunt" / unit["unit_id"]
        scratch.mkdir(parents=True, exist_ok=True)
        files = {f for t in tasks for f in t.get("target_files", [])}
        hints = " ".join(t.get("scope_hint", "") for t in tasks)
        covered = [i for i in inputs_doc.get("inputs", [])
                   if i["location"].rsplit(":", 1)[0] in files
                   or (i.get("entry_point") and i["entry_point"] in hints)]
        assignment = {
            "unit_id": unit["unit_id"],
            "class_group": unit["class_group"],
            "location": unit["location"],
            "repo": str(repo),
            "results_dir": str(results_dir),
            "mode": manifest.get("mode"),
            "isolation_tier": manifest.get("isolation_tier"),
            "execution_available": proof,
            "tasks": tasks,
            "inputs": covered,
            "design_controls": inputs_doc.get("design_controls", []),
            "scratch_dir": str(scratch),
        }
        if proof:
            blocks = {}
            for task in tasks:
                block = poc_execution_block(
                    ["python"], None, scratch, materialize=True,
                    run_id=manifest["run_id"], task_id=task["task_id"],
                    results_dir=results_dir)
                if block:
                    blocks[task["task_id"]] = block
            assignment["poc_execution_by_task"] = blocks
        (results_dir / "logs" / "assignments" / f"{unit['unit_id']}.json").write_text(
            json.dumps(assignment, indent=2) + "\n", encoding="utf-8")
        unit["inputs_covered"] = [i["input_id"] for i in covered]

    (results_dir / "logs" / "hunt_plan.json").write_text(
        json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    return plan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan phase 2 hunt units and write every assignment.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, helptext in (("plan", "plan and write hunt_plan.json + assignments"),
                           ("dry-run", "plan and print, writing nothing")):
        cmd = sub.add_parser(name, help=helptext)
        cmd.add_argument("--results-dir", required=True)
        cmd.add_argument("--repo", required=True)
        cmd.add_argument("--max-units", type=int, default=MAX_UNITS_PER_RUN)
        cmd.add_argument("--max-tasks-per-unit", type=int, default=MAX_TASKS_PER_UNIT)
        cmd.add_argument(
            "--census-routing", action="store_true",
            help="EXPERIMENT: re-aim generic attack classes at the group whose "
                 "sinks are present. Off by default — on the run that motivated "
                 "it, the tasks it moves had produced 29 sites no other group "
                 "found.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    kwargs = {"max_units": args.max_units, "max_tasks": args.max_tasks_per_unit,
              "census_routing": args.census_routing}
    if args.cmd == "dry-run":
        plan = plan_units(args.results_dir, args.repo, **kwargs)
    else:
        plan = write_plan(args.results_dir, args.repo, **kwargs)
    printable = {k: v for k, v in plan.items() if k != "units"}
    print(json.dumps(printable, indent=2))
    sys.stderr.write(
        f"units: {plan['tasks_total']} task(s) -> {plan['units_total']} unit(s) "
        f"{plan['units_by_group']}; {plan['generic_tasks_rerouted']} generic "
        f"task(s) aimed by sink census\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
