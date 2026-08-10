"""Re-ask every dismissed surface under the lenses that did not dismiss it.

The miss this exists to prevent, in the hunter's own words:

> "`random.choice` / `random.randint` / `uuid.uuid1` / `uuid.uuid3` all appear
> exclusively inside `.fake()` methods, whose entire job is synthetic test data."

Correct for the question that sweep was asking — weak randomness — and wrong for
the one it was not: two of those methods read a schema-supplied `size` and
`max_digits` straight into an allocation. Both were real findings, both were
lost, and the ledger recorded the surface as **covered** because something had
looked at it.

**"Cleared under lens X" is not "covered".** That is the whole idea, and until
now it was a paragraph in `phase3_sweep.md` telling a model to do a
cross-product in its head. That is the identical shape as the three defects this
project has already paid for — `reconcile` printing tasks nobody appended,
`apply-proofs` dropping a field nobody checked, a sweep clearing a surface
nothing re-asked. Each was invisible because everything downstream still passed.

So it is a computation:

1. read every `gaps_observed` entry whose `reason` matches ``cleared for <class>:``
   (the form `phase2_shared.md` §8 requires);
2. resolve the dismissing lens from that class;
3. for each *other* lens whose path signals touch the dismissed file, emit a
   task carrying both the original dismissal and the new question;
4. write the tasks, back up first, and read them back.

Bounded, and the truncation is reported — a dismissal that was never re-examined
is itself a gap for the report to carry.

Usage::

    python3 scripts/lens_matrix.py run --results-dir DIR [--cap 20] [--dry-run]
    python3 scripts/lens_matrix.py show --results-dir DIR
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

try:  # pragma: no cover - bundled-venv shim
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:
    pass

import coverage as coverage_mod
from specialists import _ATTACK_CLASS, _LENS_SIGNALS

#: The form `phase2_shared.md` §8 mandates: ``cleared for <class>: <why>``.
#: Anything else in `gaps_observed` is an ordinary unfinished-area note and is
#: left to the existing gapfill pass.
_DISMISSAL_RX = re.compile(r"^\s*cleared\s+for\s+([a-z0-9_\-]+)\s*:\s*(.+)$",
                           re.IGNORECASE | re.DOTALL)

DEFAULT_CAP = 20

#: class string -> lens key, inverted from `specialists._ATTACK_CLASS` so the
#: two cannot drift. A dismissal names a *class*; the matrix reasons in *lenses*.
_CLASS_TO_LENS = {cls: lens for lens, cls in _ATTACK_CLASS.items()}


def lens_for_class(vuln_class: str) -> str | None:
    needle = re.sub(r"[^a-z0-9]+", "_", str(vuln_class or "").lower()).strip("_")
    if needle in _CLASS_TO_LENS:
        return _CLASS_TO_LENS[needle]
    for cls, lens in _CLASS_TO_LENS.items():
        if cls in needle or needle in cls:
            return lens
    return None


def lenses_touching(path: str) -> list[str]:
    """Every lens whose path signals match this file.

    Signal-based rather than exhaustive on purpose: re-queuing a `.py` file
    under all seven lenses would drown the cap in work no lens would have
    chosen. `_LENS_SIGNALS` is the same table the task generator uses to decide
    a lens is interested, so a re-queue lands where a first-round task would
    have.
    """
    lowered = str(path or "").lower()
    return sorted(lens for lens, signals in _LENS_SIGNALS.items()
                  if any(signal in lowered for signal in signals))


def load_gaps(results_dir: Path) -> list[dict]:
    """Every `gaps_observed` entry the run recorded, from either location."""
    out: list[dict] = []
    for candidate in (results_dir / "logs" / "hunt" / "gaps.json",
                      results_dir / "gaps.json"):
        if not candidate.is_file():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(payload, list):
            out.extend(g for g in payload if isinstance(g, dict))
        elif isinstance(payload, dict) and isinstance(payload.get("gaps"), list):
            out.extend(g for g in payload["gaps"] if isinstance(g, dict))

    # Hunt outputs also carry gaps inline; a run whose collector never
    # concatenated them would otherwise look like it had no dismissals at all.
    hunt_dir = results_dir / "logs" / "hunt"
    if hunt_dir.is_dir():
        for path in sorted(hunt_dir.glob("*.json")):
            if path.name in {"gaps.json", "dispatch.json", "plan.json", "units.json"}:
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for doc in (payload if isinstance(payload, list) else [payload]):
                if isinstance(doc, dict):
                    out.extend(g for g in (doc.get("gaps_observed") or [])
                               if isinstance(g, dict))
    return out


def dismissals(gaps: Iterable[dict]) -> list[dict]:
    """Gap entries that are dismissals, parsed into (surface, lens, why)."""
    found: list[dict] = []
    for gap in gaps:
        reason = str(gap.get("reason") or "")
        match = _DISMISSAL_RX.match(reason)
        if not match:
            continue
        vuln_class, why = match.group(1), match.group(2).strip()
        found.append({
            "surface": str(gap.get("file_or_subsystem") or ""),
            "dismissed_for": vuln_class,
            "dismissing_lens": lens_for_class(vuln_class),
            "why": why,
            "task_id": gap.get("task_id"),
        })
    return found


def build_tasks(entries: Sequence[dict], start: int, cap: int) -> tuple[list[dict], int]:
    """One task per (surface, other lens). Deduplicated, capped, deterministic."""
    seen: set[tuple[str, str]] = set()
    pending: list[tuple[dict, str]] = []
    for entry in entries:
        surface = entry["surface"]
        if not surface:
            continue
        for lens in lenses_touching(surface):
            if lens == entry["dismissing_lens"]:
                continue
            key = (surface, lens)
            if key in seen:
                continue
            seen.add(key)
            pending.append((entry, lens))

    pending.sort(key=lambda pair: (pair[0]["surface"], pair[1]))
    capped = pending[:cap]
    tasks = []
    for offset, (entry, lens) in enumerate(capped):
        attack_class = _ATTACK_CLASS.get(lens, "improper_input_handling")
        tasks.append({
            "task_id": f"t_dis_{start + offset}",
            "source": "dismissal",
            "attack_class": attack_class,
            "target_files": [entry["surface"]],
            "priority": 2,
            "scope_hint": (
                f"{entry['surface']} — re-examined under the {lens} lens. It was "
                f"cleared for {entry['dismissed_for']}, which is a different "
                "question. Ask this lens's own questions from scratch."
            ),
            "rationale": (
                f"cleared for {entry['dismissed_for']} (\"{entry['why'][:160]}\"); "
                f"the {lens} lens has not asked about this surface. A surface "
                "cleared under one lens is not covered — that reasoning cost two "
                "real unbounded-allocation findings on a previous run."
            ),
        })
    return tasks, len(pending) - len(capped)


_DIS_TASK_ID = re.compile(r"^t_dis_(\d+)$")


def _next_index(tasks: Sequence[dict]) -> int:
    highest = 0
    for task in tasks:
        match = _DIS_TASK_ID.match(str(task.get("task_id") or ""))
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def run(results_dir: str | Path, *, cap: int = DEFAULT_CAP,
        write: bool = True) -> dict:
    results = Path(results_dir)
    gaps = load_gaps(results)
    entries = dismissals(gaps)
    existing, _ = coverage_mod.load_tasks(results)
    tasks, dropped = build_tasks(entries, _next_index(existing), cap)

    notes: list[str] = []
    if not gaps:
        notes.append("no gaps_observed were found; either no hunt has run or the "
                     "collector never concatenated them")
    elif not entries:
        notes.append(
            "no dismissals recorded. phase2_shared.md §8 requires a cleared "
            "surface to be written as `cleared for <class>: <why>` — with none "
            "present, this pass cannot tell a surface nobody examined from one "
            "that was examined and cleared")
    if dropped:
        notes.append(
            f"{dropped} (surface, lens) pair(s) exceeded the cap ({cap}) and were "
            "NOT re-queued. Each is a dismissal no other lens has re-examined.")

    payload: dict[str, Any] = {
        "gaps_seen": len(gaps),
        "dismissals": len(entries),
        "requeued": len(tasks),
        "dropped_beyond_cap": dropped,
        "cap": cap,
        "entries": entries,
        "tasks": tasks,
        "notes": notes,
    }
    if write and tasks:
        payload.update(coverage_mod.append_tasks(results, tasks))
    else:
        payload["written"] = 0
        payload["backup_path"] = None
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lens_matrix.py",
        description="Re-queue dismissed surfaces under the lenses that did not "
                    "dismiss them.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, help_text in (("run", "compute and write the re-queue"),
                            ("show", "list dismissals without queuing anything")):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--results-dir", required=True)
        if name == "run":
            cmd.add_argument("--cap", type=int, default=DEFAULT_CAP)
            cmd.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "show":
            entries = dismissals(load_gaps(Path(args.results_dir)))
            print(json.dumps({"dismissals": entries}, indent=2))
            return 0
        payload = run(args.results_dir, cap=args.cap, write=not args.dry_run)
        printable = {k: v for k, v in payload.items() if k not in ("entries",)}
        print(json.dumps(printable, indent=2))
        sys.stderr.write(
            f"lens_matrix: {payload['dismissals']} dismissal(s) -> "
            f"{payload['requeued']} re-queued task(s), "
            f"wrote {payload.get('written', 0)}\n")
        for note in payload["notes"]:
            sys.stderr.write(f"lens_matrix: {note}\n")
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"internal error: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
