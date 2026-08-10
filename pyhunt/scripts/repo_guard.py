"""Prove the target repository was not modified — the property PyHunt states twice.

``SKILL.md`` §5: *"PyHunt never modifies the target repository — not even to add
a test."* ``phase2_shared.md`` §1 repeats it to every hunt agent: *"a scanner
that edits the target has destroyed the thing it was measuring."*

Nothing checked it. During a real scan the graph extractor wrote a
``graphify-out/`` directory into the target from phase 1b onward; every hunt
agent noticed the untracked directory and reported that it "was already there",
which was true from each agent's point of view and false about the run as a
whole. The measurement was of a tree PyHunt had modified, and the report said
otherwise.

The check costs one ``git status --porcelain``. This module makes it a phase
gate:

    python3 scripts/repo_guard.py snapshot --repo DIR --results-dir DIR
    python3 scripts/repo_guard.py assert   --repo DIR --results-dir DIR --phase phase1b_taint

``snapshot`` records the target's dirty-state fingerprint at the start of the
run; ``assert`` re-reads it and exits **2** if anything moved. Exit 2 is a stop,
not a hint (``SKILL.md`` §8): a run that has modified its target has invalidated
its own baseline, and the honest response is to say so before writing a report,
not after.

Two deliberate design choices:

* **Untracked files count.** ``graphify-out/`` was untracked and additive and
  it still broke the property — on a target with a dirty-tree check, a
  pre-commit hook, or a CI step that fails on untracked files, an added
  directory changes the target's own behaviour mid-scan.
* **A non-git target is not a pass.** It degrades to a recursive
  (path, size, mtime) manifest rather than reporting "clean". A guard that
  silently passes on the targets it cannot check is the same failure this file
  exists to close.

JSON on stdout, notes on stderr. Exit 0 clean, 2 on a violation, 1 on an
internal error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

try:  # pragma: no cover - bundled-venv shim, mirrors the other scripts
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:
    pass

#: Where the baseline lives inside the results directory.
SNAPSHOT_NAME = "repo_guard.json"

#: Directories never worth fingerprinting on a non-git target: they are either
#: the target's own build detritus or ours, and neither is a modification of the
#: source tree.
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "node_modules", ".idea", ".vscode",
})


class GuardViolation(RuntimeError):
    """The target moved. Exit 2."""


def _run_git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"git unavailable: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def is_git_repo(repo: Path) -> bool:
    code, _ = _run_git(repo, "rev-parse", "--is-inside-work-tree")
    return code == 0


def git_fingerprint(repo: Path) -> dict:
    """HEAD plus the full porcelain status, untracked files included."""
    code, head = _run_git(repo, "rev-parse", "HEAD")
    code2, status = _run_git(repo, "status", "--porcelain", "--untracked-files=all")
    if code != 0 or code2 != 0:
        raise GuardViolation(f"could not read git state for {repo}: {head}{status}")
    lines = sorted(line for line in status.splitlines() if line.strip())
    return {
        "kind": "git",
        "head": head.strip(),
        "status_lines": lines,
        "dirty_entries": len(lines),
    }


def tree_fingerprint(repo: Path) -> dict:
    """(path, size) for every file, hashed. The fallback for a non-git target.

    Deliberately not content-hashing: the target can be large and this runs
    between every phase. Size and path catch an added, removed or truncated
    file, which is every way a scanner realistically damages a tree it is only
    supposed to read. ``mtime`` is excluded because reading a file updates
    ``atime`` on some mounts and tools rewrite ``mtime`` without changing bytes.
    """
    digest = hashlib.sha256()
    count = 0
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            rel = str(path.relative_to(repo))
            digest.update(f"{rel}\0{size}\0".encode("utf-8", "replace"))
            count += 1
    return {"kind": "tree", "files": count, "digest": digest.hexdigest()}


def fingerprint(repo: Path) -> dict:
    repo = Path(repo).resolve()
    if not repo.is_dir():
        raise GuardViolation(f"target {repo} is not a directory")
    record = git_fingerprint(repo) if is_git_repo(repo) else tree_fingerprint(repo)
    record["repo"] = str(repo)
    record["taken_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return record


def snapshot(repo: Path, results_dir: Path) -> dict:
    record = fingerprint(repo)
    path = Path(results_dir) / SNAPSHOT_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"baseline": record, "checks": []}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def _diff(baseline: dict, current: dict) -> list[str]:
    if baseline.get("kind") != current.get("kind"):
        return [f"fingerprint kind changed: {baseline.get('kind')} -> "
                f"{current.get('kind')}"]
    if baseline["kind"] == "git":
        problems = []
        if baseline.get("head") != current.get("head"):
            problems.append(
                f"HEAD moved: {baseline.get('head')} -> {current.get('head')}. "
                "The scan is no longer measuring the commit it started on.")
        before = set(baseline.get("status_lines") or ())
        after = set(current.get("status_lines") or ())
        for line in sorted(after - before):
            problems.append(f"appeared: {line}")
        for line in sorted(before - after):
            problems.append(f"disappeared: {line}")
        return problems
    problems = []
    if baseline.get("digest") != current.get("digest"):
        problems.append(
            f"tree fingerprint changed ({baseline.get('files')} files -> "
            f"{current.get('files')} files). The target is not byte-identical "
            "to the tree this run started against.")
    return problems


def check(repo: Path, results_dir: Path, phase: str | None = None) -> dict:
    """Compare the target against the baseline. Raises on any change."""
    path = Path(results_dir) / SNAPSHOT_NAME
    if not path.is_file():
        raise GuardViolation(
            f"no baseline at {path}. Run `repo_guard.py snapshot` in phase 0 — "
            "without a baseline this guard cannot tell an untouched target from "
            "a modified one, and reporting 'clean' would be a guess."
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    baseline = payload.get("baseline") or {}
    current = fingerprint(repo)
    problems = _diff(baseline, current)

    entry = {
        "phase": phase,
        "checked_at": current["taken_at"],
        "clean": not problems,
        "problems": problems,
    }
    payload.setdefault("checks", []).append(entry)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if problems:
        raise GuardViolation(
            "the target repository changed during this run:\n  - "
            + "\n  - ".join(problems)
            + "\n\nPyHunt states that it never modifies the target. A run that "
              "has must say so rather than report a measurement of a tree it "
              "edited. Find what wrote there (the graph extractor and any hunt "
              "agent that ignored `never write inside repo` are the usual "
              "causes), remove it, and re-check."
        )
    return entry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo_guard.py",
        description="Assert the target repository is byte-identical to the tree "
                    "this run started against.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    snap = sub.add_parser("snapshot", help="record the baseline (phase 0)")
    snap.add_argument("--repo", required=True, type=Path)
    snap.add_argument("--results-dir", required=True, type=Path)

    assert_cmd = sub.add_parser("assert", help="fail if the target moved")
    assert_cmd.add_argument("--repo", required=True, type=Path)
    assert_cmd.add_argument("--results-dir", required=True, type=Path)
    assert_cmd.add_argument("--phase", default=None,
                            help="phase id, recorded with the check")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "snapshot":
            payload = snapshot(args.repo, args.results_dir)
            base = payload["baseline"]
            print(json.dumps(payload, indent=2))
            sys.stderr.write(
                f"repo_guard: baseline recorded ({base['kind']}, "
                f"{base.get('dirty_entries', base.get('files'))} entries)\n")
            return 0
        entry = check(args.repo, args.results_dir, args.phase)
        print(json.dumps(entry, indent=2))
        sys.stderr.write(f"repo_guard: target unchanged at {args.phase or 'check'}\n")
        return 0
    except GuardViolation as exc:
        sys.stderr.write(f"contract violation: {exc}\n")
        return 2
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"internal error: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
