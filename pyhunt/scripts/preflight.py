"""Preflight: prove the run can do what it is about to assume.

`pyhunt.sandbox` answers PERMISSION — "am I allowed to execute target code?"
Nothing answered CAPABILITY — "if I execute it, will it reach the target?" —
and that gap is where this tool's worst failures live, because they are silent.

Every one of them looks like a healthy run:

  * The scan runs in a container that has no javac/go/dotnet, so every
    non-Python PoC dies at `command not found` and the findings quietly become
    static guesses.
  * Provisioning installed the target's dependencies into an image the scan is
    not actually running in, so `import <target>` fails and every PoC proves
    only that a hello-world executed.
  * A build-system misdetection left the image with no dependencies at all
    (a `pyproject.toml` read as poetry, a `uv.lock` never consulted).

In each case the report comes out looking normal. That is the problem: a
security tool that degrades silently is worse than one that fails loudly,
because the operator has no signal to distrust the output.

So this module runs cheap, deterministic checks up front and records what the
run can actually do. It follows the same discipline as the Phase 3 observers:

  * **It never blocks.** A missing capability is reported, not fatal — the run
    may still be worth doing statically, and that is the operator's call.
  * **Unknown is its own answer.** A check that could not be performed reports
    ``None``, never a cheerful ``True``.
  * **What it finds reaches the report**, so "PoC confirmation was impossible
    in this container" is visible next to the findings rather than buried in a
    log nobody reads.

**Execution stance.** The checks that run target code — importing the target
package is target code, since imports execute module-level statements — happen
ONLY when execution is already enabled, which means `sandbox.require()` has
already cleared. With execution off, this module reads the filesystem and runs
`--version` probes of VASH's own toolchain, and touches nothing of the
target's.

The CLI (`preflight.py check`) therefore defaults execution OFF, because the
skill invokes it on the **orchestrator's host** at phase 0 step 1 — before a
mode is chosen and before any sandbox has been verified. Running the target's
module-level code there would execute untrusted code outside the boundary the
whole tool exists to maintain. `--execution` exists for the one caller that may
legitimately ask for the executing probes: an invocation from *inside* the
provisioned scan container.

**The majority-Python gate.** `check` is also where decision D-5 stops being a
sentence in a document and becomes mechanical. PyHunt analyses Python. Pointed
at a Go service it does not fail — it succeeds quietly and wrongly: the PEP-578
audit-hook observer never arms, the execution gate's attribution test has no
Python stack to walk, and the language-keyed sink tables yield a tiny task
count, so the run finishes early and *looks clean*. So `check` counts the
target's source files, reports the breakdown with real numbers rather than a
verdict the operator has to take on faith, and exits **2** when Python is not
the majority. Exit 2 is a contract violation the skill may not route around.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401  (must precede any non-stdlib import)

import argparse
import json
import logging
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from lang_hints import EXT_TO_LANG

log = logging.getLogger(__name__)

# Probes are trivial (`--version`, a single import). Anything slower than this
# is hung, and preflight must never become a reason a run is late.
PROBE_TIMEOUT = 30

# Exit codes, identical in meaning to `sandbox.py`'s, because a phase file that
# has to remember two different tables is a phase file that gets one wrong.
EXIT_OK = 0
EXIT_INTERNAL_ERROR = 1
EXIT_CONTRACT_VIOLATION = 2

#: Python's minimum share of counted source files for the run to proceed.
#: Expressed as a fraction so the recorded rule and the code cannot drift.
MAJORITY_THRESHOLD = 0.5

#: Runaway guard for the census walk. Deliberately far larger than the
#: sampling limit `_source_languages` uses: the census decides whether the run
#: happens at all, and `rglob` returns files in directory order, so a truncated
#: walk is a *biased* walk — a monorepo whose Go service sorts first could be
#: judged non-Python on the strength of its first few thousand files. Counting
#: a suffix is cheap; a wrong hard stop is not.
CENSUS_FILE_LIMIT = 500_000

# Directories that are never the target's own source.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
              "build", ".tox", "target", "vendor", ".gradle", "site-packages"}

# language -> the executable a PoC in that language needs first. Absent means
# the PoC cannot even start, whatever else is true.
_TOOLCHAIN: dict[str, tuple[str, ...]] = {
    "python": ("python3",),
    "javascript": ("node",),
    "typescript": ("node",),
    "java": ("java", "javac"),
    "go": ("go",),
    "csharp": ("dotnet",),
}


@dataclass(frozen=True)
class Capability:
    """One thing the run may be assuming, and whether it actually holds.

    `ok` is deliberately tri-state. ``None`` means the check could not be
    performed — which is not the same as the capability being present, and must
    never be rendered as though it were.
    """

    name: str
    ok: bool | None
    detail: str
    # What silently degrades when this is False. Written for the operator
    # reading the report, not for the developer reading the code.
    matters_because: str

    @property
    def degraded(self) -> bool:
        return self.ok is False


@dataclass
class PreflightReport:
    execution_enabled: bool
    capabilities: list[Capability] = field(default_factory=list)

    @property
    def degraded(self) -> list[Capability]:
        return [c for c in self.capabilities if c.degraded]

    @property
    def unknown(self) -> list[Capability]:
        return [c for c in self.capabilities if c.ok is None]

    @property
    def poc_confirmation_available(self) -> bool:
        """Can this run actually confirm a finding by executing a PoC?

        The honest headline. False whenever execution is off OR anything the
        PoC path depends on is missing — which is the difference between
        "findings were proven" and "findings are static guesses".
        """
        return self.execution_enabled and not self.degraded

    def as_dict(self) -> dict:
        return {
            "execution_enabled": self.execution_enabled,
            "poc_confirmation_available": self.poc_confirmation_available,
            "degraded": [c.name for c in self.degraded],
            "unknown": [c.name for c in self.unknown],
            "capabilities": [asdict(c) for c in self.capabilities],
        }

    def summary_line(self) -> str:
        if not self.execution_enabled:
            return ("static-only run: no PoC is executed, so no finding here is "
                    "confirmed by execution")
        if self.degraded:
            names = ", ".join(c.name for c in self.degraded)
            return (f"execution is ENABLED but {len(self.degraded)} capability it "
                    f"depends on is missing ({names}) — PoC confirmation will be "
                    f"weak or impossible, and an unproven finding must NOT be "
                    f"read as disproven")
        return "execution enabled and every capability the PoC path needs is present"


def _run(argv: list[str], *, cwd: Path | None = None) -> tuple[int, str]:
    """Run a trivial probe. Never raises; a missing binary is exit 127."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=PROBE_TIMEOUT,
                           cwd=str(cwd) if cwd else None)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, f"{type(e).__name__}: {e}"
    return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()[:400]


@dataclass(frozen=True)
class LanguageCounts:
    """Raw source-file counts for the target, and how complete they are."""

    counts: dict[str, int]
    #: Files whose extension maps to `web-template` (Jinja, ERB, JSP, ...).
    #: Excluded from `counts` on purpose — a template is markup rendered *by* a
    #: backend, so counting it would dilute the very language it evidences.
    #: Reported rather than dropped, so the exclusion is visible.
    web_template_files: int
    #: True when the walk stopped at its limit, so the numbers are a prefix of
    #: the tree rather than the whole of it.
    truncated: bool

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _language_counts(repo_path: Path, limit: int) -> LanguageCounts:
    """Count source files per language, skipping vendored and build output."""
    counts: dict[str, int] = {}
    templates = 0
    seen = 0
    truncated = False
    try:
        candidates = repo_path.rglob("*")
    except OSError:
        return LanguageCounts({}, 0, False)
    try:
        for p in candidates:
            if seen >= limit:
                truncated = True
                break
            try:
                if not p.is_file():
                    continue
                rel = p.relative_to(repo_path).parts
            except (OSError, ValueError):
                continue
            if any(part in _SKIP_DIRS for part in rel):
                continue
            lang = EXT_TO_LANG.get(p.suffix.lower())
            if not lang:
                continue
            if lang == "web-template":
                templates += 1
                continue
            counts[lang] = counts.get(lang, 0) + 1
            seen += 1
    except OSError:
        # An unreadable subtree mid-walk. Keep what was counted and say the
        # numbers are partial rather than presenting them as the whole tree.
        truncated = True
    return LanguageCounts(counts, templates, truncated)


def _source_languages(repo_path: Path, limit: int = 4000) -> list[str]:
    """Languages actually present in the target, most common first."""
    counts = _language_counts(repo_path, limit).counts
    return sorted(counts, key=lambda l: (-counts[l], l))


def language_census(repo_path: Path, *, limit: int = CENSUS_FILE_LIMIT) -> dict:
    """The language breakdown, with the numbers the majority rule is applied to.

    Everything the operator needs to check the verdict themselves is in here:
    the per-language file counts, their shares, the threshold, and the boolean
    the threshold produced. A gate that reports only its conclusion is a gate
    nobody can audit — and this one can stop a run.
    """
    repo_path = Path(repo_path)
    tally = _language_counts(repo_path, limit)
    total = tally.total
    ordered = sorted(tally.counts, key=lambda l: (-tally.counts[l], l))
    shares = {lang: round(tally.counts[lang] / total, 4) for lang in ordered} if total else {}
    primary = ordered[0] if ordered else None
    python_files = tally.counts.get("python", 0)
    python_share = (python_files / total) if total else 0.0
    is_majority = bool(primary == "python" and python_share >= MAJORITY_THRESHOLD)
    return {
        "primary": primary,
        "files_counted": total,
        "counts": {lang: tally.counts[lang] for lang in ordered},
        "shares": shares,
        "python_files": python_files,
        "python_share": round(python_share, 4),
        "is_majority_python": is_majority,
        "threshold": MAJORITY_THRESHOLD,
        "rule": (
            "python must be the most common counted language AND hold at least "
            f"{MAJORITY_THRESHOLD:.0%} of counted source files"
        ),
        "web_template_files": tally.web_template_files,
        "truncated": tally.truncated,
        "excluded_dirs": sorted(_SKIP_DIRS),
    }


def python_package_candidates(repo_path: Path) -> list[str]:
    """Importable top-level package names this repo plausibly provides.

    Sourced from `src/<pkg>/__init__.py`, `<pkg>/__init__.py`, and the
    distribution name in pyproject.toml (normalised, since `my-pkg` installs as
    `my_pkg`). Best-effort by design: a wrong guess costs one failed import,
    while having no guess at all costs the entire capability check.
    """
    names: list[str] = []

    def add(n: str) -> None:
        n = n.strip().replace("-", "_")
        if n and n.isidentifier() and n not in names and not n.startswith("test"):
            names.append(n)

    for parent in (repo_path / "src", repo_path):
        try:
            entries = sorted(parent.iterdir())
        except OSError:
            continue
        for child in entries:
            try:
                if child.is_dir() and (child / "__init__.py").is_file():
                    if child.name not in _SKIP_DIRS:
                        add(child.name)
            except OSError:
                continue

    pyproject = repo_path / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
            project = data.get("project")
            if isinstance(project, dict) and project.get("name"):
                add(str(project["name"]))
        except (OSError, ValueError, TypeError):
            pass
    return names


def _check_target_readable(repo_path: Path, languages: list[str]) -> Capability:
    if not repo_path.is_dir():
        return Capability("target_readable", False, f"{repo_path} is not a directory",
                          "there is nothing to scan")
    if not languages:
        return Capability(
            "target_readable", False,
            "no files in a language VASH recognises",
            "the hunt has no source to work from, so an empty result would mean "
            "'nothing was looked at', not 'nothing was found'")
    return Capability("target_readable", True,
                      f"languages present: {', '.join(languages[:5])}",
                      "the hunt needs source it can read")


def _check_toolchain(languages: list[str]) -> list[Capability]:
    """One capability per language present: can a PoC in it even start?"""
    out: list[Capability] = []
    for lang in languages:
        tools = _TOOLCHAIN.get(lang)
        if not tools:
            continue                       # a language with no PoC runtime: not a gap
        missing = [t for t in tools if shutil.which(t) is None]
        ok = not missing
        detail = (f"{', '.join(tools)} present" if ok
                  else f"missing: {', '.join(missing)}")
        out.append(Capability(
            f"toolchain_{lang}", ok, detail,
            f"a {lang} PoC cannot compile or run without it, so every {lang} "
            f"finding would fall back to a static guess — and a PoC that never "
            f"ran is NOT evidence the vulnerability is absent"))
    return out


def _check_target_importable(repo_path: Path) -> Capability:
    """THE check that catches a scan running in the wrong container.

    Runs the target's own module-level code, so it is only ever called on the
    execution-enabled path (sandbox already cleared).
    """
    candidates = python_package_candidates(repo_path)
    if not candidates:
        return Capability(
            "target_importable", None,
            "could not determine a top-level package name for this repo",
            "a Python PoC that cannot import the target proves nothing about it")

    tried: list[str] = []
    for name in candidates[:6]:
        code, out = _run(["python3", "-c", f"import {name}"])
        if code == 0:
            return Capability("target_importable", True, f"`import {name}` succeeds",
                              "a PoC can reach the target's real code")
        tried.append(f"{name} ({out.splitlines()[-1][:80] if out else 'failed'})")

    return Capability(
        "target_importable", False,
        "none of " + ", ".join(tried) + " could be imported",
        "the target's dependencies are not installed in THIS container, so "
        "every Python PoC can only prove that a hello-world ran — the exact "
        "silent failure the scan-image design exists to prevent")


def _check_observer(languages: list[str]) -> Capability | None:
    """Is the runtime observer for the primary language usable here?

    Corroboration only — a missing observer weakens evidence, it does not
    invalidate a PoC. Reported as unknown rather than failed for that reason.
    """
    try:
        from poc_runtime import runtime_for
    except Exception:                                # pragma: no cover - import guard
        return None
    rt = runtime_for(languages)
    if rt is None or rt.observer is None:
        return None
    code, _out = _run(["sh", "-c", rt.observer.available_check])
    ok = code == 0
    return Capability(
        f"observer_{rt.observer.name}", True if ok else None,
        "available" if ok else "not available in this container",
        "an observer corroborates that the vulnerable call actually fired; "
        "without it a PoC still stands on its own assertions, so this weakens "
        "evidence rather than invalidating it")


def run_preflight(repo_path: Path, *, execution_enabled: bool) -> PreflightReport:
    """Check what this run can actually do. Never raises, never blocks.

    With `execution_enabled=False` nothing belonging to the target is executed:
    the report simply records that findings will be static.
    """
    repo_path = Path(repo_path)
    report = PreflightReport(execution_enabled=execution_enabled)
    try:
        languages = _source_languages(repo_path)
        report.capabilities.append(_check_target_readable(repo_path, languages))

        if execution_enabled:
            report.capabilities.extend(_check_toolchain(languages))
            if "python" in languages:
                report.capabilities.append(_check_target_importable(repo_path))
            obs = _check_observer(languages)
            if obs is not None:
                report.capabilities.append(obs)
    except Exception as e:                           # pragma: no cover - defensive
        log.warning("[preflight] check failed, continuing: %s", e)
        report.capabilities.append(Capability(
            "preflight_itself", None, f"{type(e).__name__}: {e}",
            "preflight could not complete, so treat its silence as no information"))

    for cap in report.capabilities:
        if cap.degraded:
            log.warning("[preflight] %s: NOT AVAILABLE (%s) — %s",
                        cap.name, cap.detail, cap.matters_because)
        elif cap.ok is None:
            log.info("[preflight] %s: unknown (%s)", cap.name, cap.detail)
    log.info("[preflight] %s", report.summary_line())
    return report


# ===========================================================================
# The results-directory record
# ===========================================================================

class PreflightContractViolation(Exception):
    """Something the run must not proceed past. Maps to exit 2.

    Distinct from an internal error (exit 1): a contract violation means
    preflight worked perfectly and the answer is no.
    """


#: Keys `check` owns in `preflight.json`. Everything else in that file belongs
#: to another step — `authorisation` and `mode` to the agent, `sandbox` to
#: `sandbox.py` — and is preserved across a re-run.
_OWNED_KEYS = (
    "target", "checked_at", "execution_enabled", "poc_confirmation_available",
    "degraded", "unknown", "capabilities", "languages", "language_census",
    "majority_python", "gate",
)


def write_preflight_json(results_dir: Path, payload: dict) -> Path:
    """Merge `payload` into `<results-dir>/preflight.json` and prove it landed.

    A merge, not a write. `sandbox.py detect|up|verify` records under
    `sandbox`, and phase 0 records the operator's verbatim authorisation
    statement at top level; clobbering the file to record a language census
    would delete a record of consent.

    The write is read back before returning. This function exists because of a
    defect where the script exited 0 having written nothing at all, and the
    phase believed the exit code — so "I wrote it" is not taken on trust here
    either.

    Raises `PreflightContractViolation` if the directory or file cannot be
    written, or if what comes back off disk is not what went down.
    """
    results_dir = Path(results_dir)
    path = results_dir / "preflight.json"
    try:
        results_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise PreflightContractViolation(
            f"results directory {results_dir} cannot be created ({type(e).__name__}: "
            f"{e}); preflight.json is the phase-0 artifact and every later phase "
            f"reads it, so there is nothing to proceed to") from e

    existing: dict = {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            existing = loaded
    except (OSError, ValueError):
        existing = {}
    existing.update(payload)

    try:
        path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    except OSError as e:
        raise PreflightContractViolation(
            f"could not write {path} ({type(e).__name__}: {e})") from e

    try:
        back = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise PreflightContractViolation(
            f"{path} is unreadable immediately after being written "
            f"({type(e).__name__}: {e})") from e
    if not isinstance(back, dict) or "language_census" not in back:
        raise PreflightContractViolation(
            f"{path} does not contain the record that was just written; the "
            f"results directory is not behaving like a filesystem")
    return path


# ===========================================================================
# CLI
# ===========================================================================

@dataclass
class CheckOutcome:
    exit_code: int
    payload: dict
    notes: list[str] = field(default_factory=list)
    written_to: Path | None = None


def _census_notes(census: dict) -> list[str]:
    """The breakdown, as numbers. The operator checks the call; they are not
    told the call."""
    total = census["files_counted"]
    if not total:
        return ["language census: no files in a language PyHunt recognises"]
    notes = [f"language census over {total} source file(s)"
             + (" (TRUNCATED — partial walk)" if census["truncated"] else "")]
    for lang, count in census["counts"].items():
        notes.append(f"    {lang:<14} {count:>7}  {count / total:6.1%}")
    if census["web_template_files"]:
        notes.append(f"    ({census['web_template_files']} web-template file(s) "
                     f"not counted: markup is rendered by a backend, not analysed "
                     f"as its own language)")
    notes.append(f"rule: {census['rule']}")
    return notes


def run_check(repo: Path, results_dir: Path, *,
              execution_enabled: bool = False) -> CheckOutcome:
    """Phase 0 step 1, whole. Returns the exit code, the record, and the notes.

    Order matters and is deliberate: the record is written **before** the
    majority-Python verdict is returned, because the phase's instruction on a
    refusal is to read `language_census` out of `preflight.json` and tell the
    user what the repository actually is. A gate that stops the run without
    leaving the evidence behind is a gate the operator cannot argue with.
    """
    repo = Path(repo).expanduser()
    try:
        # `resolve()` does not require the path to exist, and an absolute path
        # is what the record needs: a relative one is meaningless to anyone
        # reading preflight.json later from a different working directory.
        repo = repo.resolve()
    except OSError:                                  # pragma: no cover - exotic paths
        pass
    notes: list[str] = [f"target: {repo}"]

    target_exists = repo.is_dir()
    census = language_census(repo)
    report = run_preflight(repo, execution_enabled=execution_enabled)

    payload = report.as_dict()
    payload.update({
        "target": str(repo),
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "languages": list(census["counts"]),
        "language_census": census,
        "majority_python": census["is_majority_python"],
    })

    if not target_exists:
        exit_code = EXIT_INTERNAL_ERROR
        reason = (f"{repo} is not a readable directory — preflight cannot say "
                  f"anything about a target it cannot see, and must not guess")
    elif census["is_majority_python"]:
        exit_code = EXIT_OK
        reason = (f"python is {census['python_share']:.1%} of "
                  f"{census['files_counted']} counted source file(s)")
    else:
        exit_code = EXIT_CONTRACT_VIOLATION
        primary = census["primary"]
        if primary is None:
            reason = ("no files in a language PyHunt recognises — an empty scan "
                      "of an unreadable target would report zero findings, and "
                      "that must not be mistaken for a clean result")
        else:
            reason = (
                f"this target is {census['shares'][primary]:.1%} {primary} by "
                f"source file count (python: {census['python_share']:.1%}); "
                f"PyHunt's analysis is Python-specific (D-5) and would produce "
                f"confident nonsense here")

    payload["gate"] = {
        "passed": exit_code == EXIT_OK,
        "exit_code": exit_code,
        "reason": reason,
    }

    notes.extend(_census_notes(census))
    if exit_code == EXIT_OK:
        notes.append(f"VERDICT: majority Python — {reason}")
    elif exit_code == EXIT_CONTRACT_VIOLATION:
        notes.append(f"VERDICT: NOT majority Python. {reason}. Stopping.")
        notes.append("A Python-shaped scan of a non-Python service does not fail "
                     "loudly: the PEP-578 audit-hook observer never arms, the "
                     "gate's attribution test has no Python stack to walk, and "
                     "the language-keyed sink tables yield few tasks — so the run "
                     "finishes early, reports high coverage over a tiny "
                     "denominator, and looks clean.")
        notes.append("If a genuine Python component lives in a subdirectory, "
                     "re-run with --repo pointed at that subdirectory.")
    else:
        notes.append(f"ERROR: {reason}")

    for cap in report.capabilities:
        if cap.degraded:
            notes.append(f"capability {cap.name}: MISSING ({cap.detail})")
        elif cap.ok is None:
            notes.append(f"capability {cap.name}: unknown ({cap.detail})")
    if not execution_enabled:
        notes.append("capability probes that execute target code were NOT run: "
                     "this invocation is on the orchestrator's host, outside any "
                     "sandbox. Absent capabilities are unknown here, not absent.")

    # Written before the verdict is acted on — see the docstring. A failure to
    # write is itself a contract violation, but it is caught here rather than
    # raised so that the census still reaches the operator: the numbers are the
    # useful part, and losing them to a disk error would be the second time
    # this command failed silently.
    written: Path | None
    try:
        written = write_preflight_json(results_dir, payload)
        notes.append(f"wrote {written}")
    except PreflightContractViolation as e:
        written = None
        exit_code = EXIT_CONTRACT_VIOLATION
        payload["gate"] = {"passed": False, "exit_code": exit_code,
                           "reason": f"preflight.json could not be written: {e}"}
        notes.append(f"CONTRACT VIOLATION: {e}")
        notes.append("preflight.json is phase 0's artifact and phase 1's gate. "
                     "Without it there is nothing for a later phase to check, "
                     "and the run must not start.")
    return CheckOutcome(exit_code, payload, notes, written)


def _emit(payload: dict) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _note(message: str) -> None:
    print(f"[preflight] {message}", file=sys.stderr)


def cmd_check(args: argparse.Namespace) -> int:
    outcome = run_check(Path(args.repo), Path(args.results_dir),
                        execution_enabled=args.execution)
    _emit(outcome.payload)
    for note in outcome.notes:
        _note(note)
    return outcome.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preflight.py",
        description=("Prove the run can do what it is about to assume: language "
                     "census, the majority-Python gate (D-5), and the capability "
                     "record every later phase reads."),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser(
        "check",
        help=("write preflight.json and gate on the target being majority "
              "Python (exit 2 if it is not)"))
    p_check.add_argument("--repo", required=True, help="path to the target repository")
    p_check.add_argument("--results-dir", required=True,
                         help="the run's results directory; preflight.json is written here")
    p_check.add_argument(
        "--execution", action="store_true",
        help=("also run the capability probes that EXECUTE code — importing the "
              "target runs its module-level statements. Valid only from inside "
              "the provisioned scan container; never on the orchestrator's host, "
              "where phase 0 invokes this command."))
    p_check.set_defaults(func=cmd_check)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="[%(levelname)s] %(message)s")
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args))
    except PreflightContractViolation as e:
        _note(f"contract violation: {e}")
        return EXIT_CONTRACT_VIOLATION
    except Exception as e:                           # pragma: no cover - top-level guard
        log.exception("[preflight] internal error")
        _note(f"internal error: {type(e).__name__}: {e}")
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
