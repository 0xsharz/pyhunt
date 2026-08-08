"""Grade a candidate patch by running its security test in a starved environment.

This is the deterministic half of patch verification: it runs a test suite (or a
single generated security test) against a workspace and reports, per test, what
happened. It decides nothing about whether a patch is *correct* — that comparison
(RED without the patch, GREEN with it) belongs to the caller, which runs this
grader twice. This module's whole job is to make each of those two runs
**trustworthy**, and the thing that made them untrustworthy was the environment.

**The defect this module exists to remove.** Its ancestor built the child
environment like this::

    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

That copies the *entire* host environment — including ``ANTHROPIC_API_KEY`` and
``CLAUDE_CODE_OAUTH_TOKEN`` — into a subprocess that runs **model-generated test
code against untrusted target code**. Both halves of that subprocess are
attacker-influenced: the target repository chose what its modules do at import
time, and the test was written by a model reading that repository. Either one can
read ``os.environ`` and exfiltrate it. A scanner that leaks the operator's
credentials while looking for the target's vulnerabilities has done more damage
than the bug it was hunting.

**Why an allowlist and not a denylist.** A denylist (``env.pop("ANTHROPIC_API_KEY")``)
is correct only for the credential names that existed when it was written. Add a
new provider, rotate to a new variable name, run under a CI system that injects
its own token, and the denylist keeps reporting success while leaking. An
allowlist inverts the failure mode: an unknown variable is excluded *by default*,
so a credential that did not exist when this file was written is still withheld.
That difference — what happens to the case nobody anticipated — is the entire
lesson, and it is why :data:`ALLOWED_HOST_VARS` is a closed set of names rather
than a pattern.

The credential-shaped-name check in :func:`_assert_allowlist_carries_no_secrets`
is *not* the mechanism; the allowlist is. It is a tripwire against a future edit
quietly widening the allowlist, and it fails at import time so that edit cannot
ship.

**What else is starved.**

* ``--network none`` when containerised. A patch's security test that needs the
  network to pass is a test telling you something — either it is reaching a live
  service (so its verdict is about that service, not the patch) or the payload is
  calling home. Neither belongs in a verdict.
* ``PYTHONPATH`` is set to the workspace and nothing else. Inheriting the host's
  ``PYTHONPATH`` would let whatever the operator happens to have on it shadow the
  target's own modules — an injection vector into the child *and* a source of
  verdicts that cannot be reproduced on another machine.
* ``HOME`` and ``TMPDIR`` point at a scratch directory this module creates and
  owns, so a test cannot scribble in the operator's home directory or read
  ``~/.aws/credentials`` by way of ``~``.
* Read-only root filesystem, dropped capabilities, no new privileges, memory /
  pid / cpu caps, and a wall clock the child is *killed* on rather than waited on.
* The target repository, if mounted at all, is mounted read-only. The only
  writable paths are the workspace copy and this module's own report directory.

**Honesty rules, inherited from the gate.** A run that could not happen is never
reported as a run that failed:

* ``passed`` / ``failed``            — the runner ran and reached a verdict
* ``no_tests_collected``             — the runner ran and collected nothing; that
  is *not* a pass, and a grader that reports GREEN because zero tests executed is
  the same class of lie as a gate that promotes an unexploited sink
* ``timed_out``                      — killed; no verdict
* ``runner_unavailable``             — no pytest / no interpreter; an environment
  fact, never a failing test
* ``not_attempted``                  — containment was requested and could not be
  provided; nothing was executed

Only the first three mean the grader graded anything, which is what the top-level
``graded`` boolean says. And ``containerised`` is always stated explicitly, so a
bare run can never be read as a contained one.

**Scope.** Patch verification belongs to the ``pyhunt-fix`` skill, which is not
built yet. This module lands early because a known credential leak does not wait
for a roadmap. It is self-contained: standard library only, no imports from any
sibling script, no model call, no phase sequencing.

*Conventions note:* every other script here opens with ``import _bootstrap`` to
put the bundled venv's ``site-packages`` on ``sys.path``. This module imports
nothing outside the standard library, so it deliberately omits that shim rather
than take a hard dependency on a file that does not exist yet.

CLI::

    python3 verify_patch.py run --workspace DIR --tests SPEC [--tests SPEC ...] \\
        [--containerised --image IMG] [--repo DIR] [--timeout N] [--memory-mb N]
    python3 verify_patch.py env [--containerised]     # audit the child env

JSON on stdout, notes on stderr; exit 0 on a completed grading attempt, 2 on a
contract violation the caller must not route around (containment requested but
unavailable, a test spec pointing outside the workspace, a credential-shaped
``--set``), 1 on an internal error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path

SCHEMA = "pyhunt.verify_patch/1"

# Where the workspace, the (optional) target repo and this module's report
# directory land inside the container. The repo path deliberately mirrors the
# scan container's `/target`, so an observer transcript and a grader transcript
# name the same file the same way.
CONTAINER_WORKSPACE = "/workspace"
CONTAINER_REPO = "/target"
CONTAINER_REPORT = "/pyhunt-report"


# ─────────────────────────────────────────────────────────────────────────────
# The environment allowlist — the point of this module
# ─────────────────────────────────────────────────────────────────────────────

# Host variables a bare (non-containerised) test run legitimately needs. Every
# entry is here because removing it breaks a real run, not because it looked
# harmless; "harmless" is what a denylist argues about, and an allowlist does not
# have to. Anything not named here — including every variable that does not exist
# yet — is dropped.
#
#   PATH        the runner binary (`python3`, `pytest`) is found through it; with
#               no PATH the child cannot start at all
#   LANG        \\
#   LC_ALL       > text encoding. Without them CPython picks the POSIX locale and
#   LC_CTYPE    /  a test asserting on non-ASCII output fails for the wrong reason
#   TZ          date/time behaviour; a test that formats timestamps is otherwise
#               at the mercy of the host's zone
#   TERM        pytest's terminal writer probes it; an absent TERM is fine, a
#               *wrong* one produces control-character noise in the log tail
ALLOWED_HOST_VARS: frozenset[str] = frozenset({
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TERM",
})

# Inside a container, PATH / HOME / TMPDIR come from the image — inheriting the
# host's would point at directories that do not exist there. Only the locale and
# timezone hints are worth carrying across the boundary.
ALLOWED_CONTAINER_VARS: frozenset[str] = frozenset({
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
})

# Used only when the host has no PATH at all (`env -i`), so the child still has
# a chance of finding an interpreter instead of failing with a confusing ENOENT.
_DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"

# Substrings that make a variable name credential-shaped. This is a TRIPWIRE, not
# the filter: the allowlist above is what withholds secrets. This exists so that
# a later edit adding, say, "ANTHROPIC_API_KEY" to the allowlist — or an operator
# passing one through `--set` — fails loudly instead of silently restoring the
# defect this module was written to remove.
_CREDENTIAL_MARKERS: tuple[str, ...] = (
    "KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "CREDS",
    "AUTH", "SESSION", "COOKIE", "PRIVATE", "SIGNATURE", "BEARER", "OAUTH",
    "PASSPHRASE", "LICENSE", "SUBSCRIPTION",
)

# Valid POSIX environment variable name. Enforced on anything that reaches the
# child, because a name containing "=" would be mis-split by docker's
# `--env NAME=VALUE` form into a different variable than intended.
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def is_credential_shaped(name: str) -> bool:
    """Does this variable name look like it carries a secret?

    Deliberately over-broad. A false positive costs one explicit refusal the
    operator can read and work around; a false negative costs a leaked token.
    """
    upper = name.upper()
    return any(marker in upper for marker in _CREDENTIAL_MARKERS)


def _assert_allowlist_carries_no_secrets() -> None:
    """Fail at import if the allowlist ever grows a credential-shaped name.

    Import time, not call time, on purpose: the failure has to be impossible to
    reach production with, and a test that merely *could* catch it is weaker than
    a module that will not load.
    """
    for name in sorted(ALLOWED_HOST_VARS | ALLOWED_CONTAINER_VARS):
        if not _ENV_NAME_RE.match(name):
            raise RuntimeError(
                f"verify_patch: {name!r} is not a valid environment variable "
                "name and must not be on the allowlist")
        if is_credential_shaped(name):
            raise RuntimeError(
                f"verify_patch: {name!r} was added to the environment allowlist, "
                "but its name is credential-shaped. This grader runs "
                "model-generated tests against untrusted target code; nothing "
                "that may carry a secret crosses into it. Remove it.")


_assert_allowlist_carries_no_secrets()


def build_child_env(
    *,
    workspace: Path | str,
    scratch_home: Path | str | None = None,
    containerised: bool = False,
    base_env: dict[str, str] | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build the environment for the test child, from an allowlist.

    `base_env` defaults to ``os.environ`` and exists so this can be tested
    against a poisoned environment without poisoning the test process. Nothing
    reaches the returned dict except:

      * names in :data:`ALLOWED_HOST_VARS` / :data:`ALLOWED_CONTAINER_VARS` that
        are actually set in `base_env`,
      * the forced values computed here, which are never inherited, and
      * `extra`, which is screened by :func:`is_credential_shaped` first.

    Raises :class:`ValueError` for a malformed or credential-shaped `extra` name.
    """
    src = os.environ if base_env is None else base_env
    inherited = ALLOWED_CONTAINER_VARS if containerised else ALLOWED_HOST_VARS

    env: dict[str, str] = {}
    for name in sorted(inherited):
        value = src.get(name)
        # A value carrying NUL cannot be passed through execve; dropping it is
        # better than raising, because it is a property of the host we were
        # handed, not of anything the caller asked for.
        if value is None or "\x00" in value:
            continue
        env[name] = value

    if not containerised and not env.get("PATH"):
        env["PATH"] = _DEFAULT_PATH

    if containerised:
        # The image owns these paths; /tmp is the tmpfs mounted over the
        # read-only root filesystem, and is the only place the child may write
        # outside the workspace.
        home = "/tmp"
        tmpdir = "/tmp"
        pythonpath = CONTAINER_WORKSPACE
    else:
        home = str(scratch_home) if scratch_home else str(Path(workspace))
        tmpdir = home
        pythonpath = str(Path(workspace))

    env.update({
        # Never write .pyc into the tree being graded: a stray __pycache__ shows
        # up in the diff the caller takes of this workspace.
        "PYTHONDONTWRITEBYTECODE": "1",
        # Unbuffered, so the tail captured from a killed child still contains the
        # output it produced before the kill.
        "PYTHONUNBUFFERED": "1",
        # Set, never appended to. See the module docstring: an inherited
        # PYTHONPATH can shadow the target's own modules with whatever the
        # operator has on theirs, which changes the verdict for reasons that have
        # nothing to do with the patch.
        "PYTHONPATH": pythonpath,
        # HOME away from the operator's real one: a test cannot then write into
        # ~/.config, and `~/.aws/credentials` is not reachable through `~`.
        "HOME": home,
        "TMPDIR": tmpdir,
    })

    for name, value in (extra or {}).items():
        if not _ENV_NAME_RE.match(name):
            raise ValueError(f"{name!r} is not a valid environment variable name")
        if is_credential_shaped(name):
            raise ValueError(
                f"refusing to pass {name!r} to the test child: the name is "
                "credential-shaped, and this child runs model-generated test "
                "code against untrusted target code")
        if "\x00" in value:
            raise ValueError(f"the value of {name!r} contains a NUL byte")
        env[name] = value

    return env


def withheld_credential_names(base_env: dict[str, str] | None = None) -> list[str]:
    """Credential-shaped names present in the host env that were NOT passed on.

    Names only — never values. Reported so the operator can see the leak did not
    happen rather than take it on trust.
    """
    src = os.environ if base_env is None else base_env
    return sorted(
        name for name in src
        if is_credential_shaped(name) and name not in ALLOWED_HOST_VARS
    )


# ─────────────────────────────────────────────────────────────────────────────
# Run parameters
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 300          # seconds of wall clock for the whole test run
DEFAULT_MEMORY_MB = 2048
DEFAULT_CPUS = "2"
DEFAULT_PIDS = "256"
DEFAULT_FSIZE_MB = 512         # a runaway test writing a 40 GB file is not a verdict
DEFAULT_IMAGE = "python:3.12-slim"

_MAX_LOG = 8000                # tail of combined output kept on the record
_DOCKER_GRACE = 30             # extra seconds allowed for `docker run` teardown

# Outcomes. Only the first three mean a verdict was reached.
PASSED = "passed"
FAILED = "failed"
NO_TESTS = "no_tests_collected"
TIMED_OUT = "timed_out"
RUNNER_UNAVAILABLE = "runner_unavailable"
NOT_ATTEMPTED = "not_attempted"
INTERNAL_ERROR = "internal_error"

_GRADED = frozenset({PASSED, FAILED, NO_TESTS})

# pytest's documented exit codes.
_PYTEST_OK = 0
_PYTEST_TESTS_FAILED = 1
_PYTEST_INTERRUPTED = 2
_PYTEST_INTERNAL_ERROR = 3
_PYTEST_USAGE_ERROR = 4
_PYTEST_NO_TESTS = 5


class ContractViolation(Exception):
    """The caller asked for something this grader must not silently substitute.

    Exit code 2. Raised when containment is requested and cannot be provided, or
    when an input would make the result mean something other than it says.

    `record` carries the full JSON payload when one was already assembled, so the
    CLI can still print a machine-readable ``not_attempted`` record alongside the
    non-zero exit. A caller that only reads stdout must not be left guessing.
    """

    def __init__(self, message: str, record: dict | None = None) -> None:
        super().__init__(message)
        self.record = record


@dataclass(frozen=True)
class TestResult:
    """One test case, as the runner reported it."""

    id: str
    outcome: str                 # passed | failed | error | skipped
    duration_seconds: float
    message: str = ""


@dataclass
class Limits:
    """What was asked for, and what the platform actually enforced.

    `memory_mechanism` is tri-state on purpose. Reporting a limit that was not
    applied is the same failure as reporting a run that did not happen.
    """

    wall_clock_seconds: int
    memory_mb: int
    memory_mechanism: str        # cgroup | rlimit_as | unavailable
    memory_enforced: bool
    fsize_mb: int | None = None
    pids: str | None = None
    cpus: str | None = None
    note: str = ""


@dataclass
class Isolation:
    """What contained the run — stated plainly so bare never reads as contained."""

    containerised: bool
    network: str                 # none | host-inherited
    read_only_rootfs: bool
    caps_dropped: bool
    no_new_privileges: bool
    writable_paths: list[str] = field(default_factory=list)
    repo_mounted_readonly: bool | None = None
    image: str | None = None
    note: str = ""


def _tail(text: str, limit: int = _MAX_LOG) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return "…(truncated)\n" + text[-limit:]


def _note(msg: str) -> None:
    """Human-readable progress. stderr, never stdout — stdout is the JSON."""
    print(f"[verify_patch] {msg}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# Input validation
# ─────────────────────────────────────────────────────────────────────────────

def resolve_test_spec(workspace: Path, spec: str) -> str:
    """Validate one pytest spec and return it unchanged, or raise.

    A spec is ``path``, ``path::TestClass``, or ``path::TestClass::test_name``.
    Only the path part is checked. Two things are refused:

      * anything absolute, and anything that resolves outside the workspace —
        the spec is caller-supplied and, in the ``pyhunt-fix`` flow, the caller
        is a model. ``--tests ../../etc/passwd`` must not be a way to point the
        runner at the host.
      * a path that does not exist — pytest would report "no tests collected",
        which is an honest outcome for an empty suite and a *misleading* one for
        a typo.

    ``resolve()`` follows symlinks, so a link inside the workspace pointing out
    of it is caught here too.
    """
    spec = (spec or "").strip()
    if not spec:
        raise ContractViolation("empty --tests spec")
    path_part = spec.split("::", 1)[0]
    if not path_part:
        raise ContractViolation(f"--tests {spec!r} names no file")
    candidate = Path(path_part)
    if candidate.is_absolute():
        raise ContractViolation(
            f"--tests {spec!r} is absolute; specs are relative to the workspace "
            "so the same spec means the same thing bare and containerised")
    root = Path(workspace).resolve()
    target = (root / candidate).resolve()
    if target != root and root not in target.parents:
        raise ContractViolation(
            f"--tests {spec!r} resolves outside the workspace ({target}); "
            "the grader only ever runs tests from the workspace it was given")
    if not target.exists():
        raise ContractViolation(
            f"--tests {spec!r} does not exist in the workspace; refusing to run, "
            "because pytest would report 'no tests collected' and that would "
            "read as an empty suite rather than a bad path")
    return spec


def parse_set_flags(pairs: list[str] | None) -> dict[str, str]:
    """Parse repeated ``--set NAME=VALUE`` into a dict, screening the names."""
    out: dict[str, str] = {}
    for raw in pairs or []:
        if "=" not in raw:
            raise ContractViolation(f"--set {raw!r} is not NAME=VALUE")
        name, value = raw.split("=", 1)
        name = name.strip()
        if not _ENV_NAME_RE.match(name):
            raise ContractViolation(
                f"--set {name!r} is not a valid environment variable name")
        if is_credential_shaped(name):
            raise ContractViolation(
                f"--set {name!r} refused: the name is credential-shaped. This "
                "child runs model-generated test code against untrusted target "
                "code, and nothing that may carry a secret crosses into it.")
        out[name] = value
    return out


# ─────────────────────────────────────────────────────────────────────────────
# JUnit XML — per-test results without parsing pytest's prose
# ─────────────────────────────────────────────────────────────────────────────

def parse_junit(report_path: Path) -> list[TestResult]:
    """Read pytest's ``--junit-xml`` output into per-test results.

    Machine-readable on purpose: pytest's terminal output is prose that changes
    between releases, and a grader that misreads it produces a wrong verdict
    rather than an error. A missing or malformed file returns ``[]`` — the caller
    then falls back to the exit code and says so, rather than inventing results.
    """
    try:
        tree = ET.parse(report_path)
    except (OSError, ET.ParseError):
        return []

    results: list[TestResult] = []
    root = tree.getroot()
    # pytest emits <testsuites><testsuite>…; older/other writers emit a bare
    # <testsuite>. Accept both rather than depend on the wrapper.
    suites = root.iter("testsuite") if root.tag != "testsuite" else [root]
    for suite in suites:
        for case in suite.iter("testcase"):
            classname = (case.get("classname") or "").strip()
            name = (case.get("name") or "").strip()
            test_id = f"{classname}::{name}" if classname else name
            try:
                duration = float(case.get("time") or 0.0)
            except ValueError:
                duration = 0.0

            outcome, message = "passed", ""
            for child in case:
                if child.tag == "failure":
                    outcome = "failed"
                elif child.tag == "error":
                    outcome = "error"
                elif child.tag == "skipped":
                    outcome = "skipped"
                else:
                    continue
                message = (child.get("message") or child.text or "").strip()
                break
            results.append(TestResult(id=test_id, outcome=outcome,
                                      duration_seconds=round(duration, 4),
                                      message=_tail(message, 600)))
    return results


def totals_for(results: list[TestResult]) -> dict[str, int]:
    totals = {"passed": 0, "failed": 0, "error": 0, "skipped": 0}
    for r in results:
        if r.outcome in totals:
            totals[r.outcome] += 1
    return totals


# Substrings that mean "a module could not be resolved" rather than "a test
# failed". Checked BEFORE a non-zero exit is read as a failing test, because
# misreading this direction is the one error that manufactures false evidence: a
# workspace holds the target's *source* and not its installed dependencies, so an
# import error is the expected failure on any dependency-carrying target, and a
# grader that scores it as RED reports every such target as vulnerable-then-fixed.
_UNMET_MARKERS: tuple[str, ...] = (
    "ModuleNotFoundError",
    "No module named",
    "ImportError while importing test module",
    "error while loading conftest",
    "command not found",
    "No such file or directory",
)


def looks_unmet(log: str, results: list[TestResult]) -> bool:
    """Does this run look like an unresolved dependency rather than a verdict?"""
    haystack = (log or "") + "\n".join(r.message for r in results)
    return any(marker in haystack for marker in _UNMET_MARKERS)


def outcome_for(exit_code: int, results: list[TestResult], *, timed_out: bool,
                junit_written: bool, unmet: bool) -> str:
    """Turn an exit code plus parsed results into one of the honest outcomes.

    Two asymmetries are deliberate, and both slope the same way — towards saying
    "no verdict" rather than "the test failed":

    * ``unmet`` (a module could not be resolved) outranks the exit code unless a
      test actually passed or failed on its own merits. An import error is an
      environment fact.
    * only ``failed`` test cases produce :data:`FAILED`. An ``error`` case is a
      test that could not run — a fixture that raised, a collection error — and
      scoring it as a failing test would let a broken workspace masquerade as a
      reproduced vulnerability.
    """
    if timed_out:
        return TIMED_OUT

    totals = totals_for(results)
    decided = totals["passed"] + totals["failed"]
    if unmet and not decided:
        return RUNNER_UNAVAILABLE

    if exit_code == _PYTEST_OK:
        # Exit 0 with nothing collected should not happen (pytest uses 5), but if
        # it does, an empty suite is not a pass.
        return PASSED if results else NO_TESTS
    if exit_code == _PYTEST_NO_TESTS:
        return NO_TESTS
    if exit_code == _PYTEST_TESTS_FAILED:
        # pytest writes the junit report at session finish, so its absence means
        # the session never started — `python -m pytest` with no pytest installed
        # also exits 1, and that is not a failing test.
        if not junit_written:
            return RUNNER_UNAVAILABLE
        return FAILED if totals["failed"] else RUNNER_UNAVAILABLE
    if exit_code in (_PYTEST_INTERRUPTED, _PYTEST_INTERNAL_ERROR,
                     _PYTEST_USAGE_ERROR):
        # The runner broke or was misused. Genuine failures alongside the breakage
        # are still evidence; errors alone are not.
        return FAILED if totals["failed"] else RUNNER_UNAVAILABLE
    # 127 and friends: the interpreter or pytest is not there at all.
    return RUNNER_UNAVAILABLE


def resolve_python(python_exe: str) -> str:
    """Make the interpreter path absolute before anything uses it.

    The child runs with ``cwd=workspace`` while the availability probe runs with
    the grader's own cwd. A relative ``--python ./.venv/bin/python`` therefore
    resolves to two different files: the probe says pytest is importable and the
    run dies with ENOENT, which surfaced as a confusing ``runner_unavailable``
    whose log named a file that plainly existed. Resolving once, here, makes both
    talk about the same interpreter. A bare name is looked up on PATH exactly as
    ``exec`` would.

    ``abspath``, deliberately, and never ``Path.resolve()``: a virtualenv's
    ``bin/python`` is a *symlink to the base interpreter*, and resolving it hands
    back an interpreter outside the venv with none of the venv's packages. That
    turns "the runner is installed" into ``runner_unavailable`` for every
    venv-based caller — which is exactly what happened here before this comment
    existed. Making a path absolute and following its symlinks are different
    operations, and only the first one is wanted.
    """
    if os.sep in python_exe or python_exe.startswith("."):
        return os.path.abspath(python_exe)
    found = shutil.which(python_exe)
    return found or python_exe


def runner_importable(python_exe: str, module: str = "pytest") -> bool:
    """Can `python_exe` import the test runner?

    Cheap, runs no target code, and turns the commonest environment failure into
    a clear ``runner_unavailable`` before anything is executed rather than an
    exit code that has to be disambiguated afterwards.
    """
    try:
        p = subprocess.run([python_exe, "-c", f"import {module}"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0


# ─────────────────────────────────────────────────────────────────────────────
# Bare execution
# ─────────────────────────────────────────────────────────────────────────────

def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the whole process group.

    A security test spawns children — that is frequently the vulnerability being
    demonstrated. Killing only the direct child leaves them running after the
    workspace is destroyed.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError):        # pragma: no cover - race
        try:
            proc.kill()
        except OSError:
            pass


def _rlimit_plan(memory_mb: int, fsize_mb: int) -> Limits:
    """Decide which resource limits this platform can actually enforce.

    ``RLIMIT_AS`` bounds the *address space*, not the resident set. On Linux that
    is a usable proxy for memory. On Darwin CPython reserves large virtual
    mappings at startup, so a 2 GiB ``RLIMIT_AS`` kills the interpreter before it
    runs a single test — which would surface as a failed security test. So it is
    applied where it works, and reported as ``unavailable`` where it does not,
    rather than applied blindly or dropped silently.
    """
    linux = sys.platform.startswith("linux")
    if memory_mb <= 0:
        return Limits(wall_clock_seconds=0, memory_mb=0,
                      memory_mechanism="unavailable", memory_enforced=False,
                      fsize_mb=fsize_mb or None,
                      note="memory limiting disabled by the caller")
    if linux:
        return Limits(wall_clock_seconds=0, memory_mb=memory_mb,
                      memory_mechanism="rlimit_as", memory_enforced=True,
                      fsize_mb=fsize_mb or None)
    return Limits(
        wall_clock_seconds=0, memory_mb=memory_mb,
        memory_mechanism="unavailable", memory_enforced=False,
        fsize_mb=fsize_mb or None,
        note=(f"RLIMIT_AS is not enforced on {sys.platform}: CPython reserves "
              "large virtual mappings at startup there, so the limit would kill "
              "the interpreter rather than a runaway test. Only the wall clock "
              "and the file-size cap bound this run — use --containerised for a "
              "real memory cap."))


def _preexec(limits: Limits):                    # pragma: no cover - child side
    """Apply rlimits in the child.

    ``preexec_fn`` runs after ``fork`` and before ``exec``; it is not
    async-signal-safe in a threaded parent, which is acceptable here because this
    module is a single-threaded CLI. The alternative — applying limits in the
    parent — would limit the grader itself.
    """
    def _apply() -> None:
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (OSError, ValueError):
            pass
        if limits.fsize_mb:
            cap = limits.fsize_mb * 1024 * 1024
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
            except (OSError, ValueError):
                pass
        if limits.memory_enforced and limits.memory_mechanism == "rlimit_as":
            cap = limits.memory_mb * 1024 * 1024
            try:
                resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
            except (OSError, ValueError):
                pass
    return _apply


def _pytest_argv(python_exe: str, report_path: str, specs: list[str]) -> list[str]:
    """The runner command. ``-p no:cacheprovider`` keeps `.pytest_cache` out of
    the workspace, which the caller diffs."""
    return [
        python_exe, "-m", "pytest",
        "-q", "-p", "no:cacheprovider",
        "--junit-xml", report_path,
        *specs,
    ]


def run_bare(*, workspace: Path, specs: list[str], python_exe: str,
             timeout: int, limits: Limits, env: dict[str, str],
             report_path: Path) -> tuple[int, str, bool, float]:
    """Run the suite as a local subprocess. Returns (exit, log, timed_out, secs).

    Never raises: a missing interpreter comes back as exit 127 with the OSError
    on the log, because "the runner is not installed" must not look like an
    exception in the grader.
    """
    argv = _pytest_argv(python_exe, str(report_path), specs)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(workspace),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            # Its own process group, so a hung test and everything it spawned die
            # together.
            start_new_session=True,
            preexec_fn=_preexec(limits) if os.name == "posix" else None,
        )
    except OSError as e:
        return 127, f"{type(e).__name__}: {e}", False, 0.0

    try:
        out, _ = proc.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            out, _ = proc.communicate(timeout=15)
        except subprocess.SubprocessError:        # pragma: no cover - defensive
            out = ""
        out = f"{out or ''}\n[verify_patch] killed after {timeout}s"
        timed_out = True
    elapsed = time.monotonic() - started
    return proc.returncode if not timed_out else 124, out or "", timed_out, elapsed


# ─────────────────────────────────────────────────────────────────────────────
# Containerised execution
# ─────────────────────────────────────────────────────────────────────────────

def docker_available(binary: str = "docker") -> bool:
    """True only if the CLI exists AND the daemon answers.

    A present binary with a dead daemon is the case that turns "contained" into
    "bare" without anyone noticing, so both halves are checked.
    """
    if shutil.which(binary) is None:
        return False
    try:
        p = subprocess.run([binary, "version", "--format", "{{.Server.Version}}"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0 and bool(p.stdout.strip())


def image_present(image: str, binary: str = "docker") -> bool:
    """Is the image already local?

    Deliberately no pull. Pulling is egress, and the entire point of this run is
    that it has none; silently reaching the network to make a "network: none" run
    possible would be a contradiction the operator never sees.
    """
    try:
        p = subprocess.run([binary, "image", "inspect", image],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0


def container_argv(*, image: str, workspace: Path, report_dir: Path,
                   repo: Path | None, env: dict[str, str], specs: list[str],
                   memory_mb: int, cpus: str, pids: str, name: str,
                   python_exe: str, binary: str = "docker") -> list[str]:
    """The full `docker run` command line.

    Extracted so a test can assert on it without a daemon — the flags here are
    the isolation, so they are worth checking as data rather than trusting.
    """
    argv = [
        binary, "run", "--rm",
        "--name", name,
        "--label", "pyhunt.component=verify_patch",
        # The control this module exists for, after the env allowlist.
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", f"{memory_mb}m",
        # Equal to --memory disables swap; without it the cap is advisory.
        "--memory-swap", f"{memory_mb}m",
        "--cpus", cpus,
        "--pids-limit", pids,
        # Run as the invoking user so files written into the bind-mounted
        # workspace stay owned by them, and root in the container is not root on
        # the mount.
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--workdir", CONTAINER_WORKSPACE,
        # The workspace is a per-finding COPY. It is the only target-derived
        # path that is writable, and the caller is the one that made it.
        "--mount", f"type=bind,source={Path(workspace).resolve()},"
                   f"target={CONTAINER_WORKSPACE}",
        # Ours, not the target's: junit XML has to survive the container.
        "--mount", f"type=bind,source={Path(report_dir).resolve()},"
                   f"target={CONTAINER_REPORT}",
        # --read-only leaves nowhere to write; a small noexec tmpfs is the only
        # scratch, and it is where HOME and TMPDIR point.
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
    ]
    if repo is not None:
        # The target repository itself is NEVER writable. The workspace copy is
        # what a patch is applied to.
        argv += ["--mount", f"type=bind,source={Path(repo).resolve()},"
                            f"target={CONTAINER_REPO},readonly"]
    for name_, value in env.items():
        argv += ["--env", f"{name_}={value}"]
    argv += ["--entrypoint", python_exe, image]
    argv += ["-m", "pytest", "-q", "-p", "no:cacheprovider",
             "--junit-xml", f"{CONTAINER_REPORT}/junit.xml", *specs]
    return argv


def _reap(name: str, binary: str = "docker") -> None:
    """Remove a container by name after a timeout.

    `docker run` has no timeout of its own; killing the client leaves the
    container running, and an orphaned container holding a bind mount into the
    workspace is a real operational harm rather than a tidiness complaint.
    """
    try:
        subprocess.run([binary, "rm", "--force", name],
                       capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - best effort
        pass


def run_container(*, argv: list[str], name: str, timeout: int,
                  binary: str = "docker") -> tuple[int, str, bool, float]:
    """Run the suite in a container. Returns (exit, log, timed_out, secs)."""
    started = time.monotonic()
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout + _DOCKER_GRACE)
    except subprocess.TimeoutExpired as e:
        _reap(name, binary)
        out = e.stdout if isinstance(e.stdout, str) else ""
        err = e.stderr if isinstance(e.stderr, str) else ""
        return (124, f"{out}{err}\n[verify_patch] container killed after "
                     f"{timeout}s", True, time.monotonic() - started)
    except OSError as e:
        return 127, f"{type(e).__name__}: {e}", False, time.monotonic() - started
    return (p.returncode, (p.stdout or "") + (p.stderr or ""), False,
            time.monotonic() - started)


# ─────────────────────────────────────────────────────────────────────────────
# Grading
# ─────────────────────────────────────────────────────────────────────────────

def grade(
    *,
    workspace: Path | str,
    tests: list[str],
    containerised: bool = False,
    image: str = DEFAULT_IMAGE,
    repo: Path | str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    memory_mb: int = DEFAULT_MEMORY_MB,
    fsize_mb: int = DEFAULT_FSIZE_MB,
    cpus: str = DEFAULT_CPUS,
    pids: str = DEFAULT_PIDS,
    python_exe: str = "python3",
    extra_env: dict[str, str] | None = None,
    base_env: dict[str, str] | None = None,
    docker_binary: str = "docker",
) -> dict:
    """Run the tests once and describe what happened. Returns the record dict.

    Raises :class:`ContractViolation` (exit 2 at the CLI) when the caller asked
    for something that must not be silently substituted — most importantly, when
    ``containerised=True`` and no container can be provided. Falling back to a
    bare run there would hand the caller a result labelled as contained that was
    not, which is the same class of error as reporting an unrun PoC as failed.
    """
    workspace = Path(workspace)
    if not workspace.is_dir():
        raise ContractViolation(f"workspace {workspace} is not a directory")
    # Before the probe and the run can disagree about which file this names.
    python_exe = resolve_python(python_exe) if not containerised else python_exe
    if not tests:
        raise ContractViolation("no --tests spec given; refusing to run the whole "
                                "workspace by accident")
    specs = [resolve_test_spec(workspace, s) for s in tests]

    if repo is not None:
        repo = Path(repo)
        if not repo.is_dir():
            raise ContractViolation(f"--repo {repo} is not a directory")

    limits = _rlimit_plan(memory_mb, fsize_mb)
    limits.wall_clock_seconds = timeout
    limits.cpus = cpus if containerised else None
    limits.pids = pids if containerised else None
    if containerised:
        limits.memory_mechanism = "cgroup"
        limits.memory_enforced = memory_mb > 0
        limits.note = ""

    # One scratch root per run: HOME, TMPDIR and the junit report live here, so
    # nothing the child writes outside the workspace touches a shared path.
    scratch = Path(tempfile.mkdtemp(prefix="pyhunt-verify-"))
    report_dir = scratch / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    scratch_home = scratch / "home"
    scratch_home.mkdir(parents=True, exist_ok=True)

    env = build_child_env(workspace=workspace, scratch_home=scratch_home,
                          containerised=containerised, base_env=base_env,
                          extra=extra_env)

    record: dict = {
        "schema": SCHEMA,
        "workspace": str(workspace.resolve()),
        "tests_requested": specs,
        "containerised": containerised,
        "env": {
            "names_passed": sorted(env),
            "inherited_from_host": sorted(
                (ALLOWED_CONTAINER_VARS if containerised else ALLOWED_HOST_VARS)
                & set(env)),
            "withheld_credential_shaped": withheld_credential_names(base_env),
            "policy": "allowlist",
        },
    }

    try:
        if containerised:
            if not docker_available(docker_binary):
                record.update(_not_attempted_record(
                    limits, image,
                    "containerised grading was requested but no working "
                    "container runtime was found (the CLI is missing, or the "
                    "daemon is not answering). Refusing to fall back to a bare "
                    "run: the caller asked for containment and would otherwise "
                    "receive an uncontained result labelled as contained."))
                raise ContractViolation(record["reason"], record)
            if not image_present(image, docker_binary):
                record.update(_not_attempted_record(
                    limits, image,
                    f"the image {image!r} is not present locally, and this "
                    "grader never pulls: pulling is egress, and the run it is "
                    "preparing has none. Pre-pull the image, or pass --image "
                    "with one that is already local."))
                raise ContractViolation(record["reason"], record)

            name = f"pyhunt-verify-{uuid.uuid4().hex[:12]}"
            argv = container_argv(
                image=image, workspace=workspace, report_dir=report_dir,
                repo=repo, env=env, specs=specs, memory_mb=memory_mb,
                cpus=cpus, pids=pids, name=name, python_exe=python_exe,
                binary=docker_binary)
            isolation = Isolation(
                containerised=True, network="none", read_only_rootfs=True,
                caps_dropped=True, no_new_privileges=True,
                writable_paths=[CONTAINER_WORKSPACE, CONTAINER_REPORT, "/tmp"],
                repo_mounted_readonly=True if repo is not None else None,
                image=image)
            exit_code, log, timed_out, elapsed = run_container(
                argv=argv, name=name, timeout=timeout, binary=docker_binary)
            junit = report_dir / "junit.xml"
        else:
            argv = _pytest_argv(python_exe, str(report_dir / "junit.xml"), specs)
            isolation = Isolation(
                containerised=False, network="host-inherited",
                read_only_rootfs=False, caps_dropped=False,
                no_new_privileges=False,
                writable_paths=[str(workspace.resolve()), str(scratch)],
                repo_mounted_readonly=None,
                image=None,
                note=("bare run: the credential allowlist, the wall clock and "
                      "the file-size cap apply, but the test can reach the "
                      "network and the host filesystem. This result must never "
                      "be read as a contained one."))
            # Probe before executing anything: `python -m pytest` with no pytest
            # installed exits 1, which is also pytest's "tests failed" code.
            # Disambiguating it up front beats inferring it from the exit code.
            if not runner_importable(python_exe):
                record.update(_not_attempted_record(
                    limits, None,
                    f"{python_exe!r} cannot import pytest, so no test was run. "
                    "This is a fact about the environment, not a failing test."))
                record["outcome"] = RUNNER_UNAVAILABLE
                record["isolation"] = asdict(isolation)
                record["command"] = argv
                return record
            exit_code, log, timed_out, elapsed = run_bare(
                workspace=workspace, specs=specs, python_exe=python_exe,
                timeout=timeout, limits=limits, env=env,
                report_path=report_dir / "junit.xml")
            junit = report_dir / "junit.xml"

        junit_written = junit.exists()
        results = parse_junit(junit)
        unmet = looks_unmet(log, results)
        outcome = outcome_for(exit_code, results, timed_out=timed_out,
                              junit_written=junit_written, unmet=unmet)
        record.update({
            "outcome": outcome,
            "graded": outcome in _GRADED,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_seconds": round(elapsed, 3),
            "tests": [asdict(r) for r in results],
            "totals": totals_for(results),
            "per_test_results_available": bool(results),
            "dependency_resolution_failed": unmet,
            "isolation": asdict(isolation),
            "limits": asdict(limits),
            "command": argv,
            "log_tail": _tail(log),
        })
        if outcome == RUNNER_UNAVAILABLE:
            record["reason"] = (
                "the test runner reached no verdict: a module could not be "
                "resolved, the runner is not installed, or every case errored "
                "rather than failing. The workspace carries the target's source "
                "but not its installed dependencies, so this is the expected "
                "shape of an environment problem — it is a fact about the "
                "environment, not a failing test, and must not be recorded as "
                "one."
                if unmet or not results else
                "the runner ran but produced no passed or failed case, so there "
                "is no verdict to report.")
        elif outcome == NO_TESTS:
            record["reason"] = (
                "the runner ran and collected no tests. An empty suite is not a "
                "pass — nothing was graded.")
        elif outcome == TIMED_OUT:
            record["reason"] = (
                f"the run was killed after {timeout}s, so it reached no verdict.")
        return record
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _not_attempted_record(limits: Limits, image: str | None, reason: str) -> dict:
    """The shape returned when nothing was executed.

    Used both when containment was requested and refused, and when the runner
    itself is absent. Every field the graded shape carries is present, so a
    consumer never has to branch on which kind of record it received.
    """
    return {
        "outcome": NOT_ATTEMPTED,
        "graded": False,
        "reason": reason,
        "exit_code": None,
        "timed_out": False,
        "duration_seconds": 0.0,
        "tests": [],
        "totals": totals_for([]),
        "per_test_results_available": False,
        "isolation": asdict(Isolation(
            containerised=False, network="not-applicable",
            read_only_rootfs=False, caps_dropped=False,
            no_new_privileges=False, image=image,
            note="nothing was executed")),
        "limits": asdict(limits),
        "command": [],
        "log_tail": "",
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _emit(payload: dict) -> None:
    print(json.dumps(payload, indent=2, sort_keys=False))


def _cmd_run(args: argparse.Namespace) -> int:
    extra = parse_set_flags(args.set)
    record = grade(
        workspace=args.workspace,
        tests=args.tests,
        containerised=args.containerised,
        image=args.image,
        repo=args.repo,
        timeout=args.timeout,
        memory_mb=args.memory_mb,
        fsize_mb=args.fsize_mb,
        cpus=args.cpus,
        pids=args.pids,
        python_exe=args.python,
        extra_env=extra,
    )
    _emit(record)
    _note(f"{record['outcome']} — {record['totals']} in "
          f"{record['duration_seconds']}s "
          f"({'containerised' if record['containerised'] else 'BARE'})")
    if record["env"]["withheld_credential_shaped"]:
        _note("withheld from the child environment: "
              + ", ".join(record["env"]["withheld_credential_shaped"]))
    return 0


def _cmd_env(args: argparse.Namespace) -> int:
    """Audit what would cross into the child, without running anything.

    Names only, never values: the allowlist is what guarantees no value is a
    secret, and printing values would turn a single bad allowlist entry into a
    disclosure.
    """
    env = build_child_env(workspace=args.workspace or Path.cwd(),
                          scratch_home=None,
                          containerised=args.containerised)
    _emit({
        "schema": SCHEMA,
        "policy": "allowlist",
        "containerised": args.containerised,
        "allowlist": sorted(ALLOWED_CONTAINER_VARS if args.containerised
                            else ALLOWED_HOST_VARS),
        "names_passed": sorted(env),
        "withheld_credential_shaped": withheld_credential_names(),
        "host_variable_count": len(os.environ),
        "passed_variable_count": len(env),
    })
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="verify_patch.py",
        description="Run a patch's security tests in a starved environment.")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="grade a workspace")
    run.add_argument("--workspace", required=True, type=Path,
                     help="the per-finding workspace copy (the only writable "
                          "target-derived path)")
    run.add_argument("--tests", required=True, action="append", metavar="SPEC",
                     help="pytest spec relative to the workspace; repeatable")
    run.add_argument("--containerised", action="store_true",
                     help="run under `docker run --network none`; refuses rather "
                          "than falling back to a bare run")
    run.add_argument("--image", default=DEFAULT_IMAGE,
                     help=f"container image, already local (default {DEFAULT_IMAGE})")
    run.add_argument("--repo", type=Path, default=None,
                     help="target repository to mount READ-ONLY at /target")
    run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                     help=f"wall clock seconds (default {DEFAULT_TIMEOUT})")
    run.add_argument("--memory-mb", type=int, default=DEFAULT_MEMORY_MB,
                     help=f"memory cap in MiB (default {DEFAULT_MEMORY_MB}; "
                          "0 disables)")
    run.add_argument("--fsize-mb", type=int, default=DEFAULT_FSIZE_MB,
                     help=f"max file size the child may write, MiB "
                          f"(default {DEFAULT_FSIZE_MB})")
    run.add_argument("--cpus", default=DEFAULT_CPUS)
    run.add_argument("--pids", default=DEFAULT_PIDS)
    run.add_argument("--python", default="python3",
                     help="interpreter that runs pytest (default python3)")
    run.add_argument("--set", action="append", metavar="NAME=VALUE", default=[],
                     help="extra environment variable; credential-shaped names "
                          "are refused")
    run.set_defaults(func=_cmd_run)

    env = sub.add_parser("env", help="print the child environment's variable "
                                     "NAMES without running anything")
    env.add_argument("--workspace", type=Path, default=None)
    env.add_argument("--containerised", action="store_true")
    env.set_defaults(func=_cmd_env)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ContractViolation as e:
        # Still print a record when one exists: a caller reading stdout must get
        # a machine-readable `not_attempted` rather than an empty stream plus a
        # non-zero exit it has to interpret.
        if e.record is not None:
            _emit(e.record)
        else:
            _emit({"schema": SCHEMA, "outcome": NOT_ATTEMPTED, "graded": False,
                   "reason": str(e)})
        _note(f"contract violation: {e}")
        return 2
    except Exception as e:                        # pragma: no cover - defensive
        _note(f"internal error: {type(e).__name__}: {e}")
        _emit({"schema": SCHEMA, "outcome": INTERNAL_ERROR, "graded": False,
               "reason": f"{type(e).__name__}: {e}"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
