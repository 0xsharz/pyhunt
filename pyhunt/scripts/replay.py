"""Harness-side proof: re-run the PoC ourselves, and gate on *that*.

Every scanner in this lineage — `audit`, VASH, and PyHunt until now — asked the
agent that found the bug to also run the exploit, and then judged the transcript
the agent reported. `oracle/finding.py` still does exactly that: it reads
``poc.run_output``, a string the Hunt agent wrote, and hands it to the gate.

The nonce closes two holes in that arrangement and not the third. A *hostile
repository* cannot forge a marker line, because it cannot guess the nonce.
Another *concurrent task* cannot have its events mistaken for this one's, for
the same reason. But the hunt agent is handed the nonce in its own prompt, so a
confused (or motivated) hunter can compose a perfectly-formed proving line and
put it in the field the gate reads. The gate would be judging fiction.

This module removes the agent from the evidence path:

    **Only the PoC crosses the boundary.** Not the transcript, not
    ``poc.succeeded``, not the notes. Replay writes the PoC into a fresh
    container built from the unmodified provisioned image, arms the observer
    itself, captures the output itself, and hands *that* to the gate.

The trust boundary is the image tag, exactly as Anthropic's reference harness
puts it: the hunt agent could write anywhere inside its own container, but it
cannot retroactively modify the image replay starts from.

Two further rules, both cheap and both load-bearing:

* **Three runs, unanimous, or no promotion.** Once is an anecdote. A proof that
  reproduces two times in three is a flaky proof, and a flaky proof is not a
  proof. The per-run verdicts are recorded so the disagreement is *visible*
  rather than averaged away. The three is a **floor, not a default**: a caller
  that asks for fewer still gets its runs and its per-run verdicts, but the
  record is structurally incapable of saying ``proven`` (see
  :data:`PROMOTION_REPEAT_FLOOR` and :attr:`ProofRecord.promotion_blocked`).
  The promotion rule is not the caller's to relax.
* **Nothing here may delete a finding.** A container that will not start, an
  image that was never built, a PoC that needs a dependency the image lacks, a
  killed run — each is a fact about the *environment*, and each gets its own
  outcome (``not_attempted`` / ``observer_absent``) that leaves the finding
  exactly as the static analysis left it. Missing toolchain is never reported
  as a failed exploit. That includes every promotion block above: blocking a
  promotion never weakens a finding, it only declines to strengthen it.

**The marker channel (Contract A).** Replay generates a random 32-hex
``observer_key`` for every container — distinct from the nonce, never reused
between repeats — passes it in as ``PYHUNT_OBSERVER_KEY``, and opens **file
descriptor 3** inside the container for the observer to write to. The hook
signs each marker line with that key and writes it to fd 3; replay reads the
channel from the host after the container exits and hands it to the gate, which
discards any line whose signature does not verify.

Two independent mechanisms, because either alone is weak: the private fd stops
ordinary target/PoC output being *mistaken* for observer output, and the HMAC
stops a deliberate write to the channel being *believed*. Neither is a security
boundary against an adversary who has read this repository — the target runs in
the same interpreter as the hook and can, with effort, recover the key from
process memory. They defeat naive and opportunistic forgery and force any
attack to be deliberate and PyHunt-specific. Out-of-process observation
(seccomp, eBPF, ptrace) is the real fix and is out of scope. See
``references/execution-gate.md``.

**Where the PoC runtime went.** ``poc_runtime.py`` is *called*, not absorbed:
this module imports nothing from it. That file's job is to compose the recipe
and the observer wrap that go into the *hunt agent's prompt* — prompt-side text
generation. Replay's job is the opposite side of the same boundary: it builds
its own argv, in Python, from the observer asset on disk, because anything it
inherited from the prompt-side path would be one more thing an agent could
influence. The two share exactly one thing, and it is a constant:
``oracle.markers.MARKER``.

Usage::

    python3 scripts/replay.py run --results-dir DIR --finding-id f_x [--repeats 3]

JSON to stdout, human notes to stderr, ``proof/<finding_id>.json`` written into
the results directory. Exit 0 whatever the outcome — an unproven finding is a
result, not an error; 2 on a contract violation the skill must not route around;
1 on an internal error.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol, Sequence

try:  # pragma: no cover - the bundled-venv shim; absent until scripts/_bootstrap.py lands
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:
    # replay.py deliberately imports nothing outside the standard library and
    # its own siblings, so it runs correctly with or without the shim. The
    # import stays so the file matches the script convention the moment the
    # shim exists.
    pass

from oracle.classes import is_undecidable
from oracle.gate import ExecutionVerdict, Outcome, judge
from oracle.markers import MARKER, parse_observer_output
from oracle.nonce import canary_path, nonce_for

try:  # The gate owns the definition of "a frame whose name was minted"; replay
    # reports the same set into the proof record rather than inventing a second
    # one. Optional so a half-landed tree degrades instead of failing to import.
    from oracle.gate import synthesized_filenames_from_events as _gate_synthesized
except ImportError:  # pragma: no cover - depends on a sibling module's version
    _gate_synthesized = None  # type: ignore[assignment]

# ─────────────────────────────────────────────────────────────────────────────
# constants
# ─────────────────────────────────────────────────────────────────────────────

#: Anthropic's pre-filter, adopted verbatim: "reproduces 3/3". Three fresh
#: containers, three independent verdicts, and promotion only on unanimity.
DEFAULT_REPEATS = 3

#: The same number again, as a **floor** rather than a default. `--repeats` is a
#: knob a caller can turn, and a knob that can turn the promotion rule off is
#: the promotion rule being the caller's choice — which is exactly what D-6 says
#: it must not be. So a run below this floor still executes and still records
#: every per-run verdict; it simply cannot aggregate to `proven`. A refusal, not
#: a warning: a warning is not greppable after the fact, and an operator reading
#: `proven` in a report has no way to know a flag weakened it.
PROMOTION_REPEAT_FLOOR = 3

#: The schema's own constraint on `finding_id` (`finding.schema.json`). The id
#: reaches this module from model-authored JSON and is then interpolated into
#: four paths — the finding it loads, the staging directory it *deletes*, the
#: log root, and the proof it writes. It is validated once, at entry, before any
#: of those paths exists as a string.
_FINDING_ID_RX = re.compile(r"^f_[a-z0-9_-]{1,64}$")

#: Per-run wall clock. A PoC that has not demonstrated the bug in two minutes is
#: not going to; a fork bomb or a ReDoS payload is *expected* here, not
#: exceptional, so the ceiling is a containment control as much as a budget.
DEFAULT_TIMEOUT_S = 120

#: Where the provisioned image mounts the target. The frames the observer
#: records are container-side, so this is the root the gate attributes against.
CONTAINER_TARGET_ROOT = "/target"

#: Read-only mount holding the PoC and the observer. Deliberately NOT under
#: /tmp or the workdir: the PoC must not be able to rewrite the observer that is
#: watching it.
CONTAINER_PYHUNT_DIR = "/pyhunt"

#: Writable tmpfs the PoC runs in, so a PoC that writes files still works under
#: a read-only root filesystem.
CONTAINER_WORKDIR = "/work"

#: Must match :func:`oracle.nonce.canary_path`'s default root — the payload
#: templates embed that path, and replay bind-mounts a host directory there so
#: the canary can be observed from OUTSIDE the container. Host-side observation
#: is what makes the canary evidence rather than another string in a transcript.
CONTAINER_CANARY_ROOT = "/tmp/pyhunt-canary"

#: Writable mount carrying the observer's **private marker channel**. The hook
#: writes signed markers to file descriptor 3; the launcher below points fd 3 at
#: a file in here, and replay reads it from the host once the container is gone.
#: Separate from the canary mount on purpose — a marker file appearing among the
#: canary entries would corrupt the one signal replay reads structurally.
CONTAINER_MARKER_DIR = "/pyhunt-marks"

#: Basename of the marker channel inside :data:`CONTAINER_MARKER_DIR`.
MARKER_FILENAME = "markers.txt"

CONTAINER_MARKER_PATH = f"{CONTAINER_MARKER_DIR}/{MARKER_FILENAME}"

#: The descriptor the observer writes markers to. Not stdout and not stderr:
#: ordinary target output shares those, and "the observer said it" must not be
#: decidable by a string prefix anything can print.
OBSERVER_FD = 3

#: The observer asset, shipped beside this file.
OBSERVER_ASSET = Path(__file__).resolve().parent / "observers" / "pyhunt_audit_hook.py"

#: Basename of the tiny launcher replay writes beside the PoC.
LAUNCHER_NAME = "_pyhunt_fd3.py"

#: ``docker run`` forwards a container's stdout and stderr and nothing else, so
#: fd 3 has to be opened *inside* the container by the first process that runs
#: there. This is that process. It is pure Python — no `/bin/sh` dependency, so
#: an image built without a shell still gets a marker channel — and it
#: ``execv``s the hook, so the marker path never survives into the observed
#: process's ``argv`` or ``os.environ`` for the target to read back.
#:
#: Failure here is deliberately non-fatal: without fd 3 the hook falls back to
#: stderr and marks the stream, which costs channel separation and keeps the
#: signature. Refusing to run the PoC because a descriptor would not open would
#: turn an environment problem into a missing proof.
_LAUNCHER_SOURCE = '''\
"""Open the observer's marker channel on fd %(fd)d, then become the hook.

Written by replay.py into the read-only payload mount. Not a general-purpose
tool: argv is `<marker-path> <hook.py> <poc.py> [args...]`, and the marker path
is consumed here so the observed process never sees it.
"""
import os
import sys


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("pyhunt-fd3: usage: <marker-path> <hook.py> <poc.py>\\n")
        return 2
    marker_path, rest = argv[0], list(argv[1:])
    try:
        fd = os.open(marker_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        if fd != %(fd)d:
            os.dup2(fd, %(fd)d)
            os.close(fd)
        # Python opens descriptors close-on-exec; the whole point is that this
        # one survives the execv below.
        os.set_inheritable(%(fd)d, True)
    except OSError as exc:
        sys.stderr.write("pyhunt-fd3: no marker channel (%%s); the observer will "
                         "fall back to stderr\\n" %% (exc,))
    os.execv(sys.executable, [sys.executable] + rest)
    return 1  # unreachable unless execv failed, which raises


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
''' % {"fd": OBSERVER_FD}

#: Container resource caps for the fallback argv builder. Modest on purpose:
#: replay proves a sink fires, it is not a benchmark.
FALLBACK_MEMORY = "2g"
FALLBACK_CPUS = "2"
FALLBACK_PIDS = "256"

#: Isolation tiers at which PLAN §4 refuses Proof mode. Replay re-checks rather
#: than trusting that phase 0 did, because a resumed run can reach this script
#: with a stale manifest.
PROOF_REFUSED_TIERS = frozenset({"none", "runc"})

#: Anything matching this never reaches the container, and is stripped from the
#: environment the `docker` CLI itself inherits. The container environment is
#: built from an ALLOWLIST (see :func:`_container_env`), so this is the second
#: of two independent mechanisms rather than the only one.
_AUTH_ENV_RX = re.compile(
    r"(API_?KEY|OAUTH|_TOKEN$|^TOKEN$|SECRET|PASSWORD|CREDENTIAL|SESSION_KEY"
    r"|^AWS_|^AZURE_|^GOOGLE_APPLICATION|^GH_|^GITHUB_|^NPM_|^PYPI_"
    r"|^ANTHROPIC_|^CLAUDE_|^OPENAI_)",
    re.I,
)

#: The run-scoped HMAC key every nonce is derived from. Replay must derive the
#: SAME nonce the payload was authored with, which means this value has to
#: survive between processes — see :func:`resolve_run_secret`.
_RUN_SECRET_ENV = "PYHUNT_RUN_SECRET"

#: Phrases that mean "the environment was not there", as opposed to "the exploit
#: did not work". Intentionally duplicated from `oracle/finding.py` rather than
#: imported: that module classifies the *agent's* transcript and this one
#: classifies *replay's own*, and the two must be free to diverge — replay sees
#: docker-level failures the agent never can, and the agent sees toolchain
#: problems inside a container replay does not use.
_TOOLCHAIN_MISSING_RX = re.compile(
    r"command not found"
    r"|no such file or directory:\s*'?python"
    r"|ModuleNotFoundError: No module named '(?!.*poc)"
    r"|ImportError: cannot import name"
    r"|is not installed",
    re.I,
)

#: Docker itself failing, as opposed to the PoC failing. Getting this wrong in
#: the wrong direction turns a broken daemon into "the exploit did not
#: reproduce", which is the silent false negative this whole module exists to
#: prevent.
_DOCKER_FAILURE_RX = re.compile(
    r"Cannot connect to the Docker daemon"
    r"|Unable to find image"
    r"|No such image"
    r"|manifest unknown"
    r"|OCI runtime create failed"
    r"|Error response from daemon"
    r"|executable file not found"
    r"|permission denied while trying to connect",
    re.I,
)

#: How much a verdict CLAIMS, so a disagreement can be resolved conservatively.
#: When the three replays do not agree, the aggregate is the *least*-claiming
#: verdict any of them produced — never the majority, and never the best one.
#: All eight outcomes are ranked so the function is total.
_CLAIM_STRENGTH: dict[Outcome, int] = {
    Outcome.PROVEN: 8,
    Outcome.SINK_REACHED_UNPROVEN: 7,
    Outcome.SELF_ATTRIBUTED: 6,
    Outcome.NONCE_MISMATCH: 5,
    Outcome.NO_EVENT: 4,
    Outcome.OBSERVER_ABSENT: 3,
    Outcome.NOT_APPLICABLE: 2,
    Outcome.NOT_ATTEMPTED: 1,
}


class ReplayContractError(RuntimeError):
    """A precondition the skill must fix rather than route around: no results
    directory, no such finding, unreadable JSON. Exits 2."""


# ─────────────────────────────────────────────────────────────────────────────
# identifiers and the paths built from them
# ─────────────────────────────────────────────────────────────────────────────

def validate_finding_id(finding_id: str) -> str:
    """The one place a ``finding_id`` becomes trusted enough to join to a path.

    ``finding_id`` originates in model-authored JSON and this module then
    interpolates it into four filesystem operations, one of which is a
    ``shutil.rmtree``. ``--finding-id ../../../../tmp/evil`` reached all four
    before this existed. Validating against the schema's own pattern at entry —
    *before any path is constructed* — is the only order that closes it: a check
    performed after the join is a check performed after the damage.

    Raises :class:`ReplayContractError` so the CLI exits 2 and phase 2b stops,
    rather than routing around it.
    """
    ident = str(finding_id or "")
    if not _FINDING_ID_RX.match(ident):
        raise ReplayContractError(
            f"finding_id {finding_id!r} does not match {_FINDING_ID_RX.pattern} "
            "(finding.schema.json). Replay refuses to build a path from it — an "
            "id it cannot vouch for reaches a findings read, a log write, a "
            "recursive delete and a proof write."
        )
    return ident


def _safe_rmtree(directory: Path, *, inside: Path) -> None:
    """``shutil.rmtree`` that first proves its target is where it thinks it is.

    :func:`validate_finding_id` already makes traversal unconstructible; this is
    the second, independent mechanism, because the cost of being wrong here is
    unbounded and a future caller may reintroduce an unvalidated id. The
    resolved target must be strictly beneath the resolved results directory —
    equality is refused too, so a bug that collapses the staging path to the
    results root cannot delete the whole run.
    """
    root = Path(inside).resolve()
    target = Path(directory).resolve()
    if target == root or root not in target.parents:
        raise ReplayContractError(
            f"refusing to remove {target}: it is not inside the results "
            f"directory {root}"
        )
    shutil.rmtree(target)


# ─────────────────────────────────────────────────────────────────────────────
# the seam with oracle/ — checked, not assumed
# ─────────────────────────────────────────────────────────────────────────────
#
# C-1 happened because two modules were built to two different designs and each
# half passed its own tests. The seam was invisible. These two probes make it
# visible: replay asks, at runtime, whether the gate and the marker parser
# actually expose the contract it is calling them under, and a run whose gate
# cannot enforce locality (Contract B `finding_file`), cannot distrust a
# synthesized frame (`synthesized_filenames`) or cannot verify a signature
# (`observer_key` / `parse_observer_output(key=...)`) is recorded as ineligible
# for promotion. Degrading loudly beats promoting on a contract nobody is
# enforcing.

#: Parameters :func:`oracle.gate.judge` must accept for a run to be promotable.
_GATE_CONTRACT_PARAMS = ("finding_file", "synthesized_filenames", "observer_key")


def _parameters_of(fn: Callable[..., Any]) -> frozenset[str]:
    try:
        return frozenset(inspect.signature(fn).parameters)
    except (TypeError, ValueError):  # pragma: no cover - builtins/C callables
        return frozenset()


def gate_contract_gaps() -> tuple[str, ...]:
    """Contract B parameters :func:`oracle.gate.judge` does not accept."""
    params = _parameters_of(judge)
    return tuple(p for p in _GATE_CONTRACT_PARAMS if p not in params)


def markers_contract_gaps() -> tuple[str, ...]:
    """``("key",)`` when :func:`oracle.markers.parse_observer_output` cannot
    verify signatures, which means an unsigned line is indistinguishable from an
    authentic one and nothing this run produces may promote."""
    return () if "key" in _parameters_of(parse_observer_output) else ("key",)


# ─────────────────────────────────────────────────────────────────────────────
# what crosses the boundary
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PocArtifact:
    """**The only thing that crosses from the hunt agent to the gate.**

    This type is the trust boundary made structural. It has three fields and
    none of them is a transcript: there is no ``run_output``, no ``succeeded``,
    no ``notes``, so no code path downstream of :func:`load_poc` can pass the
    agent's account of its own work to :func:`judge` — not by accident, and not
    by a later edit that "just needed one more field", because the field does
    not exist to be passed.
    """

    #: The exploit source, verbatim. Written to disk and executed; never parsed
    #: for meaning, never trusted for truth.
    code: str
    #: Declared language. Anything but Python cannot be observed by a PEP-578
    #: audit hook, which is `not_attempted`, not a failure.
    language: str
    #: Basename the PoC is written under inside the container.
    filename: str


@dataclass(frozen=True)
class FindingRef:
    """The finding's *identity and classification* — deliberately not its
    evidence.

    ``vuln_class`` reaches the gate, and that is safe in the one direction that
    matters: it can only ever force ``not_applicable`` (see
    :mod:`oracle.classes`). No value an agent can put here promotes anything.
    """

    finding_id: str
    task_id: str | None
    vuln_class: str | None
    file: str | None


# ─────────────────────────────────────────────────────────────────────────────
# the container interface
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ContainerSpec:
    """One container run, described declaratively so it can be faked in tests
    and asserted over (no auth env, no host mounts beyond the two named)."""

    image: str
    #: argv INSIDE the container.
    command: tuple[str, ...]
    #: (host_path, container_path, "ro" | "rw")
    binds: tuple[tuple[str, str, str], ...]
    #: container_path -> mount options
    tmpfs: tuple[tuple[str, str], ...]
    #: Built from an allowlist. Never a copy of the host environment.
    env: tuple[tuple[str, str], ...]
    workdir: str
    labels: tuple[tuple[str, str], ...]
    network: str
    name: str
    timeout_s: int


@dataclass(frozen=True)
class ContainerResult:
    """What one container run produced. ``stdout``/``stderr`` are replay's own
    capture — this is the only text in the module that may reach the gate."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    #: False only when the runner could not launch at all (no binary, OSError).
    spawned: bool = True
    #: Runner-level error, when the run never happened.
    error: str | None = None
    duration_ms: int = 0
    #: The argv actually issued, for the audit trail.
    argv: tuple[str, ...] = ()
    #: The observer's private channel (fd 3), read from the host mount after the
    #: container exited. Filled in by :func:`replay_once`, not by the runner —
    #: the runner sees only what `docker run` forwards.
    markers: str = ""

    @property
    def transcript(self) -> str:
        """The PoC's ordinary output: stdout and stderr, verbatim.

        This is *not* the gate's input. It is what the toolchain-missing and
        docker-failure heuristics read, and what a human reads to see what the
        exploit actually printed.
        """
        return (self.stdout or "") + ("\n" if self.stdout and self.stderr else "") + (self.stderr or "")

    @property
    def observer_output(self) -> str:
        """Everything the gate is allowed to judge, marker channel first.

        stdout and stderr are included deliberately, not carelessly. Two
        reasons, and both depend on the gate verifying signatures:

        * the hook falls back to stderr when fd 3 could not be opened, and a
          fallback that the gate never sees is a proof silently lost;
        * a target or PoC that *tries* to forge a marker line does it on stdout,
          and a forgery attempt is the single most interesting thing that can
          happen in a run. Feeding those lines to the verifying parser is what
          turns them from noise into a counted, reported `forged_lines`.
        """
        parts = [self.markers or "", self.stdout or "", self.stderr or ""]
        return "\n".join(p for p in parts if p)


class ContainerRunner(Protocol):
    """Everything replay needs from a container runtime.

    A protocol rather than a hard Docker dependency for one concrete reason:
    the logic that decides `proven` must be testable without a daemon. Every
    test in ``tests/test_replay.py`` injects a fake implementation.
    """

    def available(self) -> tuple[bool, str]: ...

    def image_digest(self, image: str) -> str | None: ...

    def run(self, spec: ContainerSpec) -> ContainerResult: ...


def docker_run_argv(spec: ContainerSpec, *, binary: str = "docker") -> list[str]:
    """Fallback argv builder — used only when ``sandbox.py`` exposes none.

    The flag list is PLAN §4's "portable and enforced on every tier" row, and
    every entry is a containment control rather than a preference:
    ``--network none`` (a unit harness never needs a socket, and a payload aimed
    at a real host must not be able to leave), ``--read-only`` with writes
    confined to named tmpfs, ``--cap-drop ALL`` and ``--security-opt
    no-new-privileges``, memory/pid caps because fork bombs are an expected
    payload here, and a ``pyhunt.*`` label set so the reaper can clean up after
    a SIGKILL.

    Whenever ``sandbox.py`` provides a builder, that one wins — isolation policy
    belongs in one file, and the proof record names which built the argv.
    """
    argv = [binary, "run", "--rm", "--name", spec.name,
            # The trust boundary is the image tag, so the tag must resolve to
            # the image provisioning actually built. Docker's default is
            # `--pull missing`, which reaches out to a registry when the tag is
            # not local — turning a missing image into an internet fetch, and
            # letting a name collision run somebody else's bytes under the tag
            # this proof will cite. `never` makes a missing image fail fast,
            # which replay reports as `not_attempted`.
            "--pull", "never",
            "--network", spec.network,
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", FALLBACK_MEMORY,
            "--cpus", FALLBACK_CPUS,
            "--pids-limit", FALLBACK_PIDS,
            "--workdir", spec.workdir]
    for key, value in spec.labels:
        argv += ["--label", f"{key}={value}"]
    for dest, opts in spec.tmpfs:
        argv += ["--tmpfs", f"{dest}:{opts}" if opts else dest]
    for host, dest, mode in spec.binds:
        argv += ["--volume", f"{host}:{dest}:{mode}"]
    for key, value in spec.env:
        argv += ["--env", f"{key}={value}"]
    argv.append(spec.image)
    argv.extend(spec.command)
    return argv


def resolve_argv_builder() -> tuple[Callable[..., list[str]], str]:
    """Prefer ``sandbox.py``'s argv builder; fall back to this module's.

    The contract replay is written against — one keyword-only function taking a
    :class:`ContainerSpec` and returning a docker argv::

        def container_run_argv(spec, *, binary: str = "docker") -> list[str]

    tried under the names ``replay_run_argv``, ``container_run_argv`` and
    ``run_argv``. A signature mismatch degrades to the fallback rather than
    crashing, because a refactor in a sibling module must never be able to turn
    a provable finding into an unprovable one — but the substitution is recorded
    in the proof record, so it is visible rather than silent.
    """
    try:
        import sandbox  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on sibling module
        return docker_run_argv, f"replay-fallback (sandbox.py not importable: {exc})"
    for name in ("replay_run_argv", "container_run_argv", "run_argv"):
        fn = getattr(sandbox, name, None)
        if callable(fn):
            def _wrapped(spec: ContainerSpec, *, binary: str = "docker",
                         _fn: Callable[..., Any] = fn) -> list[str]:
                try:
                    return list(_fn(spec, binary=binary))
                except TypeError:
                    return docker_run_argv(spec, binary=binary)
            return _wrapped, f"sandbox.{name}"
    return docker_run_argv, "replay-fallback (sandbox.py exposes no argv builder)"


class DockerRunner:
    """The real runner: shells out to the ``docker`` CLI.

    Shelling out rather than adding the Docker SDK keeps the bundled venv at
    two packages, and matches how `provision/build.py` already talks to the
    daemon.
    """

    def __init__(self, binary: str = "docker") -> None:
        self.binary = binary
        self._argv_builder, self.argv_source = resolve_argv_builder()

    # -- capability ---------------------------------------------------------

    def available(self) -> tuple[bool, str]:
        """(usable, human detail). Both halves matter: a CLI with no daemon
        behind it produces exactly the failure this returns False for."""
        if shutil.which(self.binary) is None:
            return False, f"`{self.binary}` is not on PATH"
        try:
            p = subprocess.run(
                [self.binary, "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=20, env=_child_env(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"{type(exc).__name__}: {exc}"
        if p.returncode != 0 or not p.stdout.strip():
            return False, (p.stderr or p.stdout or "docker daemon did not answer").strip()[:300]
        return True, f"docker server {p.stdout.strip()}"

    def image_digest(self, image: str) -> str | None:
        """The image's content ID, recorded so the proof names exactly what was
        run. ``None`` when it cannot be read — recorded as null, never guessed."""
        try:
            p = subprocess.run(
                [self.binary, "image", "inspect", "--format", "{{.Id}}", image],
                capture_output=True, text=True, timeout=60, env=_child_env(),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        digest = (p.stdout or "").strip()
        return digest if p.returncode == 0 and digest else None

    # -- execution ----------------------------------------------------------

    def run(self, spec: ContainerSpec) -> ContainerResult:
        argv = self._argv_builder(spec, binary=self.binary)
        started = time.monotonic()
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               timeout=spec.timeout_s, env=_child_env())
        except subprocess.TimeoutExpired as exc:
            self._force_remove(spec.name)
            return ContainerResult(
                stdout=_as_text(exc.stdout), stderr=_as_text(exc.stderr),
                exit_code=124, timed_out=True, spawned=True,
                duration_ms=_ms_since(started), argv=tuple(argv),
            )
        except OSError as exc:
            return ContainerResult(
                stdout="", stderr="", exit_code=127, spawned=False,
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=_ms_since(started), argv=tuple(argv),
            )
        return ContainerResult(
            stdout=p.stdout or "", stderr=p.stderr or "", exit_code=p.returncode,
            duration_ms=_ms_since(started), argv=tuple(argv),
        )

    def _force_remove(self, name: str) -> None:
        """A timed-out `docker run` leaves the container alive. Reap it by name;
        the label-based sweep in sandbox.py is the backstop, not the plan."""
        try:
            subprocess.run([self.binary, "rm", "--force", name],
                           capture_output=True, text=True, timeout=30,
                           env=_child_env())
        except (OSError, subprocess.SubprocessError):  # pragma: no cover - best effort
            pass


def _child_env() -> dict[str, str]:
    """The environment the ``docker`` CLI itself inherits, with every credential
    stripped.

    Belt and braces: the container's own environment is built from an allowlist
    and can never inherit anything, so this only protects against a future flag
    (``--env-file``, ``-e NAME`` with no value) that would pass a host variable
    through. Defence in depth costs one dict comprehension here.
    """
    return {k: v for k, v in os.environ.items() if not _AUTH_ENV_RX.search(k)}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _ms_since(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


# ─────────────────────────────────────────────────────────────────────────────
# reading the run state
# ─────────────────────────────────────────────────────────────────────────────

def _read_json(path: Path, *, required: bool) -> dict:
    if not path.is_file():
        if required:
            raise ReplayContractError(f"{path} does not exist")
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReplayContractError(f"{path} is not readable JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ReplayContractError(f"{path} does not contain a JSON object")
    return data


def load_manifest(results_dir: Path) -> dict:
    """``manifest.json`` — absent is survivable (an older results directory),
    malformed is not."""
    return _read_json(Path(results_dir) / "manifest.json", required=False)


def load_poc(results_dir: Path, finding_id: str) -> tuple[PocArtifact | None, FindingRef, str | None]:
    """Read ``findings/<finding_id>.json`` and take the PoC **and nothing else**.

    This function is where the trust boundary is enforced. The finding document
    is read into a local, the three PoC fields are copied out of it, and the
    document goes out of scope. ``run_output``, ``compile_output``, ``succeeded``
    and ``notes`` are never bound to a name — there is deliberately no variable
    holding them that a later edit could thread through to :func:`judge`.

    Returns ``(artifact | None, ref, reason_if_no_artifact)``.
    """
    finding_id = validate_finding_id(finding_id)
    path = Path(results_dir) / "findings" / f"{finding_id}.json"
    document = _read_json(path, required=True)

    # Two shapes are accepted: the per-finding file the results contract
    # describes, and a HuntOutput wrapper (`{task_id, findings: [...]}`) as
    # emitted by a hunt subagent. Being liberal here costs nothing; guessing
    # about the PoC would cost everything.
    finding: dict | None = None
    task_id = document.get("task_id") if isinstance(document.get("task_id"), str) else None
    if isinstance(document.get("findings"), list):
        for candidate in document["findings"]:
            if isinstance(candidate, dict) and candidate.get("finding_id") == finding_id:
                finding = candidate
                break
        if finding is None:
            raise ReplayContractError(
                f"{path} contains a findings[] array with no entry whose "
                f"finding_id is {finding_id!r}"
            )
    elif document.get("finding_id") is not None:
        finding = document
    else:
        raise ReplayContractError(
            f"{path} is neither a finding object nor a {{findings: [...]}} wrapper"
        )

    if finding.get("finding_id") != finding_id:
        raise ReplayContractError(
            f"{path} holds finding_id {finding.get('finding_id')!r}, "
            f"not the requested {finding_id!r}"
        )

    ref = FindingRef(
        finding_id=finding_id,
        task_id=task_id or (finding.get("task_id") if isinstance(finding.get("task_id"), str) else None),
        vuln_class=finding.get("vuln_class") if isinstance(finding.get("vuln_class"), str) else None,
        file=finding.get("file") if isinstance(finding.get("file"), str) else None,
    )

    poc = finding.get("poc")
    if not isinstance(poc, dict):
        return None, ref, "the finding carries no PoC, so there is nothing to replay"

    code = poc.get("code")
    if not isinstance(code, str) or not code.strip():
        return None, ref, "the finding's PoC has no `code`, so there is nothing to run"

    language = poc.get("language") if isinstance(poc.get("language"), str) else "python"
    filename = poc.get("poc_filename") if isinstance(poc.get("poc_filename"), str) else "poc.py"

    return PocArtifact(code=code, language=language,
                       filename=_safe_poc_filename(filename)), ref, None


def _safe_poc_filename(name: str) -> str:
    """A basename ending in .py, or ``poc.py``. The name arrives from agent
    output, so it is treated as a path component and nothing more."""
    base = os.path.basename(name.strip())
    if not base or base in (".", "..") or not base.endswith(".py"):
        return "poc.py"
    return base


def resolve_run_secret(results_dir: Path, manifest: dict) -> tuple[str | None, str]:
    """Find the run-scoped HMAC key, in the order that keeps nonces stable.

    This matters more than it looks. The payload embedded ``nonce_for(run_id,
    task_id)`` at PoC-authoring time; replay must derive the same value or the
    payload's own nonce will not be found in the event arguments, and a real
    proof quietly degrades to ``sink_reached_unproven``. Each phase is a
    separate process, so ``oracle.nonce.run_secret``'s in-process generation is
    not enough on its own — the secret has to be written down somewhere.

    Precedence: the environment (the skill exported it for the whole run), then
    ``manifest.json``, then a ``.run_secret`` sidecar this function writes when
    it has to mint one. Returns ``(secret | None, source)``; ``None`` means every
    lookup failed and nonces will not match the hunt phase's — which is recorded
    and warned about, never silently accepted.
    """
    existing = os.environ.get(_RUN_SECRET_ENV)
    if existing:
        return existing, "environment"

    for key in ("run_secret", "nonce_secret"):
        value = manifest.get(key)
        if isinstance(value, str) and value:
            os.environ[_RUN_SECRET_ENV] = value
            return value, f"manifest.json:{key}"

    sidecar = Path(results_dir) / ".run_secret"
    try:
        if sidecar.is_file():
            value = sidecar.read_text(encoding="utf-8").strip()
            if value:
                os.environ[_RUN_SECRET_ENV] = value
                return value, ".run_secret"
    except OSError:
        pass
    return None, "unavailable"


def _persist_minted_secret(results_dir: Path) -> None:
    """Write down the secret ``oracle.nonce`` just minted, so at least every
    later replay of this results directory agrees with this one. It cannot
    retroactively agree with the hunt phase — that mismatch is reported."""
    secret = os.environ.get(_RUN_SECRET_ENV)
    if not secret:
        return
    sidecar = Path(results_dir) / ".run_secret"
    try:
        sidecar.write_text(secret + "\n", encoding="utf-8")
        os.chmod(sidecar, 0o600)
    except OSError:  # pragma: no cover - best effort
        pass


def resolve_image(manifest: dict, override: str | None) -> tuple[str | None, str]:
    """The provisioned image replay starts every container from.

    The trust boundary IS this tag: whatever the hunt agent did inside its own
    container, it could not modify the image. Resolution order puts the
    operator's explicit choice first and never guesses a default — an
    unresolvable image is ``not_attempted``, not a run against `python:slim`
    with none of the target's dependencies in it.
    """
    if override:
        return override, "--image"
    for key in ("image", "image_tag", "target_image"):
        value = manifest.get(key)
        if isinstance(value, str) and value:
            return value, f"manifest.json:{key}"
    provision = manifest.get("provision")
    if isinstance(provision, dict):
        value = provision.get("image_tag") or provision.get("image")
        if isinstance(value, str) and value:
            return value, "manifest.json:provision.image_tag"
    return None, "unresolved"


def resolve_isolation_tier(manifest: dict, override: str | None) -> tuple[str | None, str]:
    """The achieved isolation tier, which the report must state.

    ``None`` is a legitimate answer and is recorded as such: an unknown tier
    printed as "unknown" is honest, whereas defaulting it to `vm` would let a
    `runc` scan claim a boundary it never had.
    """
    if override:
        return override, "--isolation-tier"
    value = manifest.get("isolation_tier")
    if isinstance(value, str) and value:
        return value, "manifest.json"
    try:  # pragma: no cover - depends on sibling module
        import sandbox  # type: ignore
        fn = getattr(sandbox, "detect_tier", None) or getattr(sandbox, "detect", None)
        if callable(fn):
            detected = fn()
            tier = detected.get("tier") if isinstance(detected, dict) else getattr(detected, "tier", None)
            if isinstance(tier, str) and tier:
                return tier, "sandbox.detect"
    except Exception:
        pass
    return None, "unknown"


def _target_roots(manifest: dict, extra: Sequence[str]) -> list[str]:
    """Directories that constitute "the target's own code" for attribution.

    The container root always. The host repo path too, but only when it is
    absolute and deep enough to be meaningful — a root of ``/`` would make every
    stdlib frame look like the target, which is the exact over-attribution the
    gate's ``_is_target_frame`` refuses to guess about.
    """
    roots = [CONTAINER_TARGET_ROOT]
    candidates = list(extra)
    target = manifest.get("target")
    if isinstance(target, str) and target:
        candidates.append(target)
    for candidate in candidates:
        path = str(candidate).strip()
        if not path or path in roots:
            continue
        if os.path.isabs(path) and len([p for p in Path(path).parts if p not in ("/", "\\")]) >= 2:
            roots.append(path)
    return roots


# ─────────────────────────────────────────────────────────────────────────────
# one run
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReplayRun:
    """One container run and the verdict replay's own output earned."""

    index: int
    verdict: ExecutionVerdict
    result: ContainerResult
    canary_touched: bool
    #: Everything found in the canary mount afterwards. A file here whose name
    #: is NOT this run's nonce is the fingerprint of a nonce mismatch.
    canary_entries: list[str] = field(default_factory=list)
    #: Why the run's verdict was overridden after judging, if it was.
    override: str | None = None
    log_dir: str | None = None
    #: Marker lines that did not verify against this run's observer key. Above
    #: zero means something in the container tried to manufacture proof.
    forged_lines: int = 0
    #: `fd3` (the private channel carried the markers), `fallback` (the hook
    #: could not open fd 3 and used stderr) or `silent` (no markers anywhere).
    marker_channel: str = "silent"
    #: Whether the parse actually verified signatures. False means
    #: :mod:`oracle.markers` cannot, and the run is unpromotable.
    markers_verified: bool = False
    #: A fingerprint of the per-container observer key. The key itself is never
    #: recorded — this only has to show that a key existed and that no two
    #: repeats shared one.
    observer_key_id: str = ""
    #: Filenames the run passed to `compile`/`exec`, distrusted for attribution.
    synthesized_filenames: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "verdict": self.verdict.to_dict(),
            "exit_code": self.result.exit_code,
            "timed_out": self.result.timed_out,
            "spawned": self.result.spawned,
            "runner_error": self.result.error,
            "duration_ms": self.result.duration_ms,
            "canary_touched": self.canary_touched,
            "canary_entries": self.canary_entries,
            "verdict_override": self.override,
            "argv": redacted_argv(self.result.argv),
            "log_dir": self.log_dir,
            "forged_marker_lines": self.forged_lines,
            "marker_channel": self.marker_channel,
            "markers_verified": self.markers_verified,
            "observer_key_id": self.observer_key_id,
            "synthesized_filenames": list(self.synthesized_filenames),
            # Verbatim, as captured by replay. This is the record a human
            # re-checks the gate's arithmetic against: `markers` is what the
            # gate judged, `stdout`/`stderr` are what the PoC printed.
            "markers": self.result.markers,
            "stdout": self.result.stdout,
            "stderr": self.result.stderr,
        }


def _stage_run(stage: Path, artifact: PocArtifact, observer_asset: Path, *,
               results_root: Path) -> tuple[Path, Path, Path]:
    """Lay out one run's host-side directories: a read-only payload directory,
    an empty canary directory, and an empty marker channel.

    All three are rebuilt from scratch every repeat. The payload directory being
    fresh means no repeat can be influenced by what the previous one wrote; the
    canary directory being fresh is what makes ``canary_touched`` mean "this run
    created it" rather than "some run once did" — a stale canary would promote a
    *defended* sink, which is precisely the false-exploit failure the release
    gate forbids. The marker channel being fresh means a marker line can only
    ever be attributed to the repeat that produced it.

    ``results_root`` is not decoration: the deletes below are recursive, and
    :func:`_safe_rmtree` proves each target is inside the results directory
    before removing it.
    """
    poc_dir = stage / "poc"
    canary_dir = stage / "canary"
    marks_dir = stage / "marks"
    for directory in (poc_dir, canary_dir, marks_dir):
        if directory.exists():
            _safe_rmtree(directory, inside=results_root)
        directory.mkdir(parents=True, exist_ok=True)
    (poc_dir / artifact.filename).write_text(artifact.code, encoding="utf-8")
    shutil.copyfile(observer_asset, poc_dir / observer_asset.name)
    (poc_dir / LAUNCHER_NAME).write_text(_LAUNCHER_SOURCE, encoding="utf-8")
    return poc_dir, canary_dir, marks_dir


def _container_env(nonce: str, target_root: str, observer_key: str) -> tuple[tuple[str, str], ...]:
    """The container's environment, built from an allowlist.

    Nothing is copied from the host, so no credential can reach a container
    running attacker-crafted input against untrusted code — by construction,
    not by filtering. (The image's own baked-in ``ENV`` still applies inside the
    container; ``-e`` adds to it rather than replacing it. That is the *image's*
    environment, which provisioning built and the hunt agent could not modify,
    so it is inside the trust boundary — but it is why this allowlist is a
    statement about the host, not about everything the process will see.)

    ``PYTHONDONTWRITEBYTECODE`` is not hygiene: the root filesystem is read-only
    and a .pyc write would fail noisily inside the target's own import.

    ``PYHUNT_OBSERVER_KEY`` is Contract A's signing key. It is deliberately NOT
    the nonce: the nonce is handed to the payload and is therefore in the PoC's
    own source, whereas this value exists only between replay and the hook. The
    hook reads it at install time — before any target or PoC code runs — and
    deletes it from ``os.environ``, so by the time the target can look, it is
    gone from the only place a target would look first.
    """
    return (
        ("PYHUNT_NONCE", nonce),
        ("PYHUNT_OBSERVER_KEY", observer_key),
        ("PYTHONPATH", target_root),
        ("PYTHONUNBUFFERED", "1"),
        ("PYTHONDONTWRITEBYTECODE", "1"),
        ("HOME", CONTAINER_WORKDIR),
        ("PATH", "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"),
        # Tells the observer which frames ARE the code under test. Without it,
        # a target that was `pip install`ed — which is how provisioning
        # normally builds the image — lands in site-packages, under
        # `sys.prefix`, and the hook's noise filter discards every one of its
        # frames. Nothing is then attributable and nothing can be proven, and
        # the run still reports success. Not a secret: the target already knows
        # where it lives. The hook pops it from the environment anyway.
        ("PYHUNT_TARGET_ROOT", target_root),
    )


def build_spec(*, image: str, poc_dir: Path, canary_dir: Path, marks_dir: Path,
               artifact: PocArtifact, nonce: str, observer_key: str, run_id: str,
               finding_id: str, index: int, timeout_s: int,
               target_root: str = CONTAINER_TARGET_ROOT) -> ContainerSpec:
    """Describe one replay container.

    Three mounts and no more: the payload read-only (so the PoC cannot rewrite
    the observer that is watching it), the canary directory writable (so its
    contents can be read from the host *after* the container is gone, which is
    what makes the canary evidence rather than another line of text the PoC
    could have printed), and the marker channel writable (the observer has to be
    able to write to fd 3, and replay has to be able to read it afterwards).

    The marker mount is writable and its path is discoverable from inside the
    container, so it is *not* a place only the observer can write. It is not
    meant to be: forgery is defeated by the HMAC on each line, and the private
    descriptor only removes the ambiguity between "the observer said this" and
    "something printed a string that looks like the observer".

    The command is the fd-3 launcher, then the hook, then the PoC — argv the
    hunt agent never touched, built here in Python from the observer asset on
    disk.
    """
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", f"{run_id}-{finding_id}-{index}").strip("-")
    return ContainerSpec(
        image=image,
        command=(
            "python3",
            f"{CONTAINER_PYHUNT_DIR}/{LAUNCHER_NAME}",
            CONTAINER_MARKER_PATH,
            f"{CONTAINER_PYHUNT_DIR}/{OBSERVER_ASSET.name}",
            f"{CONTAINER_PYHUNT_DIR}/{artifact.filename}",
        ),
        binds=(
            (str(poc_dir), CONTAINER_PYHUNT_DIR, "ro"),
            (str(canary_dir), CONTAINER_CANARY_ROOT, "rw"),
            (str(marks_dir), CONTAINER_MARKER_DIR, "rw"),
        ),
        tmpfs=(
            (CONTAINER_WORKDIR, "rw,size=64m,mode=1777"),
            ("/tmp", "rw,size=64m,mode=1777"),
        ),
        env=_container_env(nonce, target_root, observer_key),
        workdir=CONTAINER_WORKDIR,
        labels=(
            ("pyhunt.run_id", run_id),
            ("pyhunt.finding_id", finding_id),
            ("pyhunt.phase", "replay"),
        ),
        network="none",
        name=f"pyhunt-replay-{safe}"[:120],
        timeout_s=timeout_s,
    )


def _toolchain_missing(transcript: str) -> bool:
    return bool(_TOOLCHAIN_MISSING_RX.search(transcript or ""))


def _container_failure(result: ContainerResult) -> str | None:
    """Did *docker* fail, rather than the PoC?

    The armed banner settles it: if the observer printed, the container ran the
    command, whatever happened next. Only in its absence do exit codes and
    daemon error text get a say — and they are read generously, because
    mistaking a broken daemon for a failed exploit is the one error this module
    must never make.

    The banner is looked for across the whole observer channel, not just the
    forwarded streams: with fd 3 open, a perfectly healthy run leaves stderr
    empty.
    """
    if not result.spawned:
        return result.error or "the container runtime could not be launched"
    if MARKER in result.observer_output:
        return None
    if result.exit_code in (125, 126, 127):
        return f"docker exited {result.exit_code} without running the PoC"
    match = _DOCKER_FAILURE_RX.search(result.transcript)
    if match:
        return f"the container did not start: {match.group(0)}"
    return None


def _read_marker_channel(marks_dir: Path) -> str:
    """Read fd 3's landing file from the host, after the container is gone."""
    try:
        return (Path(marks_dir) / MARKER_FILENAME).read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _parse_markers(text: str, observer_key: str | None) -> tuple[list[Any], int, bool]:
    """Parse the observer channel the same way the gate will.

    Deliberate duplication of one line of the gate's work. The gate owns the
    *verdict* and nothing here may pre-empt it; replay owns the *record*, and
    two of the things the record must carry — how many lines failed
    verification, and which filenames the run synthesized — are only knowable
    from the parse. Recomputing them is cheaper than a second return channel out
    of ``judge``, and it cannot influence the verdict because it is never fed
    back in.

    Returns ``(events, forged_lines, signed)``. Falls back to the unverifying
    parser when :mod:`oracle.markers` predates Contract A — in which case
    ``signed`` is False and the caller blocks promotion.
    """
    if observer_key and not markers_contract_gaps():
        parsed: Any = parse_observer_output(text, key=observer_key)
    else:
        parsed = parse_observer_output(text)
    events = list(getattr(parsed, "events", parsed))
    forged = int(getattr(parsed, "forged_lines", 0) or 0)
    signed = bool(getattr(parsed, "signed", False))
    return events, forged, signed


#: Bookkeeping marker kinds through which the observer may report a synthesized
#: filename **directly**, rather than leaving it to be recovered from a repr'd
#: argument tuple. This is the primary channel: the hook truncates long argument
#: reprs, so a `compile` of a large source can lose its filename from the event
#: line while the hook itself still knows it perfectly well.
_OUT_OF_BAND_SYNTHESIS_KINDS = frozenset(
    {"hook-synthesized", "synthesized", "hook-compile", "compile-filename"})

#: `file=`/`filename=`/`path=` inside such a line, or the whole body as a path.
_KEYED_FILE_RX = re.compile(r"\b(?:file|filename|path)=(\S+)")


def _looks_like_filename(value: str) -> bool:
    text = value.strip()
    if not text or len(text) > 512 or "\n" in text:
        return False
    if text.startswith("<") and text.endswith(">"):
        return True  # `<string>`, `<stdin>` — compile's defaults are synthesized too
    return "/" in text or text.endswith((".py", ".pyc", ".pyo"))


def synthesized_filenames(events: Iterable[Any]) -> tuple[str, ...]:
    """Filenames this run passed to ``compile`` or ``exec`` (C-4).

    ``compile(src, "/target/app/reports.py", "exec")`` followed by ``exec``
    produces a **genuine** audit event whose frame names the target — the
    interpreter has no idea the string was chosen rather than read from disk,
    and neither does the hook, because ``co_filename`` is simply whatever was
    passed. An attribution to such a filename cannot support a promotion, so
    Contract B has the gate treat it as `self_attributed`. This also catches the
    sincere case: a PoC that drives the target with ``exec(compile(src,
    target_path, 'exec'))`` because importing it was awkward would otherwise
    earn a pass it never demonstrated.

    Two sources, unioned:

    * the observer's own out-of-band report, which is authoritative because the
      hook sees the arguments before they are truncated for printing;
    * :func:`oracle.gate.synthesized_filenames_from_events`, recovered from the
      event lines themselves.

    The second is the gate's own function rather than a copy of it, deliberately.
    A private reimplementation here would be a second definition of "which
    frames are untrusted", and two definitions of that is how C-1 happened.
    """
    found: set[str] = set()
    for event in events:
        if getattr(event, "kind", "") not in _OUT_OF_BAND_SYNTHESIS_KINDS:
            continue
        text = (getattr(event, "args_text", "") or "").strip()
        keyed = _KEYED_FILE_RX.findall(text)
        for value in keyed:
            found.add(value.strip("'\", "))
        if not keyed and _looks_like_filename(text):
            found.add(text)
    if _gate_synthesized is not None:
        try:
            found |= set(_gate_synthesized(events))
        except Exception:  # pragma: no cover - defensive across a sibling edit
            pass
    return tuple(sorted(f for f in found if f.strip()))


def judge_replay_run(*, observer_output: str, poc_transcript: str, nonce: str,
                     observer_key: str, canary_touched: bool,
                     target_roots: Sequence[str], poc_paths: Sequence[str],
                     vuln_class: str | None, finding_file: str | None,
                     synthesized: Sequence[str]) -> ExecutionVerdict:
    """The single call site of :func:`oracle.gate.judge` in this module.

    ``observer_output`` is only ever produced by
    :attr:`ContainerResult.observer_output` — replay's own capture from its own
    container, marker channel first. ``poc_transcript`` is the PoC's stdout and
    stderr and is used for one thing only: deciding whether the *toolchain* was
    missing. It is never the evidence.

    ``model_claimed_success`` is pinned to ``None`` on purpose: the hunt agent's
    belief about its own PoC is exactly the input this whole module exists to
    remove, so ``contradicts_model`` is meaningless in a proof record and the
    field stays empty rather than carrying a value it should not have.

    Contract B's parameters are passed positional-by-name and only when the gate
    accepts them. A gate that does not is recorded as a promotion blocker by the
    caller, so the missing enforcement can never be mistaken for enforcement
    that passed.
    """
    accepted = _parameters_of(judge)
    kwargs: dict[str, Any] = {
        "nonce": nonce,
        "canary_touched": canary_touched,
        "target_roots": tuple(target_roots),
    }
    # Contract B renames the gate's first parameter to say what it is. Support
    # both spellings so a half-landed tree degrades rather than crashes.
    kwargs["observer_output" if "observer_output" in accepted else "run_output"] = observer_output

    optional: dict[str, Any] = {
        "poc_paths": tuple(poc_paths),
        "vuln_class": vuln_class,
        "execution_available": True,
        "toolchain_missing": _toolchain_missing(poc_transcript),
        "model_claimed_success": None,
        "require_nonce": True,
        "finding_file": finding_file,
        "synthesized_filenames": frozenset(synthesized),
        "observer_key": observer_key,
    }
    for name, value in optional.items():
        if name in accepted:
            kwargs[name] = value
    return judge(**kwargs)


#: Environment variables whose VALUES must never reach a stored artifact. The
#: signing key is the whole of Contract A: a reader who recovers it from a proof
#: record can mint marker lines that verify. The nonce is not secret from the
#: target (see ``oracle/nonce.py``) but there is no reason to write it down
#: either, and the two travel in the same argv.
_SECRET_ENV_NAMES = ("PYHUNT_OBSERVER_KEY", "PYHUNT_NONCE", "PYHUNT_RUN_SECRET")

_SECRET_ASSIGN_RX = re.compile(
    r"^(" + "|".join(_SECRET_ENV_NAMES) + r")=(.*)$", re.S)


def redacted_argv(argv: Sequence[str]) -> list[str]:
    """The container command with its secret env assignments blanked.

    ``ProofRecord`` records ``observer_key_id`` as a truncated hash precisely so
    the key itself is never written down — and then the full ``docker run``
    argv, which carries ``--env PYHUNT_OBSERVER_KEY=<key>``, was stored verbatim
    beside it in ``proof/<id>.json`` and written to ``logs/.../command.txt``.
    The comment claiming the key is not recorded sat directly above the line
    recording it.

    The argv is still worth keeping: it is how a human re-runs the container by
    hand and checks the gate's arithmetic. So the shape is preserved and only
    the values go, which also leaves the artifact honest about the fact that a
    key was passed at all.
    """
    out: list[str] = []
    for token in argv:
        match = _SECRET_ASSIGN_RX.match(token)
        out.append(f"{match.group(1)}=<redacted>" if match else token)
    return out


def _write_run_logs(log_dir: Path, run: ReplayRun) -> None:
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "stdout.txt").write_text(run.result.stdout, encoding="utf-8")
        (log_dir / "stderr.txt").write_text(run.result.stderr, encoding="utf-8")
        (log_dir / "markers.txt").write_text(run.result.markers, encoding="utf-8")
        (log_dir / "command.txt").write_text(
            " ".join(redacted_argv(run.result.argv)) + "\n", encoding="utf-8")
        (log_dir / "verdict.json").write_text(
            json.dumps(run.verdict.to_dict(), indent=2), encoding="utf-8")
    except OSError as exc:  # pragma: no cover - best effort
        _note(f"could not write replay logs to {log_dir}: {exc}")


def _observer_key_id(observer_key: str) -> str:
    """A short, non-reversing label for a key that is never written down."""
    return hashlib.sha256(observer_key.encode("utf-8")).hexdigest()[:12]


def replay_once(*, runner: ContainerRunner, artifact: PocArtifact, image: str,
                nonce: str, run_id: str, finding_id: str, index: int,
                stage: Path, observer_asset: Path, timeout_s: int,
                target_roots: Sequence[str], vuln_class: str | None,
                results_root: Path, finding_file: str | None = None,
                target_root: str = CONTAINER_TARGET_ROOT) -> ReplayRun:
    """One fresh container, one verdict.

    Fresh means fresh: a new container from the unmodified image, a new payload
    directory, a new empty canary directory, a new empty marker channel, and a
    **new observer key**. Nothing from the previous repeat — and nothing from
    the hunt agent's container — is reachable from here. The key being per
    container rather than per finding means a key recovered from one repeat's
    process memory cannot forge the next repeat, so 3-of-3 unanimity survives a
    partial compromise it would otherwise fold to.
    """
    poc_dir, canary_dir, marks_dir = _stage_run(
        stage, artifact, observer_asset, results_root=results_root)
    observer_key = secrets.token_hex(16)
    spec = build_spec(image=image, poc_dir=poc_dir, canary_dir=canary_dir,
                      marks_dir=marks_dir, artifact=artifact, nonce=nonce,
                      observer_key=observer_key, run_id=run_id,
                      finding_id=finding_id, index=index, timeout_s=timeout_s,
                      target_root=target_root)
    result = runner.run(spec)
    # The observer's own channel, read from the HOST once the container is gone.
    result = replace(result, markers=_read_marker_channel(marks_dir))

    # Read the canary from the HOST too, for the same reason. A file that exists
    # here was really created by something inside the container; it is not a
    # string the PoC printed.
    try:
        entries = sorted(p.name for p in canary_dir.iterdir())
    except OSError:
        entries = []
    canary_touched = os.path.basename(canary_path(nonce)) in entries

    events, forged_lines, markers_verified = _parse_markers(
        result.observer_output, observer_key)
    synthesized = synthesized_filenames(events)
    if result.markers.strip():
        channel = "fd3"
    elif MARKER in result.transcript:
        channel = "fallback"
    else:
        channel = "silent"

    failure = _container_failure(result)
    if failure:
        verdict = ExecutionVerdict(
            outcome=Outcome.NOT_ATTEMPTED,
            reason=(
                f"replay {index}: {failure}. An environment that could not run "
                "the PoC has said nothing about the vulnerability — this is not "
                "a failed exploit and it does not weaken the finding."
            ),
            nonce=nonce,
        )
        override = "container-failure"
    else:
        verdict = judge_replay_run(
            observer_output=result.observer_output,
            poc_transcript=result.transcript,
            nonce=nonce, observer_key=observer_key,
            canary_touched=canary_touched, target_roots=target_roots,
            poc_paths=[f"{CONTAINER_PYHUNT_DIR}/{artifact.filename}",
                       str(poc_dir / artifact.filename)],
            vuln_class=vuln_class, finding_file=finding_file,
            synthesized=synthesized,
        )
        override = None
        if result.timed_out and verdict.outcome is not Outcome.PROVEN:
            # Evidence already captured is still evidence, so a timed-out run
            # that PROVED something keeps its verdict. Silence from a killed
            # container is not evidence of anything, so it does not get to be
            # `no_event`.
            verdict = ExecutionVerdict(
                outcome=Outcome.NOT_ATTEMPTED,
                reason=(
                    f"replay {index} was killed at the {timeout_s}s ceiling "
                    f"before it demonstrated anything (the gate had said: "
                    f"{verdict.outcome.value}). A truncated run's silence is not "
                    "evidence about the code."
                ),
                evidence=verdict.evidence,
                events_seen=verdict.events_seen,
                observer_armed=verdict.observer_armed,
                nonce=nonce,
            )
            override = "timeout"

    run = ReplayRun(index=index, verdict=verdict, result=result,
                    canary_touched=canary_touched, canary_entries=entries,
                    override=override, log_dir=str(stage),
                    forged_lines=forged_lines, marker_channel=channel,
                    markers_verified=markers_verified,
                    observer_key_id=_observer_key_id(observer_key),
                    synthesized_filenames=list(synthesized))
    _write_run_logs(stage, run)
    return run


# ─────────────────────────────────────────────────────────────────────────────
# aggregation — 3 of 3 or nothing
# ─────────────────────────────────────────────────────────────────────────────

def aggregate(runs: Sequence[ReplayRun], repeats: int,
              promotion_blocked: Sequence[str] = ()) -> tuple[Outcome, str, bool]:
    """Fold per-run verdicts into one, promoting only on unanimity.

    Anthropic's harness gates on "reproduces 3/3" and the reason is worth
    restating: an exploit that fires twice in three tries has an unexplained
    variable in it, and an unexplained variable in a *proof* is a defect in the
    proof. So promotion needs every run to agree.

    When they do not agree the aggregate is the **least-claiming** verdict any
    run produced — not the majority, and not the best one. Two `proven` runs and
    one `no_event` record as `no_event`, with the tally in the reason and the
    individual verdicts kept in the record, so the disagreement is a visible
    fact rather than an averaged-away one. Nothing here demotes the finding:
    every non-`proven` outcome leaves it exactly as the static analysis left it.

    ``promotion_blocked`` is the structural refusal M-3 asks for. Each entry is
    a reason this *run configuration* was never eligible to promote — too few
    repeats, a waived isolation floor, a gate that cannot enforce Contract B.
    Blockers are applied at exactly one point: the branch that would have
    returned `proven`. They never touch any other outcome, because a blocked run
    that recorded `sink_reached_unproven` observed something real and
    overwriting that with an environment outcome would be its own kind of lie.
    """
    if not runs:
        return (Outcome.NOT_ATTEMPTED,
                "no replay ran, so nothing was established either way", False)

    outcomes = [r.verdict.outcome for r in runs]
    tally: dict[str, int] = {}
    for outcome in outcomes:
        tally[outcome.value] = tally.get(outcome.value, 0) + 1
    tally_text = ", ".join(f"{k}×{v}" for k, v in sorted(tally.items()))

    unanimous = len(set(outcomes)) == 1 and len(runs) == repeats
    blocked = [str(b) for b in promotion_blocked if str(b).strip()]

    if unanimous and outcomes[0] is Outcome.PROVEN:
        if blocked:
            return (Outcome.NOT_ATTEMPTED,
                    f"{len(runs)} of {repeats} fresh containers each produced a "
                    f"proving verdict, but this run was never eligible to promote: "
                    + "; ".join(blocked) +
                    ". The per-run verdicts are kept in `runs` and nothing was "
                    "discarded; re-run under the promotion rules to settle it. A "
                    "blocked promotion is not a weakened finding.",
                    False)
        return (Outcome.PROVEN,
                f"{repeats} of {repeats} fresh containers independently proved this "
                f"finding. {runs[0].verdict.reason}",
                True)

    weakest = min(outcomes, key=lambda o: _CLAIM_STRENGTH[o])

    if weakest is Outcome.PROVEN:
        # Every run that finished proved it — but fewer of them finished than
        # were asked for, so "3 of 3" was never established. The missing runs
        # are missing evidence, not tacit agreement, and the honest verdict is
        # that the environment did not deliver the reproduction the promotion
        # rule requires.
        return (Outcome.NOT_ATTEMPTED,
                f"only {len(runs)} of the {repeats} requested replays ran, and "
                f"promotion requires every one of them to prove the finding "
                f"independently. The {len(runs)} that did run all proved it — "
                f"their verdicts are in `runs` — but an incomplete set is not "
                f"unanimity, and this does not weaken the finding.",
                False)

    if unanimous:
        return (weakest,
                f"{repeats} of {repeats} replays agreed: {weakest.value}. "
                f"{runs[0].verdict.reason}",
                True)

    if Outcome.PROVEN in outcomes:
        proven_count = tally.get(Outcome.PROVEN.value, 0)
        return (weakest,
                f"replays disagreed ({tally_text} across {len(runs)} of {repeats} "
                f"runs): {proven_count} proved the finding and the rest did not. A "
                f"proof that does not reproduce every time is not a proof, so this "
                f"records the weakest verdict any run produced ({weakest.value}). "
                f"The per-run verdicts are kept in `runs` — nothing was averaged "
                f"away, and the finding is not weakened by this.",
                False)

    return (weakest,
            f"replays disagreed ({tally_text} across {len(runs)} of {repeats} runs) "
            f"and none proved the finding; the weakest verdict any run produced "
            f"({weakest.value}) is what this records.",
            False)


# ─────────────────────────────────────────────────────────────────────────────
# the proof record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProofRecord:
    """What ``proof/<finding_id>.json`` contains: the whole audit trail.

    Everything needed to re-check the verdict by hand is here — the image and
    its digest, the nonce, the isolation tier, who built the container flags,
    and every run's transcript verbatim.
    """

    finding_id: str
    run_id: str
    outcome: Outcome
    reason: str
    repeats: int
    unanimous: bool
    nonce: str | None = None
    nonce_key: str | None = None
    nonce_key_source: str = "unknown"
    run_secret_source: str = "unavailable"
    vuln_class: str | None = None
    image: str | None = None
    image_source: str = "unresolved"
    image_digest: str | None = None
    isolation_tier: str | None = None
    isolation_tier_source: str = "unknown"
    container_flags_source: str = "unknown"
    target_roots: list[str] = field(default_factory=list)
    canary_path: str | None = None
    #: The finding's own file, handed to the gate as Contract B's locality
    #: constraint. Recorded because "which file did this proof have to be in?"
    #: is not answerable from the verdict alone.
    finding_file: str | None = None
    #: Every reason this record was structurally incapable of saying `proven`.
    #: Empty in a normal run. Non-empty is not an error — it is the audit trail
    #: for a promotion that was refused rather than lost.
    promotion_blocked: list[str] = field(default_factory=list)
    runs: list[ReplayRun] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def proven(self) -> bool:
        return self.outcome is Outcome.PROVEN

    @property
    def forged_marker_lines(self) -> int:
        """Marker lines that failed signature verification, across every repeat.

        Above zero means something inside a container wrote a well-formed
        observer line it could not sign. That is the most interesting event a
        run can produce and it must never be dropped quietly, so it is a
        first-class field of the record and a note on it.
        """
        return sum(run.forged_lines for run in self.runs)

    def to_dict(self) -> dict:
        tally: dict[str, int] = {}
        for run in self.runs:
            key = run.verdict.outcome.value
            tally[key] = tally.get(key, 0) + 1
        synthesized = sorted({name for run in self.runs
                              for name in run.synthesized_filenames})
        return {
            "schema": "pyhunt.proof/1",
            "finding_id": self.finding_id,
            "run_id": self.run_id,
            "outcome": self.outcome.value,
            "proven": self.proven,
            "reason": self.reason,
            "repeats_requested": self.repeats,
            "repeats_completed": len(self.runs),
            "repeat_floor": PROMOTION_REPEAT_FLOOR,
            "unanimous": self.unanimous,
            "verdict_counts": tally,
            # M-3's audit trail. `promotion_blocked` is empty in a run that
            # played by the rules, so `grep -l '"promotion_blocked": \[$'` finds
            # every run that did not — which a warning on stderr never would.
            "promotion_blocked": list(self.promotion_blocked),
            "promotion_eligible": not self.promotion_blocked,
            # Contract A's counter-forgery record.
            "forged_marker_lines": self.forged_marker_lines,
            "marker_channels": [run.marker_channel for run in self.runs],
            "markers_verified": all(run.markers_verified for run in self.runs)
                                and bool(self.runs),
            "observer_key_ids": [run.observer_key_id for run in self.runs],
            # Contract B's inputs, recorded so the verdict can be re-derived.
            "finding_file": self.finding_file,
            "synthesized_filenames": synthesized,
            "nonce": self.nonce,
            "nonce_key": self.nonce_key,
            "nonce_key_source": self.nonce_key_source,
            "run_secret_source": self.run_secret_source,
            "vuln_class": self.vuln_class,
            "image": self.image,
            "image_source": self.image_source,
            "image_digest": self.image_digest,
            "isolation_tier": self.isolation_tier,
            "isolation_tier_source": self.isolation_tier_source,
            "container_flags_source": self.container_flags_source,
            "target_roots": self.target_roots,
            "canary_path": self.canary_path,
            # Provenance of the gate's input, stated in the artifact so a reader
            # never has to take it on faith: the verdict was computed from
            # replay's own capture, and the hunt agent's transcript was not read.
            "gate_input": "replay-captured-output",
            "agent_transcript_used": False,
            "agent_claim_used": False,
            "runs": [run.to_dict() for run in self.runs],
            "notes": self.notes,
            "generated_at": self.generated_at,
        }


def write_proof(results_dir: Path, record: ProofRecord) -> Path:
    # Re-validated rather than trusted: this is a write, the id is the filename,
    # and `write_proof` is public enough to be called with a record built
    # somewhere else.
    finding_id = validate_finding_id(record.finding_id)
    out_dir = Path(results_dir) / "proof"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{finding_id}.json"
    path.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# the entry point
# ─────────────────────────────────────────────────────────────────────────────

def replay_finding(
    *,
    results_dir: Path | str,
    finding_id: str,
    repeats: int = DEFAULT_REPEATS,
    runner: ContainerRunner | None = None,
    image: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    extra_target_roots: Sequence[str] = (),
    nonce_key: str | None = None,
    isolation_tier: str | None = None,
    observer_asset: Path | None = None,
    require_tier: bool = True,
) -> ProofRecord:
    """Replay one finding's PoC and return the proof record.

    The short-circuits come first and each is its own outcome, because each says
    something different and none of them is "the exploit failed":

    * an undecidable class → ``not_applicable`` (execution could never settle it)
    * no PoC, or a PoC in a language the observer cannot watch → ``not_attempted``
    * no image, no container runtime, a refused isolation tier, a static-mode
      run → ``not_attempted``

    Only then do containers start.

    Separately from the short-circuits, the run may be **ineligible to
    promote**: fewer repeats than :data:`PROMOTION_REPEAT_FLOOR`, a waived
    isolation floor, or a sibling module that cannot enforce Contract A/B. Those
    do not stop anything from running and they never overwrite an observation —
    they only close the one branch that returns ``proven``, and each is written
    into ``promotion_blocked`` so the refusal is legible in the artifact months
    later.
    """
    # Order is the whole point of M-4: the id is validated BEFORE it is joined
    # to anything. `--finding-id ../../../../tmp/evil` used to reach a findings
    # read, a recursive delete of the staging directory, and a proof write.
    finding_id = validate_finding_id(finding_id)
    results_dir = Path(results_dir)
    if repeats < 1:
        raise ReplayContractError("--repeats must be at least 1")

    manifest = load_manifest(results_dir)
    run_id = str(manifest.get("run_id") or results_dir.name)
    artifact, ref, missing_reason = load_poc(results_dir, finding_id)

    # ── Everything that makes this run ineligible to promote (M-3, and the
    #    seam checks). Collected before any container starts so the refusal is
    #    a property of the record, not of a branch somewhere in the middle.
    blockers: list[str] = []
    if repeats < PROMOTION_REPEAT_FLOOR:
        blockers.append(
            f"--repeats was {repeats}, below the floor of {PROMOTION_REPEAT_FLOOR} "
            "independent reproductions promotion requires (D-6). The runs still "
            "happened and their verdicts are recorded; the promotion rule was "
            "simply never applied"
        )
    if not require_tier:
        blockers.append(
            "the `vm` isolation floor was waived (--allow-any-tier). A proof "
            "obtained below the boundary PLAN §4 requires is a development "
            "convenience, and it does not promote"
        )
    gate_gaps = gate_contract_gaps()
    if gate_gaps:
        blockers.append(
            "oracle.gate.judge does not accept " + ", ".join(gate_gaps) +
            ", so locality, synthesized-frame distrust and signature "
            "verification (Contract B) could not be enforced on this run"
        )
    marker_gaps = markers_contract_gaps()
    if marker_gaps:
        blockers.append(
            "oracle.markers.parse_observer_output cannot verify observer "
            "signatures (Contract A), so a forged marker line is "
            "indistinguishable from an authentic one"
        )

    secret, secret_source = resolve_run_secret(results_dir, manifest)
    notes: list[str] = [f"promotion blocked: {b}" for b in blockers]
    if secret is None:
        notes.append(
            "PYHUNT_RUN_SECRET was not available from the environment, "
            "manifest.json or .run_secret, so the nonce is derived from a "
            "freshly minted secret and will NOT match the one the payload was "
            "authored with. A real proof can degrade to sink_reached_unproven "
            "because of this; it can never be promoted by it."
        )

    key, key_source = _nonce_key(nonce_key, ref)
    nonce = nonce_for(run_id, key)
    if secret is None:
        _persist_minted_secret(results_dir)

    tier, tier_source = resolve_isolation_tier(manifest, isolation_tier)
    image_ref, image_source = resolve_image(manifest, image)
    roots = _target_roots(manifest, extra_target_roots)

    def record(outcome: Outcome, reason: str, *, runs: Sequence[ReplayRun] = (),
               unanimous: bool = False, digest: str | None = None,
               flags_source: str = "n/a") -> ProofRecord:
        return ProofRecord(
            finding_id=finding_id, run_id=run_id, outcome=outcome, reason=reason,
            repeats=repeats, unanimous=unanimous, nonce=nonce, nonce_key=key,
            nonce_key_source=key_source, run_secret_source=secret_source,
            vuln_class=ref.vuln_class, image=image_ref, image_source=image_source,
            image_digest=digest, isolation_tier=tier,
            isolation_tier_source=tier_source, container_flags_source=flags_source,
            target_roots=roots, canary_path=canary_path(nonce),
            finding_file=ref.file, promotion_blocked=list(blockers),
            runs=list(runs), notes=list(notes),
        )

    # 1. Classes execution cannot settle. Checked here rather than inside the
    #    gate so no container starts for a question a container cannot answer.
    undecidable = is_undecidable(ref.vuln_class)
    if undecidable:
        return record(Outcome.NOT_APPLICABLE, undecidable)

    # 2. Nothing to run.
    if artifact is None:
        return record(Outcome.NOT_ATTEMPTED, missing_reason or "no PoC to replay")
    if artifact.language.strip().lower() not in ("python", "python3", "py"):
        return record(
            Outcome.NOT_ATTEMPTED,
            f"the PoC declares language {artifact.language!r}; PyHunt observes "
            "Python only (D-5), so this PoC cannot be replayed under the audit "
            "hook. That is a limit of the harness, not a fact about the finding.",
        )

    asset = Path(observer_asset) if observer_asset else OBSERVER_ASSET
    if not asset.is_file():
        return record(
            Outcome.NOT_ATTEMPTED,
            f"the observer asset {asset} is missing, so no run could be armed",
        )

    # 3. The sandbox has to be up, and at a tier where proof is permitted.
    mode = str(manifest.get("mode") or "").strip().lower()
    if mode in ("static", "static-only", "static_only"):
        return record(
            Outcome.NOT_ATTEMPTED,
            "this run is in static mode, so no PoC is executed and no finding "
            "here is confirmed or refuted by execution",
        )
    if require_tier and tier and tier.strip().lower() in PROOF_REFUSED_TIERS:
        return record(
            Outcome.NOT_ATTEMPTED,
            f"isolation tier {tier!r} is below the `vm` floor Proof mode "
            "requires (PLAN §4), so the PoC was not executed. Refusing is the "
            "honest outcome; silently downgrading the boundary is not.",
        )
    if image_ref is None:
        return record(
            Outcome.NOT_ATTEMPTED,
            "no provisioned image is recorded for this run, and replay will not "
            "guess one — a container without the target's dependencies proves "
            "only that a hello-world ran",
        )

    active_runner = runner if runner is not None else DockerRunner()
    ok, detail = active_runner.available()
    flags_source = getattr(active_runner, "argv_source", "injected-runner")
    if not ok:
        return record(
            Outcome.NOT_ATTEMPTED,
            f"the container runtime is not usable ({detail}), so the PoC was "
            "never executed. A missing toolchain is an environment limitation, "
            "never a verdict on the code.",
            flags_source=flags_source,
        )

    digest = active_runner.image_digest(image_ref)
    if digest is None:
        notes.append(
            f"the digest of image {image_ref!r} could not be read, so the proof "
            "record cannot name exactly which image bytes were run"
        )

    # 4. A cheap tell for the nonce problem above: 16-hex tokens in the PoC that
    #    are not this nonce are usually the hunt-time nonce, which means the
    #    payload's canary and this replay's canary are different files.
    foreign = sorted(set(re.findall(r"\b[0-9a-f]{16}\b", artifact.code)) - {nonce})
    if foreign:
        notes.append(
            "the PoC embeds 16-hex token(s) that are not this replay's nonce "
            f"({', '.join(foreign[:3])}): if those are hunt-time nonces, the "
            "payload's canary path differs from the one replay watches and a "
            "genuine proof may read as sink_reached_unproven"
        )

    # 5. Three fresh containers.
    log_root = results_dir / "logs" / "replay" / finding_id
    runs: list[ReplayRun] = []
    for index in range(1, repeats + 1):
        runs.append(replay_once(
            runner=active_runner, artifact=artifact, image=image_ref, nonce=nonce,
            run_id=run_id, finding_id=finding_id, index=index,
            stage=log_root / f"run-{index}", observer_asset=asset,
            timeout_s=timeout_s, target_roots=roots, vuln_class=ref.vuln_class,
            results_root=results_dir, finding_file=ref.file,
        ))
        _note(f"replay {index}/{repeats}: {runs[-1].verdict.outcome.value}")

    forged = sum(run.forged_lines for run in runs)
    if forged:
        notes.append(
            f"{forged} marker line(s) across {len(runs)} run(s) carried the "
            "observer prefix but no valid signature. Something inside the "
            "container tried to manufacture proof — the lines were discarded "
            "before the gate saw them, and they are counted here because a "
            "forgery attempt is a finding in its own right about this target"
        )
    outcome, reason, unanimous = aggregate(runs, repeats, promotion_blocked=blockers)
    return record(outcome, reason, runs=runs, unanimous=unanimous, digest=digest,
                  flags_source=flags_source)


def _nonce_key(explicit: str | None, ref: FindingRef) -> tuple[str, str]:
    """Which key the nonce is derived from.

    It must be the key the PAYLOAD was authored with, and `poc_runtime` mints
    payload nonces per **task** (a task's nonce exists before any finding does).
    So the task id wins, the finding id is the fallback, and whichever was used
    is recorded — a proof whose nonce came from the wrong key is a proof whose
    attribution silently weakened, and that has to be visible.
    """
    if explicit:
        return explicit, "--nonce-key"
    if ref.task_id:
        return ref.task_id, "finding.task_id"
    return ref.finding_id, "finding_id (no task_id recorded — payload nonces are keyed on the TASK, so this may not match)"


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _note(message: str) -> None:
    """Human-readable progress. Never stdout — stdout is the JSON contract."""
    print(f"[replay] {message}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="replay.py",
        description=("Re-run a finding's PoC in fresh containers built from the "
                     "unmodified provisioned image and gate on replay's own output."),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="replay one finding's PoC")
    run.add_argument("--results-dir", required=True,
                     help="the *_PYHUNT_RESULTS_* directory holding findings/ and manifest.json")
    run.add_argument("--finding-id", required=True,
                     help=f"must match {_FINDING_ID_RX.pattern} (finding.schema.json)")
    run.add_argument("--repeats", type=int, default=DEFAULT_REPEATS,
                     help=(f"fresh containers to run; promotion needs unanimity "
                           f"(default {DEFAULT_REPEATS}). Fewer than "
                           f"{PROMOTION_REPEAT_FLOOR} still runs, but the result "
                           f"is recorded as ineligible to promote"))
    run.add_argument("--image", default=None,
                     help="override the provisioned image the containers start from")
    run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S,
                     help=f"per-run wall clock in seconds (default {DEFAULT_TIMEOUT_S})")
    run.add_argument("--target-root", action="append", default=[],
                     help="extra directory that counts as the target's own code (repeatable)")
    run.add_argument("--nonce-key", default=None,
                     help="key the nonce is derived from; defaults to the finding's task_id")
    run.add_argument("--isolation-tier", default=None,
                     help="tier phase 0 verified, when manifest.json does not record it")
    run.add_argument("--allow-any-tier", action="store_true",
                     help=("do not refuse below the `vm` isolation floor (dev "
                           "only). The run then CANNOT return `proven`, and the "
                           "proof record says so in `promotion_blocked`"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    if args.command != "run":  # pragma: no cover - argparse enforces this
        return 2

    results_dir = Path(args.results_dir)
    try:
        record = replay_finding(
            results_dir=results_dir,
            finding_id=args.finding_id,
            repeats=args.repeats,
            image=args.image,
            timeout_s=args.timeout,
            extra_target_roots=args.target_root,
            nonce_key=args.nonce_key,
            isolation_tier=args.isolation_tier,
            require_tier=not args.allow_any_tier,
        )
    except ReplayContractError as exc:
        print(json.dumps({"error": str(exc), "finding_id": args.finding_id}), flush=True)
        _note(f"contract violation: {exc}")
        return 2
    except Exception as exc:  # pragma: no cover - defensive
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}",
                          "finding_id": args.finding_id}), flush=True)
        _note(f"internal error: {type(exc).__name__}: {exc}")
        return 1

    try:
        path = write_proof(results_dir, record)
        _note(f"wrote {path}")
    except OSError as exc:
        print(json.dumps({"error": f"could not write the proof record: {exc}",
                          "finding_id": args.finding_id}), flush=True)
        _note(f"internal error writing the proof record: {exc}")
        return 1

    for note in record.notes:
        _note(f"note: {note}")
    if record.forged_marker_lines:
        _note(f"FORGERY: {record.forged_marker_lines} unsigned marker line(s) "
              "were discarded — see `forged_marker_lines` in the proof record")
    _note(f"{record.finding_id}: {record.outcome.value} "
          f"({'unanimous' if record.unanimous else 'not unanimous'}, "
          f"{len(record.runs)}/{record.repeats} runs"
          f"{', PROMOTION BLOCKED' if record.promotion_blocked else ''})")
    print(json.dumps(record.to_dict(), indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
