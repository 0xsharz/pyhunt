"""Tiered isolation: detect it, create it, and then *prove* it.

This file used to answer one question — "am I allowed to execute target code?"
— by looking for `VASH_SANDBOX=1` or `/.dockerenv`. Its own docstring called
that "a tripwire, not a full isolation audit", and that was accurate: it decided
PERMISSION and never created CONTAINMENT. Containment came from the operator
remembering to run a wrapper script, and nothing stopped a PoC inside that
container from reaching the internet or reading an API key out of its own
environment.

The permission gate is still here, unchanged, because it is the right answer to
the question it asks (:class:`SandboxError`, :func:`is_sandboxed`,
:func:`require`, :func:`resolve_execution`). Everything else in this module is
the half that was missing.

Four subcommands, in the order Phase 0 runs them:

``detect``
    What boundary does THIS host actually have? Reported as a tier, derived from
    `docker version` / `docker info` and the platform — never assumed, never
    hardcoded. gVisor is a Linux syscall interceptor; on Darwin it cannot exist,
    but Docker Desktop's Linux VM is a *separate kernel*, which is a stronger
    boundary than gVisor's same-kernel interception. So "no gVisor" must not be
    reported as "no isolation" — that is a lie that costs the operator Proof
    mode for no security gain. The tier table lives in :data:`TIER_NOTES`.

``up``
    Create it: the `pyhunt-internal` network (``internal: true`` — no route off
    the box), the egress allowlist proxy that is the single controlled hole in
    it, and the provisioned target image. Idempotent, and it reaps orphans from
    previous runs on the way in.

``verify``
    **The honest half, and the reason this file exists.** Everything above is a
    claim about flags. This launches a throwaway container on the sandbox
    network and makes it *assert*, from the inside, that it cannot reach the
    internet, cannot see the host filesystem, carries no credential-shaped
    environment variable, and really does have a read-only rootfs. Any assertion
    that fails — or that could not be run at all — is a failure and exits 2, so
    the skill refuses Proof mode instead of downgrading to it quietly. Absence
    of evidence is not evidence of isolation.

``down``
    Tear this run down, and reap what previous runs left behind. Every container
    and network PyHunt creates carries a ``pyhunt.run_id`` label, so a run that
    was SIGKILLed — which never gets to run its own cleanup — is still
    recoverable by the next one.

**One argv builder.** :func:`container_argv` is the only place a `docker run`
command is constructed. `--read-only`, `--cap-drop ALL`,
`--security-opt no-new-privileges`, the memory/pid caps, the label and the
credential-stripped environment are not parameters — they are unconditional, so
a future edit cannot harden one call site and miss another. The network is
validated against an allowlist of two values (`none` and `pyhunt-internal`), so
no caller can quietly ask for `host`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

log = logging.getLogger(__name__)


# ===========================================================================
# Part 1 — the permission gate (unchanged behaviour; other modules import it)
# ===========================================================================

# Coarse "we are inside *some* container" marker — present on essentially every
# Docker (and Docker-derived) container filesystem. Not a security boundary by
# itself, just a signal. Module-level (rather than inlined) so tests can
# monkeypatch it to a guaranteed-absent path for a hermetic "definitely no
# sandbox" case, independent of the machine actually running the test suite.
_DOCKERENV = Path("/.dockerenv")

# Values that mean "the sandbox env var is set but not truthy".
_FALSY_ENV = ("", "0", "false", "False")

# Both names are honoured: `VASH_SANDBOX` is baked into images the provisioning
# code already builds (see provision/scan_image.py), and dropping it would
# silently un-sandbox every one of them.
_SANDBOX_ENV_VARS = ("PYHUNT_SANDBOX", "VASH_SANDBOX")

_REMEDY = (
    "target-code execution requires an active sandbox: set VASH_SANDBOX=1 "
    "(or PYHUNT_SANDBOX=1) inside a container-isolated environment before "
    "running with execution enabled, or pass --dangerously-no-sandbox for "
    "local dev (unsafe — only ever against source you already trust)."
)


class SandboxError(RuntimeError):
    """Raised when target-code execution was requested but no active sandbox was
    detected and no dev escape was granted — and by the argv builder when a
    caller asks for a container configuration the isolation contract forbids."""


def is_sandboxed() -> bool:
    """True if PyHunt appears to be running inside an isolation sandbox.

    Signal (intentionally simple — a tripwire, not a full isolation audit):
      * ``PYHUNT_SANDBOX`` / ``VASH_SANDBOX`` is truthy — set by the container
        wrapper that launches an execution-enabled run, or
      * ``/.dockerenv`` exists — a coarse "inside some container" marker.

    For the question "is the isolation I *think* I have actually there?", this
    function is the wrong tool: use :func:`verify_isolation`, which asserts it
    from inside a container instead of inferring it from a marker file.
    """
    for name in _SANDBOX_ENV_VARS:
        if os.environ.get(name, "") not in _FALSY_ENV:
            return True
    return _DOCKERENV.exists()


def resolve_execution(*, dynamic_validation: bool, allow_no_sandbox: bool = False) -> bool:
    """Resolve whether target-code execution is enabled for a run, enforcing the
    sandbox precondition. Returns True (dynamic) / False (static-only). Raises
    SandboxError if dynamic validation was requested but no sandbox (and no dev
    escape) is available — callers must fail fast rather than silently downgrade."""
    if not dynamic_validation:
        return False
    require(allow_no_sandbox=allow_no_sandbox)
    return True


def require(*, allow_no_sandbox: bool = False) -> None:
    """Gate that target-code execution MUST pass BEFORE running anything from
    the target repo. Decides PERMISSION only — never executes target code.

      * ``allow_no_sandbox=True`` (the ``--dangerously-no-sandbox`` dev escape)
        — log a LOUD warning and return; execution is permitted, unguarded.
      * Else if :func:`is_sandboxed`: return; execution is permitted.
      * Else: raise :class:`SandboxError` with a clear remedy.
    """
    if allow_no_sandbox:
        log.warning(
            "[sandbox] --dangerously-no-sandbox: proceeding WITHOUT an active "
            "isolation sandbox. Target-controlled code may execute unconfined "
            "on this host. Dev-only escape — never use this against a target "
            "you do not already trust."
        )
        return
    if is_sandboxed():
        return
    raise SandboxError(_REMEDY)


# ===========================================================================
# Part 2 — constants: the isolation contract, in one place
# ===========================================================================

DOCKER_BINARY = os.environ.get("PYHUNT_DOCKER_BINARY", "docker")

TIER_GVISOR = "gvisor"
TIER_VM = "vm"
TIER_RUNC = "runc"
TIER_NONE = "none"

# Ordered weakest -> strongest, so a caller can compare tiers without a table.
TIER_ORDER: tuple[str, ...] = (TIER_NONE, TIER_RUNC, TIER_VM, TIER_GVISOR)

# The tiers at which executing target code is permitted. `runc` is namespaces
# only: a container escape lands on the operator's own kernel, which is not a
# boundary worth betting a PoC on. `none` has nothing at all.
PROOF_TIERS: frozenset[str] = frozenset({TIER_GVISOR, TIER_VM})

TIER_NOTES: dict[str, str] = {
    TIER_GVISOR: "gVisor (runsc): the container's syscalls are interpreted by a "
                 "user-space kernel, so the host kernel is never entered directly",
    TIER_VM: "Docker Desktop-class engine: the container runs under a SEPARATE "
             "kernel inside a virtual machine, so an escape lands in the VM, not "
             "on the operator's host. gVisor is unavailable here and does not "
             "need to be — this boundary is at least as strong",
    TIER_RUNC: "plain runc on the host kernel: namespaces and cgroups only. A "
               "container escape lands directly on the operator's kernel, so "
               "Proof mode is REFUSED at this tier",
    TIER_NONE: "no usable container engine — nothing can be isolated, so the run "
               "is static-only",
}

# Substrings in `docker info`'s OperatingSystem / Name that mean the daemon is
# running inside a VM the vendor manages. These are the products, not a guess at
# the host OS — `docker info` is asked, and the platform only corroborates.
_VM_ENGINE_MARKERS = (
    "docker desktop",
    "docker for mac",
    "docker for windows",
    "rancher desktop",
    "orbstack",
    "colima",
    "lima",
    "linuxkit",
    "podman machine",
)

# The gVisor runtime as Docker reports it. Docker keys runtimes by name, and the
# containerd shim form (`io.containerd.runsc.v1`) is equally valid, so the check
# is a substring over both the key and its `path`.
_GVISOR_MARKERS = ("runsc",)

SANDBOX_NETWORK = "pyhunt-internal"
# The routed network the proxy — and ONLY the proxy — is also attached to.
EGRESS_NETWORK = os.environ.get("PYHUNT_EGRESS_NETWORK", "bridge")

# The only two networks a PyHunt container may ever be started on. `none` is for
# anything running target code; `pyhunt-internal` is for the harness's own
# containers, which reach the outside world exclusively through the proxy.
_ALLOWED_NETWORKS: frozenset[str] = frozenset({"none", SANDBOX_NETWORK})

PROXY_IMAGE = "pyhunt-egress-proxy:latest"
PROXY_BASE_IMAGE = os.environ.get("PYHUNT_PROXY_BASE_IMAGE", "python:3.11-slim")
PROXY_ALIAS = "pyhunt-proxy"
PROXY_PORT = 3128
DEFAULT_EGRESS_ALLOWLIST: tuple[str, ...] = ("api.anthropic.com:443",)

LABEL_RUN_ID = "pyhunt.run_id"
LABEL_MANAGED = "pyhunt.managed"
LABEL_ROLE = "pyhunt.role"
LABEL_CREATED = "pyhunt.created_at"

# Resource caps applied to every container. Generous enough that a real PoC runs,
# tight enough that a fork bomb or a memory balloon is contained.
DEFAULT_MEMORY = "2g"
DEFAULT_PIDS_LIMIT = 256
DEFAULT_CPUS = "2"
# Wall clock. Docker has no server-side run timeout, so this is enforced host
# side by `run_container` and the container is force-removed if it is exceeded.
DEFAULT_WALL_CLOCK = 120

# Scratch space, because the rootfs is read-only. Deliberately NOT `noexec`: a
# Python PoC legitimately writes a canary file and sometimes a helper script
# here, and a sandbox that breaks the PoC produces `no_event`, which is
# indistinguishable in the report from "the vulnerability did not fire".
# Read-only at the type level (not just by convention): this is a security
# default, and a module-level dict is one `DEFAULT_TMPFS["/"] = "rw"` away from
# silently un-hardening every container the process starts.
DEFAULT_TMPFS: Mapping[str, str] = MappingProxyType({"/tmp": "rw,nosuid,nodev,size=64m"})

# A running container belonging to *another* run is only reaped once it is this
# old. Every PyHunt container has a wall clock measured in minutes, so anything
# still alive after six hours is wreckage from a SIGKILLed run, not a peer.
ORPHAN_TTL_SECONDS = 6 * 60 * 60

DOCKER_PROBE_TIMEOUT = 30
DOCKER_BUILD_TIMEOUT = 900
VERIFY_TIMEOUT = 90

EXIT_OK = 0
EXIT_INTERNAL_ERROR = 1
EXIT_CONTRACT_VIOLATION = 2


# ===========================================================================
# Part 3 — the credential filter
# ===========================================================================

# Named explicitly because they are the two that matter most and must never
# depend on a fuzzy pattern continuing to match them.
_CREDENTIAL_NAMES: frozenset[str] = frozenset({
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "DOCKER_AUTH_CONFIG",
})

# Deliberately over-broad. This is a deny filter, and the cost of a false
# positive is one dropped variable while the cost of a false negative is an
# exfiltrated credential. `KEYBOARD_LAYOUT` losing its ride into a PoC container
# is not a problem worth a narrower regex.
_CREDENTIAL_FRAGMENT = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|AUTH|SESSION|"
    r"COOKIE|PRIVATE|SIGNATURE|BEARER|APIKEY|ACCESS_ID)",
    re.IGNORECASE,
)


def is_credential_name(name: str) -> bool:
    """True if `name` looks like it could carry a secret.

    Errs toward True. See the note on :data:`_CREDENTIAL_FRAGMENT`.
    """
    if name.upper() in _CREDENTIAL_NAMES:
        return True
    return bool(_CREDENTIAL_FRAGMENT.search(name))


def credential_names(env: Mapping[str, str]) -> list[str]:
    """The credential-shaped variable NAMES present in `env`, sorted.

    Names only — a function that returned values would eventually be logged by
    someone, and then the secret is in the transcript.
    """
    return sorted(k for k in env if is_credential_name(k))


def sanitize_env(env: Mapping[str, str] | None) -> dict[str, str]:
    """`env` with every credential-shaped entry removed.

    This is applied by :func:`container_argv` to whatever it is handed, so a
    caller that passes `os.environ` wholesale still cannot leak a key into a
    container. Dropping is logged, never silent.
    """
    clean: dict[str, str] = {}
    for key, value in (env or {}).items():
        if is_credential_name(key):
            log.warning("[sandbox] refusing to pass credential-shaped env var %r "
                        "into a container", key)
            continue
        clean[str(key)] = str(value)
    return clean


# ===========================================================================
# Part 4 — docker plumbing
# ===========================================================================

@dataclass(frozen=True)
class DockerResult:
    """One `docker ...` invocation. Never raises; a missing binary is exit 127
    and a timeout is 124, matching shell convention."""

    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        return (self.stdout + self.stderr).strip()


def _docker(args: Sequence[str], *, timeout: int = DOCKER_PROBE_TIMEOUT,
            stdin: str | None = None,
            binary: str = DOCKER_BINARY) -> DockerResult:
    """Run `docker <args>`. Pure plumbing: no policy, no raising."""
    argv = [binary, *args]
    if shutil.which(binary) is None:
        return DockerResult(tuple(argv), 127, "", f"{binary}: not found")
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        err = e.stderr if isinstance(e.stderr, str) else ""
        return DockerResult(tuple(argv), 124, out or "", err or "", timed_out=True)
    except OSError as e:
        return DockerResult(tuple(argv), 127, "", f"{type(e).__name__}: {e}")
    return DockerResult(tuple(argv), p.returncode, p.stdout or "", p.stderr or "")


def _docker_json(args: Sequence[str], *, binary: str = DOCKER_BINARY,
                 timeout: int = DOCKER_PROBE_TIMEOUT) -> dict[str, Any] | None:
    """`docker <args> --format {{json .}}` decoded, or None if anything went wrong.

    `docker info` prints warnings on stdout alongside the JSON on some engines,
    so the first `{`-prefixed line that parses wins rather than the whole blob.
    """
    r = _docker([*args, "--format", "{{json .}}"], binary=binary, timeout=timeout)
    if not r.ok:
        return None
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


# ===========================================================================
# Part 5 — detection
# ===========================================================================

@dataclass(frozen=True)
class Detection:
    """What this host can actually isolate, and why.

    `reasons` is the field that matters to a human: a tier on its own tells an
    operator that Proof mode was refused, but not what to change.
    """

    tier: str
    docker_version: str | None
    server_os: str | None
    client_os: str | None
    engine: str | None
    runtimes: list[str]
    can_create_internal_network: bool
    proof_allowed: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tier_note"] = TIER_NOTES.get(self.tier, "")
        return d


def _runtime_names(info: Mapping[str, Any]) -> list[str]:
    """Runtime keys from `docker info`, plus each runtime's `path`.

    Docker Desktop reports the key `io.containerd.runc.v2` with path `runc`,
    while a gVisor install is usually keyed `runsc`. Collecting both halves
    means the gVisor check does not depend on which naming the engine chose.
    """
    runtimes = info.get("Runtimes")
    if not isinstance(runtimes, dict):
        return []
    names: list[str] = []
    for key, value in runtimes.items():
        names.append(str(key))
        if isinstance(value, dict) and value.get("path"):
            names.append(str(value["path"]))
    return sorted(set(names))


def _looks_like_vm_engine(info: Mapping[str, Any], client_os: str | None,
                          server_os: str | None) -> tuple[bool, str | None]:
    """Is the daemon's kernel a *different* kernel from the operator's host?

    Two independent establishments, both read from the environment:

    1. The engine names itself as one of the VM-backed products. `docker info`'s
       `OperatingSystem` is "Docker Desktop" on macOS, Windows AND Linux — the
       Linux build also runs a VM — so this is the check that generalises.
    2. The client and server disagree about the OS. A Linux daemon cannot be the
       host kernel of a `darwin` or `windows` client, so something is interposed
       and that something is a virtual machine.

    Either is sufficient. Neither is an assumption about the operator's platform.
    """
    haystack = " ".join(
        str(info.get(k, "")) for k in ("OperatingSystem", "Name", "KernelVersion")
    ).lower()
    for marker in _VM_ENGINE_MARKERS:
        if marker in haystack:
            return True, f"the engine identifies as {info.get('OperatingSystem') or marker!r}"
    if client_os and server_os and client_os != server_os:
        return True, (f"the docker client runs on {client_os} while the daemon runs "
                      f"on {server_os}, so a virtual machine sits between them")
    return False, None


def can_create_internal_network(*, binary: str = DOCKER_BINARY,
                                run_id: str | None = None) -> tuple[bool, str]:
    """Can this daemon create an `internal: true` network? Answered by trying.

    Reusing an already-correct `pyhunt-internal` counts. Otherwise a throwaway
    probe network is created and removed — labelled, so that if this process is
    killed between the two the reaper still finds it.
    """
    existing = _docker(["network", "inspect", SANDBOX_NETWORK,
                        "--format", "{{.Internal}}"], binary=binary)
    if existing.ok:
        if existing.stdout.strip().lower() == "true":
            return True, f"{SANDBOX_NETWORK} already exists and is internal"
        return False, (f"a network named {SANDBOX_NETWORK} already exists but is "
                       f"NOT internal — remove it (`docker network rm "
                       f"{SANDBOX_NETWORK}`) before running in Proof mode")

    probe = f"pyhunt-probe-{uuid.uuid4().hex[:8]}"
    created = _docker([
        "network", "create", "--internal",
        "--label", f"{LABEL_MANAGED}=true",
        "--label", f"{LABEL_ROLE}=probe",
        "--label", f"{LABEL_RUN_ID}={run_id or 'probe'}",
        probe,
    ], binary=binary)
    if created.ok:
        _docker(["network", "rm", probe], binary=binary)
        return True, "an internal network was created and removed successfully"
    return False, f"internal network creation failed: {created.output[:200]}"


def detect(*, binary: str = DOCKER_BINARY, probe_network: bool = True) -> Detection:
    """Establish the isolation tier from the environment. Never raises.

    Docker being absent is tier `none`, not an error — a static run is still a
    perfectly good run, and crashing here would deny it.
    """
    reasons: list[str] = []

    version = _docker_json(["version"], binary=binary)
    info = _docker_json(["info"], binary=binary)

    if version is None and info is None:
        reasons.append(
            f"`{binary}` is unavailable (binary missing, or the daemon is not "
            f"responding), so no container boundary can be created"
        )
        return Detection(
            tier=TIER_NONE, docker_version=None, server_os=None, client_os=None,
            engine=None, runtimes=[], can_create_internal_network=False,
            proof_allowed=False, reasons=reasons,
        )

    version = version or {}
    info = info or {}
    server = version.get("Server") if isinstance(version.get("Server"), dict) else {}
    client = version.get("Client") if isinstance(version.get("Client"), dict) else {}

    server_version = (
        str(server.get("Version")) if server.get("Version")
        else (str(info.get("ServerVersion")) if info.get("ServerVersion") else None)
    )
    server_os = str(server.get("Os")) if server.get("Os") else (
        str(info.get("OSType")) if info.get("OSType") else None)
    client_os = str(client.get("Os")) if client.get("Os") else None
    platform = server.get("Platform")
    engine = None
    if isinstance(platform, dict) and platform.get("Name"):
        engine = str(platform["Name"])
    elif info.get("OperatingSystem"):
        engine = str(info["OperatingSystem"])

    if not server_version:
        # The CLI answered but the daemon did not. That is `none`: there is no
        # engine to put anything inside of.
        reasons.append(
            f"the `{binary}` CLI is installed but the daemon did not answer — "
            f"start Docker and re-run `sandbox.py detect`"
        )
        return Detection(
            tier=TIER_NONE, docker_version=None, server_os=server_os,
            client_os=client_os, engine=engine, runtimes=[],
            can_create_internal_network=False, proof_allowed=False, reasons=reasons,
        )

    runtimes = _runtime_names(info)
    has_gvisor = any(
        marker in name.lower() for name in runtimes for marker in _GVISOR_MARKERS
    )
    is_vm, vm_reason = _looks_like_vm_engine(info, client_os, server_os)

    if has_gvisor:
        tier = TIER_GVISOR
        reasons.append(
            "the daemon offers a `runsc` runtime, so containers can be started "
            "under gVisor's user-space kernel"
        )
    elif is_vm:
        tier = TIER_VM
        reasons.append(vm_reason or "the daemon runs inside a virtual machine")
        reasons.append(
            "gVisor is a Linux syscall interceptor and is not available here; "
            "that is a missing runtime, NOT missing isolation — the VM's "
            "separate kernel is a stronger boundary than same-kernel interception"
        )
    else:
        tier = TIER_RUNC
        reasons.append(
            f"the daemon shares this host's kernel ({server_os or 'unknown OS'}) "
            f"and offers no `runsc` runtime (found: {', '.join(runtimes) or 'none'})"
        )
        reasons.append(
            "Proof mode is REFUSED at this tier: a container escape would land "
            "directly on the operator's kernel. Install gVisor (`runsc`) and "
            "register it as a Docker runtime, or run PyHunt inside a VM"
        )

    if probe_network:
        net_ok, net_reason = can_create_internal_network(binary=binary)
    else:
        net_ok, net_reason = False, "internal-network probe was skipped"
    reasons.append(net_reason)

    proof_allowed = tier in PROOF_TIERS and net_ok
    if tier in PROOF_TIERS and not net_ok:
        reasons.append(
            "Proof mode is REFUSED despite an adequate tier: without an "
            "`internal: true` network, a container running target code would "
            "have a route off this box"
        )

    return Detection(
        tier=tier, docker_version=server_version, server_os=server_os,
        client_os=client_os, engine=engine, runtimes=runtimes,
        can_create_internal_network=net_ok, proof_allowed=proof_allowed,
        reasons=reasons,
    )


# ===========================================================================
# Part 6 — the one argv builder
# ===========================================================================

def container_argv(
    *,
    image: str,
    run_id: str,
    command: Sequence[str] = (),
    network: str = SANDBOX_NETWORK,
    name: str | None = None,
    role: str = "generic",
    env: Mapping[str, str] | None = None,
    entrypoint: str | None = None,
    workdir: str | None = None,
    memory: str = DEFAULT_MEMORY,
    pids_limit: int = DEFAULT_PIDS_LIMIT,
    cpus: str = DEFAULT_CPUS,
    tmpfs: Mapping[str, str] | None = None,
    remove: bool = True,
    detach: bool = False,
    interactive: bool = False,
    network_alias: str | None = None,
    extra_labels: Mapping[str, str] | None = None,
    docker_binary: str = DOCKER_BINARY,
) -> list[str]:
    """Build the ONLY form of `docker run` PyHunt is allowed to issue.

    The hardening flags are not parameters. `--read-only`, `--cap-drop ALL`,
    `--security-opt no-new-privileges`, the memory/pid caps and the
    `pyhunt.run_id` label are emitted unconditionally, and the environment is
    passed through :func:`sanitize_env` on the way in. That is the point of
    routing every call site through one function: hardening that a caller can
    opt out of is hardening that some caller eventually does opt out of.

    Raises :class:`SandboxError` for a network outside
    :data:`_ALLOWED_NETWORKS`, for a non-positive resource cap, and for an
    environment key that is not a legal variable name — the last one because
    `docker run -e FOO` (no `=`) *inherits FOO from the host environment*, which
    is precisely the leak this function exists to prevent.
    """
    if network not in _ALLOWED_NETWORKS:
        raise SandboxError(
            f"refusing to start a container on network {network!r}: PyHunt "
            f"containers may only use {sorted(_ALLOWED_NETWORKS)}. Target code "
            f"belongs on `none`; the harness's own containers belong on "
            f"{SANDBOX_NETWORK}, whose only egress is the allowlist proxy."
        )
    if pids_limit <= 0:
        raise SandboxError(f"pids_limit must be positive, got {pids_limit!r}")
    if not str(memory).strip():
        raise SandboxError("a memory cap is mandatory on every container")

    clean_env = sanitize_env(env)
    for key in clean_env:
        if "=" in key or not key.strip():
            raise SandboxError(
                f"illegal environment variable name {key!r}: a name containing "
                f"'=' cannot be passed as KEY=VALUE, and the bare `-e NAME` "
                f"form would inherit the value from the host environment"
            )

    argv: list[str] = [docker_binary, "run"]
    if remove:
        argv.append("--rm")
    if detach:
        argv.append("--detach")
    if interactive:
        argv.append("--interactive")
    if name:
        argv += ["--name", name]

    # Labels first: everything PyHunt starts must be findable by the reaper even
    # if the process that started it is SIGKILLed a millisecond later.
    labels: dict[str, str] = {
        LABEL_RUN_ID: run_id,
        LABEL_MANAGED: "true",
        LABEL_ROLE: role,
        LABEL_CREATED: str(int(time.time())),
    }
    labels.update({str(k): str(v) for k, v in (extra_labels or {}).items()})
    for key, value in labels.items():
        argv += ["--label", f"{key}={value}"]

    argv += ["--network", network]
    if network_alias and network != "none":
        argv += ["--network-alias", network_alias]

    # --- the unconditional isolation contract -----------------------------
    argv += [
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", str(memory),
        # Equal to --memory means swap is disabled: without this a memory cap is
        # a swap cap, and the container can still balloon onto disk.
        "--memory-swap", str(memory),
        "--pids-limit", str(pids_limit),
        "--cpus", str(cpus),
        # Grace period for SIGTERM before SIGKILL when the wall clock expires.
        "--stop-timeout", "5",
    ]
    for path, options in (tmpfs if tmpfs is not None else DEFAULT_TMPFS).items():
        argv += ["--tmpfs", f"{path}:{options}" if options else str(path)]
    # ----------------------------------------------------------------------

    # No `--publish`, ever, and deliberately not even as an opt-in parameter:
    # publishing binds a container port onto the host, which is a hole through
    # the boundary this function exists to build. Containers reach each other by
    # network alias on `pyhunt-internal` instead.
    for key, value in clean_env.items():
        argv += ["--env", f"{key}={value}"]
    if workdir:
        argv += ["--workdir", workdir]
    if entrypoint:
        argv += ["--entrypoint", entrypoint]

    argv.append(image)
    argv += [str(c) for c in command]
    return argv


def run_container(
    *,
    timeout_seconds: int = DEFAULT_WALL_CLOCK,
    stdin: str | None = None,
    docker_binary: str = DOCKER_BINARY,
    **kwargs: Any,
) -> DockerResult:
    """Start a container built by :func:`container_argv` under a wall clock.

    Docker has no server-side run timeout, so the wall clock is enforced here
    and — critically — the container is force-removed when it expires. `--rm`
    only fires when the container exits on its own; a container killed by our
    timeout would otherwise survive as an orphan holding the run's memory cap.
    """
    name = kwargs.get("name") or f"pyhunt-{kwargs.get('role', 'run')}-{uuid.uuid4().hex[:10]}"
    kwargs["name"] = name
    argv = container_argv(docker_binary=docker_binary, **kwargs)
    result = _docker(argv[1:], timeout=timeout_seconds, stdin=stdin,
                     binary=docker_binary)
    if result.timed_out:
        log.warning("[sandbox] container %s exceeded its %ds wall clock — removing",
                    name, timeout_seconds)
        _docker(["rm", "--force", name], binary=docker_binary)
    return result


# ===========================================================================
# Part 7 — results-directory plumbing
# ===========================================================================

def run_id_for(results_dir: Path) -> str:
    """The run's stable identity.

    Read from `manifest.json` when phase 0 has already written one; otherwise
    derived from the results directory's own name, which is timestamped and
    therefore already unique. Deriving rather than generating matters: the label
    has to be reproducible by a *later* process that is trying to reap what this
    one left behind, and that process only has the directory.
    """
    manifest = Path(results_dir) / "manifest.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("run_id"):
            return str(data["run_id"])
    except (OSError, ValueError):
        pass
    name = Path(results_dir).resolve().name or "pyhunt-run"
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name)[:96].strip("-.") or "pyhunt-run"


def merge_preflight(results_dir: Path, payload: Mapping[str, Any]) -> Path:
    """Merge `payload` into `<results-dir>/preflight.json` under `sandbox`.

    A merge, not a write: phase 0 owns preflight.json and records capability
    findings there too, so clobbering the file would delete another phase's
    honest reporting to record our own.
    """
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    path = results_dir / "preflight.json"
    existing: dict[str, Any] = {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            existing = loaded
    except (OSError, ValueError):
        existing = {}
    sandbox_block = existing.get("sandbox")
    if not isinstance(sandbox_block, dict):
        sandbox_block = {}
    sandbox_block.update(payload)
    existing["sandbox"] = sandbox_block
    path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


# ===========================================================================
# Part 8 — up: create the isolation
# ===========================================================================

def ensure_network(run_id: str, *, binary: str = DOCKER_BINARY) -> dict[str, Any]:
    """Create (or adopt) `pyhunt-internal`. Idempotent.

    An existing network that is NOT internal is a hard failure rather than
    something to adopt: a same-named routed network would give every container
    the run starts a silent route off the box, and the operator would have no
    signal that the boundary they were promised is not there.
    """
    inspect = _docker(["network", "inspect", SANDBOX_NETWORK,
                       "--format", "{{.Internal}}"], binary=binary)
    if inspect.ok:
        internal = inspect.stdout.strip().lower() == "true"
        return {
            "name": SANDBOX_NETWORK,
            "status": "existing" if internal else "unusable",
            "internal": internal,
            "note": ("adopted the existing internal network"
                     if internal else
                     f"a network named {SANDBOX_NETWORK} exists but is NOT "
                     f"internal — it must be removed before Proof mode can run"),
        }
    created = _docker([
        "network", "create", "--internal",
        "--label", f"{LABEL_MANAGED}=true",
        "--label", f"{LABEL_ROLE}=sandbox-network",
        "--label", f"{LABEL_RUN_ID}={run_id}",
        SANDBOX_NETWORK,
    ], binary=binary)
    if created.ok:
        return {"name": SANDBOX_NETWORK, "status": "created", "internal": True,
                "note": "created with internal: true — no route off this box"}
    return {"name": SANDBOX_NETWORK, "status": "failed", "internal": False,
            "note": f"could not create the sandbox network: {created.output[:300]}"}


# The proxy image is built from PyHunt's own `egress_proxy.py`, layered on a
# stock Python base. Built locally rather than pulled so the thing standing at
# the only hole in the sandbox is code that ships in this repo and is reviewable
# alongside it.
_PROXY_DOCKERFILE = f"""# GENERATED BY PyHunt (scripts/sandbox.py) — do not edit by hand.
FROM {{base}}
COPY egress_proxy.py /opt/pyhunt/egress_proxy.py
USER nobody
EXPOSE {PROXY_PORT}
ENTRYPOINT ["python3", "/opt/pyhunt/egress_proxy.py"]
"""


def ensure_proxy(
    run_id: str,
    *,
    allowlist: Sequence[str] = DEFAULT_EGRESS_ALLOWLIST,
    binary: str = DOCKER_BINARY,
    base_image: str = PROXY_BASE_IMAGE,
    build_timeout: int = DOCKER_BUILD_TIMEOUT,
    source: Path | None = None,
) -> dict[str, Any]:
    """Build and start the egress allowlist proxy. Idempotent, and fail-SOFT.

    Fail-soft is the correct stance and worth being explicit about: if the proxy
    cannot be built or started, the sandbox is left *more* restrictive than
    planned (no egress at all), not less. That is a degraded run, not an unsafe
    one, so it is recorded and the run continues — the opposite decision for the
    opposite failure, `verify`, which refuses.
    """
    proxy_name = f"pyhunt-proxy-{run_id}"[:60]
    source_file = Path(source) if source else Path(__file__).resolve().parent / "egress_proxy.py"
    if not source_file.is_file():
        return {"status": "unavailable", "name": proxy_name,
                "note": f"egress_proxy.py not found at {source_file} — the "
                        f"sandbox has NO egress at all"}

    running = _docker(["ps", "--filter", f"name=^{proxy_name}$",
                       "--filter", "status=running", "--format", "{{.ID}}"],
                      binary=binary)
    if running.ok and running.stdout.strip():
        return {"status": "existing", "name": proxy_name,
                "alias": PROXY_ALIAS, "port": PROXY_PORT,
                "allowlist": list(allowlist),
                "note": "an egress proxy for this run is already running"}

    # A stopped container of the same name would block `docker run --name`.
    _docker(["rm", "--force", proxy_name], binary=binary)

    build = _docker(
        ["build", "--tag", PROXY_IMAGE, "--file", "-", str(source_file.parent)],
        stdin=_PROXY_DOCKERFILE.format(base=base_image),
        timeout=build_timeout, binary=binary,
    )
    if not build.ok:
        return {"status": "failed", "name": proxy_name,
                "note": f"proxy image build failed (exit {build.exit_code}): "
                        f"{build.output[-400:]} — the sandbox has NO egress; "
                        f"anything that needed the allowlisted host will fail"}

    argv = container_argv(
        image=PROXY_IMAGE,
        run_id=run_id,
        name=proxy_name,
        role="egress-proxy",
        network=SANDBOX_NETWORK,
        network_alias=PROXY_ALIAS,
        env={"PYHUNT_EGRESS_ALLOW": ",".join(allowlist),
             "PYHUNT_EGRESS_PORT": str(PROXY_PORT)},
        memory="256m",
        pids_limit=64,
        cpus="1",
        remove=False,          # long-lived; `down` removes it
        detach=True,
        docker_binary=binary,
    )
    started = _docker(argv[1:], binary=binary)
    if not started.ok:
        return {"status": "failed", "name": proxy_name,
                "note": f"proxy container failed to start: {started.output[-400:]}"}

    # The proxy is the ONE container attached to a routed network as well as the
    # internal one. That second attachment is what makes it a hole, so it is
    # made here, explicitly, and never by container_argv — which cannot express
    # a routed network at all.
    connected = _docker(["network", "connect", EGRESS_NETWORK, proxy_name],
                        binary=binary)
    if not connected.ok:
        return {"status": "degraded", "name": proxy_name,
                "alias": PROXY_ALIAS, "port": PROXY_PORT,
                "allowlist": list(allowlist),
                "note": f"the proxy is running but could not be attached to "
                        f"{EGRESS_NETWORK}: {connected.output[:300]} — it will "
                        f"refuse every request, so the sandbox has no egress"}

    return {"status": "started", "name": proxy_name, "alias": PROXY_ALIAS,
            "port": PROXY_PORT, "allowlist": list(allowlist),
            "note": f"CONNECT proxy at {PROXY_ALIAS}:{PROXY_PORT} on "
                    f"{SANDBOX_NETWORK}; everything not on the allowlist is 403"}


def ensure_target_image(repo: Path, *, build: bool = True,
                        binary: str = DOCKER_BINARY) -> dict[str, Any]:
    """Locate the provisioned target image, building it if it is missing.

    Provisioning itself is not reimplemented here — `provision/` fingerprints
    the repo, renders the Dockerfile and runs the build/verify/repair ladder.
    This only answers "is the image there, and if not, make it".
    """
    repo = Path(repo)
    try:
        from provision.build import image_tag_for, provision_environment
    except ImportError as e:                        # pragma: no cover - packaging guard
        return {"status": "unavailable", "note": f"provision package not importable: {e}"}

    tag = image_tag_for(repo)
    found = _docker(["image", "inspect", tag, "--format", "{{.Id}}"], binary=binary)
    if found.ok:
        return {"status": "found", "image": tag,
                "note": "the provisioned target image already exists"}
    if not build:
        return {"status": "missing", "image": tag,
                "note": "the provisioned target image does not exist and "
                        "--no-build was given — Proof mode cannot run PoCs "
                        "against the target's real dependencies"}

    log.info("[sandbox] provisioned image %s not found — building it", tag)
    result = provision_environment(repo, build=True, verify=True, verify_network="none")
    return {
        "status": result.status,
        "image": result.image_tag,
        "note": "; ".join(result.notes[-3:]) or f"provisioning finished: {result.status}",
        "provision": result.agent_summary(),
    }


def up(repo: Path, results_dir: Path, *, build_image: bool = True,
       allowlist: Sequence[str] = DEFAULT_EGRESS_ALLOWLIST,
       binary: str = DOCKER_BINARY) -> dict[str, Any]:
    """Create the sandbox and record it. Idempotent; reaps orphans on the way in."""
    results_dir = Path(results_dir)
    run_id = run_id_for(results_dir)

    detection = detect(binary=binary)
    reaped = reap(run_id=None, binary=binary)         # orphans from earlier runs

    state: dict[str, Any] = {
        "run_id": run_id,
        "created_at": int(time.time()),
        "tier": detection.tier,
        "proof_allowed": detection.proof_allowed,
        "detection": detection.to_dict(),
        "reaped_on_entry": reaped,
    }

    if detection.tier == TIER_NONE:
        state["status"] = "unavailable"
        state["note"] = ("no container engine, so there is nothing to bring up — "
                         "this run can only be static")
        merge_preflight(results_dir, state)
        return state

    state["network"] = ensure_network(run_id, binary=binary)
    if state["network"]["status"] in ("failed", "unusable"):
        state["status"] = "failed"
        state["note"] = state["network"]["note"]
        merge_preflight(results_dir, state)
        return state

    state["proxy"] = ensure_proxy(run_id, allowlist=allowlist, binary=binary)
    state["target_image"] = ensure_target_image(Path(repo), build=build_image,
                                                binary=binary)
    state["status"] = "up"
    state["note"] = (
        f"sandbox is up at tier {detection.tier}; run `sandbox.py verify "
        f"--results-dir {results_dir}` before trusting it"
    )
    merge_preflight(results_dir, state)
    return state


# ===========================================================================
# Part 9 — verify: assert the isolation from inside
# ===========================================================================

# Runs INSIDE the throwaway container, fed to `python3 -` on stdin.
#
# Output is fenced with a nonce generated by THIS process a moment ago. That is
# not decoration: the image under test may be the target's own provisioned
# image, which is attacker-influenced, and an image that printed a forged
# "all assertions passed" block would otherwise talk us into Proof mode. The
# fence is authored after the nonce exists, so the image's contents cannot
# contain a matching one.
_VERIFY_SCRIPT = r'''
import json, os, socket, sys

fence = sys.argv[1]
canaries = [p for p in sys.argv[2].split("|") if p]
tmpfs = [p for p in sys.argv[3].split("|") if p]

results = []


def record(name, passed, detail):
    results.append({"assertion": name, "passed": bool(passed), "detail": detail})


# (a) no route off the box. Literal IPs only: DNS is answered by Docker's
# embedded resolver, which forwards to the daemon's resolvers and can succeed on
# an internal network, so a name lookup proves nothing either way. A TCP
# connect does.
probes = [("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)]
reached = []
errors = []
for host, port in probes:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((host, port))
        s.close()
        reached.append("%s:%d" % (host, port))
    except OSError as e:
        errors.append("%s:%d -> %s" % (host, port, type(e).__name__))
    except Exception as e:  # noqa: BLE001 - an unexpected error is not a pass
        errors.append("%s:%d -> UNEXPECTED %s" % (host, port, type(e).__name__))
record("no_internet", not reached,
       ("reached " + ", ".join(reached)) if reached
       else "every probe refused: " + "; ".join(errors))

# (b) the host filesystem is not visible. Two independent checks, because
# either alone is weak: a canary the host can see and the container must not,
# and the mount table, which catches a bind mount of some path we did not think
# to name.
visible = [p for p in canaries if os.path.exists(p)]
allowed_prefixes = ("/proc", "/sys", "/dev")
allowed_exact = {"/", "/etc/resolv.conf", "/etc/hostname", "/etc/hosts"} | set(tmpfs)
unexpected = []
mount_detail = ""
try:
    with open("/proc/self/mountinfo", "r") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 5:
                continue
            point = parts[4]
            if point in allowed_exact:
                continue
            if any(point == p or point.startswith(p + "/") for p in allowed_prefixes):
                continue
            if any(point == t or point.startswith(t.rstrip("/") + "/") for t in tmpfs):
                continue
            unexpected.append(point)
    mount_detail = ("no unexpected mounts" if not unexpected
                    else "unexpected mount points: " + ", ".join(sorted(set(unexpected))[:10]))
    mounts_readable = True
except OSError as e:
    mounts_readable = False
    mount_detail = "could not read /proc/self/mountinfo (%s) — the mount table " \
                   "could not be checked, which is a FAILURE, not a pass" % type(e).__name__
record("no_host_filesystem",
       (not visible) and (not unexpected) and mounts_readable,
       ("host paths visible inside the container: " + ", ".join(visible) + "; "
        if visible else "no host canary is visible; ") + mount_detail)

# (c) no credential-shaped environment variable. Names only — a detail field
# carrying values would put the secret in the transcript this asserts about.
fragments = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASSPHRASE",
             "CREDENTIAL", "AUTH", "SESSION", "COOKIE", "PRIVATE", "SIGNATURE",
             "BEARER", "APIKEY", "ACCESS_ID")
found = sorted(n for n in os.environ if any(f in n.upper() for f in fragments))
record("no_auth_env", not found,
       ("credential-shaped variables present: " + ", ".join(found)) if found
       else "no credential-shaped variable in the container environment")

# (d) the rootfs really is read-only. Verifies the flag we claim rather than
# trusting that it was passed.
try:
    with open("/pyhunt-rootfs-write-probe", "w") as fh:
        fh.write("x")
    os.unlink("/pyhunt-rootfs-write-probe")
    record("read_only_rootfs", False, "the container rootfs is WRITABLE")
except OSError as e:
    record("read_only_rootfs", True, "root filesystem rejected a write (%s)" % type(e).__name__)

payload = {"assertions": results,
           "passed": all(r["passed"] for r in results),
           "python": sys.version.split()[0]}
sys.stdout.write("<<<PYHUNT-VERIFY %s>>>%s<<<END %s>>>\n"
                 % (fence, json.dumps(payload), fence))
'''


def _extract_fenced(output: str, fence: str) -> dict[str, Any] | None:
    """Pull the nonce-fenced JSON block out of container output.

    Anything outside the fence is ignored — the image may print banners, and it
    may equally print a forged result; only a block carrying a nonce minted
    milliseconds ago is read.
    """
    start = f"<<<PYHUNT-VERIFY {fence}>>>"
    end = f"<<<END {fence}>>>"
    i = output.find(start)
    if i < 0:
        return None
    j = output.find(end, i + len(start))
    if j < 0:
        return None
    try:
        parsed = json.loads(output[i + len(start):j])
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _verify_image(results_dir: Path, *, binary: str = DOCKER_BINARY) -> tuple[str | None, str]:
    """Which image to make the assertions in.

    Preference order matters. The provisioned target image is what Proof mode
    will actually run PoCs in, so verifying anything else verifies the wrong
    thing — a stock base image could pass while the real one ships a baked-in
    API key. The fallbacks exist only so a missing target image produces a
    reported failure rather than a crash.
    """
    try:
        data = json.loads((Path(results_dir) / "preflight.json").read_text(encoding="utf-8"))
        block = data.get("sandbox") if isinstance(data, dict) else None
        image = (block or {}).get("target_image", {}).get("image")
        if image and _docker(["image", "inspect", str(image), "--format", "{{.Id}}"],
                             binary=binary).ok:
            return str(image), "the provisioned target image — the one Proof mode will use"
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    for fallback, why in ((PROXY_IMAGE, "the egress proxy image"),
                          (PROXY_BASE_IMAGE, "a stock Python base image")):
        if _docker(["image", "inspect", fallback, "--format", "{{.Id}}"], binary=binary).ok:
            return fallback, (f"{why} — the provisioned target image was not "
                              f"available, so this verifies the sandbox flags "
                              f"but NOT the target image's own environment")
    return None, ("no image was available to run the assertions in — verification "
                  "could not be performed")


@dataclass
class VerificationResult:
    """The outcome of asserting isolation from inside a container.

    `passed` is False whenever any assertion failed **or could not be run**.
    There is deliberately no third state: a verification that did not happen
    must not read as one that succeeded, because the consequence of that
    confusion is Proof mode running outside a boundary.
    """

    passed: bool
    image: str | None
    image_note: str
    network: str
    assertions: list[dict[str, Any]] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verify_isolation(results_dir: Path, *, binary: str = DOCKER_BINARY,
                     timeout: int = VERIFY_TIMEOUT) -> VerificationResult:
    """Launch a throwaway container and make it prove the sandbox holds.

    Asserted, in the container, on the sandbox network: no route off the box, no
    host filesystem, no credential-shaped environment variable, and a read-only
    rootfs. The sandbox network is deliberately the one tested even though
    target code runs on `none` — it is the weaker of the two, so a pass here
    implies a pass there.
    """
    results_dir = Path(results_dir)
    run_id = run_id_for(results_dir)
    fence = uuid.uuid4().hex

    image, image_note = _verify_image(results_dir, binary=binary)
    if image is None:
        return VerificationResult(
            passed=False, image=None, image_note=image_note,
            network=SANDBOX_NETWORK,
            note="verification could not be performed, which is a FAILURE — "
                 "absence of evidence is not evidence of isolation",
        )

    # Canaries: paths that exist on the host right now and must not exist in the
    # container. The results directory is the sharpest one — it is the run's own
    # state, and a container that can read it can rewrite the findings.
    canary = results_dir / f".pyhunt-host-canary-{fence[:12]}"
    try:
        results_dir.mkdir(parents=True, exist_ok=True)
        canary.write_text(fence, encoding="utf-8")
    except OSError as e:
        return VerificationResult(
            passed=False, image=image, image_note=image_note,
            network=SANDBOX_NETWORK,
            note=f"could not write the host canary ({e}) — the host-filesystem "
                 f"assertion could not be set up, which is a FAILURE",
        )

    # Only host-unique paths are used as canaries. `Path.home()` looks tempting
    # and is wrong: on a Linux host running as root it is `/root`, which exists
    # inside most images, so it would fail the assertion on every correctly
    # isolated container. The results directory is timestamped, so it is unique
    # by construction — and it is also the sharpest thing to test, since a
    # container that can read it can rewrite the run's own findings.
    canaries = [str(canary), str(results_dir.resolve())]
    try:
        result = run_container(
            image=image,
            run_id=run_id,
            role="isolation-verify",
            network=SANDBOX_NETWORK,
            entrypoint="python3",
            command=["-", fence, "|".join(canaries), "|".join(DEFAULT_TMPFS)],
            interactive=True,
            memory="512m",
            pids_limit=64,
            timeout_seconds=timeout,
            stdin=_VERIFY_SCRIPT,
            docker_binary=binary,
        )
    finally:
        canary.unlink(missing_ok=True)

    payload = _extract_fenced(result.stdout, fence)
    if payload is None:
        detail = result.output[-500:] or "(no output)"
        return VerificationResult(
            passed=False, image=image, image_note=image_note,
            network=SANDBOX_NETWORK,
            note=f"the verification container produced no nonce-fenced result "
                 f"(exit {result.exit_code}{', timed out' if result.timed_out else ''}). "
                 f"An assertion that could not be RUN is a failure, not a pass. "
                 f"Container output: {detail}",
        )

    assertions = payload.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        return VerificationResult(
            passed=False, image=image, image_note=image_note,
            network=SANDBOX_NETWORK,
            note="the verification container returned no assertions — treated as "
                 "a failure",
        )

    passed = all(bool(a.get("passed")) for a in assertions)
    failed = [str(a.get("assertion")) for a in assertions if not a.get("passed")]
    note = ("every isolation assertion passed inside the container"
            if passed else
            "isolation assertions FAILED: " + ", ".join(failed) +
            " — Proof mode must be refused, not downgraded")
    return VerificationResult(
        passed=passed, image=image, image_note=image_note,
        network=SANDBOX_NETWORK, assertions=assertions, note=note,
    )


# ===========================================================================
# Part 10 — down and the reaper
# ===========================================================================

def _list_managed_containers(*, binary: str = DOCKER_BINARY) -> list[dict[str, str]]:
    """Every container PyHunt ever started that still exists, from its labels."""
    fmt = ('{{.ID}}\t{{.Names}}\t{{.State}}\t'
           '{{.Label "' + LABEL_RUN_ID + '"}}\t{{.Label "' + LABEL_CREATED + '"}}')
    r = _docker(["ps", "--all", "--filter", f"label={LABEL_MANAGED}=true",
                 "--format", fmt], binary=binary)
    out: list[dict[str, str]] = []
    if not r.ok:
        return out
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        out.append({"id": parts[0], "name": parts[1], "state": parts[2],
                    "run_id": parts[3], "created_at": parts[4]})
    return out


def reap(*, run_id: str | None, binary: str = DOCKER_BINARY,
         orphan_ttl: int = ORPHAN_TTL_SECONDS) -> dict[str, Any]:
    """Remove PyHunt's containers by label. Survives SIGKILL of the run that made them.

    Three rules, and the middle one is the whole reason labels exist:

    * containers of `run_id` — removed unconditionally, this is our own cleanup;
    * containers of ANY other run that are no longer running — removed, they are
      finished wreckage;
    * containers of another run that are STILL running — removed only once older
      than `orphan_ttl`. Every PyHunt container has a wall clock measured in
      minutes, so age past that threshold means a SIGKILLed run left it behind,
      while a shorter-lived one may belong to a concurrent run that is doing
      fine and must not be killed.

    Networks are removed only when Docker says they are unused; an in-use
    removal failure is the natural interlock against tearing the network out
    from under a concurrent run, so it is treated as "left alone", not an error.
    """
    now = int(time.time())
    removed: list[str] = []
    kept: list[str] = []

    for c in _list_managed_containers(binary=binary):
        mine = run_id is not None and c["run_id"] == run_id
        running = c["state"].lower() == "running"
        try:
            age = now - int(c["created_at"])
        except (TypeError, ValueError):
            age = orphan_ttl + 1        # unlabelled age: treat as old wreckage
        if mine or not running or age > orphan_ttl:
            r = _docker(["rm", "--force", c["id"]], binary=binary)
            (removed if r.ok else kept).append(c["name"])
        else:
            kept.append(c["name"])

    networks_removed: list[str] = []
    networks_kept: list[str] = []
    nets = _docker(["network", "ls", "--filter", f"label={LABEL_MANAGED}=true",
                    "--format", "{{.Name}}"], binary=binary)
    if nets.ok:
        for name in (n.strip() for n in nets.stdout.splitlines() if n.strip()):
            r = _docker(["network", "rm", name], binary=binary)
            (networks_removed if r.ok else networks_kept).append(name)

    return {"containers_removed": removed, "containers_kept": kept,
            "networks_removed": networks_removed, "networks_kept": networks_kept}


def down(results_dir: Path, *, binary: str = DOCKER_BINARY) -> dict[str, Any]:
    """Tear this run's sandbox down and reap what earlier runs left behind."""
    results_dir = Path(results_dir)
    run_id = run_id_for(results_dir)
    result = reap(run_id=run_id, binary=binary)
    payload = {"run_id": run_id, "status": "down", "teardown": result,
               "torn_down_at": int(time.time())}
    try:
        merge_preflight(results_dir, payload)
    except OSError as e:                             # pragma: no cover - disk guard
        log.warning("[sandbox] could not record teardown: %s", e)
    return payload


# ===========================================================================
# Part 11 — CLI
# ===========================================================================

def _emit(payload: Mapping[str, Any]) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _note(message: str) -> None:
    print(message, file=sys.stderr)


def cmd_detect(args: argparse.Namespace) -> int:
    detection = detect(binary=args.docker, probe_network=not args.no_network_probe)
    payload = detection.to_dict()
    if args.results_dir:
        merge_preflight(Path(args.results_dir), {"detection": payload,
                                                 "tier": detection.tier,
                                                 "proof_allowed": detection.proof_allowed})
    _emit(payload)
    _note(f"[sandbox] tier={detection.tier} proof_allowed={detection.proof_allowed}")
    for reason in detection.reasons:
        _note(f"[sandbox]   - {reason}")
    return EXIT_OK


def cmd_up(args: argparse.Namespace) -> int:
    state = up(Path(args.repo), Path(args.results_dir),
               build_image=not args.no_build,
               allowlist=tuple(a for a in args.allow.split(",") if a.strip()),
               binary=args.docker)
    _emit(state)
    _note(f"[sandbox] {state.get('status')}: {state.get('note', '')}")
    if state.get("status") == "failed":
        return EXIT_CONTRACT_VIOLATION
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    result = verify_isolation(Path(args.results_dir), binary=args.docker)
    merge_preflight(Path(args.results_dir), {"verification": result.to_dict()})
    _emit(result.to_dict())
    for assertion in result.assertions:
        mark = "PASS" if assertion.get("passed") else "FAIL"
        _note(f"[sandbox] {mark} {assertion.get('assertion')}: {assertion.get('detail')}")
    _note(f"[sandbox] {result.note}")
    return EXIT_OK if result.passed else EXIT_CONTRACT_VIOLATION


def cmd_down(args: argparse.Namespace) -> int:
    payload = down(Path(args.results_dir), binary=args.docker)
    _emit(payload)
    t = payload["teardown"]
    _note(f"[sandbox] removed {len(t['containers_removed'])} container(s), "
          f"{len(t['networks_removed'])} network(s)")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sandbox.py",
        description="Detect, create, verify and tear down PyHunt's tiered isolation.",
    )
    parser.add_argument("--docker", default=DOCKER_BINARY,
                        help="docker binary to use (default: %(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_detect = sub.add_parser("detect", help="report the isolation tier this host can offer")
    p_detect.add_argument("--results-dir", help="record the detection in preflight.json")
    p_detect.add_argument("--no-network-probe", action="store_true",
                          help="skip creating a throwaway internal network")
    p_detect.set_defaults(func=cmd_detect)

    p_up = sub.add_parser("up", help="create the sandbox network, proxy and target image")
    p_up.add_argument("--repo", required=True, help="path to the target repository")
    p_up.add_argument("--results-dir", required=True)
    p_up.add_argument("--no-build", action="store_true",
                      help="do not build the provisioned target image if it is missing")
    p_up.add_argument("--allow", default=",".join(DEFAULT_EGRESS_ALLOWLIST),
                      help="egress allowlist, host:port[,host:port] (default: %(default)s)")
    p_up.set_defaults(func=cmd_up)

    p_verify = sub.add_parser(
        "verify", help="assert isolation from inside a throwaway container (exit 2 on failure)")
    p_verify.add_argument("--results-dir", required=True)
    p_verify.set_defaults(func=cmd_verify)

    p_down = sub.add_parser("down", help="tear down this run and reap orphans")
    p_down.add_argument("--results-dir", required=True)
    p_down.set_defaults(func=cmd_down)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="[%(levelname)s] %(message)s")
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args))
    except SandboxError as e:
        _note(f"[sandbox] contract violation: {e}")
        return EXIT_CONTRACT_VIOLATION
    except Exception as e:                           # pragma: no cover - top-level guard
        log.exception("[sandbox] internal error")
        _note(f"[sandbox] internal error: {type(e).__name__}: {e}")
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
