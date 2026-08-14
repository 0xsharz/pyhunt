"""Phase 2 provisioning: BUILD the rendered recipe, VERIFY it, REPAIR and retry.

Phase 1 (`fingerprint.py` + `dockerfile.py`) is text-only. This module is the
part that actually talks to Docker:

    fingerprint -> render -> [ docker build -> repair -> retry ]* -> verify

**Isolation stance.** Building a target's environment means running that
target's own build instructions (`npm ci` runs postinstall scripts, `mvn
package` runs plugins). VASH therefore NEVER runs them on the host: every
command issued here executes inside a container, and the verify step runs with
``--network none``, dropped privileges and cpu/memory/pid caps. Provisioning
is additionally **opt-in** (`vash run --provision` / `vash provision --build`)
— it never happens implicitly.

The Docker calls sit behind the small :class:`DockerClient` protocol so the
whole loop — including every repair rung — is unit-tested offline with a fake
client. No test in the suite runs Docker.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Protocol

from provision.dockerfile import (
    DEPS_UNKNOWN_MARKER,
    RenderedRecipe,
    render_dockerfile,
)
from provision.fingerprint import ProjectFingerprint, fingerprint
from provision.repair import repair_dockerfile

log = logging.getLogger(__name__)

DEFAULT_BUILD_TIMEOUT = 900       # seconds — a cold base-image pull is slow
DEFAULT_VERIFY_TIMEOUT = 600
DEFAULT_MAX_ATTEMPTS = 4          # 1 build + at most 3 repairs
# Not a rule in provision/repair.py's ladder: it needs the fingerprint and the
# repo path, which a (dockerfile, log) transform does not get. It is applied by
# provision_environment and named here so the two agree on one spelling.
_FALLBACK_RULE = "fallback_to_generated_recipe"
LOG_TAIL_CHARS = 4000             # what we keep of a (possibly huge) build log

# Container resource caps for the verify step. Deliberately modest: verification
# only needs to prove the environment is usable, not to be fast.
VERIFY_MEMORY = "4g"
VERIFY_CPUS = "2"
VERIFY_PIDS = "512"


def _tail(text: str, limit: int = LOG_TAIL_CHARS) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return "...[truncated]...\n" + text[-limit:]


#: Lines worth quoting back when a build fails, most specific first. A build
#: log ends with a generic "process did not complete successfully" that says
#: nothing; the useful line is several hundred lines above it.
_DECISIVE_ERROR_PATTERNS = (
    r"^.*\b(?:LookupError|ImportError|ModuleNotFoundError|FileNotFoundError|"
    r"PermissionError|OSError)\b.*$",
    r"^.*error: .*$",
    r"^.*ERROR: .*$",
    r"^.*\bfatal error\b.*$",
    r"^.*\bnot found\b.*$",
    r"^.*\bfailed\b.*$",
)


def _decisive_error_line(log_text: str, limit: int = 300) -> str:
    """The most informative single line in a build log.

    Preferring a named exception or an ``error:`` line over the generic
    "process did not complete successfully" that Docker ends with. Returns ""
    when nothing matches, so the caller can say so rather than quote noise.
    """
    lines = [ln.strip() for ln in (log_text or "").splitlines() if ln.strip()]
    if not lines:
        return ""
    for pattern in _DECISIVE_ERROR_PATTERNS:
        rx = re.compile(pattern, re.I)
        for line in reversed(lines):
            if "did not complete successfully" in line:
                continue
            if rx.match(line):
                return line[:limit]
    return ""


@dataclass
class CommandResult:
    exit_code: int
    log: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class DockerClient(Protocol):
    """Everything this module needs from Docker (fakeable in tests)."""

    def available(self) -> bool: ...

    def build(self, *, context: Path, dockerfile: str, tag: str,
              timeout: int) -> CommandResult: ...

    def run(self, *, tag: str, command: str, workdir: str, timeout: int,
            network: str) -> CommandResult: ...


class SubprocessDocker:
    """The real client: shells out to the `docker` CLI.

    Shelling out (rather than adding the `docker` SDK) keeps the dependency
    set unchanged and matches how VASH already invokes `graphify`.
    """

    def __init__(self, binary: str = "docker") -> None:
        self.binary = binary

    def available(self) -> bool:
        """True only if the CLI exists AND the daemon answers."""
        if shutil.which(self.binary) is None:
            return False
        try:
            p = subprocess.run(
                [self.binary, "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return p.returncode == 0 and bool(p.stdout.strip())

    def _exec(self, argv: list[str], *, timeout: int,
              stdin: str | None = None) -> CommandResult:
        try:
            p = subprocess.run(
                argv, input=stdin, capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or "") if isinstance(e.stdout, str) else ""
            err = (e.stderr or "") if isinstance(e.stderr, str) else ""
            return CommandResult(exit_code=124, log=_tail(out + err), timed_out=True)
        except OSError as e:
            return CommandResult(exit_code=127, log=f"{type(e).__name__}: {e}")
        return CommandResult(exit_code=p.returncode, log=_tail(p.stdout + p.stderr))

    def build(self, *, context: Path, dockerfile: str, tag: str,
              timeout: int) -> CommandResult:
        # `-f -` feeds the Dockerfile on stdin, so a repaired Dockerfile is
        # never written into the target repo (the target tree stays read-only).
        return self._exec(
            [self.binary, "build", "--tag", tag, "--file", "-", str(context)],
            timeout=timeout, stdin=dockerfile,
        )

    def run(self, *, tag: str, command: str, workdir: str, timeout: int,
            network: str) -> CommandResult:
        return self._exec(
            [
                self.binary, "run", "--rm",
                "--network", network,
                "--memory", VERIFY_MEMORY,
                "--cpus", VERIFY_CPUS,
                "--pids-limit", VERIFY_PIDS,
                "--security-opt", "no-new-privileges",
                "--workdir", workdir,
                "--entrypoint", "/bin/sh",
                tag, "-c", command,
            ],
            timeout=timeout,
        )


# ---------------------------------------------------------------------------
# result records
# ---------------------------------------------------------------------------

@dataclass
class BuildAttempt:
    attempt: int
    ok: bool
    exit_code: int
    timed_out: bool = False
    # the repair rule applied to produce THIS attempt's Dockerfile
    # (None for the first attempt, which uses the rendered recipe as-is).
    repair_rule: str | None = None
    log_tail: str = ""


@dataclass
class VerifyResult:
    ran: bool = False
    build_ok: bool | None = None
    build_log_tail: str = ""
    test_ok: bool | None = None
    test_log_tail: str = ""
    # dependency-presence probe (see RenderedRecipe.deps_cmd): False means the
    # image built but the target's declared dependencies are NOT installed.
    deps_ok: bool | None = None
    deps_log_tail: str = ""


@dataclass
class ProvisionResult:
    # planned        : recipe rendered, no Docker asked for (the default `vash run`)
    # preprovisioned : already running inside the target's scan image — the
    #                  toolchain and the target's deps are present in THIS container
    # built   : image exists
    # failed  : Docker tried and the repair ladder was exhausted
    # skipped : nothing to build (no known ecosystem / Docker unavailable)
    status: str = "skipped"
    source: str = "none"                 # existing | template | none
    image_tag: str | None = None
    dockerfile: str | None = None
    build_cmd: str | None = None
    test_cmd: str | None = None
    fingerprint: dict = field(default_factory=dict)
    attempts: list[BuildAttempt] = field(default_factory=list)
    verify: VerifyResult | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def agent_summary(self) -> dict:
        """The compact environment facts worth putting in front of an agent.

        Deliberately small (no logs, no Dockerfile) — this rides along in every
        stage's user_input, so it must stay a handful of lines.
        """
        fp = self.fingerprint
        out: dict = {
            "languages": fp.get("languages", []),
            "primary_language": fp.get("primary_language"),
            "build_systems": fp.get("build_systems", []),
            "provisioning_status": self.status,
        }
        if fp.get("version_pins"):
            out["version_pins"] = fp["version_pins"]
        if self.image_tag and self.status == "built":
            out["image_tag"] = self.image_tag
        if self.build_cmd:
            out["build_cmd"] = self.build_cmd
        if self.test_cmd:
            out["test_cmd"] = self.test_cmd
        incomplete = [n for n in self.notes if "INCOMPLETE" in n]
        if incomplete:
            out["environment_caveat"] = incomplete[0]
        return out


# ---------------------------------------------------------------------------
# the provisioning loop
# ---------------------------------------------------------------------------

_TAG_SAFE = re.compile(r"[^a-z0-9_.-]+")


def image_tag_for(repo_path: Path) -> str:
    """A deterministic, Docker-legal tag for a target repo."""
    name = _TAG_SAFE.sub("-", repo_path.name.lower()).strip("-.") or "target"
    return f"vash-env-{name}:latest"


def _recipe_dockerfile(recipe: RenderedRecipe, repo_path: Path) -> tuple[str | None, str | None]:
    """The Dockerfile TEXT for a rendered recipe. For `source="existing"` that
    means reading the target's own file (returned as text, never edited in
    place). Returns (text, error)."""
    if recipe.source == "template":
        return recipe.dockerfile, None
    if recipe.source == "existing" and recipe.path:
        p = repo_path / recipe.path
        try:
            return p.read_text(encoding="utf-8", errors="replace"), None
        except OSError as e:
            return None, f"could not read existing recipe {recipe.path}: {e}"
    return None, "no build recipe to build"


_DEP_MANIFESTS = (
    "requirements.txt", "requirements/*.txt", "requirements/*.in",
    "requirements-*.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "package.json",
    "go.mod", "go.sum", "pom.xml", "build.gradle", "Gemfile",
)


def _dockerignore_hidden_manifests(repo_path: Path) -> tuple[list[str], list[str]]:
    """Dependency manifests that exist in the repo but that its `.dockerignore`
    keeps out of the build context, and the patterns responsible.

    A repo's `.dockerignore` is written for the repo's own build, and that
    build often has a step the provisioner does not run. A pip-tools project
    ignores `requirements/*.in` because its Makefile compiles them to pinned
    `.txt` files first; adopting the ignore file verbatim therefore produces a
    context with no dependency declarations in it at all, an image with none of
    the target's dependencies installed, and a PoC that fails on
    `ModuleNotFoundError` for an environment reason. Observed exactly that way
    on a FastAPI target whose `.dockerignore` listed `*.txt` and
    `requirements/*.in`.

    Matching is fnmatch over the pattern and over its `**/`-stripped form,
    which is close enough to Docker's rules for the manifest names above.
    """
    ignore_file = repo_path / ".dockerignore"
    if not ignore_file.is_file():
        return [], []
    try:
        patterns = [
            ln.strip() for ln in ignore_file.read_text(
                encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
            and not ln.strip().startswith("!")
        ]
    except OSError:
        return [], []

    present: list[str] = []
    for glob in _DEP_MANIFESTS:
        present += [
            p.relative_to(repo_path).as_posix()
            for p in repo_path.glob(glob) if p.is_file()
        ]

    hidden, culprits = [], []
    for rel in sorted(set(present)):
        for pat in patterns:
            bare = pat[3:] if pat.startswith("**/") else pat
            if (fnmatch(rel, pat) or fnmatch(rel, bare)
                    or fnmatch(Path(rel).name, bare)
                    or rel.startswith(pat.rstrip("/") + "/")):
                hidden.append(rel)
                if pat not in culprits:
                    culprits.append(pat)
                break
    return hidden, culprits


def _context_with_manifests(repo_path: Path, culprits: list[str]) -> Path:
    """A throwaway copy of the build context whose `.dockerignore` no longer
    excludes dependency manifests. The target repository is never written to —
    `repo_guard.py` asserts that, and the honest way to change what Docker sees
    is to change the copy."""
    tmp = Path(tempfile.mkdtemp(prefix="pyhunt-ctx-")) / "ctx"
    shutil.copytree(repo_path, tmp, ignore=shutil.ignore_patterns(".git"),
                    symlinks=True)
    di = tmp / ".dockerignore"
    if di.is_file():
        kept = [
            ln for ln in di.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() not in culprits
        ]
        kept.append("# pyhunt: patterns hiding dependency manifests removed — "
                    + ", ".join(culprits))
        di.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return tmp


def _verify(client: DockerClient, tag: str, recipe: RenderedRecipe, *,
            timeout: int, network: str, workdir: str) -> VerifyResult:
    """Prove the image is actually usable: the dependency probe first (the
    check that matters for a PoC — are the target's dependencies installed?),
    then the ecosystem's build and test commands. All inside the container,
    offline by default."""
    v = VerifyResult(ran=True)
    if recipe.deps_cmd:
        r = client.run(tag=tag, command=recipe.deps_cmd, workdir=workdir,
                       timeout=timeout, network=network)
        # A probe that could not list the installed packages exits 0 so it is
        # not mistaken for a failure — but "I could not check" is not "it is
        # fine" either, so it lands on None (unknown) rather than True.
        v.deps_ok = None if DEPS_UNKNOWN_MARKER in (r.log or "") else r.ok
        v.deps_log_tail = _tail(r.log, 2000)
    if recipe.build_cmd:
        r = client.run(tag=tag, command=recipe.build_cmd, workdir=workdir,
                       timeout=timeout, network=network)
        v.build_ok = r.ok
        v.build_log_tail = _tail(r.log, 2000)
    if recipe.test_cmd:
        r = client.run(tag=tag, command=recipe.test_cmd, workdir=workdir,
                       timeout=timeout, network=network)
        v.test_ok = r.ok
        v.test_log_tail = _tail(r.log, 2000)
    return v


def provision_environment(
    repo_path: Path,
    *,
    build: bool = False,
    client: DockerClient | None = None,
    tag: str | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    verify: bool = True,
    build_timeout: int = DEFAULT_BUILD_TIMEOUT,
    verify_timeout: int = DEFAULT_VERIFY_TIMEOUT,
    verify_network: str = "none",
    fp: ProjectFingerprint | None = None,
) -> ProvisionResult:
    """Fingerprint a repo, render its Dockerfile and (when `build=True`) build,
    repair and verify it.

    `build=False` is the cheap default: pure Phase-1 text work, zero Docker,
    which is what the pipeline runs unless the operator opts in. `build=True`
    executes the target's build instructions — inside a container, never on the
    host (see the module docstring).
    """
    repo_path = Path(repo_path)
    fp = fp or fingerprint(repo_path)
    recipe = render_dockerfile(fp, repo_path)
    result = ProvisionResult(
        source=recipe.source,
        build_cmd=recipe.build_cmd,
        test_cmd=recipe.test_cmd,
        fingerprint=asdict(fp),
        notes=list(recipe.notes),
    )

    dockerfile, err = _recipe_dockerfile(recipe, repo_path)
    if dockerfile is None:
        result.status = "skipped"
        if err:
            result.notes.append(err)
        return result
    result.dockerfile = dockerfile

    if not build:
        # Already running inside the target's scan image (vash-scan-<target>):
        # the toolchain and the target's dependencies are present RIGHT HERE, so
        # reporting "planned" would tell the hunter the opposite of the truth
        # and make it distrust deps_hint's "just import the target".
        preprovisioned = os.environ.get("VASH_SCAN_IMAGE", "").strip()
        if preprovisioned:
            result.status = "preprovisioned"
            result.notes.append(
                f"running inside the target's scan image ({preprovisioned}) — "
                "the target's toolchain and dependencies are already installed "
                "in this container; PoCs can use them directly"
            )
            return result
        result.status = "planned"
        result.notes.append(
            "recipe rendered only — no image built "
            "(`vash provision --build` / `vash run --provision` builds it)"
        )
        return result

    client = client or SubprocessDocker()
    if not client.available():
        result.status = "skipped"
        result.notes.append(
            "docker unavailable (CLI missing or daemon not responding) — "
            "provisioning skipped, the run continues static-only"
        )
        return result

    result.image_tag = tag or image_tag_for(repo_path)
    applied: set[str] = set()
    pending_rule: str | None = None

    build_context = repo_path
    scratch_context: Path | None = None
    hidden, culprits = _dockerignore_hidden_manifests(repo_path)
    if hidden:
        try:
            scratch_context = _context_with_manifests(repo_path, culprits)
            build_context = scratch_context
            result.notes.append(
                "the target's .dockerignore excluded "
                f"{len(hidden)} dependency manifest(s) ({', '.join(hidden[:5])}"
                f"{'…' if len(hidden) > 5 else ''}) via {', '.join(culprits)}; "
                "built from a copy of the context with those patterns removed "
                "— the target repository itself is untouched"
            )
        except OSError as e:
            result.notes.append(
                "the target's .dockerignore excludes dependency manifests "
                f"({', '.join(culprits)}) and the context copy failed ({e}); "
                "the image may be INCOMPLETE"
            )

    for n in range(1, max(1, max_attempts) + 1):
        r = client.build(context=build_context, dockerfile=dockerfile,
                         tag=result.image_tag, timeout=build_timeout)
        result.attempts.append(BuildAttempt(
            attempt=n, ok=r.ok, exit_code=r.exit_code, timed_out=r.timed_out,
            repair_rule=pending_rule, log_tail=_tail(r.log, 2000),
        ))
        if r.ok:
            result.status = "built"
            break
        if r.timed_out:
            result.notes.append(
                f"build timed out after {build_timeout}s — not retried"
            )
            result.status = "failed"
            break
        if n == max_attempts:
            result.status = "failed"
            result.notes.append(f"build failed after {n} attempt(s)")
            break
        fix = repair_dockerfile(dockerfile, r.log, already_applied=frozenset(applied))

        # The repo's own Dockerfile is the highest-signal recipe and the wrong
        # thing to keep patching once it has failed for a reason no rule
        # recognises, or once the only rule left is "make the install
        # non-fatal". Both endings hand the pipeline an image holding the
        # target's source and none of its dependencies, which is the shape
        # every PoC then fails against for an environment reason. Re-render
        # from the fingerprint instead: the templated recipe is written to
        # tolerate what a vendored one assumes.
        if (recipe.source == "existing"
                and _FALLBACK_RULE not in applied
                and (fix is None or fix.rule == "soften_install_step")):
            alt = render_dockerfile(fp, repo_path, ignore_existing=True)
            alt_dockerfile, _ = _recipe_dockerfile(alt, repo_path)
            if alt_dockerfile:
                dockerfile = alt_dockerfile
                recipe = alt
                result.source = alt.source
                result.build_cmd = alt.build_cmd
                result.test_cmd = alt.test_cmd
                applied.add(_FALLBACK_RULE)
                pending_rule = _FALLBACK_RULE
                result.dockerfile = dockerfile
                note = (f"repair[{_FALLBACK_RULE}]: the repo's own Dockerfile "
                        "could not be repaired; rebuilt from PyHunt's templated "
                        f"recipe ({'; '.join(alt.notes) or alt.source})")
                result.notes.append(note)
                log.info("[provision] build attempt %d failed -> repair %s", n, _FALLBACK_RULE)
                continue

        if fix is None:
            result.status = "failed"
            # Quote the decisive line. This used to say "see the last attempt
            # log" and name no path, and no log file was written anywhere —
            # so the one message a failed provision produced told the reader
            # to go and read something that did not exist. The tail is already
            # captured on the attempt; the least it can do is show the error.
            result.notes.append(
                "build failed and no repair rule matched. Decisive line: "
                + (_decisive_error_line(r.log) or "(no error line recognised)")
                + f" — full output in attempts[{n - 1}].log_tail of this result"
            )
            break
        dockerfile = fix.dockerfile
        applied.add(fix.rule)
        pending_rule = fix.rule
        result.dockerfile = dockerfile
        result.notes.append(f"repair[{fix.rule}]: {fix.note}")
        log.info("[provision] build attempt %d failed -> repair %s", n, fix.rule)

    if result.status == "built" and verify and (
            recipe.build_cmd or recipe.test_cmd or recipe.deps_cmd):
        result.verify = _verify(
            client, result.image_tag, recipe,
            timeout=verify_timeout, network=verify_network, workdir="/target",
        )
        if result.verify.deps_ok is False:
            result.notes.append(
                "verify: the target's declared dependencies are NOT installed "
                "in the image — the environment is INCOMPLETE "
                f"({result.verify.deps_log_tail.strip()[:200]})"
            )
        elif (result.verify.deps_ok is None
                and DEPS_UNKNOWN_MARKER in (result.verify.deps_log_tail or "")):
            result.notes.append(
                "verify: could NOT check whether the target's dependencies are "
                "installed — treat the environment as UNVERIFIED, not as ready "
                f"({result.verify.deps_log_tail.strip()[:200]})"
            )
        if result.verify.build_ok is False:
            result.notes.append(
                "verify: the ecosystem build command failed inside the image — "
                "the environment may be INCOMPLETE"
            )
    if scratch_context is not None:
        shutil.rmtree(scratch_context.parent, ignore_errors=True)
    return result
