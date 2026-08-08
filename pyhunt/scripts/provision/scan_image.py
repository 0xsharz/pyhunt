"""Render and build the SCAN image: the target's provisioned image with the
PyHunt skill laid on top.

The phase-0 file names a container this module is the recipe for. From
``phases/phase0_preflight.md``:

    ``preflight.py check --execution`` exists solely for an invocation from
    *inside* the provisioned scan container.

The executing capability probes — *can a PoC actually import the target?* — have
to run the target's module-level code, so they may only run somewhere that
already contains both the target's environment **and** PyHunt's scripts. Neither
image alone is that: the provisioned image (``provision/build.py``) has the
target and none of PyHunt, and there is no PyHunt image at all any more. This
module produces the union.

**Nothing in the skill's phase path builds it today, and this file does not
pretend otherwise.** ``sandbox.py up`` provisions the target image and stops
there; ``replay.py`` deliberately starts each PoC from that image *unmodified*,
because its trust argument is that the hunt agent cannot retroactively change
what the container starts from. So the union image has one documented consumer
(``preflight.py check --execution``) and no caller yet. That gap is recorded in
``plan/PLAN.md`` rather than papered over here.

What changed from the VASH ancestor of this file, and why — each removal is a
consequence of a locked decision, not of the knowledge going stale:

* It used to ``COPY vash prompts schemas config`` and set
  ``ENTRYPOINT ["/opt/vashvenv/bin/vash"]``. **D-2** deleted the CLI, so that
  entrypoint names a binary that cannot exist; ``vash/`` is the parent
  project's package name; and the skill carries its own ``schemas/``. The
  payload below is the skill directory as it is actually laid out on disk.
* It installed node and the ``claude`` CLI, because VASH ran the *agent* inside
  the container. Under **D-2** the agent is Claude Code on the operator's host
  and only the PoC crosses the boundary, so an npm install here would buy
  nothing.
* It installed ``strace`` as the observer for compiled languages. **D-5** made
  the analysis Python-only; the observer is an in-process PEP-578 audit hook and
  there is no compiled-language PoC left to watch at the syscall boundary.

What is deliberately *kept* is the pair of lessons that were paid for in failed
builds and are still true of any Debian-family base: probe ``venv`` by attempting
one rather than by checking a version, and keep PyHunt's interpreter off
``PATH``. Both are commented at their line.

Text generation plus a ``docker build``; nothing here executes target code.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from provision.build import (
    DEFAULT_BUILD_TIMEOUT,
    CommandResult,
    DockerClient,
    SubprocessDocker,
    _TAG_SAFE,
    _tail,
)

log = logging.getLogger(__name__)

#: The skill directory — the build context, and the thing that gets installed.
#:
#: ``scripts/provision/scan_image.py`` -> ``scripts/provision`` -> ``scripts``
#: -> the skill root (the directory holding ``SKILL.md``). The skill root rather
#: than the repository root on purpose: an *installed* skill under
#: ``~/.claude/skills/pyhunt/`` has no repository above it, and a source root
#: that only resolves in a dev checkout would make this module unbuildable
#: exactly where it would be used.
SKILL_SOURCE_ROOT = Path(__file__).resolve().parents[2]

#: Where the skill lands inside the image. ``_bootstrap.py`` derives the skill
#: root from its own ``__file__``, so the only requirement is that the tree stay
#: intact — ``scripts/`` beside ``schemas/`` beside ``.venv/``.
SKILL_DIR = "/app/pyhunt"

#: The bundled venv, in the one place ``scripts/_bootstrap.py`` looks for it:
#: ``<skill root>/.venv``. Deliberately NOT on PATH — see the rendered comment.
VENV = f"{SKILL_DIR}/.venv"

#: Runtime dependencies of the skill's scripts. The same pair as
#: ``install.sh``'s ``DEPS`` and ``_bootstrap.REQUIRED_MODULES``; a mismatch
#: shows up as an ``ImportError`` on the first script the container runs.
DEPS = "jsonschema>=4.21 pyyaml>=6.0"


def scan_image_tag_for(repo_path: Path) -> str:
    """Deterministic tag for a target's scan image."""
    name = _TAG_SAFE.sub("-", Path(repo_path).name.lower()).strip("-.") or "target"
    return f"pyhunt-scan-{name}:latest"


#: The skill, copied out of ``SKILL_SOURCE_ROOT``. Every entry is a real
#: top-level member of the skill directory; ``tests/provision/test_scan_image.py``
#: asserts that against the filesystem, so a rename cannot leave this list
#: describing a layout that no longer exists.
#:
#: ``.venv/`` is pointedly absent: the host's bundled venv has this machine's
#: paths and ABI baked in, and the image builds its own below.
_SKILL_PAYLOAD: tuple[tuple[str, str], ...] = (
    ("SKILL.md", f"{SKILL_DIR}/SKILL.md"),
    ("phases", f"{SKILL_DIR}/phases"),
    ("references", f"{SKILL_DIR}/references"),
    ("schemas", f"{SKILL_DIR}/schemas"),
    ("scripts", f"{SKILL_DIR}/scripts"),
)

#: Attribution. PyHunt derives from Apache-2.0 work, and Apache-2.0 §4 requires
#: the NOTICE to travel with the distributed work — an image is a distribution.
#: ``install.sh`` puts these three inside the installed skill for exactly this
#: reason, so they are present when the context is an installed skill. A dev
#: checkout keeps them at the repository root instead, one level above the
#: context; :func:`build_scan_image` detects that and says so rather than
#: rendering a ``COPY`` that would fail the build.
_ATTRIBUTION_PAYLOAD: tuple[tuple[str, str], ...] = (
    ("NOTICE", f"{SKILL_DIR}/NOTICE"),
    ("LICENSE", f"{SKILL_DIR}/LICENSE"),
    ("licenses", f"{SKILL_DIR}/licenses"),
)


def attribution_present(source_root: Path) -> bool:
    """True when every attribution file is inside ``source_root``."""
    return all((Path(source_root) / src).exists() for src, _ in _ATTRIBUTION_PAYLOAD)


# Create the skill's venv. The base is the target's own provisioned image, so
# its Python is whatever the target needs — possibly python:3.11-slim (python
# plus a working venv), possibly a Debian base whose python3.11 has a BROKEN
# `venv` until the separate python3-venv package is installed.
#
# The probe therefore ATTEMPTS A THROWAWAY VENV rather than merely checking the
# version — observed on node:20, where `python3 -c 'sys.version_info >= (3,11)'`
# passes and `python3 -m venv` then fails with "you need to install the
# python3-venv package", taking the fast path straight into a build error. Check
# for what you are about to use, not for a proxy of it.
#
# uv is the universal fallback: it installs a private 3.11 with no distro
# package and no root.
_VENV_SETUP = f"""RUN set -eu; \\
    if command -v python3 >/dev/null 2>&1 \\
       && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \\
       && python3 -m venv /tmp/pyhunt-venv-probe >/dev/null 2>&1; then \\
        rm -rf /tmp/pyhunt-venv-probe; \\
        python3 -m venv {VENV}; \\
        {VENV}/bin/pip install --no-cache-dir {DEPS}; \\
    else \\
        rm -rf /tmp/pyhunt-venv-probe; \\
        curl -LsSf https://astral.sh/uv/install.sh | sh; \\
        export PATH="/root/.local/bin:$PATH"; \\
        uv python install 3.11; \\
        uv venv --python 3.11 {VENV}; \\
        uv pip install --python {VENV}/bin/python --no-cache {DEPS}; \\
    fi"""


def render_scan_dockerfile(base_image: str, *, include_attribution: bool = True) -> str:
    """Dockerfile text for a scan image layered on ``base_image``.

    ``base_image`` is normally the provisioned target image from
    ``provision/build.py``, but any image the target builds in works.

    ``include_attribution`` renders the ``COPY`` for ``NOTICE``/``LICENSE``/
    ``licenses/``. It is a parameter rather than a filesystem probe so that the
    rendered text depends only on the arguments — the caller decides, and the
    decision is visible in the result.
    """
    payload = _SKILL_PAYLOAD + (_ATTRIBUTION_PAYLOAD if include_attribution else ())
    copies = "\n".join(f"COPY {src} {dst}" for src, dst in payload)
    return f"""# GENERATED BY PYHUNT (scripts/provision/scan_image.py) — do not edit by hand.
# The scan container IS the target's environment: this layers the PyHunt skill
# on top of the provisioned image, so an in-container probe can import the real
# target instead of guessing whether it would import.
FROM {base_image}

# curl + ca-certificates: the uv fallback below fetches an interpreter when the
# base image's python cannot make a venv. build-essential: source builds of the
# two runtime deps on a base with no matching wheel.
#
# No `git` (history mining runs on the operator's host, in phase 1) and no
# `strace` (D-5 — the analysis is Python-only, and its observer is an in-process
# PEP-578 audit hook, so there is no compiled binary to watch at the syscall
# boundary).
RUN apt-get update && apt-get install -y --no-install-recommends \\
        build-essential curl ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
{copies}

{_VENV_SETUP}

# *** LOAD-BEARING: PyHunt's venv is deliberately NOT added to PATH. ***
# If it were, `python3` inside the container would resolve to PyHunt's own
# interpreter, where the TARGET's code and dependencies are invisible — the very
# import an in-container probe exists to test would fail (observed: `import
# app.reports` -> ModuleNotFoundError under PyHunt's interpreter, while the
# target's own interpreter imported it fine). Instead the venv sits at
# <skill>/.venv, which is where scripts/_bootstrap.py looks: the skill's scripts
# are invoked by absolute path with the TARGET's `python3`, and _bootstrap either
# adds the bundled site-packages or hands over to the bundled interpreter.
#
#   python3 {SKILL_DIR}/scripts/preflight.py check --repo /target --execution
#
ENV PYHUNT_SANDBOX=1
# VASH_SANDBOX is the same signal under the ancestor's name. scripts/sandbox.py
# still honours both, and images built before the rename set only the old one;
# dropping it here would silently un-sandbox them.
ENV VASH_SANDBOX=1
# Tells a script running inside this image that it is executing INSIDE the
# target's provisioned environment — the toolchain and the target's dependencies
# are already present. Without it, provisioning reports itself as merely
# "planned" and a probe cannot tell whether "the target is installed, just import
# it" is actually true here. provision/build.py reads the VASH-named variable.
ENV PYHUNT_SCAN_IMAGE={base_image}
ENV VASH_SCAN_IMAGE={base_image}

# Reset the base image's own entrypoint. The provisioned image is the target's,
# and the target's entrypoint is frequently a server: inheriting it would make
# `docker run <scan image>` start the application under test instead of the
# probe that was asked for. There is no PyHunt entrypoint to put in its place —
# D-2 deleted the CLI, and the skill's scripts are invoked by absolute path.
ENTRYPOINT []
CMD ["/bin/sh"]
"""


@dataclass
class ScanImageResult:
    status: str = "skipped"          # built | failed | skipped
    tag: str | None = None
    base_image: str | None = None
    dockerfile: str | None = None
    exit_code: int | None = None
    log_tail: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


def build_scan_image(
    repo_path: Path,
    *,
    base_image: str,
    client: DockerClient | None = None,
    tag: str | None = None,
    skill_source: Path | None = None,
    timeout: int = DEFAULT_BUILD_TIMEOUT,
) -> ScanImageResult:
    """Build ``pyhunt-scan-<target>`` from ``base_image`` + this skill.

    Fail-soft: a failure is reported, never raised — the caller degrades to the
    provisioned image without PyHunt rather than losing the run.
    """
    result = ScanImageResult(
        base_image=base_image, tag=tag or scan_image_tag_for(repo_path)
    )
    # NOTE: the build context is the SKILL directory (that is what gets
    # installed), NOT the target repo — the target is already baked into
    # base_image by provisioning.
    context = Path(skill_source or SKILL_SOURCE_ROOT)

    with_attribution = attribution_present(context)
    dockerfile = render_scan_dockerfile(base_image, include_attribution=with_attribution)
    result.dockerfile = dockerfile
    if not with_attribution:
        result.notes.append(
            "NOTICE/LICENSE/licenses are not in the build context — this is a dev "
            "checkout, where they live at the repository root; an installed skill "
            "carries them and the image then ships the attribution"
        )

    client = client or SubprocessDocker()
    if not client.available():
        result.status = "skipped"
        result.notes.append("docker unavailable — scan image not built")
        return result

    r: CommandResult = client.build(
        context=context, dockerfile=dockerfile, tag=result.tag, timeout=timeout
    )
    result.exit_code = r.exit_code
    result.log_tail = _tail(r.log, 2000)
    if r.ok:
        result.status = "built"
        result.notes.append(
            f"scan image {result.tag} = {base_image} + the PyHunt skill "
            "(an in-container probe can now import the real target)"
        )
        log.info("[provision] scan image built: %s (from %s)", result.tag, base_image)
    else:
        result.status = "failed"
        result.notes.append(
            f"scan image build failed (exit {r.exit_code}) — the provisioned "
            "image is still usable for PoC replay, but nothing can run the "
            "skill's executing probes inside the target's environment"
        )
        log.warning("[provision] scan image build failed (exit %d)", r.exit_code)
    return result
