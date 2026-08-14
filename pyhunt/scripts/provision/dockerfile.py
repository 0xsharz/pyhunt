"""Render a Dockerfile for a fingerprinted repo. Prefers an existing repo
recipe; otherwise emits a per-ecosystem template STRING. Text only — this
module never runs `docker build` (`build.py` owns build/verify/repair)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from provision.fingerprint import ProjectFingerprint, _version_key

# Dependency-presence probe for the ecosystems whose `build` command cannot
# fail on missing dependencies (python's `python -c ...` and npm's
# `--if-present` are both no-ops on a bare image, so "built" would otherwise
# hide an environment with none of the target's dependencies installed).
# POSIX sh, offline, read-only. Go/Maven/Gradle/dotnet need no probe: their
# build command already fails hard when dependencies are missing.
#
# Two things this probe has to get right, both learned from a real target
# (worldbank/data360-mcp) where it reported MISSING for an image whose every
# dependency actually imported:
#
#   * A **marker** cannot be evaluated in POSIX sh. A universal lock exports
#     `pywin32==306 ; sys_platform == "win32"`, which will never be installed on
#     a linux image, so demanding it makes the probe fail permanently on any
#     project that depends on colorama/pywin32/keyring. Markered requirements
#     are therefore skipped, not required. That is a deliberate loss of
#     coverage: an unchecked conditional dependency is a smaller harm than a
#     probe that cries wolf on every build, because a warning that always fires
#     is a warning that stops being read.
#   * A **direct/VCS requirement** (`draco @ git+https://...`) is one name and
#     one URL. `pip freeze` was already stripping the URL, but the wanted side
#     was not, so the two could never match and every git dependency read as
#     missing.
#
# Names are normalised per PEP 503 (case, `_` and `.` all fold to `-`) so
# `zope.interface` and `zope-interface` are one package.
#   * If the installed-package list cannot be produced AT ALL, the answer is
#     "unknown", never "everything is missing". `pip freeze 2>/dev/null` on an
#     image without pip (a uv-built venv ships none) printed nothing, the wanted
#     set was compared against an empty set, and every single dependency was
#     reported missing — the loudest possible false alarm from the quietest
#     possible failure. The listing is attempted several ways, and if none work
#     the probe says so and declines to judge.
DEPS_UNKNOWN_MARKER = "DEPENDENCY CHECK NOT POSSIBLE"

#   * The wanted set is read from **every** place a Python project declares its
#     dependencies, not just `requirements.txt`. The probe used to open with
#     `[ -f requirements.txt ] || exit 0`, so a pip-tools layout shipping
#     `requirements/base.in`, or any pyproject-only project, produced "no
#     manifest" and the caller read the exit 0 as `deps_ok: True`. Observed on a
#     FastAPI target: the image had neither fastapi nor jinja2 installed and
#     provisioning reported the environment complete. Absence of a manifest is
#     now `unknown`; only a manifest that genuinely declares nothing passes.
# A `requirements/` directory is a mainstream pip-tools layout, and neither
# python template looked inside one: a target declaring fastapi and jinja2 in
# `requirements/base.in` got an image with neither. The `.in` files are
# installed too, because a repo that commits only the inputs and generates the
# pinned `.txt` at build time (via its Makefile, which the provisioner does not
# run) would otherwise contribute nothing. `-r` lines inside them resolve
# relative to the file, so a `base.in` including `common.in` still works.
_REQ_DIR_INSTALL = (
    "RUN for f in requirements/*.txt requirements/*.in requirements-*.txt; do \\\n"
    "        [ -f \"$f\" ] && (pip install --no-cache-dir -r \"$f\" || true); \\\n"
    "    done; true"
)

_PYPROJECT_DEPS = (
    "import sys;"
    "t=__import__('tomllib') if sys.version_info>=(3,11) else None;"
    "d=t.load(open('pyproject.toml','rb')) if t else {};"
    "p=(d.get('project') or {}).get('dependencies') or [];"
    "q=((d.get('tool') or {}).get('poetry') or {}).get('dependencies') or {};"
    "print(chr(10).join(list(p)+[k for k in q if k.lower()!='python']))"
)

_PIP_DEPS_PROBE = (
    ": > /tmp/want.raw; found=0; "
    "for f in requirements.txt requirements-*.txt requirements/*.txt "
    "requirements/*.in; do "
    "  [ -f \"$f\" ] && { found=1; cat \"$f\" >> /tmp/want.raw; }; "
    "done; "
    "pyx=''; for c in python3 python; do "
    "  command -v \"$c\" >/dev/null 2>&1 && { pyx=\"$c\"; break; }; done; "
    "if [ -f pyproject.toml ] && [ -n \"$pyx\" ]; then found=1; "
    f"  \"$pyx\" -c \"{_PYPROJECT_DEPS}\" >> /tmp/want.raw 2>/dev/null; fi; "
    f"[ \"$found\" = 1 ] || {{ echo '{DEPS_UNKNOWN_MARKER}: no dependency "
    "manifest found (requirements*.txt, requirements/*.in, pyproject.toml), so "
    "there is nothing to check the image against'; exit 0; }; "
    # `pip list --format=freeze` first, because plain `pip freeze` omits pip,
    # setuptools and wheel by design. A target that pins `pip~=25.3` in its
    # requirements therefore had pip itself reported as a missing dependency of
    # a correctly provisioned image — the false alarm mirrors the false green
    # above, and both make the probe's verdict worthless.
    "freeze=''; "
    "for c in 'pip list --format=freeze' 'pip3 list --format=freeze' "
    "'python3 -m pip list --format=freeze' 'pip freeze' 'pip3 freeze' "
    "'python3 -m pip freeze' 'python -m pip freeze' 'uv pip freeze'; do "
    "  if $c >/tmp/have.raw 2>/dev/null && [ -s /tmp/have.raw ]; then "
    "    freeze=\"$c\"; break; fi; "
    "done; "
    f"[ -n \"$freeze\" ] || {{ echo '{DEPS_UNKNOWN_MARKER}: no working pip in the "
    "image, so the installed packages could not be listed'; exit 0; }; "
    "grep -v '^-' /tmp/have.raw "
    "| sed -e 's/[[:space:]]*@.*//' -e 's/[=<>].*//' "
    "| tr 'A-Z_.' 'a-z--' | sort -u > /tmp/have; "
    "grep -v ';' /tmp/want.raw "
    "| sed -e 's/#.*//' -e 's/\\[.*\\]//' -e 's/[[:space:]]*@.*//' "
    "-e 's/[<>=!~].*//' -e 's/[[:space:]]//g' "
    "| grep -v '^$' | grep -v '^-' | tr 'A-Z_.' 'a-z--' | sort -u > /tmp/want; "
    "missing=$(comm -23 /tmp/want /tmp/have); "
    "[ -z \"$missing\" ] || { echo \"MISSING DEPENDENCIES: $missing\"; exit 1; }"
)
_NPM_DEPS_PROBE = (
    "[ -f package.json ] || exit 0; "
    # A package.json that declares NO dependencies legitimately has no
    # node_modules — demanding one there is a false alarm (observed against a
    # dependency-free target). Only require the directory when the manifest
    # actually asks for something. If `node` is somehow absent, fall through to
    # exit 0 rather than inventing a failure.
    "node -e \"const p=require('./package.json');"
    "process.exit(Object.keys({...(p.dependencies||{}),...(p.devDependencies||{})}).length?0:1)\" "
    "2>/dev/null || exit 0; "
    "[ -d node_modules ] || { echo 'MISSING DEPENDENCIES: node_modules absent'; exit 1; }"
)

# build-system -> template pieces. {ver} is filled from version_pins when present.
ECOSYSTEM_TEMPLATES: dict[str, dict] = {
    "npm": {
        "base": "node:{ver}",
        "default_ver": "20",
        "ver_key": "node",
        "install": "RUN (npm ci || npm install) && (npm run build --if-present || true)",
        "build": "npm run build --if-present",
        "test": "npm test --if-present",
        "deps": _NPM_DEPS_PROBE,
    },
    "pnpm": {
        "base": "node:{ver}",
        "default_ver": "20",
        "ver_key": "node",
        # `npm install` CANNOT resolve pnpm's `workspace:^` protocol, so a pnpm
        # monorepo templated as npm installs nothing (observed on
        # graphql-code-generator). corepack activates the exact pnpm pinned by
        # the repo's packageManager field.
        # A TS monorepo's packages resolve to dist/, which does not exist until
        # something builds them — so a PoC doing `require('@scope/pkg')` hits
        # MODULE_NOT_FOUND and can never reach the code it is meant to attack
        # (observed on graphql-code-generator). pnpm builds in topological order,
        # so the workspace packages are compiled even when a trailing example
        # fails; `|| true` keeps that failure from failing the image, and the
        # verify step still reports it honestly.
        "install": (
            "RUN corepack enable \\\n"
            "    && (pnpm install --frozen-lockfile "
            "|| pnpm install --no-frozen-lockfile || true) \\\n"
            "    && (pnpm -r --if-present run build || true)"
        ),
        "build": "pnpm -r --if-present run build",
        "test": "pnpm -r --if-present run test",
        "deps": _NPM_DEPS_PROBE,
    },
    "yarn": {
        "base": "node:{ver}",
        "default_ver": "20",
        "ver_key": "node",
        "install": (
            "RUN corepack enable \\\n"
            "    && (yarn install --immutable || yarn install || true) \\\n"
            "    && (yarn run build || true)"
        ),
        "build": "yarn run build || true",
        "test": "yarn run test || true",
        "deps": _NPM_DEPS_PROBE,
    },
    "maven": {
        "base": "maven:3.9-eclipse-temurin-{ver}",
        "default_ver": "21",
        "ver_key": "java",
        "install": "RUN mvn -q -B dependency:go-offline || true",
        "build": "mvn -q -B -DskipTests package",
        "test": "mvn -q -B test",
    },
    "gradle": {
        "base": "gradle:8-jdk{ver}",
        "default_ver": "21",
        "ver_key": "java",
        "install": "RUN gradle --no-daemon dependencies || true",
        "build": "gradle --no-daemon assemble",
        "test": "gradle --no-daemon test",
    },
    "go-modules": {
        "base": "golang:{ver}",
        "default_ver": "1.22",
        "ver_key": "go",
        "install": "RUN go mod download",
        "build": "go build ./...",
        "test": "go test ./...",
    },
    "dotnet": {
        "base": "mcr.microsoft.com/dotnet/sdk:{ver}",
        "default_ver": "8.0",
        "ver_key": "dotnet",
        "install": "RUN dotnet restore || true",
        "build": "dotnet build -c Release --no-restore",
        "test": "dotnet test --no-build",
    },
    "pip": {
        "base": "python:{ver}-slim",
        "default_ver": "3.11",
        "ver_key": "python",
        # Both steps run, independently: a succeeding `pip install -e .` used to
        # short-circuit the `||` chain and leave requirements.txt uninstalled —
        # an image that builds but has none of the target's dependencies.
        "install": (
            "RUN if [ -f requirements.txt ]; then pip install -r requirements.txt || true; fi \\\n"
            "    && if [ -f setup.py ] || [ -f pyproject.toml ]; then pip install -e . || true; fi\n"
            + _REQ_DIR_INSTALL
        ),
        "build": "python -c \"import sys; print(sys.version)\"",
        "test": "pytest -q || true",
        "deps": _PIP_DEPS_PROBE,
    },
    "poetry": {
        "base": "python:{ver}-slim",
        "default_ver": "3.11",
        "ver_key": "python",
        # Three faults lived in the previous one-liner
        # (`RUN pip install poetry && poetry install --no-root || true`), and
        # together they made Proof mode structurally unreachable for every
        # Poetry-managed Python target:
        #
        # 1. Poetry creates its OWN virtualenv by default, so every dependency
        #    landed in ~/.cache/pypoetry/virtualenvs/... — a directory the
        #    PoC's `python3` never looks in. The image looked provisioned and
        #    could not import the target.
        # 2. `--no-root` skips installing the target package itself, which is
        #    the one package a PoC must be able to import.
        # 3. `|| true` swallowed the failure, so `sandbox.py up` reported
        #    `provisioning_status: "built"` on a total miss. phase0_preflight.md
        #    §4 promises that degraded provisioning "is recorded and carried
        #    into every finding as an environment fact" — `|| true` guaranteed
        #    that promise could never be kept.
        #
        # The pip fallback stays deliberately un-swallowed: if neither path can
        # install the target, the BUILD must fail so provisioning reports it,
        # rather than handing replay an image that can only prove hello-world.
        "install": (
            "ENV POETRY_VIRTUALENVS_CREATE=false \\\n"
            "    POETRY_NO_INTERACTION=1 \\\n"
            "    PIP_DISABLE_PIP_VERSION_CHECK=1\n"
            "RUN pip install --no-cache-dir poetry \\\n"
            " && (poetry install --no-interaction \\\n"
            "     || pip install --no-cache-dir -e .)"
        ),
        "build": "python -c \"import sys; print(sys.version)\"",
        "test": "poetry run pytest -q || true",
        "deps": _PIP_DEPS_PROBE,
    },
    "uv": {
        "base": "python:{ver}-slim",
        "default_ver": "3.11",
        "ver_key": "python",
        # Installed --system, NOT into uv's default `.venv`. A PoC runs
        # `python3 poc.py`, which resolves to the system interpreter; deps in a
        # project venv would be invisible to it and every import would fail —
        # the mirror image of the scan-image rule that VASH's own venv must
        # never be on PATH.
        #
        # `uv export` is what makes this work with the existing pip deps probe:
        # it writes the lock out as a requirements.txt the probe already knows
        # how to check, so an image that builds without the target's
        # dependencies is still caught rather than reported as a success.
        #
        # git + ca-certificates because a lockfile routinely carries a
        # `pkg @ git+https://...` dependency, and python:slim ships neither.
        "install": (
            "RUN apt-get update && apt-get install -y --no-install-recommends \\\n"
            "        git ca-certificates \\\n"
            "    && rm -rf /var/lib/apt/lists/*\n"
            "RUN pip install uv \\\n"
            "    && (uv export --frozen --no-dev --no-hashes --no-emit-project \\\n"
            "            -o requirements.txt \\\n"
            "        || uv export --no-dev --no-hashes -o requirements.txt || true) \\\n"
            "    && (if [ -s requirements.txt ]; then \\\n"
            "            uv pip install --system -r requirements.txt || true; fi) \\\n"
            "    && (uv pip install --system --no-deps -e . || pip install -e . || true)\n"
            + _REQ_DIR_INSTALL
        ),
        "build": "python -c \"import sys; print(sys.version)\"",
        "test": "pytest -q || true",
        "deps": _PIP_DEPS_PROBE,
    },
    "pipenv": {
        "base": "python:{ver}-slim",
        "default_ver": "3.11",
        "ver_key": "python",
        # A Pipfile's dependencies live nowhere pip can read them, so a repo
        # carrying only a Pipfile previously matched no python ecosystem at all
        # and got an image with nothing installed. `--system` for the same
        # reason as uv: a PoC runs the system interpreter, not a project venv.
        # `pipenv requirements` writes the lock out for the existing deps probe.
        "install": (
            "RUN pip install pipenv \\\n"
            "    && (pipenv requirements > requirements.txt 2>/dev/null || true) \\\n"
            "    && (pipenv install --system --deploy \\\n"
            "        || pipenv install --system || true)"
        ),
        "build": "python -c \"import sys; print(sys.version)\"",
        "test": "pytest -q || true",
        "deps": _PIP_DEPS_PROBE,
    },
}

# preference order when a repo declares several ecosystems.
# pnpm/yarn before npm: all three are proven by a package.json, but the
# lockfile-specific one is what the repo actually uses, and installing a pnpm
# workspace with npm silently produces an empty node_modules.
# uv and poetry outrank pip: each is proven by its own lockfile, and a repo
# carrying one also carries a pyproject.toml (which now maps to pip), so the
# more specific tool has to win or the lock would never be used.
_PRIORITY = ["maven", "gradle", "pnpm", "yarn", "npm", "go-modules", "dotnet",
             "uv", "poetry", "pipenv", "pip"]

# ecosystem -> language it belongs to, so _pick_ecosystem can prefer the
# ecosystem matching the repo's dominant language over one from a vendored
# manifest (e.g. a Python repo with a vendored frontend/package.json).
_ECOSYSTEM_LANG = {
    "npm": "javascript", "yarn": "javascript", "pnpm": "javascript",
    "maven": "java", "gradle": "java", "go-modules": "go",
    "dotnet": "csharp", "pip": "python", "poetry": "python", "uv": "python",
    "pipenv": "python",
}


@dataclass
class RenderedRecipe:
    source: str = "none"            # "existing" | "template" | "none"
    path: str | None = None
    dockerfile: str | None = None
    build_cmd: str | None = None
    test_cmd: str | None = None
    # Optional dependency-presence probe run by the Phase 2 verify step for
    # ecosystems whose build command cannot itself fail on missing deps.
    deps_cmd: str | None = None
    notes: list[str] = field(default_factory=list)


# TypeScript ships through the JavaScript toolchain, so a TS-majority repo must
# match npm/pnpm/yarn — otherwise the language check silently never fires and the
# ecosystem falls back to raw priority order.
_LANG_ALIASES = {"typescript": "javascript"}


def _pick_ecosystem(fp: ProjectFingerprint) -> str | None:
    """Which ecosystem template to render, in increasing order of evidence.

    Marker files are an inference; the repo's own recipe is a statement. So a
    tool named by the project's CI/devcontainer/run scripts wins over one merely
    inferred from a filename — and is trusted even when its marker file is
    missing entirely (a uv project that never committed uv.lock, whose workflow
    runs `uv sync`).
    """
    recipe = [bs for bs in (fp.recipe_tools or []) if bs in ECOSYSTEM_TEMPLATES]
    known = set(fp.build_systems) | set(recipe)
    present = [bs for bs in _PRIORITY if bs in known]
    if not present:
        return None
    primary = _LANG_ALIASES.get(fp.primary_language, fp.primary_language)
    pool = [bs for bs in present if _ECOSYSTEM_LANG.get(bs) == primary] if primary else []
    pool = pool or present
    for bs in pool:
        if bs in recipe:
            return bs
    return pool[0]


def _resolve_version(fp: ProjectFingerprint, t: dict) -> str:
    """Exact pin wins; otherwise max(stated floor, our default).

    A floor is a MINIMUM (`engines: {"node": ">= 16.0.0"}`). Treating it as a
    pin builds the project on its oldest supported runtime — which is how a repo
    whose .nvmrc says 24 got a node:16 image.
    """
    key, default = t["ver_key"], t["default_ver"]
    exact = fp.version_pins.get(key)
    if exact:
        return exact
    floor = getattr(fp, "version_floors", {}).get(key)
    if floor and _version_key(floor) > _version_key(default):
        return floor
    return default


def render_dockerfile(fp: ProjectFingerprint, repo_path: Path,
                      *, ignore_existing: bool = False) -> RenderedRecipe:
    """Render the build recipe for `fp`.

    `ignore_existing` skips the repo's own Dockerfile and templates the
    ecosystem instead. The repo's recipe is the highest-signal source and stays
    the default, but it is written for the maintainer's build, not for a
    provisioner: it can assume a `make` step ran first, or COPY a lockfile the
    repo generates and does not commit. When it fails for such a reason no
    repair rule can recover it, and the ladder's last resort — softening the
    install — yields an image with the target's source and none of its
    dependencies. `build.py` retries with this flag before accepting that.
    """
    # 1. Prefer an existing repo recipe (highest signal).
    if not ignore_existing:
        for rel in fp.existing_recipes:
            if Path(rel).name == "Dockerfile":
                return RenderedRecipe(source="existing", path=rel,
                                      notes=["reused existing repo Dockerfile"])

    # 2. Otherwise template the highest-priority known ecosystem.
    eco = _pick_ecosystem(fp)
    if eco is None:
        return RenderedRecipe(source="none",
                              notes=["no known build system detected"])
    t = ECOSYSTEM_TEMPLATES[eco]
    ver = _resolve_version(fp, t)
    base = t["base"].format(ver=ver)
    dockerfile = "\n".join([
        f"FROM {base}",
        "WORKDIR /target",
        "COPY . /target",
        t["install"],
        "# build/test are run by the Phase 2 provisioning stage, not at build time",
    ]) + "\n"
    return RenderedRecipe(
        source="template", path=None, dockerfile=dockerfile,
        build_cmd=t["build"], test_cmd=t["test"], deps_cmd=t.get("deps"),
        notes=[f"templated {eco} (base={base})"],
    )
