"""Resolve the skill's bundled virtualenv, and nothing else.

Every script in ``scripts/`` starts with ``import _bootstrap  # noqa: F401``
before any third-party import. That single line has to make ``jsonschema`` and
``yaml`` importable in two very different situations:

* **Installed skill.** ``install.sh`` copied the skill to
  ``~/.claude/skills/pyhunt/`` and built ``<skill>/.venv`` beside ``SKILL.md``.
  Claude Code invokes ``python3 <skill>/scripts/foo.py`` with whatever
  ``python3`` resolves to on the operator's PATH — an interpreter that has
  never heard of ``jsonschema``. The bundled venv's ``site-packages`` has to
  come onto ``sys.path``.
* **Dev checkout.** The repo's own ``.venv`` (pytest, pytest-asyncio, and the
  same runtime deps) is already active. There is nothing to resolve and
  nothing to do: touching ``sys.path`` here could only shadow the interpreter
  the developer deliberately chose.

So the contract is deliberately small, and every clause of it is a rule about
what this module must NOT do:

* **Never install anything, never reach the network.** Provisioning is
  ``install.sh``'s job, and it runs when the operator asked for it — not as a
  side effect of a scan.
* **Never raise.** A missing, half-built, or version-mismatched venv leaves
  ``sys.path`` as it found it. The caller then gets the real
  ``ModuleNotFoundError: No module named 'jsonschema'``, which names the actual
  problem and points at ``install.sh``. A bootstrap that raised its own
  exception here would replace a precise error with a vague one.
* **Only ever add a site-packages built for the RUNNING interpreter.**
  ``jsonschema`` pulls in ``rpds-py``, which ships a compiled
  ``.cpython-311-darwin.so``. Putting a 3.11 ``site-packages`` on a 3.13
  interpreter's path makes the pure-Python half import fine and the native half
  fail with ``No module named 'rpds.rpds'`` — an error that looks like a
  corrupt install rather than an interpreter mismatch. Refusing the mismatch
  keeps the failure legible.

There is one case where refusing the mismatch is not enough, and it is the
common one rather than an edge case. PyHunt requires Python 3.11+, but the
``python3`` on an operator's PATH is frequently older — macOS ships 3.9 at
``/usr/bin/python3``, and that is what Claude Code invokes. ``install.sh`` then
correctly builds the bundled venv with a 3.11+ interpreter, and the two never
meet: every scan would die on ``No module named 'jsonschema'`` with a perfectly
good venv sitting next to it. So when the deps are missing AND the bundled venv
has its own interpreter, this module re-executes the script under that
interpreter. The re-exec is deliberately narrow — it cannot fire when the
current interpreter already has the deps, which is what keeps the dev venv
untouched — and it is guarded against looping.

It also puts ``scripts/`` itself on ``sys.path``. When Claude Code runs
``python3 <skill>/scripts/report_build.py``, ``scripts/`` is already
``sys.path[0]`` and siblings import by bare name (``from oracle.gate import
judge``). When pytest *imports* the same module, it is not — and the bare-name
imports would fail. One line here makes both work.

Diagnostics land in :data:`RESOLUTION` rather than on stderr: a module imported
for its side effect must stay silent, and a script that wants to explain itself
can read the dict.
"""

from __future__ import annotations

import os
import sys
from typing import Any

#: Directory holding this file — the skill's ``scripts/`` directory.
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

#: The skill root: the directory containing ``SKILL.md``, ``schemas/``,
#: ``phases/``, ``references/`` and ``.venv/``.
SKILL_ROOT = os.path.dirname(SCRIPTS_DIR)

#: Where every phase's output schema lives. Scripts resolve schemas through
#: this rather than recomputing ``__file__``-relative paths of their own, so a
#: future layout change is a one-line edit here.
SCHEMAS_DIR = os.path.join(SKILL_ROOT, "schemas")

#: Where the bundled venv is expected. Absence is normal (dev checkout).
VENV_DIR = os.path.join(SKILL_ROOT, ".venv")

#: The bundled venv's own interpreter, used only for the re-exec below.
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python3")

#: Set on the child process so a re-exec can never loop, however the
#: interpreter paths compare.
REEXEC_FLAG = "PYHUNT_BOOTSTRAP_REEXEC"

#: Third-party modules the skill's scripts actually need at runtime. Kept in
#: sync with ``install.sh``'s dependency list by hand — both are two entries
#: long, and a mismatch shows up immediately as a failed smoke test.
REQUIRED_MODULES = ("jsonschema", "yaml")

#: What this module did, and why. Purely for diagnostics — a script can print
#: it when a dependency is missing, and ``install.sh``'s smoke test reads it.
RESOLUTION: dict[str, Any] = {
    "skill_root": SKILL_ROOT,
    "venv_dir": VENV_DIR,
    "site_packages": None,
    "action": "pending",
    "reason": "",
}


def _prepend_once(path: str) -> bool:
    """Put `path` at the front of ``sys.path`` if it is a real directory and
    is not already there. Returns whether the list changed."""
    if not path or not os.path.isdir(path):
        return False
    if path in sys.path:
        return False
    sys.path.insert(0, path)
    return True


def _deps_already_importable() -> bool:
    """Can the current interpreter already find every required module?

    Uses ``find_spec`` rather than ``import``: locating a module does not run
    its top-level code, so this stays cheap and free of side effects even when
    the answer is yes.
    """
    try:
        from importlib.util import find_spec
    except Exception:  # pragma: no cover - importlib is always present
        return False
    for name in REQUIRED_MODULES:
        try:
            if find_spec(name) is None:
                return False
        except (ImportError, ValueError):
            # A namespace-package edge case or a broken parent package. Treat
            # as "not available" and let the venv resolution have a go.
            return False
    return True


def bundled_site_packages() -> str | None:
    """Path to the bundled venv's ``site-packages`` for the RUNNING
    interpreter, or None.

    The version is not discovered by globbing ``python*``: it is constructed
    from ``sys.version_info`` and then checked for existence. A venv built for
    a different minor version is therefore reported as absent, which is the
    honest answer — its compiled extensions cannot load here.
    """
    minor = f"python{sys.version_info.major}.{sys.version_info.minor}"
    candidates = (
        os.path.join(VENV_DIR, "lib", minor, "site-packages"),
        # virtualenv on Windows, and a couple of vendored layouts. Cheap to
        # check, and costs nothing on POSIX where it simply does not exist.
        os.path.join(VENV_DIR, "Lib", "site-packages"),
    )
    for path in candidates:
        if os.path.isdir(path):
            return path
    return None


def _same_interpreter(a: str, b: str) -> bool:
    """Compare two Python executables through symlinks."""
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:
        return False


def _reexec_under_bundled_python() -> None:
    """Re-run this script under the bundled venv's interpreter, if that is the
    only way the deps can be found.

    Preconditions, all of them required:

    * the deps are NOT already importable (checked by the caller) — so this can
      never fire in a dev checkout, where the active venv already has them;
    * a bundled venv interpreter exists;
    * it is not the interpreter already running;
    * we have not re-executed once already (env flag);
    * ``sys.argv[0]`` is a real script file. ``python3 -c ...`` and interactive
      sessions have no script to re-run, and ``os.execv`` with ``argv[0] ==
      '-c'`` would silently change what runs. Those callers fall through to
      plain ``sys.path`` resolution instead.

    ``os.execv`` replaces the process, so anything imported before this module
    is discarded. That is why the convention is to import ``_bootstrap`` first,
    before any third-party import.
    """
    if os.environ.get(REEXEC_FLAG) == "1":
        return
    if not os.path.isfile(VENV_PYTHON):
        return
    if _same_interpreter(sys.executable, VENV_PYTHON):
        return
    script = sys.argv[0] if sys.argv else ""
    if not script or not os.path.isfile(script):
        return
    os.environ[REEXEC_FLAG] = "1"
    os.execv(VENV_PYTHON, [VENV_PYTHON, *sys.argv])


def _describe_mismatch() -> str:
    """Explain a present-but-unusable venv, for :data:`RESOLUTION`."""
    lib = os.path.join(VENV_DIR, "lib")
    try:
        built_for = sorted(
            name for name in os.listdir(lib) if name.startswith("python")
        )
    except OSError:
        return "bundled venv has no lib/ directory"
    if not built_for:
        return "bundled venv has no lib/python*/ directory"
    running = f"python{sys.version_info.major}.{sys.version_info.minor}"
    return (
        f"bundled venv was built for {', '.join(built_for)} but this "
        f"interpreter is {running}, and handing over to {VENV_PYTHON} was not "
        f"possible; refusing to mix ABIs — re-run install.sh"
    )


def _resolve() -> None:
    """Run once at import. Records what happened in :data:`RESOLUTION`."""
    # Sibling imports by bare name must work whether a script here was run
    # directly (scripts/ is already sys.path[0]) or imported by a test runner
    # from elsewhere (it is not). Unconditional and harmless.
    _prepend_once(SCRIPTS_DIR)

    if _deps_already_importable():
        RESOLUTION.update(
            action="noop",
            reason="the running interpreter already provides the runtime deps",
        )
        return

    site_packages = bundled_site_packages()
    if site_packages is None:
        # The venv exists but was built for a different minor version. Its own
        # interpreter is the right one; hand over to it rather than mixing ABIs.
        # Does not return if it fires.
        _reexec_under_bundled_python()
        RESOLUTION.update(
            action="unresolved",
            reason=(
                _describe_mismatch()
                if os.path.isdir(VENV_DIR)
                else f"no bundled venv at {VENV_DIR} — run install.sh"
            ),
        )
        return

    _prepend_once(site_packages)
    RESOLUTION.update(
        site_packages=site_packages,
        action="bundled",
        reason="loaded the bundled venv's site-packages",
    )


try:
    _resolve()
except Exception as exc:  # pragma: no cover - defensive; must never raise
    # Whatever went wrong, the caller is better served by the ImportError it is
    # about to get than by an exception from the bootstrap.
    RESOLUTION.update(action="error", reason=f"{type(exc).__name__}: {exc}")


def schema_path(name: str) -> str:
    """Absolute path to ``schemas/<name>.schema.json``.

    Accepts either the bare name (``"finding"``) or the file name
    (``"finding.schema.json"``), because both spellings appear in phase
    instructions and neither should be a trap.
    """
    if not name.endswith(".schema.json"):
        name = f"{name}.schema.json"
    return os.path.join(SCHEMAS_DIR, name)
