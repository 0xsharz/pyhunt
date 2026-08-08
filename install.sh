#!/bin/bash
#
# Install the PyHunt skill into ~/.claude/skills/.
#
# One skill ships from this repository: `pyhunt`, the scanner. `pyhunt-fix` and
# `pyhunt-fix-verify` are named in the plan but NOT built, and this script does
# not pretend otherwise — a skill directory that installs an empty shell is
# worse than one that is absent, because Claude Code will happily invoke it.
#
# Properties this script is required to have, in the order they matter:
#
#   * **It never clobbers silently.** An existing install is replaced only when
#     it is recognisably a previous PyHunt install, and the replacement is
#     printed. Anything else at the destination stops the script and asks.
#   * **It is idempotent.** Re-running it after a `git pull` is the supported
#     upgrade path, and a healthy bundled venv survives the upgrade instead of
#     being rebuilt (and re-downloaded) every time. `--rebuild-venv` forces one.
#   * **It verifies what it installed.** The bundled venv is smoke-tested
#     through the skill's own `scripts/_bootstrap.py`, with the same `python3`
#     Claude Code will invoke. An install that reports success and then fails on
#     the first scan is the failure mode this check exists to prevent.
#   * **The attribution travels with it.** PyHunt derives from Apache-2.0 work
#     (Capital One VulnHunter, Visa VVAH) and MIT work (VASH, evilsocket/audit).
#     Apache-2.0 §4(d) requires the NOTICE to accompany the distributed work,
#     and this script IS the distribution — what it copies is the only PyHunt
#     most operators will ever have. So `NOTICE`, `LICENSE` and `licenses/` are
#     installed beside `SKILL.md`, and a source tree missing any of them is a
#     hard error rather than a quieter install.
#
# Usage:
#   ./install.sh                 install or upgrade
#   ./install.sh --rebuild-venv  force a fresh bundled venv
#   ./install.sh --no-venv       skip the venv (deps managed by the operator)
#   ./install.sh --force         replace whatever is at the destination
#
set -euo pipefail

# HOME guard: every destination below derives from HOME, and so does the `rm
# -rf`. An empty HOME turns that into `rm -rf /.claude/skills/pyhunt`.
if [ -z "${HOME:-}" ]; then
    echo "error: HOME is unset — refusing to run install.sh" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_PARENT="$HOME/.claude/skills"
SKILL_NAME="pyhunt"
SRC="$SCRIPT_DIR/pyhunt"
DST="$SKILLS_PARENT/$SKILL_NAME"

# Runtime dependencies of the skill's scripts. `jsonschema` validates every
# phase output; `pyyaml` reads the sink and hint tables. Kept in step with
# scripts/_bootstrap.py's REQUIRED_MODULES by hand — both lists are two entries
# long, and a mismatch surfaces immediately in the smoke test below.
DEPS=("jsonschema>=4.21" "pyyaml>=6.0")

# Attribution that must travel with the installed skill (Apache-2.0 §4(d)).
# Lives at the repository root, next to this script, and is copied in beside
# SKILL.md. `tests/test_licensing.py` installs into a temporary HOME and asserts
# all three arrive, so this cannot quietly stop happening.
ATTRIBUTION=("NOTICE" "LICENSE" "licenses")

REBUILD_VENV=0
BUILD_VENV=1
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --rebuild-venv) REBUILD_VENV=1 ;;
        --no-venv)      BUILD_VENV=0 ;;
        --force)        FORCE=1 ;;
        # Print the header block, whatever length it has grown to: everything
        # from line 2 up to the first non-comment line, minus that line.
        -h|--help)      sed -n '2,/^[^#]/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "error: unknown option: $arg" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Locate the interpreter
# ---------------------------------------------------------------------------
#
# Prefer plain `python3`, deliberately. Claude Code invokes the skill's scripts
# as `python3 <skill>/scripts/foo.py`, and _bootstrap.py only loads a bundled
# venv whose site-packages was built for the RUNNING interpreter's minor
# version — mixing ABIs would make `rpds` (a compiled transitive dep of
# jsonschema) fail with an error that looks like a corrupt install. So the venv
# must be built with the same `python3` that will later run the scripts.
find_python() {
    if command -v python3 >/dev/null 2>&1 && \
       python3 -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)' 2>/dev/null; then
        command -v python3
        return 0
    fi
    for cand in python3.13 python3.12 python3.11; do
        if command -v "$cand" >/dev/null 2>&1; then command -v "$cand"; return 0; fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Pre-flight on the source tree
# ---------------------------------------------------------------------------

if [ ! -f "$SRC/SKILL.md" ]; then
    echo "error: $SRC/SKILL.md not found." >&2
    echo "       Run ./install.sh from the repository root." >&2
    exit 1
fi

for item in "${ATTRIBUTION[@]}"; do
    if [ ! -e "$SCRIPT_DIR/$item" ]; then
        echo "error: $SCRIPT_DIR/$item not found." >&2
        echo "       PyHunt derives from Apache-2.0 work, and §4(d) requires the" >&2
        echo "       NOTICE to travel with it. Refusing to install a skill whose" >&2
        echo "       attribution is incomplete." >&2
        exit 1
    fi
done

for unbuilt in pyhunt-fix pyhunt-fix-verify; do
    if [ -d "$SCRIPT_DIR/$unbuilt" ]; then
        echo "note: $unbuilt is present in this repo but is NOT built — not installing it."
    fi
done

mkdir -p "$SKILLS_PARENT"

# ---------------------------------------------------------------------------
# Handle whatever is already at the destination
# ---------------------------------------------------------------------------

PRESERVED_VENV=""
cleanup() {
    [ -n "$PRESERVED_VENV" ] && [ -d "$PRESERVED_VENV" ] && rm -rf "$PRESERVED_VENV"
    rm -f "$DST/scripts/_smoke.py" 2>/dev/null
    return 0
}
trap cleanup EXIT

if [ -L "$DST" ]; then
    echo "Removing old symlink $DST"
    rm "$DST"
elif [ -d "$DST" ]; then
    if [ "$FORCE" -eq 1 ]; then
        echo "Replacing $DST (--force)"
    elif grep -qs '^name: pyhunt$' "$DST/SKILL.md"; then
        installed_from="$(cat "$DST/.installed-from" 2>/dev/null || echo unknown)"
        echo "Upgrading existing pyhunt install at $DST (was: $installed_from)"
    else
        echo "error: $DST exists and is not a PyHunt install." >&2
        echo "       Refusing to overwrite it. Move it aside, or re-run with --force." >&2
        exit 1
    fi

    # Keep a healthy bundled venv across the upgrade: the skill's files change
    # on every pull, its two pinned dependencies almost never do, and a
    # reinstall that re-downloads them needs the network for no reason.
    if [ "$BUILD_VENV" -eq 1 ] && [ "$REBUILD_VENV" -eq 0 ] && [ -d "$DST/.venv" ]; then
        PRESERVED_VENV="$(mktemp -d "${TMPDIR:-/tmp}/pyhunt-venv.XXXXXX")/.venv"
        mkdir -p "$(dirname "$PRESERVED_VENV")"
        mv "$DST/.venv" "$PRESERVED_VENV"
        echo "  preserving the existing bundled venv"
    fi
    rm -rf "$DST"
fi

# ---------------------------------------------------------------------------
# Copy
# ---------------------------------------------------------------------------

cp -R "$SRC" "$DST"
# The repo's own .venv is a dev artifact with this checkout's paths baked into
# its scripts. The installed skill gets its own, built below.
rm -rf "$DST/.venv"
find "$DST" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$DST" -name '*.pyc' -delete 2>/dev/null || true

# The attribution, from the repository root into the installed skill. Copied
# after the tree so a re-install refreshes it, and verified afterwards: `cp`
# succeeding is not the same claim as the file being where the licence needs it.
for item in "${ATTRIBUTION[@]}"; do
    cp -R "$SCRIPT_DIR/$item" "$DST/"
    if [ ! -e "$DST/$item" ]; then
        echo "error: $item did not reach $DST — install aborted." >&2
        exit 1
    fi
done

# Record the source commit so a staleness check can compare an installed copy
# against upstream. Best-effort, and only when it really is a commit id: an
# unborn HEAD makes `git rev-parse` print the literal string "HEAD", which
# would later read as a plausible-looking (and wrong) provenance record.
SRC_COMMIT="$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || true)"
if printf '%s' "$SRC_COMMIT" | grep -Eq '^[0-9a-f]{40}$'; then
    printf '%s\n' "$SRC_COMMIT" > "$DST/.installed-from"
fi

echo "Installed $SKILL_NAME -> $DST"
echo "  attribution installed: ${ATTRIBUTION[*]}"

# ---------------------------------------------------------------------------
# The bundled venv
# ---------------------------------------------------------------------------

# The interpreter Claude Code will actually invoke. Verifying with anything
# else proves the venv works for a caller that never exists — and on a host
# whose `python3` predates 3.11 (macOS ships 3.9 at /usr/bin/python3) that is
# exactly the difference between "installed" and "works".
PLAIN_PY="$(command -v python3 2>/dev/null || true)"

smoke_test() {
    local py="$1"
    "$py" "$DST/scripts/_smoke.py" >/dev/null 2>&1
}

write_smoke_script() {
    cat > "$DST/scripts/_smoke.py" <<'PY'
"""Written by install.sh, run once, deleted. Proves the bundled venv resolves
through the skill's own bootstrap, from a real script file — which is what lets
_bootstrap re-exec under the bundled interpreter when the caller's python3 is
too old."""
import _bootstrap  # noqa: F401
import jsonschema  # noqa: F401
import yaml  # noqa: F401
import json
import sys

print(json.dumps({"python": sys.version.split()[0], **_bootstrap.RESOLUTION}))
PY
}

if [ "$BUILD_VENV" -eq 0 ]; then
    echo "Skipping the bundled venv (--no-venv). The skill's scripts will use"
    echo "whatever jsonschema/pyyaml the invoking interpreter provides."
else
    if ! PY="$(find_python)"; then
        echo "error: no python3 >= 3.11 found (PyHunt requires 3.11+)." >&2
        echo "       Install one and re-run ./install.sh." >&2
        exit 1
    fi
    PY_VERSION="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    write_smoke_script

    if [ -n "$PLAIN_PY" ] && [ "$PLAIN_PY" != "$PY" ]; then
        PLAIN_VERSION="$("$PLAIN_PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo unknown)"
        echo "  note: 'python3' on your PATH is $PLAIN_VERSION ($PLAIN_PY), below PyHunt's 3.11 minimum."
        echo "        The bundled venv is built with $PY_VERSION and scripts/_bootstrap.py hands"
        echo "        over to it automatically, so the skill still works — verified below."
    fi

    if [ -n "$PRESERVED_VENV" ] && [ -d "$PRESERVED_VENV/lib/python$PY_VERSION/site-packages" ]; then
        mv "$PRESERVED_VENV" "$DST/.venv"
        PRESERVED_VENV=""
        if smoke_test "${PLAIN_PY:-$PY}"; then
            echo "  reused the existing bundled venv (python $PY_VERSION)"
        else
            echo "  the preserved venv no longer satisfies the skill — rebuilding"
            rm -rf "$DST/.venv"
        fi
    elif [ -n "$PRESERVED_VENV" ]; then
        echo "  the preserved venv was built for a different python — rebuilding"
        rm -rf "$PRESERVED_VENV"
        PRESERVED_VENV=""
    fi

    if [ ! -d "$DST/.venv" ]; then
        echo "  creating the bundled venv with $PY (python $PY_VERSION)"
        "$PY" -m venv "$DST/.venv"
        "$DST/.venv/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade pip
        echo "  installing runtime deps: ${DEPS[*]}"
        if ! "$DST/.venv/bin/python" -m pip install --quiet --disable-pip-version-check "${DEPS[@]}"; then
            echo "error: could not install ${DEPS[*]} into $DST/.venv" >&2
            echo "       (this step needs network access; the skill itself never does)" >&2
            exit 1
        fi
    fi

    if ! smoke_test "${PLAIN_PY:-$PY}"; then
        echo "error: bootstrap smoke test failed — the venv exists but the skill" >&2
        echo "       cannot import its dependencies through scripts/_bootstrap.py." >&2
        echo "       Inspect: $DST/.venv/lib/python$PY_VERSION/site-packages/" >&2
        "${PLAIN_PY:-$PY}" "$DST/scripts/_smoke.py" >&2 || true
        rm -f "$DST/scripts/_smoke.py"
        exit 1
    fi
    echo "  bundled venv verified: $("${PLAIN_PY:-$PY}" "$DST/scripts/_smoke.py")"
    rm -f "$DST/scripts/_smoke.py"
fi

# ---------------------------------------------------------------------------
# Verify the skill itself
# ---------------------------------------------------------------------------

if [ "$BUILD_VENV" -eq 1 ]; then
    for script in findings_io report_build validate_gates; do
        if ! "${PLAIN_PY:-$PY}" "$DST/scripts/$script.py" --help >/dev/null 2>&1; then
            echo "error: $DST/scripts/$script.py does not run under ${PLAIN_PY:-$PY}." >&2
            exit 1
        fi
    done
    echo "  skill scripts verified under ${PLAIN_PY:-$PY}"
fi

echo ""
echo "PyHunt is installed. Invoke it from Claude Code as /pyhunt."
echo "To upgrade after a git pull: re-run ./install.sh"
echo "To uninstall: rm -rf \"$DST\""
