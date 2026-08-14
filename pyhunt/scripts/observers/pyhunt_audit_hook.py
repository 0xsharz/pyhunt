#!/usr/bin/env python3
"""PEP-578 audit-hook observer for Python PoCs.

    python3 vash_audit_hook.py python3 poc.py [args...]
    python3 vash_audit_hook.py poc.py [args...]

Installs a `sys.addaudithook` hook, then runs the PoC through `runpy` in the
same interpreter. Every security-relevant CPython audit event the PoC triggers
(process spawn, file open, socket connect, exec/compile, pickle/marshal load)
is printed to **stderr** with a distinctive marker prefix, so the Hunt agent
can tell "the script exited 0" apart from "the vulnerable behaviour actually
fired". Exit code and stdout of the PoC are passed through unchanged.

**Why an audit hook and not a wrapper library.** Audit events are raised by
CPython itself, below the Python API, so they fire no matter how the target
reaches the sink — `os.system`, a C extension calling `subprocess`, a pickle
gadget chain. A monkey-patched module can be bypassed; an audit hook cannot
(hooks can never be removed once added, by design).

**Noise control, and why it matters.** The interpreter raises `open`,
`compile` and `exec` constantly just to *start* — importing modules, reading
`.py` files, compiling the PoC. Reporting those would produce evidence that
proves nothing, so this hook (a) arms itself only once the PoC is about to
run, (b) drops events attributable to loading the PoC itself, (c) drops
`open` of code files and of anything under the interpreter's own prefix, and
(d) caps each event type. The bias is deliberate: a missed event costs a
weaker proof, a fabricated event costs a false finding.

**Honesty.** This observer is OPTIONAL instrumentation. If it is not used, or
its output is empty, that says nothing about whether the vulnerability
reproduced — read the PoC's own assertions. The `hook-armed` banner line
exists precisely so "the observer never ran" is distinguishable from "the
observer ran and saw nothing".

**Nonce.** Every line carries `n=<nonce>`, read from ``PYHUNT_NONCE``. Hunt runs
many PoCs concurrently inside one scan container, so an unstamped marker line
cannot be attributed to the PoC that produced it. The nonce is what makes
`pyhunt.oracle.gate` able to say *this* exploit caused *this* event, rather than
merely that the event occurred somewhere.

**Signature (Contract A).** The nonce alone cannot establish that the OBSERVER
said something, only which PoC a line claims to be about — and the nonce is
handed to the container, so the PoC and the target's own import-time code can
both print a well-formed, correctly-nonced line and manufacture a proof. So
every line also carries `s=<sig>`, the first 16 hex of
``HMAC-SHA256(observer_key, body)`` where `body` is everything after `s=`. The
key arrives in ``PYHUNT_OBSERVER_KEY``, is read at import — before any target or
PoC code runs — into a closure, and is **deleted from os.environ** immediately.
``PYHUNT_NONCE`` is scrubbed the same way and for the same reason.

**Channel.** Markers go to **file descriptor 3**, not stdout and not stderr, so
ordinary target output cannot be mistaken for observer output. `replay.py`
points fd 3 at a file it reads from the host after the container exits. When fd
3 is not open the hook falls back to stderr and says so in the banner, so a
degraded channel is never read as an authentic one.

**What this is not.** The target runs in this same interpreter, so a target
written specifically to attack PyHunt can recover the key from process memory
with effort. Signing + scrubbing + a private descriptor defeat naive and
opportunistic forgery and force any attack to be deliberate and PyHunt-specific.
It is NOT a security boundary against an adversary who has read this repository.
Out-of-process observation (seccomp, eBPF, ptrace) is the real fix, and is out
of scope.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import runpy
import re
import sys

MARKER = "[PYHUNT-OBSERVER]"


def _make_signer(key: str):
    """Capture the observer key in a closure and hand back a signing function.

    The key is passed in and never stored in a module global, so the only
    reference to it is this closure's cell. That is not a memory-safety
    boundary — see the module docstring — but it does mean no attribute lookup
    on this module yields the key.
    """

    def sign(body: str) -> str:
        if not key:
            return ""
        return hmac.new(
            key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:16]

    return sign


# Read AND delete in one step, at import, before the PoC or any target code can
# run: `pop` means the value never exists as a module-level name, and the
# environment the target inherits no longer carries either secret. This is what
# closes C-3 — a hostile repository's `__init__.py` printing a forged marker at
# import time — as far as an in-process observer can close it.
_SIGN = _make_signer(os.environ.pop("PYHUNT_OBSERVER_KEY", ""))

# Stamped onto every emitted line so the gate can attribute an event to this
# exact PoC. Read once at import: a target that later mutates os.environ must
# not be able to change what this observer claims.
NONCE = os.environ.pop("PYHUNT_NONCE", "")

#: The descriptor markers are written to. Must match `replay.OBSERVER_FD`.
OBSERVER_FD = 3


def _fd_is_open(fd: int) -> bool:
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


# Probed once, at import. The launcher `replay.py` runs before this process
# opens fd 3 and clears close-on-exec; anything else (a developer running the
# hook by hand, an image whose entrypoint dropped the descriptor) lands on the
# stderr fallback.
_CHANNEL_FD = OBSERVER_FD if _fd_is_open(OBSERVER_FD) else None

# Audit events worth reporting. Chosen for "an attacker got something to
# happen" value, not completeness — see the noise-control note above.
WATCHED_EVENTS = (
    "subprocess.Popen",     # every subprocess.* API funnels through this
    "os.system",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "os.startfile",
    "open",                 # io.open / builtins.open / os.open
    "socket.connect",
    "socket.getaddrinfo",
    "urllib.Request",
    "exec",                 # raised by both exec() and eval()
    "compile",
    "pickle.find_class",    # the pickle RCE primitive
    "marshal.load",
    "marshal.loads",
    "ctypes.dlopen",
)

# Events the import system raises constantly just to load a module (reading
# and unmarshalling .pyc, exec'ing module bodies, compiling namedtuple
# accessors). They stay in WATCHED_EVENTS — a PoC that unmarshals attacker
# bytes is exactly what we want to see — but they are dropped when the call
# came from inside the import machinery. The high-value events
# (subprocess/os/socket/pickle) are NEVER filtered this way.
_IMPORT_NOISY_EVENTS = ("open", "exec", "compile", "marshal.load", "marshal.loads")

MAX_PER_EVENT = 25

# `open` of these is almost always the import system, not the PoC.
_CODE_SUFFIXES = (".py", ".pyc", ".pyo", ".pyi", ".so", ".pyd", ".dll", ".egg")

# how far up the stack to look for the import machinery
_FRAME_SCAN_LIMIT = 60

_state = {"armed": False, "reentrant": False, "poc": None, "nonce": NONCE}
_counts: dict[str, int] = {}


def _noise_roots() -> tuple[str, ...]:
    roots = [sys.prefix, sys.base_prefix]
    try:
        roots.append(os.path.dirname(os.__file__ or ""))
    except Exception:  # pragma: no cover - defensive
        pass
    return tuple(os.path.normcase(r) for r in roots if r)


_NOISE_ROOTS = _noise_roots()


def _target_roots() -> tuple[str, ...]:
    """Directories that are the code under test, whatever else they are.

    **This exists because the noise filter was silently fatal.** Frames under
    ``sys.prefix`` are discarded as interpreter or third-party noise, which is
    right for the standard library and for installed dependencies — and wrong
    for the target, because the ordinary way to provision a Python project is
    to ``pip install`` it, which puts it in ``site-packages``, which is under
    ``sys.prefix``. Every frame of the code under test then looked like noise,
    nothing could be attributed to the target, and **no finding could ever be
    proven** through the documented provisioning path. The failure was silent:
    the run completed, the observer armed, and every verdict came back
    ``no_event``, which reads as "the PoC did not work".

    ``PYHUNT_TARGET_ROOT`` is set by ``replay.py`` (colon-separated, same shape
    as ``PATH``) and wins over the noise filter. Unset, behaviour is unchanged.
    """
    raw = os.environ.pop("PYHUNT_TARGET_ROOT", "") or ""
    out = []
    for part in raw.split(os.pathsep):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(os.path.normcase(os.path.abspath(part)))
        except Exception:  # pragma: no cover - defensive
            continue
    return tuple(out)


_TARGET_ROOTS = _target_roots()


def _emit(body: str) -> None:
    """Write one marker line: nonce-stamped, signed, on the private channel.

    ``body`` is the claim — the kind, its arguments, the frame attribution — and
    is exactly what the signature covers, so what the gate verifies is what the
    gate reads.

    Never raises: instrumentation must not be able to break the PoC (fd 3 or
    stderr can be closed during interpreter shutdown). A dropped marker line
    costs a weaker proof; an exception escaping the audit hook would corrupt the
    run it was supposed to observe.
    """
    try:
        nonce = _state.get("nonce") or ""
        prefix = f"{MARKER} n={nonce}" if nonce else MARKER
        sig = _SIGN(body)
        line = f"{prefix} s={sig} {body}\n" if sig else f"{prefix} {body}\n"
        if _CHANNEL_FD is not None:
            os.write(_CHANNEL_FD, line.encode("utf-8", "replace"))
        else:
            sys.stderr.write(line)
            sys.stderr.flush()
    except Exception:
        pass


def _short(value: object, limit: int = 200) -> str:
    try:
        text = repr(value)
    except Exception:
        return "<unrepresentable>"
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


def _emit_declared_filename(filename: object) -> None:
    """Report the filename a ``compile`` was handed, out of band and in full.

    This is the channel ``replay.synthesized_filenames`` calls its *primary*
    one, and until now it had a consumer and no producer: nothing in this file
    ever emitted a ``hook-compile`` line, so the gate was left recovering
    declared filenames from the event line — which :func:`_short` truncates at
    200 characters.

    That truncation is a bypass, not a rough edge. ``compile(<10 KB of
    source>, "/target/app/reports.py")`` loses its filename from the printed
    repr, the gate cannot tell that the name was minted, and a frame carrying
    it is trusted as the target's own. The hook is the one place that holds the
    argument before it is shortened, so this is the one place the problem can
    be fixed.

    Two shapes, because the consumer accepts two. ``file=<path>`` is matched by
    a ``\\S+`` pattern, so a path containing whitespace is emitted as the whole
    body instead, which the consumer falls back to reading as a filename.
    Anything implausible as a path is dropped rather than guessed at.

    **A file compiling under its own name is not reported**, and that
    exemption lives here rather than in the gate because this is the only
    place it can be decided exactly. A name is suspect when the code that
    chose it is not the file it names — a PoC minting ``/target/app/reports.py``
    from ``poc.py``. When a target does ``exec(compile(user_code, __file__))``
    the two are the same file: that is eval-injection, the frames the injected
    code creates are the evidence for it, and reporting the name here would
    make the gate throw that evidence away. Downstream both consumers see real
    objects' paths compared directly, not two filenames recovered from a
    truncated repr.
    """
    try:
        text = filename if isinstance(filename, str) else os.fsdecode(filename)
    except Exception:
        return
    text = text.strip()
    if not text or len(text) > 512 or "\n" in text or "\r" in text:
        return
    frame = _nearest_user_frame()
    if frame is not None:
        try:
            here = os.path.normcase(os.path.abspath(frame.f_code.co_filename))
            if os.path.normcase(os.path.abspath(text)) == here:
                return
        except Exception:
            pass
    _emit(f"hook-compile {text}" if any(c.isspace() for c in text)
          else f"hook-compile file={text}")


def _is_poc(path: object) -> bool:
    poc = _state["poc"]
    if not poc or not isinstance(path, str):
        return False
    try:
        return os.path.normcase(os.path.abspath(path)) == poc
    except Exception:
        return False


def _boring_open(path: object) -> bool:
    if not isinstance(path, str):
        return False                       # an int fd — keep it, it is unusual
    norm = os.path.normcase(path)
    if norm.endswith(_CODE_SUFFIXES):
        return True
    return any(norm.startswith(root) for root in _NOISE_ROOTS)


#: The filename CPython hands `ast.parse` when PEP-657 renders caret anchors
#: for a traceback frame. See :func:`_is_traceback_caret_compile`.
_PEP657_FILENAME = "<unknown>"

#: The stdlib module that compiles while *formatting an exception*.
#:
#: `traceback.py` only, deliberately, and this is not a detail. The obvious
#: reading is to also match `ast.py`, since PEP-657 reaches `compile` through
#: `ast.parse` — but `ast.py` is where `ast.literal_eval` lives, and a target
#: calling `literal_eval` on attacker input raises a `compile` event that is
#: exactly the security-relevant signal this observer exists to catch. Matching
#: `ast.py` suppressed it: PyHunt's own sanitized `code_evaluation` twin
#: silently changed verdict from `sink_reached_unproven` to `no_event`, i.e. a
#: working defence stopped being visible as one. `traceback.py` is on the stack
#: for caret rendering and is not on it for `literal_eval`, so it separates the
#: two cleanly.
_TRACEBACK_RENDERERS = ("traceback.py",)


def _is_traceback_caret_compile(args: tuple) -> bool:
    """True for the `compile` event PEP-657 raises while printing a traceback.

    On CPython >= 3.11 `traceback` renders caret anchors (`~~~~^^^^`) by calling
    `ast.parse` on each frame's source segment. `ast.parse` calls `compile`,
    which raises a **watched** audit event attributed to whichever frame is
    printing the traceback — in practice the PoC's own `except` block.

    The gate then rules `self_attributed`, which means "the PoC called the sink
    directly and therefore proved nothing". That verdict is wrong here: the PoC
    called `traceback.print_exc()`, and the interpreter compiled something on its
    own behalf. Four findings of one real run lost their honest `no_event` to
    this, and catching an exception and printing it is ordinary PoC behaviour.

    Two conditions, both required, so a target that genuinely compiles attacker
    input can never be filtered out by this:

    1. the filename is exactly ``<unknown>`` — what `ast.parse` passes for a
       bare source segment, and not something real code passes by accident; and
    2. a **stdlib** `traceback.py` or `ast.py` frame is on the stack right now.

    The stdlib check matters: a target file named `ast.py` is not the stdlib's,
    so the frame's path must sit under a noise root.

    One trap worth recording, because it hides the bug from a casual check: the
    event only fires when the frame's source is a real file on disk. Under
    ``python -c`` there is no segment for `linecache` to fetch, `ast.parse` is
    never reached, and no event is raised. A REPL or ``-c`` reproduction
    therefore "disproves" a defect that is entirely real in a `.py` file.
    """
    if len(args) < 2 or args[1] != _PEP657_FILENAME:
        return False
    try:
        frame = sys._getframe(1)
    except Exception:
        return False
    depth = 0
    while frame is not None and depth < _FRAME_SCAN_LIMIT:
        name = frame.f_code.co_filename
        if os.path.basename(name) in _TRACEBACK_RENDERERS:
            try:
                path = os.path.normcase(os.path.abspath(name))
            except Exception:
                return False
            if any(path.startswith(root) for root in _NOISE_ROOTS):
                return True
        frame = frame.f_back
        depth += 1
    return False


def _in_import_machinery() -> bool:
    """True when the current call is being made *by* an import.

    Walking the stack is the only reliable discriminator: there is no
    "import finished" audit event, so a depth counter cannot work, and the
    noisy events (`marshal.loads` of a .pyc, `exec` of a module body,
    `compile` of a namedtuple accessor) look identical to the real thing
    from their arguments alone.
    """
    try:
        frame = sys._getframe(1)
    except Exception:
        return False
    depth = 0
    while frame is not None and depth < _FRAME_SCAN_LIMIT:
        name = frame.f_code.co_filename
        if "importlib" in name or "zipimport" in name:
            return True
        frame = frame.f_back
        depth += 1
    return False


def _attribution() -> str:
    """`  <- from file:line in func` naming the code that caused the event.

    Without this an event line only proves "a process was spawned" — which
    perfectly innocent code also does. What makes it EVIDENCE is that the spawn
    came from the sink under test. This is the attribution JFR gives Java for
    free via its stackTrace.

    Interpreter and stdlib frames are skipped (the nearest frame to a
    `subprocess.run` is always `subprocess.py:_execute_child`, which says
    nothing). This observer's own frames are skipped too. The PoC is NOT
    skipped, deliberately: if the nearest user frame is the PoC rather than the
    target, the PoC reached the sink DIRECTLY and therefore proves nothing about
    the target — the hunter needs to see that.

    Best-effort: any failure yields "" rather than breaking the event line.
    """
    frame = _nearest_user_frame()
    if frame is None:
        return ""
    return (f"  <- from {frame.f_code.co_filename}:{frame.f_lineno} "
            f"in {frame.f_code.co_name}")


def _nearest_user_frame():
    """The frame :func:`_attribution` would name, as a frame object.

    Split out so that :func:`_emit_declared_filename` can ask *which file
    declared this name* and get the same answer the event line will carry,
    rather than a second, subtly different walk.
    """
    try:
        frame = sys._getframe(2)   # 0 = here, 1 = _attribution/_emit_*, 2 = _hook
    except Exception:
        return None
    me = os.path.normcase(os.path.abspath(__file__))
    depth = 0
    while frame is not None and depth < _FRAME_SCAN_LIMIT:
        try:
            path = os.path.normcase(os.path.abspath(frame.f_code.co_filename))
        except Exception:
            return None
        if path == me:
            pass                       # never attribute an event to the observer
        elif any(path.startswith(r) for r in _TARGET_ROOTS):
            return frame               # the target wins over the noise filter
        elif not any(path.startswith(r) for r in _NOISE_ROOTS):
            return frame
        frame = frame.f_back
        depth += 1
    return None


def _hook(event: str, args: tuple) -> None:
    if not _state["armed"] or _state["reentrant"]:
        return
    if event not in WATCHED_EVENTS:
        return
    _state["reentrant"] = True             # our own formatting must not recurse
    try:
        if event in _IMPORT_NOISY_EVENTS and _in_import_machinery():
            return
        if event == "open":
            path = args[0] if args else None
            if _is_poc(path) or _boring_open(path):
                return
        elif event == "compile":
            if len(args) > 1 and _is_poc(args[1]):
                return                     # runpy compiling the PoC itself
            if _is_traceback_caret_compile(args):
                return                     # PEP-657 caret rendering, not the target
        elif event == "exec":
            code = args[0] if args else None
            if _is_poc(getattr(code, "co_filename", None)):
                return                     # runpy exec'ing the PoC itself
        seen = _counts[event] = _counts.get(event, 0) + 1
        if seen > MAX_PER_EVENT:
            if seen == MAX_PER_EVENT + 1:
                _emit(f"audit:{event} <further occurrences suppressed>")
            return
        _emit(f"audit:{event} {_short(args)}{_attribution()}")
        if event == "compile" and len(args) > 1:
            # The filename, before _short() can lose it. See C-4.
            _emit_declared_filename(args[1])
    except Exception:
        pass
    finally:
        _state["reentrant"] = False


_ENV_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)

#: Never echoed by value and never written back into ``os.environ``.
_SECRET_ENV = ("PYHUNT_NONCE", "PYHUNT_OBSERVER_KEY")


def _apply_env_assignments(argv: list[str]) -> list[str]:
    """Consume leading `NAME=VALUE` tokens and apply them to this process.

    The runtime's own deps_hint tells the agent to reach the target with
    `PYTHONPATH=/target python3 poc.py`. The shell only treats `NAME=VALUE` as
    an assignment at the START of a command, so once that command is spliced
    after `python3 <hook>` the assignment arrives here as a plain argv token —
    the wrapper would then treat "PYTHONPATH=/target" as the script name and
    exit 2 WITHOUT EVER RUNNING THE POC, which reads downstream as "the
    observer saw nothing". Applying it here keeps the documented invocation
    working, and because it is applied before the PoC is loaded, the PoC sees
    the intended import path.

    PyHunt's own two secrets are handled here the way they are at import: taken
    into the hook's state and NEVER written into ``os.environ``, and echoed with
    their values masked. An assignment token is the one route by which a
    scrubbed secret could get re-planted into the environment the target reads,
    and the echo line is the one route by which the observer could print its own
    signing key into the transcript it signs.
    """
    out = list(argv)
    while out:
        m = _ENV_ASSIGN.match(out[0])
        if not m:
            break
        name, value = m.group(1), m.group(2)
        if name == "PYHUNT_NONCE":
            _state["nonce"] = value
        elif name == "PYHUNT_OBSERVER_KEY":
            global _SIGN
            _SIGN = _make_signer(value)
        else:
            os.environ[name] = value
            if name == "PYTHONPATH":
                # sys.path was already built from the inherited environment, so
                # setting os.environ alone would be too late for this process.
                for part in reversed(value.split(os.pathsep)):
                    if part and part not in sys.path:
                        sys.path.insert(0, part)
        shown = "<redacted>" if name in _SECRET_ENV else value
        _emit(f"env {name}={shown}")
        out.pop(0)
    return out


def _strip_interpreter(argv: list[str]) -> list[str]:
    """Drop a leading `python3 [-u ...]` so the wrapper can be spliced in front
    of a plain run command (`python3 vash_audit_hook.py <run_cmd>`)."""
    out = list(argv)
    while out:
        head = out[0]
        base = os.path.basename(head).lower()
        if base.startswith("python") or base in ("py", "py.exe"):
            out.pop(0)
            continue
        if head in ("-u", "-B", "-E", "-s", "-S", "-I", "-q"):
            out.pop(0)
            continue
        break
    return out


def main(argv: list[str]) -> int:
    # Order matters: `PYTHONPATH=/target python3 poc.py` puts the assignment
    # first, and a `python3` may follow it.
    cmd = _strip_interpreter(_apply_env_assignments(argv))
    # `_apply_env_assignments` has already folded any `PYHUNT_NONCE=` argv token
    # into `_state`. It is deliberately NOT re-read from `os.environ` here: the
    # import-time `pop` scrubbed it, and reading it back would mean a target
    # that re-planted `PYHUNT_NONCE` between import and now could choose the
    # nonce this observer stamps on its lines.
    _state["nonce"] = _state.get("nonce") or ""
    if not cmd or cmd[0].startswith("-"):
        _emit(f"usage: vash_audit_hook.py [python3] <poc.py> [args...] "
              "(only the script form is observable; `-c` / `-m` are not)")
        return 2

    script = cmd[0]
    if not os.path.isfile(script):
        _emit(f"error: no such PoC script: {script}")
        return 2

    _state["poc"] = os.path.normcase(os.path.abspath(script))
    sys.argv = [script] + cmd[1:]
    sys.addaudithook(_hook)
    _state["armed"] = True
    # The banner declares the channel and whether lines are signed, so a reader
    # of the transcript can tell an authentic stream from a degraded one without
    # having the key. `unsigned_fallback` is the honest name for "these lines
    # are on the same stream the target writes to, and they are not signed" —
    # nothing may read that as authentic.
    channel = "fd3" if _CHANNEL_FD is not None else "stderr"
    signed = bool(_SIGN("probe"))
    stream = channel if signed else f"{channel}:unsigned_fallback"
    _emit(f"hook-armed poc={script} pid={os.getpid()} "
          f"channel={stream} events={','.join(WATCHED_EVENTS)}")

    code = 0
    try:
        runpy.run_path(script, run_name="__main__")
    except SystemExit as exc:
        if isinstance(exc.code, int):
            code = exc.code
        elif exc.code is not None:
            _emit(f"poc-exit {_short(exc.code)}")
            code = 1
    finally:
        _state["armed"] = False
        total = sum(_counts.values())
        detail = " ".join(f"{k}={v}" for k, v in sorted(_counts.items())) or "none"
        _emit(f"hook-summary observed={total} {detail} "
              "(no events observed is NOT proof the vulnerability did not fire)")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
