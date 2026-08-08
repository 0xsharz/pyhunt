"""The gate. The only code permitted to call a finding proven.

Inputs are the artifacts of one PoC run — the **observer's** output, the nonce
the payload carried, where the target lives, where the PoC lives, which file
the finding is about. Output is one :class:`ExecutionVerdict`.

Everything here is a pure function of its arguments: no I/O, no model, no
clock. That is deliberate — the gate is the component whose correctness the
zero-false-positive claim rests on, so it must be testable by handing it a
recorded transcript and asserting an outcome.

The promotion rule, in full::

    PROVEN  ⟺  the observer armed
           ∧   at least one dangerous-operation event fired
           ∧   that event carried this PoC's nonce
           ∧   the frame that caused it is inside the target, is not a frame
               the PoC synthesized, and names THIS finding's file
           ∧   the payload was INTERPRETED, not merely carried

Every other combination produces an outcome that leaves the finding exactly as
the static analysis left it. Read the outcome table in :class:`Outcome` as the
specification; the code below is its implementation.

Four things the gate learned the hard way, each of which is a test:

* **`co_filename` is a string, not an observation.** ``compile(src,
  "/target/app/reports.py", "exec")`` followed by ``exec`` produces a *genuine*
  CPython audit event whose frame claims to be inside the target. The frame is
  real; the name is a lie the caller chose. Any attribution to a filename that
  was handed to ``compile``/``exec`` during the run is therefore untrusted.
* **The nonce is keyed on the task, not the finding.** The hunt agent has to
  know it while authoring the PoC, before any finding exists, so every finding
  from one task shares it. One real vulnerability would otherwise prove N
  unrelated findings. ``finding_file`` closes that: the attributed frame must
  be *this finding's own file*.
* **Carrying a value is not interpreting it.** ``subprocess.run(["echo",
  name])`` raises a real ``subprocess.Popen`` from the target's own frame with
  the nonce in argv — a *working defence* whose evidence is byte-identical to
  the vulnerable case. The same hole exists for ``open`` (a nonce in a path is
  not proof the path escaped its root) and for the network events (a nonce in
  a URL's *query string* is not proof of SSRF). Each family gets a predicate
  that looks at the part of the argument that would have to be attacker-chosen
  for the vulnerability to be real.
* **A missing nonce is not a licence to skip attribution.** Without a nonce no
  event can be tied to this PoC, so there is nothing to promote on.
"""

from __future__ import annotations

import inspect
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence

from oracle.classes import is_undecidable
from oracle.markers import ObserverEvent, parse_observer_output

# Frames inside these are never the target's code: the interpreter, the
# standard library, installed packages, and the observer itself. A sink reached
# through `subprocess.py` is attributed to whatever called into it.
_NEVER_TARGET_FRAGMENTS = (
    "/site-packages/",
    "/dist-packages/",
    "/lib/python",
    "<frozen ",
    "<string>",
)

# Shells. A `Popen` whose argv[0] is one of these, carrying the nonce inside the
# command string, means the payload was PARSED AS A COMMAND — which is the
# difference between a command injection and a string that happened to travel
# through a safe argv.
_SHELLS = ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh",
           "cmd.exe", "powershell")

# Events where the nonce appearing in the arguments at all is itself proof of
# interpretation: the value was not passed alongside code, it WAS the code (or
# the pickle, or the shared object). Note what is NOT here any more — `open`
# and the three network events, which used to sit in this list and made the
# gate promote two different working defences. See `_payload_was_interpreted`.
_CODE_EXECUTION_EVENTS = (
    "exec", "compile", "os.system",
    "pickle.find_class", "marshal.load", "marshal.loads",
    "ctypes.dlopen",
)

# Process-spawn events: interpreted only when argv[0] is a shell.
_PROCESS_EVENTS = ("subprocess.Popen", "os.exec", "os.spawn", "os.posix_spawn",
                   "os.startfile")

# Network events: interpreted only when the nonce is in the HOST, because the
# host is the part an SSRF has to control. A defended fetch where the host is
# allowlisted and the attacker owns only the query string still carries the
# nonce in the URL — and used to promote.
_NETWORK_EVENTS = ("urllib.Request", "socket.connect", "socket.getaddrinfo")

# The directory `oracle.nonce.canary_path` puts the canary in. Kept as a bare
# string rather than importing the function so the gate stays free of any
# dependency that could grow I/O later.
_CANARY_DIR_MARKER = "pyhunt-canary"

# `compile(source, filename, mode)` — the mode is a closed vocabulary, which is
# what lets the filename be recovered from a truncated repr without splitting
# the tuple.
_COMPILE_MODES = ("exec", "eval", "single", "func_type")

# A quoted string inside a repr'd argument tuple. The three body alternatives
# are disjoint on their first character — ordinary, backslash-escape, the OTHER
# quote character — so the match is linear. An ambiguous pattern here would be
# a backtracking bomb reachable from attacker-controlled text: the argument
# repr of an audit event is, by definition, whatever the payload put there.
_QUOTED_RX = re.compile(
    r"""(?P<q>['"])(?P<s>(?:[^'"\\]|\\.|(?!(?P=q))['"])*)(?P=q)"""
)

# `<code object f at 0x7f…, file "/target/app/reports.py", line 1>` — the
# filename a code object was minted with, which is exactly the string that will
# show up as `co_filename` in every frame that object creates.
_CODE_OBJECT_FILE_RX = re.compile(r"""\bfile\s+(['"])(?P<f>.*?)\1""")

# Does the marker parser support signature verification yet (Contract A)?
# Probed once, at import, so a gate running against an older `markers` module
# degrades to unverified parsing instead of raising.
try:  # pragma: no cover - trivial introspection
    _PARSER_ACCEPTS_KEY = "key" in inspect.signature(parse_observer_output).parameters
except (TypeError, ValueError):  # pragma: no cover - defensive
    _PARSER_ACCEPTS_KEY = False


class Outcome(str, Enum):
    """What the execution attempt established.

    ================== ========================================================
    Outcome            Meaning, and what it does to the finding
    ================== ========================================================
    PROVEN             The vulnerable operation fired, carried this PoC's
                       nonce, was caused by the target's own code *in this
                       finding's file*, AND the payload was demonstrably
                       *interpreted* rather than merely carried. **Promotes**
                       the finding.
    SINK_REACHED_UNPROVEN
                       The target's own code performed the dangerous operation
                       with the attacker's data present — but nothing shows the
                       data was interpreted, or the frame was in a different
                       file from the one this finding is about. This is what a
                       working defence looks like from the runtime:
                       `subprocess.run([...])` still spawns a process, it just
                       does not run the payload. Reported as "sink reached,
                       exploitation not demonstrated"; it neither promotes nor
                       demotes.
    SELF_ATTRIBUTED    An event fired, but every frame that caused one names
                       the PoC, names nothing placeable, or names a filename
                       the PoC *synthesized* via `compile`/`exec`. The PoC
                       reached the sink itself, or minted the frame that claims
                       otherwise, and proved nothing about the target.
    NONCE_MISMATCH     Events fired but none carried this PoC's nonce — output
                       from another concurrent task, a stale log, a replayed
                       transcript, or no nonce was supplied at all. Not
                       attributable, so not proof.
    NO_EVENT           The observer armed and saw no dangerous operation. The
                       most that can be said is that this PoC did not
                       demonstrate it; the sink may still be reachable another
                       way. **Not** a refutation.
    OBSERVER_ABSENT    No armed banner: the observer never ran. Says nothing
                       about the vulnerability at all.
    NOT_ATTEMPTED      Execution was unavailable — static-only run, or the
                       toolchain was missing. An environment limitation, never
                       a verdict on the code.
    NOT_APPLICABLE     The vulnerability class cannot be settled by running
                       code — either because the question is a policy question
                       (access control, business logic) or because this
                       observer has no event for the sink (SQL/NoSQL
                       injection, XSS, template injection). Counted separately
                       so the proven-ratio stays honest.
    ================== ========================================================
    """

    PROVEN = "proven"
    SINK_REACHED_UNPROVEN = "sink_reached_unproven"
    SELF_ATTRIBUTED = "self_attributed"
    NONCE_MISMATCH = "nonce_mismatch"
    NO_EVENT = "no_event"
    OBSERVER_ABSENT = "observer_absent"
    NOT_ATTEMPTED = "not_attempted"
    NOT_APPLICABLE = "not_applicable"


#: The one outcome that may raise a finding's standing. Kept as a set of one so
#: that adding a second promoting outcome is a visible, reviewable edit rather
#: than a changed comparison operator somewhere.
PROMOTING = frozenset({Outcome.PROVEN})


@dataclass(frozen=True)
class ExecutionVerdict:
    """The gate's decision about one PoC run."""

    outcome: Outcome
    reason: str
    #: Marker lines that carried the decision, verbatim, for the report.
    evidence: list[str] = field(default_factory=list)
    #: Dangerous-operation events seen, whether or not they were attributable.
    events_seen: int = 0
    #: Events that were both nonce-matched and target-attributed.
    events_attributed: int = 0
    observer_armed: bool = False
    nonce: str | None = None
    #: What the model claimed, kept alongside so a divergence is auditable.
    model_claimed_success: bool | None = None
    #: Marker lines that claimed to be observer output and failed HMAC
    #: verification. Contract A: these are dropped, never judged — but a target
    #: or PoC *attempting* to forge proof is the single most interesting event
    #: in a run, so the count is carried into the proof record and the report.
    forged_lines: int = 0
    #: True when the markers were verified against a per-run observer key. When
    #: False the transcript was accepted unverified, which is the pre-Contract-A
    #: behaviour and is stated rather than assumed.
    markers_signed: bool = False

    @property
    def proven(self) -> bool:
        """True only when execution established the vulnerability. This is the
        value that replaces the model-set ``poc.succeeded``."""
        return self.outcome in PROMOTING

    @property
    def contradicts_model(self) -> bool:
        """The model said the PoC succeeded and the gate disagrees.

        Not an error — the model may be reading assertions the observer cannot
        see. It is worth counting, because a rising rate means either the
        payload templates stopped embedding the nonce or the prompt is
        over-claiming.
        """
        return bool(self.model_claimed_success) and not self.proven

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome.value,
            "proven": self.proven,
            "reason": self.reason,
            "evidence": self.evidence,
            "events_seen": self.events_seen,
            "events_attributed": self.events_attributed,
            "observer_armed": self.observer_armed,
            "nonce": self.nonce,
            "model_claimed_success": self.model_claimed_success,
            "contradicts_model": self.contradicts_model,
            "forged_lines": self.forged_lines,
            "markers_signed": self.markers_signed,
        }


# --------------------------------------------------------------------------
# Path handling
# --------------------------------------------------------------------------

def _normalise(path: str | None) -> str:
    if not path:
        return ""
    try:
        return os.path.normcase(os.path.abspath(path.strip()))
    except Exception:
        return os.path.normcase(path)


def _is_pseudo_file(frame_file: str | None) -> bool:
    """``<string>``, ``<stdin>``, ``<template>``, ``<frozen importlib…>``.

    CPython uses ``<…>`` for code that has no file. None of it is ever the
    target's own source, and the generalised check matters because the gate
    used to exclude only the literal ``<string>`` — which is nothing more than
    ``compile``'s *default*. Anything else in the same shape got through.
    """
    if not frame_file:
        return True
    base = os.path.basename(frame_file.strip())
    return base.startswith("<") and base.endswith(">")


def _repo_relative(path: str | None, roots: tuple[str, ...]) -> str:
    """Reduce a path to something comparable across the container boundary.

    The observer records container-side frames (``/target/app/reports.py``);
    a finding records a repo-relative path (``app/reports.py``); a host-side
    caller may hold ``/Users/…/repo/app/reports.py``. All three have to compare
    equal, so each is stripped of whichever target root it sits under and what
    remains is matched.
    """
    if not path:
        return ""
    text = path.strip()
    try:
        norm = os.path.normcase(os.path.normpath(text))
    except Exception:  # pragma: no cover - defensive
        norm = os.path.normcase(text)
    for root in roots:
        stripped = root.rstrip("/\\")
        if not stripped:
            continue
        if norm == stripped:
            return ""
        for sep in ("/", os.sep):
            prefix = stripped + sep
            if norm.startswith(prefix):
                return norm[len(prefix):].lstrip("/\\")
    return norm.lstrip("/\\")


def _same_file(frame_file: str | None, finding_file: str | None,
               roots: tuple[str, ...]) -> bool:
    a = _repo_relative(frame_file, roots)
    b = _repo_relative(finding_file, roots)
    return bool(a) and bool(b) and a == b


# --------------------------------------------------------------------------
# Reading arguments out of a repr'd audit event
# --------------------------------------------------------------------------

def _unescape(text: str) -> str:
    return (text.replace("\\\\", "\x00")
                .replace("\\'", "'")
                .replace('\\"', '"')
                .replace("\x00", "\\"))


def _quoted_strings(text: str | None, limit: int = 24) -> list[str]:
    """Every quoted string in a repr'd tuple, in order."""
    out: list[str] = []
    for match in _QUOTED_RX.finditer(text or ""):
        out.append(_unescape(match.group("s")))
        if len(out) >= limit:
            break
    return out


def _first_arg_string(text: str | None) -> str | None:
    """The first element of a repr'd tuple, when it is a string.

    ``('/etc/passwd', 'r', 524288)`` → ``/etc/passwd``.
    ``(3, 'r', 524288)`` → None, because an integer fd is not a path and must
    not be confused with the mode string that follows it.
    """
    stripped = (text or "").lstrip()
    if not stripped.startswith("("):
        return None
    match = _QUOTED_RX.match(stripped[1:].lstrip())
    return _unescape(match.group("s")) if match else None


def _url_host(url: str) -> str:
    """The netloc, without userinfo.

    Userinfo is dropped on purpose: ``http://user:<nonce>@allowed.host/`` puts
    the nonce in a string the attacker controls without the request ever going
    anywhere the attacker chose, so counting it would reopen exactly the hole
    this function exists to close.
    """
    rest = url.split("://", 1)[-1]
    for cut in ("/", "?", "#"):
        rest = rest.split(cut, 1)[0]
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]
    return rest


def _host_strings(event: ObserverEvent) -> list[str]:
    """The parts of a network event a real SSRF would have to control."""
    name = event.event_name
    if name == "urllib.Request":
        url = _first_arg_string(event.args_text)
        return [_url_host(url)] if url else []
    if name == "socket.getaddrinfo":
        host = _first_arg_string(event.args_text)
        return [host] if host else []
    if name == "socket.connect":
        # `(<socket.socket …>, ('evil.host', 80))` — the address is the only
        # place a hostname can appear, and the socket's own repr contributes
        # only local addresses, which cannot carry a nonce.
        return _quoted_strings(event.args_text)
    return []


def declared_filenames(event: ObserverEvent) -> set[str]:
    """Filenames this event handed to ``compile``/``exec``.

    These are the strings that become ``co_filename`` for every frame the
    resulting code object creates — i.e. the raw material of a forged
    attribution. Recovered from the event's own arguments so the gate closes
    C-4 on a recorded transcript alone; the observer also reports them
    out-of-band, and :func:`judge` takes the union.

    Best-effort by construction: the hook truncates long argument reprs, so a
    ``compile`` of a large source can lose its filename here. That is why the
    hook-side channel is the primary one and this is the backstop.

    **The arity matters, and getting it wrong once cost the whole defence.**
    CPython's ``compile`` audit event carries ``(source, filename)`` — two
    arguments, no mode::

        compile audit args: [('compile', 2, ['bytes', 'str'])]

    This function used to require ``quoted[-1] in _COMPILE_MODES``, i.e. the
    three-argument form of the *builtin*, which the audit event never mirrors.
    It therefore returned nothing for every real event, leaving the ``exec``
    code-object repr as the only live source of synthesized filenames — and
    that repr is truncated at 200 characters by the hook and is never emitted
    at all when a PoC runs its code object through ``types.FunctionType``
    instead of ``exec``. Both were confirmed bypasses producing a false
    ``proven``. Both forms are accepted now, the two-argument one first
    because it is the one that actually occurs.
    """
    name = event.event_name
    found: set[str] = set()
    if name == "compile":
        quoted = _quoted_strings(event.args_text)
        if len(quoted) >= 2 and quoted[-1] in _COMPILE_MODES:
            # `(source, filename, mode)`. Anchoring on the closed mode
            # vocabulary rather than splitting the tuple, which repr makes
            # unreliable. Kept for any caller that synthesizes the builtin's
            # own signature into an event.
            found.add(quoted[-2])
        elif len(quoted) >= 2:
            # `(source, filename)` — what CPython emits. The filename is last.
            found.add(quoted[-1])
    if name == "exec":
        for match in _CODE_OBJECT_FILE_RX.finditer(event.args_text or ""):
            found.add(match.group("f"))
    return {f for f in found if f}


#: Marker kinds through which the observer reports a declared filename
#: directly. Mirrors ``replay._OUT_OF_BAND_SYNTHESIS_KINDS``; the gate accepts
#: the same vocabulary so that judging a recorded transcript needs nothing but
#: the transcript.
_OUT_OF_BAND_SYNTHESIS_KINDS = frozenset(
    {"hook-synthesized", "synthesized", "hook-compile", "compile-filename"})

#: ``file=``/``filename=``/``path=`` inside such a line.
_KEYED_FILE_RX = re.compile(r"\b(?:file|filename|path)=(\S+)")


def _keyed_or_bare_filename(text: str | None) -> list[str]:
    """``file=/a/b.py`` → ``["/a/b.py"]``; a bare path body → itself."""
    body = (text or "").strip()
    keyed = [v.strip("'\", ") for v in _KEYED_FILE_RX.findall(body)]
    if keyed:
        return [k for k in keyed if k]
    if body and len(body) <= 512 and (
            "/" in body or body.endswith((".py", ".pyc", ".pyo"))
            or (body.startswith("<") and body.endswith(">"))):
        return [body]
    return []


def synthesized_filenames_from_events(
    events: Iterable[ObserverEvent],
) -> frozenset[str]:
    """Every filename minted by ``compile``/``exec`` across a transcript.

    Public because ``replay.py`` may want the same set for its proof record.

    **A filename declared from the file it names is not synthesized**, and the
    distinction is the whole difference between catching a forgery and
    inventing a false negative. Compare:

    * A PoC does ``compile(src, "/target/app/reports.py", "exec")`` from
      ``poc.py``. The declaring frame is the PoC; the name it chose is someone
      else's file. Every frame that code object goes on to create is a
      fabrication, and the gate must refuse them — this is C-4.
    * A target legitimately does ``exec(compile(user_code, __file__, "exec"))``
      inside ``handler.py``. The declaring frame *is* ``handler.py`` and the
      name it passed is its own. That is not a spoof, it is eval-injection —
      the very thing being hunted — and the frames the injected code creates
      are the proof of it.

    Distrusting both would have made the sincere case unprovable the moment
    :func:`declared_filenames` started working, trading a false positive for a
    false negative. Only names declared from somewhere other than themselves
    are collected.

    Two sources. The event lines are the backstop; the observer's own
    ``hook-compile`` report is authoritative, because the hook holds the
    filename before ``_short()`` truncates it at 200 characters — a
    ``compile`` of a large source loses its filename from the printed repr,
    and that was a confirmed way to spoof a frame past this check. The hook
    has already applied the declared-from-its-own-file exemption above, using
    the real paths rather than two strings recovered from a repr, so those
    lines are taken as given.
    """
    out: set[str] = set()
    for event in events:
        if event.kind in _OUT_OF_BAND_SYNTHESIS_KINDS:
            for name in _keyed_or_bare_filename(event.args_text):
                out.add(name)
            continue
        if not event.is_audit_event:
            continue
        here = _normalise(event.frame_file)
        for name in declared_filenames(event):
            if _normalise(name) != here:
                out.add(name)
    return frozenset(out)


# --------------------------------------------------------------------------
# Attribution
# --------------------------------------------------------------------------

def _is_synthesized_attribution(
    event: ObserverEvent,
    synthesized: frozenset[str],
) -> bool:
    """Is this event's frame one the PoC (or the target) *minted*?

    ``compile(src, "/target/app/reports.py", "exec")`` then ``exec`` yields a
    real audit event from a frame whose ``co_filename`` is that string. Nothing
    about the frame is evidence: the caller chose the name.

    One exemption, and it is not a loophole. The ``compile`` or ``exec`` call
    that *declared* the filename is itself attributed to its real caller, so
    when a target legitimately does ``exec(compile(user_code, __file__,
    "exec"))`` — genuine eval-injection — that event's own frame stays
    trustworthy and the finding can still be proven on it. Only the frames the
    minted code object goes on to create are distrusted.
    """
    if not synthesized:
        return False
    norm = _normalise(event.frame_file)
    if norm not in synthesized:
        return False
    if event.event_name in ("compile", "exec"):
        declared = {_normalise(f) for f in declared_filenames(event)}
        if norm in declared:
            return False
    return True


def _is_target_frame(
    frame_file: str | None,
    target_roots: tuple[str, ...],
    poc_paths: tuple[str, ...],
) -> bool:
    """Did the target's own code cause this event?

    Ways the answer is no, each a distinct kind of non-proof: the frame is the
    PoC (the exploit bypassed the code under test), the frame is the
    interpreter or an installed package (says nothing about this repo), the
    frame is a ``<…>`` pseudo-file (there is no such source), or there is no
    frame at all (an observer without attribution cannot support a promotion).

    Frames whose *name* was synthesized by ``compile``/``exec`` are rejected by
    :func:`_is_synthesized_attribution` before this is reached — that check
    needs the whole event, not just the filename.
    """
    if not frame_file:
        return False
    if _is_pseudo_file(frame_file):
        return False
    norm = _normalise(frame_file)
    if norm in poc_paths:
        return False
    if any(fragment in norm for fragment in _NEVER_TARGET_FRAGMENTS):
        return False
    if not target_roots:
        # No root was supplied: refuse to guess. Falling back to "anything that
        # is not the PoC" would promote findings on the strength of a stdlib
        # frame, which is exactly the over-claiming this module exists to stop.
        return False
    return any(norm.startswith(root) for root in target_roots)


# --------------------------------------------------------------------------
# Condition 5: interpretation
# --------------------------------------------------------------------------

def _path_escaped_target(path: str, target_roots: tuple[str, ...]) -> bool:
    """Did the opened path leave the directories the target owns?

    Traversal is proven by *where the read landed*, not by what the path
    string contains. ``open(os.path.join(BASE, os.path.basename(user_path)))``
    with ``../../etc/passwd_<nonce>`` still carries the nonce and still resolves
    inside ``BASE`` — the defence worked, and the old predicate promoted it.
    """
    if not path or not target_roots:
        return False
    norm = _normalise(path)
    return not any(norm.startswith(root) for root in target_roots)


def _is_canary(path: str | None, nonce: str | None) -> bool:
    """The path the payload was asked to create — see ``oracle.nonce.canary_path``."""
    if not path or not nonce or nonce not in path:
        return False
    return _CANARY_DIR_MARKER in path.replace("\\", "/")


def _compiled_code_was_executed(
    event: ObserverEvent,
    events: Sequence[ObserverEvent],
) -> bool:
    """Did the code object this ``compile`` produced actually run?

    Compiling is carrying, not interpreting. ``ast.literal_eval`` parses its
    input — which raises a ``compile`` audit event carrying the whole payload,
    from the target's own frame, indistinguishable at the event level from
    ``eval`` — and then executes nothing at all. Treating ``compile`` as proof
    on its own promoted that defended sink to ``proven``, which is a false
    exploit of the exact kind the gate exists to prevent: the finding arrives
    carrying the strongest claim PyHunt can make, and a reader who trusts that
    claim stops checking.

    The two halves are separated by one event, and the recordings in
    ``corpus/code_evaluation/observed/`` show it plainly. ``eval`` emits
    ``compile`` **then** ``exec`` of the resulting code object, then whatever
    the payload does. ``ast.literal_eval`` emits ``compile`` and stops.

    The link is checked, not assumed: an ``exec`` counts only when its code
    object names a filename this very ``compile`` declared. Where the
    declaration cannot be recovered — the hook truncates long reprs — the
    weaker "some code was exec'd in this run" is accepted rather than
    silently dropping a genuine proof, and that is the one place this
    predicate is looser than its docstring.
    """
    declared = {_normalise(f) for f in declared_filenames(event)}
    saw_exec = False
    for other in events:
        if not other.is_audit_event or other.event_name != "exec":
            continue
        saw_exec = True
        for match in _CODE_OBJECT_FILE_RX.finditer(other.args_text or ""):
            if _normalise(match.group("f")) in declared:
                return True
    return saw_exec and not declared


def _payload_was_interpreted(
    event: ObserverEvent,
    nonce: str | None,
    target_roots: tuple[str, ...],
    events: Sequence[ObserverEvent] = (),
) -> bool:
    """Did the target *act on* the attacker's data, or merely carry it?

    This predicate is the fix for the gate's original over-promotion, and it
    has now been widened three times for the same reason each time: the nonce
    being *somewhere in the arguments* is a fact about the payload, not about
    the target's behaviour.

    * **Process spawn** — a shell invocation whose command string contains the
      nonce. ``('/bin/sh', ['-c', 'echo hi; touch …<nonce>'])`` is injection;
      ``('/bin/echo', ['echo', 'hi; touch …<nonce>'])`` is the same string
      safely passed as an argument, and argv[0] is what tells them apart.
    * **Code execution** — ``exec``, ``os.system``, an unpickle, ``marshal``,
      ``ctypes.dlopen``: carrying the value at all means executing it.
      ``compile`` is the exception and is deferred to
      :func:`_compiled_code_was_executed`, because a parse is not a run.
    * **File open** — the opened path must have left ``target_roots``, or be
      the canary. A nonce inside a path that still resolves under the target's
      own root is what a *working* path-traversal defence produces.
    * **Network** — the nonce must be in the *host*. A defended fetch to an
      allowlisted host with an attacker-controlled query string carries the
      nonce in the URL and proves nothing about where the request went.

    A caller that can observe the payload's real side effect (the canary file,
    read from outside the sandbox after it exits) should pass
    ``canary_touched``: a materialised canary is direct proof, and this
    predicate is inference from arguments.
    """
    if not nonce or nonce not in event.args_text:
        return False
    name = event.event_name
    if name == "compile":
        return _compiled_code_was_executed(event, events)
    if name in _CODE_EXECUTION_EVENTS:
        return True
    if name in _PROCESS_EVENTS:
        head = event.args_text[:120].lower()
        return any(sh in head for sh in _SHELLS)
    if name == "open":
        path = _first_arg_string(event.args_text)
        if not path or nonce not in path:
            return False
        return _path_escaped_target(path, target_roots) or _is_canary(path, nonce)
    if name in _NETWORK_EVENTS:
        return any(nonce in host for host in _host_strings(event) if host)
    return False


# --------------------------------------------------------------------------
# Parsing, with Contract A signature verification when a key is available
# --------------------------------------------------------------------------

def _parse(text: str | None, key: str | None) -> tuple[list[ObserverEvent], int, bool]:
    """Parse and, when a key is supplied, verify.

    Written against both shapes of ``parse_observer_output``: the plain list it
    returned before Contract A, and the richer result that carries
    ``forged_lines`` / ``signed`` afterwards. The gate must not be the thing
    that breaks while the two halves land.
    """
    if key and _PARSER_ACCEPTS_KEY:
        parsed = parse_observer_output(text, key=key)
    else:
        parsed = parse_observer_output(text)
    events = list(getattr(parsed, "events", parsed))
    forged = int(getattr(parsed, "forged_lines", 0) or 0)
    # Absent attribute defaults to False, never to "we passed a key so it must
    # have been checked". Unverified reading as verified is the one direction
    # this must never fail in.
    signed = bool(getattr(parsed, "signed", False))
    return events, forged, signed


def _forgery_note(forged_lines: int) -> str:
    if not forged_lines:
        return ""
    return (
        f" {forged_lines} marker line(s) failed observer-key verification and "
        "were discarded before judging — something in this run tried to forge "
        "proof."
    )


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

def judge(
    *,
    observer_output: str | None = None,
    nonce: str | None,
    canary_touched: bool | None = None,
    target_roots: list[str] | tuple[str, ...] = (),
    poc_paths: list[str] | tuple[str, ...] = (),
    finding_file: str | None = None,
    synthesized_filenames: Iterable[str] = frozenset(),
    observer_key: str | None = None,
    vuln_class: str | None = None,
    execution_available: bool = True,
    toolchain_missing: bool = False,
    model_claimed_success: bool | None = None,
    require_nonce: bool = True,
    run_output: str | None = None,
) -> ExecutionVerdict:
    """Decide what one PoC run established.

    Parameters
    ----------
    observer_output
        The **observer's** transcript for one replay run. Named for what it has
        to be: not ``poc.run_output``, which is text a hunt agent wrote about
        its own work and which the gate must never see. ``replay.py`` produces
        this from its own container.
    nonce
        The nonce this PoC's payload was built with. It is **required**: with
        no nonce nothing can be tied to this PoC, and the verdict is
        ``NONCE_MISMATCH`` rather than a promotion on attribution alone.
    canary_touched
        The payload's side effect really materialised. Only meaningful when the
        caller read it from *outside* the sandbox the PoC ran in, after that
        sandbox exited — a canary stat'd on a filesystem the PoC could write to
        directly is not evidence.
    target_roots
        Directories that constitute "the target's own code". Both the host repo
        path and the in-container mount (``/target``) should be passed, because
        the frame paths the observer records are container-side. Also used by
        condition 5 to decide whether an ``open`` escaped the target.
    poc_paths
        Path(s) to the generated PoC. A frame naming one of these means the
        exploit reached the sink directly.
    finding_file
        The file **this finding** is about, repo-relative or absolute. The
        nonce is keyed on the task, not the finding, because the hunt agent
        must know it while authoring the PoC — so without this, one real
        vulnerability proves every finding that shares the task. A frame inside
        the target but in a different file yields
        ``SINK_REACHED_UNPROVEN``, and the reason names both files.
    synthesized_filenames
        Filenames the observer saw passed to ``compile``/``exec`` during the
        run. Attribution to any of them is untrusted: ``co_filename`` is
        whatever string ``compile`` was handed, so such a frame is the PoC's
        claim about itself. The gate also derives this set from the transcript
        and takes the union, so the check holds even if the observer's
        out-of-band channel is unavailable.
    observer_key
        The per-run HMAC key the observer signed its marker lines with
        (Contract A). When supplied, lines that fail verification are discarded
        and counted in ``forged_lines`` — they never reach a verdict.
    execution_available, toolchain_missing
        Environment facts. Either being unfavourable yields NOT_ATTEMPTED — an
        environment limitation is never evidence about the code.
    require_nonce
        Retained only so existing call sites keep working. **It no longer does
        anything**: the nonce is always required. It used to disable condition
        3 for "pre-nonce transcripts", a category that no longer exists, and in
        combination with ``canary_touched`` it would have promoted a finding
        with no attribution to this PoC at all.
    run_output
        Deprecated alias for ``observer_output``, kept so call sites owned by
        other modules keep working through the rename. Passing both is an
        error.
    """
    if observer_output is not None and run_output is not None:
        raise TypeError(
            "judge() takes observer_output or run_output, not both — "
            "run_output is the deprecated alias"
        )
    text = observer_output if observer_output is not None else run_output

    undecidable = is_undecidable(vuln_class)
    if undecidable:
        return ExecutionVerdict(
            outcome=Outcome.NOT_APPLICABLE,
            reason=undecidable,
            nonce=nonce,
            model_claimed_success=model_claimed_success,
        )

    if not execution_available or toolchain_missing:
        return ExecutionVerdict(
            outcome=Outcome.NOT_ATTEMPTED,
            reason=(
                "the toolchain required to run a PoC was not present"
                if toolchain_missing
                else "execution was not available (static-only run)"
            ),
            nonce=nonce,
            model_claimed_success=model_claimed_success,
        )

    events, forged_lines, markers_signed = _parse(text, observer_key)
    armed = any(e.is_armed_banner for e in events)
    audit_events = [e for e in events if e.is_audit_event]
    forgery = _forgery_note(forged_lines)

    def verdict(outcome: Outcome, reason: str, **kw) -> ExecutionVerdict:
        return ExecutionVerdict(
            outcome=outcome,
            reason=reason + forgery,
            nonce=nonce,
            model_claimed_success=model_claimed_success,
            forged_lines=forged_lines,
            markers_signed=markers_signed,
            **kw,
        )

    if not armed:
        return verdict(
            Outcome.OBSERVER_ABSENT,
            "no armed banner in the PoC output — the observer never ran, so "
            "there is nothing to judge. This says nothing about whether the "
            "vulnerability reproduced.",
            events_seen=len(audit_events),
        )

    if not audit_events:
        return verdict(
            Outcome.NO_EVENT,
            "the observer armed and recorded no dangerous operation. This "
            "PoC did not demonstrate the finding; it is not evidence that "
            "the sink is unreachable.",
            evidence=[e.raw for e in events if e.is_summary][:2],
            observer_armed=True,
        )

    norm_roots = tuple(r for r in (_normalise(x) for x in target_roots) if r)
    norm_pocs = tuple(r for r in (_normalise(x) for x in poc_paths) if r)
    # A bare string would iterate into single characters and silently distrust
    # nothing; accept it as the one filename the caller meant.
    supplied = ({synthesized_filenames} if isinstance(synthesized_filenames, str)
                else set(synthesized_filenames))
    synthesized = frozenset(
        _normalise(f) for f in
        (supplied | set(synthesized_filenames_from_events(audit_events)))
        if f
    )

    # Condition 3. `require_nonce` is deliberately not consulted: an event that
    # cannot be tied to this PoC cannot promote this finding, and there is no
    # transcript vintage for which that stops being true.
    if not nonce:
        return verdict(
            Outcome.NONCE_MISMATCH,
            f"{len(audit_events)} dangerous operation(s) were recorded but no "
            "nonce was supplied, so no event can be attributed to this PoC. "
            "An unattributed event proves that something happened, not that "
            "this exploit caused it.",
            evidence=[e.raw for e in audit_events][:5],
            events_seen=len(audit_events),
            observer_armed=True,
        )

    nonce_ok = [e for e in audit_events if e.nonce == nonce or nonce in e.args_text]

    if not nonce_ok:
        return verdict(
            Outcome.NONCE_MISMATCH,
            f"{len(audit_events)} dangerous operation(s) were recorded but none "
            f"carried this PoC's nonce ({nonce}). The output cannot be "
            "attributed to this exploit — concurrent task, stale log, or "
            "replayed transcript — so it cannot prove this finding.",
            evidence=[e.raw for e in audit_events][:5],
            events_seen=len(audit_events),
            observer_armed=True,
        )

    # Condition 4, in two halves: the frame must be real, and it must be the
    # target's.
    synthetic = [e for e in nonce_ok if _is_synthesized_attribution(e, synthesized)]
    # Identity, not equality: ObserverEvent is a frozen dataclass, so two
    # genuinely distinct occurrences of the same event compare equal and a
    # membership test on values would drop the wrong one.
    synthetic_ids = {id(e) for e in synthetic}
    attributed = [
        e for e in nonce_ok
        if id(e) not in synthetic_ids
        and _is_target_frame(e.frame_file, norm_roots, norm_pocs)
    ]

    if not attributed:
        if synthetic:
            names = sorted({e.frame_file or "" for e in synthetic})[:2]
            reason = (
                "the dangerous operation fired from a frame naming "
                + ", ".join(names)
                + " — but that filename was handed to compile()/exec() during "
                "this run, so the PoC minted the frame. `co_filename` is "
                "whatever string compile() was given; a frame carrying it is "
                "the PoC's claim about itself, not an observation of the "
                "target."
            )
        elif [e for e in nonce_ok if _normalise(e.frame_file) in norm_pocs]:
            reason = (
                "the dangerous operation fired, but the frame that caused it is "
                "the PoC itself — the exploit called the sink directly and "
                "demonstrated nothing about the target's code path."
            )
        else:
            reason = (
                "the dangerous operation fired but could not be attributed to a "
                "frame inside the target. Without attribution an event only "
                "proves that something happened, not that this code caused it."
            )
        return verdict(
            Outcome.SELF_ATTRIBUTED,
            reason,
            evidence=[e.raw for e in nonce_ok][:5],
            events_seen=len(audit_events),
            observer_armed=True,
        )

    # Locality. The nonce is task-keyed by necessity, so without this one real
    # vulnerability would prove every finding filed under the same task.
    if finding_file:
        local = [e for e in attributed if _same_file(e.frame_file, finding_file, norm_roots)]
    else:
        local = attributed

    if not local:
        elsewhere = sorted({e.frame_file or "?" for e in attributed})[:3]
        return verdict(
            Outcome.SINK_REACHED_UNPROVEN,
            "the dangerous operation fired inside the target, but from "
            + ", ".join(elsewhere)
            + f" — and this finding is about {finding_file}. The nonce is keyed "
            "on the task, not the finding, so every PoC in a task shares it; a "
            "frame in a different file therefore proves a different finding, "
            "not this one. Sink reached elsewhere; this finding is not proven "
            "and is not weakened.",
            evidence=[e.raw for e in attributed][:5],
            events_seen=len(audit_events),
            events_attributed=len(attributed),
            observer_armed=True,
        )

    # Condition 5.
    interpreted = [e for e in local
                   if _payload_was_interpreted(e, nonce, norm_roots, audit_events)]

    if not interpreted and not canary_touched:
        first = local[0]
        return verdict(
            Outcome.SINK_REACHED_UNPROVEN,
            f"{first.event_name} fired from {first.frame_file}:"
            f"{first.frame_line} in {first.frame_func} with the payload "
            "present, but nothing shows the payload was interpreted — no "
            "shell parsed it, no path escaped the target, no attacker-named "
            "host was contacted, no canary appeared. The sink is reachable "
            "with attacker data; exploitation was not demonstrated. This is "
            "also what an effective defence looks like from the runtime, so "
            "Validate decides which it is.",
            evidence=[e.raw for e in local][:5],
            events_seen=len(audit_events),
            events_attributed=len(attributed),
            observer_armed=True,
        )

    if interpreted:
        first = interpreted[0]
        detail = (
            f"{first.event_name} fired from {first.frame_file}:{first.frame_line} "
            f"in {first.frame_func} and interpreted this PoC's payload"
        )
    else:
        first = local[0]
        detail = (
            f"{first.event_name} fired from {first.frame_file}:{first.frame_line} "
            f"in {first.frame_func}, and the payload's canary side effect "
            "materialised"
        )
    return verdict(
        Outcome.PROVEN,
        detail + " — the target's own code executed attacker-controlled data.",
        evidence=[e.raw for e in (interpreted or local)][:5],
        events_seen=len(audit_events),
        events_attributed=len(attributed),
        observer_armed=True,
    )
