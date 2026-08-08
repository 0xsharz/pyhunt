"""Parsing observer output into structured events, and authenticating it.

The observer prints lines like::

    [PYHUNT-OBSERVER] n=a3f19c22b7d40e51 s=9f3c1d80ab27e451 hook-armed poc=poc.py pid=475 events=...
    [PYHUNT-OBSERVER] n=a3f19c22b7d40e51 s=41ba0e7c9d2f6a13 audit:subprocess.Popen ('/bin/sh', ['-c', 'id']) \
        <- from /target/app/reports.py:7 in build_report
    [PYHUNT-OBSERVER] n=a3f19c22b7d40e51 s=cc02f7e5194db836 hook-summary observed=1 subprocess.Popen=1

Contract A: ``s=`` is ``HMAC-SHA256(observer_key, body)`` truncated to 16 hex
characters, where ``body`` is everything after the ``s=`` field. The key is
minted per container by ``replay.py``, handed to the hook through
``PYHUNT_OBSERVER_KEY``, and scrubbed from ``os.environ`` by the hook before any
target or PoC code runs.

**Why a signature and not just the nonce.** The nonce is handed to the container
too, so anything running inside it — the PoC, and the *target's own import-time
code* — can print a well-formed, correctly-nonced marker line and manufacture a
proof (defects C-2 and C-3). The nonce answers "which PoC is this about"; it
cannot answer "did the observer say this". Only a secret the target never sees
can do that.

**What this is not.** The target executes in the same interpreter as the hook,
so a target written specifically to attack PyHunt can recover the key from
process memory with effort. Signing, environment scrubbing and a private file
descriptor defeat naive and opportunistic forgery and force any attack to be
deliberate and PyHunt-specific. This is **not** a security boundary against an
adversary who has read this repository. Out-of-process observation (seccomp,
eBPF, ptrace) is the real fix and is out of scope. See
``references/execution-gate.md``.

Three facts are extracted from each line, and all three are load-bearing:

``nonce``
    Ties the event to one PoC. See :mod:`pyhunt.oracle.nonce`.

``event``
    Which dangerous operation fired.

``frame``
    **The file that caused it.** This is the difference between evidence and
    theatre. ``subprocess.Popen`` attributed to the target's handler proves the
    vulnerable path executed. The same event attributed to the PoC itself proves
    the PoC called the sink directly and demonstrated nothing about the target —
    a distinction VASH's hook was careful to record and which nothing then
    checked.

This module only parses. It renders no judgement; that is :mod:`pyhunt.oracle.gate`.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

# The single definition of the marker prefix. It was previously duplicated in
# three modules (the hook asset, the runtime registry, the report renderer),
# which is how a rename silently half-lands.
MARKER = "[PYHUNT-OBSERVER]"

# `[PYHUNT-OBSERVER] n=<nonce> [s=<sig> ]<kind>[ <rest>]`
#
# `s=` is optional in the grammar even though Contract A makes it mandatory in
# practice, because the parser must be able to SEE an unsigned line in order to
# reject and count it. A grammar that simply failed to match unsigned lines
# would silently drop a forgery attempt, and `forged_lines` — the loudest signal
# a run can produce — would read zero.
_LINE_RX = re.compile(
    r"^\s*" + re.escape(MARKER) + r"\s+"
    r"(?:n=(?P<nonce>[0-9a-f]{4,64})\s+)?"
    r"(?:s=(?P<sig>[0-9a-f]{16})\s+)?"
    r"(?P<kind>[A-Za-z][\w.:-]*)"
    r"(?:\s+(?P<rest>.*))?$"
)

#: Length of the truncated HMAC carried in `s=`. 16 hex = 64 bits, which is far
#: beyond forging by trial and short enough to keep a marker line readable.
_SIG_HEX = 16


def sign(body: str, key: str) -> str:
    """Contract A's signature over one marker line's body.

    ``body`` is everything after the ``s=`` field — the kind, its arguments and
    the frame attribution. The nonce and the marker prefix are deliberately
    outside the MAC: they are routing, not claims. Swapping the nonce on an
    authentic line can only *lose* attribution (the gate requires the nonce to
    match this PoC), never gain it, and the claim itself — which event fired,
    and from which frame — is exactly what the MAC covers.
    """
    return hmac.new(
        key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:_SIG_HEX]

# `  <- from /path/to/file.py:123 in func_name`, appended to an event line.
_FRAME_RX = re.compile(
    r"<-\s+from\s+(?P<file>.+?):(?P<line>\d+)\s+in\s+(?P<func>[\w.<>]+)\s*$"
)

_ARMED_KIND = "hook-armed"
_SUMMARY_KIND = "hook-summary"
_AUDIT_PREFIX = "audit:"


@dataclass(frozen=True)
class ObserverEvent:
    """One parsed marker line."""

    kind: str                  # "audit:subprocess.Popen", "hook-armed", "env", ...
    nonce: str | None
    args_text: str             # the event's arguments, verbatim and untruncated
    frame_file: str | None     # the file that caused the event
    frame_line: int | None
    frame_func: str | None
    raw: str

    @property
    def is_armed_banner(self) -> bool:
        return self.kind == _ARMED_KIND

    @property
    def is_summary(self) -> bool:
        return self.kind == _SUMMARY_KIND

    @property
    def is_audit_event(self) -> bool:
        """True for the dangerous-operation events, as opposed to the
        observer's own bookkeeping lines (armed banner, summary, env echo)."""
        return self.kind.startswith(_AUDIT_PREFIX)

    @property
    def event_name(self) -> str:
        """`subprocess.Popen` for kind `audit:subprocess.Popen`."""
        return self.kind[len(_AUDIT_PREFIX):] if self.is_audit_event else self.kind


class ObserverParse(list):
    """The parse result: a list of :class:`ObserverEvent`, plus provenance.

    Subclasses ``list`` so every pre-Contract-A caller — and every test that
    compares the result to a plain list — keeps working unchanged. The two extra
    facts ride alongside:

    ``forged_lines``
        Well-formed marker lines that failed signature verification and were
        discarded. **Above zero means something inside the sandbox tried to
        manufacture proof**, which is the most interesting thing a run can
        produce. It is counted rather than merely dropped so it can be recorded
        in the proof record and surfaced in the report.

    ``signed``
        Whether verification actually ran. Never inferred from "a key was
        passed": unverified output reading as authentic is the one direction
        this must not fail in.
    """

    def __init__(self, events=(), *, forged_lines: int = 0, signed: bool = False):
        super().__init__(events)
        self.forged_lines = int(forged_lines)
        self.signed = bool(signed)

    @property
    def events(self) -> list[ObserverEvent]:
        """The accepted events. Present so consumers can be explicit rather
        than relying on this object's list-ness."""
        return list(self)


def parse_observer_output(
    output: str | None, *, key: str | None = None
) -> ObserverParse:
    """Extract every marker line from an observer transcript.

    Non-marker lines — the PoC's own chatter, the application's logging, a
    stack trace — are ignored rather than being a parse error: PoC output is
    arbitrary text and the parser must never be the reason a proof is lost.

    When ``key`` is given (Contract A), every marker line must carry an ``s=``
    field that verifies under it. Lines that do not are **discarded and
    counted** in ``forged_lines``; they never reach the gate. A transcript whose
    only dangerous events were forged therefore falls through to the existing
    ``no_event`` outcome naturally — no new outcome is introduced, because a
    forged line is not a verdict, it is the absence of evidence plus a red flag.

    With ``key=None`` behaviour is exactly what it was before Contract A, and
    ``signed`` is False so no caller can mistake unverified text for authentic.
    """
    events: list[ObserverEvent] = []
    forged = 0
    for raw_line in (output or "").splitlines():
        if MARKER not in raw_line:
            continue
        # A marker can be embedded mid-line when the target interleaves its own
        # writes with the observer's; start parsing at the marker itself.
        line = raw_line[raw_line.index(MARKER):]
        m = _LINE_RX.match(line)
        if not m:
            # Unparseable. With no key this is the historical "ignore junk"
            # path. With a key it is a line that WORE the observer's marker and
            # could not be authenticated, which is a forgery attempt however
            # badly formed — counting it is what makes a clumsy forger as
            # visible as a careful one.
            if key:
                forged += 1
            continue
        if key:
            # The body is reconstructed from the match rather than re-split, so
            # what is verified is exactly what is parsed. Anything else would
            # let a line verify under one reading and be interpreted under
            # another.
            body = line[m.start("kind"):].strip()
            got = m.group("sig")
            if not got or not hmac.compare_digest(got, sign(body, key)):
                forged += 1
                continue
        rest = (m.group("rest") or "").strip()
        frame_file = frame_line = frame_func = None
        fm = _FRAME_RX.search(rest)
        if fm:
            frame_file = fm.group("file").strip()
            frame_line = int(fm.group("line"))
            frame_func = fm.group("func")
            rest = rest[: fm.start()].strip()
        events.append(
            ObserverEvent(
                kind=m.group("kind"),
                nonce=m.group("nonce"),
                args_text=rest,
                frame_file=frame_file,
                frame_line=frame_line,
                frame_func=frame_func,
                raw=line.strip(),
            )
        )
    return ObserverParse(events, forged_lines=forged, signed=bool(key))


def marker_lines(output: str | None, limit: int = 40) -> list[str]:
    """The raw marker lines, for the report. Kept verbatim — they are the
    receipt a human reads to check the gate's arithmetic."""
    return [ln.strip() for ln in (output or "").splitlines() if MARKER in ln][:limit]
