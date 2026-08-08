"""Per-finding nonces — what makes an observer line *evidence about this PoC*.

A marker line saying ``audit:subprocess.Popen`` proves that a process started.
It does not prove that *this* PoC started it. Three ways that goes wrong in
practice, all of them real:

1. **Concurrency.** Hunt runs at concurrency 50. Fifty PoCs execute under one
   scan container, and a hunter that reads a stale or shared log can attribute
   another task's event to its own finding.
2. **Innocent behaviour.** The target legitimately spawns processes and opens
   files at import time. Arming the hook late filters most of it, not all.
3. **Replay.** A transcript pasted back into a later run would otherwise
   re-prove a finding that was never re-run.

So every PoC carries a nonce: the payload embeds it (``; touch /canary/<nonce>``,
``id > /canary/<nonce>``), the observer stamps every line with it, and
:mod:`pyhunt.oracle.gate` requires it to appear in the event before that event
may promote a finding.

The nonce is derived, not random, so a scan is reproducible: the same run and
finding always get the same value, which means a recorded transcript can be
replayed in CI and still pass the gate. It is keyed by a per-run secret, so it
cannot be *guessed* from inside the repository under test.

What the nonce is not
---------------------
**It is not a secret from the target, and it is not what stops forgery.** That
distinction used to be stated backwards here, and getting it wrong matters,
because the two claims call for different defences.

A hostile repository does not have to guess the nonce. It cannot read it from
the environment — ``pyhunt_audit_hook`` pops both ``PYHUNT_NONCE`` and
``PYHUNT_OBSERVER_KEY`` out of ``os.environ`` at import, before any target or
PoC code runs — but the PoC's payload embeds the nonce by construction, the
PoC's source is a file in the same container, and fd 3 stays writable by
anything in the process. All three were confirmed by running the attack:
``tests/test_contract_a_markers.py::test_a_hostile_target_cannot_forge_a_proof``
is a malicious ``__init__.py`` that recovers the nonce from the PoC source and
writes a flawlessly-formed ``audit:os.system`` line onto the private channel.

What defeats it is **Contract A**: every genuine marker line carries an HMAC
over its own body under a key the target never sees, so the forgery is
discarded, counted in ``forged_lines``, and the run is judged ``no_event``.
The nonce's job is attribution — telling this PoC's events apart from the 49
others running concurrently in the same container — not authentication.

The honest residual is unchanged and stated in the hook and in
``references/execution-gate.md``: the target shares an interpreter with the
observer, so an attacker who has read this repository can still recover the
signing key from process memory. Out-of-process observation is the real fix
and is out of scope.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

# Length of the hex nonce. 16 hex chars = 64 bits: far beyond guessing, short
# enough to sit inside a shell payload without making it unreadable.
_NONCE_HEX = 16

_ENV_SECRET = "PYHUNT_RUN_SECRET"


def run_secret() -> str:
    """The per-run secret that keys every nonce.

    Read from ``PYHUNT_RUN_SECRET`` when present so that a resumed run (or a
    replayed transcript in CI) derives the same nonces it did originally.
    Generated fresh otherwise, and exported, so a scan that never thinks about
    nonces still gets unguessable ones.
    """
    existing = os.environ.get(_ENV_SECRET)
    if existing:
        return existing
    generated = secrets.token_hex(16)
    os.environ[_ENV_SECRET] = generated
    return generated


def nonce_for(run_id: str, finding_key: str) -> str:
    """Derive the nonce for one PoC.

    `finding_key` is whatever uniquely identifies the PoC within the run — a
    task id before findings exist, a finding id afterwards. Stability matters
    more than which one: the value embedded in the payload must be the value
    the gate later looks for.
    """
    mac = hmac.new(
        run_secret().encode("utf-8"),
        f"{run_id}\x00{finding_key}".encode("utf-8"),
        hashlib.sha256,
    )
    return mac.hexdigest()[:_NONCE_HEX]


def canary_path(nonce: str, root: str = "/tmp/pyhunt-canary") -> str:
    """Filesystem path a payload should touch to leave a durable trace.

    Used by payload templates (``; touch {canary}``). The gate does not require
    the file to exist — the observer event is the primary signal and the file is
    corroboration — but a PoC that writes it gives the ``open``/``subprocess``
    event a nonce-bearing argument to be matched on, which is what turns a
    generic event into an attributable one.
    """
    return f"{root}/{nonce}"
