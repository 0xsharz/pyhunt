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


def secret_is_durable() -> bool:
    """True when the run secret already exists outside this process.

    An in-process mint is exported to `os.environ` and dies with the process.
    Every phase is a separate process, so a nonce derived from an unpersisted
    secret is unreproducible by the phase that has to verify it — and nothing
    fails: `poc_execution_block` returns a perfectly well-formed nonce, and
    replay later derives a *different* one, finds no match, and reports
    `sink_reached_unproven`. Both ends look healthy; the proof is simply gone.

    This is the same class of failure the `poc_execution_block` docstring
    already guards against, arriving by a different route. That guard hardened
    against a **null** nonce; this one is a non-null nonce with no durable key.
    Observed on a real run: `resolve_run_secret` reported `unavailable` while 36
    valid-looking nonces were being minted.
    """
    return bool(os.environ.get(_ENV_SECRET))


def ensure_durable_secret(results_dir) -> str:
    """Mint the run secret if needed and write it down. Returns the secret.

    Writes a ``.run_secret`` sidecar (0600) beside the run's other state, which
    is where :func:`replay.resolve_run_secret` looks after the environment and
    ``manifest.json``. Call this **before** deriving any nonce.
    """
    import pathlib
    path = pathlib.Path(results_dir) / ".run_secret"

    # The sidecar wins, and it is read BEFORE anything is minted.
    #
    # This used to call `run_secret()` first. In a process that has not
    # exported PYHUNT_RUN_SECRET — which is every fresh process, and every
    # phase is a fresh process — that mints a new random secret, finds it
    # differs from the sidecar, and then *overwrites the sidecar with it*.
    #
    # Every nonce already embedded in an authored PoC is keyed to the old
    # secret, so it is invalidated in the same breath, and nothing fails:
    # replay derives a different nonce, matches nothing, and reports
    # `sink_reached_unproven` — which is also exactly what a working defence
    # looks like. Measured on the dca-avroschema v3 run: 102 of 102 PoCs came
    # back with `nonce_in_poc: false` and the run produced **zero** `proven`
    # findings, on a target with a live `eval()` on attacker-controlled text.
    # The hunters had embedded their nonces correctly; a later process had
    # moved the key underneath them.
    #
    # `secret_is_durable`'s docstring already describes this failure class
    # ("a non-null nonce with no durable key"). The guard existed; the writer
    # one level below it was the thing creating the condition.
    try:
        stored = path.read_text(encoding="utf-8").strip()
    except OSError:
        stored = ""
    if stored:
        # Export it so every later derivation in this process agrees with the
        # PoCs already on disk.
        os.environ[_ENV_SECRET] = stored
        return stored

    secret = run_secret()
    try:
        path.write_text(secret + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass
    return secret


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
