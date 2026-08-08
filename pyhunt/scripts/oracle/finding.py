"""The placeholder verdict a freshly-recorded finding carries.

**This module used to judge findings, and that was defect C-1.** It built the
gate's input by concatenating ``poc.run_output`` and ``poc.compile_output`` —
text the hunt agent wrote about its own work — and stored the resulting verdict
as ``finding["execution"]``, which is exactly the field ``report_build`` reads
as "confirmed by execution". A PoC whose body was ``print('hello, I did
nothing')`` plus a forged transcript therefore reported as ``proven``, while the
real replay's ``proof/<id>.json`` said ``no_event`` and was read by nothing.

The fix is structural rather than defensive: **there is no longer a function
here that takes a finding and returns a verdict.** ``judge_finding`` is gone. A
finding gets its execution block from exactly one place —
:func:`findings_io.apply_proof`, fed by ``replay.py``'s own container — and
until that runs, it carries the honest placeholder below.

The corollary matters as much as the rule: a finding with a placeholder is
**not** a rejected finding. ``not_attempted`` says the gate has not run, which
is a fact about the environment and never a fact about the code.
"""

from __future__ import annotations

from oracle.gate import ExecutionVerdict, Outcome

#: Why a freshly-recorded finding is not yet judged. Phrased for the human who
#: reads it in a report and needs to know whether to worry.
UNJUDGED_REASON = (
    "not yet replayed — the execution gate judges the observer's transcript "
    "from replay.py's own container, never the hunt agent's account of its "
    "own run. Run phase 2b (`replay.py`) to obtain a verdict."
)


def placeholder_verdict(
    *, nonce: str | None = None, model_claimed_success: bool | None = None
) -> ExecutionVerdict:
    """The execution block a finding carries before replay has run.

    ``model_claimed_success`` is carried through deliberately: what the agent
    claimed is worth recording next to what the gate later decides, because a
    divergence between them is auditable and a rising rate is a signal. It is
    recorded, never believed — :attr:`ExecutionVerdict.proven` does not consult
    it, so nothing downstream can promote on it.
    """
    return ExecutionVerdict(
        outcome=Outcome.NOT_ATTEMPTED,
        reason=UNJUDGED_REASON,
        nonce=nonce,
        model_claimed_success=model_claimed_success,
    )
