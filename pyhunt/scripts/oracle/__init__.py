"""The execution oracle: a deterministic judge of whether a PoC proved anything.

VASH (and `audit` before it) asked the Hunt agent to run a PoC, read the output,
and set ``poc.succeeded`` itself. The runtime observer produced excellent
evidence, but that evidence was only ever *read by the model* and *rendered into
the report* — nothing in Python ever decided anything with it. So the
zero-false-positive claim rested on prompt obedience.

This package moves that decision into code. Given the observer output a PoC
produced, :func:`judge` returns an :class:`ExecutionVerdict` computed by pure
predicates over parsed marker lines. The model may state what it *believes*
happened; only this package may promote a finding to ``proven``.

The asymmetry from VASH is preserved exactly, because it is what keeps the tool
honest:

    Only ``PROVEN`` promotes a finding. **Nothing here may delete one.**

An absent observer, a missing toolchain, a silent run, or an undecidable
vulnerability class all produce a verdict that leaves the finding standing on
its static source→sink argument. The gate makes "proven" mean something; it does
not make "unproven" mean "false".
"""

from oracle.gate import (
    ExecutionVerdict,
    Outcome,
    judge,
)
from oracle.markers import MARKER, ObserverEvent, ObserverParse, parse_observer_output, sign
from oracle.nonce import nonce_for
from oracle.classes import UNDECIDABLE_BY_EXECUTION, is_undecidable
# `judge_finding` is deliberately absent: it judged agent-authored text, which
# was defect C-1. A finding's execution block now comes only from
# `findings_io.apply_proof`, fed by replay's own container.
from oracle.finding import placeholder_verdict

__all__ = [
    "ExecutionVerdict",
    "Outcome",
    "judge",
    "placeholder_verdict",
    "MARKER",
    "ObserverEvent",
    "ObserverParse",
    "parse_observer_output",
    "sign",
    "nonce_for",
    "UNDECIDABLE_BY_EXECUTION",
    "is_undecidable",
]
