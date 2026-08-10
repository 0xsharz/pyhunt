"""The second oracle: deterministic structural proof for classes the audit hook cannot see.

Why this module exists
----------------------
PyHunt's execution gate (:mod:`oracle.gate`) is the strongest evidence a scanner
in this lineage produces, and it is deliberately narrow: a CPython audit event,
carrying this PoC's nonce, caused by a frame inside the target, whose payload
was demonstrably interpreted. Everything else is honestly reported as
``not_applicable``.

Measured on a real run (``dataclasses-avroschema`` 0.70.2, 145 findings):
**74 of 145 were ``not_applicable``** — every one of them a codegen-injection or
resource-exhaustion finding that no audit event can settle. The report was
accurate and nearly useless: a reader saw "1 proven" and had no way to tell that
30 of the unproven sites were trivially demonstrable by a two-line assertion.

The comparison run (VASH, same package, same version) settled all 18 of its
findings — by having each PoC *assert about itself*: "parse the generated
module, check the marker became a syntax node". That evidence is real. It is
also self-reported, which is the exact failure mode :mod:`oracle.gate` was built
to remove. Both tools were half right.

This module is the synthesis. It takes VASH's insight — that a code generator's
defect is demonstrable *structurally*, without ever executing the generated code
— and puts the assertion where the model cannot reach it:

    **The hunter declares a probe. The harness executes it and decides.**

A hunter writes a JSON spec naming a callable inside the target, a benign input,
and a hostile input. It writes no assertion, no parsing, and no verdict. The
harness (``observers/pyhunt_structural_probe.py``, shipped by PyHunt, running
inside the same locked-down container as a replay) calls the target's own
function on both inputs, computes the property in Python, signs the result with
the per-container HMAC key, and this module folds the signed lines into a
verdict. That is strictly stronger than a PoC that asserts about its own output,
because the assertion is not authored by the party with an interest in the
answer.

The five structural conditions
------------------------------
Deliberately parallel to the execution gate's five, and for the same reason: a
condition removed later must be removed visibly, by someone who read why it was
added.

======  ======================================================================
S-1     The **harness armed** — a signed ``structural:probe-armed`` banner. Its
        absence is ``PROBE_ABSENT``, never a refutation, exactly as
        ``observer_absent`` is not one.
S-2     The callable under test **resolved inside the target**. The harness
        reports ``inspect.getfile()`` of the function it actually called; a
        path outside the target roots means the probe measured something else
        and the result is discarded. This is condition 4's analogue, and it is
        what stops a probe from "proving" a defect against a helper the PoC
        author wrote.
S-3     The hostile input **carried this run's nonce**, and the observed
        property is expressed *in terms of that nonce*. Without it a probe
        proves that some string reached some position, not that the attacker's
        string did.
S-4     The **differential held**: the benign control did NOT exhibit the
        property and the hostile input did. One-sided evidence is not evidence
        — a generator that emits ``ast.Call`` nodes for every input is doing
        its job.
S-5     The property is **semantic, not textual**. "The nonce appears in the
        output" is satisfied by correct escaping. What must hold is that the
        nonce occupies a position the language treats as *code* (an AST node
        that is not a ``Constant``), or that a measured resource curve breached
        a stated bound, or that module state changed to the attacker's value.
        This is condition 5's analogue and it exists for the same reason: drop
        it and a working defence launders into a demonstration.
======  ======================================================================

What a structural verdict is NOT
--------------------------------
It is **not** ``proven``. ``proven`` means a dangerous operation fired and the
runtime interpreted the payload; ``demonstrated`` means a deterministic
predicate over the target's own output held under a differential. They are
different claims, they get different words, and :mod:`report_build` reports them
under separate denominators. Merging them would be the same dishonesty as
merging ``not_applicable`` into ``not proven``.

``PROMOTING`` in :mod:`oracle.gate` remains a set of one. Nothing here can make
a finding ``proven``.

And it can refute
-----------------
``REFUTED`` is the outcome the execution gate has no analogue for, and it is the
most valuable thing in this module. When the differential runs and the hostile
nonce lands as an ``ast.Constant`` — a properly escaped string literal — that is
a **deterministic demonstration that the defence works**. It still does not
delete the finding (nothing in an oracle path deletes a finding), but
``phase2c_verify.md`` must weigh it, and a verifier that confirms a finding
against a ``refuted`` structural probe has to say why in writing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Sequence

from oracle.markers import MARKER, sign

# ─────────────────────────────────────────────────────────────────────────────
# outcomes
# ─────────────────────────────────────────────────────────────────────────────


class StructuralOutcome(str, Enum):
    """What one structural probe established.

    ================= =======================================================
    Outcome           Meaning, and what the report does with it
    ================= =======================================================
    DEMONSTRATED      All five structural conditions held. The target's own
                      code turned attacker text into an executable construct
                      (or breached a stated resource bound, or mutated shared
                      state), the benign control did not, and a harness the
                      hunter did not write measured it. **Corroborates** the
                      finding; it does not make it ``proven``.
    REFUTED           The differential ran cleanly and the property did NOT
                      hold: the hostile nonce landed as inert data. A working
                      defence, deterministically shown. Does not delete the
                      finding; phase 2c must address it explicitly.
    INCONCLUSIVE      The probe ran but the differential was not decisive —
                      the benign control ALSO exhibited the property, or the
                      nonce never reached the output at all. Says nothing.
    PROBE_ERROR       The probe could not run: the callable did not resolve,
                      resolved outside the target, the input did not
                      round-trip, or the harness raised. An environment or
                      spec fact, never a verdict on the code.
    PROBE_ABSENT      No signed armed banner. The harness never ran.
    NOT_ATTEMPTED     No probe was declared, or the run was static-only.
    ================= =======================================================
    """

    DEMONSTRATED = "demonstrated"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    PROBE_ERROR = "probe_error"
    PROBE_ABSENT = "probe_absent"
    NOT_ATTEMPTED = "not_attempted"


#: Outcomes that raise a finding's evidentiary standing. Kept as a set of one
#: for the same reason ``gate.PROMOTING`` is: adding a second must be a visible
#: edit, not a changed comparison.
CORROBORATING = frozenset({StructuralOutcome.DEMONSTRATED})

#: Outcomes that carry evidence AGAINST the finding. Never auto-deletes —
#: `phase2c_verify.md` reads this and must argue past it in writing.
CONTRADICTING = frozenset({StructuralOutcome.REFUTED})


# ─────────────────────────────────────────────────────────────────────────────
# probe kinds
# ─────────────────────────────────────────────────────────────────────────────

#: The probe vocabulary. Each entry is a *closed* recipe: the harness knows how
#: to run it, so the hunter supplies data and never code. Adding a kind means
#: adding a measurement function to the harness and a fold rule below — which is
#: the point. A probe kind whose assertion could be supplied by the hunter would
#: be VASH's self-assertion with extra steps.
PROBE_KINDS: dict[str, str] = {
    "codegen_ast": (
        "Differential AST test for code generators. The harness calls the "
        "target's generator twice — once with a benign value in the "
        "attacker-controlled schema field, once with a hostile value carrying "
        "the run nonce — parses both outputs with `ast.parse`, and locates the "
        "node whose source segment contains the nonce. DEMONSTRATED when that "
        "node is executable (Call/Import/Assign/FunctionDef/ClassDef/Attribute "
        "/Name/Expr-statement) in the hostile render and the benign render's "
        "corresponding value was a Constant. REFUTED when the nonce lands "
        "inside an `ast.Constant` — i.e. the generator escaped it. The "
        "generated module is NEVER executed: that is what makes this decidable "
        "at all, since executing it is precisely what makes the execution "
        "gate's condition 4 reject the attribution as PoC-minted."
    ),
    "growth_curve": (
        "Algorithmic-complexity and unbounded-allocation test. The harness "
        "calls the target at a geometric ladder of input sizes under RLIMIT_AS "
        "and RLIMIT_CPU in a forked child, recording wall time and peak RSS at "
        "each rung. DEMONSTRATED when the measured cost is superlinear beyond "
        "`ratio_threshold` across two consecutive doublings, or when a rung "
        "below `hostile_size` dies on MemoryError/RecursionError/SIGSEGV/CPU "
        "limit while the benign rung completes. The benign rung completing is "
        "the differential: a function that is slow on every input is slow, not "
        "vulnerable."
    ),
    "state_mutation": (
        "Shared-state contamination test. The harness snapshots a dotted "
        "module attribute, calls the target with hostile input, and re-reads "
        "it. DEMONSTRATED when the attribute changed to a value derived from "
        "the attacker's input and the benign control left it unchanged. This "
        "is the shape of a process-global (decimal context precision, a "
        "registry, a cached config) that any caller can move under any other "
        "caller's feet."
    ),
    "differential_response": (
        "Authorisation test. Access control was filed under 'policy questions "
        "no measurement answers'; for BUSINESS LOGIC that is true, for ACCESS "
        "CONTROL it is not. Authorisation has an observable definition — two "
        "principals, one call, different answers — so the harness plants a "
        "sentinel only the privileged context should see, calls the target as "
        "each principal, and compares. DEMONSTRATED when the unprivileged "
        "caller receives it and was not denied. REFUTED when the control held "
        "for that pair. Two reads, nothing written, nothing exploited."
    ),
    "type_selection": (
        "Dispatch-steering test. A registry keyed on attacker-supplied text "
        "lets the attacker choose which class is constructed. The harness "
        "calls the target twice, changing ONLY the attacker-controlled field, "
        "and compares the resolved types. DEMONSTRATED when a different type "
        "comes back, or when the type differs from a declared "
        "`expected_type`. This is the union name-collision shape, and it is "
        "measurable rather than arguable."
    ),
    "config_assertion": (
        "Committed-configuration test for supply-chain and IaC findings. "
        "Whether a job holding a publishing credential has an environment gate "
        "is not a matter of opinion — it is a key lookup. The harness parses "
        "the named file (yaml.safe_load or json, never a constructor that can "
        "instantiate objects) and evaluates ONE assertion from a closed "
        "vocabulary against a dotted path. No target code runs at all. "
        "DEMONSTRATED when the committed bytes satisfy the stated unsafe "
        "condition; REFUTED when the finding's premise is not present in them."
    ),
    "sink_semantics": (
        "Reach-AND-meaning test. The harness wraps the dangerous callable named "
        "in `intercept` with a shim that CAPTURES its arguments and raises, so "
        "the operation never runs — no query executes, no file opens, no "
        "request leaves. It then calls the public entry point twice, benign and "
        "hostile, and analyses what actually arrived with a closed vocabulary "
        "of analysers (sql, path, url, shell, html, format). DEMONSTRATED when "
        "the hostile payload puts the nonce in a position the grammar treats as "
        "STRUCTURE — outside a quoted literal, in a URL authority, as its own "
        "shell token, escaping a path root — and the benign control did not. "
        "This is the non-intrusive PoC done properly: the payload provably "
        "reaches the sink AND provably arrives as syntax rather than data, and "
        "the assertion is written here rather than by the model that filed the "
        "finding."
    ),
    "flow_witness": (
        "Data-arrival test (W3.1). The harness installs `sys.settrace` scoped "
        "to frames whose file lives under the target root, calls the declared "
        "public entry point with a sentinel-bearing input (the run nonce rides "
        "in the untrusted field), and records at every line whether any "
        "frame-local carries the sentinel. DEMONSTRATED when a value "
        "containing the sentinel is live in the claimed sink's frame at the "
        "claimed line. REFUTED when the sink line executed and no local "
        "carried it — and the report names the LAST frame that did, which is "
        "the sanitiser or the branch that dropped it. This settles classes the "
        "audit hook has no event for at all (SQL injection, XSS, open redirect, "
        "template rendering), because it needs no dangerous operation to fire; "
        "it needs the data to arrive. Costs 10-50x in wall time and does not "
        "follow values through C extensions — a trace that goes dark inside a "
        "decoder is reported as bounded, never as a negative result."
    ),
    "exception_escape": (
        "Availability test for a public entry point. The harness calls the "
        "target's documented API with benign input (which must succeed) and "
        "with hostile input, and records the exception type that escapes. "
        "DEMONSTRATED when the hostile call raises an escaping exception of a "
        "type in `expected_exceptions` — an unhandled crash reachable from "
        "attacker-controlled bytes — and the benign call returns normally. "
        "REFUTED when the hostile call is handled cleanly."
    ),
}

#: Vulnerability classes the audit hook is structurally blind to, mapped to the
#: probe kind that CAN settle them. Consulted by phase 2b so a hunter working a
#: class in this table is told which probe to declare rather than being left to
#: write a PoC that can only ever return ``not_applicable``.
#:
#: Matching is key-in-needle, matching :func:`oracle.classes.observer_blind_reason`
#: — the same directional rule, for the same reason.
CLASS_TO_PROBE: dict[str, str] = {
    "codegen": "codegen_ast",
    "codegen_injection": "codegen_ast",
    "template_injection_into_generated_code": "codegen_ast",
    "resource_exhaustion": "growth_curve",
    "algorithmic_complexity": "growth_curve",
    "denial_of_service": "growth_curve",
    "dos": "growth_curve",
    "redos": "growth_curve",
    "uncontrolled_recursion": "growth_curve",
    "memory_exhaustion": "growth_curve",
    "global_state_pollution": "state_mutation",
    "state_mutation": "state_mutation",
    "race_condition": "state_mutation",
    "sql_injection": "sink_semantics",
    "nosql_injection": "sink_semantics",
    "command_injection": "sink_semantics",
    "path_traversal": "sink_semantics",
    "zip_slip": "sink_semantics",
    "ssrf": "sink_semantics",
    "open_redirect": "sink_semantics",
    "xss": "sink_semantics",
    "xss_stored": "sink_semantics",
    "xss_reflected": "sink_semantics",
    "ssti": "sink_semantics",
    # No single callable to wrap: the "sink" is a formatter or a header dict,
    # so reach is the strongest available structural claim.
    "log_injection": "flow_witness",
    "header_injection": "flow_witness",
    # Access control is measurable; business logic is not. Keeping them apart
    # is the whole point — see `differential_response`.
    "access_control": "differential_response",
    "authorization": "differential_response",
    "auth_bypass": "differential_response",
    "missing_auth": "differential_response",
    "idor": "differential_response",
    "privilege_escalation": "differential_response",
    "information_disclosure": "differential_response",
    "infoleak": "differential_response",
    "credential_leak": "differential_response",
    "unsafe_reflection": "type_selection",
    "type_confusion": "type_selection",
    "union_confusion": "type_selection",
    "mass_assignment": "type_selection",
    "supply_chain": "config_assertion",
    "security_misconfiguration": "config_assertion",
    "improper_input_handling": "exception_escape",
    "validation_bypass": "exception_escape",
    "unhandled_exception": "exception_escape",
}


def probe_kind_for(vuln_class: str | None) -> str | None:
    """The probe kind that can settle this class, or None.

    ``None`` is a normal answer and means what it says: this class is settled by
    execution (in which case :mod:`oracle.gate` owns it) or by nothing at all
    (access control, business logic — a policy question no measurement answers).
    Never guess a probe for a policy class: a "demonstrated" IDOR would be the
    same category error the ``not_applicable`` table exists to prevent.
    """
    if not vuln_class:
        return None
    needle = vuln_class.strip().lower().replace(" ", "_").replace("-", "_")
    for key, kind in CLASS_TO_PROBE.items():
        if key in needle:
            return kind
    return None


# ─────────────────────────────────────────────────────────────────────────────
# the verdict
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class StructuralVerdict:
    """The structural oracle's decision about one probe run."""

    outcome: StructuralOutcome
    reason: str
    probe_kind: str | None = None
    #: The signed harness lines that carried the decision, verbatim.
    evidence: list[str] = field(default_factory=list)
    #: Per-condition results, so a reader can see WHICH condition failed rather
    #: than being handed a word. Keys are ``s1``…``s5``.
    conditions: dict[str, bool] = field(default_factory=dict)
    #: What the harness measured, verbatim from its signed report — the AST node
    #: type, the growth ratios, the before/after state values.
    measurements: dict[str, Any] = field(default_factory=dict)
    #: File the callable under test actually resolved to, as the harness saw it.
    callable_file: str | None = None
    nonce: str | None = None
    #: Lines that claimed to be harness output and failed HMAC verification.
    #: Above zero means something inside the container tried to manufacture a
    #: structural proof, which is as interesting here as it is in the gate.
    forged_lines: int = 0
    markers_signed: bool = False

    @property
    def demonstrated(self) -> bool:
        return self.outcome in CORROBORATING

    @property
    def refuted(self) -> bool:
        return self.outcome in CONTRADICTING

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome.value,
            "demonstrated": self.demonstrated,
            "refuted": self.refuted,
            "reason": self.reason,
            "probe_kind": self.probe_kind,
            "evidence": self.evidence,
            "conditions": self.conditions,
            "measurements": self.measurements,
            "callable_file": self.callable_file,
            "nonce": self.nonce,
            "forged_lines": self.forged_lines,
            "markers_signed": self.markers_signed,
        }


# ─────────────────────────────────────────────────────────────────────────────
# marker parsing — Contract A, applied to the harness channel
# ─────────────────────────────────────────────────────────────────────────────

#: `[PYHUNT-OBSERVER] n=<nonce> s=<sig> structural:<kind> <json>`
#:
#: The signature is over ``structural:<kind> <json>`` — the whole claim, exactly
#: as :func:`oracle.markers.sign` covers the whole claim for an audit line. The
#: nonce sits outside the MAC for the same reason it does there: it is routing,
#: and swapping it can only lose attribution, never gain it.
_PROBE_LINE_RX = re.compile(
    r"^\s*" + re.escape(MARKER) + r"\s+"
    r"n=(?P<nonce>[0-9a-f]{4,64})\s+"
    r"(?:s=(?P<sig>[0-9a-f]{16})\s+)?"
    r"(?P<body>structural:(?P<kind>[A-Za-z][\w.-]*)(?:\s+(?P<payload>.*))?)$"
)

ARMED_KIND = "probe-armed"
REPORT_KIND = "probe-report"


@dataclass(frozen=True)
class ProbeLine:
    kind: str
    nonce: str
    payload: dict
    raw: str


def parse_probe_output(text: str | None, key: str | None,
                       ) -> tuple[list[ProbeLine], int, bool]:
    """Verified harness lines, forged-line count, and whether verification ran.

    Unsigned lines are *parsed and then rejected* rather than skipped by the
    grammar, so an attempt to manufacture a structural proof shows up as a
    number instead of vanishing. That asymmetry is the same one
    :class:`oracle.markers.ObserverParse` documents, and it is the reason this
    does not simply require ``s=`` in the regex.
    """
    lines: list[ProbeLine] = []
    forged = 0
    verified = bool(key)
    for raw in (text or "").splitlines():
        match = _PROBE_LINE_RX.match(raw)
        if not match:
            continue
        sig = match.group("sig")
        body = match.group("body")
        if key:
            if not sig or sign(body, key) != sig:
                forged += 1
                continue
        payload_text = match.group("payload") or "{}"
        try:
            payload = json.loads(payload_text)
        except (TypeError, ValueError):
            # A signed line whose payload is not JSON is a harness bug, not a
            # forgery — it verified. Count it as evidence with an empty payload
            # rather than dropping the fact that the harness spoke.
            payload = {}
        if not isinstance(payload, dict):
            payload = {"value": payload}
        lines.append(ProbeLine(kind=match.group("kind"), nonce=match.group("nonce"),
                               payload=payload, raw=raw.strip()))
    return lines, forged, verified


# ─────────────────────────────────────────────────────────────────────────────
# the fold
# ─────────────────────────────────────────────────────────────────────────────


def _inside(path: str | None, roots: Sequence[str]) -> bool:
    """True when ``path`` sits under one of ``roots``.

    String-prefix containment on normalised POSIX paths. The harness reports
    container-side absolute paths and the caller passes container-side roots, so
    there is nothing to resolve and nothing that could resolve differently on
    the host than it did in the container.
    """
    if not path:
        return False
    p = path.replace("\\", "/")
    for root in roots or ():
        r = str(root).replace("\\", "/").rstrip("/")
        if r and (p == r or p.startswith(r + "/")):
            return True
    return False


def judge_structural(
    *,
    probe_output: str | None,
    nonce: str | None,
    probe_kind: str | None,
    target_roots: Sequence[str] = (),
    observer_key: str | None = None,
    execution_available: bool = True,
) -> StructuralVerdict:
    """Fold one probe run's signed output into a verdict.

    Every branch below is a fact read out of the harness's own signed report.
    Nothing here re-derives a measurement, and nothing here accepts a claim the
    harness did not sign — the module computes ``and`` over five conditions and
    names the first one that failed.
    """
    if not execution_available:
        return StructuralVerdict(
            outcome=StructuralOutcome.NOT_ATTEMPTED,
            reason="execution was not available (static-only run)",
            probe_kind=probe_kind, nonce=nonce,
        )
    if not probe_kind:
        return StructuralVerdict(
            outcome=StructuralOutcome.NOT_ATTEMPTED,
            reason="no structural probe was declared for this finding",
            nonce=nonce,
        )

    lines, forged, signed = parse_probe_output(probe_output, observer_key)
    forgery = (
        f" {forged} line(s) claiming to be harness output failed signature "
        "verification and were discarded." if forged else ""
    )

    armed = [ln for ln in lines if ln.kind == ARMED_KIND]
    if not armed:
        return StructuralVerdict(
            outcome=StructuralOutcome.PROBE_ABSENT,
            reason=("no signed probe-armed banner: the harness never ran, so "
                    "this says nothing about the code." + forgery),
            probe_kind=probe_kind, nonce=nonce, forged_lines=forged,
            markers_signed=signed,
            conditions={"s1_armed": False},
        )

    reports = [ln for ln in lines if ln.kind == REPORT_KIND]
    if not reports:
        return StructuralVerdict(
            outcome=StructuralOutcome.PROBE_ERROR,
            reason=("the harness armed but produced no report — it raised "
                    "before measuring anything." + forgery),
            probe_kind=probe_kind, nonce=nonce, forged_lines=forged,
            markers_signed=signed, evidence=[ln.raw for ln in armed],
            conditions={"s1_armed": True},
        )

    report = reports[-1].payload
    evidence = [ln.raw for ln in armed + reports]
    measurements = report.get("measurements") or {}
    callable_file = report.get("callable_file")

    def verdict(outcome: StructuralOutcome, reason: str,
                conditions: dict[str, bool]) -> StructuralVerdict:
        return StructuralVerdict(
            outcome=outcome, reason=reason + forgery, probe_kind=probe_kind,
            evidence=evidence, conditions=conditions, measurements=measurements,
            callable_file=callable_file, nonce=nonce, forged_lines=forged,
            markers_signed=signed,
        )

    conditions: dict[str, bool] = {"s1_armed": True}

    # The harness could not do its job at all — a spec fact or an import error,
    # never a statement about the vulnerability.
    if report.get("error"):
        return verdict(
            StructuralOutcome.PROBE_ERROR,
            f"the probe could not run: {report['error']}. That is a fact about "
            "the probe spec or the environment, not about the code.",
            conditions,
        )

    # S-2 — attribution. The measured callable has to BE the target's.
    inside = _inside(callable_file, target_roots)
    conditions["s2_callable_in_target"] = inside
    if not inside:
        return verdict(
            StructuralOutcome.PROBE_ERROR,
            f"the callable under test resolved to {callable_file!r}, which is "
            f"not inside the target ({', '.join(target_roots) or 'no roots given'}). "
            "A probe that measured something other than the target's own code "
            "proves nothing about the target — this is condition 4's analogue "
            "and it fails closed.",
            conditions,
        )

    # S-3 — attribution to this run. Two honest forms, and which one applies is
    # a property of the probe kind rather than a knob:
    #
    #   payload — the nonce is IN the attacker's input, so the thing observed in
    #             the output is provably the thing this PoC sent. Mandatory for
    #             `codegen_ast`, whose entire claim is "*this* string became
    #             code".
    #   spec    — a precision integer, a recursion depth, a 40000-element list:
    #             there is nowhere in the payload to put a 16-hex string.
    #             Attribution then rests on the signed channel and the
    #             per-container key. Weaker, real, and recorded as such rather
    #             than dressed up as the stronger form.
    carried_in = report.get("nonce_carried_in") or "payload"
    nonce_in_input = bool(nonce) and bool(report.get("nonce_in_hostile_input"))
    if probe_kind == "codegen_ast" and carried_in != "payload":
        nonce_in_input = False
    conditions["s3_nonce_in_input"] = nonce_in_input
    measurements = dict(measurements)
    measurements["nonce_carried_in"] = carried_in
    if not nonce_in_input:
        return verdict(
            StructuralOutcome.PROBE_ERROR,
            "the hostile input did not carry this run's nonce, so nothing the "
            "probe observed is attributable to this PoC. The nonce reaches a "
            "probe only through its spec — it can never be read from the "
            "environment, which the harness deletes before any target code runs.",
            conditions,
        )

    # S-4 — the differential. Both halves must have run.
    if not report.get("differential_ran"):
        return verdict(
            StructuralOutcome.PROBE_ERROR,
            "the benign control did not complete, so there is no differential. "
            "One-sided evidence is not evidence: a generator that emits a call "
            "node for every input is doing its job.",
            {**conditions, "s4_differential": False},
        )

    hostile_holds = bool(report.get("hostile_property_holds"))
    benign_holds = bool(report.get("benign_property_holds"))
    conditions["s4_differential"] = hostile_holds and not benign_holds

    if benign_holds and hostile_holds:
        return verdict(
            StructuralOutcome.INCONCLUSIVE,
            "the benign control exhibited the same property as the hostile "
            "input, so the property is not attacker-induced. Sharpen the "
            "control or the payload and re-run.",
            conditions,
        )

    # S-5 — semantic, not textual.
    semantic = bool(report.get("semantic_position_confirmed"))
    conditions["s5_semantic"] = semantic

    if hostile_holds and not benign_holds and semantic:
        return verdict(
            StructuralOutcome.DEMONSTRATED,
            _demonstration_reason(probe_kind, measurements),
            conditions,
        )

    # Two ways a codegen differential is simply not decisive, and neither is a
    # refutation. Checked before the refutation branch because both would
    # otherwise be misread as "the defence held".
    if measurements.get("hostile_parse_error"):
        return verdict(
            StructuralOutcome.INCONCLUSIVE,
            "the attacker's text changed the emitted module enough that it no "
            f"longer parses ({measurements['hostile_parse_error']}). That "
            "proves the payload escaped its literal, but not that what it "
            "became is executable — a syntax error is a broken generator, not "
            "a demonstrated injection. Re-aim the payload at a well-formed "
            "statement and re-run.",
            conditions,
        )
    if measurements.get("hostile_needle_found") is False:
        return verdict(
            StructuralOutcome.INCONCLUSIVE,
            "the nonce never reached the generated source at all. Either the "
            "generator drops this field entirely (a defence) or the payload "
            "went into a field this generator ignores (a mis-aimed probe) — "
            "the measurement cannot tell those apart, so it claims neither.",
            conditions,
        )

    if not hostile_holds:
        return verdict(
            StructuralOutcome.REFUTED,
            _refutation_reason(probe_kind, measurements) +
            " This does not delete the finding — phase 2c weighs it — but a "
            "verifier that confirms against a refuted probe must say why.",
            conditions,
        )

    # hostile_holds and not semantic: the property fired, but the attacker's
    # text did not land anywhere that carries the meaning the finding claims.
    # That IS the escaping case, and its wording is kind-specific because the
    # generic sentence sends a reader looking for the wrong thing.
    if probe_kind == "flow_witness":
        last_intact = measurements.get("last_frame_carrying_it_unaltered")
        return verdict(
            StructuralOutcome.REFUTED,
            "the sentinel reached the claimed sink, but TRANSFORMED — "
            "something between the entry point and the sink rewrote the value "
            "while leaving the sentinel inside it. Arrival is not danger: a "
            "defence that escapes, quotes or filters produces exactly this "
            "shape. "
            + (f"The last frame that held the value unaltered was "
               f"{last_intact}, which is where to look for the transform. "
               if last_intact else
               "No frame held the value unaltered, so the transform happened "
               "at or before the entry point. ")
            + "Calling this a demonstration would launder the defence into a "
              "finding (condition 5's analogue).",
            conditions,
        )
    return verdict(
        StructuralOutcome.REFUTED,
        "the attacker's text reached the output but occupies an inert "
        "position — a string constant, a comment, or an escaped literal. That "
        "is what a working defence looks like, and calling it a demonstration "
        "would launder the defence into a finding (condition 5's analogue).",
        conditions,
    )


def _demonstration_reason(kind: str, m: dict) -> str:
    if kind == "codegen_ast":
        return (
            f"the target's generator turned the attacker's schema text into a "
            f"{m.get('hostile_node_type', 'executable')} node in the emitted "
            f"source (the benign control produced "
            f"{m.get('benign_node_type', 'a Constant')}). The generated module "
            "was parsed, never executed, so nothing here is PoC-minted."
        )
    if kind == "growth_curve":
        return (
            f"cost grew superlinearly across the ladder "
            f"({m.get('ratios') or m.get('outcome_by_size')}) while the benign "
            f"rung completed in {m.get('benign_seconds', 'bounded')} s — "
            "attacker-chosen input size drives unbounded work."
        )
    if kind == "state_mutation":
        return (
            f"calling the target with hostile input changed "
            f"{m.get('attribute')} from {m.get('before')!r} to "
            f"{m.get('after')!r}; the benign control left it unchanged. Process "
            "state is attacker-writable across callers."
        )
    if kind == "exception_escape":
        return (
            f"hostile input raised {m.get('hostile_exception')} out of the "
            "target's public entry point while the benign call returned "
            "normally — an unhandled crash reachable from attacker bytes."
        )
    if kind == "flow_witness":
        return (
            f"the sentinel-bearing value was live in the claimed sink's frame "
            f"at {m.get('sink_location')}, byte-for-byte as it was supplied, "
            f"having travelled {m.get('carrier_path')}. Nothing between the "
            "public entry point and the sink altered it — the attacker's data "
            "provably arrives."
        )
    return "the structural property held under a differential."


def _refutation_reason(kind: str, m: dict) -> str:
    if kind == "codegen_ast":
        return ("the attacker's text was emitted as an inert "
                f"{m.get('hostile_node_type', 'Constant')} — the generator "
                "escaped it.")
    if kind == "growth_curve":
        return (f"cost stayed within the stated bound across the ladder "
                f"({m.get('ratios')}) — no unbounded growth was demonstrated.")
    if kind == "state_mutation":
        return f"{m.get('attribute')} was unchanged after the hostile call."
    if kind == "exception_escape":
        return "hostile input was handled without an escaping exception."
    if kind == "flow_witness":
        last = m.get("last_frame_carrying_sentinel")
        return ("the claimed sink line executed and no frame-local carried the "
                "sentinel" + (f"; the last frame that did was {last}, which is "
                              f"the sanitiser or the branch that dropped it"
                              if last else ", and no frame ever carried it"))
    return "the structural property did not hold."


# ─────────────────────────────────────────────────────────────────────────────
# aggregation — same unanimity rule as replay
# ─────────────────────────────────────────────────────────────────────────────

#: Structural probes are deterministic by construction, which makes disagreement
#: between repeats *more* alarming than it is for an execution replay, not less:
#: a differing AST between two runs of the same generator on the same input
#: means something non-deterministic is in the path. So unanimity is required
#: here too, and a split is reported as INCONCLUSIVE rather than averaged.
STRUCTURAL_REPEATS = 2


def aggregate_structural(verdicts: Sequence[StructuralVerdict],
                         ) -> StructuralVerdict:
    """Fold repeats into one. Unanimous or inconclusive; never a majority vote."""
    real = [v for v in verdicts if v is not None]
    if not real:
        return StructuralVerdict(
            outcome=StructuralOutcome.NOT_ATTEMPTED,
            reason="no probe runs were performed",
        )
    if len(real) == 1:
        return real[0]
    outcomes = {v.outcome for v in real}
    if len(outcomes) == 1:
        head = real[0]
        return StructuralVerdict(
            outcome=head.outcome,
            reason=f"{len(real)}/{len(real)} probe runs agreed: {head.reason}",
            probe_kind=head.probe_kind,
            evidence=[line for v in real for line in v.evidence],
            conditions=head.conditions,
            measurements=head.measurements,
            callable_file=head.callable_file,
            nonce=head.nonce,
            forged_lines=sum(v.forged_lines for v in real),
            markers_signed=all(v.markers_signed for v in real),
        )
    return StructuralVerdict(
        outcome=StructuralOutcome.INCONCLUSIVE,
        reason=(
            "probe runs disagreed ("
            + ", ".join(sorted(o.value for o in outcomes))
            + "). A structural probe is deterministic by construction, so a "
            "split means something non-deterministic sits in the measured "
            "path — a timestamp, a hash seed, a dict ordering. Nothing is "
            "demonstrated until that is found."
        ),
        probe_kind=real[0].probe_kind,
        evidence=[line for v in real for line in v.evidence],
        measurements={"per_run": [v.outcome.value for v in real]},
        nonce=real[0].nonce,
        forged_lines=sum(v.forged_lines for v in real),
        markers_signed=all(v.markers_signed for v in real),
    )


__all__ = [
    "StructuralOutcome", "StructuralVerdict", "CORROBORATING", "CONTRADICTING",
    "PROBE_KINDS", "CLASS_TO_PROBE", "probe_kind_for", "parse_probe_output",
    "judge_structural", "aggregate_structural", "STRUCTURAL_REPEATS",
    "ARMED_KIND", "REPORT_KIND",
]
