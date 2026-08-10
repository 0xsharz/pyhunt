"""The class vocabulary, and the rule that a finding's label must match its evidence.

Defect D18, found by building the scoreboard rather than by reading code. Scoring
the recorded run turned up seven apparent misses; three were not misses at all —
the defect was found, at the right line, and filed under a class the ground truth
does not recognise.

The worst of the three is worth stating plainly: **the single ``proven`` finding
of the entire run — a remote code execution the gate settled 3/3 in fresh
containers with a materialised canary — was filed as
``improper_input_handling`` / CWE-829.** That label is defensible in isolation
and indefensible as the description of the strongest result the tool produced.

Three consequences, none cosmetic:

1. **Benchmarking breaks.** A CWE-keyed matcher scores it a miss. Detection
   recall reads 14 of 21 when the true figure is 18.
2. **Routing breaks.** :mod:`dedupe` groups by class family and
   :mod:`oracle.classes` decides provability by class string. A code execution
   labelled ``improper_input_handling`` lands in the wrong family and is judged
   against the wrong table.
3. **One class absorbs everything.** ``improper_input_handling`` was the filed
   label on all three misclassified rows, across three unrelated defects. A
   class that means anything means nothing.

Two mechanisms here, and they are deliberately different in kind:

:func:`consistency_errors`
    A *static* check — does the finding's ``cwe`` agree with its ``vuln_class``?
    Advisory, run at collection time, so a hunter's slip is visible while the
    run is still going.

:func:`upgrade_for_evidence`
    An *evidence-driven* correction. When the gate proves a finding via an
    ``exec``/``compile`` audit event, the finding **is** a code execution
    whatever the hunter called it. The gate already knew; nothing fed that back
    into the label. This only ever moves a label toward the evidence, never
    away from it, and it records the original so the change is auditable rather
    than silent.
"""

from __future__ import annotations

import re
from typing import Any

#: ``vuln_class`` -> the CWE that class means. The single source; `report_build`
#: imports this rather than keeping a second copy, because two tables that drift
#: apart is how a class ends up with two CWEs depending on which module asked.
CLASS_CWE: dict[str, str] = {
    # code execution
    "code_injection": "CWE-94", "codegen": "CWE-94", "ssti": "CWE-94",
    "logic_chain": "CWE-94", "codegen_injection": "CWE-94",
    "docstring_injection": "CWE-94", "template_injection": "CWE-1336",
    "eval_injection": "CWE-95", "untrusted_code_execution": "CWE-94",
    "code_execution": "CWE-94", "arbitrary_code_execution": "CWE-94",
    # injection
    "command_injection": "CWE-78", "sql_injection": "CWE-89",
    "nosql_injection": "CWE-943", "header_injection": "CWE-113",
    "log_injection": "CWE-117",
    # navigation
    "ssrf": "CWE-918", "path_traversal": "CWE-22", "zip_slip": "CWE-22",
    "xxe": "CWE-611", "open_redirect": "CWE-601",
    # deserialisation
    "deserialization": "CWE-502", "deserialization_pickle": "CWE-502",
    "deserialization_yaml": "CWE-502", "unsafe_reflection": "CWE-470",
    "type_confusion": "CWE-843", "union_confusion": "CWE-843",
    # web
    "xss_stored": "CWE-79", "xss_reflected": "CWE-79",
    # disclosure
    "credential_leak": "CWE-200", "information_disclosure": "CWE-200",
    "infoleak": "CWE-200", "hardcoded_secret": "CWE-798",
    # availability — the family that was missing entirely, which is part of why
    # `improper_input_handling` absorbed so much
    "resource_exhaustion": "CWE-400", "denial_of_service": "CWE-400",
    "algorithmic_complexity": "CWE-407", "algorithmic_complexity_dos": "CWE-407",
    "regex_dos": "CWE-1333", "redos": "CWE-1333",
    "uncontrolled_recursion": "CWE-674",
    "uncontrolled_recursion_resource_exhaustion": "CWE-674",
    "memory_exhaustion": "CWE-789", "unbounded_allocation": "CWE-770",
    "integer_overflow": "CWE-190",
    # state and concurrency
    "race_condition": "CWE-362", "state_mutation": "CWE-1250",
    "global_state_pollution": "CWE-1250",
    # policy
    "access_control": "CWE-284", "authorization": "CWE-285",
    "auth_bypass": "CWE-287", "idor": "CWE-639",
    "privilege_escalation": "CWE-269", "missing_auth": "CWE-306",
    "business_logic": "CWE-840", "logic_error": "CWE-840",
    "insecure_design": "CWE-1173", "security_misconfiguration": "CWE-16",
    "mass_assignment": "CWE-915", "csrf": "CWE-352", "rate_limit": "CWE-770",
    "weak_crypto": "CWE-327", "cryptographic_failure": "CWE-327",
    "supply_chain": "CWE-1357",
    # the catch-all, kept last so the docstring below is next to it
    "improper_input_handling": "CWE-20",
    "validation_bypass": "CWE-20",
    "unhandled_exception": "CWE-248",
}

#: Classes that are honest only when nothing more specific fits. A finding
#: carrying one of these AND a CWE from a specific family is the D18 signature:
#: the hunter knew what it was (the CWE says so) and reached for the generic
#: label anyway.
_CATCH_ALL = frozenset({"improper_input_handling", "validation_bypass",
                        "logic_error", "business_logic"})

#: Audit events that mean "the target executed attacker-controlled code". A
#: ``proven`` verdict carrying one of these settles the class, whatever the
#: hunter wrote.
_CODE_EXECUTION_EVENTS = ("audit:exec", "audit:compile")

#: ...and the events that mean a process was launched.
_PROCESS_EVENTS = ("audit:subprocess.Popen", "audit:os.system", "audit:os.exec",
                   "audit:os.spawn", "audit:os.posix_spawn")

_CWE_RX = re.compile(r"CWE-\d+", re.I)


def normalise(vuln_class: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(vuln_class or "").lower()).strip("_")


def cwe_for(vuln_class: Any) -> str | None:
    """The CWE this class means, or None when the vocabulary does not know it."""
    return CLASS_CWE.get(normalise(vuln_class))


def consistency_errors(finding: dict) -> list[str]:
    """Ways this finding's label disagrees with itself. Advisory, never fatal.

    Fatal would be wrong: a finding is never deleted for a labelling problem,
    and a hunter that guessed a CWE is still holding a real defect. But the
    disagreement has to be *visible* while the run is going, because by report
    time it has already corrupted routing, dedupe grouping and every CWE-keyed
    consumer downstream.
    """
    problems: list[str] = []
    vuln_class = normalise(finding.get("vuln_class"))
    declared = str(finding.get("cwe") or "").upper()
    expected = cwe_for(vuln_class)

    if not vuln_class:
        problems.append("no vuln_class")
        return problems

    if expected is None:
        problems.append(
            f"vuln_class {vuln_class!r} is not in the taxonomy, so nothing "
            "downstream can route it by class — add it to CLASS_CWE or use a "
            "known label")
    elif declared and _CWE_RX.fullmatch(declared) and declared != expected.upper():
        detail = (f"cwe {declared} does not match vuln_class {vuln_class!r} "
                  f"(which means {expected})")
        if vuln_class in _CATCH_ALL:
            detail += (
                ". The CWE is more specific than the class — this is the D18 "
                "shape: the finding knows what it is and the label does not. "
                "Prefer the class that matches the CWE")
        problems.append(detail)
    return problems


#: CWE -> the class a catch-all should be repaired to. **Explicit, not inverted
#: from** :data:`CLASS_CWE`.
#:
#: Inverting was tried first and repaired nothing: CWE-674 is claimed by both
#: ``uncontrolled_recursion`` and its longer alias, so an "unambiguous only"
#: rule dropped it — and CWE-674 was the single biggest cluster in the data
#: (nine findings). Picking the shortest name would have worked there and been
#: wrong for CWE-94, which nine genuinely different classes claim and where a
#: guess would relabel a codegen injection as an eval.
#:
#: So the entries here are the ones where a catch-all label plus this CWE has
#: exactly one sensible reading, chosen by hand. A CWE absent from this table is
#: left alone, which is the safe direction.
_CWE_TO_CLASS: dict[str, str] = {
    "CWE-674": "uncontrolled_recursion",
    "CWE-400": "resource_exhaustion",
    "CWE-407": "algorithmic_complexity",
    "CWE-1333": "regex_dos",
    "CWE-789": "memory_exhaustion",
    "CWE-770": "unbounded_allocation",
    "CWE-843": "type_confusion",
    "CWE-1250": "state_mutation",
    "CWE-190": "integer_overflow",
    "CWE-248": "unhandled_exception",
    "CWE-502": "deserialization",
    "CWE-22": "path_traversal",
    "CWE-918": "ssrf",
    "CWE-611": "xxe",
    "CWE-78": "command_injection",
    "CWE-89": "sql_injection",
}


def repair_class(finding: dict) -> str | None:
    """Replace a catch-all class with the one its own CWE names.

    Measured on the recorded run: **46 of 145 findings** carried a class that
    disagreed with their CWE, and nine of them were
    ``improper_input_handling`` + CWE-674 — which is ``uncontrolled_recursion``,
    a class that routes to the resource lens and is eligible for a
    ``growth_curve`` probe. So this is not tidying: nine findings were sitting
    outside the population the second oracle can settle purely because of their
    label.

    Only fires when the current class is a catch-all **and** the declared CWE
    maps to exactly one specific class. A CWE claimed by two classes repairs
    nothing — picking one by dict order would be worse than leaving it alone.
    Returns the new class, or None.
    """
    current = normalise(finding.get("vuln_class"))
    if current not in _CATCH_ALL:
        return None
    declared = str(finding.get("cwe") or "").upper()
    if not _CWE_RX.fullmatch(declared):
        return None
    target = _CWE_TO_CLASS.get(declared)
    if not target or target == current:
        return None

    finding["vuln_class_original"] = finding.get("vuln_class")
    finding["vuln_class"] = target
    finding["class_repaired_by"] = (
        f"taxonomy: {declared} names exactly one class, and the finding was "
        "filed under a catch-all. The CWE is the more specific statement."
    )
    return target


def upgrade_for_evidence(finding: dict, proof: dict | None) -> str | None:
    """Correct a finding's class from what the gate actually observed.

    Returns the new ``vuln_class`` when one was applied, else None. Only ever
    moves toward the evidence:

    * a ``proven`` verdict whose marker lines carry ``audit:exec`` or
      ``audit:compile`` is a **code execution**;
    * a ``proven`` verdict carrying a process-spawn event is a **command
      injection**.

    Nothing else is touched, and a class that is already in the right family is
    left alone — re-labelling ``codegen_injection`` as ``code_injection``
    because a probe happened to compile something would be the correction
    running in the wrong direction.
    """
    if not isinstance(proof, dict) or str(proof.get("outcome")) != "proven":
        return None

    evidence = " ".join(_evidence_lines(proof))
    current = normalise(finding.get("vuln_class"))
    if current not in _CATCH_ALL:
        return None

    if any(marker in evidence for marker in _CODE_EXECUTION_EVENTS):
        new_class = "code_injection"
    elif any(marker in evidence for marker in _PROCESS_EVENTS):
        new_class = "command_injection"
    else:
        return None

    finding["vuln_class_original"] = finding.get("vuln_class")
    finding["vuln_class"] = new_class
    finding["cwe"] = CLASS_CWE[new_class]
    finding["class_upgraded_by"] = (
        "execution evidence: the gate proved this finding via an event that "
        "settles the class, and the hunter's label was a catch-all"
    )
    return new_class


def _evidence_lines(proof: dict) -> list[str]:
    lines: list[str] = []
    for key in ("evidence",):
        value = proof.get(key)
        if isinstance(value, list):
            lines.extend(str(v) for v in value)
    for run in proof.get("runs") or []:
        verdict = (run or {}).get("verdict") or {}
        for line in verdict.get("evidence") or []:
            lines.append(str(line))
    return lines


__all__ = ["CLASS_CWE", "cwe_for", "normalise", "consistency_errors",
           "upgrade_for_evidence"]
