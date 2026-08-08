"""Vulnerability classes execution cannot settle.

Two separate reasons a class can be unprovable, and the honesty of the report's
denominators depends on both being written down.

**1. The question is not a runtime question.** Running code answers *"did this
behaviour occur?"*. It cannot answer *"was this behaviour allowed?"* — that
needs the intended policy, which does not exist in the runtime. A PoC can show
user A reading user B's record and still not establish that doing so is wrong.
That is :data:`UNDECIDABLE_BY_EXECUTION`.

**2. This observer has no event for the sink.** The gate can only promote on a
CPython audit event, and ``WATCHED_EVENTS`` in
``scripts/observers/pyhunt_audit_hook.py`` has no DB-cursor event and no
response-write event. A SQL injection can be perfectly real, perfectly
exploited, and produce *nothing the observer can see*. That is
:data:`NOT_PROVABLE_BY_THIS_OBSERVER`, and it is a fact about PyHunt, not about
the target — which is exactly why it must be stated rather than left to look
like a PoC that failed.

VASH already stated the first rule in ``prompts/02-hunt.md`` as an instruction
to the model ("never drop such a finding for want of executed proof"). Here both
become tables the gate consults, so a class that cannot be proven by execution
is recorded as ``NOT_APPLICABLE`` rather than sliding into ``NOT_REPRODUCED``
and reading, to anyone scanning the report, like a finding that failed.

The distinction matters for the coverage arithmetic: a delivered-findings figure
of "18 of 25 proven" is misleading if 6 of the 7 unproven ones are IDORs that no
amount of execution could ever prove — and equally misleading if three more are
SQL injections whose sink raises no audit event. ``report_build`` excludes
``not_applicable`` from ``provable_by_execution``; both tables feed it.
"""

from __future__ import annotations

# Keyed by the `vuln_class` / `attack_class` strings the hunt-task schema uses.
# Matching is substring-based and case-insensitive, because class strings drift
# ("broken_access_control", "access-control", "Broken Access Control").
UNDECIDABLE_BY_EXECUTION: dict[str, str] = {
    "access_control": (
        "Execution can show the read happening; it cannot show that the read "
        "was unauthorised. That requires the intended policy, which is not in "
        "the runtime."
    ),
    "access-control": "See access_control.",
    "authorization": (
        "A missing authorization check is an absence. Running the handler "
        "proves the absence had an effect only if the intended policy is known."
    ),
    "authz": "See authorization.",
    "idor": (
        "A PoC can fetch another user's object and still not establish that "
        "cross-tenant reads are unintended."
    ),
    "privilege_escalation": (
        "Whether the elevated capability was meant to be reachable is a policy "
        "question, not a runtime one."
    ),
    "business_logic": (
        "The runtime has no model of the intended workflow, so it cannot "
        "distinguish abuse from use."
    ),
    "workflow": "See business_logic.",
    "insecure_design": (
        "The defect is the absence of a control. There is no operation to "
        "observe firing."
    ),
    "insecure_default": "See insecure_design.",
    "missing_auth": "See authorization.",
    "mass_assignment": (
        "Observing a field being written does not establish that the field was "
        "not meant to be writable."
    ),
    "information_disclosure": (
        "Whether the disclosed value is sensitive is a judgement about the "
        "data, not an observable runtime event."
    ),
    "csrf": (
        "The missing control is a token check; there is no dangerous operation "
        "for the observer to record, and a same-origin PoC cannot demonstrate "
        "cross-origin submission."
    ),
    "rate_limit": (
        "The absence of a limit is proven by policy, not by one execution."
    ),
    "cryptographic_failure": (
        "Weak parameters are read from the code, not observed at the syscall "
        "boundary. A PoC that decrypts proves the algorithm, not the intent."
    ),
    "weak_crypto": "See cryptographic_failure.",
    "hardcoded_secret": (
        "A literal in source is a static fact. Nothing fires at runtime that "
        "an observer could attribute."
    ),
}


# Classes this observer is blind to. Not a policy question — a genuine,
# fully-exploited instance of any of these produces no watched audit event, so
# the gate could never reach `proven` no matter how good the PoC was. Leaving
# them in the provable denominator makes PyHunt's own blind spot read as the
# target's findings failing to reproduce.
#
# **This is a statement about PyHunt today, not a claim about the class.** The
# honest fix is out-of-process observation or a DB/response-write event; until
# then, saying so is better than a denominator that lies. If
# ``WATCHED_EVENTS`` ever grows a `cursor.execute`-shaped event, delete the
# corresponding entry here — a promise in this table is worse than nothing.
#
# Matched key-in-needle ONLY (see :func:`observer_blind_reason`), unlike the
# table above: the bidirectional match that lets ``broken_access_control`` find
# ``access_control`` would also let a bare ``injection`` find ``sql_injection``
# and silently exclude command injection from the denominator.
NOT_PROVABLE_BY_THIS_OBSERVER: dict[str, str] = {
    "codegen": (
        "Codegen injection is unprovable by construction, and the reason is "
        "worth stating because the gate otherwise reports it as though the "
        "hunter cheated. The defect is that untrusted data is written into "
        "SOURCE CODE the tool emits; the harm happens when something later "
        "compiles and runs that source. To demonstrate it, a PoC must itself "
        "cause the generated file to run — and the moment it does, the frame "
        "the dangerous call comes from names a file whose `co_filename` this "
        "run handed to `compile()`. Condition 4 then correctly rejects the "
        "attribution as PoC-minted, which is the C-4 defence working exactly "
        "as intended. Importing the generated module instead of exec'ing it "
        "does not help: the import machinery is stdlib, so the frame walk "
        "attributes the compile to the PoC either way.\n\n"
        "The canary does not rescue it. Measured on datamodel-code-generator: "
        "three unanimous replays produced `canary_touched: True` with the "
        "nonce-named file present in the host-side mount, and the verdict was "
        "still `self_attributed` — correctly, because a PoC that knows its own "
        "nonce can create that file directly, so the canary corroborates an "
        "attributed event rather than standing in for one.\n\n"
        "So this class is filed here rather than left to look like a failed "
        "PoC. The static evidence is what carries it, and for this class that "
        "evidence is unusually strong: an unescaped interpolation into a "
        "docstring or comment is visible in the template, and the diff against "
        "a sibling template that DOES escape is the whole proof."
    ),
    "codegen_injection": "See codegen.",
    "template_injection_into_generated_code": "See codegen.",
    "sql_injection": (
        "The sink is a DB cursor. CPython raises no audit event for "
        "`cursor.execute`, so a fully successful SQL injection is invisible to "
        "this observer. The finding stands on its static source→sink argument; "
        "PyHunt simply cannot execute-prove this class."
    ),
    "sqli": "See sql_injection.",
    "nosql_injection": (
        "Same as SQL injection: the driver's query call raises no audit event, "
        "so a working NoSQL injection produces nothing to attribute."
    ),
    "nosqli": "See nosql_injection.",
    "xss": (
        "The sink is a response body or DOM write. Nothing in the CPython "
        "audit table fires when a template renders or a response is written, "
        "so this observer cannot see the payload land — and it has no browser "
        "in which the payload would execute."
    ),
    "cross_site_scripting": "See xss.",
    "html_injection": "See xss.",
    "open_redirect": (
        "The sink is a `Location` header. No audit event fires on writing a "
        "response header, and there is no client to follow the redirect."
    ),
}

# Deliberately NOT in the table above, and it is worth saying why, because it
# looks like it belongs:
#
#   `template_injection` / `ssti` — Jinja2 and friends implement rendering with
#   `compile(source, filename, "exec")`, which DOES raise a watched audit
#   event, and the hook's frame walk skips site-packages and attributes it to
#   the target's own `render(user_input)` line. A server-side template
#   injection whose payload carries the nonce therefore reaches `proven`
#   legitimately, while a safe render (static template, user data passed as
#   context) never puts the nonce in compile's source and correctly does not.
#   Listing it here would short-circuit replay for a class the gate can settle,
#   which trades a dishonest denominator for a false negative.


def _needle(vuln_class: str | None) -> str:
    if not vuln_class:
        return ""
    return vuln_class.strip().lower().replace(" ", "_").replace("-", "_")


def undecidable_by_policy(vuln_class: str | None) -> str | None:
    """Reason this class is a policy question rather than a runtime one, or None.

    Substring matching in both directions, because the class vocabulary is not
    fully closed: a hunter may emit ``broken_access_control`` where the table
    holds ``access_control``.
    """
    needle = _needle(vuln_class)
    if not needle:
        return None
    for key, reason in UNDECIDABLE_BY_EXECUTION.items():
        norm_key = key.replace("-", "_")
        if norm_key in needle or needle in norm_key:
            return reason
    return None


def observer_blind_reason(vuln_class: str | None) -> str | None:
    """Reason this observer could never see this class fire, or None.

    Key-in-needle only. The reverse direction is unsafe here: a finding filed
    as the bare class ``injection`` is contained in ``sql_injection``, and
    matching it would quietly exclude command injection — a class the gate
    proves routinely — from the provable denominator.
    """
    needle = _needle(vuln_class)
    if not needle:
        return None
    for key, reason in NOT_PROVABLE_BY_THIS_OBSERVER.items():
        if key.replace("-", "_") in needle:
            return reason
    return None


def is_undecidable(vuln_class: str | None) -> str | None:
    """Return the reason execution cannot settle this class, or None.

    The union of both tables, because the gate's answer is the same either way
    — ``NOT_APPLICABLE``, excluded from the provable denominator, finding left
    exactly as the static analysis left it. Callers that need to tell "we are
    the wrong instrument" apart from "no instrument would work" should call
    :func:`observer_blind_reason` and :func:`undecidable_by_policy` directly;
    the returned reason text says which it was in either case.
    """
    return undecidable_by_policy(vuln_class) or observer_blind_reason(vuln_class)
