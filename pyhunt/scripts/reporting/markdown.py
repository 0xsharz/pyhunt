"""VVAH/GHSA-style Markdown renderer for an enriched VASH report.

`render_report(report, db=None, run_id=None) -> str` turns the enriched
`report.json` payload (the Task-3 schema shape: top-level
`threat_model`/`scan_metrics`/`verification`, and per-finding
`cvss`/`impact`/`exploit_scenario`/`preconditions`/`how_to_fix`/`poc`/
`variants`/`trace`/`validation`) into a detailed Markdown document that reads
as a peer of a VVAH scan report, with a per-finding GHSA-style advisory block.

Design invariants:

- **Pure & deterministic.** No timestamps, no `Date.now`, no dependence on
  dict-iteration order (severity tallies iterate a fixed order; lists render in
  the order given). Two calls on the same payload are byte-identical.
- **Never drops a section, never crashes.** Every top-level section always
  emits its header; a missing/empty object renders an explicit
  `_Not determined (static run)._` line instead of vanishing. Each section is
  additionally wrapped so a single malformed sub-object degrades to that same
  line rather than taking down the whole document. `render_report` must not
  raise on a minimal `{"run_id", "target", "findings": []}` payload.
- **Post-hoc enrichment lives upstream.** `db`/`run_id` are accepted for
  signature parity with the other attaches; the renderer is pure over the
  already-enriched `report` dict and does not read the DB.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

# The single canonical "we could not determine this in a static run" line. Used
# for any optional field/section that is absent, so nothing is ever silently
# dropped. (The GHSA affected/patched lines use a distinct em-dash phrasing —
# see `_ADVISORY_VERSIONS` — because that is a deliberate advisory statement,
# not a gap.)
NOT_DETERMINED = "_Not determined (static run)._"
_ADVISORY_VERSIONS = (
    "_Not established by this run — the scan reads one commit and does not "
    "bisect history or test other releases._"
)

_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]

# Verdict labels for the adversarial-verification block — map VASH's internal
# validate verdicts onto the TRUE/FALSE-positive vocabulary a reader expects.
_VERDICT_LABEL = {
    "confirmed": "TRUE_POSITIVE",
    "rejected": "FALSE_POSITIVE",
    "needs_more_info": "NEEDS_MORE_INFO",
}

# A small CWE id -> name table for the common classes VASH emits, so the CWE
# line and Weaknesses block read richly. Absent ids fall back to the bare id +
# link (never a crash, never a wrong invented name).
_CWE_NAMES = {
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command (Command Injection)",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
    "CWE-94": "Improper Control of Generation of Code (Code Injection)",
    "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)",
    "CWE-113": "Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-407": "Inefficient Algorithmic Complexity",
    "CWE-470": "Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
}


# ---------------------------------------------------------------------------
# Small formatting primitives.
# ---------------------------------------------------------------------------


def _s(value: Any) -> str:
    """Coerce a value to a stripped display string ('' for None)."""
    if value is None:
        return ""
    return str(value).strip()


def _as_list(value: Any) -> list:
    """Coerce to a list without swallowing a lone item.

    A caller that wrote one caveat as a bare string, and a caller that wrote
    several as a list, must both render. Iterating a string would emit it one
    character at a time, so a string is wrapped rather than iterated.
    """
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _int(value: Any) -> str:
    """Format an integer with thousands separators, or '' if not numeric."""
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return ""


def _cwe_url(cwe: str) -> str:
    """`CWE-918` -> the canonical MITRE definition URL."""
    num = _s(cwe).replace("CWE-", "").strip()
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def _cwe_label(cwe: str) -> str:
    """`CWE-918` -> `CWE-918: Server-Side Request Forgery (SSRF)` (id-only if unknown)."""
    cwe = _s(cwe)
    name = _CWE_NAMES.get(cwe)
    return f"{cwe}: {name}" if name else cwe


def _fmt_score(score: Any) -> str:
    """CVSS score as a one-decimal string ('9.1', '10.0'); '' if not numeric."""
    try:
        return f"{float(score):.1f}"
    except (TypeError, ValueError):
        return ""


def _fenced(body: str, lang: str = "") -> list[str]:
    """A fenced code block. The body is emitted verbatim (evidence/PoC are
    already redacted upstream by `redact_json`)."""
    return [f"```{lang}", body if body else "", "```"]


def _md_table(headers: list[str], rows: list[list[str]],
              aligns: list[str] | None = None) -> list[str]:
    """Render a GitHub-flavoured Markdown table. `aligns` entries are one of
    'l' (default) or 'r' (right, for numbers)."""
    aligns = aligns or ["l"] * len(headers)
    sep = ["---:" if a == "r" else "---" for a in aligns]
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(sep) + " |"]
    for row in rows:
        out.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return out


def _cell(value: Any) -> str:
    """Sanitise a table cell: single line, pipes escaped."""
    return _s(value).replace("\n", " ").replace("|", "\\|")


# ---------------------------------------------------------------------------
# Top-level orchestration.
# ---------------------------------------------------------------------------


def render_report(report: dict, db: Any = None, run_id: str | None = None) -> str:
    """Render an enriched report dict to a VVAH/GHSA-style Markdown document.

    Pure over `report`; deterministic; never raises on a well-formed-ish dict.
    `db`/`run_id` are accepted for call-site parity and are unused.
    """
    report = report if isinstance(report, dict) else {}
    lines: list[str] = []
    lines += _title(report)
    lines += _section(_summary_section, report, "Summary")
    # Advisories come before everything else that is not the summary: they are
    # the "how many defects are there" answer, and a reader who stops after one
    # section should stop after that one. Conditional — a run whose phase 3 did
    # not reach clustering renders exactly as it did before.
    lines += _safe_optional(_advisories_section, report)
    lines += _section(_execution_section, report, "Execution and Coverage")
    lines += _section(_scan_metrics_section, report, "Scan Metrics")
    lines += _section(_threat_model_section, report, "Threat Model")
    lines += _section(_verification_section, report, "Verification")
    lines += _section(_findings_section, report, "Findings")
    # Exploit chains are conditional — only emitted when present.
    lines += _safe_optional(_chains_section, report)
    return "\n".join(lines).rstrip() + "\n"


def _section(fn: Callable[[dict], list[str]], report: dict, name: str) -> list[str]:
    """Render one always-present section, fail-soft: any exception degrades to
    the section header + a Not-determined line rather than crashing the doc."""
    try:
        return fn(report)
    except Exception as e:  # never let one section break the whole report
        log.warning("markdown: section %s failed: %s", name, e)
        return ["", f"## {name}", "", NOT_DETERMINED, ""]


def _clip(value: Any, limit: int) -> str:
    """Shorten for a table cell, marking the cut so it never reads as the whole
    sentence."""
    text = _s(value)
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _advisories_section(report: dict) -> list[str]:
    """One entry per root cause, each listing every location it occurs at.

    This is the section that answers "how many bugs are there", which is not
    the same question as "how many rows are there" and was previously left to
    the reader. A real run delivered 127 rows over 81 sites; site dedupe got
    that to 55 over 69, and still showed eight rows for one templating defect.
    """
    advisories = _as_list(report.get("advisories"))
    if not advisories:
        return []
    summary = report.get("advisory_summary") or {}

    lines = ["", "## Advisories — one entry per root cause", ""]
    count = _s(summary.get("advisories")) or str(len(advisories))
    sites = _s(summary.get("sites"))
    settled = summary.get("settled_advisories")
    head = f"**{count} distinct defect(s)** across **{sites} site(s)**."
    if isinstance(settled, int) and settled:
        head += f" {settled} of them machine-settled."
    lines += [head, ""]
    lines += [
        "Each entry below is one root cause with every location it occurs at. "
        "The per-site findings are unchanged and appear in full under "
        "**Findings** — nothing here is collapsed away, and every advisory "
        "names the finding ids it covers.",
        "",
    ]
    if summary.get("order_note"):
        lines += [f"_{_s(summary['order_note'])}_", ""]

    rows: list[list[str]] = []
    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        proven = advisory.get("proven") or 0
        demonstrated = advisory.get("demonstrated") or 0
        # Never one merged column: two oracles, two claims.
        if proven:
            evidence = f"**proven ×{proven}**"
            if demonstrated:
                evidence += f", demonstrated ×{demonstrated}"
        elif demonstrated:
            evidence = f"demonstrated ×{demonstrated}"
        else:
            evidence = "—"
        if advisory.get("refuted"):
            evidence += f", refuted ×{advisory['refuted']}"
        rows.append([
            _cell(advisory.get("advisory_id")),
            # Trimmed for the table only. The full sentence survives in
            # report.json and in the per-finding section below; a 200-character
            # cell makes the table unreadable, which defeats the point of
            # having one.
            _cell(_clip(advisory.get("title"), 110)),
            _cell(str(advisory.get("severity") or "").lower()),
            _cell(advisory.get("site_count")),
            evidence,
        ])
    lines += _md_table(
        ["ID", "Defect", "Severity", "Sites", "Machine evidence"], rows)
    lines.append("")

    multi = [a for a in advisories
             if isinstance(a, dict) and (a.get("site_count") or 0) > 1]
    if multi:
        lines += ["### Where each multi-site defect occurs", ""]
        for advisory in multi:
            lines.append(
                f"**{_s(advisory.get('advisory_id'))} — "
                f"{_s(advisory.get('title'))}**")
            signature = advisory.get("signature") or {}
            note = advisory.get("signature_note")
            if signature or note:
                lines.append("")
                lines.append(
                    f"Grouped by `{_s(signature.get('kind'))}` "
                    f"(`{_s(signature.get('key'))}`) — {_s(note)}.")
            lines.append("")
            location_rows = [
                [_cell(loc.get("file")), _cell(loc.get("line")),
                 _cell(loc.get("finding_id"))]
                for loc in _as_list(advisory.get("locations"))
                if isinstance(loc, dict)
            ]
            lines += _md_table(["File", "Line", "Finding"], location_rows)
            lines.append("")
    return lines


def _safe_optional(fn: Callable[[dict], list[str]], report: dict) -> list[str]:
    """Render one conditional section, fail-soft to nothing."""
    try:
        return fn(report)
    except Exception as e:
        log.warning("markdown: optional section failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Title + Summary.
# ---------------------------------------------------------------------------


def _target_name(report: dict) -> str:
    target = report.get("target") or {}
    repo = _s(target.get("repo_path"))
    if repo:
        name = Path(repo).name
        if name:
            return name
    return _s(report.get("run_id")) or "target"


def _title(report: dict) -> list[str]:
    return [f"# Agentic SAST — {_target_name(report)}", ""]


def _summary_section(report: dict) -> list[str]:
    out = ["## Summary", ""]
    target = report.get("target") or {}
    repo = _s(target.get("repo_path"))
    commit = _s(target.get("commit"))
    if repo:
        line = f"**Target:** `{repo}`"
        if commit:
            line += f" (commit `{commit}`)"
        out.append(line)
    run_id = _s(report.get("run_id"))
    if run_id:
        out.append(f"**Run ID:** `{run_id}`")
    out += _run_context_lines(report)

    summary = report.get("summary") or {}
    total = summary.get("total")
    if total is None:
        total = len(report.get("findings") or [])
    tally = _sev_tally(summary.get("by_severity") or {})
    line = f"**Total findings:** {total}"
    if tally:
        line += f" — {tally}"
    out.append(line)
    out.append("")
    return out


def _run_context_lines(report: dict) -> list[str]:
    """The header facts `phase4_report.md` prescribes, from `coverage.run_context`.

    Two of these were required and rendered nowhere. The achieved isolation
    tier appeared only further down, and the per-phase model list — the
    "Model transparency" section of the phase file — appeared not at all,
    which is the one line that makes a verification that shared the hunt's
    model visible to a reader. Both are copied from the manifest by
    `report_build._run_context`; nothing here derives anything.
    """
    ctx = (report.get("coverage") or {}).get("run_context") or {}
    if not isinstance(ctx, dict) or not ctx:
        return []
    out: list[str] = []
    repo = _s(ctx.get("target_repo"))
    tag = _s(ctx.get("target_tag"))
    commit = _s(ctx.get("target_commit"))
    if repo or tag or commit:
        parts = [p for p in (repo, tag, f"`{commit}`" if commit else "") if p]
        out.append(f"**Upstream:** {' @ '.join(parts)}")
    if _s(ctx.get("target_scope")):
        out.append(f"**Scope:** `{_s(ctx['target_scope'])}` — nothing outside it was hunted")
    started = _s(ctx.get("started_at"))
    if started:
        out.append(f"**Scan date:** {started[:10]}")
    mode = _s(ctx.get("mode"))
    if mode:
        out.append(f"**Mode:** {mode}")
    tier = _s(ctx.get("isolation_tier"))
    if tier:
        verified = ctx.get("isolation_verified")
        suffix = ("sandbox verification passed" if verified is True
                  else "sandbox verification did NOT pass" if verified is False
                  else "sandbox verification not recorded")
        out.append(f"**Isolation tier:** `{tier}` ({suffix})")
    models = ctx.get("models")
    if isinstance(models, dict) and models:
        rendered = "; ".join(f"{k}={v}" for k, v in models.items())
        out.append(f"**Models:** {rendered}")
        hunt = _s(models.get("phase2_hunt")).split(" ")[0]
        verify = _s(models.get("phase2c_verify")).split(" ")[0]
        distinct = {str(v).split(" ")[0] for v in models.values()}
        if hunt and verify and hunt != verify:
            out.append(
                f"**Model independence:** adversarial verification ran on "
                f"`{verify}`, a different model than the hunt's `{hunt}`."
            )
        elif hunt and verify:
            out.append(
                "**Model independence:** NONE — verification ran on the same "
                "model as the hunt and shared its blind spots."
            )
        elif len(distinct) == 1:
            out.append(
                "**Model independence:** every phase ran on the same model — "
                "verification shared the hunt's blind spots."
            )
    deviations = ctx.get("harness_deviations")
    if isinstance(deviations, int) and deviations:
        out.append(
            f"**Harness deviations:** {deviations} recorded in "
            "`manifest.json:harness_deviations`"
        )
    return out


def _sev_tally(by_severity: dict) -> str:
    """`critical: 1, medium: 2` in fixed severity order (deterministic)."""
    parts = [f"{sev}: {by_severity[sev]}" for sev in _SEV_ORDER if by_severity.get(sev)]
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Execution and Coverage — the four disclosures phase4_report.md requires.
# ---------------------------------------------------------------------------


def _execution_section(report: dict) -> list[str]:
    """Render the disclosures `phases/phase4_report.md` makes mandatory.

    `report_build.py` computes all of this into `report.json` under
    `coverage.execution`, and nothing rendered it. The phase file's completion
    gate is explicitly about `report.md` — "the run is not complete until
    report_build.py exits 0 **and the four disclosures are present in
    report.md**" — so a renderer that omits them turns a passing build into a
    report a reader cannot calibrate:

    * no achieved isolation tier, so `proven` carries no stated boundary;
    * proven / provable / not-provable-by-this-observer / total merged into
      silence, which is exactly the "18 of 25 proven" framing the phase file
      spends a section forbidding;
    * no uncovered-input count, so a partial scan reads as a complete one;
    * no over-claim tally, so prompt drift cannot be tracked across runs.

    Everything here is read, never derived — the numbers are Python's.
    """
    cvg = report.get("coverage") or {}
    ex = cvg.get("execution") or {}
    if not ex and not cvg:
        return ["## Execution and Coverage", "", NOT_DETERMINED, ""]

    out = ["## Execution and Coverage", ""]

    mode = _s(ex.get("mode"))
    tier = _s(ex.get("isolation_tier"))
    tier_note = {
        "gvisor": "syscall interception; proof mode permitted",
        "vm": "a separate kernel inside a virtual machine; proof mode permitted",
        "runc": "namespaces only, shared kernel; proof mode refused",
        "none": "no usable container runtime; static only",
    }.get(tier, "")
    if mode:
        out.append(f"- **Mode:** {mode}")
    if tier:
        out.append(f"- **Isolation tier achieved:** `{tier}`"
                   + (f" — {tier_note}" if tier_note else ""))

    total = ex.get("total")
    provable = ex.get("provable_by_execution")
    proven = ex.get("proven_by_execution")
    blind = ex.get("not_provable_by_observer")
    na = ex.get("not_applicable")
    if total is not None:
        out.append(
            f"- **Execution:** {_int(proven)} proven of {_int(provable)} provable by "
            f"execution; {_int(blind)} not provable by this observer; "
            f"{_int(na)} not settleable by any execution; {_int(total)} total."
        )

    enum_ = cvg.get("inputs_enumerated")
    covered = cvg.get("inputs_covered")
    uncovered = cvg.get("inputs_uncovered")
    if enum_ is not None:
        out.append(
            f"- **Coverage:** {_int(covered)} of {_int(enum_)} enumerated inputs "
            f"covered; {_int(uncovered)} uncovered."
        )
    out.append("")

    # The uncovered inputs by name. A count on its own tells a reader that a
    # gap exists and withholds the only thing that would let them close it,
    # and "silence about a gap reads as coverage of it" is the phase file's
    # own description of the most consequential lie a scanner can tell.
    uncovered_rows = cvg.get("uncovered_inputs")
    if isinstance(uncovered_rows, list) and uncovered_rows:
        out += ["### Enumerated inputs NOT covered", "",
                "Each row is attacker-reachable surface the run enumerated and "
                "then did not trace to a sink. None of them is a clean result.",
                ""]
        out += _md_table(
            ["Input", "Location", "Entry point", "Trust", "Why it is uncovered"],
            [[_cell(r.get("id")), f"`{_cell(r.get('location'))}`",
              _cell(r.get("entry_point")), _cell(r.get("trust_level")),
              _cell(r.get("note") or r.get("reason"))]
             for r in uncovered_rows if isinstance(r, dict)],
        )
        out.append("")

    note = _s(ex.get("not_provable_by_observer_note"))
    if note:
        out += [f"> **What \"not provable by this observer\" means.** {note}", ""]

    by_outcome = ex.get("by_outcome") or {}
    if by_outcome:
        out += ["### Execution outcome, per finding", ""]
        out += _md_table(
            ["Outcome", "Findings", "What it establishes"],
            [[f"`{k}`", _int(v), _OUTCOME_MEANING.get(k, "")]
             for k, v in sorted(by_outcome.items(), key=lambda kv: -kv[1])],
            aligns=["l", "r", "l"],
        )
        out.append("")

    artefact = ex.get("self_attribution_artefacts")
    if isinstance(artefact, dict) and artefact.get("count"):
        ids = ", ".join(f"`{_cell(i)}`" for i in artefact.get("finding_ids") or [])
        out += [
            f"> **{_int(artefact['count'])} of the `self_attributed` verdicts are a "
            f"harness artefact, not a PoC that cheated.** {_s(artefact.get('note'))}"
            + (f" Affected: {ids}." if ids else ""),
            "",
        ]

    out += _structural_block(ex.get("structural") or {})
    out += _oracle_conflict_block(ex.get("oracle_conflicts") or {})

    sites = cvg.get("sites_canonicalised_by_a_rejected_finding")
    if isinstance(sites, dict) and sites.get("count"):
        hidden = int(sites.get("with_a_confirmed_member_hidden") or 0)
        out += [
            f"- **Sites led by a rejected record:** {_int(sites['count'])} of the "
            "deduplicated sites are represented by a finding the adversarial "
            "verifier rejected, and are therefore withheld in full. "
            + ("Every one of them had all its members rejected, so nothing "
               "confirmed is hidden behind them."
               if hidden == 0 else
               f"**{hidden} of them hide a CONFIRMED finding**, withheld twice — "
               "once as rejected, once as a duplicate of the rejected record. "
               "That is a defect in the report, not a property of the code."),
            "",
        ]

    claimed = ex.get("overclaimed")
    if claimed is not None:
        out += [f"- **Over-claim tally:** {_int(claimed)} finding(s) where the hunt "
                f"agent claimed success and the gate disagreed.", ""]

    caveats = [c for c in (_s(x) for x in _as_list(cvg.get("caveats"))) if c]
    legacy = _s(cvg.get("coverage_caveat"))
    if legacy and legacy not in caveats:
        caveats.append(legacy)
    for caveat in caveats:
        out += [f"> **Incomplete coverage.** {caveat}", ""]

    return out


def _oracle_conflict_block(conflicts: dict) -> list[str]:
    """Where the oracles and the verifier disagreed, printed rather than resolved.

    A report that shows only the verdict it happened to reach last is a report
    that hides the one thing a reader can use to calibrate how much any single
    verdict is worth.
    """
    if not isinstance(conflicts, dict) or not conflicts:
        return []
    out = ["### Where the oracles and the verifier disagreed", ""]
    rows = (
        ("demonstrated_but_rejected",
         "A structural probe held and phase 2c still rejected the finding. The "
         "predicate was true and the defect was not reachable with "
         "attacker-supplied data — which is exactly why `demonstrated` is not "
         "`proven` and not a substitute for the verifier."),
        ("refuted_but_confirmed",
         "A structural probe refuted the finding and phase 2c confirmed it "
         "anyway, in writing. Read the finding's verification block before "
         "deciding: an overturned refutation is a claim about the probe, and "
         "it is printed here rather than deleted."),
        ("proven_but_rejected",
         "The execution gate observed the target's own frame interpret this "
         "PoC's payload and phase 2c disagreed on re-reading the source. The "
         "observation outranks the re-read, so the finding is delivered; the "
         "disagreement is disclosed."),
    )
    for key, meaning in rows:
        ids = conflicts.get(key)
        if not ids:
            continue
        rendered = ", ".join(f"`{_cell(i)}`" for i in ids)
        out += [f"- **`{key}`** ({len(ids)}): {rendered}. {meaning}"]
    out.append("")
    return out


def _structural_block(st: dict) -> list[str]:
    """The second oracle's numbers, rendered strictly beside the first.

    Never summed with the execution denominators, never placed in the same
    table, and always carrying the sentence that says why. A reader who takes
    `demonstrated` for `proven` has been told the run settled something in a
    fresh container under five conditions when what actually happened is that a
    deterministic predicate held over the target's own output. Both are
    evidence; only one is the claim the word `proven` makes.

    The block also reports how much of the observer-blind population was probed
    at all. Without that, `0 demonstrated` is ambiguous between "we looked and
    found nothing" and "we never looked", and those are opposite facts.
    """
    if not st:
        return []
    if not st.get("probed"):
        # Silence here would be the ambiguity this block exists to remove: a
        # reader seeing nothing cannot tell "probed and found nothing" from
        # "never probed", and with a large observer-blind population the second
        # is a gap in the run that must be stated.
        blind = st.get("observer_blind_total") or 0
        if not blind:
            return []
        return [
            "### Structural evidence (second oracle)", "",
            f"- **No structural probe was run.** {_int(blind)} finding(s) are in "
            "classes the audit-hook observer has no event for, so execution "
            "could never settle them — and no differential was declared for any "
            "of them either. Those findings rest on their static argument "
            "alone. This is a gap in the run, not a property of the code.", "",
        ]

    out = ["### Structural evidence (second oracle)", ""]
    out.append(
        f"- **Demonstrated:** {_int(st.get('demonstrated'))} of "
        f"{_int(st.get('probed'))} probed — a deterministic differential showed "
        "the target's own code turning attacker-controlled input into an "
        "executable construct, a breached resource bound, or a mutated global."
    )
    refuted = st.get("refuted") or 0
    if refuted:
        out.append(
            f"- **Refuted:** {_int(refuted)} — the differential ran and the "
            "defence held. Recorded, never deleted; phase 2c had to address "
            "each one in writing before confirming the finding."
        )
    for key, label in (("inconclusive", "Inconclusive"),
                       ("probe_error", "Probe error"),
                       ("probe_absent", "Probe absent")):
        value = st.get(key) or 0
        if value:
            out.append(f"- **{label}:** {_int(value)}")

    blind_total = st.get("observer_blind_total")
    blind_probed = st.get("observer_blind_probed")
    if blind_total:
        out.append(
            f"- **Second look at the blind spot:** {_int(blind_probed)} of "
            f"{_int(blind_total)} findings in classes the audit hook cannot see "
            "carried a structural probe."
        )
    out.append("")

    kinds = st.get("by_probe_kind") or {}
    if kinds:
        out += _md_table(
            ["Probe", "Findings"],
            [[f"`{k}`", _int(v)] for k, v in sorted(kinds.items(), key=lambda kv: -kv[1])],
            aligns=["l", "r"],
        )
        out.append("")

    note = _s(st.get("note"))
    if note:
        out += [f"> **`demonstrated` is not `proven`.** {note}", ""]
    return out


#: How each gate outcome is written. Taken from `phase4_report.md`'s table,
#: which also lists what each must never be called — `sink_reached_unproven` is
#: not "failed", `self_attributed` is not "false positive", `not_attempted` is
#: not "unconfirmed", and nothing here is "not vulnerable".
_OUTCOME_MEANING = {
    "proven": "All five gate conditions held in a fresh container, unanimously.",
    "sink_reached_unproven": "The sink was reached with attacker data present; "
                             "interpretation was not demonstrated. This is also what "
                             "an effective defence looks like from the runtime.",
    "self_attributed": "The PoC reached the sink directly and did not exercise the "
                       "target's own path.",
    "nonce_mismatch": "Runtime events could not be attributed to this PoC.",
    "no_event": "This PoC did not trigger the operation. Not a refutation — the sink "
                "may be reachable another way.",
    "observer_absent": "The observer never armed; the harness failed. This says "
                       "nothing about the code.",
    "not_attempted": "Execution was unavailable (static mode or a missing toolchain). "
                     "An environment limitation.",
    "not_applicable": "This class cannot be settled by running code; the finding rests "
                      "on source analysis.",
}


# ---------------------------------------------------------------------------
# Scan Metrics.
# ---------------------------------------------------------------------------


def _scan_metrics_section(report: dict) -> list[str]:
    out = ["## Scan Metrics", ""]
    m = report.get("scan_metrics")
    if not m:
        out += [NOT_DETERMINED, ""]
        return out

    # "(static run)" was printed against every absent metric, including on
    # proof runs, which told a reader the wrong reason for the gap. An absent
    # number is unmeasured; it is not evidence that execution did not happen.
    def bullet(label: str, value: str, absent: str = "not measured on this run") -> None:
        out.append(f"- {label}: {value if value else absent}")

    bullet("Files in scope", _int(m.get("files_in_scope")),
           "not measured — this run recorded no file-level coverage ledger")
    bullet("Files analyzed (unique)", _int(m.get("files_analyzed")),
           "not measured — see the input ledger above for the coverage that was")
    cov = m.get("coverage_pct")
    bullet("Coverage", f"{cov:.1f}%" if isinstance(cov, (int, float)) else "",
           "no file-level percentage; the input ledger is the coverage disclosure")
    dur = m.get("duration_sec")
    bullet("Duration (sec)", _fmt_num(dur))
    cost = m.get("cost_usd")
    bullet(
        "Cost (USD)",
        f"${cost:.4f}" if isinstance(cost, (int, float)) else "",
        "deliberately not stated — no rate table was supplied, and no rate card "
        "is compiled into PyHunt. Tokens and container time are measured and "
        "reported under Cost, which is what can be priced against whatever "
        "card applies",
    )
    out.append("")

    # Coverage gaps belong next to the coverage number, not buried in JSON. A
    # reader who sees "Coverage 98%" and nothing else will assume the sweep was
    # complete — even when hunt tasks died and whole attack angles went
    # unexamined.
    #
    # Two shapes are accepted, and BOTH must render. `report_build` writes a
    # LIST under `caveats` — `attach_coverage` appends the failed/incomplete/
    # unmeasured-task disclosures and `attach_preflight` appends the
    # "execution was requested but the container could not provide it" one, so
    # a single string could not have held them. `coverage_caveat` is the older
    # single-string key. Reading only one of the two silently drops every
    # caveat the other writer produced, which is worse than emitting none:
    # the report then reads exactly like a run with nothing to disclose.
    cvg = report.get("coverage") or {}
    caveats = [c for c in (_s(x) for x in _as_list(cvg.get("caveats"))) if c]
    legacy = _s(cvg.get("coverage_caveat"))
    if legacy and legacy not in caveats:
        caveats.append(legacy)
    for caveat in caveats:
        out += [f"> **Incomplete coverage.** {caveat}", ""]

    phases = m.get("tokens_by_phase") or []
    if phases:
        out += ["### Tokens by phase", ""]
        rows = []
        for p in phases:
            rows.append([
                _s(p.get("phase")),
                _int(p.get("input_tokens")),
                _int(p.get("output_tokens")),
                f"${p['cost_usd']:.4f}" if isinstance(p.get("cost_usd"), (int, float)) else "",
            ])
        out += _md_table(
            ["Phase", "Input tokens", "Output tokens", "Cost (USD)"],
            rows, aligns=["l", "r", "r", "r"],
        )
        out.append("")
    return out


def _fmt_num(value: Any) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.1f}"
    return ""


# ---------------------------------------------------------------------------
# Threat Model.
# ---------------------------------------------------------------------------


def _threat_model_section(report: dict) -> list[str]:
    out = ["## Threat Model", ""]
    tm = report.get("threat_model")
    if not tm:
        out += [NOT_DETERMINED, ""]
        return out

    out += ["### System context", ""]
    out += [_s(tm.get("system_context")) or NOT_DETERMINED, ""]

    # Assets table.
    out += ["### Assets", ""]
    assets = tm.get("assets") or []
    if assets:
        rows = [[_s(a.get("name")), _s(a.get("sensitivity")), _s(a.get("description"))]
                for a in assets]
        out += _md_table(["Asset", "Sensitivity", "Description"], rows)
    else:
        out.append(NOT_DETERMINED)
    out.append("")

    # Trust boundaries.
    out += ["### Trust boundaries", ""]
    boundaries = tm.get("trust_boundaries") or []
    if boundaries:
        for b in boundaries:
            name = _s(b.get("name"))
            desc = _s(b.get("description"))
            out.append(f"- **{name}** — {desc}" if name else f"- {desc}")
    else:
        out.append(NOT_DETERMINED)
    out.append("")

    # Ranked threats table.
    out += ["### Ranked threats", ""]
    threats = tm.get("ranked_threats") or []
    if threats:
        rows = [[_s(t.get("rank")), _s(t.get("threat")), _s(t.get("rationale"))]
                for t in threats]
        out += _md_table(["#", "Threat", "Rationale"], rows, aligns=["r", "l", "l"])
    else:
        out.append(NOT_DETERMINED)
    out.append("")

    # Open questions.
    out += ["### Open questions", ""]
    questions = tm.get("open_questions") or []
    if questions:
        out += [f"- {_s(q)}" for q in questions]
    else:
        out.append(NOT_DETERMINED)
    out.append("")
    return out


# ---------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------


def _verification_section(report: dict) -> list[str]:
    out = ["## Verification", ""]
    v = report.get("verification")
    if not v:
        out += [NOT_DETERMINED, ""]
        return out
    out.append(f"- Raw findings (pre-verification): {_s(v.get('raw_findings'))}")
    out.append(f"- True positives (confirmed): {_s(v.get('true_positives'))}")
    out.append(f"- False positives (rejected): {_s(v.get('false_positives'))}")
    out.append(f"- Needs more info: {_s(v.get('needs_more_info'))}")
    out.append(f"- Duplicates collapsed: {_s(v.get('duplicates_collapsed'))}")
    prec = v.get("precision_pct")
    if isinstance(prec, (int, float)):
        out.append(f"- Verification precision: {prec:.1f}%")
    else:
        # Never render undefined precision as a number. `0.0%` on a run where
        # verification simply did not happen tells the reader every finding was
        # rejected, when in fact none was even examined.
        note = v.get("precision_note") or "not computed (verification did not run)"
        out.append(f"- Verification precision: **not computed** — {note}")

    # Where the difference between "recorded" and "delivered" went. The funnel
    # above says how many findings were rejected; this says how many rows the
    # report withheld and for which of two different reasons, so the gap
    # between `Raw findings` and `Findings (N)` is arithmetic a reader can do
    # rather than a number they have to trust.
    withheld = (report.get("coverage") or {}).get("findings_withheld")
    if isinstance(withheld, dict) and withheld:
        parts = ", ".join(f"{k.replace('_', ' ')}: {_int(n)}"
                          for k, n in sorted(withheld.items()))
        out.append(f"- Withheld from the delivered set: {parts}")
    out.append(
        "- Nothing was deleted. Every rejected candidate keeps its own record "
        "in `verify/<finding_id>.json` with the verifier's rationale, its "
        "`checked_lines`, and the alternative explanation it ruled in — so a "
        "reader can see what the run considered and dismissed, not only what "
        "it kept.")
    out.append("")
    return out


# ---------------------------------------------------------------------------
# Findings.
# ---------------------------------------------------------------------------


def _findings_section(report: dict) -> list[str]:
    findings = report.get("findings") or []
    out = [f"## Findings ({len(findings)})", ""]
    if not findings:
        out += ["_No reachable, confirmed findings._", ""]
        return out
    for idx, f in enumerate(findings, start=1):
        out += _finding_block(idx, f if isinstance(f, dict) else {})
    return out


def _finding_block(idx: int, f: dict) -> list[str]:
    sev = _s(f.get("severity")).upper() or "UNKNOWN"
    title = _s(f.get("title")) or "(untitled finding)"
    out = [f"### {idx}. [{sev}] {title}", ""]
    out += _finding_meta(f)
    out.append("")

    out += ["#### Description", "", _s(f.get("description")) or NOT_DETERMINED, ""]
    out += ["#### Impact", "", _s(f.get("impact")) or NOT_DETERMINED, ""]
    out += ["#### Exploit scenario", "", _s(f.get("exploit_scenario")) or NOT_DETERMINED, ""]
    out += _preconditions(f)
    out += _evidence_and_trace(f)
    out += ["#### How to fix", "",
            _s(f.get("how_to_fix")) or _s(f.get("recommendation")) or NOT_DETERMINED, ""]
    out += _adversarial_verification(f)
    out += _ghsa_block(f)
    out += ["---", ""]
    return out


def _finding_meta(f: dict) -> list[str]:
    """The metadata header lines: Class / CWE (+link) / File / CVSS / Confidence /
    Also-at. Each line ends with two spaces so it hard-wraps in Markdown."""
    out: list[str] = []
    out.append(f"**Class:** {_s(f.get('vuln_class')) or NOT_DETERMINED}  ")
    cwe = _s(f.get("cwe"))
    if cwe:
        out.append(f"**CWE:** {_cwe_label(cwe)} — {_cwe_url(cwe)}  ")
    else:
        out.append(f"**CWE:** {NOT_DETERMINED}  ")

    file = _s(f.get("file"))
    ls, le = f.get("line_start"), f.get("line_end")
    loc = file
    if file and ls is not None:
        loc = f"{file}:{ls}-{le}" if le is not None and le != ls else f"{file}:{ls}"
    out.append(f"**File:** `{loc}`  " if loc else f"**File:** {NOT_DETERMINED}  ")

    out.append(f"**CVSS 3.1:** {_cvss_str(f.get('cvss'))}  ")
    out.append(f"**Confidence:** {_confidence_str(f)}  ")

    units = f.get("independent_units")
    if isinstance(units, int) and units > 1:
        out.append(
            f"**Found independently by:** {units} hunt units  ")

    # The execution gate's verdict for THIS finding, by name. Disclosure 4 of
    # `phase4_report.md` — "Each finding carries its outcome string verbatim.
    # Render it, do not translate it into a pass/fail column" — and it was
    # rendered only in aggregate, so a reader of a finding could not tell a
    # `proven` one from a `no_event` one without opening `report.json`.
    execution = f.get("execution") or {}
    gate = _s(execution.get("outcome"))
    if gate:
        detail = _OUTCOME_MEANING.get(gate, "")
        repeats = execution.get("repeats")
        unanimous = execution.get("unanimous")
        stamp = ""
        if isinstance(repeats, int) and repeats:
            stamp = f" ({repeats} replay{'s' if repeats != 1 else ''}"
            if unanimous is True:
                stamp += ", unanimous"
            elif unanimous is False:
                stamp += ", NOT unanimous"
            stamp += ")"
        out.append(f"**Execution gate:** `{gate}`{stamp}"
                   + (f" — {detail}" if detail else "") + "  ")

    structural = f.get("structural") or {}
    outcome = _s(structural.get("outcome"))
    if outcome:
        kind = _s(structural.get("probe_kind"))
        label = {
            "demonstrated": "demonstrated by a structural differential",
            "refuted": "REFUTED by a structural differential — the defence held",
            "inconclusive": "structurally inconclusive",
            "probe_error": "structural probe could not run",
            "probe_absent": "structural harness never armed",
            "not_attempted": "no structural probe was run",
        }.get(outcome, outcome)
        suffix = f" (`{kind}`)" if kind else ""
        out.append(f"**Structural oracle:** {label}{suffix}  ")

    also = _also_at(f.get("variants"))
    if also:
        out.append(f"**Also at:** {also}  ")
    return out


def _cvss_str(cvss: Any) -> str:
    if not isinstance(cvss, dict):
        return NOT_DETERMINED
    score = _fmt_score(cvss.get("score"))
    sev = _s(cvss.get("severity")).title()
    vector = _s(cvss.get("vector"))
    if not (score or vector):
        return NOT_DETERMINED
    head = f"**{score}**" if score else ""
    if sev:
        head = f"{head} ({sev})" if head else f"({sev})"
    if vector:
        return f"{head} — `{vector}`" if head else f"`{vector}`"
    return head or NOT_DETERMINED


def _confidence_str(f: dict) -> str:
    """Prefer the validator's confidence (adversarial), else the finding's own."""
    val = f.get("validation")
    if isinstance(val, dict):
        c = val.get("validator_confidence")
        if isinstance(c, (int, float)):
            return f"{c:.2f}"
    c = f.get("confidence")
    if isinstance(c, (int, float)):
        return f"{c:.2f}"
    return "Not determined"


def _also_at(variants: Any) -> str:
    """Render located-sibling references as `file:line` (or the bare finding_id
    when a variant carries no file). Empty string when there are none."""
    if not variants:
        return ""
    locs: list[str] = []
    for v in variants:
        if isinstance(v, dict):
            if v.get("file"):
                locs.append(f"`{_s(v.get('file'))}:{_s(v.get('line_start'))}`")
            else:
                locs.append(f"`{_s(v.get('finding_id'))}`")
        else:
            locs.append(f"`{_s(v)}`")
    return ", ".join(locs)


def _preconditions(f: dict) -> list[str]:
    out = ["#### Preconditions", ""]
    pres = f.get("preconditions")
    if isinstance(pres, list) and pres:
        out += [f"- {_s(p)}" for p in pres]
    else:
        out.append(NOT_DETERMINED)
    out.append("")
    return out


def _evidence_and_trace(f: dict) -> list[str]:
    out: list[str] = []
    evidence = _s(f.get("evidence"))
    if evidence:
        out += ["_Evidence:_", ""]
        out += _fenced(evidence)
        out.append("")
    trace = f.get("trace") or {}
    eps = trace.get("entry_points") or []
    if eps:
        out.append("**Entry points:**")
        for e in eps:
            kind = _s(e.get("kind"))
            location = _s(e.get("location"))
            by = _s(e.get("controllable_by"))
            line = f"- `{kind}` at `{location}`"
            if by:
                line += f" — controllable by {by}"
            out.append(line)
        out.append("")
    chain = trace.get("call_chain") or []
    if chain:
        out.append("**Call chain:**")
        for frame in chain:
            out.append(f"1. `{_s(frame.get('file'))}:{_s(frame.get('line'))}` — "
                       f"`{_s(frame.get('function'))}()`")
        out.append("")
    return out


def _adversarial_verification(f: dict) -> list[str]:
    out = ["#### Adversarial verification", ""]
    val = f.get("validation")
    if not isinstance(val, dict) or not val:
        out += [NOT_DETERMINED, ""]
        return out
    verdict = _s(val.get("verdict"))
    label = _VERDICT_LABEL.get(verdict, verdict.upper() or "UNKNOWN")
    conf = val.get("validator_confidence")
    head = f"**Verdict:** {label}"
    if isinstance(conf, (int, float)):
        head += f" — confidence {conf:.2f}"
    out.append(head)
    rationale = _s(val.get("rationale"))
    if rationale:
        out += ["", rationale]
    out.append("")
    return out


# ---------------------------------------------------------------------------
# GHSA-style advisory sub-block (Advisory metadata + Proof of Concept + Weaknesses).
# ---------------------------------------------------------------------------


def _ghsa_block(f: dict) -> list[str]:
    out = ["#### Advisory", "",
           "_GHSA-style advisory — paste-ready for a GitHub Security Advisory._", ""]
    out.append(f"**Summary** — {_s(f.get('title')) or NOT_DETERMINED}")
    out.append("")
    out.append(f"**Details** — {_s(f.get('description')) or NOT_DETERMINED}")
    out.append("")
    out.append(f"**Impact** — {_s(f.get('impact')) or NOT_DETERMINED}")
    out.append("")
    out.append(f"**Affected versions:** {_ADVISORY_VERSIONS}  ")
    out.append(f"**Patched versions:** {_ADVISORY_VERSIONS}")
    out.append("")
    out += _advisory_references(f)

    # Proof of Concept — its own sub-header so the fenced PoC reads clearly.
    out += ["#### Proof of Concept", ""]
    poc = f.get("poc")
    gate = _s(((f.get("execution") or {}).get("outcome")))
    if not poc and gate == "not_applicable":
        # A finding in a class no execution can settle has no PoC BY DESIGN,
        # and "_Not determined (static run)._" tells the reader the opposite —
        # that something was meant to be here and is missing.
        out += ["_No PoC, deliberately. The execution gate returned "
                "`not_applicable` for this finding: its class cannot be "
                "settled by running code, so a PoC would demonstrate that the "
                "behaviour occurs without saying anything about whether it is "
                "allowed. The evidence is the source reading above._", ""]
    else:
        out += _poc_block(poc)
    out.append("")

    # Weaknesses — CWE id + name + MITRE link.
    out += ["#### Weaknesses", ""]
    cwe = _s(f.get("cwe"))
    if cwe:
        out.append(f"- [{_cwe_label(cwe)}]({_cwe_url(cwe)})")
    else:
        out.append(NOT_DETERMINED)
    out.append("")
    return out


def _advisory_references(f: dict) -> list[str]:
    out = ["**References:**"]
    cwe = _s(f.get("cwe"))
    refs: list[str] = []
    if cwe:
        refs.append(f"- {_cwe_url(cwe)}")
    file = _s(f.get("file"))
    if file:
        ls = f.get("line_start")
        loc = f"{file}:{ls}" if ls is not None else file
        refs.append(f"- `{loc}` (source location)")
    if not refs:
        refs.append(f"- {NOT_DETERMINED}")
    out += refs
    out.append("")
    return out


def _poc_block(poc: Any) -> list[str]:
    if not isinstance(poc, dict) or not _s(poc.get("code")):
        return [NOT_DETERMINED]
    lang = _s(poc.get("language"))
    out = _fenced(_s(poc.get("code")), lang)
    succeeded = poc.get("succeeded")
    if isinstance(succeeded, bool):
        status = "executed successfully" if succeeded else "not executed (static run)"
        out.append("")
        out.append(f"_PoC status: {status}._")

    # The observer evidence is the receipt: it records that the dangerous
    # operation was seen to FIRE (a process spawned, a socket opened) and — via
    # the attribution suffix / JFR stack trace — that it fired from the target's
    # own code. Without it a reader has the exploit script but no proof it ran,
    # which is precisely the claim this tool exists to make.
    evidence = poc.get("observer_evidence")
    if isinstance(evidence, list) and evidence:
        out += ["", "**Runtime observer evidence** — the dangerous operation was "
                    "observed as it fired:", ""]
        out += _fenced("\n".join(str(e) for e in evidence[:12]), "text")

    run_output = _s(poc.get("run_output"))
    if run_output and not evidence:
        out += ["", "**PoC output:**", ""]
        out += _fenced(run_output[-1200:], "text")

    notes = _s(poc.get("notes"))
    if notes:
        out += ["", f"_{notes}_"]
    return out


# ---------------------------------------------------------------------------
# Exploit chains (conditional).
# ---------------------------------------------------------------------------


def _chains_section(report: dict) -> list[str]:
    chains = report.get("chains") or []
    if not chains:
        return []
    out = ["## Exploit chains", ""]
    for c in chains:
        c = c if isinstance(c, dict) else {}
        sev = _s(c.get("severity")).upper() or "UNKNOWN"
        title = _s(c.get("title")) or "(untitled chain)"
        out.append(f"### [{sev}] {title}")
        fids = c.get("finding_ids") or []
        if fids:
            out.append(f"**Findings:** {', '.join(_s(x) for x in fids)}")
        out.append("")
        out.append(_s(c.get("narrative")) or NOT_DETERMINED)
        out.append("")
        blocked = c.get("blocked_by_controls") or []
        if blocked:
            out.append(f"**Blocked by controls:** {', '.join(_s(x) for x in blocked)}")
            out.append("")
    return out
