# Honest reporting

Coverage, denominators, and disclosure. These are release gates, not style
preferences: a report that violates one of them is worse than no report, because
it converts a gap into a clean bill of health that someone will act on.

The governing idea is one sentence: **a scanner's most dangerous output is a
number that hides the thing it did not do.**

---

## 1. Three denominators, never merged

Every summary states **proven**, **provable**, and **total** as three separate
numbers.

| Number | Definition |
|---|---|
| **total** | every finding that survived phase 2c — the deliverable set |
| **provable** | of those, the ones whose class execution *could* settle: total minus the `not_applicable` findings |
| **proven** | of the provable ones, the ones the gate returned `proven` for |

Write them as two fractions with their bases visible:

> **18 of 19 provable findings were proven by execution.** A further **6
> findings are not provable by execution** (access control ×4, hardcoded secret
> ×2) and rest on a static argument. **25 findings total.**

Never write this:

> ~~18 of 25 findings confirmed (72%).~~

The second sentence is arithmetically true and materially false. It implies 7
findings failed to reproduce; in fact 6 of them were never candidates for
reproduction, and the single genuine miss is buried. A reader deciding what to
fix first is misled by a number that looks like a confidence score.

**A percentage without its base is not permitted anywhere in the report.**

### Why `not_applicable` is not "unproven"

Execution answers *"did this behaviour occur?"*. It cannot answer *"was this
behaviour allowed?"* — that needs the intended policy, which does not exist in
the runtime. A PoC can show user A reading user B's record and still not
establish that doing so is wrong.

`UNDECIDABLE_BY_EXECUTION` in `scripts/oracle/classes.py` is the authoritative
list, and `is_undecidable()` is consulted **before** any evidence or environment
question, so these findings never enter the evidence path at all:

`access_control` · `authorization` · `authz` · `idor` · `privilege_escalation` ·
`business_logic` · `workflow` · `insecure_design` · `insecure_default` ·
`missing_auth` · `mass_assignment` · `information_disclosure` · `csrf` ·
`rate_limit` · `cryptographic_failure` · `weak_crypto` · `hardcoded_secret`

Matching is substring-based in both directions and normalises `-` and spaces to
`_`, so `broken_access_control` matches the `access_control` key.

Report each of these as **"not provable by execution"**, with the reason the
table gives, and with the *policy* argument the finding rests on instead: which
code should have carried the check, and what the intended policy evidently is.
Never dress one up as proven, and never let it sit silently in an unproven
column where a reader will read it as "we tried and failed".

---

## 2. Every enumerated input carries a disposition

`coverage.py` asserts it, exits `2` if it does not hold, and that exit code stops
the run. The report states the ledger:

> Recon enumerated **12** attacker-controllable inputs. **11 covered**, **1
> uncovered** (`in_7`, `X-Forwarded-For` header at `app/middleware.py:22` — no
> finding file or task scope reached it).

Rules:

- `covered + uncovered == enumerated`, and `len(inputs) == enumerated`. Both are
  asserted; neither may be computed by the report agent.
- **An `uncovered` input is a disclosed gap, not a pass.** It means nothing
  traced that input to a sink. Name it, with its location and why it was missed.
- **Zero enumerated inputs is a red flag, not perfect coverage.** A denominator
  of zero makes every coverage percentage 100%. If recon found no
  attacker-controlled surface in a repository that has one, the run is broken —
  say that instead of reporting complete coverage.
- The identifier key is `input_id` in the results directory and `id` in
  `recon_output.schema.json`. They are the same value; a consumer that reads only
  one spelling drops inputs silently, and a completeness assertion that iterated
  an empty list passes. See the seam note in `references/output-contracts.md`.

### File-level coverage is a second, separate ledger

From `coverage.json`:

> **214** eligible source files; **198** reached by a targeted task; **9**
> catch-all sweep tasks covered the remainder; **0** files dropped at the sweep
> cap.

`catchall_dropped > 0` sets `coverage_complete: false`, and when that flag is
false **the report may not imply full coverage — not in prose, and not by
omission.** Say how many files were not hunted and why.

Also disclose what is structurally outside the denominator: `catchall.py` drops
docs, lockfiles, snapshots, fixtures, minified assets, and anything under
`docs/`, `examples/`, `fixtures/`, `mocks/`. A vulnerability living in
`examples/` was not looked for. (Credential-prone configs — `.env`, `*.pem`,
`*.key` — are deliberately kept in scope.)

---

## 3. The achieved isolation tier is stated, by name

From `manifest.json:isolation_tier`, written by `sandbox.py detect` in phase 0.

| Tier | Boundary | Proof mode |
|---|---|---|
| `gvisor` | syscall interception | allowed |
| `vm` | separate kernel in a VM (Docker Desktop) | allowed |
| `runc` | namespaces only | refused |
| `none` | no Docker | refused, static only |

> Findings were proven under isolation tier **`vm`** (Docker Desktop; separate
> kernel, `network: none`, read-only rootfs, all capabilities dropped, no auth
> environment). Sandbox verification passed.

**A `vm` run must never be described as `gvisor`**, and a Static run must never
imply Proof. Two related disclosures:

- If Proof mode was **refused** because `sandbox.py verify` failed, say so and
  say why. Every finding will carry `not_attempted`, and the report must not read
  as though nothing could be proven about the code.
- If the user chose Static, say that no exploit was executed, so the strongest
  available verdict was `not_attempted` by construction.

---

## 4. Missing toolchain is never a failed exploit

`not_attempted` is an environment fact. So is `observer_absent`. Neither is
evidence about the code, and neither may be presented alongside "did not
reproduce".

The eight outcomes, and the exact language each gets in the report:

| Outcome | Report it as |
|---|---|
| `proven` | "Confirmed by execution", with the attributed marker line quoted verbatim |
| `sink_reached_unproven` | "Sink reachable with attacker data; exploitation not demonstrated." Note that this is also what an effective defence looks like |
| `self_attributed` | "PoC bypassed the code under test; not evidence about the target" |
| `nonce_mismatch` | "Output not attributable to this PoC" |
| `no_event` | "This PoC did not demonstrate the finding." **Never** "the finding is false" |
| `observer_absent` | "Instrumentation did not run — harness failure, no information about the code" |
| `not_attempted` | "Execution unavailable (static run / missing toolchain / unprovisioned dependencies)" |
| `not_applicable` | "Not provable by execution — [reason from the class table]" |

Collapsing rows 2–8 into "not proven" is how a scanner turns a broken container
into a clean bill of health. Each row means something different, and the
difference is what a reader needs.

The specific case that keeps recurring: `preflight.json` reporting
`target_importable: false` means the target's dependencies are not installed in
the container that ran the PoCs, so **every Python PoC could only prove that a
hello-world ran.** That is a whole-run caveat and belongs in the summary, not in
a per-finding footnote.

---

## 5. Verification honesty

**The funnel, not just the survivors.** `report.json:verification` is injected
from run state and never agent-authored:

> **41** raw findings from phase 2 → **25** confirmed, **13** rejected, **3**
> needs-more-info; **4** duplicates collapsed. Precision **61%**.

Reporting only the 25 hides the 13 refutations, which are the evidence that phase
2c did anything.

**Model independence, disclosed either way.** Phase 2c must run on a different
model than phase 2. Compare `manifest.json:model_used` against the `model` field
each `verify/<id>.json` recorded:

- Different → state that verification was model-independent.
- **Same, or the `model` field missing → say so plainly.** A verification that
  shared the producer's model shared its blind spots, and the verification column
  implies an independence it did not have. This control is weaker in the skill
  form than the config pin it replaced (it detects rather than prevents), and
  concealing a detection defeats the only thing it can do.

**`needs_more_info` is not a quiet rejection.** It means a decisive
disambiguation needs information nobody had. Report those findings with the
`suggested_test` that would resolve them.

**Reasoned and executed findings are never presented at the same visual
weight.** Label each one. A reader skimming a severity column cannot tell the
difference otherwise.

**CVSS is computed, not asserted.** `cvss.py` derives score and rating from the
vector the verifier supplied. Do not let a model do the arithmetic and do not
re-derive a rating in prose that disagrees with the computed one.

---

## 6. What must be disclosed even when it is embarrassing

A gap that is not disclosed reads as a clean result. All of these go in the
report:

- **Failed work units** — hunt tasks that errored, subagents that returned
  malformed JSON after the repair attempt, phases that were resumed and re-ran
  work.
- **Files past the sweep cap** (`catchall_dropped`) and files outside the
  eligibility filter.
- **Unprovisioned dependencies** and any `preflight.json` capability that came
  back `false` or `null`. A `null` means unknown; treat its silence as no
  information, never as a pass.
- **Everything in `gaps_observed`** across all findings files — the areas hunters
  said they could not fully examine.
- **Resume boundaries.** If the run resumed from `phases_completed`, say which
  phases ran in which invocation; a phase that failed halfway re-runs from its
  start and may have duplicated or skipped work.
- **Any gate anomaly.** A rising `contradicts_model` rate means the hunters
  claimed successes the evidence did not support. Report the count.

---

## 7. Findings must earn their place

- **Zero findings is a valid outcome.** If every candidate died in phase 2c, say
  "no exploitable vulnerabilities found", list the gaps and the code smells, and
  stop. Do not soften the criteria to fill the report.
- **Do not pad.** Theoretical attacks, patterns with downstream mitigations, and
  weaker variants of already-reported issues are code smells. They go in a
  separate section, clearly labelled, and never in the severity table.
- **Name the capability, not the mechanism.** "String interpolation into
  `cursor.execute`" is a mechanism. "An unauthenticated caller can read every row
  of `users`, including password hashes" is a finding. *A vulnerability must harm
  someone other than the attacker* — a "vulnerability" only the attacker can
  trigger against themselves is not one.
- **Every finding carries a concrete flow** from an attacker-controlled source to
  a sink, at `file:line`s that were actually read. Never cite a line you did not
  open.
- **One finding per sink location.** Do not group multiple sinks under one id to
  make the table shorter; the count of confirmed sinks is a number people use.

---

## 8. Redaction, and what evidence may be published

`redact.py` runs at the write boundary so card data, PII, and credential material
the model quoted out of source never lands in the report. Two rules that survive
redaction:

- **Marker lines are quoted verbatim.** They are the receipt a human uses to
  check the gate's arithmetic. If redaction would destroy a marker line's
  meaning, say the line was redacted rather than paraphrasing it into something
  that looks like proof.
- **Payloads are described, not weaponised.** The PoC that proved a finding is
  evidence; a copy-paste-ready exploit for a live system is not the deliverable.
  For code-generation findings the strongest evidence is a parse tree
  (`ast.parse` showing the injected marker as a statement rather than string
  text), which is both stronger and safe to publish.

---

## The honest summary block

What the top of a report should look like when all of the above is applied:

> **Target:** `/srv/acme-api` @ `a1b2c3d` · **Mode:** Proof · **Isolation tier:**
> `vm` (verified: no egress, no host filesystem, no auth environment)
>
> **25 findings** after adversarial verification (41 raw → 25 confirmed, 13
> rejected, 3 needs-more-info, 4 duplicates collapsed; precision 61%).
> Verification ran on a different model than the hunt.
>
> **18 of 19 provable findings proven by execution.** One provable finding
> (`f_archiver_join`) returned `sink_reached_unproven` — the sink is reachable
> with attacker data but nothing interpreted the payload; see its entry.
> **6 findings are not provable by execution** (access control ×4, hardcoded
> secret ×2) and rest on static and policy arguments.
>
> **Coverage:** 12 inputs enumerated, 11 covered, 1 uncovered (`in_7`). 214
> eligible source files, 0 dropped at the sweep cap. `coverage_complete: true`.
> Not examined: `docs/`, `examples/`, and 3 hunt tasks that failed to return
> valid output (listed in Appendix B).

Every number in that block has a visible base, every gap is named, and nothing
implies a strength the run did not have.

---

## Related

- `references/execution-gate.md` — the eight outcomes and why nothing demotes
- `references/output-contracts.md` — where each number comes from
- `scripts/oracle/classes.py` — the `UNDECIDABLE_BY_EXECUTION` table
- `scripts/coverage.py` — the completeness assertion that backs §2
