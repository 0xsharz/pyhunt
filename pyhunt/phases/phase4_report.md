# Phase 4 — Report: the advisory

> **Reads:** everything in `${RESULTS_DIR}` — `manifest.json`, `findings/*`,
> `proof/*`, `verify/*`, `coverage.json`, `inputs.json`, and the phase logs.
> **Writes:** `${RESULTS_DIR}/logs/report_narrative.json` (your prose), then
> `${RESULTS_DIR}/report.json` and `${RESULTS_DIR}/report.md` — both produced by
> `report_build.py`, never by hand.
> **Gate:** the run is not complete until `report_build.py` exits `0` and the
> four disclosures below are present in `report.md`.

Findings have been hunted, replayed against the gate, adversarially verified,
and swept for siblings, and the coverage ledger is closed (`coverage.py
assert-complete` exited `0`). This phase turns the results directory into an
advisory a human will act on.

`${PYHUNT_DIR}` is the skill directory, `${RESULTS_DIR}` the timestamped results
directory, `${TARGET}` the repository under scan. Where a flag below does not
match, run the script with `--help`: the script is authoritative, and a non-zero
exit is never routed around.

## The division of labour

**You render prose. Every number comes from Python.**

| Python computes it | You write it |
|---|---|
| Severity band and CVSS score (`scripts/cvss.py`, from the vector phase 2c emitted) | `title`, `description`, `impact`, `exploit_scenario`, `preconditions`, `how_to_fix`, `recommendation` |
| Execution outcome per finding (`scripts/oracle/gate.py`, via `proof/`) | The narrative that explains what the outcome means here |
| Coverage totals, input inventory, uncovered list (`coverage.json`) | The sentence that says plainly what was not examined |
| Finding identity for cross-run suppression (`scripts/fingerprint.py`) | The threat model, synthesised from what this run actually found |
| Secret masking at the write boundary (`scripts/redact.py`) | Nothing that needs masking, if you follow the rule below |
| Baseline checklist of classes checked (`scripts/baselines.py`) | The "checked and not found" commentary |
| The rendered Markdown itself (`scripts/reporting/markdown.py`) | — |

The reason for the split is not tidiness. Model arithmetic on a CVSS vector
produces a number that looks authoritative and is wrong by a band; a
model-estimated coverage percentage is a guess wearing a percent sign. Anything a
reader would act on numerically is computed once, deterministically, by code that
has tests.

## Procedure

**1. Read the run.** `manifest.json` (run id, target, commit, mode,
`isolation_tier`, `model_used`, `phases_completed`), every `findings/*.json`,
every `proof/*.json`, every `verify/*.json`, `coverage.json`, `inputs.json`,
`logs/sweep_table.md`, and `logs/phase2b_overclaim.txt`.

**2. Write the narrative.** Emit one JSON document to
`${RESULTS_DIR}/logs/report_narrative.json`, shaped by
`${PYHUNT_DIR}/schemas/report.schema.json` — but **only the fields listed as
yours** in the table above, plus `run_id`, `target`, and the `findings` array.

**3. Assemble.**

```bash
python3 "${PYHUNT_DIR}/scripts/report_build.py" build \
  --results-dir "${RESULTS_DIR}" \
  --narrative "${RESULTS_DIR}/logs/report_narrative.json" \
  --markdown "${RESULTS_DIR}/report.md" \
  --strict
```

`--markdown` is what produces `report.md`; it is opt-in, so omitting it leaves
you with `report.json` and no advisory. `--strict` is what turns a contract
violation into a non-zero exit instead of a line on stderr you will not read.
Both are required here.

`report_build.py` joins your prose to the computed facts, applies the CVSS
vector phase 2c assessed (or a severity-keyed baseline floor where there is
none), computes the execution denominators from `proof/`, injects the coverage
ledger and the input inventory, redacts the whole document, validates it
against `report.schema.json`, and writes `${RESULTS_DIR}/report.json` and
`${RESULTS_DIR}/report.md`.

**Your prose reaches the report only through `--narrative`.** There is no other
path. If you skip the flag, every `impact`, `exploit_scenario`, `how_to_fix`
and `preconditions` renders as `_Not determined (static run)._` and every
finding carries the same boilerplate recommendation — a report that looks like
a static run of a tool that executed PoCs.

The merge is a **whitelist**: it copies exactly the fields listed as yours in
the table above and ignores everything else, so a narrative can never overwrite
a computed number. The command reports what it did — `narrative_fields_applied`,
`narrative_findings_with_prose`, `narrative_unmatched_finding_ids` (prose you
wrote for a finding that was not delivered, which is dropped) and
`narrative_computed_fields_supplied`.

Exit `2` means a contract violation — a schema failure, or a narrative that
supplied a field the report computes. Fix the cause. Do not hand-write
`report.md` to get past it: a report assembled by hand is a report whose
numbers nobody checked.

**4. Read `report.md` before showing it to anyone**, and confirm the four
disclosures below are present and correct.

## Fields you must never write

The narrative merge is a whitelist, so a value you supply for any of these is
discarded rather than applied — but supplying one is still a bug, because it
means you believed you were computing something you were not. `--strict` exits
`2` and names the field:

Per finding: `cvss` · `execution` · `fingerprint` · `evidence` · `trace` ·
`variants` · `validation` · `confidence`

Top level: `summary` · `coverage` · `input_inventory` · `scan_metrics` ·
`verification`

Two of those are not merely overwritten but **rejected by the schema**:
`report.schema.json` sets `additionalProperties: false` on a report finding and
allows neither `execution` nor `fingerprint` there. A finding's execution
outcome lives in `coverage.execution` (run-level counts) and in its
`proof/<id>.json` record; its fingerprint lives on the `findings/*.json` record
that `fingerprint.py` wrote. Neither is a per-finding report field, so writing
one produces a schema error rather than a silently ignored key.

## The four disclosures

These are the difference between an advisory and a marketing document. Each must
appear on its own, in the report, unmerged with the others.

### 1. The achieved isolation tier

Print the tier the run actually got, from `manifest.isolation_tier` — never the
tier PyHunt is capable of, never the strongest tier in the table.

| Tier | Boundary | Proof mode |
|---|---|---|
| `gvisor` | Syscall interception (Linux + `runsc`) | allowed |
| `vm` | A separate kernel in a VM (Docker Desktop) | allowed |
| `runc` | Namespaces only | **refused** |
| `none` | No Docker | refused; static only |

**A `vm` scan never claims `gvisor`.** State the tier by name and say what its
boundary is in one clause. If phase 0's sandbox verification failed and proof
mode was refused, say that too, and say that every execution outcome is
therefore `not_attempted` — an environment limit, not a clean result.

### 2. Proven, provable, not-provable-here, and total — four denominators, never merged

All four come from `coverage.execution`, and `report_build.py stats` prints
them. They **partition** the findings: `provable_by_execution` +
`not_applicable` + `not_provable_by_observer` = `total`, exactly.

| Denominator | Key | Definition |
|---|---|---|
| **total** | `total` | Every finding the run recorded |
| **provable** | `provable_by_execution` | Findings execution could settle AND this observer can see |
| **proven** | `proven_by_execution` | Findings whose gate outcome is `proven` |
| **not provable by this observer** | `not_provable_by_observer` | Findings whose class PyHunt's observer has no event for |

Write all four. Never divide one by another and present a single number.

> "18 of 25 proven" is misleading when 6 of the 7 unproven findings are IDORs
> that no amount of execution could ever prove. "18 proven of 19 provable by
> execution; 6 more findings are in classes execution cannot settle; 25 total"
> is the same run, described honestly.

**The fourth number is about PyHunt, not about the target, and must be written
that way.** `not_applicable` means *no instrument could settle this class* — an
IDOR is a policy question and the runtime holds no policy.
`not_provable_by_observer` means *execution could settle it and our observer is
deaf to it*: CPython raises no audit event when a database cursor runs a query
or when a response body or header is written, so SQL injection, NoSQL
injection, XSS and open redirect can never reach `proven` here however sound
the finding is. Counting them as provable would measure the tool against
findings it structurally cannot prove; folding them into `not_applicable` would
bill PyHunt's blind spot to the target.

`coverage.execution.not_provable_by_observer_note` is the plain-language
sentence for this, and `not_provable_by_observer_reasons` gives the specific
reason per class. Quote them. A bare number invites the reader to hear "4
findings we tried and failed to prove", which is the opposite of what it means.

> "12 proven of 12 provable by execution; 4 findings are SQL injection and XSS,
> which PyHunt's runtime observer has no event for and therefore cannot prove
> either way; 3 more are access-control findings no execution could settle; 19
> total."

In static mode the sentence is: **"0 proven of 19 provable — execution was not
attempted (static mode, isolation tier `none`)."** It is never "0 vulnerabilities
confirmed", which a reader will hear as "nothing was wrong".

### 3. What the scan did not look at, and why

Straight from `coverage.json` and the sweep table. At minimum:

- inputs enumerated / covered / **uncovered**, with the uncovered ones listed by
  location and reason;
- files the catch-all sweep dropped at its cap (`catchall_dropped`), if any;
- hunt tasks that failed, timed out, or were deferred at the sweep bound;
- dependencies that would not provision, so their PoCs could not run.

**If `coverage.coverage_complete` is false, or `catchall_dropped > 0`, no
sentence anywhere in the report may imply the scan was exhaustive.** State
plainly that coverage is incomplete and by how much. Silence about a gap reads
as coverage of it, which is the most consequential lie a scanner can tell.

### 4. Every finding's execution outcome, by name

Each finding carries its outcome string verbatim. Render it, do not translate it
into a pass/fail column:

| Outcome | How it is written | Never write |
|---|---|---|
| `proven` | "Confirmed by execution — the target's own frame at `app/reports.py:7` interpreted the payload" + the attributed marker line | — |
| `sink_reached_unproven` | "The sink was reached with attacker data present; interpretation was not demonstrated. This is also what an effective defence looks like from the runtime" | "failed" |
| `self_attributed` | "The PoC reached the sink directly and did not exercise the target's path" | "false positive" |
| `nonce_mismatch` | "Runtime events could not be attributed to this PoC" | "no evidence" |
| `no_event` | "This PoC did not trigger the operation. Not a refutation — the sink may be reachable another way" | "not vulnerable" |
| `observer_absent` | "The observer never armed; the harness failed. This says nothing about the code" | anything about the code |
| `not_attempted` | "Execution was unavailable (static mode / missing toolchain). An environment limitation" | "unconfirmed", "failed" |
| `not_applicable` | "This class cannot be settled by running code; the finding rests on source analysis" — but say WHICH kind: either no execution could settle it (a policy question, e.g. IDOR) or PyHunt's observer has no event for it (e.g. SQL injection). `coverage.execution.not_provable_by_observer_reasons` tells you which, per class | "unproven" |

**`not_attempted` and `not_applicable` are honest results.** They are not
failures, they are not hidden, and they are not quietly folded into an
"unconfirmed" bucket. A reader must be able to tell a broken container from a
missing environment from a question execution cannot answer.

Alongside each finding, name the evidence class: **executed** (`proven`) or
**reasoned** (everything else). Never present a reasoned finding and an executed
one at the same visual weight without labelling which is which.

## Writing the findings

- **One entry per instance, not per root cause.** If the sweep found five sites
  of the same pattern and three survived the pipeline, the report has three
  entries with three IDs and three rows in the summary table. They may share a
  root-cause description and a fix strategy; they do not share a row.
- **Titles are specific and unexcited.** "Unauthenticated command injection in
  `POST /api/import` via the `filename` JSON field" — not "Critical RCE!".
- **Every finding carries a CWE**, the most specific one that applies (CWE-78
  for OS command injection, not CWE-74 for injection generally). Omit rather
  than guess.
- **Impact is the capability the attacker gains**, not a restatement of the
  class: what they read, write, execute, or reach. "A vulnerability must harm
  someone other than the attacker."
- **`exploit_scenario` is a short concrete narrative** for an attacker holding
  exactly the access the trace implies — not a generic kill chain.
- **`how_to_fix` names the function, the safer API, and the validation.** Not
  "validate user input".
- **`preconditions` is an array of what must hold** (auth level, feature flag,
  network position). Empty array when there are none — an empty array is a
  claim, so mean it.
- **Severity comes from the CVSS band Python computed** from phase 2c's vector.
  Where the trace shows reachability is narrower than the vector assumed (admin
  auth required, an internal-only route), say so in the description rather than
  quietly restating the score.
- **Be conservative, and do not pad.** If nothing in the run is worth staking a
  reputation on, deliver an empty findings array and let the coverage disclosure
  speak. A padded report costs the reader's trust in the whole document,
  including the parts that are right.

Findings whose outcome was `sink_reached_unproven` and which phase 2c did not
confirm belong in a separate **Defence in depth / code quality** section, each
with: the location, what the code does, which gate or defence downgraded it
(with the `file:line` you read), and what would have to change for it to become
exploitable. They do not get finding IDs.

Rejected candidates are not deleted — `verify/` records them. Summarise them as
a count with their rejection reasons available, so a reader can see the run
considered and dismissed them rather than never looking.

## Redaction

`redact.py` masks card data, PII and credential material over the fully rendered
text, at the write boundary, so it covers every field without enumerating them.

Treat it as the safety net, not the plan. **Do not quote a live secret you found
into your prose** — describe it ("a 40-character AWS secret key literal at
`config/settings.py:31`") and let the finding's evidence snippet carry the
location. A masked secret in a report is still a secret that travelled through a
model's context and a scratch file.

Marker lines from `proof/` are different: quote them **verbatim**. They are the
receipt a human uses to check the gate's arithmetic, and a paraphrased marker
line proves nothing.

## Fingerprints and suppression

Each finding carries a content-addressed fingerprint (normalised path, class,
CWE, entry point) from `scripts/fingerprint.py`, written onto its
`findings/<id>.json` record. It gives a finding a stable identity across runs so
a re-scan at a later commit can show what is new, what persists, and what was
fixed.

The fingerprint lives in run state, **not** in `report.json` — the report
schema has no per-finding `fingerprint` field. Do not write one into your
narrative; it is a schema error, not an ignored key.

**Do not suppress anything in this phase.** Suppression is the operator's
decision, made against a baseline they control; a scanner that hides a finding
because it saw it before will hide it forever.

## Model transparency

Print, in the header, the model each phase ran as, from `manifest.model_used`.
If phase 2c ran on the same model as phase 2, print that fact rather than
omitting it — the pin that used to enforce model diversity mechanically is gone,
and this line is the only thing that makes a same-model verification visible.

Print the over-claim tally from `logs/phase2b_overclaim.txt` (claimed vs proven
vs contradicted). A rising contradiction rate is how prompt drift is detected,
and it cannot be tracked if it is not reported.

## Report header

```markdown
# PyHunt Security Report

**Run ID**:          <basename of ${RESULTS_DIR}>
**Target**:          <repo path or URL>  @ <branch [short-sha]>
**Scan date**:       <YYYY-MM-DD>
**Mode**:            static | proof
**Isolation tier**:  vm  (separate kernel in a VM; proof mode permitted)
**Models**:          hunt=<…>  verify=<…>  report=<…>
**Findings**:        <N critical, N high, N medium, N low, N informational>
**Execution**:       <P> proven of <Q> provable by execution; <B> not provable by this observer; <R> not settleable by any execution; <T> total
**Coverage**:        <V> of <E> enumerated inputs covered; <U> uncovered (listed below)
```

## Before this phase is complete

- [ ] `report.json` and `report.md` exist and `report_build.py` exited 0 —
      which means `--markdown` and `--narrative` were both passed.
- [ ] `narrative_findings_with_prose` equals the number of delivered findings.
      A lower number means prose you wrote never reached the report; check
      `narrative_unmatched_finding_ids`.
- [ ] `narrative_computed_fields_supplied` is empty.
- [ ] Every delivered finding has a CWE, a location, an entry point, a data
      flow, a concrete impact, and its execution outcome by name.
- [ ] The isolation tier printed is the tier `manifest.json` records.
- [ ] Proven, provable, not-provable-by-this-observer and total appear as four
      separate numbers, and the fourth is described as a limit of PyHunt's
      observer rather than as a property of those findings.
- [ ] The uncovered-input list is present, with reasons — or the report says
      explicitly that every enumerated input was covered.
- [ ] No sentence implies exhaustiveness while `coverage_complete` is false or
      `catchall_dropped > 0`.
- [ ] No `not_attempted` or `not_applicable` finding is rendered as a failure,
      and none is omitted.
- [ ] No finding present in `findings/` is missing from the report without a
      recorded disposition (delivered, rejected in 2c, or downgraded to code
      quality).
- [ ] `manifest.json` has `phase4_report` appended to `phases_completed`.

Then hand the user the summary, the path to `report.md`, and — in one sentence —
the strongest honest claim the run supports. If that sentence is "nothing was
proven, and here is what was not examined", say that.
