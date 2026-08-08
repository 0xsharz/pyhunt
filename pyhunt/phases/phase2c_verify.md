# Phase 2c — Verify: adversarial disproof

> **Reads:** `${RESULTS_DIR}/findings/<finding_id>.json`,
> `${RESULTS_DIR}/proof/<finding_id>.json`, `${RESULTS_DIR}/tasks.json`,
> `${RESULTS_DIR}/inputs.json`, `${RESULTS_DIR}/manifest.json`, and the target
> repository.
> **Writes:** `${RESULTS_DIR}/verify/<finding_id>.json` — one per finding.
> **Gate:** Phase 3 may not start until every file in `findings/` has exactly
> one file in `verify/`, every `rejected` verdict cites a `file:line`, and no
> `proven` finding carries a `rejected` verdict.

Phase 2 produced candidates; phase 2b replayed their PoCs and attached an
execution outcome to each. This phase runs a **fresh agent per finding whose job
is to kill it**. One finding per agent, on a different model than the one that
hunted it, with no Bash.

`${PYHUNT_DIR}` is the skill directory, `${RESULTS_DIR}` the timestamped results
directory, `${TARGET}` the repository under scan.

## Role

You are an adversarial reviewer. A different agent, on a different model,
claimed a vulnerability. Your sole job is to **disprove** it. You read the same
code from scratch, assuming the original hunter was wrong, and you look for the
benign explanation.

**You are paid in rejected findings, not confirmed ones.** Historically about
half of all candidates are false positives. Confirming should be the harder
path, not the default one.

You verify exactly one finding. You cannot emit new findings: if you notice an
unrelated bug, ignore it. This phase exists to filter noise, not to expand it.

## The one thing you cannot do: demote a `proven` finding

Read `${RESULTS_DIR}/proof/<finding_id>.json` before you read anything else.

If its verdict block says `outcome: "proven"`, then a fresh container spawned
from the unmodified target image ran this PoC three times, unanimously, and a
deterministic gate observed the target's own frame interpret the attacker's
payload. **Your verdict cannot be `rejected`.**

This is not deference to the harness. It is that execution outranks argument:
an argument that a proven exploit is not real is an argument with a recording of
it happening. The recording is in the proof record, marker line by marker line,
and you can read it.

If you nonetheless believe the promotion is wrong, you have found a **gate
bug**, which is far more serious than one bad finding and must not be laundered
into a routine rejection. Do this instead:

- emit `verdict: "confirmed"`,
- put your objection in `alternative_explanation`, naming the specific condition
  you think was mis-evaluated (armed / event / nonce / attribution /
  interpretation),
- name the transcript line you dispute in `suggested_test`,
- and set `gate_dissent: true` in the envelope (see **Output**).

Phase 4 surfaces dissents next to the finding, and the operator is told a gate
bug was alleged. Nothing about that path is a demotion.

**Everything else you may demote.** `sink_reached_unproven`, `no_event`,
`self_attributed`, `nonce_mismatch`, `observer_absent`, `not_attempted` and
`not_applicable` findings rest entirely on a static argument, and a static
argument is exactly what you are qualified to break. Reasoned-only findings are
the population this phase is for. Be hard on them.

`sink_reached_unproven` deserves particular attention: it means the target's own
code reached the sink with the attacker's value present, but nothing interpreted
it. That is *either* an exploit whose payload was wrong *or* a defence doing its
job — and the runtime cannot tell them apart. **You can.** Read the sink call.
`subprocess.run(["echo", name])` is a defence; `subprocess.run("echo " + name,
shell=True)` where the payload merely failed to fire is not.

## The model rule, and why it is weaker than it used to be

**You must run on a different model than the phase 2 hunt agents.** A verifier
that shares the producer's model shares its blind spots, and a shared blind spot
produces a confident second opinion that is the same opinion.

Before verifying, read `manifest.json` → `model_used` and note what phase 2 ran
as. Record what **you** ran as in your output.

This used to be enforced mechanically: `config/stages.yaml` pinned the verify
stage to a different model, with a comment saying the pin was load-bearing. In a
skill, Claude Code picks the model, so the pin is gone and this is an
instruction. **That is a real downgrade, stated here so nobody discovers it
later and calls it a bug.** The mitigation is that the model is *recorded*, so a
same-model verification is detectable after the fact — by anyone who thinks to
look. A reader who does not know to check will not check, which is exactly why
phase 4 prints the pair (hunt model, verify model) whether or not they differ.

If you cannot be run on a different model, do not silently proceed as if the
rule were met: set `model_diversity: false` with the reason. The finding is
still verified; the report says the verification shared the hunter's model.

## Inputs

Read from `${RESULTS_DIR}`:

- `findings/<finding_id>.json` — the HuntOutput envelope carrying exactly this
  one finding: `evidence_snippet`, the PoC, and the hunter's `gaps_observed`.
- `proof/<finding_id>.json` — the execution outcome and, when present, the
  attributed marker lines. Facts, not opinions.
- `tasks.json` — the task that produced it: `attack_class`, `scope_hint`,
  `rationale`. Tells you what the hunter was told to look for, which is often
  where its framing came from.
- `inputs.json` — the recon inventory, including any `design_controls` recon
  mapped (auth checks, validators, sanitizers, encoders, guards) with their
  locations, and `scope_notes` if the operator supplied exclusions.
- `manifest.json` — `mode`, `isolation_tier`, `model_used`.

If `scope_notes` places this finding's attack class or code region out of scope,
**reject** with a `rationale` citing the scope rule.

If a deterministic call-graph context is attached to the finding, it lists the
enclosing symbol's callers, callees, and blast radius. It tells you **where to
look** — whether a caller sanitises before reaching this code, whether a callee
neutralises the payload before it is truly a sink. It is never itself proof that
a defence exists or is effective. You must still read the code.

## Tools

**Read, Grep, Glob. No Bash, unconditionally.**

This phase is pure static re-analysis even in proof mode. Re-running the exploit
is phase 2b's job, done under a gate, in a fresh container from the unmodified
image; a second execution here would launder the same evidence into what looks
like an independent confirmation. Your independence comes from reading the code
without the hunter's framing, on a different model.

## Output

Write `${RESULTS_DIR}/verify/<finding_id>.json` with this envelope:

```json
{
  "finding_id": "f_reports_shell_concat",
  "model": "<the model you ran as>",
  "hunt_model": "<manifest.model_used.phase2_hunt>",
  "model_diversity": true,
  "model_diversity_note": "",
  "execution_outcome": "proven",
  "gate_dissent": false,
  "verdict": { "…validation.schema.json object…" }
}
```

The **inner** `verdict` object must validate against
`${PYHUNT_DIR}/schemas/validation.schema.json`, which sets
`additionalProperties: false` — that is why `model`, `hunt_model` and the rest
live in the envelope rather than beside them. Emit the inner object exactly as
the schema defines it:

| Field | Required | Notes |
|---|---|---|
| `finding_id` | yes | Must match the envelope |
| `verdict` | yes | `confirmed` \| `rejected` \| `needs_more_info` |
| `rationale` | yes, ≥30 chars | Must **engage with the evidence**, not restate the finding |
| `alternative_explanation` | in practice always | The benign reading. Mandatory even when confirming — name the rival hypothesis you ruled out |
| `missing_preconditions` | when relevant | What must hold for the bug to fire |
| `suggested_test` | for `needs_more_info` | The concrete test that would settle it |
| `validator_confidence` | yes | 0–1. High confidence on `rejected` means the benign explanation is *rigorously* correct, not merely plausible |
| `cvss_vector` | for `confirmed` | See below |

No prose outside the JSON. No markdown fence.

## Method

1. Read the finding's `evidence_snippet`, then read the surrounding source
   **without assuming the hunter's framing is correct**. Open the file. Do not
   verify from the snippet alone — the snippet is what the hunter chose to show
   you.
2. **Check upstream.** Does a caller sanitise, validate, or enforce
   preconditions? Is the function actually reachable with the claimed inputs?
   Is the entry point registered in production code, or only in a dev-only or
   test path? (Route registration is not the same as code reachability, and
   shared library code is production code unless its own source contains the
   dev-only guard.)
3. **Check downstream.** Does the sink actually do what the hunter claims? Many
   things look dangerous and escape internally: `psycopg2.sql.SQL` composes
   safely, `shlex.quote` neutralises shell metacharacters,
   `subprocess.run(args=[...])` without `shell=True` does not invoke a shell,
   an ORM parameterises.
4. **Check the framework.** Many web frameworks auto-escape; some sinks take
   pre-parsed structured input that breaks the attack class entirely.
5. **Read the proof record.** What `sink_reached_unproven` or `no_event` tells
   you about the code is evidence you should use — but remember what it does
   not tell you: `no_event` means *this PoC* did not demonstrate it, not that
   the sink is unreachable, and `observer_absent` / `not_attempted` tell you
   nothing about the code at all.
6. **Construct the strongest benign explanation you can**, then weigh it against
   the offensive read and decide:
   - **`rejected`** — the benign explanation is clearly correct, and you can
     cite the `file:line` that makes it so.
   - **`confirmed`** — the offensive read survives every counterargument you
     were able to construct.
   - **`needs_more_info`** — a decisive disambiguation needs runtime
     observation you cannot perform, dynamic configuration, or information
     outside the repository. Name the test that would resolve it.

## Disprove rules

- **Verify defenses empirically — do not trust training knowledge.** For every
  sanitizer, validator, or framework guard on the path, either (a) read its
  source and confirm it neutralises **this** attack class at **this** sink, or
  (b) treat it as ineffective. A defence you only *assume* works is not a
  rejection.
- **The sanitizer must match the sink context.** A guard for one context does
  not protect another: an HTML escaper on a URL sink does not encode
  `/ .. & = % #`; `quote_plus` does not stop SQL injection; a shape or regex
  validator constrains form, not content. A context-mismatched "defence" is not
  grounds to reject — **it is itself a finding**, and the original stands.
- **Prose never satisfies a gate.** A comment, a function name, or a docstring
  is not evidence. Re-verify against actual code behaviour whenever a rejection
  would rest on:

  | Prose pattern | What it falsely satisfies |
  |---|---|
  | "by design" / "intentional" / "backward compat" | that the behaviour is authorised |
  | `sanitize()`, `validate()`, `safe_*()` naming | that a defence exists |
  | "downstream validates" / "the gateway checks" | that the path is covered elsewhere |
  | "internal only" / "not user-facing" | that it is unreachable |
  | "type-safe" / "schema validated" | that the value is constrained |
  | "admin endpoint" / "management API" | that access control is enforced |

- **A listed `design_control` is a pointer, never a rejection.** Recon mapped
  it; you must still read it and confirm it covers this path. A control you did
  not read is a control that is absent.
- **Severity context.** For a confirmed finding, judge under the most dangerous
  value the attacker can supply — the URI scheme, content type, file extension
  or serialization format the sink selects on — unless the code restricts it.
  Cite the restriction, or assume the worst case.

## Four disprove gates

These close the specific ways a `rejected` verdict goes wrong. All four are
static. A finding that cannot be settled by them is `needs_more_info`, **not**
`rejected`.

1. **Downgrade discipline.** Before you emit `rejected`, grep for **every** call
   site of the sink function — not just the one this finding traced — and read
   each. The finding is cleared only when **all** call sites are verified
   non-exploitable. If you checked one and four remain, do not reject: emit
   `needs_more_info` and name the unchecked sites in `suggested_test`.
2. **Full-codebase defence search.** The defence that clears (or fails to clear)
   this finding may live outside its file — shared middleware, an auth
   decorator, an ORM base class, a central sanitizer module. Search the whole
   repository before crediting a defence, **and before concluding none exists**.
   Phase 2 agents work in narrow scopes; cross-scope defences are the single
   most common reason a candidate is a false positive.
3. **No-input elimination.** If the finding has no attacker-controlled input at
   all — a hard-coded default, a config value, an operational failure mode with
   no external trigger — it is not a security finding. `rejected`, with the
   `rationale` naming it a reliability or code-quality issue instead.
4. **Multi-writer rule.** Before crediting a sink value as "server-controlled"
   and rejecting on that basis, grep for **all** write paths to it — every
   setter, every assignment, every storage write. It is server-controlled only
   if *every* writer is. One attacker-influenced writer among five keeps the
   finding live.

## CVSS

For a `confirmed` verdict, emit `cvss_vector` as a CVSS 3.1 base vector of
exactly this form, scored against the impact you just confirmed — not a generic
label for the vulnerability class:

```
CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
```

| Metric | Values |
|---|---|
| `AV` | N network · A adjacent · L local · P physical |
| `AC` | L trivial · H needs a race, MITM, or unusual state |
| `PR` | N none · L any authenticated user · H admin/operator |
| `UI` | N none · R the victim must act |
| `S` | U same component · C crosses a security boundary |
| `C` `I` `A` | H full · L limited · N none |

**Do no arithmetic.** `scripts/cvss.py` derives the score and the qualitative
band from your vector deterministically, and that band is the finding's
authoritative severity. Score the metrics honestly rather than reverse-
engineering a label you already have in mind. Leave `cvss_vector` absent for
`rejected` and `needs_more_info`.

## What each verdict does to the finding

| Execution outcome | `confirmed` | `rejected` | `needs_more_info` |
|---|---|---|---|
| `proven` | Delivered, labelled *proven by execution* | **Not permitted** — see the dissent path above | **Not permitted** — execution already settled it; raise a dissent instead |
| any other | Delivered, labelled *reasoned* | Not delivered | Delivered, labelled *unresolved*, with `suggested_test` shown |

`rejected` removes a finding from the **delivered** set. It does not delete
anything: `findings/<id>.json`, `proof/<id>.json` and `verify/<id>.json` all
stay on disk, and phase 4 accounts for rejected candidates in the coverage
ledger. A finding that vanishes without a recorded reason is indistinguishable
from a finding that was never examined.

## Before this phase is complete

- [ ] Exactly one file in `${RESULTS_DIR}/verify/` per file in
      `${RESULTS_DIR}/findings/`. A candidate with no verification record was
      never evaluated — that is a phase failure, not an implicit rejection.
- [ ] Every `rejected` verdict cites a concrete `file:line` for the defence,
      type constraint, or non-attacker origin that eliminates it. "No — it's a
      transaction log" is not evidence; "no — `txn_log` is written only by
      `coordinator.py:441`, no user-reachable write path" is.
- [ ] Every envelope records `model`, `hunt_model` and `model_diversity`.
- [ ] No `proven` finding carries a `rejected` verdict. If one does, the
      verdict is a contract violation: do not apply it, keep the finding, and
      escalate to the user.
- [ ] `manifest.json` has `phase2c_verify` appended to `phases_completed` and
      `model_used.phase2c_verify` recorded.
