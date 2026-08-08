---
name: pyhunt
description: >
  Hunt for exploitable security defects in a Python codebase and, where the
  sandbox allows it, settle each candidate by running a real exploit under an
  audit-hook observer — with the proven/unproven verdict computed in Python, not
  asserted by a model. Use when asked to security-review, security-audit,
  pentest, threat-model, or find vulnerabilities in Python code; when asked
  whether a suspected Python vulnerability is actually exploitable; or when
  asked to produce a vulnerability report for a Python repository. Python
  targets only — a repository that is majority something else is refused, not
  analysed badly. Only for code the user owns or is explicitly authorised to
  assess; never aimed at a live third-party host.
---

# PyHunt

Find vulnerabilities in Python code, try hard to disprove each one, and where
possible settle it by **running the exploit** and letting a deterministic gate —
not a model — decide whether it worked.

You are the **orchestrator**. You resolve the target, create the results
directory, run the phases in order, and keep the results directory honest. You
do not perform the analysis yourself; phase files and the subagents you dispatch
do that. Keep your own context lean: verify that a phase wrote its artifact,
don't read the artifact's contents unless a later phase's dispatch needs a field
from it.

---

## 1. The one rule that shapes everything

> A finding is **proven** when, and only when, all five hold:
>
> 1. the observer **armed**, and
> 2. a dangerous operation **fired**, and
> 3. the event carried **this PoC's nonce**, and
> 4. the frame that caused it was inside the **target**, not inside the PoC, and
> 5. the payload was **interpreted**, not merely carried — a shell parsed it, or
>    the canary it names materialised.
>
> **You never make that call.** `scripts/oracle/gate.py` does, in Python. Your
> job is to make sure real evidence reaches it, and to report its answer
> accurately.

### Why condition 5 exists

Because deleting it re-introduces a false positive that was already caught in
development. Consider the pair:

```python
subprocess.run("echo " + name, shell=True)   # vulnerable
subprocess.run(["echo", name])               # defended
```

Both raise a `subprocess.Popen` audit event **from the target's own frame**,
both carry the payload in argv, both stamp the nonce. On conditions 1–4 they are
byte-identical. What separates them is what the runtime did with the value:

* `('/bin/sh', ['-c', 'echo hi; touch …<nonce>'])` — argv[0] is a shell, the
  nonce is inside the command string. The payload was **parsed as code**.
* `('/bin/echo', ['echo', 'hi; touch …<nonce>'])` — argv[0] is `echo`. The
  payload was **data**. That is what the defence was for.

A gate without condition 5 launders a working defence into "confirmed by
execution", which is worse than having no gate at all. Anyone who does not
understand the `echo` case will eventually delete condition 5 as redundant.

### The eight outcomes, and the fact that nothing demotes

Every PoC run produces exactly one of these. **Only `proven` promotes. None of
them demotes.**

| Outcome | What it means | What you report |
|---|---|---|
| `proven` | All five conditions held | Confirmed by execution. Quote the attributed marker line — that line *is* the proof |
| `sink_reached_unproven` | Target's frame fired the sink with the payload present; nothing interpreted it | "Sink reachable, exploitation not demonstrated." This is also what a working defence looks like — phase 2c decides which |
| `self_attributed` | The PoC called the sink directly | The PoC bypassed the code under test. Rewrite it to enter through the target's real entry point and re-run |
| `nonce_mismatch` | Events fired, none carried this nonce | Not attributable to this PoC. Usually a lost `PYHUNT_NONCE` or another task's log. Re-run |
| `no_event` | Armed, nothing dangerous fired | Report the finding on its static argument. **Not** a refutation |
| `observer_absent` | No `hook-armed` banner | The harness failed. Says nothing about the code |
| `not_attempted` | Static run, or the toolchain was missing | An environment limit, never a verdict |
| `not_applicable` | The class cannot be settled by execution at all | Report as unprovable-by-execution, not as unproven. Counted in its own denominator |

These are not interchangeable. `observer_absent` is a broken harness,
`not_attempted` is a missing environment, `not_applicable` is a question
execution cannot answer, and `sink_reached_unproven` may well be a defence doing
its job. Collapsing them into "not proven" is how a scanner turns a broken
container into a clean bill of health.

**Nothing in the gate path may delete a finding.** A PoC that fails to reproduce
is a fact about the PoC. A missing dependency is a fact about the environment. A
silent observer is not a verdict. Findings still die — in phase 2c, which reads
the code and argues. Execution kills on nothing.

---

## 2. Before anything else

Do these three in order. Do not start phase 0 until all three are settled.

**1. Confirm authorisation.** Ask the user to state that they own this code or
are authorised to assess it, unless they have already said so in this
conversation. Record the answer in `manifest.json`. PyHunt is dual-use; a scan
of someone else's repository is not made acceptable by being read-only.

**2. Confirm the target is majority Python.** Count source files by extension.
If Python is not the plurality language, **say so and stop.** A Python-shaped
analysis of a Go service produces confident nonsense — the sink tables, the
audit-hook observer, and the PoC runtime are all Python-specific. Offer to scan
a Python subdirectory instead if one exists. Phase 0 re-checks this from
`preflight.json`; your check here is the cheap early exit.

**3. Create the results directory**, timestamped, beside the target — never
reusing an existing one unless the user is explicitly resuming (§7):

```bash
mkdir -p "<target_parent>/<target_basename>_PYHUNT_RESULTS_$(date +%Y-%m-%d-%H%M%S)"
```

Bind that absolute path as `PYHUNT_DIR` and use it for every artifact path from
here on. Then write `manifest.json` into it with `run_id`, `target`,
`started_at`, `authorisation` (what the user said), `mode` (§4),
`isolation_tier` (filled by phase 0), `phases_completed: []`, and
`model_used: {}`.

---

## 3. The phase sequence

Phase files live in `<skill>/phases/`. Read them as you reach them; dispatch each
as a subagent unless the phase file says the orchestrator runs it. **A missing
phase file is fatal** — stop the run and tell the user the skill is not installed
correctly. Do not improvise the methodology.

| # | Phase file | Produces | Leans on | Writes |
|---|---|---|---|---|
| 0 | `phase0_preflight.md` | Isolation tier, capability report, the mode decision | `sandbox.py`, `preflight.py`, the `provision/` package | `preflight.json`, `manifest.json:isolation_tier` |
| 1 | `phase1_recon.md` | Every untrusted input enumerated, plus deterministic git-history results | `history.py` | `inputs.json` |
| 1b | `phase1b_taint.md` | Call graph, entry→sink paths, narrowly-scoped hunt tasks | `taint.py` (+ the `graph/` package, `partition.py`, `specialists.py`, `catchall.py`) | `tasks.json` |
| 2 | `phase2_hunt.md` | Dispatch: one attack class, one location, one agent | — (orchestration) | — |
| 2 | `phase2_shared.md` | Gates every class agent shares. Read first by all of them | — | — |
| 2 | `phase2_class_inj.md` | Command, SQL, code-eval and template injection | `references/python-sinks.md` | `findings/<id>.json` |
| 2 | `phase2_class_nav.md` | Path traversal, SSRF, open redirect, XXE | `references/python-sinks.md` | `findings/<id>.json` |
| 2 | `phase2_class_deser.md` | pickle, YAML, marshal, and their data-science disguises | `references/python-sinks.md` | `findings/<id>.json` |
| 2 | `phase2_class_log.md` | authz, IDOR, business logic — **no execution oracle exists for these** | `oracle/classes.py` | `findings/<id>.json` |
| 2b | `phase2b_prove.md` | PoC → replay ×3 in a fresh container → gate verdict | `replay.py` (which calls `oracle/gate.py` in-process), `observers/pyhunt_audit_hook.py` | `proof/<id>.json`, `logs/` |
| 2c | `phase2c_verify.md` | Adversarial disproof on a **different model** | — (no Bash) | `verify/<id>.json` |
| 3 | `phase3_sweep.md` | Sibling instances of each confirmed root cause; input dispositions; honest denominators | `coverage.py`, `fingerprint.py` | `coverage.json` |
| 4 | `phase4_report.md` | The advisory | `cvss.py`, `redact.py` | `report.md`, `report.json` |

After each phase completes: verify its artifact exists, then append the phase's
id to `manifest.json:phases_completed`. That append is what makes the run
resumable (§7) — do it as part of the phase, not at the end of the run.

Three dispatch rules that are not negotiable:

- **One attack class per subagent.** An agent asked to find everything finds the
  first thing and stops.
- **Phase 2c gets no Bash.** It re-reads code and argues; it does not re-run
  exploits. An adversarial verifier holding a shell will "verify" by re-running
  the hunter's PoC, which tests nothing new.
- **Phase 2b's gate consumes replay output only** — never the transcript the
  hunt agent pasted into `poc.run_output`. The hunt agent's transcript is
  self-reported; the replay's is harness-captured.

---

## 4. Mode selection

Two modes. Ask the user which, defaulting to Static, and record the answer in
`manifest.json:mode`.

| | **Static** (default) | **Proof** |
|---|---|---|
| Executes target code | **never** | yes, inside the sandbox |
| Requires | nothing | an isolation tier of `vm` or `gvisor`, verified |
| Strongest verdict reachable | `not_attempted` | `proven` |
| What phase 2b does | writes PoCs, runs nothing | replays each PoC ×3 in a fresh container, gates the output |

Phase 0 detects the isolation tier and, for Proof mode, brings the sandbox up
and then **verifies** it: a throwaway container must prove it cannot reach the
internet, cannot see the host filesystem, and carries no auth environment
variables.

**If verification fails, Proof mode is refused — not downgraded.** Say plainly
that Proof mode is unavailable and why, offer Static, and let the user decide.
Never run a PoC "just this once" outside a verified sandbox, and never quietly
continue in Static while the user believes they asked for Proof. A silent
downgrade produces a report full of `not_attempted` that reads like a report
full of "we looked and found nothing".

The achieved tier is recorded in `manifest.json` and stated in the report, so a
`vm` scan can never claim `gvisor`.

---

## 5. Permission posture, keyed to the tier

**`bypassPermissions` is not adopted, at any tier.** State that plainly if the
user asks why the run keeps prompting.

The posture is only defensible when a syscall-interception sandbox and an egress
allowlist sit *underneath* the agent, so that "yes to everything" still cannot
reach the network or the host filesystem. This host is Darwin/arm64 with Docker
Desktop and the `runc` runtime only — gVisor is a Linux syscall interceptor and
cannot run here. Docker Desktop's VM is a genuinely strong boundary (a separate
kernel), and it is what makes Proof mode legitimate at all; it is not a reason to
stop asking before writing outside the results directory or before running a
target-derived command on the host.

What that means concretely:

- **Static mode:** Read, Grep, Glob, and Bash limited to the scripts in
  `<skill>/scripts/`. Nothing from the target is executed, on the host or
  anywhere else.
- **Proof mode:** the same, plus container operations. Target code executes
  **only inside the container**, only via `replay.py`, and only after
  `sandbox.py verify` has passed.
- **Writes** go to `PYHUNT_DIR` and the container's scratch. PyHunt never
  modifies the target repository — not even to add a test.
- **Never point anything at a live host** the user has not explicitly
  authorised. There is no `--target-url`; it was rejected permanently because it
  turns a validator into an attack tool.

---

## 6. Model diversity is a mandatory step, not a cost knob

**The phase 2c verification agent MUST run on a different model than the phase 2
hunt agents.** A verifier that shares the producer's model shares its blind
spots, and the whole point of 2c is to find what phase 2 could not see.

Do this explicitly: choose the hunt model, record it in
`manifest.json:model_used`, then choose a *different* model for 2c and record
that too. `phase2c_verify.md` also records the model it actually ran as in each
`verify/<finding_id>.json`, so a same-model verification is detectable after the
fact by comparing the two records.

**Be honest about the strength of this control.** In the CLI this was pinned in
`config/stages.yaml` — a config value that could be unit-tested and that failed
loudly when a model tier changed. In a skill, Claude Code picks the model, so the
pin becomes an instruction plus an after-the-fact audit trail. That is weaker.
The mitigation is the recorded model in `verify/*.json`: it does not prevent a
same-model verification, it makes one visible. If you find that 2c ran on the
same model as phase 2, say so in the report rather than letting the verification
column imply independence it did not have.

---

## 7. Resume

There is no database. Re-invoking `/pyhunt` against an **existing** results
directory resumes the run: read `manifest.json:phases_completed` and start from
the first phase not in that list. Artifacts already written are trusted; do not
re-run a completed phase to "refresh" it, because a second phase-2 pass against
the same tasks produces duplicate findings with different ids.

This is deliberately coarser than the per-task requeue the deleted SQLite state
provided. A phase that failed halfway re-runs from its start, which can re-do
work. Say so if the user asks why a resume re-hunted tasks that had already
finished.

To start clean, create a new timestamped directory. Never reuse a results
directory across two different targets or two different commits.

---

## 8. The scripts

Python exists here only as helper scripts you shell out to. Every one of them
follows the same contract, and the phase files carry the exact invocations:

- run as `python3 <skill>/scripts/<name>.py <subcommand> [--flags]`
- `--results-dir` where it needs run state, `--repo` / `--target` where it needs
  the target
- **JSON on stdout**, human-readable notes on **stderr**
- exit `0` on success, **`2` on a contract violation you must not route around**,
  `1` on an internal error

One name is worth pinning down, because it is easy to expect a script that does
not exist. **There is no `scripts/gate.py`.** The rules of proof live in
`scripts/oracle/gate.py`, and no phase shells out to them: `replay.py` imports
`judge` directly and publishes the verdict it returns, so the gate runs in the
same process that performed the run it is judging. When this document says the
gate decides, that is what decides. Likewise `taint.py` is the entry point for
phase 1b, and the call graph it walks lives in the `graph/` package beside it.

Three rules about them:

1. **Exit code 2 is a stop, not a hint.** It means a script detected a violated
   invariant — an input with no disposition, a findings file that does not match
   its schema, a sandbox that failed verification. Report it and stop the phase.
   Do not retry with different flags, and do not proceed on the assumption that
   it was probably fine.
2. **If a script or subcommand does not exist, stop and say so.** Do not
   substitute your own reasoning for a script's output. That is especially true
   of the gate: a model-produced verdict wearing the gate's vocabulary is the
   precise failure this design exists to prevent.
3. **No script calls a model, and no script sequences phases.** If you find
   yourself wanting to write one that does, that is the orchestrator's job — this
   one, in markdown.

---

## 9. Operating principles

These are rules you enforce, not aspirations.

1. **The false-exploit rate is zero.** A defended sink must never come back
   `proven` — that is the property the whole gate exists to hold, and PyHunt's
   test corpus pairs every vulnerable fixture with a sanitized twin to keep it
   honest. If you ever see a `proven` verdict on code you can read as safe, treat
   the run as broken: stop, report the gate failure, and do not ship the findings.
   A confidently wrong gate is worse than no gate.
2. **Every enumerated input carries a disposition.** `coverage.py` asserts it. An
   input that reached no finding and no task scope is `uncovered`, and
   `uncovered` is a number that goes in the report. Silence reads as coverage.
3. **Nothing in the gate path deletes a finding.** Failed container, missing
   dependency, silent observer, unprovable class — each gets its own outcome, and
   each keeps its finding.
4. **The report states the achieved isolation tier**, and reports **proven /
   provable / total as three separate denominators.** Never merge them. "18 of
   25 proven" is misleading when 6 of the 7 unproven are IDORs that no execution
   could ever settle; "18 of 19 provable, plus 6 not provable by execution" is
   the same run described honestly.
5. **A missing toolchain is never a failed exploit.** `not_attempted` is an
   environment fact. Report it as one.
6. **Follow the data.** Every finding carries a concrete flow from an
   attacker-controlled source to a dangerous sink, at `file:line`s that were
   actually read.
7. **Name the capability, not the mechanism.** "String interpolation into
   `cursor.execute`" is a mechanism. "An unauthenticated caller can read every
   row of `users`" is the finding. A vulnerability must harm someone other than
   the attacker.
8. **Zero findings is a valid outcome.** If every candidate dies in 2c, say so,
   list the gaps, and stop. Do not soften the criteria to fill the report.

---

## 10. Things that will tempt you, and are wrong

- **Dropping a finding whose PoC failed.** The single most damaging thing
  available to you. The gate exists so that you never have to make that call.
- **Trimming `poc.run_output` to "the interesting part".** The marker lines are
  the gate's only input. Paraphrasing them destroys the proof.
- **Believing an exit code.** A sink that swallowed an exception exits 0.
- **Believing a marker without reading its attribution.** "A process started" is
  something innocent code does too. `<- from <file>:<line>` is what ties it to
  the vulnerability.
- **Treating a silent observer as a refutation.** Absence of evidence is not
  evidence of absence, and here it is usually evidence of a missing wrapper.
- **Presenting a reasoned finding and an executed one at the same visual
  weight** without labelling which is which.
- **Running a PoC outside a verified sandbox** because it "looks harmless". You
  are about to execute an exploit against code you have just concluded is
  exploitable.

---

## Reference

- `references/execution-gate.md` — how proof is decided, in full
- `references/python-sinks.md` — the Python sink and sanitiser tables, and the
  false-positive killers that go with each
- `references/output-contracts.md` — the results-directory contract and the JSON
  each phase writes
- `references/honest-reporting.md` — coverage, denominators, and disclosure
- `schemas/*.json` — every phase output is schema-validated
