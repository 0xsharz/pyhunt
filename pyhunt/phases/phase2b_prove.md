# Phase 2b — Prove: replay in a fresh container, then the gate

> **Reads:** `${RESULTS_DIR}/findings/*.json`, `${RESULTS_DIR}/manifest.json`.
> **Writes:** `${RESULTS_DIR}/proof/<finding_id>.json` — one per finding,
> written by `replay.py`, never by hand — plus
> `${RESULTS_DIR}/logs/phase2b_overclaim.txt`, plus the `execution` block of
> each finding, written **only** by `findings_io.py apply-proofs`.
> **Gate:** Phase 2c may not start until every file in `findings/` has exactly
> one file in `proof/` carrying one of the eight outcome strings, **and
> `apply-proofs` has run.** No finding may be deleted or renamed by this phase,
> and no field of one may be edited except `execution`.

Phase 2 wrote one file per candidate into
`${RESULTS_DIR}/findings/<finding_id>.json` — a HuntOutput envelope carrying
exactly that one finding, with the PoC its hunt agent authored and that agent's
account of running it. This phase decides which
of those PoCs actually **proved** something. The decision is made by
`scripts/oracle/gate.py`, in Python, from a run the harness performed itself.

`${PYHUNT_DIR}` is the skill directory, `${RESULTS_DIR}` the timestamped results
directory, `${TARGET}` the repository under scan. Where a flag below does not
match, run the script with `--help`: **the script is authoritative, and a
non-zero exit is never routed around.**

## You are not the judge

This is the phase where PyHunt's zero-false-positive claim is either earned or
quietly lost, so read this section before running anything.

You do not decide whether a PoC worked. You do not read a transcript and
conclude "the exploit succeeded". You do not upgrade a finding because its
output looks convincing, and you do not downgrade one because it does not.
Your entire job here is:

1. call `replay.py` once per finding,
2. check that every finding came back with exactly one proof record,
3. run `findings_io.py apply-proofs` so those records reach the findings,
4. carry the outcomes forward verbatim.

A model in this loop is the failure mode the gate exists to remove. Every
scanner in this lineage instructed its agent to "DROP findings that don't
reproduce"; a prompt cannot be unit-tested, does not fail loudly when the model
tier changes, and cannot tell "the exploit worked" from "the exploit looked like
it worked". `scripts/oracle/gate.py` can, it is a pure function of its inputs,
and `tests/test_oracle_gate.py` is its specification.

## The trust boundary is the image tag

**Only the PoC crosses from the hunt agent to this harness.** Nothing else the
hunt agent produced about its own run is trusted — not its transcript, not
`poc.succeeded`, not its notes, not its description of what it saw. The harness
re-runs the PoC itself, in a **fresh container spawned from the unmodified
target image**, and the gate reads *that* run.

Two independent reasons, and both have bitten real harnesses:

- **The hunt agent's container is contaminated by the hunt agent.** It has been
  writing files, installing packages, possibly editing the target to "make the
  PoC work". A payload that only fires against a mutated tree proves nothing
  about the repository under scan. Spawning from the image tag — not from the
  agent's container, not from a snapshot of it — is what makes the target the
  target.
- **A transcript is a claim, and claims are the thing being replaced.** The
  hunt agent authored the payload, ran it, and reported the result; letting it
  also supply the evidence closes the loop on itself. Marker lines pasted into
  a finding are text a model produced. Marker lines captured by the harness
  from a process it started are an observation.

Concretely: `poc.run_output` in `findings/<id>.json` is retained for the record
and for the over-claim counter. **It is never the gate's input.** The gate's
input is what `replay.py` captured.

## Three preconditions, and none of them is a demotion

Check these before spending a container.

**1. Static mode.** If `manifest.json` records `mode: "static"`, or the phase 0
isolation tier was below `vm` and proof mode was refused, nothing executes.
Every finding is recorded `not_attempted`. Write the proof records anyway —
absence of a record is indistinguishable from a lost one.

> `not_attempted` means *the environment could not attempt this*. It is a fact
> about the harness, not about the code. **This is not a demotion.** A finding
> marked `not_attempted` stands exactly as the static analysis left it, and the
> report says so in those words.

**2. Classes execution cannot settle.** `scripts/oracle/classes.py` holds
`UNDECIDABLE_BY_EXECUTION`: access control, authorization, IDOR, privilege
escalation, business logic, insecure design, mass assignment, information
disclosure, CSRF, rate limiting, weak crypto, hardcoded secrets. These skip
replay entirely and are recorded `not_applicable`.

Execution answers *"did this behaviour occur?"*. It cannot answer *"was this
behaviour allowed?"* — that needs the intended policy, which does not exist in
the runtime. A PoC can show user A reading user B's record and still not
establish that doing so is wrong.

> **This is not a demotion either.** `not_applicable` findings are excluded from
> the *provable* denominator in phase 4, so the proven ratio stays honest.
> "18 of 25 proven" is misleading when 6 of the 7 unproven are IDORs; "18 of 19
> provable, plus 6 not provable by execution" is the same run described
> truthfully.

**3. A finding with no PoC.** Phase 2 sets `needs_poc: true` when execution was
unavailable to it. That is also `not_attempted`. It is never `no_event` — the
observer never ran, so there was nothing to observe.

## The procedure

One finding at a time, in `finding_id` order so a resumed run is deterministic:

```bash
python3 "${PYHUNT_DIR}/scripts/replay.py" run \
  --results-dir "${RESULTS_DIR}" \
  --finding-id f_reports_shell_concat
```

`replay.py` owns everything between those two lines: it derives the nonce,
spawns a fresh container from the unmodified image, copies in **only** the PoC,
runs it under the audit-hook observer three times, feeds the captured output to
the gate, and writes `${RESULTS_DIR}/proof/<finding_id>.json`.

Exit codes, and what each obliges you to do:

| Exit | Meaning | What you do |
|---|---|---|
| `0` | The replay completed and a proof record was written | Read the outcome, carry it forward |
| `1` | Internal error (container died, image pull failed, disk full) | Re-run **once**. If it fails again, stop replaying, record the harness error in `logs/`, and leave every un-replayed finding at `not_attempted` with that error as the reason. Report the harness failure to the user |
| `2` | Contract violation (no results dir, no image, findings dir empty, PoC path escapes the scratch dir) | **Stop.** Do not route around it, do not hand-write a proof file, do not fall back to the agent's transcript. Fix the precondition or tell the user why the phase cannot run |

`proof/<finding_id>.json` contains the three run records (command, exit status,
combined output, duration) and the gate's verdict block — the exact dict from
`ExecutionVerdict.to_dict()`: `outcome`, `proven`, `reason`, `evidence`,
`events_seen`, `events_attributed`, `observer_armed`, `nonce`,
`model_claimed_success`, `contradicts_model`.

**Never hand-edit a file under `proof/`.** It is the receipt. If it is wrong,
the gate or the replay harness is wrong, and that is a bug to escalate, not a
number to correct.

## Then make the receipts count

`replay.py` deliberately does not touch `findings/`. Once every finding has its
proof record, fold them in — **once, after the loop**:

```bash
python3 "${PYHUNT_DIR}/scripts/findings_io.py" apply-proofs \
  --results-dir "${RESULTS_DIR}"
```

This is a **promotion-only merge**, and it is the only writer of a finding's
`execution` block. It may raise an outcome to `proven` and it may replace the
`not_attempted` placeholder that phase 2 attached. It may **never** delete a
finding and never demote a `proven` one — so running it twice is safe, and
running it after a re-replay cannot lose a proof you already had.

Skipping this step does not produce a smaller number. It produces **zero
proven**, silently, however well the exploits actually worked: `proof/` would be
an artifact nobody reads, and phase 4 reads `findings/`. That gap — a real
verdict in `proof/` and a placeholder in the report — was defect C-1.

Its JSON reports `updated` (findings whose outcome changed) and `promoted` (the
ones that reached `proven`). If `updated` is 0 and you have proof records, the
`finding_id`s do not match and something upstream is wrong; stop and say so
rather than reporting a clean run.

## Three of three, unanimous, or no promotion

`replay.py` runs the PoC **three times** and promotes only on unanimity. Two
proofs out of three is not a two-thirds proof; it is a flaky PoC, and a flaky
proof is not a proof.

What flakiness usually means, all of which are reasons not to promote:

- the payload raced something (a background thread, a lazily-built cache) and
  the sink fired only when it won;
- the "evidence" was an artefact of a previous run — a canary file left behind,
  a log the container inherited;
- the exploit depends on state the target accumulated, not on the input, so a
  real attacker's first request would not reproduce it.

When the three runs disagree, the recorded outcome is the **non-promoting** one
and the disagreement is part of the record. A split is worth reading: it is a
finding about the PoC, and phase 2c may want it in `suggested_test`.

## The observer is an audit hook, not a patch

`scripts/observers/pyhunt_audit_hook.py` installs a PEP-578 hook via
`sys.addaudithook`, then runs the PoC through `runpy` in the same interpreter.
CPython raises audit events **below the Python API**, so they fire however the
sink is reached: `os.system`, a C extension that spawns a process, a pickle
gadget chain, a subprocess launched from inside a library.

A monkeypatched `subprocess.run` sees none of that. It is also removable — the
target could restore the original in a `finally` block, and an attacker-authored
repository absolutely would. Audit hooks cannot be removed once added, by
design. That asymmetry is why the observer is a hook.

Two properties of the hook that the gate depends on:

- **It prints a `hook-armed` banner before the PoC starts.** That line is what
  makes "the observer ran and saw nothing" (`no_event`) distinguishable from
  "the observer never ran" (`observer_absent`). Collapsing those two is how a
  broken harness becomes a clean bill of health.
- **It does not skip the PoC's own frames.** Every event line carries
  `<- from file:line in func` naming the code that caused it. When that names
  the PoC, the PoC called the sink directly and demonstrated nothing about the
  target — and the hunter needs to see that rather than have it filtered away.

The observer is optional instrumentation. Its silence is never a refutation.

## The nonce

Every marker line is stamped `n=<nonce>`, and the payload embeds the same value
(`; touch /tmp/pyhunt-canary/<nonce>`).

It is **derived, not random**: `HMAC(run_secret, run_id || finding_key)`
truncated to 64 bits, in `scripts/oracle/nonce.py`. Derived, so a resumed run
and a replayed transcript compute the same value and the gate stays testable in
CI. Keyed by a per-run secret, so a hostile repository cannot predict it and
print forged marker lines from its own code.

It is **re-derived by the harness, never read back from the finding.** An agent
that could name the nonce to check for could also invent the marker line that
matches it.

Without it, an event proves that *something* spawned a process — which innocent
code does at import time, and which forty-nine other concurrent PoCs are doing
in the neighbouring container. With it, an event is attributable to exactly one
PoC.

## The five conditions

A finding is `proven` when, and only when, all five hold:

1. **The observer armed.** No `hook-armed` banner ⇒ the instrumentation never
   ran. A fact about the harness, nothing about the code.
2. **A dangerous operation fired.** One of the watched audit events:
   `subprocess.Popen`, `os.system`, `os.exec`, `os.spawn`, `open`,
   `socket.connect`, `socket.getaddrinfo`, `urllib.Request`, `exec`, `compile`,
   `pickle.find_class`, `marshal.load(s)`, `ctypes.dlopen`.
3. **The event carried this PoC's nonce.**
4. **The frame that caused it is inside the target** — not the PoC, not the
   stdlib, not site-packages:

   ```
   [PYHUNT-OBSERVER] n=a3f19c22 audit:subprocess.Popen ('/bin/sh', ['-c', 'echo hi; id'])
       <- from /target/app/reports.py:7 in build_report        ← PROVEN
       <- from /work/hunt/t1/poc.py:3 in <module>              ← proves nothing
   ```

   The gate refuses to guess: with no target root supplied it attributes
   nothing, because falling back to "anything that is not the PoC" would promote
   a finding on the strength of a stdlib frame.
5. **The payload was interpreted, not merely carried.**

## Condition 5, and why it exists

This condition was not designed in. It was added after the end-to-end
false-exploit test caught the gate promoting a **defended** sink.

```python
subprocess.run("echo " + name, shell=True)   # vulnerable
subprocess.run(["echo", name])               # defended
```

Both raise `subprocess.Popen`. Both raise it **from the target's own frame**.
Both carry the attacker's value in the arguments, so both stamp the nonce. On
conditions 1–4 they are byte-identical — and the defended one would have been
reported as "confirmed by execution".

What separates them is what the runtime did with the value:

- `('/bin/sh', ['-c', 'echo hi; touch …<nonce>'])` — argv[0] is a shell and the
  nonce is inside the command string. The payload was **parsed as code**.
- `('/bin/echo', ['echo', 'hi; touch …<nonce>'])` — argv[0] is `echo`. The
  payload was **data**. That is precisely what the defence was for.

Accepted forms of interpretation, from `_payload_was_interpreted`:

- a shell invocation (`/bin/sh`, `/bin/bash`, `cmd.exe`, …) whose command
  string contains the nonce;
- an event where carrying the value at all means executing it — `exec`,
  `compile`, `os.system`, `pickle.find_class`, `marshal.load(s)`,
  `ctypes.dlopen`, a socket connect or `urllib.Request` naming the payload;
- an `open` of a nonce-derived path (traversal and arbitrary-write).

Stronger still, and preferred when available: **the canary materialised.** The
payload asks the target to create `/tmp/pyhunt-canary/<nonce>`; that file
existing afterwards cannot be explained by the sink merely running. It promotes
on its own, because it is direct observation rather than inference from
arguments.

A gate without condition 5 launders a false positive into "confirmed by
execution", which is strictly worse than having no gate: the reader trusts it
more.

## The eight outcomes

| Outcome | What it establishes | Effect | What you do with it |
|---|---|---|---|
| `proven` | All five conditions held | **Promotes.** The only outcome that does | Quote the attributed marker line in the report — that line *is* the proof |
| `sink_reached_unproven` | The target's frame fired the sink with the payload present; nothing shows it was interpreted | None | Report as "sink reachable with attacker data, exploitation not demonstrated". This is also what a working defence looks like from the runtime — phase 2c decides which |
| `self_attributed` | An event fired, but every causing frame is the PoC or a non-target file | None | The PoC bypassed the code under test. See "one re-attempt" below |
| `nonce_mismatch` | Events fired; none carried this PoC's nonce | None | Not attributable — another task's log, a stale transcript, a lost `PYHUNT_NONCE`. Re-run once; if it persists, report it as a harness fault |
| `no_event` | The observer armed and saw no dangerous operation | None | This PoC did not demonstrate the finding. **Not** a refutation — the sink may be reachable another way. Report on the static argument |
| `observer_absent` | No armed banner; the observer never ran | None | The harness failed. Says nothing about the vulnerability. Fix the wrap or the asset path and re-run |
| `not_attempted` | Static run, or the toolchain was missing | None | An environment limitation. Never render it as a failed exploit |
| `not_applicable` | The class cannot be settled by running code | None, and **counted separately** | Report as unprovable-by-execution, excluded from the provable denominator |

**Only the first promotes. None demotes.**

Consider the alternative to that rule. A finding is real; the container fails to
install a dependency; the PoC cannot import the target; the outcome is unproven;
the finding is dropped for "not reproducing". A broken build has become a silent
false negative — the worst outcome available to a security tool, because it is
invisible in the report. So the promoting set is a one-element frozenset in
`gate.py`, and nothing in this phase may lower a finding's standing.

Findings still die. They die in phase 2c, which reads the code and argues, and
they die when nothing shows attacker input reaching the sink. Those stages kill
on *evidence about the code*. **Execution kills on nothing.**

The seven non-promoting outcomes are not interchangeable and must never be
merged into "not proven": `observer_absent` is a broken harness,
`not_attempted` is a missing environment, `not_applicable` is a question
execution cannot answer, `sink_reached_unproven` may be a defence doing its job,
and `self_attributed` is a badly aimed PoC.

## What `proven` does not mean

`proven` establishes that **the sink is exploitable given the value**. It does
not establish that **an attacker can supply the value**.

A PoC that imported the target module and called the vulnerable function
directly can be entirely genuine — the target's own frame fired the sink and
interpreted the payload — while never touching routing, authentication, or
input validation. Showing that an attacker can reach it is the trace argument
phase 2c and phase 4 must carry, and a `proven` verdict is not a substitute for
it. Say which one you have.

## One re-attempt, for `self_attributed` only

`self_attributed` is the single actionable outcome: the PoC reached the sink
directly instead of entering through the target's real path. That is a defect in
the exploit, not in the finding.

You may return such a finding to phase 2 **once**, quoting the offending frame
line and asking for a PoC that enters through the documented entry point. Replay
the new PoC; the second proof record is authoritative. Record the re-attempt in
`${RESULTS_DIR}/logs/`. Bounded at one, because an unbounded retry loop is a
model grinding against a gate until something promotes — which is the shape of
every over-claim this design exists to prevent.

No other outcome earns a re-attempt. In particular, never rewrite a PoC to
"produce better evidence" for `sink_reached_unproven`; if the payload is not
being interpreted, the interesting question is *why not*, and that is phase 2c's.

## The over-claim counter

`contradicts_model` is true when `poc.succeeded` was `true` and the gate
disagreed. It is not an error — the hunter may be reading assertions the
observer cannot see — but the **rate** is a drift detector. A rising rate means
either the payload templates stopped embedding the nonce, or the hunt prompt has
drifted into optimism.

Count it across all findings and write the tally to
`${RESULTS_DIR}/logs/phase2b_overclaim.txt` (claimed / proven / contradicted).
Phase 4 reports it.

## Things that will tempt you, and are wrong

- **Feeding the gate the hunt agent's `run_output`.** That is the loop this
  phase exists to cut. The gate reads replay output only.
- **Dropping a finding whose PoC failed.** The single most damaging thing
  available to you here.
- **Believing an exit code.** A sink that swallowed an exception exits 0.
- **Believing a marker line without reading its attribution.** "A process
  started" is something innocent code does too.
- **Treating a silent observer as a refutation.** Absence of evidence is not
  evidence of absence; here it is usually evidence of a missing wrapper.
- **Summarising `run_output` anywhere.** The marker lines are the receipt a
  human reads to check the gate's arithmetic.
- **Promoting on two of three runs.**

## Before you leave this phase

- [ ] `ls ${RESULTS_DIR}/proof/ | wc -l` equals the number of files in
      `${RESULTS_DIR}/findings/`. A finding without a proof record was never
      judged, which is a phase failure, not an implicit non-promotion.
- [ ] Every proof record carries one of the eight outcome strings, spelled
      exactly as the enum spells it.
- [ ] **`findings_io.py apply-proofs --results-dir ${RESULTS_DIR}` has run**, and
      its `updated` count equals the number of proof records whose outcome
      differs from `not_attempted`. Until this runs, `proof/` is an artifact
      nobody reads: the findings still carry their placeholder, and phase 4
      reports **zero** proven no matter what replay observed. This was defect
      C-1 and it is the one step in this phase that cannot be skipped.
- [ ] No file under `findings/` was deleted or renamed by this phase, and the
      only field any of them gained is `execution`.
- [ ] The over-claim tally is written.
- [ ] `manifest.json` has `phase2b_prove` appended to `phases_completed`.

Then report to the user, in this shape and no other:

> N findings replayed. **P proven** by execution (unanimous 3/3), out of Q
> provable by execution at all; R marked `not_applicable` (class cannot be
> settled by running code). Non-promoting outcomes: `sink_reached_unproven` ×a,
> `no_event` ×b, `self_attributed` ×c, `observer_absent` ×d,
> `not_attempted` ×e. **Nothing was dropped.**
