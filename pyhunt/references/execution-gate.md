# The execution gate

How PyHunt decides that a proof-of-concept proved something, and why the
decision is not made by a model.

The rules live in `scripts/oracle/gate.py`. Read it alongside this document —
this file is the reasoning, that file is the specification. Neither a phase
file, nor a subagent, nor `SKILL.md` may reach a verdict any other way.

## The problem it solves

Every LLM-driven scanner in this lineage converged on the same shape: hunt
broadly, then disprove. The disproof got steadily better — adversarial review, a
different model, a reachability stage — but the strongest form of evidence,
*actually running the exploit*, kept being graded by the agent that produced it.

VASH went furthest: it ran real PoCs in a container under a PEP-578 audit hook
that recorded each dangerous operation and attributed it to the line that caused
it. Excellent evidence. But `poc.succeeded` was still a boolean the Hunt agent
set about its own work, the observer's output was only ever *rendered into the
report*, and the instruction that produced zero false positives was a sentence in
a prompt:

> you MUST attempt the PoC and DROP / downgrade findings that don't reproduce —
> this is how we reach zero false positives

A prompt cannot be unit-tested, does not fail loudly when a model tier changes,
and has no way to distinguish "the exploit worked" from "the exploit looked like
it worked". PyHunt keeps every part of that design except the last step, which
moves into `scripts/oracle/`.

## What must be true for a finding to be proven

All five, together. `judge()` checks them in this order, and the first one that
fails determines the outcome.

1. **The observer armed.** The hook prints a `hook-armed` banner before running
   the PoC. Its absence means the instrumentation never ran, which is a fact
   about the harness and nothing about the code.

2. **A dangerous operation fired.** One of the watched CPython audit events. The
   list is `WATCHED_EVENTS` in `scripts/observers/pyhunt_audit_hook.py`:
   `subprocess.Popen`, `os.system`, `os.exec`, `os.spawn`, `os.posix_spawn`,
   `os.startfile`, `open`, `socket.connect`, `socket.getaddrinfo`,
   `urllib.Request`, `exec` (raised by both `exec()` and `eval()`), `compile`,
   `pickle.find_class`, `marshal.load`, `marshal.loads`, `ctypes.dlopen`.

3. **The event carried this PoC's nonce.** Without a nonce, an event proves that
   *something* spawned a process, not that *this exploit* did. The nonce is
   **required**: `judge(nonce=None)` yields `nonce_mismatch`, never a promotion.
   The `require_nonce` parameter survives only so existing call sites keep
   importing; it no longer does anything. It used to disable this condition for
   "pre-nonce transcripts", a category that stopped existing, and combined with
   `canary_touched` it would have promoted a finding with no attribution to the
   PoC at all.

4. **The frame that caused it is inside the target, is a frame nobody minted,
   and names *this finding's file*.** Three separate checks, below.

5. **The payload was *interpreted*, not merely carried.** Also below.

## Condition 4a — the frame is inside the target

Not the PoC, not the stdlib, not site-packages, not a `<…>` pseudo-file. This is
the difference between evidence and theatre:

```
[PYHUNT-OBSERVER] n=a3f19c22 audit:subprocess.Popen ('/bin/sh', ['-c', 'echo hi; id'])
    <- from /target/app/reports.py:7 in build_report          ← PROVEN
    <- from /work/hunt/t1/poc.py:3 in <module>                ← proves nothing
```

The second line means the PoC called the sink directly and never went through
the code under test. VASH's hook deliberately did *not* skip the PoC's own
frames so this would be visible. PyHunt acts on it.

`_is_target_frame` refuses to guess: with no `target_roots` supplied it returns
False for everything, because falling back to "anything that is not the PoC"
would promote a finding on the strength of a stdlib frame — exactly the
over-claiming this module exists to stop.

Pseudo-files are rejected generally, by shape (`<string>`, `<stdin>`,
`<template>`, `<frozen importlib._bootstrap>`) rather than by an allow-list of
two. The gate previously excluded only the literal `"<string>"`, which is
nothing more than `compile`'s **default** — every other name in the same shape
went straight through.

## Condition 4b — the frame was not synthesized

`co_filename` is whatever string was handed to `compile()`. So:

```python
exec(compile(payload_src, "/target/app/reports.py", "exec"))
```

produces a **completely genuine** CPython audit event, raised by the interpreter
itself, from a real frame — whose file is a string the caller chose. Conditions
1–3 and 4a all pass. Nothing about the target ran.

`judge` therefore distrusts any attribution to a filename that was passed to
`compile`/`exec` during the run. Outcome: `self_attributed`, because the PoC
synthesized that frame.

The set arrives two ways and the gate takes the union:

- **Out of band, from the observer.** The hook sees `args[1]` of `compile` and
  the code object's `co_filename` for `exec` directly, un-truncated. `replay.py`
  collects them and passes `synthesized_filenames`. This is the primary channel.
- **Derived from the transcript.** `gate.declared_filenames()` recovers the same
  names from the event's own repr'd arguments — the `compile` mode vocabulary
  (`exec`/`eval`/`single`/`func_type`) anchors the filename as the element
  before it, and an `exec` event's code-object repr carries `file "…"` verbatim.
  Best-effort by construction: the hook truncates long argument reprs, so a
  `compile` of a large source can lose its filename here. That is why the
  observer's channel is primary and this is the backstop.

**One exemption, and it is not a loophole.** The `compile`/`exec` call that
*declared* the filename is itself attributed to its real caller. So a target that
genuinely does `exec(compile(user_code, __file__, "exec"))` — real eval-injection
— still proves on that event's own frame. Only the frames the minted code object
goes on to create are distrusted.

This also catches the *sincere* PoC that drives the target via
`exec(compile(src, target_path, "exec"))` rather than importing it. That PoC
demonstrates nothing about the target's real entry point, and used to get an
undeserved pass.

## Condition 4c — locality

**The nonce is keyed on the task, not the finding.** It has to be: the hunt agent
must know it while authoring the PoC, and findings do not exist yet at that
point. So every finding from one task shares a nonce, and a hunter that attaches
the same PoC to N findings used to get N proofs out of one real vulnerability.
Reproduced: a single transcript attributing to `/target/app/reports.py` promoted
findings whose `file` was `app/unrelated.py` and `app/also_unrelated.py`.

`finding_file` closes it. The attributed frame must be *this finding's own file*.
A frame inside the target but in a different file is **not proven** — outcome
`sink_reached_unproven`, and the reason names both files, because "the sink was
reached, somewhere else" is a genuinely useful thing to report and a genuinely
different thing from a proof.

Matching normalises across the container boundary rather than comparing raw
strings: the observer records `/target/app/reports.py`, the finding records
`app/reports.py`, and a host-side caller may hold `/srv/repo/app/reports.py`.
`_repo_relative` strips whichever target root applies and compares what remains.

Locality is skipped when `finding_file` is not supplied, so callers judging a
whole run rather than one finding keep working — but `replay.py` always supplies
it, and a run where it was missing is not a run that proved a finding.

## Condition 5, and the `echo` case that produced it

This condition was added after the end-to-end false-exploit test caught the gate
promoting a **defended** sink. Consider the pair:

```python
subprocess.run("echo " + name, shell=True)   # vulnerable
subprocess.run(["echo", name])               # defended
```

Both raise `subprocess.Popen`. Both raise it **from the target's own frame**.
Both carry the payload in the arguments, so both stamp the nonce. On conditions
1–4 they are indistinguishable, and the defended one would have been reported as
"confirmed by execution".

What separates them is what the runtime did with the value:

* `('/bin/sh', ['-c', 'echo hi; touch …<nonce>'])` — argv[0] is a shell and the
  nonce is inside the command string. The payload was **parsed as code**.
* `('/bin/echo', ['echo', 'hi; touch …<nonce>'])` — argv[0] is `echo`. The
  payload was **data**, which is what the defence was for.

The same hole existed for three other event families, and each was reproduced as
a working defence that the gate promoted. The corrected predicate:

| Event | Interpretation test |
|---|---|
| `subprocess.Popen`, `os.exec`, `os.spawn`, `os.posix_spawn`, `os.startfile` | argv[0] is a shell — `/bin/sh`, `/bin/bash`, `/bin/dash`, `/bin/zsh`, `/bin/ksh`, `cmd.exe`, `powershell` — **and** the nonce appears in the arguments |
| `exec`, `compile`, `os.system`, `pickle.find_class`, `marshal.load`, `marshal.loads`, `ctypes.dlopen` | carrying the nonce at all is proof: the value *was* the code, the pickle, or the shared object |
| `open` | the opened path carries the nonce **and** resolved **outside** `target_roots`, or is the canary path |
| `urllib.Request`, `socket.connect`, `socket.getaddrinfo` | the nonce is in the **host**, not merely somewhere in the URL |

Why the last two changed:

* **`open`.** The old rule was "any `open` whose arguments contain the nonce".
  A *working* path-traversal defence —
  `open(os.path.join(BASE, os.path.basename(user_path)))` with input
  `../../etc/passwd_<nonce>` — carries the nonce straight into the path and
  still lands inside `BASE`. Carrying a value into a path is not evidence the
  path escaped its root; **where the read landed** is. The canary
  (`/tmp/pyhunt-canary/<nonce>`) is accepted as the other proving shape, because
  nothing but the payload explains that path.
* **The network events.** The old rule was "the nonce is in the arguments".
  A defended SSRF where the host is allowlisted and the attacker controls only
  the query string puts the nonce in the URL and proved nothing about where the
  request went. Userinfo is stripped before the check for the same reason:
  `http://user:<nonce>@allowed.host/` still reaches the allowlisted host.

In every one of these cases the correct outcome is `sink_reached_unproven` — the
sink was genuinely reached, which is worth reporting, and nothing was proven.

Stronger still, and preferred when available: **the canary materialised.** The
payload asks the target to create `/tmp/pyhunt-canary/<nonce>`; that file
existing afterwards cannot be explained by the sink merely running. It is only
evidence when read from **outside** the sandbox the PoC ran in, after that
sandbox exited — `replay.py` bind-mounts a fresh empty directory per run and
stats it host-side once the container is gone. A canary stat'd on a filesystem
the PoC could write to directly is not evidence of anything.

A gate without condition 5 launders a working defence into "confirmed by
execution", which is worse than having no gate. Anyone who does not understand
the `echo` case will eventually delete it as redundant — that is why the story
is written down here and in `SKILL.md`.

## Signed observer markers, and what they are not

**Contract A.** The transcript the gate parses is produced inside the same
container as the PoC and the target. Before signing, a PoC that performed no
dangerous operation at all could simply *print* two well-formed
`[PYHUNT-OBSERVER]` lines and verdict `proven`, deterministically, three runs out
of three. So could a hostile repository, from its own `__init__.py`, since
`PYTHONPATH=/target` and the nonce was handed to the container.

The fix has four parts:

- `replay.py` generates a random 32-hex **`observer_key`** per run — distinct
  from the nonce — and passes it in as `PYHUNT_OBSERVER_KEY`.
- The audit hook reads it **at install time, before any target or PoC code
  runs**, keeps it in a closure, and **deletes it from `os.environ`**. It deletes
  `PYHUNT_NONCE` after reading it too, for the same reason.
- Every marker line becomes `[PYHUNT-OBSERVER] n=<nonce> s=<sig> <body>`, where
  `<sig>` is the first 16 hex characters of `HMAC-SHA256(observer_key, body)`.
- Markers go to **file descriptor 3**, not stdout and not stderr, so ordinary
  target output cannot be mistaken for observer output. With fd 3 unopened the
  hook falls back to stderr and marks the stream `unsigned_fallback`, so nothing
  silently reads as authentic.

`markers.parse_observer_output(text, *, key=None)` verifies when a key is given.
Lines that fail verification are **discarded and counted**; the result carries
`forged_lines`. `judge` carries that count onto the verdict and into
`to_dict()`, so it reaches the proof record and the report. Forged lines produce
no new outcome — they are dropped, and a transcript whose only dangerous events
were forged falls through to `no_event` naturally. But `forged_lines > 0` is
surfaced regardless, because *something in the run trying to forge proof* is the
most interesting thing that can happen in a scan.

`ExecutionVerdict.markers_signed` records whether verification actually ran. When
the key is absent, or the parser predates Contract A, it is `False` — unverified
must never read as verified.

**The honest residual.** Target code executes in the same interpreter as the
hook. A target that specifically attacks PyHunt can, with effort, recover the key
from process memory. Signing plus environment scrubbing plus a private fd defeats
naive and opportunistic forgery and forces any attack to be deliberate and
PyHunt-specific — it is **not** a security boundary against an adversary who has
read this repository. Out-of-process observation (seccomp, eBPF, ptrace) is the
real fix and is out of scope. Do not describe this as tamper-proof anywhere.

## The eight outcomes

`Outcome` in `scripts/oracle/gate.py`. Every PoC run yields exactly one. The enum
is referenced across schemas, phases, references and roughly seventy tests; a
ninth outcome is a cross-cutting edit, never a local one.

| Outcome | Meaning | Effect on the finding |
|---|---|---|
| `proven` | All five conditions held | **Promoted.** `verdict.proven` is True; this replaces the model's `poc.succeeded` |
| `sink_reached_unproven` | The target's frame fired the sink with the payload present, but nothing interpreted it, or the frame was in a different file from this finding's | Unchanged. "Reachable, exploitation not demonstrated" — and also what an effective defence looks like from the runtime, so phase 2c decides which |
| `self_attributed` | An event fired; every nonce-matched frame was the PoC, an unplaceable file, or a filename the PoC synthesized | Unchanged. The report says the PoC bypassed or minted the code under test. Rewrite the PoC to enter through the target's real entry point |
| `nonce_mismatch` | Events fired, none carried this nonce — or no nonce was supplied | Unchanged. Concurrent task, stale log, or replayed transcript. Usually a lost `PYHUNT_NONCE` — re-run |
| `no_event` | Armed, nothing dangerous fired | Unchanged. **Not** a refutation |
| `observer_absent` | No armed banner | Unchanged. The harness failed, not the finding |
| `not_attempted` | Static-only run, or the toolchain was missing | Unchanged. An environment limit |
| `not_applicable` | The class cannot be settled by running code | Unchanged, and **counted in its own denominator** |

`PROMOTING` is a `frozenset` of exactly one element, deliberately, so that adding
a second promoting outcome is a visible reviewable edit rather than a changed
comparison operator somewhere.

Only the first promotes. **None demotes.**

## Why nothing demotes

Consider the alternative. A finding is real; the container failed to install a
dependency; the PoC cannot import the target; the gate marks it unproven; the
finding is dropped for "not reproducing". A broken build has become a silent
false negative — the worst outcome available to a security tool, because it is
invisible in the report.

VASH already got this right in prose (*"a missing `javac` is an environment
limitation, not a verdict"*). PyHunt makes it structural: nothing in
`scripts/oracle/gate.py` can lower a finding's standing, and no caller is
permitted to. `replay.py`'s verdict reaches `finding["execution"]` through a
**promotion-only merge**: it may raise an outcome to `proven` and it may replace
a placeholder, but it may never delete the finding and never demote a `proven`.

Findings still die — in phase 2c, which re-reads the code adversarially on a
different model and must produce a refutation at a `file:line`. That stage kills
on *evidence about the code*. Execution kills on nothing.

## `not_applicable` and honest denominators

Two different reasons a class can be unprovable, and `scripts/oracle/classes.py`
keeps them as two tables because the report's denominators depend on both.

**1. The question is not a runtime question** — `UNDECIDABLE_BY_EXECUTION`.
Execution answers *"did this behaviour occur?"*. It cannot answer *"was this
behaviour allowed?"*, which needs the intended policy, and the policy does not
exist in the runtime. A PoC can show user A reading user B's record and still not
establish that doing so is wrong.

`access_control` · `access-control` · `authorization` · `authz` · `idor` ·
`privilege_escalation` · `business_logic` · `workflow` · `insecure_design` ·
`insecure_default` · `missing_auth` · `mass_assignment` ·
`information_disclosure` · `csrf` · `rate_limit` · `cryptographic_failure` ·
`weak_crypto` · `hardcoded_secret`

Matched substring-wise in **both** directions, normalising `-`/space to `_`,
because the class vocabulary is not closed — a hunter emitting
`broken_access_control` still matches the `access_control` key.

**2. This observer has no event for the sink** — `NOT_PROVABLE_BY_THIS_OBSERVER`.
`WATCHED_EVENTS` has no DB-cursor event and no response-write event, so a
fully-exploited SQL injection produces nothing the gate can attribute. Leaving
these in the provable denominator made **PyHunt's own blind spot read as the
target's findings failing to reproduce**.

`sql_injection` · `sqli` · `nosql_injection` · `nosqli` · `xss` ·
`cross_site_scripting` · `html_injection` · `open_redirect`

Matched **key-in-needle only**, unlike the table above: the bidirectional match
that lets `broken_access_control` find `access_control` would also let a bare
class `injection` find `sql_injection` and quietly exclude command injection —
a class the gate proves routinely — from the denominator.

This is a statement about PyHunt today, not about the class. The alternative
considered was adding DB-cursor and response-write events to the hook; that was
rejected because it is a *promise*, whereas this is *true today*. If
`WATCHED_EVENTS` ever grows such an event, delete the corresponding entry.

**Template injection is deliberately absent from that table**, although it looks
like it belongs. Jinja2 and friends implement rendering by calling
`compile(source, filename, "exec")`, which **is** a watched event, and the hook's
frame walk skips site-packages and attributes it to the target's own
`render(user_input)` line. A server-side template injection whose payload carries
the nonce therefore reaches `proven` legitimately, while a safe render (static
template, user data passed as context) never puts the nonce in `compile`'s source
and correctly does not. Listing `ssti` would have traded a dishonest denominator
for a false negative.

Two consequences worth stating:

- Both tables are **excluded from the proven-ratio denominator**, not counted as
  failures. "18 of 25 proven" is misleading if 6 of the 7 unproven are IDORs.
  "18 of 19 provable, plus 6 not provable by execution" is the same run described
  honestly. See `references/honest-reporting.md`.
- Because `is_undecidable()` is checked **first**, before any environment or
  evidence question, a `not_applicable` class never reaches the evidence path and
  `replay.py` starts no container for it. `phase2_class_log.md` therefore has no
  execution oracle by design, and its findings must carry a *policy* argument —
  which code *should* have carried the check — instead of a PoC transcript.

## The nonce

Derived, not random: `HMAC(run_secret, run_id || finding_key)`, truncated to 64
bits (16 hex chars). Derived so a resumed run and a replayed transcript compute
the same value in CI. Keyed by a per-run secret — `PYHUNT_RUN_SECRET`, generated
and exported if unset.

It travels three ways, and any one suffices:

- exported into the container as `PYHUNT_NONCE`, so the hook stamps every line
  it prints;
- embedded in the payload itself (`; touch /tmp/pyhunt-canary/<n>`), so the
  event's *arguments* carry it even if the stamp is lost;
- re-derived by the gate from `run_id` and the task/finding key — **never read
  back from the agent's output**, because an agent that could name the nonce to
  check for could also invent the line that matches it.

**What the nonce is not.** An earlier version of this document claimed the
per-run secret stopped a hostile repository forging marker lines. It does not,
and the claim was wrong: the nonce is *handed to the container* so the hook can
stamp with it, which means the target's own code can read it out of the
environment and print a perfectly-formed line. The nonce solves **attribution**
between concurrent tasks, stale logs and replayed transcripts. It has never
solved **authenticity**. That is what the observer key in Contract A is for, with
the honest residual stated above.

## What the gate is allowed to read

`judge()` is a pure function: no I/O, no model, no clock. It takes the observer's
output, the nonce, the target roots, the PoC paths, this finding's file, the
synthesized filenames, the observer key, and a few environment booleans, and
returns one `ExecutionVerdict`. That is what makes it testable by handing it a
recorded transcript and asserting an outcome.

The first parameter is named **`observer_output`**, and the name is the point:

1. **The gate consumes replay output, not the hunt agent's transcript.**
   `poc.run_output` as returned by a hunt agent is text the agent wrote about its
   own work — self-reported, and possibly trimmed, paraphrased or invented.
   The gate judged exactly that for a while, and a forged transcript attached to
   three findings in unrelated files produced `proven_by_execution: 3`.
   Phase 2b re-runs the PoC through `replay.py` — only the PoC crosses into a
   fresh container built from the unmodified image — and the gate reads *that*
   output. Three runs, unanimous, or no promotion. `replay.py`'s `PocArtifact`
   makes this structural: it has no `run_output` field for a later edit to pass.
   `run_output=` survives on `judge()` only as a deprecated alias so call sites
   in other modules compile through the rename; passing both is an error.
2. **`target_roots` must include both the host repo path and the in-container
   mount.** The frames the observer records are container-side (`/target/...`)
   even when the repo path is a host path. Forgetting one turns every `proven`
   into `self_attributed` — and now also disables the `open` escape test, which
   asks whether the opened path left those roots.

## Where the verdict goes

A gate reading the right input is only half of it. The verdict has to reach the
findings, and for a while it did not: `replay.py` wrote `proof/<id>.json` and
**nothing read it back**, while `findings_io.record_finding` judged
`poc.run_output` and wrote *that* to `finding["execution"]` — the one field
`report_build` reads as "confirmed by execution". A PoC whose body was
`print('hello, I did nothing')` reported `proven` while its own proof record
said `no_event`, three runs out of three. That was defect C-1, and it is why
`oracle/finding.py` no longer contains a function that turns a finding into a
verdict.

There is now exactly one writer of `finding["execution"]`:

- `findings_io.record_finding` attaches the **placeholder** — `not_attempted`,
  with a reason saying replay has not run. A placeholder is not a rejection.
- `findings_io.apply_proof` performs a **promotion-only merge** of a proof
  record. It may raise an outcome to `proven` and it may replace the
  placeholder. It may never delete a finding, and never demote a `proven` one —
  so it is idempotent and safe to re-run. `proven` is derived from the record's
  `outcome`, never copied from its `proven` field, so a proof record cannot
  claim a promotion its own outcome does not support.
- Phase 2b invokes it as `findings_io.py apply-proofs`. **Skipping that step
  does not produce a smaller number — it produces zero proven**, however well
  the exploits worked.

Two shape mismatches lived on this seam and are worth remembering, because both
were invisible while each side was tested against its own hand-written dict:
`ProofRecord.to_dict()` carries no top-level `evidence`/`events_seen`/
`observer_armed` (they are per-run, under `runs[i]["verdict"]`) and no
`run_output` at all (the transcript is `runs[i]["markers"]`, with
`stdout`/`stderr` beside it). Anything consuming a proof record must read it
where replay actually writes it.

`contradicts_model` is carried alongside the verdict: the hunter claimed success
and the gate disagrees. It is not an error — the model may be reading assertions
the observer cannot see — but a rising rate means either the payload templates
stopped embedding the nonce or the prompt has drifted into optimism. Log it at
the end of every hunt phase for that reason. `replay.py` pins
`model_claimed_success=None`, because the agent's belief is precisely the input
that module exists to remove.

## Testing it

`tests/test_oracle_gate.py` is the specification. Each test is a recorded
transcript and the outcome it must produce, including the ones that must *not*
promote:

- a PoC-attributed event, a stdlib frame, a `<template>` frame;
- another task's nonce, and no nonce at all;
- a silent observer and a missing hook;
- the defended `subprocess.run(["echo", name])` twin;
- the traversal defence that carries the nonce into a path inside the root;
- the allowlisted SSRF with the nonce in the query string, and in userinfo;
- the frame minted by `compile(src, "/target/app/reports.py", "exec")`;
- a real vulnerability in `app/reports.py` offered as proof of a finding in
  `app/unrelated.py`.

Each of those last four fails on the pre-review gate, which is the point of
writing them down.

Two properties are worth watching as the corpus grows:

- **False-exploit rate must stay at zero.** A sanitized twin of a vulnerable
  fixture must never come back `proven`. A confidently wrong gate is worse than
  no gate. This is a release gate, not a metric.
- **The over-claim rate is a drift detector.** See `contradicts_model` above.
