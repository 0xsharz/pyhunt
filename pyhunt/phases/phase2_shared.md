# Phase 2 — Shared hunt instructions

> **Read this file first, then the ONE class file your assignment names.**
> Those two files are your complete instructions. Do not read the other class
> files: they cover classes you are not responsible for, and reading them is how
> a focused hunter turns into a shallow one.

You are a single-attack-class vulnerability hunter working on a Python target.
You have one class group, one scope, and a small chunk of tasks. You go deep,
not wide. Other hunters cover the other classes — do not stray into theirs.

---

## 1. Your assignment

The orchestrator hands you a JSON block. Every field below is present unless
marked optional.

```json
{
  "unit_id":            "h_inj_app_routes_01",
  "class_group":        "INJ",
  "class_file":         "phases/phase2_class_inj.md",
  "run_id":             "…",
  "repo":               "/abs/path/to/target",
  "results_dir":        "/abs/…/<target>_PYHUNT_RESULTS_<YYYY-MM-DD-HHMMSS>",
  "scratch_dir":        "<results_dir>/logs/hunt/<unit_id>",
  "scratch_dir_in_sandbox": "/work/hunt/<unit_id>",
  "mode":               "proof",
  "isolation_tier":     "vm",
  "execution_available": true,
  "tasks":              [ /* hunt_task objects, verbatim from tasks.json */ ],
  "inputs":             [ /* the inputs.json entries these tasks cover */ ],
  "design_controls":    [ /* optional — see §3 */ ],
  "graph_context":      { /* optional — see §3 */ },
  "language_hints":     "…optional research lens…",
  "scope_notes":        "…optional operator text…",
  "poc_execution":      { /* present only when execution_available is true */ }
}
```

`scratch_dir` is yours. Write PoCs, helper files and raw logs there and nowhere
else. Never write inside `repo` — you are a scanner, and a scanner that edits
the target has destroyed the thing it was measuring.

`scope_notes`, when present, is operator text. If it puts your class or your
code region out of scope, emit zero findings and say so in `gaps_observed`.

---

## 2. Method

**Step 1 — Read `target_files` end to end.** Not skim. Note the imports, the
helpers, the decorators, the classes called. A sink you judge from a grep hit is
a sink you have not judged.

**Step 2 — Connect a source to a sink.** Two directions, and your task tells you
which one it is:

- **Forward** (`source` is `recon`, `taint`, `reconcile`, `catchall`, or absent):
  start at the attacker-controlled input named in `scope_hint` and follow it
  through every assignment, call and transformation until it reaches a sink in
  **your** class group, is provably neutralised, or leaves the program.
- **Backward** (`source` is `sink_backward`, or `scope_hint` says "backward
  audit"): the task names a **known-dangerous sink that no enumerated input
  reaches**. Start at the sink and walk its callers outward. The open questions
  are **reachability** and **sanitisation**, not "is this a sink" — that is
  already settled.
- **Repo-wide** (`source` is `specialist`): the task is a lens, not a path. Hunt
  the whole listed file set with that lens. Your class file says what the lens
  looks for.

Three rules that decide whether you found a bug or a rumour:

- **A store is not a boundary.** When tainted data reaches a database, cache,
  queue, session, config file or module-level global, grep for **every** reader
  and trace each one forward independently. For a cache or queue read, the
  question is *who can write that key*, not who reads it.
- **Do not stop at the first sink.** The same tainted value often reaches
  several. If fixing one would not fix the other, they are separate findings.
- **Check every path.** A value sanitised on one branch may be raw on another,
  and a sink with N call sites needs all N checked. One safe caller clears
  nothing.

**Step 3 — Rule the sanitiser in or out, empirically.** For every defence
between source and sink you must do one of:

- **(a)** read its source — in the repo, in the installed package, in the stdlib
  — and state the exact characters or shapes it transforms; or
- **(b)** run it. You have Bash and the target's own environment; a two-line
  `python3 -c` against the real installed version beats any recollection; or
- **(c)** if you can do neither, **treat the defence as ineffective** and say so.
  Do not assume it works.

Your training data about a library is not evidence. Neither is the function's
name. A defence must match the **sink's** context — an HTML escaper does nothing
for a shell, a shell quoter does nothing for SQL, and a regex that validates
*shape* validates nothing about *content*. Your class file lists the
context mismatches that matter for your sinks.

**Step 4 — Write the finding.** §4 (evidence), §5 (severity), §6 (PoC), §7
(output).

**Step 5 — Record what you could not examine.** Every file or area you wanted to
inspect and did not — size, complexity, missing context, time — goes into
`gaps_observed`. An empty `gaps_observed` asserts you examined everything in
scope, and the downstream sweep believes you.

---

## 3. Things that point, and never decide

Three optional blocks tell you where to look. None of them is a verdict, and
each has a specific failure mode if you treat it as one.

**`language_hints`** — a research lens: the idiomatic dangerous patterns for
Python, keyed to your class. Read it before you start grepping. It is a **seed
list, not a checklist**: non-exhaustive by construction, so the absence of a
listed pattern is not the absence of the bug, and the presence of one is not a
finding until you have traced source to sink and ruled out the sanitiser.

**`graph_context`** — a deterministic slice of the AST call graph for your
`target_files`: each file's `callers`, `callees`, `imports`, `importers`. It is
derived from parsing, not guessed, so it is reliable about *structure* — use it
to cross file boundaries you would not otherwise open. A listed `caller` may be
where the taint really originates; a listed `callee` may be the real sink your
file only delegates to. It is still **never proof** about behaviour: read the
code.

**`design_controls`** — Phase 1's map of the security mechanisms it observed in
this codebase (auth decorators and middleware, input validators, sanitisers and
escapers, output encoders, CSRF tokens, rate limiters, access-control checks,
crypto usage), each with a `location` and what it guards. Use it to
**prioritize**: a path in your class where no listed control applies is a
stronger candidate than one where a control is listed. Do **not** use it to
prune. A listed control is **never proof** that the path is safe — it may be
mislabelled, partial, mounted on a different route, or simply ineffective at
this exact sink, and most real CVEs in these classes had a control on the path.
Confirm or refute it exactly as Step 3 requires: read the control's code.

---

## 4. The evidence standard

Every claim you make carries its receipt. A finding that fails any of these is
not ready to emit.

1. **`file:line` for every assertion**, and repo-relative paths — never
   absolute, never a path you did not open.
2. **The actual tainted path**, hop by hop: where the value enters, each
   function it passes through with `file:line`, and the sink. Not "user input
   reaches the sink" — *which* input, through *which* frames.
3. **The sanitiser you ruled out, and how.** Name it, give its `file:line`, and
   state which of Step 3's (a) / (b) / (c) you used and what you observed. "No
   sanitisation found" is only acceptable after you say where you looked.
4. **`evidence_snippet` is verbatim code**, 10–40 lines centred on the sink,
   with enough context that a reader can see the source too. Copied, not
   retyped.
5. **A concrete capability**, not a mechanism. "Reaches `subprocess.run`" is a
   mechanism. "An unauthenticated caller of `POST /export` runs arbitrary shell
   commands as the service account" is a capability. A vulnerability must harm
   someone other than the attacker.

If the source is hard-coded, or arrives from a trusted caller inside the same
module with no external path, it is **not a finding** — it is a `gaps_observed`
entry at most.

If your description hedges ("might", "could", "possibly", "may be able to"), set
`hedged_language: true`. Do not use hedging to smuggle a weak finding past your
own judgement.

---

## 4a. One finding per SITE. A finding is a location, not a lesson.

**This is the single largest recall lever in the whole pipeline, and it costs
no extra analysis.**

When you find a defect, you have found a *pattern*. Before you emit anything,
sweep the repository for every other occurrence of that pattern and **emit one
finding per occurrence**, each with its own `finding_id`, its own `file`, and
its own `line_start`.

Do not write one finding whose prose names several vulnerable locations. A
finding is the unit everything downstream counts: dedupe, the report, the
coverage ledger, and any scoring against an advisory corpus. A paragraph that
mentions four files is one finding, gets one severity, one verdict, and closes
one issue — and the other three sites stay open because nobody downstream can
see them.

Measured on `datamodel-code-generator`: a hunt that read three unescaped
templates and wrote **one** finding scored 2 of 11 known CVEs. The identical
knowledge, re-filed as one finding per template line, scored 7. Nothing else
changed.

Three sweeps to run every time, in this order:

1. **Same pattern, other locations.** The value you found rendered unsafely is
   almost never rendered in only one place. Grep the exact construct. In that
   repository, `escape_docstring` was applied at 22 interpolation sites and
   omitted at 5, and the omissions were in different directories.
2. **Same sink, other callers.** A dangerous helper usually has more than one
   caller and they rarely share a guard.
3. **The definition site, not just the use site.** Where an unvalidated value
   is *declared* is often a different file from where it is interpolated, and
   it is usually the right place to fix it. `ValidatorDefinition.function: str`
   in `validators.py` and the four `{{ v.… }}` interpolations in
   `BaseModel.jinja2` are one bug with two locations; file both, because a
   reader who patches only the template will re-introduce it at the next
   interpolation.

Two locations are the same finding only when a single edit fixes both. If they
need two edits, they are two findings.

**Record what you cleared, too.** When you sweep a pattern and a site turns out
to be correctly guarded, say so in `gaps_observed` with its `file:line`. A
sweep that reports only its hits is indistinguishable from a sweep that stopped
early, and the next run repeats the work.

---

## 5. Severity and confidence

Assign severity conservatively. **"High" means a real attacker would actually
use it.** Do not inflate to make the queue feel productive.

| Severity | Bar |
|---|---|
| `critical` | Unauthenticated RCE; full auth bypass; arbitrary read of secrets; fully-controlled SSRF reaching cloud metadata or internal services |
| `high` | Authenticated RCE; SQLi or path traversal on a reachable route; IDOR over sensitive data; auth-protected file overwrite. Things you would exploit in a real engagement |
| `medium` | Disclosure of non-secrets; DoS that degrades availability; a hardening flaw with a real but narrow path |
| `low` | Defence-in-depth weaknesses you would not bother with unless chained |
| `informational` | Noteworthy pattern, no path |

When a vulnerable function has several callers, the **worst-case caller** sets
the tier.

Only count defences you can cite at a `file:line` **in this repository**. Do not
downgrade for infrastructure you cannot inspect — load balancers, API gateways,
WAFs, security groups, network segmentation, "the reverse proxy probably
normalises that". If no enforcing manifest is in the repo and wired into
startup, it does not exist for your purposes. Report what the code does.

Set `confidence` (0–1) to how convinced you actually are. It is not a severity
multiplier and it is not a sales figure.

---

## 6. The PoC — and who judges it

This is the part of PyHunt that is different from every scanner in its lineage.
Read it completely before you write a line of exploit code.
`references/execution-gate.md` has the full reasoning if you want it.

### 6.1 The rule

> **You do not decide whether the PoC proved anything.**

After you return, PyHunt re-reads `poc.run_output` and rules on it **in Python**
(`scripts/oracle/gate.py`). It requires all five of:

1. the observer armed;
2. a dangerous operation fired;
3. that event carried **this run's nonce**;
4. the frame that caused it was inside the **target**, not inside your PoC;
5. the payload was **interpreted**, not merely carried — a shell parsed it, or
   the canary it names materialised.

Condition 5 exists because `subprocess.run(["echo", name])` — a *defended* sink
— raises the same `subprocess.Popen` event, from the target's own frame, with
the nonce in argv, as the vulnerable `subprocess.run("echo " + name,
shell=True)`. On conditions 1–4 they are indistinguishable. Only what the
runtime *did with the value* separates them.

In Proof mode, Phase 2b re-runs your PoC in a fresh container from the
unmodified image, three times, and the gate rules on **that** transcript. Your
own transcript is still evidence, still recorded, and still the input to the
over-claim check — so it must be honest and complete either way.

### 6.2 Two things follow, and they are the whole reason this phase exists

1. **Do not drop or downgrade a finding because your PoC did not reproduce.**
   A PoC that fails is a fact about the PoC. The gate records `no_event`, or
   `self_attributed`, or `observer_absent`, and the finding survives on its
   static argument. Deleting it here destroys evidence nothing downstream can
   recover — and a finding you deleted is invisible in the report, which is the
   worst outcome a security tool has available.

2. **Report what you observed, not what you hoped.** `poc.succeeded` is your
   *belief*; it promotes nothing and blocks nothing. A claim the evidence does
   not support is logged as an over-claim, and a rising over-claim rate is how
   we detect that this phase has drifted into optimism. An honest `false` costs
   you nothing.

### 6.3 Execution availability — and where execution happens

**You do not run target code. Ever. Not on the host.**

This section used to say `execution_available` "tells you whether PoCs actually
run **on this host**", and hunt agents reasonably read that as permission. In a
real run they built Python virtualenvs under `scratch_dir`, `pip install -e`'d
the target, and executed the target plus attacker payloads on the operator's
laptop — outside the sandbox phase 0 had just spent a page verifying. They were
following this file, which is the correct thing for a hunt agent to do; the file
was wrong, and `SKILL.md` §5 and §10 said the opposite ("target code executes
**only inside the container**", "running a PoC outside a verified sandbox
because it looks harmless" listed among the things that will tempt you and are
wrong).

The document that is right is `SKILL.md`. You are about to execute an exploit
against code you have just concluded is exploitable, and the authoring step is
the one that runs the most novel code in the whole run.

So:

- **`execution_available: false` (Static mode)** — reason statically, build the
  source→sink argument, and set `needs_poc: true`. **Omit the `poc` object
  entirely**: the schema requires a real `run_output` inside it, and there is no
  honest value for that field when nothing ran. Say in the description what a
  later sandboxed run should try.
- **`execution_available: true` (Proof mode)** — you **must** write a PoC, and
  `poc_execution` is the concrete recipe for this repo's Python runtime. Write
  it to be correct by construction and hand it over. **Phase 2b runs it**, in a
  fresh container, three times, under an observer you never touch, and the gate
  judges that — not anything you ran.

What this costs you is the ability to iterate against a live interpreter, and
that is a real cost. Two things pay it back:

- The gate has never read your transcript anyway. `poc.run_output` is not the
  gate's input and never was (`SKILL.md` §3): replay captures its own. A PoC you
  ran successfully on the host and a PoC you reasoned about carefully reach the
  gate as exactly the same artifact.
- `poc.notes` is where you say what you could not check. "I could not verify
  that `Meta.schema_name` accepts a newline without running it" is useful to
  phase 2c and costs nothing. A guess presented as a result is what costs.

If you believe a PoC needs a trial run to be worth writing, say so in
`poc.notes` and write your best version. Do not run it.

### 6.4 Writing the PoC

**`poc.code` must be a complete, standalone script.** Phase 2b takes that exact
text, writes it into a fresh container built from the unmodified image, and runs
it there — nothing else of yours crosses. A PoC that depends on a helper you
left in `scratch_dir`, on a variable you set in your shell, on a fixture file
you created by hand, or on a `cd` you performed earlier will not reproduce, and
the finding will be recorded unproven for a reason that is entirely about your
packaging. Put the setup **inside** the script: create the fixtures it needs,
import what it needs, and make it runnable as `python3 poc.py` from any working
directory.

**Read `poc_execution.deps_hint` before writing a line.** It tells you how to
reach the target's own dependencies. A PoC that cannot import the target proves
only that hello-world runs. Verify the target's symbol is actually reachable
first — then write the exploit.

**Enter through the target's own code path.** Call the public entry point named
in the task: the route handler, the CLI command, the parser, the service
function. A PoC that calls `os.system` (or `pickle.loads`, or `cursor.execute`)
**directly** proves nothing about the target — the gate will attribute the event
to your file and return `self_attributed`. If that happens, rewrite the PoC to
enter through the target and run it again; do not report it as evidence.

**Put the nonce in the payload, as a LITERAL, at authoring time.**
`poc_execution.nonce` is a token minted for this run and
`poc_execution.canary_path` is a path built from it. Your payload should cause
**the target** to touch that path — `; touch <canary_path>`,
`id > <canary_path>`, `open('<canary_path>','w')` — whichever fits your sink.
Your class file gives the shape for your sinks.

> **`os.environ.get("PYHUNT_NONCE")` is always `None` inside a PoC.** The audit
> hook pops `PYHUNT_NONCE` and `PYHUNT_OBSERVER_KEY` out of `os.environ` at
> import, before any PoC or target code runs. That deletion is deliberate: it is
> the measure that stops a hostile repository reading the nonce and printing a
> forged marker line. So a PoC written as
> `NONCE = os.environ.get("PYHUNT_NONCE") or "<literal>"` **silently uses the
> literal, every time**, and if that literal is stale the run comes back
> `sink_reached_unproven` — which is indistinguishable, in the report, from a
> working defence.
>
> This is not hypothetical. A real code execution was lost to it: three
> container transcripts showed the target's own frame compiling and running
> attacker-controlled Python as `uid=0(root)`, conditions 1, 2, 4 and 5 all
> satisfiable, and the verdict was `sink_reached_unproven` because condition 3
> had nothing to match. Copy the value out of `poc_execution.nonce` into your
> payload text. Do not read it at run time.

The nonce travels two independent ways: the observer stamps it onto every line
it prints, and your payload carries it in the event's own arguments. A payload
carrying the nonce is the one that survives a lost stamp, and a materialised
canary is the strongest evidence available — it cannot be explained by the sink
merely running.

**Write the PoC to run under the observer; do not run it yourself.**
`poc_execution.observer` describes the instrumentation phase 2b will arm around
your script: `available_check`, the `{cmd}` template in `observer.wrap`, and
`evidence_markers` — the substrings whose presence in the transcript means the
dangerous operation fired. Phase 2b performs the substitution and the run. Read
`observer.notes` for that mechanism's blind spots before you decide what your
PoC should assert — a PoC aimed at a sink the observer cannot see is a PoC that
will come back `no_event` however good it is.

`observer.files` are the helper assets; the harness materialises its own copies
inside the container, from the skill, so nothing you place beside them travels.

**Know what the observer can and cannot see.** It is a PEP-578 audit hook, so it
records exactly these CPython events and nothing else:

```
subprocess.Popen   os.system   os.exec   os.spawn   os.posix_spawn   os.startfile
open   socket.connect   socket.getaddrinfo   urllib.Request
exec   compile   pickle.find_class   marshal.load   marshal.loads   ctypes.dlopen
```

There is **no event for a SQL query, a template render, a log write, an
authorization decision, or an HTML response.** A vulnerability whose sink raises
none of the above will produce `no_event` no matter how real it is. That is a
limit of the instrument, not a verdict on the code — your class file tells you
which of your sinks are observable, and what to assert on when none of them is.

Two filters are worth knowing because they will otherwise eat your evidence:
`open` is suppressed for paths ending in `.py`, `.pyc`, `.pyi`, `.so`, `.pyd`,
`.dll`, `.egg` and for anything under the interpreter's own prefix (that is
import noise); and `exec`/`compile`/`marshal.*`/`open` are suppressed when the
call came from inside the import machinery. Aim your payload somewhere the
filter does not reach — the canary path is chosen to be exactly that.

**Read the attribution on every marker.** Each marker line ends with
`<- from <file>:<line> in <func>`, naming the code that performed the dangerous
operation. Event and attribution are one line — that is what the parser expects:

```
[PYHUNT-OBSERVER] n=a3f19c22b7d40e51 audit:subprocess.Popen ('/bin/sh', ['/bin/sh', '-c', 'echo hi; touch /tmp/pyhunt-canary/a3f19c22b7d40e51'], None, None)  <- from /target/app/reports.py:7 in build_report
```

That line is proof: the target's own frame spawned a shell and the shell's
command string carries the nonce. Change the attribution to
`/work/hunt/h_inj_01/poc.py:3 in <module>` and the same line proves nothing —
your PoC hit the sink directly. A marker on its own only says *a process was
spawned*, which innocent code does too; the attribution is what ties it to the
vulnerability.

For calibration, these are the four outcomes the gate actually returns for the
four canonical shapes — verified against `scripts/oracle/gate.py`, not
paraphrased:

| What ran | Marker | Outcome |
|---|---|---|
| target does `subprocess.run("echo hi; " + name, shell=True)` | argv[0] `/bin/sh`, nonce inside the command string | `proven` |
| target does `subprocess.run(["echo", "hi", name])` | argv[0] `echo`, nonce sitting in argv[2] | `sink_reached_unproven` |
| your PoC calls `subprocess.run(..., shell=True)` itself | attributed to `poc.py` | `self_attributed` |
| an IDOR, whatever you ran | irrelevant | `not_applicable` |

**Put the canary near the front of the payload.** The observer renders each
event's arguments with `repr()` **truncated at 200 characters**, and the gate
looks for the nonce inside that rendered text. A payload that carries the canary
after 300 characters of decoy is a payload whose nonce the gate never sees.

### 6.5 `poc.run_output` — verbatim, complete, unedited

**`poc.run_output` must be the COMPLETE combined stdout+stderr of the observed
run, exactly as it was printed.**

Not a summary. Not "the interesting part". Not a paraphrase. Not reconstructed
from memory after the fact. Not cleaned up, re-indented, de-duplicated or
re-ordered. Those marker lines are the only input the gate has; text you trimmed
is evidence the gate cannot see, and a proven finding becomes an unproven one
because of an editing decision you made for readability.

If the output is enormous, that is fine — paste it. If it contains the target's
own noise, paste that too.

### 6.6 State your observer decision in `poc.notes` — always, in one line

Exactly one of:

- `observer python-audit-hook: evidence captured (<marker>)`
- `observer python-audit-hook: available_check failed (<what was missing>)`
- `observer python-audit-hook: armed, no markers`
- `observer python-audit-hook: not applicable — <reason>`

Deciding the observer is irrelevant is a perfectly good answer; a
CPU-exhaustion PoC spawns no process and opens no socket, so a
process/file/socket observer has nothing to record and the timing curve is the
evidence. **Not saying anything is not an answer.** A finding whose notes are
silent about the observer is indistinguishable from one where the wrapper
failed silently or the instruction was ignored, and no reviewer can tell which.

### 6.7 The honesty rules

**An observer is corroboration, never a verdict.** If `available_check` fails,
or the wrapped run produces no marker lines, that is **not** evidence the
finding is false. Re-run the PoC unwrapped, judge it on its own assertions
exactly as you would with no observer available, and record in `poc.notes` that
the observer was unavailable or silent. Never drop or downgrade a finding
because an observer was unavailable.

**A missing runtime is not a failed exploit.** If the run fails because the
toolchain itself is absent (`command not found`), or the target's dependencies
cannot be reached at all, then this environment cannot execute this PoC. That is
the `execution_available: false` situation discovered late — **not** evidence
against the finding. Set `needs_poc: true`, keep the severity your static
argument justifies, record in `poc.notes` exactly which command was missing, and
never drop or downgrade the finding for it. A properly provisioned run can prove
it later.

**Undecidable-class rule — some real bugs cannot be settled by running code,
and dropping them is a recall bug, not precision.** Execution answers *"did this
behaviour occur?"*. It cannot answer *"was this behaviour allowed?"* — that
needs the intended policy, which does not exist in the runtime. So for a finding
whose whole claim is about intent rather than behaviour — broken access control
/ IDOR, privilege escalation, business-logic and workflow abuse, missing
authorization, mass assignment, insecure-by-design defaults, CSRF, rotatable
rate limits, weak crypto, hard-coded secrets — a PoC can show user A reading
user B's record and still not establish that doing so is wrong.

For these: DO report the finding, set `needs_poc: false`, and state in
`poc.notes`, in one line, **what you executed, what it showed, and the specific
policy question execution cannot answer** — e.g. "ran `get_order(2)` as user 1
and it returned user 2's order; whether cross-tenant reads are intended is not
decidable from the runtime — no owner check exists in the handler". Cite the
code that *should* have carried the check. **Never drop such a finding for want
of executed proof**, and never dress it up as proven either. The gate marks
these `not_applicable`, which is a fact about the class, not a failure of the
run, and the report counts them in their own denominator.

**The one place a failed attempt does cost something.** If neither an
observed run nor an unwrapped run produces a reproducible proof, **and** the
toolchain was actually present to attempt one, **and** the finding is not of an
undecidable class above — then lower severity by at least one step and say in
`poc.notes` exactly what you tried. The finding stays. Never apply even the
downgrade to a PoC that could not run, nor to a claim execution was never able
to settle. Later phases read code you have not read, and they get their turn.

---

### 6.8 The second oracle — declare a `structural_probe`

There is a whole population of real defects the audit hook cannot see, and until
recently the only honest thing PyHunt could say about them was `not_applicable`.
On one real run that was **74 of 145 findings** — every one accurate, every one
useless to a reader, because "no execution could settle this" says nothing about
whether the defect is real.

It is now settleable, deterministically, by a second oracle. Run:

```bash
python3 <skill>/scripts/structural.py kinds
```

for the vocabulary. Nine probe kinds:

| kind | settles | the differential it measures |
|---|---|---|
| `codegen_ast` | codegen / template injection into generated source | benign vs hostile render, then **where the parser puts the attacker's text**: an executable node, or an inert string constant |
| `growth_curve` | resource exhaustion, algorithmic complexity, unbounded allocation | cost at an ascending size ladder under `RLIMIT_AS`/`RLIMIT_CPU` in a forked child, against a benign rung that must complete |
| `state_mutation` | global-state contamination, shared registries, process-wide config | a named module global before and after a hostile call, against a benign control that must leave it unchanged |
| `exception_escape` | unhandled crashes reachable from attacker bytes | what escapes a public entry point on hostile input, against a benign call that must succeed |
| `differential_response` | **access control, IDOR, auth bypass, privilege escalation, information disclosure** | the same call made as two principals: does the unprivileged one receive a value only the privileged one should see? |
| `type_selection` | **unsafe reflection, type confusion, union collisions, mass assignment** | change only the attacker-controlled field: does a **different class** get constructed? |
| `config_assertion` | **supply chain, CI and IaC misconfiguration** | parse the committed workflow/config and evaluate one assertion from a closed vocabulary against a dotted path. No target code runs at all. |
| `sink_semantics` | **SQL/NoSQL injection, command injection, path traversal, zip-slip, SSRF, open redirect, XSS, SSTI** | the dangerous callable is **wrapped so it captures and never runs**, then what actually arrived is analysed: did the payload become syntax, or is it still data? |
| `flow_witness` | **SQL injection, XSS, open redirect, SSTI, log/header injection** — every class CPython raises no audit event for | whether a sentinel-bearing value is **live in the claimed sink's frame at the claimed line**, traced with `sys.settrace` scoped to the target's own frames |

#### Access control is measurable. Business logic is not.

Three classes were previously filed as "policy questions no measurement
answers". That was true of one of them and wrong about the rest, and the
distinction is worth holding onto:

- **Authorisation has an observable definition** — two principals, one call,
  different answers. `differential_response` plants a sentinel only the
  privileged context should see and asks whether the unprivileged one gets it.
  Two reads, nothing written, nothing exploited.
- **Dispatch steering is a type comparison.** `type_selection` changes only the
  attacker-controlled field and asks whether a different class comes back. This
  is the union name-collision shape.
- **A workflow file is data.** Whether the job holding a publishing credential
  has an `environment:` gate is a key lookup. `config_assertion` parses the
  committed bytes and evaluates one assertion — `key_absent`, `key_present`,
  `value_equals`, `value_matches`, `value_not_matches`.

**What stays judgment-only: business logic.** `business_logic`, `logic_error`
and `logic_chain` get no probe and never will. A probe claiming to settle "this
refund flow can be replayed" would be inventing a measurement, and that is the
category error the `not_applicable` bucket exists to prevent. Report those on
their static argument and say so.

One trap worth knowing about `config_assertion`: **YAML turns bare `on` into the
boolean `True`.** Every GitHub workflow starts with `on:`, so the trigger block
parses under a key of `True`. The harness resolves `on`, `off`, `yes` and `no`
to their boolean forms; without that, `on.push.tags` would report "key absent"
on every workflow ever written.

#### `sink_semantics` — the non-intrusive PoC, done properly

This is the probe to reach for whenever a dangerous callable can be named. It
makes **both** of the claims a reader needs, and `flow_witness` only makes the
first:

1. the payload **reaches** the dangerous construct, and
2. it arrives as **syntax**, not as data.

The harness wraps the callable you name in `intercept` with a shim that captures
its arguments and raises immediately. **The operation is never performed** — no
query executes, no file opens, no request leaves the container. Then it calls
your entry point twice, benign and hostile, and analyses what arrived.

```json
"structural_probe": {
  "kind": "sink_semantics",
  "target": "pkg.api.lookup",
  "intercept": "pkg.db.run_query",
  "argument": 0,
  "semantics": "sql",
  "benign_args": ["$PYHUNT_BENIGN"],
  "hostile_args": ["x' OR '$PYHUNT_NONCE'='"],
  "rationale": "the name parameter reaches the query builder unescaped"
}
```

On a real vulnerable/parameterised pair this produces:

| | what arrived at the sink | verdict |
|---|---|---|
| concatenated | `SELECT * FROM t WHERE n = 'x' OR '<nonce>'=''` | **demonstrated** — the span broke out of the literal |
| parameterised | `SELECT * FROM t WHERE n = ?` | **refuted** — the payload never entered the SQL text |

Six analysers, and the vocabulary is closed: `sql`, `path`, `url`, `shell`,
`html`, `format`. Each asks one question — did the attacker's text acquire
grammatical force in *that* grammar?

Three things to get right:

- **`intercept` is the Python-level callable your target actually calls**, not
  the driver method underneath it. `sqlite3.Cursor.execute` lives on an
  immutable C type and cannot be wrapped at all; the harness says so and names
  the alternative. The wrapper is usually the more meaningful boundary anyway.
- **Put the whole attack in `hostile_args`, not just the sentinel.** The
  analyser examines the span *you* injected. `"x' OR '$PYHUNT_NONCE'='"` is
  analysable; `"$PYHUNT_NONCE"` alone tells it nothing about quoting.
- **The benign control must be benign.** The differential is what makes this
  evidence: a builder that renders every value as structure is broken in a way
  that says nothing about this attacker.

#### `flow_witness` is the one that answers a question the others assume

The other four ask whether a dangerous property holds. This one asks the prior
question: **does the attacker's data actually arrive?** It needs no dangerous
operation to fire, which is why it reaches the classes the audit hook is blind
to — a fully successful SQL injection raises no audit event, so the execution
gate could never settle it however sound the finding is.

Its negative result is worth as much as its positive one. *"Not witnessed, last
seen at `validators.py:88`"* is a precise, checkable statement that a sanitiser
exists and works, **on the line it works**. That is what phase 2c currently has
to establish by reading.

Declare three things:

```json
"structural_probe": {
  "kind": "flow_witness",
  "target": "pkg.api.handle_search",
  "entry_args": ["name=evil-$PYHUNT_NONCE-'"],
  "sink_location": "pkg/db/query.py:41",
  "rationale": "the `name` parameter reaches raw string concatenation into SQL"
}
```

- `target` — the **public entry point**, not the sink. The point is to trace the
  path an attacker actually has.
- `entry_args` / `entry_kwargs` — must contain `$PYHUNT_NONCE` somewhere. The
  sentinel is the entire mechanism; without it the tracer cannot tell the
  attacker's value from any other string the target is holding. A spec without
  it is refused with exit 2.
- `sink_location` — `file:line`, exact. The verdict is the claim that the
  sentinel is live in **that** frame at **that** line, so an approximate line
  makes the result meaningless.

**Arrival is graded, and you should understand why before reading a verdict.**
The probe distinguishes a value that arrived *byte-for-byte as supplied* from
one that arrived *transformed*. Only the first is `demonstrated`. This is not
pedantry: a sanitiser that strips quotes leaves a hex nonce untouched, so a
properly defended path still reports "the sentinel arrived". It arrived
harmless. `refuted` in that case names the last frame that held the value
unaltered — which is where the transform lives.

Two limits, stated so you do not discover them as surprises:

- `sys.settrace` costs 10–50× in wall time. The probe is bounded by the same
  container timeout as everything else and reports `event_cap_reached` rather
  than truncating silently.
- The trace does not follow values through C extensions. A value that transits a
  C decoder is seen entering and leaving but not inside; that is reported as a
  bounded trace, never as a negative result.


**You declare data. You do not write the assertion.** That is the whole design.
A PoC that parses its own output and asserts "the marker became a syntax node"
is the party with an interest in the answer grading its own work — the exact
failure the execution gate exists to remove. So the probe is a JSON object on
the finding: a dotted callable, a benign input, a hostile input. PyHunt's own
harness runs it inside the container, computes the property, signs the result,
and `oracle/structural.py` decides. There is nowhere in the spec to put code,
and a spec carrying an unknown key is refused with exit 2 rather than ignored.

```json
"structural_probe": {
  "kind": "codegen_ast",
  "target": "pkg.model_generator.generator.ModelGenerator.render",
  "construct": "pkg.model_generator.generator.ModelGenerator",
  "benign_args": [{"type": "record", "name": "M",
                   "doc": "an ordinary docstring $PYHUNT_BENIGN"}],
  "hostile_args": [{"type": "record", "name": "M",
                    "doc": "x\"\"\"\n    pyhunt_$PYHUNT_NONCE()\n    \"\"\""}],
  "rationale": "the doc field is interpolated into a triple-quoted docstring with no escaping"
}
```

Four rules that decide whether your probe is worth anything:

1. **`$PYHUNT_NONCE` goes in the hostile input; `$PYHUNT_BENIGN` goes in the
   benign one.** The harness substitutes both. The benign marker is minted by
   the harness, not by you, so a control cannot be chosen to collide with the
   payload. For `codegen_ast` the nonce in the payload is **mandatory** — the
   claim is that *this* string became code.
2. **Prefer the nonce as an identifier** (`pyhunt_<nonce>()`) over the nonce
   inside a string argument. Both work — the harness reads the enclosing
   statement as well as the innermost node — but an identifier makes the answer
   unambiguous in one field.
3. **`target` must resolve inside the target.** The harness reports
   `inspect.getfile()` of the callable it actually called, and a path outside
   the target roots fails condition S-2 and the whole probe is discarded. This
   is condition 4's analogue and it fails closed.
4. **The benign control must work.** If the control render does not parse, or
   the control call raises, or the benign marker never reaches the output, the
   probe is a `probe_error` and says nothing. One-sided evidence is not
   evidence: a generator that emits a call node for every input is doing its job.

A probe can come back **`refuted`** — the differential ran and the defence held.
That is a real result and it is *supposed* to be possible. It never deletes your
finding, and phase 2c will read it; a verifier confirming past a `refuted` probe
has to say why in writing. If your probe is refuted and you still believe the
finding, the useful thing is to say in `poc.notes` what the probe could not see.

Declare a probe whenever your finding's class is in the table above. A finding
in one of those classes with no probe is a finding that will be reported on its
static argument alone, and the report now says so by name.

---

## 7. Output

Write **one JSON object** to `<results_dir>/logs/hunt/<unit_id>.json` and
nothing else there. It must validate against `schemas/finding.schema.json`:

```json
{
  "task_id": "t_taint_03",
  "findings": [
    {
      "finding_id": "f_reports_shell_concat_1",
      "file": "app/reports.py",
      "line_start": 7,
      "line_end": 9,
      "vuln_class": "command_injection",
      "cwe": "CWE-78",
      "severity": "high",
      "description": "…what an attacker gains, at least 20 chars, no hedging…",
      "evidence_snippet": "…verbatim code…",
      "confidence": 0.9,
      "hedged_language": false,
      "needs_poc": false,
      "poc": {
        "language": "python",
        "code": "…the exploit, verbatim…",
        "run_output": "…COMPLETE combined stdout+stderr, verbatim…",
        "succeeded": true,
        "notes": "observer python-audit-hook: evidence captured (audit:subprocess.Popen)"
      }
    }
  ],
  "gaps_observed": [
    {"file_or_subsystem": "app/legacy/",
     "reason": "exceeded read budget; 4200 lines unread",
     "suggested_attack_class": "path_traversal"}
  ],
  "files_read": ["app/routes.py", "app/db.py", "app/validators.py"]
}
```

Rules the schema does not state:

- **`files_read` is required, and it means what it says.** Every repo-relative
  path you actually opened, including files you opened and found irrelevant.
  Phase 3 joins it against your task's `target_files` and reports the
  difference.

  The coverage ledger is *input*-level: it proves every enumerated input reached
  a disposition. It cannot see that a unit assigned five files answered from
  two. That unit's task has an outcome, its inputs have dispositions, and the
  coverage number reads full — the gap has no name and produces no warning.
  This field is the only thing that gives it one.

  **Report short and honest rather than complete and false.** An unread file is
  a gap the sweep re-queues; an inflated list is a coverage claim nothing
  downstream can check. Not reading a file is a normal outcome and is never
  held against you. Claiming you did is the one thing that breaks the ledger.

- **`task_id`** is the task this object reports on. If your chunk held several
  tasks, emit one object per task — as a JSON array of these objects in the same
  file — so no finding loses its provenance.
- **`finding_id`** is `f_<task_id without its leading `t_`>_<n>`, lowercase,
  matching `^f_[a-z0-9_-]{1,64}$`.
- **`file`** is repo-relative. Absolute paths are rejected.
- **Never emit an `execution` object.** PyHunt computes it and overwrites
  anything found there.
- **`needs_poc: true` means execution was unavailable.** It does not mean "my
  PoC did not work" — the gate records that itself, and it never deletes a
  finding.
- **`vuln_class`** is the specific class, not your class-group label. Your class
  file names the strings that matter and says why the exact string is
  load-bearing.
- No prose, no markdown fence, no commentary around the JSON.

Then return a message of **20 words or fewer** naming your `unit_id`, the number
of findings, and the number of gaps. The orchestrator reads the file, not your
message; a long return message only burns its context.

---

## 8. Constraints

- **Emit findings only for your class group.** Anything else you notice goes
  into `gaps_observed` with a `suggested_attack_class`. It is not lost — the
  sweep re-queues it.

- **If you CLEAR a surface, record it as a dismissal — with the question you
  asked.** This is the recall rule, and it exists because of a specific,
  expensive miss. A sweep once cleared every `.fake()` method in a library with
  the reasoning: *"`random.choice` / `random.randint` / `uuid.uuid1` all appear
  exclusively inside `.fake()` methods, whose entire job is synthetic test
  data."* That is correct for the question it was asking — weak randomness — and
  wrong for the one it was not: a schema-supplied `size` and `max_digits` field
  driving an unbounded allocation. Two real findings were lost, and nothing in
  the run recorded that the surface had been looked at *under one lens only*.

  So when you decide a whole file, directory, or family of methods is not
  interesting, that is not silence — it is a `gaps_observed` entry whose
  `reason` names **the lens you applied**, in the form "cleared for <class>:
  <why>". Phase 3 re-queues a cleared surface under every *other* lens that
  would touch it. "Cleared under lens X" is not the same as "covered", and the
  ledger now knows the difference.

- **Zero findings is a valid, respectable output** when the code is clean. Do
  not pad the queue with low-confidence noise, and never invent a `high`.
- **Do not refactor anything, do not comment on style, do not fix what you
  find.** PyHunt is a scanner. Remediation is a different skill entirely.
- **Network egress is off.** Local loopback and the sandbox's own services only.
  Never point a PoC at a host the operator did not authorise.
- Stay inside `scratch_dir` for every file you write.
