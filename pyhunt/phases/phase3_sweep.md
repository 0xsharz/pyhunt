# Phase 3 — Sweep: siblings, and honest denominators

> **Reads:** `${RESULTS_DIR}/findings/*.json`, `${RESULTS_DIR}/proof/*.json`,
> `${RESULTS_DIR}/verify/*.json`, `${RESULTS_DIR}/inputs.json`,
> `${RESULTS_DIR}/tasks.json`, and the target repository.
> **Writes:** new tasks appended to `${RESULTS_DIR}/tasks.json`,
> `${RESULTS_DIR}/coverage.json` (written by `coverage.py`, never by hand), and
> the sweep table at `${RESULTS_DIR}/logs/sweep_table.md`.
> **Gate:** Phase 4 may not start until `coverage.py assert-complete` exits `0`.
> Exit `2` fails the run — an incomplete scan is never reported as a complete
> one.

Findings have been hunted, replayed against the gate, and adversarially
verified. This phase does two jobs before the report is allowed to exist: it
hunts the **siblings** of every confirmed bug, and it **closes the coverage
ledger** so the report's denominators are true.

`${PYHUNT_DIR}` is the skill directory, `${RESULTS_DIR}` the timestamped results
directory, `${TARGET}` the repository under scan. Where a flag below does not
match, run the script with `--help`: the script is authoritative, and a non-zero
exit is never routed around.

---

# Job 1 — the sibling sweep

## The premise

A confirmed bug at one location is **evidence about a pattern, not about a
line.** A codebase that concatenated a request parameter into a shell command in
one export handler wrote the other twenty handlers with the same idiom, the same
helper, and the same habits. The value of a confirmed finding is not the finding;
it is what it tells you about how this codebase exposes bugs:

- a shared helper that was supposed to be safe and is not
  (`archive_utils.safe_extract`);
- a framework idiom that turns out to be insecure (a custom deserializer that
  trusts a class hint);
- an entry-point shape that skips a check (`@bp.route` handlers that accept JSON
  with no schema validation).

Phase 2 hunted where the taint graph and the input inventory pointed. The sweep
catches the instances **no enumerated input reached** — a sink called from a
cron job, a background worker, a management command, an internal RPC handler,
a code path that starts nowhere the inventory covers.

## Tools

Read, Grep, Glob. The sweep produces **tasks**, not findings, so it needs no
execution: every task it emits re-enters the pipeline at phase 2 and is judged
by exactly the same gates as any other.

## Method

For each **confirmed** finding (and each `proven` one, which is the strongest
signal available about which patterns this codebase actually gets wrong):

**1. Name the transferable pattern.** One sentence, concrete. Not "input
validation issues" — "`request.args` interpolated into a `subprocess` command
string via `shell=True`", or "`yaml.load` without `SafeLoader` on a request
body".

**2. Build two grep patterns and search with both.**

- a **source-construction** pattern — the vulnerable construction itself
  (`shell=True` alongside a variable; f-string interpolation into a path; `+`
  concatenation into a query);
- a **sink** pattern — the dangerous call (`subprocess.run`, `os.system`,
  `yaml.load`, `pickle.loads`, `eval`, `open`, `requests.get`).

One pattern alone always misses half. The source pattern catches the same unsafe
construction feeding a **different** sink; the sink pattern catches the same sink
reached from a **different** source. Use Grep's `glob` to scope to `*.py`.

**3. Expand transitive callers.** For any shared helper involved, grep for its
importers, then the importers of *those*, until you reach entry points or the
chain is exhausted. Wrapper functions and re-exports are exactly how a direct
grep misses an instance.

**4. Verify the receiver, not the name.** A method name that exists on several
types can mean different things (`x.contains(...)` on a string is a substring
match; on a set it is exact membership). Trace the variable's declaration.
Sibling variables in the same scope may have different types even when they come
from the same config load.

**5. Triage every hit.** For each instance: `file:line`, the interpolated
variable(s), whether the value is attacker-controlled (**trace backward** through
storage reads, state services and property getters — "looks server-controlled at
this call site" is not sufficient), what mitigation exists if any, and a verdict:

| Verdict | Meaning | What happens |
|---|---|---|
| `candidate` | Plausibly reachable with attacker data | Becomes a hunt task |
| `mitigated` | A defence covers it — cite the `file:line` you read | Recorded, not queued |
| `already-hunted` | A phase 2 task already covered this file with this attack class | Recorded, not queued |
| `unreachable` | No production path — cite the guard | Recorded, not queued |

**Account for every hit.** If the grep found 20 and you queued 3, the table says
"20 found, 3 candidates, 15 mitigated, 2 already hunted" — never "3 found, 3
queued". An unaccounted hit is an untriaged one.

## Also sweep these, whenever one instance was confirmed

- **Unauthenticated management or debug endpoints** → sweep every route
  registration and every listener bind that omits auth. Each is separate.
- **Hardcoded secrets** → sweep all of them, source and config alike
  (`api_key`, `secret`, `password`, `token`, `credential`, `private_key`).
- **Weak crypto** → audit every cryptographic call: algorithm, mode, padding,
  KDF iteration count, entropy source.
- **Sanitizer misuse** → find every call to that sanitizer and check each
  against its own sink's context.
- **Sibling handlers with asymmetric auth** → in every router or controller file
  you opened, compare authentication across all handlers. A handler that omits
  what its siblings require is a candidate.

## Gapfill: the axis the sweep does not cover

The sibling sweep is driven by what was *found*, which biases it toward classes
that already landed — once SQL injection lands, the next twenty hunts all look
like SQL injection. Push back once, deliberately:

1. Build a `subsystem × attack_class` matrix from `tasks.json`. Mark the cells
   that ran.
2. Aggregate `gaps_observed` from every phase 2 output — each gap is an area
   that was opened and not finished.
3. Queue the empty cells that plausibly apply: an area named in `gaps_observed`,
   a subsystem with no findings at all, or an attack class never attempted
   against a subsystem where it makes sense (`xxe` against an XML parser, not
   against a CSV reader).

### 3a. Re-queue every DISMISSED surface under the other lenses

This is the recall step, and it exists because of a miss that cost two real
findings. A sweep cleared an entire `.fake()` surface with the reasoning:

> "`random.choice` / `random.randint` / `uuid.uuid1` / `uuid.uuid3` all appear
> exclusively inside `.fake()` methods, whose entire job is synthetic test data."

Correct for the question it was asking — weak randomness — and wrong for the one
it was not: two of those methods read a schema-supplied `size` and `max_digits`
straight into an allocation. The surface had been *cleared under one lens* and
the ledger recorded it as covered, so nothing ever looked again.

So: **"cleared under lens X" is not "covered".** Scan every `gaps_observed`
entry whose `reason` begins `cleared for <class>:` (`phase2_shared.md` §8
requires that form) and, for each one, queue a task under **every other lens
whose `_LENS_SIGNALS` would touch that path** — `scripts/specialists.py` holds
the signal table. Set the new task's `rationale` to name both the original
dismissal and the new question:

```json
{"task_id": "t_dis_3", "source": "dismissal",
 "attack_class": "resource_exhaustion",
 "target_files": ["dataclasses_avroschema/fields/fields.py"],
 "scope_hint": "the .fake() methods, asked about SIZE rather than randomness",
 "rationale": "cleared for weak_crypto (\"synthetic test data\"); the resource lens has not asked whether a schema-supplied size reaches an allocator here"}
```

Bounded like everything else in this phase — cap at the same fan-out limit — and
if the cap truncates the re-queue, say how many were dropped. A dismissal that
was never re-examined under another lens is itself a `gaps_observed` entry for
the report.

## Emitting tasks

Append to `${RESULTS_DIR}/tasks.json`. Each task validates against
`${PYHUNT_DIR}/schemas/hunt_task.schema.json`:

```json
{
  "task_id": "t_fb_1",
  "source": "feedback",
  "attack_class": "command_injection",
  "scope_hint": "cli/admin.py:88 builds a shell string from the --name option, same shape as f_reports_shell_concat; trust boundary is the CLI argument",
  "target_files": ["cli/admin.py"],
  "rationale": "Sibling of f_reports_shell_concat: same shell=True concatenation idiom, different entry point",
  "priority": 2
}
```

- `source: "feedback"` and `task_id` prefix `t_fb_` for sibling-sweep tasks;
  `source: "gapfill"` and prefix `t_gf_` for matrix-gap tasks.
- `priority` is an integer 1–5 (1 = highest), never a string.
- `rationale` must name **which finding's pattern** motivated the task.
- Do not re-queue a `(target_file, attack_class)` pair that already ran.

## Bounds, and what happens at the bound

Budget enforcement is advisory in a skill — there is no per-task abort hook —
so the bound is here, in the instructions, and the honest half is kept:

- **At most 40 new tasks** across both jobs combined.
- **One round. No recursion.** Sibling tasks that confirm do not seed a second
  sweep in this run. Otherwise the sweep is a fixed point that never terminates
  on a repository with a consistent idiom.
- **Everything over the bound is recorded, not forgotten.** A candidate instance
  you could not queue is written to the sweep table with verdict
  `deferred (cap)` and its `file:line`, and it flows into the report's "what
  this scan did not look at" section. An instance dropped silently is a false
  negative that nobody can see.

New tasks run the **full** pipeline: phase 2 hunt → phase 2b replay and gate →
phase 2c verify. **A sibling is never assumed exploitable because its cousin
was.** Different call sites have different upstream validation, different data
flows, and sometimes a defence the original site lacked.

## Sweep output

Write the table to `${RESULTS_DIR}/logs/sweep_table.md` so phase 4 can quote it:

| Root cause | Source pattern | Sink pattern | Found | Candidates | Mitigated | Already hunted | Deferred |
|---|---|---|---|---|---|---|---|
| `shell=True` with request data | `shell\s*=\s*True` | `subprocess\.(run\|call\|Popen)` | 20 | 3 | 15 | 2 | 0 |
| `yaml.load` on request body | `yaml\.load\(` | `yaml\.load\(` | 4 | 1 | 3 | 0 | 0 |

Use the count from grepping, not the count you chose to highlight.

---

# Job 2 — close the ledger

## What this is for

Recon enumerated every attacker-controllable input it could find into
`inputs.json`. Unless every one of those inputs is accounted for, the report's
denominators are decoration: "we found 3 vulnerabilities" reads very differently
depending on whether 4 or 400 inputs were examined, and a scan that examined 12
of 90 inputs and says nothing about the other 78 has told the reader something
false by omission.

So the run does not get to end until every enumerated input carries a
disposition. **`coverage.py` asserts it, and the run fails rather than reporting
an incomplete scan as a complete one.**

## The commands, in order

```bash
# 1. Give every enumerated input a disposition and the evidence for it.
python3 "${PYHUNT_DIR}/scripts/coverage.py" classify \
  --results-dir "${RESULTS_DIR}"

# 2. Re-queue the uncovered ones as hunt tasks (bounded). THIS WRITES
#    tasks.json — it appends, backs the file up first, and reports `written`.
python3 "${PYHUNT_DIR}/scripts/coverage.py" reconcile \
  --results-dir "${RESULTS_DIR}"

#    → run the emitted t_rc_* tasks through phase 2 → 2b → 2c,
#      then re-run `classify` so their results land in the ledger.

# 3. Re-ask every dismissed surface under the lenses that did not dismiss it.
python3 "${PYHUNT_DIR}/scripts/lens_matrix.py" run \
  --results-dir "${RESULTS_DIR}"

# 4. Re-queue findings the structural oracle could settle and was never asked to.
python3 "${PYHUNT_DIR}/scripts/coverage.py" probe-gap \
  --results-dir "${RESULTS_DIR}"

#    → steps 3 and 4 emit tasks. Run them through phase 2 → 2b → 2c like any
#      other, then return here.

# 5. Report which assigned files no unit ever opened.
python3 "${PYHUNT_DIR}/scripts/coverage.py" read-ledger \
  --results-dir "${RESULTS_DIR}"

#    → for each file in `unread_files` that belongs to a task whose outcome was
#      `clean`, queue it. A clean verdict over a file nobody opened is not a
#      clean verdict.

# 6. Repair any class that disagrees with its own CWE, then collapse same-site
#    findings. Order matters: dedupe groups by class family, so a mislabelled
#    finding groups into the wrong one.
python3 "${PYHUNT_DIR}/scripts/findings_io.py" class-repair \
  --results-dir "${RESULTS_DIR}"
python3 "${PYHUNT_DIR}/scripts/dedupe.py" run \
  --results-dir "${RESULTS_DIR}"

#    Then the tier above it: group same-root-cause SITES into advisories.
#    dedupe answers "is this the same line"; this answers "is this the same
#    defect", which is the question a maintainer actually has.
python3 "${PYHUNT_DIR}/scripts/cluster.py" run \
  --results-dir "${RESULTS_DIR}"

# 7. Assert the ledger is complete. Exit 2 = the run fails.
python3 "${PYHUNT_DIR}/scripts/coverage.py" assert-complete \
  --results-dir "${RESULTS_DIR}"
```

**Check that step 2 actually wrote.** Its JSON reports `written`, `tasks_total`
and `backup_path`; if `written` is 0 while `requeued` is not, stop. This step
used to print the tasks on stdout and mutate nothing, with no phase file saying
who was supposed to perform the append — so on a real run it emitted 20 `t_rc_*`
tasks against 54 uncovered inputs, `tasks.json` was unchanged, and **every gate
downstream still passed**, because `uncovered` is a legal disposition. The
result would have been a report claiming an honest ledger over a re-queue step
that silently did nothing.

**Steps 3 and 4 are the recall pair, and both used to be prose.**
`lens_matrix.py` reads every `gaps_observed` entry of the form
`cleared for <class>: <why>`, resolves the lens that cleared it, and emits a
task for every *other* lens whose path signals touch that file. Fed the exact
wording that lost two findings — *"random.choice / random.randint / uuid.uuid1
all appear exclusively inside `.fake()` methods, whose entire job is synthetic
test data"* — it produces a `resource_exhaustion` task on `fields.py`, which is
precisely the question nobody asked.

`coverage.py probe-gap` does the same for the second oracle: a finding whose
class the audit hook cannot see, carrying no `structural_probe`, becomes a task
whose job is to author one. On the recorded run that would have been **88
findings across 14 sites**, against 1 probe actually declared. An oracle nobody
is required to invoke produces the same report as no oracle.

Both write their tasks, back `tasks.json` up first, and read it back — because
the failure they exist to prevent is a step that reports success and changes
nothing.

**Step 5 is the third member of that family, and it is a report rather than a
gate.** `coverage.py read-ledger` joins each hunt unit's `files_read` against
its task's `target_files` and names every file that was assigned and never
opened. The coverage ledger cannot see this: it is input-level, so a unit given
five files that answers from two still produces a task outcome, input
dispositions, and a full coverage number.

It does not exit 2, deliberately. A file legitimately goes unread — answered
from elsewhere, or generated — and failing the run for it would push units
toward inflating `files_read`, converting a measurable gap into an unmeasurable
lie. Naming the file is what makes it actionable.

**Step 5 is what stops the report drowning the reader.** `dedupe.py` groups
findings by (file, class family, adjacent line range), picks the canonical by
evidence rather than by luck — proven beats demonstrated beats severity, with a
deterministic tie-break so two runs over the same inputs agree — and stamps
`group_id` / `is_canonical` / `independent_units`. Nothing is deleted:
non-canonical records keep their file, their PoC and their verdict, and phase 4
renders them as located "also at" references.

Both halves matter. On a real run 127 delivered findings sat on 81 distinct
sites (`base.py:240` was filed five separate times), and a reader had to do the
deduplication the tool should have done. But 21 of 55 sites had been filed
independently by two or more hunt units that could not see each other's work,
and *that* is corroboration — several agents, each reading only its own scope,
landing on the same line. It used to be thrown away by the very step that
noticed it. `independent_units` keeps it, and phase 4 prints it.

`classify` writes `${RESULTS_DIR}/coverage.json`:

```json
{
  "inputs": [
    {"input_id": "i_07", "disposition": "covered",
     "evidence": "finding f_reports_shell_concat touches reports.py"},
    {"input_id": "i_08", "disposition": "uncovered",
     "evidence": "no finding file or task scope reached this input"}
  ],
  "totals": {"enumerated": 90, "covered": 84, "uncovered": 6}
}
```

## `uncovered` is an honest disposition. *No* disposition is a broken ledger

This distinction is the whole point, and it is easy to get backwards.

- **`uncovered`** means the run looked and nothing reached this input. It is a
  legitimate, reportable outcome. It appears in the report under "what this scan
  did not look at", with its reason. A scan with six uncovered inputs and a
  sentence saying so is an honest scan.
- **No disposition at all** means the ledger does not know what happened to this
  input — nobody classified it, or the classification pass never ran. That is
  not a result; it is a bookkeeping failure that would let an unexamined input
  be silently counted as examined.

`assert-complete` exits `2` on the second case: an input with no disposition, or
`covered + uncovered ≠ enumerated`. **Do not route around exit 2.** Do not
hand-edit `coverage.json`, do not delete the offending input from `inputs.json`,
and do not proceed to phase 4. Diagnose why the input was never classified —
usually a phase that failed and was not recorded, or a task whose output never
landed — fix it, and re-run.

## Rules for dispositions

- **A disposition needs evidence, and the evidence is mechanical.** An input is
  `covered` when a finding's file matches its location, or when its entry point
  appears in some task's scope. "I read that file" is not coverage, and neither
  is "that input is obviously safe" — an input judged safe by a hunt task is
  covered *by that task*, and the task is the evidence.
- **Never mark an input covered by hand.** `classify` derives dispositions from
  `findings/` and `tasks.json`. If it says uncovered and you disagree, the fix is
  a task, not an edit.
- **Failed tasks are not coverage.** A hunt task that errored, timed out, or was
  dropped at a cap leaves its inputs uncovered. It appears in the report as a gap.
- Catch-all sweep drops (`catchall_dropped > 0`) mean eligible files were never
  swept. That is a coverage gap too, and phase 4 is forbidden from implying
  exhaustiveness when it is non-zero.

## Before this phase is complete

- [ ] Every confirmed and every `proven` finding has a named transferable
      pattern and two grep patterns run against the whole repository.
- [ ] Every grep hit has a triage verdict; the totals in the sweep table equal
      the grep counts.
- [ ] New tasks are appended to `tasks.json`, schema-valid, within the 40-task
      bound, and every deferred candidate is recorded with its `file:line`.
- [ ] Every new task that ran went through phase 2b and phase 2c — no task's
      findings bypass the gate or the adversarial review.
- [ ] `coverage.py classify` has been re-run **after** the last task completed,
      so the ledger reflects final state.
- [ ] `coverage.py assert-complete` exits `0`.
- [ ] `manifest.json` has `phase3_sweep` appended to `phases_completed`.

Report to the user:

> Swept N root-cause patterns across the repository: H hits, C candidates
> queued, M mitigated, D deferred at the cap. Coverage ledger closed: E inputs
> enumerated, V covered, U uncovered (listed in the report with reasons).
