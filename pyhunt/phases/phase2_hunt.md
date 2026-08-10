# Phase 2 — Hunt dispatch

> **This file is for the orchestrator only.** Hunt subagents never read it; they
> read `phase2_shared.md` plus exactly one class file. Do not paste any of this
> into a subagent prompt.

Phase 2 turns `tasks.json` into findings. It does that by fan-out: one subagent
per **(class group, location)** pair, each carrying a small chunk of tasks, each
reading two instruction files and nothing else. The orchestrator dispatches,
collects, validates, and writes the ledger. It does **not** analyse code itself —
keeping findings out of the orchestrator's context is what forces the systematic
method instead of improvised reading.

---

## 0. Preconditions

Refuse to start unless all three hold:

- `<results_dir>/manifest.json` exists and its `phases_completed` contains the
  task-generation phase (`phase1b`);
- `<results_dir>/tasks.json` exists and `tasks` is non-empty;
- `<results_dir>/inputs.json` exists.

If `tasks` is empty, do **not** invent tasks. Write the ledger (§8) with zero
units, `scan_complete: false`, and a note naming the empty input; then stop and
tell the user. An empty task list means Phase 1b found nothing to hunt, which is
a finding about Phase 1b.

If `manifest.json` already lists `phase2_hunt` in `phases_completed`, this run is
being resumed past Phase 2 — read the existing ledger and skip to Phase 2b
rather than re-dispatching.

---

## 1. Read the run state

```bash
RESULTS_DIR="<the timestamped results directory>"
SKILL_DIR="<the pyhunt skill directory>"
PHASES_DIR="${SKILL_DIR}/phases"
```

From `manifest.json` take `run_id`, `target` (the repo path), `mode`
(`static` | `proof`) and `isolation_tier`. From `tasks.json` take `tasks`. From
`inputs.json` take `inputs`.

`mode` decides `execution_available` for every subagent: `proof` → `true`,
`static` → `false`. Never tell a subagent execution is available when Phase 0
refused Proof mode — a hunter that tries to run PoCs on a bare host produces
noise and, worse, may execute untrusted target code outside a sandbox.

Create the directories Phase 2 writes to:

```bash
mkdir -p "${RESULTS_DIR}/findings" "${RESULTS_DIR}/logs/hunt"
```

---

## 2. Route every task to exactly one class file

Route on the task's `attack_class` string. This table is exhaustive over the
classes PyHunt's own task generators emit (`scripts/taint.py`,
`scripts/specialists.py`, `scripts/catchall.py`) plus the vocabulary documented
in `schemas/hunt_task.schema.json`.

| Class group | File | `attack_class` values routed here |
|---|---|---|
| **INJ** | `phase2_class_inj.md` | `command_injection`, `sql_injection`, `code_injection`, `ssti`, `codegen_injection`, `log_injection`, `xss_stored`, `xss_reflected` |
| **NAV** | `phase2_class_nav.md` | `path_traversal`, `ssrf`, `open_redirect`, `xxe`, `zip_slip`, `improper_input_handling` |
| **DESER** | `phase2_class_deser.md` | `deserialization`, `unsafe_reflection`, `prototype_pollution` |
| **RES** | `phase2_class_res.md` | `resource_exhaustion`, `denial_of_service`, `dos`, `algorithmic_complexity`, `regex_dos`, `redos`, `uncontrolled_recursion`, `memory_exhaustion`, `unbounded_allocation`, `integer_overflow` |
| **LOG** | `phase2_class_log.md` | `auth_bypass`, `idor`, `access_control`, `authorization`, `missing_auth`, `privilege_escalation`, `business_logic`, `logic_error`, `mass_assignment`, `csrf`, `rate_limit`, `weak_crypto`, `cryptographic_failure`, `hardcoded_secret`, `information_disclosure`, `insecure_design`, `insecure_default`, `security_misconfiguration`, `supply_chain`, `state_mutation`, `global_state_pollution`, `validation_bypass`, `race_condition` |

Three of those rows moved and it is worth knowing why. `regex_dos` and
`integer_overflow` used to sit in LOG, which is the file for *"execution cannot
settle this"* — but a ReDoS and an unbounded allocation are settleable, by
measurement, and putting them in LOG told the hunter the opposite. `race_condition`
stays in LOG because whether an interleaving is *allowed* is still a policy
question, even though `state_mutation` next to it is measurable.

**Unknown `attack_class`.** Route it by the sink family its `scope_hint` names:
a shell/SQL/template/eval sink → INJ; a path, URL or XML parser → NAV; anything
that reconstructs objects or resolves names from strings → DESER; anything whose
harm is *how much* rather than *what* — a size, a depth, a count, a loop bound →
RES. If the hint still does not settle it, route to **LOG** and set the unit's
`routing` field to `"fallback"` in the ledger. **Never drop a task for being
unroutable** — an unroutable task is a fact about the routing table, and it
belongs in the ledger where the next maintainer can see it.

> **Check this table against the generators before you dispatch.** The sweep and
> the reconciler mint classes this table has been behind on before: one real run
> had to invent routings for `injection`, `untrusted_code_execution`,
> `resource_exhaustion`, `validation_bypass`, `supply_chain`, `state_mutation`
> and `global_state_pollution` mid-flight, because they were emitted by phase 3
> and absent here. The table above now covers all seven. A one-line check that
> the run's own tasks are all routable, before any agent is dispatched:
>
> ```bash
> "${SKILL_DIR}/.venv/bin/python" - <<'PY'
> import json, sys
> known = set()  # paste the union of the table's class values
> tasks = json.load(open(f"{RESULTS_DIR}/tasks.json"))
> tasks = tasks.get("tasks", tasks)
> unknown = sorted({t["attack_class"] for t in tasks} - known)
> print("unroutable:", unknown or "none")
> PY
> ```
>
> Anything printed is routed by the fallback rule above **and recorded as
> `routing: "fallback"`**, so the gap is visible in the ledger rather than
> silently absorbed.

**LOG is defined by `scripts/oracle/classes.py`.** Every class in
`UNDECIDABLE_BY_EXECUTION` routes to LOG, because those are exactly the classes
the execution gate cannot settle and `phase2_class_log.md` is the file written
for that condition. To confirm a class's membership rather than trusting this
table:

```bash
"${SKILL_DIR}/.venv/bin/python" -c \
  "import sys; sys.path.insert(0,'${SKILL_DIR}/scripts'); \
   from oracle.classes import is_undecidable; print(is_undecidable('idor'))"
```

Two routing labels are in the LOG row but are **not** in that table:
`auth_bypass` and `logic_error` (both emitted by `scripts/specialists.py`).
They still belong in LOG — the reasoning is identical — but their findings must
be emitted with a `vuln_class` the table recognises, which is why
`phase2_class_log.md` makes the exact `vuln_class` string a hard requirement.

---

## 3. Group tasks into hunt units

A **unit** is one subagent's work: one class group, one location, at most five
tasks.

1. **Location** is the top-two-directory prefix of the task's **first**
   `target_files` entry — `app/routes` for `app/routes/users.py`, `pkg/sub` for
   `pkg/sub/deep/mod.py`, `.` for a file at the repo root. This mirrors the
   `_dirkey` grouping `scripts/partition.py` and `scripts/catchall.py` already
   use, so a unit is a coherent slice of the codebase rather than an arbitrary
   grab-bag.
2. Bucket every task by `(class_group, location)`.
3. Split any bucket holding more than **5** tasks into consecutive chunks of 5,
   preserving order. A sixth task in one prompt is a task that gets skimmed.
4. Name each unit
   `h_<class_group lowercased>_<location with '/' , '-' and '.' replaced by '_'>_<nn>`,
   e.g. `h_inj_app_routes_01`.

Every task lands in exactly one unit. Count them before and after: the total
across units must equal `len(tasks)`. If it does not, you have lost a task —
fix the grouping, do not proceed.

---

## 4. Bound the fan-out — and record exactly what the bound cuts

```
MAX_CONCURRENT_UNITS   = 6      # per wave
MAX_UNITS_PER_RUN      = 40
MAX_TASKS_PER_UNIT     = 5
```

**Why a bound at all.** In the CLI PyHunt was built from, `_budget_check`
aborted work cooperatively, mid-fan-out, in Python. A skill has no equivalent
API, so budget enforcement here is advisory (PLAN.md §5.2). What survives the
move is the honest half: **every unit the bound cuts is recorded, and a scan
that did not cover everything says so.**

**Wave discipline.** Dispatch at most `MAX_CONCURRENT_UNITS` subagents in a
single message. Wait for all of them to write their result files, then dispatch
the next wave. Do not dispatch all units at once regardless of count — high
concurrency saturates rate limits and a rate-limited agent returns *nothing*,
which is indistinguishable from *clean code* unless you go looking.

**Ordering before truncation.** If there are more than `MAX_UNITS_PER_RUN`
units, sort before you cut, so the cut falls on the least valuable work:

1. ascending by the unit's **minimum task `priority`** (1 is most urgent);
2. then by **source rank**: `taint` → `sink_backward` → `recon` → `specialist`
   → `reconcile` → `feedback` → `gapfill` → `catchall`;
3. then by `unit_id`, so the order is deterministic across reruns.

**What truncation means — and does not mean.** A unit beyond the cap is **not
dropped and not skipped silently**. For each one:

- write a ledger entry with `status: "truncated_by_budget"` and its full
  `task_ids`;
- synthesise a `gaps_observed` entry into `logs/hunt/gaps.json`:
  `{"file_or_subsystem": "<location>", "reason": "hunt fan-out cap of 40 units
  reached; this unit was not dispatched", "suggested_attack_class":
  "<attack_class>"}`;
- set `scan_complete: false` in the ledger.

`scan_complete: false` must reach the report. Phase 4 states proven, provable
and total as separate denominators; an undispatched unit is neither proven nor
disproven, and a report that hides it reads as a clean bill of health for code
nobody looked at.

If the user asked for a complete scan and the cap bites, say so in plain words
before continuing, and offer to re-invoke against the same results directory —
resume will pick up from the ledger.

---

## 5. The dispatch prompt

Each subagent reads its own instruction files. **Do not interpolate the contents
of `phase2_shared.md` or the class file into the prompt** — they are large,
they cache across the wave when read as files, and an interpolated copy drifts
from the file on disk.

Substitute `{UNIT_ID}`, `{CLASS_GROUP}`, `{CLASS_FILE}`, `{PHASES_DIR}`,
`{RESULTS_DIR}`, `{REPO}` and `{ASSIGNMENT_JSON}`:

```
You are a {CLASS_GROUP} hunt agent for unit {UNIT_ID}, working on a Python
target. You are responsible for ONE class group. Findings outside it go in
gaps_observed with a suggested_attack_class — never in findings.

Read these two files IN ORDER before doing anything else:
1. {PHASES_DIR}/phase2_shared.md   — method, evidence standard, severity,
                                     PoC discipline, output contract
2. {PHASES_DIR}/{CLASS_FILE}       — your sinks, your sanitisers, your
                                     false-positive killers, your PoC shapes

Read no other file in {PHASES_DIR}.

Your assignment:

{ASSIGNMENT_JSON}

Write your output to {RESULTS_DIR}/logs/hunt/{UNIT_ID}.json — one JSON object
per task_id (a JSON array if your chunk holds more than one task), validating
against {SKILL_DIR}/schemas/finding.schema.json. No prose, no markdown fence.

IMPORTANT: your return message must be 20 words or fewer.
```

`{ASSIGNMENT_JSON}` is the block documented in `phase2_shared.md` §1. Build it
per unit:

- `tasks` — the unit's task objects, **verbatim** from `tasks.json`. Do not
  summarise them; `scope_hint` and `rationale` are the hunter's starting point.
- `inputs` — the `inputs.json` entries whose `location` file appears in any of
  the unit's `target_files`, or whose `entry_point` string appears in any of the
  unit's `scope_hint` values. This is the same predicate `scripts/coverage.py`
  uses, so what the hunter sees and what coverage counts cannot diverge.
- `design_controls`, `graph_context`, `language_hints` — pass through when
  Phase 1 / 1b produced them, omit the key entirely when they did not. Never
  fabricate an empty one that looks like "we checked and there are none".
- `mode`, `isolation_tier`, `execution_available` — from `manifest.json`.
- `poc_execution` — include only when `execution_available` is `true`. It is the
  per-task recipe from `scripts/poc_runtime.py` (`poc_execution_block`), carrying
  `nonce`, `canary_path` and `nonce_transport`. **The nonce is minted per task,
  in Python, and is never shown to the hunter as something to invent or echo
  back.**

  Call it with the task's identity, not with a nonce you computed yourself:

  ```python
  from poc_runtime import poc_execution_block
  block = poc_execution_block(task_languages, project_env, scratch_dir,
                              materialize=True,
                              run_id=RUN_ID, task_id=task["task_id"])
  ```

  It derives `oracle.nonce.nonce_for(run_id, task_id)` — the same derivation
  `replay.py` uses, so the two cannot drift — and it **raises** if given neither
  a nonce nor an identity. It used to return `"nonce": null` when called with
  nothing and nothing failed; 24 tasks of a real run went out that way, gate
  condition 3 was unsatisfiable for every one of them, and it was caught only
  because all six hunt agents noticed unprompted and said so.

  **A unit holds up to 5 tasks and the nonce is per task**, so a single
  `poc_execution` on the assignment cannot express what the gate requires. Emit
  `poc_execution_by_task`: a `{task_id: block}` map. Then persist the run secret
  — `manifest.json:run_secret` and `.run_secret` — before dispatching, or replay
  will derive different nonces from a fresh secret and match nothing.
- `scratch_dir` — `{RESULTS_DIR}/logs/hunt/{UNIT_ID}` — and create it before
  dispatching, along with the observer assets when Proof mode is on.

---

## 6. Waves, failures, and the difference between them

Run the waves. After each wave, before dispatching the next:

1. **Confirm every unit in the wave wrote its file.** Glob for
   `logs/hunt/<unit_id>.json`.
2. **A missing or empty file is not "no findings".** It is unknown coverage.
   Re-dispatch that unit **once**, unchanged.
3. If it fails a second time, record `status: "failed"` with the error in the
   ledger, add a `gaps_observed` entry for its location, and set
   `scan_complete: false`. Do not re-dispatch a third time and do not paper over
   it — two failures on the same unit usually means the chunk is too large or a
   target file is unreadable, and that is worth telling the user.

A unit that returned a valid file containing `"findings": []` **is** a result:
it means a hunter read the code and found nothing. Record it `completed`.

---

## 7. Collect, validate, and explode into `findings/`

For each `completed` unit, read `logs/hunt/<unit_id>.json` and process every
HuntOutput object in it:

**Validate first.**

```bash
"${SKILL_DIR}/.venv/bin/python" - "$RESULTS_DIR" "$SKILL_DIR" <<'PY'
import json, sys, pathlib
results, skill = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
sys.path.insert(0, str(skill / "scripts"))
from json_utils import validate_schema
schema = skill / "schemas" / "finding.schema.json"
# Reserved names: files this directory holds that are NOT hunt output. The
# orchestrator's own unit plan once landed here and failed validation loudly,
# for the entirely correct reason that a plan is not a finding — so the plan
# moved to logs/hunt_plan.json and the glob learned the convention rather than
# the next bookkeeping file repeating it.
RESERVED = {"dispatch.json", "gaps.json", "plan.json", "units.json"}
for f in sorted((results / "logs" / "hunt").glob("*.json")):
    if f.name in RESERVED:
        continue
    docs = json.loads(f.read_text())
    for doc in (docs if isinstance(docs, list) else [docs]):
        errs = validate_schema(doc, schema)
        print(f.name, doc.get("task_id"), errs or "OK")
PY
```

Write the orchestrator's own bookkeeping to `logs/hunt_plan.json` and
`logs/hunt/dispatch.json`; anything else you invent under `logs/hunt/` must be
added to `RESERVED` above in the same edit.

**Then check the labels.**

```bash
python3 "${PYHUNT_DIR}/scripts/findings_io.py" class-check \
  --results-dir "${RESULTS_DIR}"
```

Advisory, never fatal — a mislabelled finding is still a real finding. But the
disagreement has to surface *now*, because by report time it has already
corrupted three things: `dedupe.py` groups by class family, `oracle/classes.py`
decides provability by class string, and every CWE-keyed consumer downstream
reads the label rather than the description.

Measured on a real run: **46 of 145 findings** carried a class that disagreed
with their own CWE, and the single `proven` remote code execution of the entire
scan was filed as `improper_input_handling` / CWE-829.

A malformed return gets **one** repair attempt: hand the subagent its own output
and the validator's error list and ask for a corrected object. If the repair
also fails, record the unit `failed` per §6 and keep the raw file — never delete
a hunter's output because it did not parse.

**Then explode.** For each finding in each validated object, write

```
<results_dir>/findings/<finding_id>.json
```

containing a HuntOutput envelope carrying **exactly that one finding**:

```json
{"task_id": "<the owning task_id>", "findings": [ <the finding object> ],
 "gaps_observed": []}
```

This shape validates against `schemas/finding.schema.json` unchanged, so every
downstream phase can load one finding with the same loader it uses for a whole
hunt output.

- **`finding_id` collision** (two units both produced `f_taint_03_1`): keep the
  first, and rename the second by appending `_b`, `_c`, … Record the rename in
  the ledger. Never overwrite — an overwritten finding is a deleted finding.
- **Exact duplicates** — same `file`, same `line_start`, same `vuln_class`, from
  different units — keep the one with the higher `confidence`, merge the other's
  `poc` in if the kept one has none, and list the discarded `finding_id` under
  `merged_from` in the ledger. Deduplication proper happens later and on root
  cause; this step only collapses the byte-identical case that shared
  infrastructure files produce.

**Then collect the gaps.** Concatenate every `gaps_observed` array from every
unit, plus the synthesised entries from §4 and §6, into
`<results_dir>/logs/hunt/gaps.json` as a flat array. Phase 3 consumes it.

Nothing in this step may delete a finding. Not a schema error, not a duplicate,
not a failed PoC, not a finding you personally doubt. Doubt is Phase 2c's job
and it is done adversarially, in writing, on a different model.

---

## 8. Close each task's input disposition

Write `<results_dir>/logs/hunt/dispatch.json`. This is the ledger, and it is the
record that makes an incomplete scan visible:

```json
{
  "run_id": "…",
  "phase": "phase2_hunt",
  "bounds": {"max_units_per_run": 40, "max_concurrent_units": 6,
             "max_tasks_per_unit": 5},
  "tasks_total": 57,
  "tasks_dispatched": 40,
  "tasks_truncated": 17,
  "tasks_failed": 0,
  "scan_complete": false,
  "units": [
    {
      "unit_id": "h_inj_app_routes_01",
      "class_group": "INJ",
      "class_file": "phase2_class_inj.md",
      "location": "app/routes",
      "routing": "table",
      "task_ids": ["t_taint_03", "t_taint_07"],
      "status": "completed",
      "attempts": 1,
      "inputs_covered": ["in_004", "in_011"],
      "findings": ["f_taint_03_1"],
      "gaps": 1,
      "note": ""
    }
  ]
}
```

`status` is one of `completed`, `failed`, `truncated_by_budget`, `out_of_scope`
(the task's region was excluded by operator `scope_notes`).

**`inputs_covered` is computed, not reported by the subagent.** For each unit,
an input is covered when the input's `location` file appears in the unit's
`target_files`, or the input's `entry_point` string appears in the unit's
`scope_hint` or `target_files` — the same predicate `scripts/coverage.py`
applies in Phase 3.

**The rule Phase 3 depends on: only a unit with `status: "completed"` may
contribute coverage.** A truncated or failed unit's `inputs_covered` list
records *what it would have covered*, so the gap is legible — it is not
evidence that those inputs were examined. `scripts/coverage.py` asserts that
every enumerated input reaches a disposition, and the run fails if one does not;
that assert is only honest if it knows which units actually ran.

> **Known hazard — read this before you truncate anything.**
> `coverage.py classify` derives dispositions from `findings/` **and
> `tasks.json`**: an input counts as covered when its entry point appears in
> *some task's scope*. A task that this phase never dispatched is still in
> `tasks.json`. So a truncated unit's inputs would be marked `covered` on the
> strength of a task nobody ever ran — a fan-out cap silently manufacturing
> coverage, which is precisely the failure PLAN.md §5.2 says must not survive
> the move off the CLI.
>
> Until `coverage.py classify` takes this ledger and credits only
> `status: "completed"` units, the orchestrator closes the hole by hand and
> **must not skip it**:
>
> 1. every truncated or failed unit's `task_ids` and `inputs_covered` go into
>    `logs/hunt/gaps.json` as explicit gap entries (§4, §6);
> 2. `scan_complete: false` goes into the ledger and into what you tell the
>    user;
> 3. when you hand off to Phase 3, name `logs/hunt/dispatch.json` as an input
>    and state the truncated count out loud, so Phase 4's "what was not
>    examined" sentence is built from a real number rather than from silence.
>
> Never delete a truncated task from `tasks.json` to make the arithmetic work.
> That trades a visible gap for an invisible one.

---

## 9. Before proceeding to Phase 2b

Verify, and do not proceed with a box unticked:

- [ ] Every task in `tasks.json` appears in exactly one unit in the ledger.
- [ ] Every unit has a terminal `status`; none is left mid-flight.
- [ ] Every `completed` unit has a validated result file.
- [ ] Every finding in every result file exists as a `findings/<id>.json`.
- [ ] `logs/hunt/gaps.json` exists (an empty array is fine and means something).
- [ ] `scan_complete` is `true` **only** if no unit was truncated or failed.
- [ ] `manifest.json` `phases_completed` now includes `phase2_hunt`, and
      `model_used` records the model the hunt subagents ran as — Phase 2c must
      use a **different** model, and that check needs this value to be recorded.

Then report to the user, in plain numbers: tasks total, units dispatched, units
truncated, units failed, findings emitted. If `scan_complete` is `false`, say
which regions were not hunted and why. Do not present a finding count as a
result without the denominator that gives it meaning.
