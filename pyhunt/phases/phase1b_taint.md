# Phase 1b — Graph and task generation

> **Reads:** `${RESULTS_DIR}/inputs.json`, the target repository, and
> `${RESULTS_DIR}/logs/history.json` if it exists.
> **Writes:** `${RESULTS_DIR}/tasks.json`, plus the graph cache at
> `${RESULTS_DIR}/logs/graph.json`.
> **Gate:** Phase 2 may not start until `tasks.json` exists, every task
> validates against `schemas/hunt_task.schema.json`, and `totals.total` is
> recorded — it is the denominator Phase 3 reports against.

---

## No model runs in this phase

Not a subagent. Not a "quick check first". **One command, and you read its
output.**

```bash
python3 "${SKILL_DIR}/scripts/tasks.py" generate \
  --repo "${TARGET}" --results-dir "${RESULTS_DIR}"
```

It writes `tasks.json` and prints the summary block to stdout. Exit `0` is
success; exit `2` means a contract violation you must not route around
(`inputs.json` missing or unparseable); exit `1` is an internal error you report
rather than work around.

Do not "improve" the task list afterwards. Do not add a task because a file
looked interesting, drop one that looks redundant, or re-rank priorities.
`tasks.json` is a deterministic function of (repository content, `inputs.json`).
Two runs at the same commit with the same inventory produce the same tasks, and
that property is what makes a coverage number comparable between runs, a
regression detectable, and a benchmark meaningful. One hand-added task destroys
it for the whole run, and leaves no trace that it was destroyed.

If the task list looks wrong, the right response is to say so in the run summary
and fix the generator or the inventory — not to patch the output.

---

## Why one task is one (entry point, sink, path)

Every task carries exactly one attack class, one code locus, and the specific
files needed to judge it. Agents are **never** handed "here is the repo, find
bugs".

Three reasons, and they compound:

1. **An agent asked to find everything finds the first thing and stops.** This
   is the single most reliable failure in agentic security work. Given a whole
   repository and an open question, a model produces one or two findings in the
   first subsystem it reads and then writes a confident summary. Given "command
   injection, this input, this sink, these three files", it either finds it or
   reports it clean — and either answer is usable.
2. **The hunter sees source and sink together.** A task built from a real call
   graph path shows the entry point, every hop, and the dangerous call in one
   context. That is the precondition for a confirmed data-flow finding, and it
   is what makes the difference between "this file contains `subprocess.run`"
   and "this unauthenticated query parameter reaches `subprocess.run` through
   four functions, none of which sanitises".
3. **Cost is bounded and countable.** N tasks with a known file scope is a
   budget. "Explore the repo" is not, and it produces a coverage claim that
   nobody can check.

The deterministic substrate is doing the work a model is worst at — exhaustive
graph traversal — so the model can do the work it is best at: reading a specific
path and deciding whether the value survives it intact.

---

## What the generator does, in order

`tasks.py generate` composes five modules. The order is load-bearing: the
catch-all sweep must see everything the other four queued, or its coverage
claim is wrong.

### 1. Build the call graph — `scripts/graph/`

```python
doc = build_or_load(repo_path, results_dir / "logs" / "graph.json")
gq  = GraphQuery(doc, repo_path)
```

`graph/build.py` wraps the `graphify` AST extractor. It is **AST-only** — it
never calls a cloud model — and it caches on a content hash over the source
files, so an unchanged repository reuses the previous graph and a changed one
rebuilds. On any failure (import error, extraction crash, or cloud-LLM
environment variables detected, which would break backend isolation) it degrades
to `graph/fallback.py`, a grep-based graph marked `confidence: "low"`. The two
recorded fields are `backend` (`"ast"` or `"grep"`) and `confidence` (`"high"`
or `"low"`); Phase 4 quotes both.

On Darwin, extraction runs **sequentially** by default:
`ProcessPoolExecutor.__init__` calls `os.sysconf("SC_SEM_NSEMS_MAX")`, which the
macOS sandbox denies, aborting the whole extract and forcing a grep fallback for
a reason that has nothing to do with the source. `GRAPHIFY_PARALLEL=1` forces
parallel, `=0` forces sequential.

**The reachability gate.** The two graph-derived sources below run only when
**both** hold:

- `doc.confidence != "low"` — a grep-built graph's edges are guesses, and a
  false edge produces a task asserting a data flow that does not exist
- `count(edges where kind == "calls") > 0` — with no call edges there is no path
  to walk, forward or backward

When the gate fails, taint and sink-backward produce zero tasks. **This is
recorded, not swallowed**: `sources.taint.status` becomes
`skipped:low_confidence_graph` or `skipped:no_call_edges`, and Phase 4 discloses
that the run had no reachability substrate. A scan with a degraded graph is a
weaker scan, and the report must say so rather than showing a smaller task count
with no explanation.

Specialist and catch-all generation are **graph-independent** and run regardless.

### 2. Forward taint paths — `scripts/taint.py`

```python
build_taint_tasks(gq, inputs, repo_path, max_tasks=40, max_hops=8)
```

- Resolves each input's `location` (`file:line`) to its **enclosing symbol** via
  `graph.symbol_at_line`. An input whose location does not resolve contributes
  nothing — which is why Phase 1 insists the line be one you actually read.
  Inputs are deduplicated by enclosing symbol; the first input in a function
  wins.
- Scans every graph file for dangerous-API lines using the sink table for that
  file's language (`SINKS_BY_LANG`; `PYTHON_SINKS` is the one that matters here).
  Matching is line-by-line and **first matching class per line wins**, so one
  dangerous line yields at most one sink. Files are read statically, `utf-8`
  with `errors="replace"`; the target's code is never executed.
- Runs a multi-source BFS (`graph.taint_paths`) from every entry symbol to every
  sink symbol, up to `max_hops=8`.
- Emits **one task per (entry symbol, sink, path)**, deduplicated on
  `(entry_symbol, sink_id, frozenset(target_files))`, capped at `max_tasks=40`.

`target_files` is the ordered, unique set of files along the flow: the entry
file, every file on the path, the sink file. That is "exactly the source needed
to judge it" — not the subsystem, not the package.

`source: "taint"`, `priority: 1`, ids `t_taint_01`…

The sink table is the one genuinely authored artefact in the chain — a few
high-signal patterns per class rather than exhaustive noise. Some entries encode
hard-won specifics: `yaml.load` is a sink unless the loader is `SafeLoader`
(`FullLoader` was RCE-capable before PyYAML 5.4), `torch.load` is a sink unless
`weights_only=True`, `numpy.load` only with `allow_pickle=True`, and the
triple-quote and `.substitute` patterns exist to catch docstring-terminator
injection in code generators, which no eval/exec pattern would find.

### 3. Orphan sinks, hunted backward — `scripts/taint.py`

```python
build_sink_backward_tasks(gq, inputs, repo_path, max_tasks=20, max_back_hops=3)
```

Step 2 covers sinks reachable **forward** from an enumerated input. The recall
gap it leaves is the **orphan sink**: a dangerous call that no enumerated input
reaches — either because Phase 1 missed the source, or because the source is
subtle enough that no reasonable inventory would have caught it.

This source computes `orphans = all_sinks − forward_reached` and hunts each one
**backward** through its callers (`graph.callers_within`, 3 hops), handing the
hunter the sink plus up to 15 caller files and asking it to discover the source.

Because orphans are defined by subtraction, these tasks are **disjoint from
step 2's by construction**. There is no overlap to deduplicate and no double
spend — it is pure additional coverage.

`source: "sink_backward"`, `priority: 2`, ids `t_sinkback_01`…

This source is also the structural answer to under-enumeration in Phase 1. It
cannot repair a missing input in the ledger, but it means a missed input does
not automatically mean a missed sink.

### 4. Repo-wide specialist sweeps — `scripts/specialists.py`

```python
source_files = sweepable_source_files(repo_path, gq)
active       = active_specialists(recon, inputs, repo_path, source_files)
build_specialist_tasks(active, source_files, repo_path, max_files=40)
```

Steps 2 and 3 scope to a single path. Some bug classes are invisible at that
scope because the defining question spans the repository — "is the sanitiser
correct at **every** call site of this field?" is unanswerable one file at a
time. This source emits one repo-wide task per specialist lens.

Each lens is **gated on whether its surface actually exists here**, so hunt and
verify budget is never spent proving a guaranteed false positive:

| Lens | Fires when | Attack class |
|---|---|---|
| `crypto` | crypto API names appear in source | `weak_crypto` |
| `logic-bug` | **always** — no file signature exists for it | `logic_error` |
| `access-control` | an HTTP/RPC/webhook entry point, an `auth_required` flag, a declared trust boundary, or any input at trust level `unauthenticated`/`authenticated` | `auth_bypass` |
| `deserialization` | a JVM-style **or** Python-style deserialiser is present | `deserialization` |
| `batch-etl` | a CLI/file entry point, or batch/ETL signatures (struct, EBCDIC codecs, glob, csv) | `improper_input_handling` |
| `iac` | any file classifies as IaC/CI config | `security_misconfiguration` |
| `codegen` | the repo **emits source code** *and* **reads free-text schema fields** | `codegen_injection` |

`source: "specialist"`, `priority: 3`, ids `t_spec_<lens>`, plus a `specialist`
field carrying the lens key — Phase 2 feeds it to `hints_for(specialist=...)` so
the hunter gets the specialist lens instead of generic language hints.

Two details worth knowing when reading the output:

- The `access-control` gate is why Phase 1's `trust_level` and `architecture`
  block matter. With neither, the gate falls back to weaker signals and the
  sweep may not fire at all on a repository that plainly needs it.
- The `codegen` gate is deliberately biased toward over-firing: it requires both
  halves (something emits source code, something reads a `description` /
  `doc` / `comment` field) but cannot prove the free text reaches the emitter
  without dataflow. Over-firing costs one task; under-firing loses the bug.

Every gated-**off** lens is recorded in `tasks.json` with its reason. A
specialist that did not run is a coverage fact, and Phase 4 reports it.

### 5. The catch-all coverage sweep — `scripts/catchall.py`

```python
tasks, dropped = build_catchall_tasks(all_source_files, covered, graph=gq,
                                      max_files_per_task=25, max_tasks=40)
```

**This runs last.** `covered` is the union of `target_files` across every task
queued in steps 2–4 (and the history-seeded tasks below). Any eligible source
file in neither set has been reached by nothing — no input, no sink, no
specialist — and gets one low-priority sweep task so the coverage claim "every
eligible file received at least one hunt" is actually true.

The eligibility filter drops docs, lock files, images, snapshots, fixtures,
minified bundles and stylesheets, while **keeping** credential-prone configs
(`.env`, `.npmrc`, `*.key`, `*.pem`, `*.p12`). Grouping is by call-graph
connectivity when a graph is available, and by top-two-directory adjacency when
it is not; either way every eligible file lands in exactly one group, so
grouping changes cohesion, never coverage.

`source: "catchall"`, `priority: 5`, ids `t_catchall_01`…

**The `dropped` count is not optional output.** When the `max_tasks=40` cap is
hit, some eligible files get no task. That count goes into
`tasks.json.coverage.catchall_dropped` and Phase 4 discloses it as an
unexamined-surface gap. A dropped file that is never mentioned turns a capped
sweep into a clean bill of health.

### File universe

Steps 4 and 5 both operate over the *sweepable* file set: every file whose
extension maps to a known language (which includes `.jinja2` / `.j2` / `.mako`
— where CWE-94 codegen injection actually lives) **or** that classifies as
IaC/CI config. It skips `.git`, `.venv`, `node_modules`, `__pycache__`, `build`,
`dist`, `vendor`, `target`, and the usual cache directories, unions the on-disk
result with graph-known files, and caps at 20 000 files.

A `.py`-only universe was a real bug here twice: it made template codegen
injection unreachable by the coverage net, and it made the `iac` gate unable to
fire at all, because a Dockerfile has never had a `.py` suffix.

### History-seeded tasks

If `logs/history.json` carries a `tasks` array, `tasks.py generate` merges those
tasks in **before** the catch-all sweep, so their files count as covered. They
are the deterministic form of "this codebase patched this idiom once; here are
the siblings that still carry it".

If the array is absent, the phase proceeds — this source is additive.

---

## Fail-open, but never silent

Each of the five sources is independently fail-open: a crash inside the
specialist gates must not lose the taint tasks that were already generated.
Task generation never aborts the run.

But fail-open is not fail-quiet. Every source records its own status in
`tasks.json`:

| Status | Meaning |
|---|---|
| `ok` | ran and produced tasks (possibly zero, legitimately) |
| `skipped:<reason>` | a documented precondition was not met — e.g. `skipped:low_confidence_graph`, `skipped:no_inputs`, `skipped:gated_off` |
| `failed:<error>` | it raised; the error string is recorded |

A source that produced no tasks and no status line is indistinguishable from a
source that ran and found nothing. That ambiguity is exactly the class of thing
this project refuses to ship: it is the same shape as treating a broken
container as a clean scan.

---

## Output — `tasks.json`

```json
{
  "run_id": "<from manifest.json>",
  "generated_at": "2026-08-08T11:04:00Z",
  "graph": {
    "backend": "ast",
    "confidence": "high",
    "nodes": 1841,
    "calls_edges": 3620,
    "used_for_reachability": true
  },
  "sources": {
    "taint":         {"status": "ok", "tasks": 34},
    "sink_backward": {"status": "ok", "tasks": 11},
    "specialist":    {"status": "ok", "tasks": 4,
                      "active": ["logic-bug", "access-control",
                                 "deserialization", "codegen"],
                      "gated_off": {"crypto": "no crypto API in source",
                                    "batch-etl": "no batch surface",
                                    "iac": "no IaC files"}},
    "history":       {"status": "skipped:no_history_tasks", "tasks": 0},
    "catchall":      {"status": "ok", "tasks": 18}
  },
  "coverage": {
    "source_files": 412,
    "covered_files": 297,
    "catchall_dropped": 0
  },
  "totals": {"taint": 34, "sink_backward": 11, "specialist": 4,
             "history": 0, "catchall": 18, "total": 67},
  "tasks": [
    {
      "task_id": "t_taint_01",
      "source": "taint",
      "attack_class": "command_injection",
      "target_files": ["app/views/export.py", "app/services/shell.py"],
      "scope_hint": "unauthenticated input at app/views/export.py:41 reaches command_injection sink run() at app/services/shell.py:18 via export_view -> build_cmd -> run. Verify every hop for sanitization; if none, exploitable.",
      "rationale": "Deterministic call-graph path from attacker-controllable input in_1 (app/views/export.py:41) to a command_injection sink at app/services/shell.py:18. ...",
      "priority": 1
    }
  ]
}
```

**Each element of `tasks[]` validates against `schemas/hunt_task.schema.json`
unchanged.** That schema sets `additionalProperties: false`, so the entry point,
the sink, and the path are carried as prose inside `scope_hint` and `rationale`
rather than as separate fields. Promoting them to first-class keys is a schema
change, not something to do inline here — a task with extra keys fails
validation and the whole phase fails with it.

Append `"phase1b_taint"` to `manifest.json.phases_completed`.

---

## `totals.total` is the denominator

Phase 3 reports coverage against this number, and Phase 4 prints it. Which means
three things:

- It is fixed here. Phase 2 may not add tasks to make coverage look better, and
  may not remove one to avoid reporting it as failed. A task that failed is
  reported as failed against this denominator.
- Gapfill and feedback tasks generated later carry their own `source` values and
  are counted separately. They do not silently inflate this figure.
- If it is small, say why it is small. `graph.confidence: "low"`, an empty
  `inputs.json`, or a `sources.taint.status` of `skipped:*` are all reasons a
  scan covered less ground, and every one of them is visible in this file.

A small honest denominator with a stated cause is a usable result. A small
denominator presented as full coverage is the failure this whole structure is
built to prevent.

---

## Gate to Phase 2

Proceed only when:

- [ ] `tasks.json` exists and parses
- [ ] every element of `tasks[]` validates against `schemas/hunt_task.schema.json`
- [ ] every `task_id` is unique
- [ ] every path in every `target_files` exists in the target
- [ ] every source has a `status` — no source is absent from `sources`
- [ ] `totals.total` is present and equals `len(tasks)`
- [ ] `coverage.catchall_dropped` is recorded, even when `0`

If `totals.total` is `0`, do **not** proceed silently. Report the per-source
statuses to the user and stop — zero tasks against a non-empty repository means
the graph failed, the inventory was empty, or the sweepable file set came back
empty. All three are bugs in the run, and none of them is a clean scan.
