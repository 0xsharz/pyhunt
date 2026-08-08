# Output contracts

There is no database. **The results directory is the state**, and this file is
its contract: what each phase writes, where, in what shape, and which schema in
`schemas/` validates it.

Two rules apply to everything below:

1. **Emit valid JSON matching the schema. No prose around it, no markdown
   fence.** A malformed return gets one repair attempt and is then recorded as a
   failed work unit — never silently dropped, and never patched up by hand into
   something that validates but says something the agent did not say.
2. **A phase is complete when its artifact exists and validates**, and only then
   is its id appended to `manifest.json:phases_completed`. That append is what
   makes the run resumable.

---

## The results directory

```
<target_parent>/<target_basename>_PYHUNT_RESULTS_<YYYY-MM-DD-HHMMSS>/
  manifest.json              run identity, mode, tier, progress, models
  preflight.json             phase 0
  inputs.json                phase 1
  tasks.json                 phase 1b
  findings/<finding_id>.json phase 2   one file per finding
  proof/<finding_id>.json    phase 2b  replay transcript + gate verdict
  verify/<finding_id>.json   phase 2c  adversarial disproof + model used
  coverage.json              phase 3
  report.md  report.json     phase 4
  logs/                      raw container logs, replay transcripts, script stderr
```

Never reuse a results directory across two targets or two commits. Re-invoking
against an existing one **resumes**; it does not start over.

---

## `manifest.json` — the orchestrator writes this

Not schema-validated (it is the orchestrator's own bookkeeping), but its keys are
load-bearing and every one of them ends up in the report:

```json
{
  "run_id": "2026-08-08-141133",
  "target": "/abs/path/to/repo",
  "commit": "a1b2c3d",
  "started_at": "2026-08-08T14:11:33Z",
  "authorisation": "user stated they own this repository (2026-08-08)",
  "mode": "proof",
  "isolation_tier": "vm",
  "phases_completed": ["phase0", "phase1", "phase1b"],
  "model_used": {"phase2": "<hunt model>", "phase2c": "<a different model>"}
}
```

`isolation_tier` is written by phase 0 from `sandbox.py detect`, and is one of
`gvisor` | `vm` | `runc` | `none`. It is stated verbatim in the report — a `vm`
run must never be described as `gvisor`.

`model_used` exists so a same-model verification is detectable after the fact.
Compare it against the `model` field each `verify/<id>.json` records; if they
match, the verification was not independent and the report must say so.

---

## Phase 0 → `preflight.json`

No schema — a capability report, not an agent output. Shape:

```json
{
  "execution_enabled": true,
  "isolation_tier": "vm",
  "sandbox_verified": true,
  "languages": ["python", "shell"],
  "capabilities": [
    {"name": "target_readable", "ok": true,  "detail": "...", "why_it_matters": "..."},
    {"name": "target_importable", "ok": false, "detail": "...", "why_it_matters": "..."},
    {"name": "observer_python-audit-hook", "ok": null, "detail": "...", "why_it_matters": "..."}
  ]
}
```

`ok` is deliberately three-valued: `true` (present), `false` (absent and it
matters), `null` (unknown — treat its silence as no information, never as a
pass). A degraded capability changes what the report may claim; it never changes
whether a finding exists.

`target_importable: false` is the single most important line in this file. It
means the target's dependencies are not installed in the container that will run
PoCs, so every Python PoC can prove only that a hello-world ran. Phase 2b must
report `not_attempted`, not "did not reproduce".

---

## Phase 1 → `inputs.json`

The attacker-controllable input inventory, plus deterministic git-history
results from `history.py`.

```json
{
  "inputs": [
    {
      "input_id": "in_1",
      "source_type": "http_param",
      "location": "app/routes/reports.py:41",
      "variable": "name",
      "entry_point": "GET /reports/<name>",
      "trust_level": "unauthenticated",
      "notes": "reaches the exporter service unmodified"
    }
  ],
  "history": [
    {
      "commit": "9f2c1ab",
      "subject": "fix: quote filename before shelling out",
      "files": ["app/services/exporter.py"],
      "sink_similarity": ["app/services/archiver.py:88"],
      "why": "a past patch to one call site; its siblings were never patched"
    }
  ]
}
```

Each element of `inputs` validates against
`schemas/recon_output.schema.json#/properties/inputs/items`, which requires
`source_type`, `location`, `variable`, `entry_point`, and a `trust_level` from
`unauthenticated | authenticated | internal | privileged`.

> **Known seam.** The schema names the identifier `id`; the results-directory
> contract names it `input_id`. They are the same value. Any producer or consumer
> that touches `inputs.json` must accept both spellings, and `coverage.py` in
> particular must not silently drop an input because it looked for the other key —
> a dropped input is a missing disposition, which is a release-gate failure.

**`gaps_observed` discipline starts here.** Recon that enumerates no inputs is
asserting the repository has no attacker-controlled surface. That is almost never
true, and `coverage.py` will compute a denominator of zero, which reads as
perfect coverage.

---

## Phase 1b → `tasks.json`

```json
{"tasks": [ … ]}
```

Each task validates against `schemas/hunt_task.schema.json`:

| Field | Notes |
|---|---|
| `task_id` | `^[a-z0-9_-]{1,64}$` |
| `attack_class` | exactly one concrete class — `command_injection`, `sql_injection`, `path_traversal`, `ssrf`, `xxe`, `deserialization`, `ssti`, `open_redirect`, `idor`, `auth_bypass`, … |
| `scope_hint` | ≥10 chars, and must name the **trust boundary above the sink**, not just the sink |
| `target_files` | ≥1, repo-relative |
| `rationale` | ≥10 chars |
| `priority` | 1–5; 1 = deterministic taint path, 5 = catch-all sweep |
| `source` | `recon` \| `gapfill` \| `feedback` \| `reconcile` \| `taint` \| `sink_backward` \| `specialist` \| `catchall` |
| `specialist` | only with `source: specialist` — `crypto` \| `logic-bug` \| `access-control` \| `deserialization` \| `batch-etl` \| `iac` \| `codegen` |

`source` is not cosmetic: it is the denominator breakdown in `coverage.json` and
the report's `tasks_by_source`. A run with no `catchall` tasks has not proved
whole-repo coverage, and the report may not imply it did.

---

## Phase 2 → `findings/<finding_id>.json`

One file per finding, validated against `schemas/finding.schema.json`. The hunt
agent returns the whole `{task_id, findings, gaps_observed}` envelope; the phase
splits it into per-finding files and keeps `gaps_observed` for phase 3.

```json
{
  "task_id": "t_taint_01",
  "findings": [
    {
      "finding_id": "f_reports_shell_concat",
      "file": "app/services/exporter.py",
      "line_start": 7,
      "line_end": 9,
      "vuln_class": "command_injection",
      "cwe": "CWE-78",
      "severity": "high",
      "description": "…≥20 chars, no hedging…",
      "evidence_snippet": "subprocess.run('echo ' + name, shell=True)",
      "confidence": 0.9,
      "hedged_language": false,
      "needs_poc": false,
      "poc": {
        "language": "python",
        "code": "…the exploit, verbatim…",
        "run_output": "…COMPLETE combined stdout+stderr, verbatim…",
        "succeeded": true,
        "notes": "observer python-audit-hook: evidence captured"
      }
    }
  ],
  "gaps_observed": [
    {"file_or_subsystem": "app/legacy/", "reason": "exceeded read budget",
     "suggested_attack_class": "path_traversal"}
  ]
}
```

`finding_id` matches `^f_[a-z0-9_-]{1,64}$`. `severity` is one of `critical`,
`high`, `medium`, `low`, `informational`. `cwe` matches `^CWE-[0-9]+$`. `file`
is repo-relative, never absolute.

Four fields decide whether this finding can ever be proven:

- **`poc.run_output` — verbatim and complete.** The `[PYHUNT-OBSERVER]` marker
  lines inside it are the gate's only input. Summarising this field, or keeping
  "the interesting part", is how a proven finding silently becomes an unproven
  one.
- **`poc.succeeded` — your belief, not a verdict.** It promotes nothing and
  blocks nothing. Answer it honestly; a claim the evidence does not support is
  counted as an over-claim, which is how prompt drift gets detected.
- **`needs_poc`** — true only when execution was *unavailable*. Not "my PoC
  didn't work". The gate records that outcome itself.
- **`execution`** — **never emit it.** PyHunt computes it and overwrites anything
  found there. Its shape is documented in the schema so readers can see it, and
  it is written by phase 2b, below.

`gaps_observed` is not optional politeness. An empty array asserts you examined
everything in scope, and phase 3 believes you.

---

## Phase 2b → `proof/<finding_id>.json`

The harness-captured replay plus the gate's verdict. **The gate reads the replay
transcript, never the hunt agent's `poc.run_output`** — the first is captured by
`replay.py`, the second is self-reported.

```json
{
  "finding_id": "f_reports_shell_concat",
  "nonce": "a3f19c22b7d40e51",
  "canary_path": "/tmp/pyhunt-canary/a3f19c22b7d40e51",
  "runs": [
    {"n": 1, "exit_code": 0, "run_output": "…verbatim…", "container": "…", "image": "…"},
    {"n": 2, "exit_code": 0, "run_output": "…verbatim…", "container": "…", "image": "…"},
    {"n": 3, "exit_code": 0, "run_output": "…verbatim…", "container": "…", "image": "…"}
  ],
  "unanimous": true,
  "execution": {
    "outcome": "proven",
    "proven": true,
    "reason": "subprocess.Popen fired from /target/app/services/exporter.py:7 in build_report and interpreted this PoC's payload — the target's own code executed attacker-controlled data.",
    "evidence": ["[PYHUNT-OBSERVER] n=a3f19c22b7d40e51 audit:subprocess.Popen ('/bin/sh', ['-c', 'echo hi; touch /tmp/pyhunt-canary/a3f19c22b7d40e51']) <- from /target/app/services/exporter.py:7 in build_report"],
    "events_seen": 2,
    "events_attributed": 1,
    "observer_armed": true,
    "nonce": "a3f19c22b7d40e51",
    "model_claimed_success": true,
    "contradicts_model": false
  }
}
```

The `execution` object is exactly `ExecutionVerdict.to_dict()` from
`scripts/oracle/gate.py`, and it is also merged back into
`findings/<finding_id>.json` as that finding's `execution` field.

Three invariants:

- **`outcome` is one of the eight**, and `proven` is true only for `proven`.
- **Three runs, unanimous, or no promotion.** `unanimous: false` means the
  outcome was not stable across replays; record the per-run outcomes and do not
  promote. A flaky exploit is not a proven one.
- **`evidence` is verbatim marker lines.** They are the receipt a human reads to
  check the gate's arithmetic. Never paraphrase them into the report.

`logs/` holds the raw container output for each run so the transcript above can
be audited against something the agent did not author.

---

## Phase 2c → `verify/<finding_id>.json`

Adversarial re-read on a **different model**, with **no Bash**. The job is to
**disprove**; a refutation needs evidence at a `file:line`, and "probably fine"
is not a verdict. Confirming should be the harder path, not the default one.

Validates against `schemas/validation.schema.json`, plus one required extra key:

```json
{
  "finding_id": "f_reports_shell_concat",
  "verdict": "confirmed",
  "rationale": "…≥30 chars, engaging with the evidence rather than restating it…",
  "alternative_explanation": "the benign reading, and why it fails here",
  "missing_preconditions": [],
  "suggested_test": "",
  "validator_confidence": 0.85,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "model": "<the model this verification actually ran as>"
}
```

- `verdict` ∈ `confirmed` | `rejected` | `needs_more_info`.
- `cvss_vector` is **required for `confirmed`** and omitted for the other two.
  `cvss_score` and `cvss_rating` are computed by `cvss.py` from the vector —
  never by the model. Model arithmetic on CVSS is how a 9.8 becomes a 7.5.
- **`model` is mandatory.** It is the only after-the-fact evidence that
  verification was model-independent (§ `SKILL.md` 6). A file without it must be
  treated as an unverified finding, not a verified one.

This is the one phase permitted to kill a finding, and only on evidence about the
code. Note what a `proven` execution verdict does and does not give it: it
establishes that **the sink is exploitable given the value**; it does not
establish that **an attacker can supply the value**. A PoC that imported the
module directly never touched routing or auth, and that gap is exactly this
stage's question.

---

## Phase 3 → `coverage.json`

The completeness ledger. `coverage.py` writes it and **asserts** it.

```json
{
  "inputs": [
    {"input_id": "in_1", "disposition": "covered",
     "evidence": "finding touches exporter.py"},
    {"input_id": "in_7", "disposition": "uncovered",
     "evidence": "no finding file or task scope reached this input"}
  ],
  "totals": {"enumerated": 12, "covered": 11, "uncovered": 1},
  "files": {"source_files": 214, "covered_files": 198,
            "catchall_tasks": 9, "catchall_dropped": 0},
  "tasks_by_source": {"taint": 18, "sink_backward": 6, "specialist": 4, "catchall": 9},
  "coverage_complete": false
}
```

- `disposition` is `covered` or `uncovered`. An input is **covered** when some
  finding's file matches its location file, or its `entry_point` appears in a
  task's `scope_hint` or `target_files`. Otherwise **uncovered**.
- **Every enumerated input must carry a disposition.** `coverage.py` exits `2`
  if any does not, and that exit code is a stop, not a hint. This is a release
  gate: `len(inputs) == totals.enumerated`, and `covered + uncovered ==
  enumerated`.
- `coverage_complete` is **false** whenever `catchall_dropped > 0` or any input
  is unreconciled. When it is false the report may not imply full coverage — not
  in prose, not by omission.
- `catchall_dropped` counts eligible source files that hit the task cap. Coverage
  loss is never silent; it is a number.

---

## Phase 4 → `report.json` and `report.md`

`report.json` validates against `schemas/report.schema.json`. Python assembles
the payload — CWE, CVSS score and rating, PoC evidence, the coverage block, the
verification funnel — before the agent renders `report.md` from it. Do not invent
fields Python did not provide, and do not recompute a number Python already
computed.

The blocks that are **injected from run state and never agent-authored**:

| Block | Contents |
|---|---|
| `input_inventory` | every enumerated input with its `disposition` — the completeness artifact |
| `coverage` | the counts from `coverage.json`, including `coverage_complete` |
| `verification` | `raw_findings`, `true_positives`, `false_positives`, `needs_more_info`, `duplicates_collapsed`, `precision_pct` |
| `scan_metrics` | files in scope / analysed, coverage %, duration |

Per finding, `report.json` requires `finding_id`, `title`, `severity`,
`vuln_class`, `file`, `line_start`, `line_end`, `description` (≥30 chars),
`evidence`, `trace` (`entry_points` + `call_chain`), and `recommendation`.

`report.md` additionally must state, in the prose:

- the **achieved isolation tier**, named;
- **proven / provable / total** as three separate numbers (see
  `references/honest-reporting.md`);
- what was **not** examined — failed tasks, files past the sweep cap,
  unprovisioned dependencies. A gap that is not disclosed reads as a clean
  result.

Never present a reasoned finding and an executed one at the same visual weight
without labelling which is which.

---

## Contracts kept for phases not in this build

These schemas exist and are still valid; nothing in the current 13-phase sequence
writes them. Listed so nobody assumes they are dead:

| Schema | Would validate |
|---|---|
| `trace.schema.json` | a standalone reachability verdict per finding |
| `dedupe_output.schema.json` | root-cause clustering, one group per defect |
| `gapfill_output.schema.json` | re-queued tasks for under-covered areas |
| `feedback_output.schema.json` | fresh tasks seeded from confirmed patterns |
| `chain.schema.json` | multi-finding attack chains |
| `revalidation.schema.json`, `remediation.schema.json` | `pyhunt-fix` / `pyhunt-fix-verify`, **not built** |

---

## The rules every contract shares

1. **Emit valid JSON matching the schema.** No prose around it.
2. **Never invent a `file:line` you did not read.**
3. **Say what you could not examine.** Silence reads as coverage.
4. **Name the concrete capability the attacker gains.** Mechanism is not impact.
5. **Do not delete a finding because a tool, a container, or an import failed.**
