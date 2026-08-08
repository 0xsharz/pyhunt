# Phase 0 — Preflight: authorisation, language, and the sandbox

> **Reads:** the target path, and the user.
> **Writes:** `${RESULTS_DIR}/preflight.json`, and the `mode` / `isolation_tier`
> fields of `${RESULTS_DIR}/manifest.json`.
> **Gate:** Phase 1 may not start until `preflight.json` exists **and was read
> back** with `gate.passed: true`, `mode` is resolved to `static` or `proof`,
> and — when it is `proof` — a `sandbox.py verify` run in *this* session passed
> every assertion. An exit code is not a substitute for any of these.

`${SKILL_DIR}` is the skill directory; `${RESULTS_DIR}` is the timestamped
results directory. SKILL.md binds both before invoking this phase.

---

## What this phase is for

Every later phase spends money and makes claims. This one decides whether the
run is entitled to make them at all. It answers three questions, in order, and
**each of the three can stop the run**:

1. Is the operator authorised to have this code attacked?
2. Is this actually a Python target?
3. What isolation does this host really have — and therefore, may a PoC run?

Nothing here is analysis. There is exactly one judgement call in the whole
phase (step 0, authorisation), and it belongs to the user, not to you. The rest
is two scripts and a menu.

The output of this phase is the *only* place the final report gets its
isolation claim from. If this phase records `vm`, the report says `vm`. There
is no path by which a later phase can upgrade it, and no phase may re-derive it
by looking at the host again.

---

## Step 0 — Authorisation

Ask, unless the user has already said it in this conversation:

> Before I start: confirm you own this code or are authorised to security-test
> it. PyHunt writes and (in Proof mode) executes working exploits.

Wait for an answer. Record the user's words verbatim in
`preflight.json.authorisation.statement`, with `preflight.json.authorisation.
confirmed: true`.

Do not paraphrase the confirmation into a tidier sentence, and do not accept
your own summary of an earlier turn as the statement. The field exists so that
a person reading the results directory months later can see what was actually
agreed to. A generated sentence in that field is a fabricated record.

If the user declines, will not answer, or answers about a *different*
repository than the one resolved as the target — stop. Do not offer Static mode
as a compromise. Static mode still reads the code and still produces an
exploitability report; authorisation is not about whether code executes.

**No tool calls in this step.** In particular, do not run `git remote -v` to
"check" ownership. A remote URL is not a permission.

---

## Step 1 — Is this a Python target?

```bash
python3 "${SKILL_DIR}/scripts/preflight.py" check \
  --repo "${TARGET}" --results-dir "${RESULTS_DIR}"
```

This writes `${RESULTS_DIR}/preflight.json` — the language census, the
majority-Python verdict, and the capability record every later phase reads —
and prints the same JSON to stdout. Human-readable notes go to **stderr**;
stdout is JSON and nothing else, so it is safe to pipe.

The command **merges** into `preflight.json` rather than overwriting it. Keys
written by other steps — `authorisation`, `mode`, and the `sandbox` block from
`sandbox.py` — survive a re-run, which is what makes a resume safe.

### Then verify the artifact — do not trust the exit code alone

```bash
python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("ARTIFACT MISSING OR UNREADABLE:", type(e).__name__, e); raise SystemExit(1)
missing = [k for k in ("gate", "language_census") if k not in d]
if missing:
    print("ARTIFACT INCOMPLETE, missing:", missing); raise SystemExit(1)
print(json.dumps({"gate": d["gate"], "counts": d["language_census"]["counts"]}))
' "${RESULTS_DIR}/preflight.json"
```

`preflight.json` must exist, parse, and carry a `gate` object
(`{"passed": ..., "exit_code": ..., "reason": ...}`) and a `language_census`
block. If the file is absent, empty, unparseable, or missing either key, treat
the run as **failed regardless of the exit code** and report that — do not
continue, and do not re-run hoping for a different result.

This is not defensive boilerplate. `preflight.py` shipped once with no
`if __name__ == "__main__"` guard: the interpreter imported the module, defined
its functions, wrote nothing, and exited **0**. This phase read that 0 as a
pass and proceeded, so the D-5 gate below never executed on any run. An exit
code is produced by the interpreter and says only that nothing crashed; the
artifact is produced by the logic and is the only evidence the work happened.
**Check the artifact.**

**Exit codes:**

| Exit | Meaning | What you do |
|---|---|---|
| `0` | Python is the target's primary language | verify the artifact, then continue to step 2 |
| `2` | contract violation: not majority Python, or `preflight.json` could not be written | **stop the run**; report the census and the `gate.reason` |
| `1` | preflight itself failed (unreadable target path, crash) | stop and report the error; do not guess |

An exit of `2` is not a preference you may override. Per **D-5**, PyHunt
analyses Python targets. Read the `language_census` block out of `preflight.json`
and tell the user what the repository actually is, **with the numbers** — the
operator checks the call, they are not told the call:

> This target is 87.5% Go by source file count (Python: 12.5%, 8 source files
> counted). PyHunt's analysis is Python-specific and would produce confident
> nonsense here. Stopping.

The rule the gate applied is recorded in `language_census.rule` alongside
`counts`, `shares`, `python_share` and `threshold`. Quote the real numbers from
that block; do not estimate them from your own reading of the tree.

**What the census counts.** Files whose extension maps to a programming
language, excluding vendored and build directories (`node_modules`, `.venv`,
`dist`, `build`, `vendor`, …). Web templates (Jinja, ERB, JSP, …) are counted
separately in `web_template_files` and kept **out** of the denominator: a Jinja
template is evidence *for* a Python backend, not a rival language, and letting
templates vote would stop a Flask service on the strength of its own HTML.
`language_census.truncated` being `true` means the walk hit its limit and the
numbers are partial — say so if you quote them.

**Why this is a hard stop rather than a warning.** The Python-shaping is not
cosmetic — it goes all the way down:

- The proof observer is a **PEP-578 audit hook**. It is a CPython interpreter
  feature. Against a Go service it never arms, so every finding comes back
  `observer_absent` — an outcome that is *supposed* to mean "the harness broke",
  and here would mean "the harness was never applicable". That is a corrupted
  signal, not a missing one.
- The gate's attribution test (condition 4: *the frame that caused the event was
  inside the target*) walks a Python stack. There is no stack to walk.
- Phase 1b's sink tables and call graph are keyed by language. A Go repo yields
  few entries, few tasks, and a small denominator — so the run would finish
  early, report high coverage over a tiny task count, and look *clean*.

That last point is the actual danger. A Python-shaped scan of a Go service does
not fail loudly; it succeeds quietly and wrongly. A mixed repository with a
genuine Python component is a different case — say so, and let the user re-scope
the target path to that subdirectory.

**What this step does NOT check, and why.** The capability probes that would
answer "can a PoC actually import the target?" have to *execute the target's
code* — an import runs module-level statements. This command runs on the
**operator's host**, before a mode has been chosen and before any sandbox has
been verified. Running target code there would execute untrusted code outside
the only boundary this tool has. So `check` records `execution_enabled: false`
and reports the executing capabilities as unknown rather than absent, and
`preflight.py check --execution` exists solely for an invocation from *inside*
the provisioned scan container. **Do not pass `--execution` here.** If a PoC
later cannot import the target, that is discovered inside the container and
recorded as an environment fact — never as a failed exploit.

---

## Step 2 — Detect the isolation tier

```bash
python3 "${SKILL_DIR}/scripts/sandbox.py" detect
```

JSON on stdout. Read `tier` from it — verbatim. Do not infer the tier from
prose, from the Docker version, from the platform string, or from your own
knowledge of the host. If the JSON has no `tier` key, that is a contract break:
stop and say so.

| Tier | Condition | Boundary | Proof mode |
|---|---|---|---|
| `gvisor` | Linux with the `runsc` runtime | syscall interception | allowed |
| `vm` | Docker Desktop / Lima / Colima — a Linux VM | **separate kernel** | allowed |
| `runc` | Linux, plain containers | namespaces only, shared kernel | **refused** |
| `none` | no usable Docker | — | refused; Static only |

Two things about this table are easy to get backwards, so state them to the
user when they matter:

- **`vm` is not a degraded `gvisor`.** Docker Desktop runs containers inside a
  Linux VM with its own kernel. A container escape there lands the attacker in
  the VM, not on the operator's macOS host. gVisor intercepts syscalls against
  the *host's own* kernel. The VM boundary is the stronger one. What a macOS
  host lacks is gVisor specifically — not isolation. **D-7**: the tier is
  detected, never assumed, and never hardcoded to `gvisor`.
- **`runc` is refused even though it is "a container".** Namespaces share the
  host kernel with the payload. Proof mode exists to run exploit code written to
  be effective; a kernel-boundary-only sandbox is not where that belongs.

Record the whole `detect` payload into `preflight.json.sandbox.detect`.

---

## Step 3 — The mode menu

Present this to the user. Static is the default; if they express no preference,
Static is what runs.

> **Static** (default) — I read the code, trace inputs to sinks, and write PoCs,
> but **nothing executes**. Strongest verdict available: `not_attempted`.
>
> **Proof** — PoCs actually run inside an isolated container, and a deterministic
> gate decides whether each one worked. Strongest verdict available: `proven`.
> Requires isolation tier `vm` or better; this host detected **`<tier>`**.

Substitute the real detected tier into that last line. If the tier is `runc` or
`none`, present Proof mode as unavailable and say why in one clause — do not
hide the option, and do not offer it as selectable-but-doomed.

Record the chosen mode in `preflight.json.mode` and `manifest.json.mode`.

**Static is a complete product, not a fallback.** It enumerates inputs, builds
the graph, generates tasks, hunts, verifies adversarially, and reports coverage.
The single thing it cannot do is promote a finding to `proven`. Say that plainly
when a user is choosing; a user who picks Static because Proof was refused
should understand they are losing one verdict, not the scan.

If Static was chosen, skip to **step 7**.

---

## Step 4 — Bring the sandbox up (Proof only)

```bash
python3 "${SKILL_DIR}/scripts/sandbox.py" up \
  --repo "${TARGET}" --results-dir "${RESULTS_DIR}"
```

This creates the `pyhunt-internal` network (`internal: true` — no route off the
box), starts the egress-allowlist proxy for the one host agents legitimately
need, and provisions the target image via `${SKILL_DIR}/scripts/provision/`.

Provisioning matters more than it looks. A container without the target's own
dependencies importable cannot run a real PoC — it can only prove that
hello-world runs. If `up` reports that provisioning failed or degraded, that is
recorded and carried into every finding as an environment fact; it is **never**
recorded as an exploit that failed.

Non-zero exit from `up`: do not retry blindly, and do not proceed to `verify`.
Report what it said and offer Static.

---

## Step 5 — Verify the boundary (Proof only)

```bash
python3 "${SKILL_DIR}/scripts/sandbox.py" verify \
  --results-dir "${RESULTS_DIR}"
```

`verify` launches a **throwaway container from the same image PoCs will run in**
and makes it *assert*, from the inside, three things:

1. **It cannot reach the internet.** An outbound connection to a known-good host
   fails or times out.
2. **It cannot see the host filesystem.** No bind mount exposes the operator's
   home, the repo's parent, or `/`.
3. **It carries no auth environment variable.** `ANTHROPIC_API_KEY`,
   `CLAUDE_CODE_OAUTH_TOKEN`, cloud credentials — absent, not merely unused.

**Print the result to the user**, per assertion, before you continue. Not a
summary — the assertions and their outcomes. The user is the person authorising
attacker-shaped code to run on their machine. They are entitled to see the
boundary demonstrated rather than described.

Read `ok` and the per-assertion results from the JSON. `ok: true` and every
assertion passing is the only combination that permits Proof mode.

**Never cache this result across sessions.** `verify` must run in the session
that runs the PoCs. Containers do not survive a laptop sleeping, a Docker
restart, or a day passing; a `verify` from yesterday is a claim about a sandbox
that no longer exists.

Record the full payload into `preflight.json.sandbox.verify`.

---

## Step 6 — Refusal

If `verify` fails any assertion, or the tier is below `vm`:

1. `python3 "${SKILL_DIR}/scripts/sandbox.py" down --results-dir "${RESULTS_DIR}"`
2. Tell the user which assertion failed, verbatim.
3. Offer **Static** mode.
4. Set `preflight.json.mode` to `static` and record
   `preflight.json.proof_refused` with the reason.

**Never silently downgrade.** A run that quietly becomes Static after
advertising Proof produces a report whose `not_attempted` outcomes look like an
analysis choice rather than a refusal, and the user never learns their sandbox
is broken.

There is no override flag, and you must not construct one — no "the user said
it's fine", no `--dangerously-*`, no running the PoC on the host "just this
once". If the user pushes, the answer is Static plus a plain statement of what
it costs: findings will read `not_attempted` instead of `proven`.

---

## Why the refusal is correct

Four independent reasons. Any one of them is sufficient; they are written out
because a phase file that only issues orders gets rationalised around by a model
under pressure, and one that gives reasons does not.

**1. The report's isolation claim is load-bearing, and it is only as good as
this phase.** A reader calibrates how much to trust `proven` against the tier it
was proven under. If the run records `vm` but actually executed under `runc`,
every `proven` in that report is over-trusted by exactly the amount the reader
adjusted for. The tier is not decoration; downgrading it silently is falsifying
the evidence's provenance.

**2. What runs in Proof mode is real exploit code.** Not a synthetic probe — a
payload written to be *effective* against the target, by a model, from an
adversarial prompt. That is the correct design; it is also precisely why the
container it runs in must be a boundary rather than a convention. Namespaces
share a kernel with that payload.

**3. The operator's credentials are on the host.** `ANTHROPIC_API_KEY` and
`CLAUDE_CODE_OAUTH_TOKEN` are usually in the ambient environment. Assertion 3
exists because target code executing with those variables present can exfiltrate
them, and unlike a container escape this needs no kernel bug at all — just
`os.environ`. An unverified sandbox may well be leaking them into every PoC
container. Refusing costs one verdict; not refusing can cost the credential.

**4. The honest alternative loses almost nothing.** This is the reason that
makes the other three easy. Refusing does not abandon the scan — it runs Static,
and Static differs by exactly one thing: `proven` becomes `not_attempted`. That
outcome exists in the eight-outcome taxonomy *specifically* so a missing
capability is recorded as a missing capability. The machinery for being honest
about this is already built. Using it is not a loss; routing around it converts
a known-unknown into a false claim.

The general principle underneath all four: **a missing toolchain is never
reported as a failed exploit, and a missing boundary is never reported as a
boundary.** Both are facts about the environment. Neither is evidence about the
code.

---

## Step 7 — Record the tier

Write into `manifest.json`:

```json
{
  "mode": "static",
  "isolation_tier": "vm",
  "isolation_verified": true
}
```

Rules for these three fields:

- `isolation_tier` is copied **verbatim** from `sandbox.py detect`'s `tier`. Not
  re-derived, not upgraded, not softened.
- In Static mode, `isolation_tier` still records what was *detected* (that is a
  true fact about the host), and `isolation_verified` is `false` — because no
  `verify` ran. A Static run must never claim a verified boundary it did not
  exercise.
- `isolation_verified` is `true` only when a `verify` in **this session** passed
  every assertion.

Phase 4 reads exactly these three fields for its isolation statement. It does
not look at the host.

`preflight.json` carries the fuller record. `preflight.py check` writes the
`target`, `checked_at`, `language_census`, `majority_python`, `gate`,
`languages`, `capabilities`, `execution_enabled`, `poc_confirmation_available`,
`degraded` and `unknown` keys; `sandbox.py` merges the `sandbox` block; **you**
write `authorisation`, `mode` and `proof_refused`. Nobody overwrites anybody:

```json
{
  "authorisation": {"confirmed": true, "statement": "<user's words, verbatim>"},
  "mode": "proof",
  "proof_refused": null,

  "target": "/abs/path/to/target",
  "checked_at": "2026-08-08T14:11:33Z",
  "majority_python": true,
  "gate": {"passed": true, "exit_code": 0,
           "reason": "python is 94.1% of 812 counted source file(s)"},
  "language_census": {
    "primary": "python",
    "files_counted": 812,
    "counts": {"python": 764, "shell": 40, "javascript": 8},
    "shares": {"python": 0.9409, "shell": 0.0493, "javascript": 0.0099},
    "python_files": 764,
    "python_share": 0.9409,
    "is_majority_python": true,
    "threshold": 0.5,
    "rule": "python must be the most common counted language AND hold at least 50% of counted source files",
    "web_template_files": 31,
    "truncated": false,
    "excluded_dirs": ["...", "node_modules", "vendor"]
  },
  "languages": ["python", "shell", "javascript"],
  "execution_enabled": false,
  "poc_confirmation_available": false,
  "degraded": [],
  "unknown": [],
  "capabilities": [
    {"name": "target_readable", "ok": true, "detail": "...",
     "matters_because": "..."}
  ],
  "sandbox": {
    "detection": { "...verbatim detect payload..." },
    "verification": { "...verbatim verify payload..." }
  }
}
```

`capabilities[].ok` is three-valued: `true`, `false`, and `null` for *could not
be determined*. A `null` is never rendered as a pass. On the host path above,
`execution_enabled` is `false` and the executing probes did not run — so a
sparse `capabilities` list here means "not measured", not "nothing is missing".

Append `"phase0_preflight"` to `manifest.json.phases_completed`.

---

## Resuming

When SKILL.md is re-invoked against an existing results directory whose
`phases_completed` already contains `phase0_preflight`:

- Keep the recorded **authorisation** and **mode**.
- **Re-run `detect`, and in Proof mode re-run `up` and `verify`.** Containers,
  networks and proxies do not survive between sessions. The recorded tier
  describes the previous session's host state and is not evidence about this
  one.
- If re-verification fails now, the run continues in **Static** mode from
  wherever it resumed, `manifest.json.isolation_verified` becomes `false`, and
  the report states that proof was available for part of the run only. Findings
  already recorded as `proven` keep that outcome — they were proven, under a
  sandbox that was verified at the time. **Nothing demotes.**

---

## Gate to Phase 1

Proceed only when all of these hold:

- [ ] `preflight.json` exists, is non-empty, and parses as JSON
- [ ] it carries a `language_census` block and a `gate` object — **checked by
      reading the file, not by trusting an exit code**
- [ ] `preflight.json.authorisation.confirmed` is `true`
- [ ] `preflight.py check` exited `0` **and** `gate.passed` is `true` and
      `majority_python` is `true` (target is majority Python)
- [ ] `manifest.json.mode` is exactly `static` or `proof`
- [ ] `manifest.json.isolation_tier` was copied from `sandbox.py detect`
- [ ] if mode is `proof`: tier is `vm` or `gvisor`, **and** `verify` passed every
      assertion in this session, **and** `isolation_verified` is `true`

Any unchecked box means Phase 1 does not start. There is no partial pass.

---

## Failure modes, and what they are not

| What happened | What it is | What it is **not** |
|---|---|---|
| `detect` reports `none` | no Docker on this host | evidence the target is safe |
| `verify` assertion 1 fails | the container has egress | a reason to run PoCs anyway |
| `verify` assertion 3 fails | credentials are reaching the sandbox | a minor hygiene issue |
| `up` reports provisioning degraded | the target's deps are not importable | a failed exploit |
| `preflight.py check` exits `2` | wrong language for this tool, or the results directory is unwritable | a clean scan |
| `preflight.py check` exits `0` but no `preflight.json` | the script did not run — a broken install, not a pass | a passed preflight |
| `capabilities` is sparse after step 1 | the executing probes deliberately did not run on the host | evidence that nothing is missing |
| user declines authorisation | out of scope | a reason to run Static instead |

Every row's middle column goes into the report. None of them is a finding, and
none of them is an absence of findings.
