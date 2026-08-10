# Phase 1 — Recon: the input inventory

> **Reads:** `${RESULTS_DIR}/preflight.json` (mode, language census),
> `${RESULTS_DIR}/logs/recon_enumeration.json`,
> `${RESULTS_DIR}/logs/history.json`, and the target repository.
> **Writes:** `${RESULTS_DIR}/inputs.json`.
> **Gate:** Phase 1b may not start until `inputs.json` exists, every input has a
> unique `input_id` and a `file:line` you actually read, and the `history` array
> is present.

This phase runs as a subagent. Its tool envelope is **Read — no Bash, no Grep,
no Glob.** See "What moved out of this phase" for why that changed, twice.

---

## The one thing this phase is for

**Enumerate every point where attacker-influenced data enters this codebase.**

Not "find the interesting inputs". Not "find the inputs that look dangerous".
Every one. Phase 1b turns this list into the task queue, Phase 3 reconciles
every entry to a disposition, and Phase 4 reports the totals. An input you do
not write down here is not analysed, is not counted, and does not appear in the
denominator — so the run reports high coverage over a surface you shrank.

You do not decide whether an input is safe. Later phases do that, with the call
graph and with the gate. Your job is enumeration, and enumeration errs wide.

---

## What moved out of this phase, and why

The predecessor prompt asked the recon *agent* to mine git history — to run
`git log --grep='CVE\|security\|vuln\|...'`, read the top commits, work out
which pattern each fix addressed, and grep for unpatched siblings.

**That work is now `scripts/history.py`. Do not do it here.** Do not run `git
log`, `git show`, or `git blame`. You have no Bash.

Three reasons the move was right, and they generalise to anything else in a
phase file that looks mechanical:

1. **Reproducibility.** A model re-deriving the grep pattern each run picks
   slightly different commits each run, so the seeded tasks are not stable
   across two scans of the same commit. A Python implementation returns the same
   commits every time, which is the precondition for comparing two runs at all.
2. **Cost.** It is `git log` piped into string matching and a table join. Paying
   Opus rates for a join is the clearest possible waste, and it consumes context
   the enumeration actually needs.
3. **Tool envelope.** It was the *only* reason this phase needed Bash. Removing
   it means the agent that reads the most untrusted repository content — README
   text, comments, docstrings, filenames, all of it attacker-authored in the
   threat model — now cannot execute anything at all. That is a real reduction
   in blast radius, bought for free.

The corollary is a constraint on you: `history.py`'s output is **input, not
suggestion**. You may not filter it, re-rank it, or drop entries you disagree
with. If an entry looks wrong, enumerate against it anyway and say so in that
input's `notes`.

### And then the enumeration moved too (D6)

The paragraph above was written, the phase kept its Grep and Glob, and the
property still was not held: the harness could not supply Grep or Glob, so the
recon agent delegated the whole structural pass to a **nested Bash subagent**.
The prompt said no Bash; a Bash ran anyway, over the most attacker-authored
content in the run. Defect D6.

The same reasoning that moved the history mining applies to the file walk, the
extension census, the framework detection, and the entry-point grep. All four
are `os.walk` plus regex wearing an LLM costume. They are now
`scripts/recon_enumerate.py`, and SKILL.md runs it before dispatching you:

```bash
python3 "${SKILL_DIR}/scripts/recon_enumerate.py" enumerate \
  --repo "${TARGET}" --results-dir "${RESULTS_DIR}"
```

**You have `Read` and nothing else.** That is an envelope the harness can
actually supply, so the property is now held rather than requested.

What you gain, beyond the envelope: a candidate set that is byte-identical
across two scans of the same commit, that does not thin out at file 300 because
context got tight, and that already contains the public API surface — for a
library target, `public_api[]` is the attack surface, computed with `ast`
instead of by remembering to be thorough.

---

## Step 1 — Run the history miner

```bash
python3 "${SKILL_DIR}/scripts/history.py" mine \
  --repo "${TARGET}" --results-dir "${RESULTS_DIR}"
```

SKILL.md runs this before dispatching you, and it writes
`${RESULTS_DIR}/logs/history.json`. **Read that file.**

Each entry describes one past security-relevant commit: the commit, the pattern
that was fixed, and the sibling locations in the current tree that still carry
the unpatched idiom.

Use it two ways:

- **As a reading list.** Open the sibling files it names while you enumerate.
  A past patch is evidence that this codebase's own authors got this idiom wrong
  at least once. The patched file is now hardened; the siblings usually are not,
  and they are exactly where an inventory built from framework-API greps tends
  to come up short.
- **As a carried artefact.** Copy the `patches` array from `history.json`
  **verbatim** into `inputs.json.history`. Byte-for-byte. Phase 4 cites it, and
  a summarised copy cannot be checked against the miner's own output.

If `history.json` is absent or its array is empty, set `"history": []` and note
it in the phase summary. An empty history is a normal result for a young or
freshly-imported repository. It is not a reason to re-derive the mining
yourself.

---

## Step 2 — Read the enumeration

**Read `${RESULTS_DIR}/logs/recon_enumeration.json`.** It is already written.
The structural pass this step used to describe has been done for you:

| key | what it holds | how to use it |
|---|---|---|
| `files[]` | every source file, with `lines`, `reachable_from`, `status` | your reading list. `status` other than `read` says why a file was not analysed. |
| `extension_census` | counts by extension | tells you if a language is present that the sink tables do not cover — say so in the summary. |
| `reachability_census` | counts by tier | `test`, `ci`, `example` files are **enumerated, not excluded**. See below. |
| `frameworks[]` | each with `confidence` and `evidence` | `confirmed` first. See the confidence rule below. |
| `manifests[]` | dependency names per manifest, with `scope` | read, never run. |
| `entry_point_candidates` | by category, with `matched` vs `kept` | your grep results. Open each one. |
| `indirect_dispatch` | dispatch tables, registries, dynamic imports | every target behind one is its own entry point. |
| `public_api[]` | every exported callable and its parameter names | **for a library target this is the attack surface.** |

### The confidence rule on `frameworks[]`

A claim is graded, and the grade changes what you do with it:

- **`confirmed`** — imported by first-party source. Enumerate its input APIs in
  full.
- **`peripheral`** — imported only by examples, tests, docs or CI. Real, and its
  entry points are real; they are just reachable from a different place. Still
  enumerate them, and let `reachable_from` carry the urgency.
- **`declared`** — named by a root manifest, never imported. Look once for a
  usage the import regex missed, then move on.
- **`transitive`** — named only by a lock file. **This is not a framework of
  this project.** A lock file lists the transitive closure of a dev
  environment; on the first real target this produced tornado, kafka and
  aiohttp for a schema library that uses none of them. Do not enumerate an HTTP
  surface that does not exist.

### Tests, CI and examples are enumerated

This step used to say "exclude `**/tests/**`". That was wrong, and it cost real
findings: the recorded run surfaced a `publish.yaml` tag trigger and several
test-harness issues, all genuine. A file dropped from the inventory produces no
gap, no warning, and a silently smaller denominator.

So nothing is excluded for being a test. Every file carries a `reachable_from`
tier — `public_api`, `internal`, `ci`, `test`, `example`, `build` — which flows
onto every finding and lets a reader sort by reachability. **Sorting is the
reader's job. Dropping is nobody's.**

Only vendored trees (`node_modules/`, `.venv/`, `site-packages/`, `vendor/`)
and generated artefacts are excluded, and each exclusion is recorded in
`excluded[]` with the rule that caused it.

### What you still owe

The enumeration gives you *candidates*. It cannot tell you what an input **is**,
what it is called, or who can reach it. That is Step 3, it needs the code
opened, and it is the reason this phase still has an agent in it.

---

## Step 3 — Enumerate the inputs

`entry_point_candidates` has already found the call sites. **Open each one** and
enumerate every input it receives.

The tables below are the vocabulary the enumerator swept with, kept here because
you need to recognise what you are looking at when you open a candidate — and
because a candidate list is a floor, not a ceiling. When you read a file and see
an input the sweep did not flag, **enumerate it**. A regex finds the idioms it
was given; you find the ones it was not, and that difference is why this phase
still has an agent in it.

Where a category shows `matched` greater than `kept`, the sweep was bounded.
Open the file the last kept hit points at and read the rest of it yourself.

**HTTP**
- Flask / Quart: `request.args`, `request.form`, `request.json`,
  `request.get_json`, `request.values`, `request.files`, `request.headers`,
  `request.cookies`, `request.data`, and every `<converter:name>` in a
  `@app.route` / `@bp.route` path
- Django: `request.GET`, `request.POST`, `request.body`, `request.FILES`,
  `request.META`, `request.COOKIES`, plus URLconf capture groups and every
  `ModelForm` / serializer field
- FastAPI / Starlette: path and query parameters in the signature, `Body(...)`,
  `Query(...)`, `Header(...)`, `Cookie(...)`, `Form(...)`, `UploadFile`, and
  every field of every Pydantic request model
- aiohttp / Tornado / Bottle: `request.query`, `request.match_info`,
  `await request.post()`, `self.get_argument`, `self.request.body`

**Not HTTP** — enumerate every one of these that exists here:
- **CLI**: `argparse` arguments, `click.option` / `click.argument`, `typer`
  parameters, raw `sys.argv`, and **stdin**
- **Environment and config**: `os.environ` / `os.getenv` reads, and values loaded
  from config files a deployment-adjacent attacker can influence
- **File readers**: anything reading a path, an archive, or an upload —
  `open()`, `zipfile`, `tarfile`, `pandas.read_*`, `csv`, image loaders. Both the
  **filename** and the **content** are separate inputs
- **Deserialisers**: `pickle.loads`, `yaml.load`, `marshal.loads`, `dill`,
  `jsonpickle`, `joblib.load`, `torch.load`, `numpy.load(allow_pickle=True)`.
  Every field of the deserialised object is an input
- **Message consumers**: Celery task signatures, Kafka/SQS/RabbitMQ consumer
  bodies and message attributes
- **Webhook handlers**: signature-verified or not — enumerate both, the
  verification is a later phase's question
- **Template renderers**: any value interpolated into a template, and the
  **template name or path** itself when it is selected by input
- **WebSocket**: message handlers, upgrade parameters
- **Scheduled jobs**: if a cron job reads a store an attacker can write to, those
  values are inputs
- **Second-order**: values read back from a DB, cache, or object store that
  another endpoint lets an attacker write. These are the most commonly missed
  entries in any inventory
- **Third-party API responses**, where the attacker can influence what the
  external service returns
- **Public library API**: for a library target, every exported function's
  parameters are the attack surface. There is no HTTP layer to enumerate and the
  inventory is *not* therefore empty

### Indirect dispatch

`indirect_dispatch.hits[]` lists the sites: functions stored in dicts, lists, or
registries and called dynamically — `handlers[kind](payload)`,
`getattr(mod, name)(...)`, plugin registries, entry-point loading,
`functools.singledispatch`, strategy tables, decorator-registered callbacks.

Enumerate **every target** in the dispatch table as its own entry point. Each
one receives the data the dispatcher received, and a forward trace that stops at
the dispatcher silently loses all of them. Set `notes: "indirect dispatch via
<dispatcher location>"` on those inputs so Phase 1b and Phase 2 know the call
edge may be missing from the graph.

### The sibling-input rule

When one extraction point yields N inputs, enumerate **all N**.

`user = request.json` followed by `user["name"]`, `user["role"]`,
`user["avatar_url"]` is three inputs, not one, and not "one plus two boring
ones". Then grep each parameter name across every other entry point — the same
name at a different route is a **different input** with a different id, because
it has a different trust level and a different downstream path.

Judging safety here is the single most expensive mistake available in this
phase, because it is invisible: a dropped input produces no error, no gap, and
no coverage warning. It just shrinks the denominator.

### Endpoints with no input

An entry point that takes nothing still gets an inventory row: `source_type:
"no-input endpoint"`, `variable: "N/A"`, `trust_level` set by what
authentication it requires.

They are not filler. A sensitive operation reachable with no credential is
CWE-306 whether or not it parses anything, and this row is the only way that
endpoint reaches Phase 1b's specialist gate at all.

### Trust level

Exactly one of `unauthenticated` / `authenticated` / `internal` / `privileged`.
No synonyms — `unauth`, `public`, `anon` all fail the schema, and this field is
read by deterministic code downstream.

Assign it from **audited code**, not from naming. A path prefixed `/internal/`,
a comment saying "auth handled by the gateway", or a config flag that opts the
route *out* of authentication are all the absence of enforcement, not evidence
of it. If you cannot point at the code that rejects a credential-less request,
the level is `unauthenticated`.

This field is load-bearing: `taint.py` writes it into every generated task's
scope hint, and `specialists.py` gates the entire access-control sweep on
whether any input is `unauthenticated` or `authenticated`. A guessed trust level
propagates into task generation silently.

### Design controls

While you are reading the code anyway, **map the design controls** you see: the
security mechanisms this codebase already has — authentication, input
validation, sanitizers, output encoding, CSRF tokens, rate limiting, access
control, crypto — each with the `file:line` where it lives.

This is a **map of what exists, not an assertion that it is sufficient**, and
the distinction is the whole point of recording it. Downstream, `design_controls`
is a pointer telling a hunter where to look first; it never clears a path.
Phase 2 must still verify empirically that a listed control actually covers the
specific flow in front of it, and `phase2_class_log.md` refuses to use the list
to clear anything at all — the entire class of authorisation bug is "the control
exists and does not cover this case."

So record what you saw and where, and nothing about whether it works:

```json
{"kind": "input_validation", "location": "app/forms.py:22",
 "description": "Regex allowlist on `name` before it reaches the query.",
 "applies_to": "GET /lookup"}
```

`kind`, `location` and `description` are required; `applies_to` is optional and
names the entry point or route the control guards, when you can tell. Omitting
the section entirely is legal and means "I mapped none", which costs later
phases a hint but breaks nothing. Guessing at one you did not read costs more:
a control listed at a line that does not implement it sends a hunter to the
wrong place and reads, to every later phase, exactly like one you verified.

---

## Step 4 — Write `inputs.json`

```json
{
  "run_id": "<from manifest.json>",
  "target": "/abs/path/to/target",
  "frameworks": ["flask", "sqlalchemy", "jinja2", "celery"],
  "inputs": [
    {
      "input_id": "in_1",
      "source_type": "HTTP query param",
      "location": "app/views/search.py:41",
      "variable": "q",
      "entry_point": "GET /api/search",
      "trust_level": "unauthenticated",
      "notes": "also reachable via /v1/search alias registered at app/urls.py:88"
    }
  ],
  "design_controls": [
    {"kind": "input_validation", "location": "app/forms.py:22",
     "description": "Regex allowlist on `q` before it reaches the query.",
     "applies_to": "GET /api/search"}
  ],
  "architecture": {
    "entry_points": [
      {"kind": "http_route", "name": "GET /api/search",
       "location": "app/views/search.py:38", "auth_required": false}
    ],
    "trust_boundaries": [
      {"from": "HTTP request body", "to": "SQLAlchemy text() query",
       "location": "app/db/search.py:22"}
    ],
    "external_inputs": [
      {"name": "q", "controllable_by": "anonymous_user"}
    ]
  },
  "history": [ "...verbatim copy of logs/history.json patches[]..." ]
}
```

**Field rules.**

- `input_id` — stable and unique: `in_1`, `in_2`, …. Phase 3's ledger is keyed
  on it. Never renumber on a re-run of this phase; append.
- `location` — a `file:line` you **read**. Phase 1b resolves it against the call
  graph to find the enclosing function; an invented or approximate line resolves
  to the wrong symbol, or to none, and that input silently generates no tasks.
- `variable` and `trust_level` — required, not optional. Both are read by
  deterministic code (see Step 3).
- `notes` — optional, free text. Use it for the indirect-dispatch marker, for
  aliases, and for anything you were unsure of. An honest note here is worth
  more than a confident guess in a structured field.
- `design_controls` — optional. A map of the security mechanisms you read, per
  the rules in Step 3. `kind` / `location` / `description` required,
  `applies_to` optional. Phase 2 treats every entry as a pointer to verify, and
  never as an exclusion.
- `architecture` — optional but strongly preferred. `specialists.py` reads
  `entry_points[].kind`, `entry_points[].auth_required`, `trust_boundaries`, and
  `external_inputs[].controllable_by` to decide which repo-wide specialist
  sweeps run at all. Omit it and two gates (access-control, batch-etl) fall back
  to weaker signals and may not fire.
- `history` — verbatim, per Step 1.

---

## The invariant this phase opens

> **Every input enumerated here must later carry a disposition, or the run
> fails.**

Phase 3 calls:

```bash
python3 "${SKILL_DIR}/scripts/coverage.py" assert-complete \
  --results-dir "${RESULTS_DIR}"
```

which reconciles `inputs.json` against the generated tasks and the recorded
findings and gives every `input_id` a disposition with evidence. An input that
reaches none is a hard failure of the run — not a warning, not a footnote.

The obvious way to make that assertion easy is to enumerate fewer inputs. Do not
do it, and understand why it does not work:

- **The ledger is the point.** It exists to make "we looked at everything"
  checkable. An inventory trimmed to what you were confident about converts a
  checkable claim into an unverifiable one, and the check still passes — which
  is worse than failing.
- **Phase 3 sweeps for what you missed.** It re-derives entry points from the
  call graph and the sink tables and compares against your inventory. Inputs it
  finds that you did not enumerate are reported as a *recon* gap, attributed to
  this phase.
- **An uncovered input is a legitimate outcome.** `uncovered` is a disposition.
  It is disclosed in the report as a gap, and that is an honest result. A
  *missing* input is not a gap — it is a silently smaller denominator, and no
  reader can see it.

Enumerating wide and letting some entries land `uncovered` is the correct
failure mode. Enumerating narrow so everything lands `covered` is the failure
this ledger was built to catch.

---

## Gate to Phase 1b

Proceed only when:

- [ ] `inputs.json` exists and parses
- [ ] every `input_id` is unique
- [ ] every `location` is a `file:line` in a file you read
- [ ] every `trust_level` is one of the four enum values, verbatim
- [ ] every entry point found in Step 2 appears in at least one input row, or has
      a `no-input endpoint` row
- [ ] every `entry_point_candidates` hit whose framework is `confirmed` or
      `peripheral` has been opened, and either produced an input row or is named
      in the phase summary with the reason it produced none
- [ ] for a library target, every `public_api[]` symbol's parameters are covered
      by input rows, or the summary says which are not and why
- [ ] `history` is present (possibly `[]`) and, when non-empty, byte-identical to
      the miner's array
- [ ] zero inputs is reported explicitly with the reason, not left implicit

Return a summary of **≤ 40 words**: input count, entry-point count, framework
list, history entry count. Do not return the inventory itself — it is in the
file.

---

## Things that will tempt you, and are wrong

- **Dropping an input because it is validated.** Whether the validation is
  sufficient is Phase 2's question, decided against the sink's context. A
  `isinstance(x, str)` check protects nothing from command injection.
- **Merging inputs that share an extraction point.** Different fields take
  different paths. See the sibling-input rule.
- **Inferring trust level from a path prefix or a comment.** Cite the enforcing
  code or write `unauthenticated`.
- **Re-running the history mining, or the enumeration, because you have an idea
  for a better grep.** You have no Bash, no Grep and no Glob, and the
  determinism is the feature. An idea for a better pattern is a real
  contribution — put it in the phase summary so it can be added to
  `recon_enumerate.py`, where it will apply to every future run instead of
  this one.
- **Treating `entry_point_candidates` as the complete list.** It is a floor.
  An input you find by reading that the sweep did not flag is exactly the value
  you add.
- **Enumerating a `transitive` framework's surface.** A lock file is not a
  statement that this project uses the package.
- **Reporting an empty inventory for a library target.** A library's public
  functions are its attack surface.
- **Writing a `location` you did not open.** It resolves to the wrong symbol in
  Phase 1b, and the resulting task points a hunter at unrelated code.
