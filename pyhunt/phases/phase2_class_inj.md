# Class group INJ — injection

> Read `phase2_shared.md` first. This file adds the sinks, sanitisers,
> false-positive killers and PoC shapes for **your** class group only.

You own the classes where attacker data is **parsed as instructions** by
something downstream: a shell, a SQL engine, the Python compiler, a template
engine, a code generator, a log reader, a browser.

| `attack_class` routed here | `vuln_class` to emit | CWE |
|---|---|---|
| `command_injection` | `command_injection` | CWE-78 (CWE-88 for argument injection) |
| `sql_injection` | `sql_injection` | CWE-89 |
| `code_injection` | `code_injection` | CWE-94 / CWE-95 |
| `ssti` | `ssti` | CWE-1336 |
| `codegen_injection` | `codegen_injection` | CWE-94 |
| `log_injection` | `log_injection` | CWE-117 |
| `xss_stored`, `xss_reflected` | `xss_stored` / `xss_reflected` | CWE-79 |

**Not yours:** file paths and URLs (NAV), `pickle`/`yaml`/`importlib`/`getattr`
(DESER), authorisation and secrets (LOG). Cross-flag those into
`gaps_observed` with a `suggested_attack_class` and move on.

---

## 1. What the observer can see for your classes

| Your sink | Audit event raised | Provable by execution? |
|---|---|---|
| `os.system`, `os.popen` | `os.system` / `subprocess.Popen` | **Yes** — `os.system` is an interpretation event on its own |
| `subprocess.*` with a shell | `subprocess.Popen` with argv[0] = `/bin/sh` | **Yes** |
| `subprocess.*` with a plain argv list | `subprocess.Popen` with argv[0] = the real binary | Fires, but is **not** interpretation — expect `sink_reached_unproven`, which is what a working defence looks like |
| `eval` / `exec` / `compile` | `compile` **and** `exec` | **Yes** — but only `compile` carries the payload text |
| Jinja2 / Mako render of a user-controlled template | `compile`, plus whatever the payload calls | **Yes** |
| `cursor.execute`, `session.execute`, `text()` | **nothing** | **No** — expect `no_event` |
| `logging.*` | **nothing** | **No** |
| HTML response bodies | **nothing** | **No** |

Three of your seven classes have no observable event at all. That is a property
of the instrument. Report those findings on their static argument, set
`poc.succeeded` from your PoC's own assertions, and let the gate record
`no_event`. It is not a refutation and you must not treat it as one.

---

## 2. Sinks to grep for

**OS command**
`os.system` · `os.popen` · `os.execl*` / `os.execv*` · `os.spawn*` ·
`subprocess.run` / `call` / `check_call` / `check_output` / `Popen` ·
`shell=True` anywhere · `pty.spawn` · `commands.getoutput` (py2 leftovers) ·
`asyncio.create_subprocess_shell` · `sh`/`plumbum`/`invoke`/`fabric` wrappers ·
`pandas.read_csv` with a piped command string.

**SQL**
`.execute` / `.executemany` / `.executescript` · `session.execute` ·
`sqlalchemy.text` · `.raw()` / `.extra()` / `RawSQL` (Django) ·
`.filter(text(...))` · `connection.cursor()` chains · any `f"SELECT`,
`"SELECT " +`, `"…%s…" % `, `.format(` producing SQL.

**Code evaluation**
`eval` · `exec` · `compile` · `__import__` · `types.FunctionType` ·
`code.InteractiveInterpreter` · `timeit`/`pdb` string arguments ·
`numexpr.evaluate` · `pandas.DataFrame.query` / `.eval` (these evaluate
expressions and reach Python objects) · `str.format` / `%` where the **format
string** is attacker-controlled.

**Templates**
`jinja2.Environment` · `.from_string` · `jinja2.Template` · `render_template_string`
· `mako.template.Template` · `.render(` · `django.template.Template` ·
`string.Template().substitute` / `.safe_substitute` (see §4.4 — usually not what
you think).

**Code generation**
`.py.jinja` / `.py.j2` / `.py.mako` template files · `ast.unparse` ·
`astor.to_source` · `black.format_str` · `isort.code` · f-strings and `.format`
that build source text · anything writing a `.py`, `.sql`, `.tf` or `.yaml` file
the tool itself produces.

**Log / HTML**
`logging.info/warning/error/exception` with `%` or f-string interpolation of
request data · `Markup()` · `|safe` · `mark_safe` · `autoescape` off ·
hand-rolled `f"<td>{x}</td>"`.

---

## 3. Command injection — the class this project was tuned on

### 3.1 When it is real

- `shell=True` (or `os.system` / `os.popen` / `create_subprocess_shell`) with
  **any** interpolated attacker value. `;` `|` `&` `` ` `` `$( )` `\n` all break out.
- Argv list whose **first element** is attacker-influenced:
  `subprocess.run([user_cmd, "-x"])` lets the attacker choose the binary. That is
  arbitrary program execution — at least as bad as shell injection.
- Argv list that **is** a shell: `subprocess.run(["sh", "-c", cmd])`,
  `["bash", "-lc", cmd]`. `shell=False` is irrelevant here; you handed the string
  to a shell yourself.
- **Argument injection (CWE-88)** in an otherwise correct argv list: the value
  lands in a middle element and can start with `-`. `["git", "clone", url]` with
  `url = "--upload-pack=touch /tmp/x"`; `["tar", "-xf", name]` with
  `name = "--to-command=…"`; `curl -o`, `rsync -e`, `ffmpeg -f lavfi`,
  `find -exec`. `shlex.quote` does **not** stop this — the value is already a
  single word; the problem is that it is a *flag*. The fix is a `--` separator or
  an allowlist, and its absence is a finding.

### 3.2 When it is not

- **`subprocess.run(["echo", name])` with no shell, no attacker control of
  argv[0], and a value that cannot be read as a flag is not command injection.**
  Say so and move on. This exact pattern is why the execution gate has a fifth
  condition: it raises `subprocess.Popen` from the target's own frame with your
  payload in argv, and on the first four conditions it is byte-identical to the
  vulnerable case. Reporting it launders a false positive into "confirmed by
  execution", which is worse than having no gate.
- A plain **string** command with `shell=False` (POSIX) is not shell injection —
  the whole string becomes the program name and the call simply fails. If the
  attacker controls the whole string it is still arbitrary program execution;
  if they control a suffix, it is a bug but not an exploit. Say which.
- A `shell=True` command with no interpolation at all.

### 3.3 `shlex.quote` — where it works and where it does not

`shlex.quote(v)` is correct only when the result is dropped into a shell string
**as a bare word**:

```python
cmd = f"grep {shlex.quote(pattern)} /var/log/app.log"     # correct
cmd = f"grep '{shlex.quote(pattern)}' /var/log/app.log"   # BROKEN — see below
```

The second is a finding. `shlex.quote` already adds its own quoting, and for a
value containing `'` it emits `'a'"'"'b'`; wrapping that in another pair of
single quotes lets the value's own quote close the literal early. Grep for
`shlex.quote` inside an existing quoted context — it is a common and confident
mistake. Also check: quoting applied to some interpolations in the command and
not others; quoting applied to a copy while the raw original is used later;
quoting a value that is then `.split()` or passed through `os.path.expandvars`.

---

## 4. The rest of the classes, and what actually clears them

### 4.1 SQL injection

**Parameterised is safe. String-built is not. The discriminator is whether a
parameters argument is passed** — not whether the string contains `%s`.

```python
cur.execute("SELECT * FROM t WHERE a = %s", (x,))    # SAFE — psycopg2 binds it
cur.execute("SELECT * FROM t WHERE a = %s" % x)      # INJECTION — Python formatted it
cur.execute(f"SELECT * FROM t WHERE a = {x}")        # INJECTION
cur.execute("SELECT * FROM t WHERE a = ?", (x,))     # SAFE — sqlite3 style
```

Missing this distinction is the single most common false positive in this class.
`%s` in psycopg2/mysqlclient is a **placeholder**, not a format specifier.

Then check the things parameters cannot cover:

- **Identifiers are not bindable.** Table names, column names, `ORDER BY`
  targets, `ASC`/`DESC`, schema names must be interpolated, so an allowlist is
  the only defence. `ORDER BY {user_col}` with no allowlist is a real finding
  even though every value in the query is bound.
- **`LIMIT` / `OFFSET`** — bindable in most drivers but frequently interpolated.
  `int(x)` coercion is a complete defence; a regex `^\d+$` is too. Say which one
  you found.
- **SQLAlchemy**: `text("… WHERE a = :a")` with bound params is safe;
  `text(f"…")` is not. `.filter(text(f"…"))`, `.order_by(text(user))` and
  `RawSQL`/`.extra(where=[…])` in Django are all injection sinks.
- **ORM comparisons** (`Model.x == user`) are parameterised. Not a finding.

**Receiver check (false-positive killer).** `\.execute\(` matches any object with
an `execute` method — thread-pool executors, script runners, HTTP clients, test
harnesses. Confirm the receiver is a DB cursor, connection, session or engine
before you write anything down.

### 4.2 Code evaluation

- `ast.literal_eval` is safe. Do not report it.
- **`eval(x, {"__builtins__": {}})` is not a sandbox.** The classic escape
  `().__class__.__base__.__subclasses__()` still reaches every loaded class and
  from there `os`. Emptying globals raises the effort and nothing else. Treat a
  restricted-globals `eval` on attacker data as a finding and say why the
  restriction fails.
- `compile()` alone does not execute — but find where the code object goes.
  Almost always into `exec` or `eval` a few lines later, and the finding belongs
  at the pair.
- **Attacker-controlled format strings.** `user_fmt.format(obj)` and
  `user_fmt % obj` let the attacker walk attributes:
  `"{0.__class__.__init__.__globals__[SECRET]}"`. It is a read primitive, not
  RCE — report it as `code_injection` with the disclosure impact stated, and
  cross-flag `information_disclosure` to LOG if secrets are provably in scope.
- `pandas.DataFrame.query` / `.eval` with `engine="python"` evaluate expressions
  that can reach `@`-prefixed locals. Attacker-controlled query strings are a
  finding.

### 4.3 Template injection (SSTI)

**The question is whether the attacker controls the template SOURCE or a
template VARIABLE.** Only the first is SSTI:

```python
render_template("page.html", name=user)     # user is DATA — not SSTI
render_template_string(user)                # SSTI
Environment().from_string(user).render()    # SSTI
Template(user).render()                     # SSTI
render_template(user)                       # NOT SSTI — template *name* control:
                                            # arbitrary-template render / traversal.
                                            # Cross-flag to NAV.
```

- **Jinja2** SSTI is full RCE via `{{ ''.__class__.__mro__ }}`,
  `{{ cycler.__init__.__globals__ }}`, `{{ lipsum.__globals__ }}`, `{{ config }}`
  in Flask.
- **Mako** executes Python directly inside `${ }` and `<% %>`. Attacker-controlled
  Mako source is RCE with no gymnastics.
- **`SandboxedEnvironment`** is a real control but not a verdict. Read the
  version pin: sandbox escapes via `str.format`, `attr`, and `|attr("…")` have
  shipped repeatedly. If you cannot read the installed version's source, treat it
  as ineffective per shared §Step 3(c) and say so.
- **Autoescape is off by default in bare `jinja2.Environment()`.** Flask's
  `render_template` autoescapes only `.html`, `.htm`, `.xml`, `.xhtml`. A
  `.txt` or `.j2` template rendering into an HTML response is unescaped. That is
  XSS, not SSTI.

### 4.4 `string.Template` is not code execution

`string.Template(...).substitute()` and `.safe_substitute()` appear in PyHunt's
sink table because they build text that is often *code*. The class itself only
replaces `$name` placeholders — no attribute access, no calls, no imports.
**Do not report `string.Template` as SSTI or RCE.** It matters only when the
substituted text becomes source code, config or SQL that something later
executes — and then the finding is §4.5, not this one.

### 4.5 Code generation (CWE-94) — the signature bug of a generator

If the target **generates** Python, config, SQL or markup — Jinja/Mako templates
whose output is source, `ast.unparse`, `black.format_str`, f-strings that build
a module — then untrusted input reaching the generated output without escaping
is **injected code**. Field *names*, type names, aliases, default values,
docstrings, titles, `$ref`s all count. Trace the untrusted value from the parser
**into** the template variable or the built source string and show what the
attacker can emit — e.g. a schema field default of
`x');__import__('os').system('id` appearing verbatim in the generated Python.
Check the template files and the render call sites, not just `eval`/`exec`.

**Docstring / comment terminator breakout — the highest-yield variant.** A
free-text field (`description`, `doc`, `comment`, `summary`, `title`, protobuf
`leading_comments`) is written into a string literal or a `#` comment of the
generated file. The attacker supplies the literal's **own** terminator — `"""`,
`'''`, or a bare `\r` for a comment — closing it early so the rest of their text
is real code. Execution is **deferred** to whoever imports the generated file;
do not dismiss it because the generator itself never runs the output. Precedent:
datamodel-code-generator CVE-2026-54621 / 54656 / 55415, openapi-python-client
GHSA-9x4c-63pf-525f.

**An escape call on the path is not a verdict** — most CVEs in this class had
one. Before you clear it, check and state which of these you checked:

1. Does it escape the delimiter the sink **actually** uses? Escaping `"` is
   useless for a `"""` sink; escaping `"` but not `\` lets a trailing backslash
   escape the escape.
2. Does it survive `\"""`, `""\"`, or a lone `\r`?
3. Is it applied at **every** call site of that field? Grep them all — one
   correct site proves nothing about its siblings.
4. Does a sanitised copy sit next to the still-raw original, reused later in a
   decorator argument, a dict key, or an import line?

Values routed through `repr()`, `json.dumps()`, or `ast.Constant` + `ast.unparse`
are safe. Do not report those.

### 4.6 Log injection and XSS

**Log injection (CWE-117)**: unescaped `\n` / `\r` in a value written to a log
lets an attacker forge log records — audit-trail manipulation, and log-parser
injection where a SIEM ingests the file. Usually `low`; raise it when the log is
the authorisation audit trail or is parsed by something that acts on it.

**XSS (CWE-79)** in a Python target is nearly always an escaping failure:
`Markup(user)`, `|safe`, `mark_safe`, `autoescape` off, `json.dumps` inside a
`<script>` block (which does not escape `</script>`), or hand-built HTML in an
f-string. Trace to the response, and name the context (HTML body, attribute,
`<script>`, URL attribute) because the required escaping differs per context.

---

## 5. Sanitiser table — what clears an INJ finding

| Sink | Clears it | Does **not** clear it |
|---|---|---|
| Shell | argv list with a fixed argv[0], no shell, `--` before user values, or an allowlist | `shlex.quote` inside existing quotes; blocklisting `;` and `\|`; `.replace("'", "")`; `re.escape` |
| SQL | bound parameters; allowlist for identifiers; `int()` for numerics | escaping quotes by hand; `%s` with no params argument; "the ORM is used elsewhere" |
| `eval`/`exec` | `ast.literal_eval`; an allowlist checked **before** evaluation | empty `__builtins__`; a regex over the expression; `nan`/`inf` filtering |
| Template | passing user data as a **variable**; a read, version-pinned sandbox | `SandboxedEnvironment` you did not read; stripping `{{` |
| Generated source | `repr()`, `json.dumps()`, `ast.Constant` + `ast.unparse` | an escaper that handles the wrong delimiter, or is applied at some call sites |
| HTML | context-correct autoescaping you confirmed is on | an HTML escaper on a URL or JS context; a "sanitiser" that validates shape |

A validator that checks **shape** (a regex, a JSON Schema, a Pydantic type)
validates nothing about **content** unless the shape it enforces excludes every
dangerous character. If it enforces `^[A-Za-z0-9_-]+$`, say so and clear the
finding. If it enforces "is a string", it clears nothing.

---

## 6. PoC shapes

The universal rule from `phase2_shared.md` applies: **enter through the target's
own function**, put the canary **early** in the payload, and paste the complete
output. Below, `CANARY` is `poc_execution.canary_path`.

**Command injection.** Make the target build the shell command; do not build it
yourself.

```python
import app.reports                                   # the TARGET's module
app.reports.build_report(name=f"; touch {CANARY}; #")
```

Proof looks like a `subprocess.Popen` (or `os.system`) marker whose argv[0] is
`/bin/sh` and whose command string contains the nonce, attributed to
`app/reports.py`. If instead you see argv[0] = `/bin/echo` with the payload sitting
in argv[1], the sink is **defended** — that is `sink_reached_unproven`, it is the
right answer, and forcing a shell yourself to "get proof" is falsification.

**Argument injection.** The canary must come from the injected *flag*:
`url = f"--upload-pack=touch {CANARY}"`. Same marker shape.

**Code evaluation.** Put the canary in the source string so the `compile` event
carries it — the `exec` event's argument is a code object and shows nothing:

```python
target.calc(expr=f"__import__('os').system('touch {CANARY}')")
```

**SSTI.** Jinja2 payload that reaches `os.popen` (which uses a shell, so argv[0]
is `/bin/sh` and the payload text is in the command):

```python
target.render_user_template(f"{{{{ cycler.__init__.__globals__.os.popen('touch {CANARY}').read() }}}}")
```

**SQL injection.** Not observable. Write a PoC that proves the *parser* saw your
syntax — rows returned that the intended query could not return, a
`sqlite3.OperationalError` naming the injected clause, a `UNION` result — assert
on that, set `poc.succeeded` from the assertion, and expect `no_event`. Do not
invent a shell to make a marker appear. If the injection can drive an operation
the observer *does* watch (a driver that opens a file, a stored procedure the
application then feeds to `open`), take that route and say so in `poc.notes`.

**Code generation.** The best PoC here is **not** execution. Generate the file
from a crafted schema, then `ast.parse` it and show the injected marker parsed
as a `Name` or a statement rather than as string text. That proves it became
code and is safe to publish. Do **not** `exec` or `compile` the generated source
inside your PoC — the event would be attributed to your file and the gate would
correctly return `self_attributed`. Expect `no_event`, report `succeeded: true`
if the AST assertion held, and say in `poc.notes` that the proof is an AST
assertion rather than an observed event.

---

## 6a. Codegen injection — declare a `codegen_ast` probe, and mind the indent

`codegen_injection` is the one class in this group the audit hook **cannot see
at all**. Writing a `.py` file containing an attacker-controlled call raises no
CPython audit event, and a PoC that runs the generated module hands condition 4
a filename its own `compile()` minted — the C-4 defence working exactly as
designed. Every such PoC returns `not_applicable`, correctly, forever. On one
real run that was 74 of 145 findings.

So this class is settled by the **second oracle** (`phase2_shared.md` §6.8).
Declare the probe; do not write the assertion.

```json
"structural_probe": {
  "kind": "codegen_ast",
  "target": "pkg.model_generator.generator.ModelGenerator.render",
  "construct": "pkg.model_generator.generator.ModelGenerator",
  "benign_kwargs": {"schema": {"type": "record", "name": "M",
                               "doc": "an ordinary docstring $PYHUNT_BENIGN",
                               "fields": [{"name": "a", "type": "string"}]}},
  "hostile_kwargs": {"schema": {"type": "record", "name": "M",
                                "doc": "x\"\"\"\npyhunt_$PYHUNT_NONCE()\n\"\"\"",
                                "fields": [{"name": "a", "type": "string"}]}},
  "rationale": "record `doc` is interpolated into the emitted class docstring with no escaping"
}
```

**The indentation trap, which you will hit.** A generator usually re-indents the
continuation lines of a docstring to the class body's level. If your payload
carries its own four spaces, they are added to the generator's four and the
injected statement lands at eight — a `SyntaxError: unexpected indent`, and the
oracle returns `inconclusive` rather than `demonstrated`:

> "the attacker's text changed the emitted module enough that it no longer
> parses. That proves the payload escaped its literal, but not that what it
> became is executable — a syntax error is a broken generator, not a
> demonstrated injection."

That is the oracle refusing to over-claim, and it is right to. Write the payload
with **no leading whitespace on the injected line** and let the generator supply
the indentation. Verified against a live generator: with the payload above, the
emitted module is

```python
class M(AvroModel):
    """
    x"""
    pyhunt_<nonce>()
    """
    """
    a: str
```

— the nonce is a `Name` node inside an `Expr` statement, where the benign
control produced an inert `Expr(Constant)`. Differential holds; verdict
`demonstrated`, 2/2 unanimous.

**Prefer the nonce as an identifier** (`pyhunt_<nonce>()`) over the nonce inside
a string argument (`system("touch /canary/<nonce>")`). Both are read correctly —
the harness inspects the enclosing statement as well as the innermost node — but
an identifier makes the answer unambiguous in one field rather than two.

**Aim at the field the generator actually renders.** If the benign marker never
reaches the generated source, the probe is a `probe_error` and says nothing:
the payload went into a field this generator ignores. Check which fields the
template consumes before choosing one.

---

## 7. Do not eliminate these

- **Any attacker-controlled unsanitised value that crosses a tier boundary** —
  into an internal API, a queue, a cache, a downstream service. Default to a
  finding. Downgrade only by citing the `file:line` where the downstream
  validates it.
- **A scope-mismatched sanitiser is no sanitiser.** An HTML escaper protecting a
  shell, a URL encoder protecting SQL, a `re.escape` protecting a template.
- **"The value is probably short/numeric/from our own UI."** The client is not a
  control.
- **Deferred execution.** Injected code in a generated file that nothing in this
  repo runs is still injected code; the victim is whoever imports it.

**Severity floor.** A confirmed injection reaching a shell, a database, or the
Python compiler with the service's own credentials is **high** at minimum. Do
not downgrade for "uncertain downstream impact", "read-only", or "the base
command is hard-coded".
