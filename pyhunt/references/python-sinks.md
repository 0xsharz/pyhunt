# Python sinks and sanitisers

What PyHunt actually matches, what neutralises each match, and the
Python-specific reasons a match is usually **not** a finding.

This file documents `PYTHON_SINKS` in `scripts/taint.py`, the specialist gates in
`scripts/specialists.py`, and the eligibility filter in `scripts/catchall.py`. It
is written from the regexes, not from a general idea of which Python functions
are dangerous. Where the table is deliberately narrower or broader than you would
expect, the reason is recorded — those choices were measured.

## How the matching works, and what a match means

- **Line-by-line regex over statically-read source.** Files are read UTF-8 with
  `errors="replace"`. The target's code is **never executed** to find sinks.
- **First matching class per line wins.** One dangerous line yields at most one
  sink. Dict order decides ties, and it is: command_injection → code_injection →
  deserialization → unsafe_reflection → path_traversal → ssrf → sql_injection →
  xxe → ssti → open_redirect → log_injection → information_disclosure. This
  matters: `Template(`, `Environment(` and `.from_string(` appear in **both**
  `code_injection` and `ssti`, so they are always tagged `code_injection`. A
  server-side template injection in this codebase arrives labelled as code
  injection; do not conclude SSTI was not hunted.
- **A sink becomes a task only if the graph resolves an enclosing symbol.** A
  dangerous call at module scope in a file the call graph did not parse produces
  no task. That is a coverage gap, and it belongs in `gaps_observed`.
- **A match is a place to look, never a finding.** Precision comes from the
  hunter tracing source→sink and from the adversarial phase 2c. These patterns
  are tuned for recall; several of them fire on completely ordinary code, and
  the entries below say which.

---

## The sink table

### `command_injection` (CWE-78)

| Matched | Tainted argument | Neutralised by |
|---|---|---|
| `subprocess.run` / `call` / `check_call` / `check_output` / `Popen` | the command — `args`, whether string or list | a **list** argv with `shell=False` (the default), where the tainted value is a non-zero element |
| `os.system` | the whole command string | nothing; there is no safe form. Rewrite to `subprocess` with a list |
| `os.popen` | the command string | as above |
| `os.execl*` / `os.execv*` / `os.spawn*` | argv | list form where the tainted value is not argv[0] and no shell is invoked |
| `commands.getoutput` / `getstatusoutput` | the command string | Python 2 only; its presence is itself a finding-adjacent fact |
| a bare `shell=True` on any line | whichever argument the shell parses | `shell=False` + list argv, or `shlex.quote()` on every interpolated value |
| `pty.spawn` | argv | list form, fixed program |

**False-positive killers.**

- **`subprocess.run(["echo", name])` is defended, and looks identical to the
  vulnerable form at the audit-event level.** This is the exact case that forced
  condition 5 into the execution gate (`references/execution-gate.md`). A list
  argv means the OS passes the tainted value to `execve` as one argument; no
  shell parses it. Do not report it, and do not accept a `proven` verdict on it —
  the gate will return `sink_reached_unproven`, which is what a working defence
  looks like from the runtime.
- **`shlex.quote()` on every interpolated value** neutralises `shell=True`.
  "Every" is the load-bearing word: one unquoted value in a five-value command
  string is still command injection.
- **The `\bshell\s*=\s*True\b` pattern matches the kwarg alone**, wherever it
  appears — including on a continuation line of a call whose command is a fixed
  literal. Read the call, not the line.
- A **fixed program with a tainted argument** (`subprocess.run(["git", "log",
  user_ref])`) is argument injection, not command injection: the question becomes
  whether the program has flags that read or write files (`--upload-pack`,
  `--output`). That is a real finding, with a different CWE and a different
  impact claim.

### `code_injection` (CWE-94 / CWE-95)

| Matched | Tainted argument | Neutralised by |
|---|---|---|
| `eval(` | the expression | `ast.literal_eval()`, which parses literals only and cannot call |
| `exec(` | the statement source | nothing; no safe form exists |
| `compile(` | the source | as above |
| `__import__(` | the module name | an allow-list checked **before** the call |
| `types.FunctionType(` | the code object | nothing |
| `.render(` / `Template(` / `Environment(` / `.from_string(` / `render_template(_string)?(` | the **template text**, not the context | passing the tainted value as a *context variable* rather than as template source |
| `f"""` / `'''` or `"""` opening straight into a `{` slot | the interpolated value | `repr()`, `json.dumps()`, or `ast.Constant` + `ast.unparse` |
| `.substitute(` / `.safe_substitute(` | the template string | as above |

**The code-generation variant is the one that gets missed.** If the target
generates source, config, SQL or markup, untrusted input that reaches the
generated output without escaping *is* injected code, and execution is deferred
to whoever imports the generated file. The highest-yield shape is the
**docstring / comment terminator breakout**: a free-text field (`description`,
`doc`, `comment`, `summary`, `title`, protobuf `leading_comments`) written into a
string literal or `#` comment of the emitted file. The attacker supplies the
literal's own terminator — `"""`, `'''`, or a bare `\r` for a comment — closing
it early so the remainder is real code.

**False-positive killers, and the killers that are not.**

- **`ast.literal_eval` is safe. `eval` is not.** No further analysis needed.
- **Values routed through `repr()`, `json.dumps()`, or `ast.Constant` +
  `ast.unparse` are safe** in the codegen case — do not report those.
- **An escape call on the path is not a verdict.** Most CVEs in this class had
  one. Before clearing it, check and state which you checked:
  1. does it escape the delimiter the sink **actually** uses? Escaping `"` is
     useless for a `"""` sink; escaping `"` but not `\` lets a trailing backslash
     escape the escape;
  2. does it survive `\"""`, `""\"`, or a lone `\r`?
  3. is it applied at **every** call site of that field? Grep them all — one
     correct site proves nothing about its siblings;
  4. is there a sanitised copy sitting next to the still-raw original, reused
     later in a decorator argument, a dict key, or an import line?
- **`.render(` is extremely common and usually benign.** The template being a
  fixed file with the tainted value in the context is the normal, safe case. The
  finding is a tainted *template source*, or a codegen emitter.
- **The best PoC here is not execution.** Generate the file from a crafted
  schema, `ast.parse` it, and show the injected marker parsed as a `Name` or a
  statement rather than as string text. That proves it became code, and it is
  safe to publish.

### `deserialization` (CWE-502)

| Matched | Tainted argument | Neutralised by |
|---|---|---|
| `pickle.load` / `loads`, `cPickle`, `_pickle` | the bytes | nothing. Pickle is arbitrary code execution by design |
| `yaml.load(` **without** `SafeLoader` / `CSafeLoader` | the document | `yaml.safe_load()`, or `Loader=yaml.SafeLoader` |
| `yaml.unsafe_load` / `yaml.full_load` | the document | as above |
| `marshal.load` / `loads` | the bytes | nothing |
| `dill.load` / `loads` | the bytes | nothing |
| `jsonpickle.decode` / `loads` | the document | plain `json.loads` into a schema |
| `shelve.open` | the file (a pickle store) | nothing; treat the store's writers as the attack surface |
| `pandas.read_pickle` / `pd.read_pickle` | the file | a non-pickle format |
| `joblib.load` | the file | a non-pickle format |
| `numpy.load(..., allow_pickle=True)` | the file | drop `allow_pickle` (safe by default) |
| `torch.load(` **without** `weights_only=True` | the file | `weights_only=True` |

**False-positive killers.**

- **A `Loader=` kwarg is not a fix.** `Loader=yaml.Loader` and
  `Loader=yaml.UnsafeLoader` are full deserialisers, and `FullLoader` was
  RCE-capable before PyYAML 5.4 (CVE-2020-14343). The regex exempts *only*
  `SafeLoader` / `CSafeLoader` for exactly this reason — an earlier version
  exempted anything with a `Loader=` kwarg and silently cleared all three.
- **`numpy.load` and `torch.load` are safe by default** on current versions. The
  patterns match the *override*, not the call — so a match here means someone
  turned the protection off deliberately.
- **The sink is often one layer down.** A `Serializer.load()` or `deserialize()`
  wrapper hides the real call; audit the **wrapper's** callers too.
- **For a cache, session, or queue read, ask who can WRITE that key**, not who
  reads it. "The value comes from Redis" is not a trust boundary; it is a
  question about who can put things in Redis.

### `unsafe_reflection` (CWE-470)

| Matched | Tainted argument | Neutralised by |
|---|---|---|
| `importlib.import_module(` | the module name | an allow-list checked **before** the call |
| `pydoc.locate(` | the dotted name | as above |
| `globals()[` | the key | a fixed dispatch dict |

**Resolving a name is not a lookup: importing runs the module's top-level code**,
so an allow-list applied *after* resolution has already lost.

**`getattr(obj, name)` is deliberately NOT in this table.** It measured 34 hits
across the bench targets, almost all benign dynamic attribute access. It belongs
in the hunter's lens, not in a table that spends a hunt task per match. If you
find a genuinely dangerous `getattr` — a name from a request used to select a
callable that is then invoked — report it; its absence from the table is a
budget decision, not a judgement that it is safe.

### `path_traversal` (CWE-22 / CWE-23)

| Matched | Tainted argument | Neutralised by |
|---|---|---|
| `open(` | the path | `os.path.realpath()` + a `startswith(base)` containment check |
| `os.path.join(` | any component after the base | as above. **`join` does not neutralise `..`**, and an absolute component silently discards the base |
| `shutil.copy*` / `move` / `rmtree` | source or destination | as above |
| `send_file(` / `send_from_directory(` | the filename | `send_from_directory` with a fixed directory *and* a validated basename |
| `os.remove` / `os.unlink` | the path | as above |
| `Path(` | the path | as above |

**False-positive killers.**

- **`open(` and `Path(` are the noisiest patterns in the whole table.** Most
  matches are fixed literals or config-derived paths. The finding requires a
  tainted component and no containment check.
- **`os.path.join(base, user)` is not a defence — it is the classic sink.**
  `join("/srv/data", "../../etc/passwd")` returns the traversal, and
  `join("/srv/data", "/etc/passwd")` returns `/etc/passwd`.
- **Basename-only handling** (`os.path.basename(user)`) is a real defence against
  traversal, though not against overwriting a sibling in the same directory.
- **Archive extraction is a separate shape the table does not match**:
  `tarfile.extractall` / `zipfile.extractall` on an untrusted archive is zip-slip
  — member names containing `../` or absolute paths. Hunt it; the table's silence
  is a gap, not an all-clear.
- **UNC prefixes on Windows** (`\\host\...`, `//host/...`) passed to `open` or
  any Win32 path API trigger SMB and leak the runner's NTLMv2 hash (CWE-73). A
  containment check that only rejects `..` does not reject these.

### `ssrf` (CWE-918)

| Matched | Tainted argument | Neutralised by |
|---|---|---|
| `requests.get/post/put/delete/head/patch/request` | the URL — specifically its **scheme, host, or port** | an allow-list of hosts resolved **after** DNS, plus `allow_redirects=False` |
| `urllib.request.urlopen(` / bare `urlopen(` | the URL | as above |
| `httpx.get/post/put/delete/request/Client/AsyncClient` | the URL | as above |
| `aiohttp.ClientSession` / `aiohttp.request` | the URL | as above |
| `socket.connect` / `socket.create_connection` | the address tuple | a fixed host, or an allow-list |

**False-positive killers.**

- **A tainted path or query string on a fixed host is not SSRF.** The finding
  requires control of scheme, host, or port. `requests.get(f"{FIXED}/{user}")` is
  a path-traversal-shaped question, not an SSRF one — unless `user` can contain
  `//evil.com` or `@evil.com` and change the authority.
- **Redirect following re-opens it.** An allow-list checked on the initial URL
  with `allow_redirects=True` (the default for `requests`) is bypassed by a
  redirect to an internal host.
- **A validated hostname is still DNS-rebindable.** Checking the name and then
  letting the library resolve it separately is a TOCTOU.
- **The response is tainted too.** If the attacker chose the server, the response
  body is attacker-controlled — trace it forward. Do not treat the outbound call
  as a terminal sink.

### `sql_injection` (CWE-89)

| Matched | Tainted argument | Neutralised by |
|---|---|---|
| `.execute(` / `.executemany(` / `.executescript(` | the query string | DB-API **bound parameters**: `cur.execute("… WHERE id = %s", (uid,))` |
| `session.execute(` | the statement | SQLAlchemy bound parameters, or the expression language |
| `text(` | the SQL text | `text("… :id").bindparams(id=uid)` |
| `.raw(` | the query | Django's `raw()` `params=` argument |

**False-positive killers.**

- **Parameterised queries are safe, and this is the single most common false
  positive in the class.** The placeholder style varies by driver (`?`, `%s`,
  `:name`) and none of them is string formatting. A `%s` inside a query string
  passed with a params tuple is a **bind marker**, not `%`-interpolation — do not
  report it.
- **Bound parameters cannot parameterise identifiers.** Table and column names,
  `ORDER BY` targets and `LIMIT` cannot be bound; those need an allow-list, and
  a tainted identifier is a genuine finding even when the values are bound.
  `psycopg2.sql.Identifier` is the safe construction.
- **`.execute(` matches any method named `execute`.** `executor.execute(fn)`,
  `pipeline.execute()`, and a Celery task's `.execute()` all match. Read the
  call.
- **`text(` matches `gettext`-style helpers and any local function named
  `text`.** Check the import.
- **An ORM does not make it safe**: `.extra()`, `.annotate(RawSQL(...))` and
  f-strings inside `filter()` all reach raw SQL.

### `xxe` (CWE-611)

| Matched | Tainted argument | Neutralised by |
|---|---|---|
| `etree.parse` / `fromstring` / `XML` | the document | `defusedxml`, or an `XMLParser(resolve_entities=False, no_network=True)` |
| any line naming `lxml` | — (module-level signal) | as above |
| `xml.dom.minidom`, `xmlrpc`, `pulldom` | the document | `defusedxml` equivalents |
| `sax.parse` / `parseString` | the document | disabling external general entities |

**False-positive killer.** Modern `xml.etree.ElementTree` does not resolve
external entities, so a plain-stdlib parse of untrusted XML is billion-laughs /
DoS territory rather than file disclosure. `lxml` **does** resolve them by
default. Name which parser you found; the bare `\blxml\b` pattern fires on an
import line and proves nothing on its own.

### `ssti` (CWE-1336)

Matches `Template(`, `render_template_string(`, `.from_string(`, `Environment(`.

In practice these lines are tagged `code_injection` because that class is checked
first. The distinction that matters is unchanged: the finding is a **tainted
template source**, not a tainted template *context*. `render_template("x.html",
name=user)` is the normal safe case; `render_template_string(user)` is RCE via
Jinja's sandbox escape.

### `open_redirect` (CWE-601)

Matches `redirect(`, `HttpResponseRedirect(`.

Tainted argument: the target URL. Neutralised by an allow-list of paths, or by
rejecting anything with a scheme or `//` prefix. **False-positive killer:** a
redirect to a tainted *path* on the same origin is not an open redirect —
`//evil.com` and `https://evil.com` are, and so is `/\evil.com` on some
browsers.

### `log_injection` (CWE-117)

Matches `logging`/`logger`/`log` `.info|warning|warn|error|debug|critical|exception(`
whose argument list contains a `%`.

Tainted argument: the interpolated value. Neutralised by passing the value as a
**logging argument** (`log.info("user=%s", user)`) rather than pre-formatting it,
and by stripping CR/LF before logging. **False-positive killer:** the pattern
fires on `%`-style lazy logging, which is the *recommended* form. The finding is
CR/LF or ANSI-escape injection into a log a human or a parser reads, or a format
string built from user data — not the presence of `%`.

### `information_disclosure` (CWE-200)

Matches `traceback.format_exc` / `format_exception` / `print_exc`, and any
`.format_exc(`. A deliberately narrow net.

A broad `except` that prints, logs, returns, or string-formats a caught
exception, a traceback, or an object's repr can leak secrets that object carries:
connection and request objects embed headers including `Authorization`, URLs
embed credentials, config objects embed keys.

**Report a finding only when a secret-bearing value is provably in scope of the
printed expression.** A bare `traceback.format_exc()` with no secret in scope is
not a finding. Note also that this class is in
`UNDECIDABLE_BY_EXECUTION` — whether a disclosed value is *sensitive* is a
judgement about the data, not an observable runtime event, so it will come back
`not_applicable` from the gate. That is correct, and it is not a failure to
prove.

---

## Classes with no sink pattern, hunted by specialist sweep

`scripts/specialists.py` adds one repo-wide task per lens **whose surface
actually exists in this repo**, so verification budget is never spent proving a
guaranteed false positive.

| Lens | Attack class | Turned on by |
|---|---|---|
| `crypto` | `weak_crypto` | any of AES, RSA, HMAC, SHA-1/2, MD5, PBKDF2, bcrypt, scrypt, argon2, Cipher, X509, PKCS, TLS, SSLContext, jwt, jose, nacl, sodium, `hashlib`, `hmac.`, `cryptography.`, OpenSSL, SecureRandom appearing anywhere in source |
| `logic-bug` | `logic_error` | **always on** — behavioural and state-machine defects have no file signature |
| `access-control` | `auth_bypass` | an entry point of kind `http_route`/`rpc`/`grpc`/`webhook`, or any entry point declaring `auth_required` (either value), or an external input controllable by `anonymous_user`/`authenticated_user`, or any declared trust boundary, or an input whose `trust_level` is `unauthenticated`/`authenticated` |
| `deserialization` | `deserialization` | the JVM-flavoured signature (`ObjectInputStream`, `readObject`, `XMLDecoder`, `XStream`, `SnakeYAML`, `yaml.load`, `pickle.`, `marshal.load`, …) **or** the Python supplement (`joblib.load`, `read_pickle`, `torch.load`, `dill.load(s)`, `jsonpickle.decode/loads`, `shelve.open`, `yaml.unsafe_load/full_load`, `allow_pickle=True`, `weights_only=False`, `pydoc.locate`, `importlib.import_module`) |
| `batch-etl` | `improper_input_handling` | a `cli`/`file_input` entry point, or `struct.pack/unpack`, EBCDIC codecs, `cp037`/`cp1047`, COMP-3, RECFM/LRECL, `glob.glob`, `os.listdir`, `shutil.move/copy`, `csv.writer/reader`, JCL `EXEC PGM=` / DD statements |
| `iac` | `security_misconfiguration` | any infrastructure-as-code file (Terraform, Ansible, Bicep, Dockerfile, Kubernetes/Helm, CI configs) |
| `codegen` | `codegen_injection` | **both** halves below |

The `codegen` gate is the unusual one and worth understanding, because it is what
catches the CWE-94 class above. It requires:

1. **The repo emits source code**, proved by any one of: a template named for the
   code extension it produces (`endpoint_module.py.jinja`, `model.ts.j2`); a
   template whose *body* is source code (contains `"""`/`'''`, or a
   `class`/`def`/`import`/`from`/`func`/`package`/`interface`/`@dataclass` line)
   and does **not** look like markup; or a call to `ast.unparse`,
   `astor.to_source`, `black.format_str`, `isort.code`, or `autopep8.fix_code`.
2. **The repo reads free-text schema fields** — `.get("doc"/"description"/
   "comment"/"summary"/"help"/"documentation")`, a `.description`/`.comment`/
   `.summary`/`.docstring` attribute, `obj.help`, or protobuf
   `leading_comments`/`trailing_comments`.

Deliberately **not** proof of emission: `.write_text(`, `open(..., "w")`,
importing jinja2, or the word "generator". Every one of those is ubiquitous in
repos that generate nothing.

Known over-fire, disclosed rather than hidden: a repo carrying Alembic's
`alembic/script.py.mako` passes the emitter half honestly, and any unrelated
`.description` read satisfies the other. The gate is biased that way on purpose —
over-firing spends a hunt task, under-firing loses the bug.

---

## What never gets hunted at all

`scripts/catchall.py` runs a terminal whole-repo sweep so every eligible source
file gets at least one hunt. These are dropped from that sweep, and if nothing
else reached them they were never examined:

- **Extensions:** `.md .mdx .txt .rst .adoc`, images and fonts, `.css .scss .sass
  .less`, `.lock .log .map .min.js .min.css`, `.snap .d.ts`, `.csv .tsv .xls
  .xlsx`, `.po .pot .mo`
- **Names:** `license changelog changes authors contributors notice readme
  codeowners .gitignore .gitattributes .editorconfig .prettierrc
  .prettierignore .eslintignore .dockerignore`, and every lockfile
- **Directory parts:** `__snapshots__ __fixtures__ fixtures __mocks__ mocks docs
  doc examples example samples`

**Credential-prone configs are deliberately KEPT** — `.env`, `.npmrc`, `.yarnrc`,
`*.key`, `*.pem`, `*.p12`. A secret in a checked-in `.env` is a finding.

Two honesty consequences:

- The sweep caps its task count. Eligible files beyond the cap are counted in
  `catchall_dropped`, and any non-zero value there means coverage is
  **incomplete** and the report must say so.
- Everything in the skip list above is outside the coverage denominator. If a
  vulnerability lives in a file under `examples/`, PyHunt did not look.

---

## Related

- `references/execution-gate.md` — why `subprocess.run(["echo", name])` cannot be
  proven, and the eight outcomes
- `references/honest-reporting.md` — the denominators these tables feed
- `scripts/taint.py`, `scripts/specialists.py`, `scripts/catchall.py` — the code
  this file documents. When they change, change this file in the same edit.
