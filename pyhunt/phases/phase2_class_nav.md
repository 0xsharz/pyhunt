# Class group NAV — traversal, SSRF, redirect, XXE

> Read `phase2_shared.md` first. This file adds the sinks, sanitisers,
> false-positive killers and PoC shapes for **your** class group only.

You own the classes where attacker data chooses a **destination**: which file is
opened, which host is contacted, where the browser is sent, which external
entity is pulled in. The payload is not code — it is a *name*, and the bug is
that the name was not constrained.

| `attack_class` routed here | `vuln_class` to emit | CWE |
|---|---|---|
| `path_traversal` | `path_traversal` | CWE-22 |
| `zip_slip` | `zip_slip` | CWE-22 |
| `ssrf` | `ssrf` | CWE-918 |
| `open_redirect` | `open_redirect` | CWE-601 |
| `xxe` | `xxe` | CWE-611 |
| `improper_input_handling` | `improper_input_handling` | pick the specific CWE |

**Not yours:** shells, SQL, `eval`, templates (INJ); `pickle`/`yaml`/`importlib`
(DESER); who is *allowed* to reach the endpoint (LOG). If a traversal is only
exploitable because an ownership check is missing, the traversal is yours and
the missing check is a `gaps_observed` entry for LOG.

---

## 1. What the observer can see for your classes

| Your sink | Audit event | Provable by execution? |
|---|---|---|
| `open` / `io.open` / `os.open` on an attacker-chosen path | `open` | **Yes** — an `open` carrying the nonce is an interpretation event |
| `shutil.*`, `os.remove`, `Path.write_text` | `open` (underneath) | **Yes**, usually |
| `requests` / `httpx` / `urlopen` to an attacker-chosen host | `socket.getaddrinfo`, `socket.connect`, `urllib.Request` | **Yes** — all three are interpretation events |
| `redirect()` / `HttpResponseRedirect` | **nothing** | **No** — expect `no_event` |
| `lxml` / `xml.sax` / `ElementTree` entity expansion | **nothing** (libxml2 and expat do their own I/O in C, below the Python layer) | **No** |
| Archive extraction | `open` per member | Usually yes |

Two filters will eat your evidence if you ignore them: `open` is suppressed for
paths ending `.py`, `.pyc`, `.pyi`, `.so`, `.pyd`, `.dll`, `.egg`, and for
anything under the interpreter's own prefix. **Never aim a traversal PoC at a
`.py` file or at anything inside the virtualenv** — the read will succeed and
the marker will be filtered as import noise, and you will report `no_event` on a
working exploit. Aim at the canary path.

---

## 2. Sinks to grep for

**Filesystem**
`open` · `io.open` · `os.open` · `pathlib.Path(...).read_text/.write_text/.open`
· `os.path.join` · `shutil.copy*` / `move` / `rmtree` / `unpack_archive` ·
`os.remove` / `unlink` / `rename` / `makedirs` · `send_file` ·
`send_from_directory` · `FileResponse` · `tarfile.open` / `.extractall` ·
`zipfile.ZipFile` / `.extractall` · `glob.glob` · `os.listdir` · `os.walk` ·
`tempfile.NamedTemporaryFile(dir=…)` · `open(..., "w")` anywhere the name is
built.

**Outbound network**
`requests.get/post/put/delete/head/patch/request` · `requests.Session` ·
`httpx.*` · `urllib.request.urlopen` / `Request` / `urlretrieve` ·
`aiohttp.ClientSession` · `socket.connect` / `create_connection` ·
`ftplib` / `smtplib` / `paramiko` / `boto3` with an endpoint URL ·
webhook senders · image/PDF/SVG fetchers · `Image.open` on a URL-derived stream.

**Redirect**
`flask.redirect` · `django.shortcuts.redirect` · `HttpResponseRedirect` ·
`RedirectResponse` (FastAPI/Starlette) · manual `Location` header assignment.

**XML**
`lxml.etree.parse` / `fromstring` / `XML` / `XMLParser` · `xml.etree.ElementTree`
· `xml.dom.minidom` · `xml.dom.pulldom` · `xml.sax` · `xmlrpc.client` ·
`xmltodict` · SOAP / SAML / OOXML / SVG handlers (these are all XML).

---

## 3. Path traversal

### 3.1 The three ways it actually happens in Python

1. **`os.path.join` discards the base when the second argument is absolute.**

   ```python
   os.path.join("/var/data", "/etc/passwd")   # -> "/etc/passwd"
   Path("/var/data") / "/etc/passwd"          # -> PosixPath("/etc/passwd")
   ```

   A `..` filter that never considers an absolute path misses this entirely, and
   it is the single most common traversal in Python code. Check it first.
2. **`..` segments** — plain, URL-encoded (`%2e%2e%2f`) if the framework decodes
   before the handler sees it, or doubled (`....//`) against a filter that
   replaces `../` once and does not loop.
3. **A symlink inside the allowed base**, when containment is checked with
   `os.path.abspath` (which normalises `..` textually but does **not** resolve
   symlinks) instead of `os.path.realpath`.

### 3.2 What actually clears it

The complete defence is *resolve, then contain*:

```python
base = os.path.realpath(BASE)
cand = os.path.realpath(os.path.join(base, user))
if os.path.commonpath([base, cand]) != base:
    raise Forbidden
```

Accept these as equivalent, and say which you found:

- `Path(user).resolve().is_relative_to(base_resolved)` (3.9+);
- `os.path.realpath(cand).startswith(base + os.sep)` — the **separator matters**:
  `startswith("/var/data")` alone admits `/var/data-evil`;
- `werkzeug.security.safe_join(base, user)` — a real, correct defence, and what
  Flask's **`send_from_directory`** uses internally. `send_file` does **not**
  use it: `send_from_directory(dir, user)` is safe, `send_file(os.path.join(dir,
  user))` is not. That pair is the highest-value discriminator in Flask code;
- `werkzeug.utils.secure_filename(user)` — correct for a *filename*, useless as a
  *path* defence (it flattens directories away, which is the point, so verify
  the result is then joined to a fixed base and not to another user value).

Do **not** accept:

- a `..` blocklist without absolute-path rejection (see §3.1.1);
- `os.path.normpath` on its own — `normpath("../../etc/passwd")` is still
  `../../etc/passwd`;
- `os.path.abspath` for containment when symlinks are possible;
- an extension allowlist (`.endswith(".csv")`) — it constrains the suffix, not
  the directory, and `../../etc/passwd` can be renamed by the attacker in an
  upload flow;
- a null-byte claim. Modern CPython raises `ValueError: embedded null byte` for
  paths containing `\0`, so **do not report null-byte truncation** as the bug.

### 3.3 Archive extraction — get this one right

- **`zipfile.ZipFile.extract` / `.extractall` sanitise member names** in current
  CPython: leading `/` and `..` components are stripped. A plain zip-slip claim
  against `zipfile` is usually a **false positive**. What is still real: symlink
  members (zipfile does not create them, so check whether the code recreates
  them itself), member-name collisions, and decompression bombs.
- **`tarfile.extractall` is the dangerous one.** With no `filter=` argument it
  applies no restriction at all — `..` members and absolute paths write anywhere,
  and symlink members redirect subsequent writes (CVE-2007-4559). The `filter`
  parameter arrived in 3.12 and was backported to 3.8.17 / 3.9.17 / 3.10.12 /
  3.11.4, but its **default stays `fully_trusted` until Python 3.14**, where it
  becomes `"data"` (PEP 706). So on every version a real project is likely to be
  pinned to, `extractall(path)` with no filter is the vulnerable call.
  `filter="data"` is safe; `filter="tar"` still allows absolute paths and links;
  `filter="fully_trusted"` is the old behaviour. **Read the pinned Python version
  and the call site**, and say which you found. `TarFile.extraction_filter` may
  also be set once at module level — grep for it before concluding.
- `shutil.unpack_archive` delegates to those two and inherits their behaviour.

### 3.4 Windows and UNC (CWE-73)

An externally-supplied path passed to `open`, `shutil.*`, `os.startfile` or a
Win32 API without rejecting UNC prefixes (`\\host\share`, `//host/share`) makes
the runtime resolve a remote SMB path — which leaks the process's NTLM hash to
an attacker-chosen host. Report it when the target runs on or supports Windows.

---

## 4. SSRF

### 4.1 The bypasses a defence must survive

Name each one you checked. A defence that fails any of them is not a defence:

- **Loopback and link-local spellings**: `127.0.0.1`, `127.1`, `0.0.0.0`, `[::1]`,
  `0x7f000001`, `2130706433`, `localhost`, `localtest.me`, and any DNS name the
  attacker controls that resolves to them. `169.254.169.254` (and
  `metadata.google.internal`) is the cloud-metadata endpoint — reaching it is
  `critical`.
- **Redirect following.** `requests` follows redirects by default. Validating the
  URL and then calling `requests.get(url)` validates hop 0 only; a 302 to
  `http://169.254.169.254/` is followed without re-checking. The defence must set
  `allow_redirects=False` and re-validate every hop.
- **DNS rebinding.** Resolve-then-check-then-connect has a window in which the
  name re-resolves. A check on the *hostname string* rather than the resolved
  address does not even try.
- **URL parsing confusion.** `"evil.com" in url` and `url.startswith("https://good.com")`
  are not host checks. `https://good.com@evil.com/` has host `evil.com`;
  `https://good.com.evil.com/` starts with the allowed prefix. Only
  `urlparse(url).hostname` compared against an **allowlist** (exact match, or a
  suffix match anchored at a dot) is a host check.
- **Scheme.** `urllib.request.urlopen` supports `file://` — `urlopen(user)` is
  arbitrary local file read as well as SSRF. It also supports `ftp://`.
  `requests` does not support `file://`, which is a real difference between the
  two sinks. Anything that does not pin the scheme to `{http, https}` is a
  finding.

An **allowlist** clears it. A **blocklist** almost never does — say which one the
code uses.

### 4.2 Gate-0 style exemption, and its limit

A component whose *purpose* is to fetch a caller-supplied URL — a webhook tester,
a link previewer, a proxy — is doing its job, and "the caller controls the URL"
is not by itself the finding. It becomes a finding the moment the fetch can reach
somewhere the caller could not reach directly: internal hosts, cloud metadata,
loopback services, a file URL. State which, concretely.

---

## 5. Open redirect

- The classic bypasses: `//evil.com` (protocol-relative — a "path-only" check
  passes it and the browser treats it as a host), `/\evil.com` and `\/\/evil.com`
  (browsers normalise the backslash; `urlparse` does not), `https://good.com.evil.com`
  against a `startswith` check, and a redirect chain through an allowed host.
- **Scheme first.** If the sink does not reject `javascript:` and `data:`, this is
  not an open redirect — it is XSS, which is worse. Reclassify: emit
  `vuln_class: "xss_reflected"` and cross-flag INJ in `gaps_observed` so the
  escaping question gets its own look.
- Django's `url_has_allowed_host_and_scheme(url, allowed_hosts, require_https=…)`
  is a correct defence when its result actually gates the redirect. Read the call
  — a common bug is computing it and not branching on it.
- Parameter names worth grepping: `next`, `redirect`, `redirect_uri`,
  `return_to`, `returnUrl`, `continue`, `dest`, `destination`, `redir`, `url`,
  `target`, `forward`, `callback`.

Severity is usually `medium` — it is a phishing enabler, not direct data access —
and rises when it is part of an OAuth flow (`redirect_uri`), because then it
leaks a token.

---

## 6. XXE

**Python's own parsers are mostly not the problem; `lxml` is.**

- `lxml.etree.parse` / `fromstring` / `XML` use a parser with
  `resolve_entities=True` by default, so a `<!ENTITY xxe SYSTEM
  "file:///etc/passwd">` **is expanded** — local file disclosure. Network
  retrieval is blocked by the default `no_network=True`, so an `http://` entity
  usually fails; do not claim SSRF-via-XXE unless `no_network=False` is set.
  The fix is `etree.XMLParser(resolve_entities=False, no_network=True,
  load_dtd=False)` passed to the parse call — check it is actually passed, at
  every call site.
- **stdlib** (`xml.etree.ElementTree`, `xml.dom.minidom`, `xml.sax`,
  `xml.dom.pulldom`) does not resolve external general entities by default. It
  *is* vulnerable to **entity-expansion DoS** — billion laughs and quadratic
  blowup — so report that instead, as availability impact, and do not claim file
  disclosure you cannot demonstrate. The exception: `xml.sax` with
  `setFeature(feature_external_ges, True)` explicitly re-enables it, and that is
  a finding.
- `defusedxml` replacing the parser is a correct, complete defence. Check the
  import is actually the one used at the call site.
- Remember what is XML: SOAP, SAML assertions, OOXML (`.docx`/`.xlsx`), SVG,
  RSS, XML-RPC, and anything parsed by `xmltodict`.

**Not observable.** libxml2 and expat perform their own I/O in C, below the
Python layer the audit hook watches, so a successful entity expansion raises no
event. Your PoC's evidence is the **parsed document**: assert that the expanded
entity's content appears in the tree, quote it in `run_output`, and expect
`no_event`.

---

## 7. Batch / ETL and file-driven input (`improper_input_handling`)

When the task's `source` is `specialist` with `batch-etl`, the attacker model is
an upstream producer, a scheduler parameter, or a shared landing directory — not
a browser. For every finding cite (a) the externally-influenced value (job
parameter, env var, upstream record field, filename in a watched directory) and
(b) the `file:line` where it reaches a path, a command, a query or an output
record without validation. If both producer and consumer sit inside the same
trust domain and no lower-privileged party can set the value, it is a
`gaps_observed` entry, not a finding.

The high-yield patterns:

- job parameters (`sys.argv`, `os.environ`, scheduler variables) flowing into
  `open` / `Path` / `shutil.*` / `os.remove` with no containment — that is §3;
- **CSV formula injection (CWE-1236)**: cell values from parsed input written by
  `csv.writer` / `pandas.to_csv` without stripping a leading `=`, `+`, `-`, `@`
  or tab. Spreadsheets evaluate those on open, and `=cmd|'…'!A1` is code
  execution on the analyst's machine;
- encoding conversions (`codecs.decode`, EBCDIC/`cp037`, `struct.unpack`) where a
  length or offset comes from the record itself;
- "pick the latest file" selection (`max(glob(...), key=os.path.getmtime)`) in a
  shared directory — any local writer can plant a future-dated entry and win.
  That is a trust problem in file selection; report it here and cross-flag LOG if
  the exploit is really a race.

---

## 8. PoC shapes

`CANARY` is `poc_execution.canary_path` — a path built from this run's nonce.
Enter through the target's own function; put the canary early in the payload.

**Path traversal (read).** Make the target open the canary path by traversal,
after creating it so the read succeeds:

```python
import os, pathlib
pathlib.Path(CANARY).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(CANARY).write_text("pyhunt")
rel = os.path.relpath(CANARY, start="/var/data/uploads")   # "../../tmp/pyhunt-canary/<nonce>"
target.download_report(name=rel)
```

Proof is an `open` marker whose argument contains the nonce, attributed to the
target's file. **Do not traverse to a `.py` file, to anything in the virtualenv,
or to `/etc/passwd`** — the first two are filtered as import noise and the third
carries no nonce, so neither can be attributed to your PoC.

**Path traversal (write).** Let the target write to the canary path. You get both
the `open` marker and a materialised canary, which is the strongest evidence
available.

**SSRF.** Make the target resolve a hostname that carries the nonce. Use the
`.invalid` TLD (RFC 2606, guaranteed never to resolve) so nothing leaves the box
— the audit event fires on the attempt, and failure to connect is irrelevant:

```python
target.fetch_preview(url=f"http://pyhunt-{NONCE}.invalid/")
```

Proof is `socket.getaddrinfo` (or `socket.connect` / `urllib.Request`) carrying
the nonce, attributed to the target's file. If the code has an allowlist and your
URL never reaches the socket, that is the allowlist working — report it, do not
route around it.

**Open redirect.** Not observable. Assert on the response: status 30x and a
`Location` header pointing at your host. Quote the raw header in `run_output`,
set `succeeded` from the assertion, expect `no_event`.

**XXE.** Not observable. Feed a document whose entity resolves to a file you
created at the canary path, and assert the canary's contents appear in the
parsed tree — that ties the disclosure to this run without reading a real
system file:

```python
pathlib.Path(CANARY).write_text("PYHUNT-XXE-OK")
doc = f'<!DOCTYPE r [<!ENTITY x SYSTEM "file://{CANARY}">]><r>&x;</r>'
assert "PYHUNT-XXE-OK" in target.parse_config(doc)
```

Expect `no_event` and say in `poc.notes` that the proof is the expanded entity,
not an observed operation.

---

## 9. Do not eliminate these

- **A traversal or SSRF behind an authentication check.** Authentication is not
  containment. It lowers severity by one tier at most, and only if you cite the
  check at a `file:line`.
- **"The base directory is hard-coded."** It is, and `os.path.join` throws it
  away for an absolute input. Check that specific case before clearing.
- **"It only reads files."** Arbitrary read of a config, a key, a token or
  `.env` is `critical`. Name what is readable.
- **A fetch that goes to an internal host.** "Same network" is not "same
  capability", and service-to-service credentials usually ride along.
- **Speculated infrastructure.** No egress filter, WAF, security group or
  metadata-service hardening counts unless it is a manifest in this repository,
  wired into startup, that you read.

**Severity floors.** Arbitrary file read reaching secrets, or SSRF reaching cloud
metadata or an internal service: `critical`. Traversal to an
attacker-controllable **write** (overwrite of code, config, or a cron/systemd
unit): `critical`, because it becomes execution. Read-only traversal confined to
a data directory: `high`. Open redirect: `medium`, `high` inside an OAuth
`redirect_uri`.
