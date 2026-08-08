# Class group DESER — deserialization and name resolution

> Read `phase2_shared.md` first. This file adds the sinks, sanitisers,
> false-positive killers and PoC shapes for **your** class group only.

You own the classes where attacker bytes are turned back into **live Python
objects**, or where an attacker-supplied **string chooses what code runs**. In
Python the two are the same bug wearing different clothes: both hand the
attacker a callable, and both execute **immediately, in this process, at load
time** — there is no deferred, "only if you use the object" phase the way there
is in some JVM chains.

| `attack_class` routed here | `vuln_class` to emit | CWE |
|---|---|---|
| `deserialization` | `deserialization` | CWE-502 |
| `unsafe_reflection` | `unsafe_reflection` | CWE-470 |
| `prototype_pollution` | `prototype_pollution` | CWE-1321 (JS only — see §7) |

**Not yours:** shells, SQL, templates, `eval` on a source string (INJ); file and
URL destinations (NAV); whether the caller was allowed to submit the blob (LOG).

---

## 1. What the observer can see for your classes

| Sink | Audit event | Notes |
|---|---|---|
| `pickle.loads` / `Unpickler.load` | `pickle.find_class`, then whatever the gadget calls | `find_class` args are `(module, name)` and carry **no** payload text — the proof comes from the operation the gadget performs |
| `marshal.load` / `loads` | `marshal.load` / `marshal.loads` | args are raw bytes |
| unsafe `yaml.load` | whatever the constructor calls (`os.system`, `subprocess.Popen`) | the YAML parse itself raises nothing |
| `importlib.import_module` on a planted module | `open` of the `.py` is **filtered** as import noise | attribution will name the planted module, not the target — see §8 |

The useful consequence: **do not try to prove deserialization by the
deserialization event.** Prove it by what your gadget *does*. A `__reduce__` that
calls `os.system(f"touch {CANARY}")` raises `audit:os.system` with the nonce in
its arguments, attributed to the target frame that called `pickle.loads` — that
is a clean `proven`, and the canary materialises as well.

---

## 2. The sinks, in three tiers

### Tier 1 — no safe mode exists; the only fix is not using it here

`pickle` · `cPickle` · `_pickle` · `pickle.loads` / `.load` / `Unpickler` ·
`marshal.loads` / `.load` · `dill.loads` / `.load` · `shelve.open` (a pickle
database) · `jsonpickle.decode` / `.loads` · `pandas.read_pickle` ·
`joblib.load` · `sklearn.externals.joblib` · `torch.load` (see tier 2) ·
`ObjectInputStream`-shaped wrappers ported from other languages.

The last two names in that list matter because they do not look like pickle.
`pandas.read_pickle` and `joblib.load` are unpickle calls wearing a data-science
costume, and a "load the user's uploaded model / dataframe" feature is a
complete, unauthenticated RCE.

### Tier 2 — safe **by default**, unsafe when the default is overridden

Match the **call**, not the library's reputation:

- `numpy.load(..., allow_pickle=True)` — safe without it since NumPy 1.16.2.
- `torch.load(..., weights_only=False)` — the default flipped to `True` in
  PyTorch 2.6. **Read the pinned version.** A call with no `weights_only`
  argument is safe on ≥2.6 and full RCE on <2.6, and the pin is in
  `requirements.txt` / `pyproject.toml` / the lock file, not in the docs you
  remember.
- `yaml.load(...)` — see §3.

### Tier 3 — name resolution (CWE-470)

`importlib.import_module` · `__import__` · `pydoc.locate` · `globals()[name]` ·
`getattr(obj, name)` where `name` came from outside · `operator.attrgetter` /
`methodcaller` built from input · `django.utils.module_loading.import_string` ·
`pkg_resources` / `importlib.metadata` entry-point resolution · Celery's
`task` name routing · any plugin registry keyed by a request value.

**Order is the whole bug here.** Importing a module has already run its
top-level code, so an allowlist checked **after** resolution is too late. The
check must happen on the *string*, before anything resolves it.

### Where the untrusted bytes come from

Grep the transports as well as the sinks — the sink is often three files from
the request:

- session and cookie storage (`SESSION_SERIALIZER = PickleSerializer`, Flask
  cookies signed with `SECRET_KEY` — a leaked key turns a cookie into RCE);
- cache and queue (`redis`, `memcached`, `diskcache`, `cachetools` with a pickle
  codec; Celery `task_serializer="pickle"` or `accept_content` including
  `pickle`; Kombu);
- uploaded files (`.pkl`, `.joblib`, `.pt`, `.npy`, `.yaml`, `.yml`, notebooks);
- inter-process channels (`multiprocessing` over a network socket,
  `multiprocessing.connection` with no `authkey`).

---

## 3. YAML — the four traps

1. **`yaml.load` is unsafe unless the loader is `SafeLoader` / `CSafeLoader`.**
   A `Loader=` keyword is **not** a fix: `Loader=yaml.Loader` and
   `Loader=yaml.UnsafeLoader` are full deserializers, and `FullLoader` executed
   code before PyYAML 5.4 (CVE-2020-14343). `yaml.unsafe_load` and
   `yaml.full_load` are the same thing with a shorter name.
2. **`yaml.safe_load` is safe. Do not report it.** Likewise
   `yaml.load(x, Loader=yaml.SafeLoader)`.
3. **A safe loader that is not.** Confirm the `SafeLoader` in use has not been
   re-armed by an `add_constructor` / `add_multi_constructor` call or a loader
   subclass that puts object construction back. Grep `add_constructor` across the
   repo before you clear a `safe_load`.
4. **Check what `yaml` is bound to.** `ruamel.yaml`'s `YAML(typ="safe").load(x)`
   is safe and reads exactly like an unsafe `yaml.load(` to a line-based
   scanner; `YAML(typ="unsafe")` is not. Read the import and the receiver.

The payload shape to recognise in a fixture or a report:
`!!python/object/apply:os.system ["…"]`, `!!python/object/new:`,
`!!python/name:`.

---

## 4. Gadget-chain reasoning

Most of the time you do not need it, and saying so saves everyone effort:

> **Unrestricted `pickle.loads` on attacker bytes is RCE, full stop.** The
> `__reduce__` protocol lets the attacker name any importable callable and its
> arguments directly. There is no gadget to find, no chain to build, and no
> "but do they have a suitable class on the path" question. Report it as
> `critical` (unauthenticated) or `high` (authenticated) and move on.

Gadget reasoning becomes the actual work in exactly one situation: **the
deserializer is restricted and you have to decide whether the restriction
holds.** That is a custom `Unpickler` subclass overriding `find_class`, a class
allowlist, or a `SafeLoader` with added constructors. Then work these:

1. **What primitives does the allowlist admit?** Any of `builtins.eval`,
   `builtins.exec`, `builtins.getattr`, `builtins.setattr`,
   `builtins.__import__`, `importlib.import_module`, `pydoc.locate`,
   `os.*`, `subprocess.*`, `types.FunctionType`, `copyreg._reconstructor`,
   `functools.partial`, `operator.attrgetter`, `operator.methodcaller`, or
   `operator.itemgetter` is game over on its own — `partial(getattr, …)` and
   `methodcaller("system", "…")` are complete chains.
2. **Does it admit a class with side effects on construction?** Pickle's opcodes
   call `__reduce__`, `__setstate__`, `__init__` (via `INST`/`OBJ`) and update
   `__dict__` directly (`BUILD`). An allowed class whose `__setstate__` writes a
   file, spawns a thread, or re-enters a loader is a chain.
3. **Can attribute walking reach a callable?** If the allowlist admits any class
   and the surrounding code later reads attributes off the result, the classic
   `__class__.__mro__` / `__globals__` / `__subclasses__()` walk applies exactly
   as it does in SSTI.
4. **Is the restriction applied on every path?** A hardened `Unpickler` used in
   one module and a bare `pickle.loads` in its sibling is not a defence. Grep
   both names.

If you cannot read the allowlist's source, treat it as ineffective per shared
§Step 3(c) and say so — do not credit a restriction you did not read.

---

## 5. The four traps that decide most findings in this class

Ported from the deserialization lens, and each one has produced real bugs:

1. **Wrapper indirection.** The dangerous call is usually one layer down, inside
   a `Serializer.load()` / `deserialize()` / `from_bytes()` / `decode()` helper.
   PyHunt's sink table only ever saw the *wrapper's* name at the call site. Grep
   the wrapper's callers, not just the sink's.
2. **Laundering through a store.** Data that looks internal at the sink may have
   entered the store from outside. A Redis, memcached or database value is only
   as trusted as the least-trusted writer to that key. **Find who WRITES the key
   that is later loaded**, not who reads it. A cache-poisoning path plus a
   pickle-backed cache is unauthenticated RCE, and neither half looks dangerous
   alone.
3. **A safe loader that is not** — §3.3 above.
4. **Version-default drift.** `torch.load`'s `weights_only`, `numpy.load`'s
   `allow_pickle`, PyYAML's `FullLoader` all changed defaults across releases.
   Read the project's **pinned** version. A call that is safe today can be RCE on
   the version the lock file installs, and vice versa — and getting this
   backwards is both a false positive and a false negative waiting to happen.

---

## 6. What clears a DESER finding

| Situation | Clears it | Does **not** clear it |
|---|---|---|
| Structured data from outside | `json.loads`, `yaml.safe_load`, a Pydantic/msgspec/protobuf schema, `ast.literal_eval` | "it's our own format"; a magic-byte check; a size limit |
| Pickle you must keep | An HMAC over the blob verified **before** `loads`, with a key the attacker cannot obtain | a signature verified *after* loading; a signature with a key in the repo (cross-flag `hardcoded_secret` to LOG) |
| `torch` / `numpy` | `weights_only=True` / no `allow_pickle`, on a version where that is the default or explicitly passed | "the model came from our bucket" — check who can write the bucket |
| Name resolution | An allowlist tested against the **string**, before any import or `getattr` | an allowlist tested against the resolved object; `startswith("myapp.")`; stripping dots |
| Custom `Unpickler` | A `find_class` allowlist you read, admitting no primitive from §4.1 | a `find_class` that only blocks `os` and `subprocess` |

A hash or checksum is an **integrity** control against corruption, not an
authenticity control against an attacker — unless it is keyed. Say which one you
found.

---

## 7. `prototype_pollution` and other non-Python routes

`prototype_pollution` is a JavaScript class and PyHunt targets Python (D-5). If a
task routes here with that class, the honest outcome is almost always zero
findings plus a `gaps_observed` entry saying the class does not apply to this
target. The Python-shaped analogue worth a look, if you see it, is recursive
`dict.update` / `setattr` loops that copy attacker keys onto an object or a
config — but that is **mass assignment**, which belongs to LOG. Cross-flag it.

---

## 8. PoC shapes

`CANARY` is `poc_execution.canary_path`; put it early in the payload — the
observer truncates rendered arguments at 200 characters.

**Pickle.** Build the payload with a `__reduce__`, feed it through the *target's*
loading function, and let the gadget perform an observable operation:

```python
import os, pickle
class P:
    def __reduce__(self):
        return (os.system, (f"touch {CANARY}",))
blob = pickle.dumps(P())
target.load_session(blob)          # the TARGET's own deserialization entry point
```

Proof is `audit:os.system` carrying the nonce, attributed to the target file
that called `pickle.loads` — the unpickler's own frames are stdlib and are
skipped, so the nearest reported frame is the target's. The canary materialises
too, which promotes independently.

**Do not call `pickle.loads` yourself.** A PoC that unpickles its own blob and
then asserts the side effect fired proves that pickle works, which nobody
doubted; the gate will return `self_attributed` and it will be right.

**YAML.**

```python
doc = f'!!python/object/apply:os.system ["touch {CANARY}"]'
target.load_config(doc)
```

Same marker shape. If the target uses `safe_load`, the parse raises
`ConstructorError` — that is the defence working. Report it as such; do not
switch the target's loader to make a marker appear.

**`torch` / `joblib` / `pandas`.** Same technique: a class with `__reduce__`,
serialised through the matching writer (`torch.save`, `joblib.dump`,
`DataFrame.to_pickle`), loaded through the target's function.

**Name resolution.** Prefer pointing the resolution at an **existing** dangerous
callable rather than planting a module — a planted module's top-level code is
attributed to *your* file, and the gate will correctly call that
`self_attributed`:

```python
target.dispatch(handler="os.system", args=[f"touch {CANARY}"])   # good
```

If the only reachable shape really is "import an attacker-named module", say so:
run it, note that the canary materialised, expect `self_attributed` or
`no_event`, and rest the finding on the static argument plus the canary. That is
an honest result, and it is exactly the situation the gate's non-demoting design
exists for.

---

## 9. Do not eliminate these

- **"The pickle comes from our own cache / queue / session."** Trace who can
  **write** that key. This is trap 2 and it is where the real bugs live.
- **"It requires authentication."** Authenticated RCE is `high`. It is not a
  reason to drop.
- **"The file has to be uploaded by an admin."** Say so and set the severity
  accordingly — but a model-upload or config-import feature is exactly the
  intended path, and "admin" is one phished session away.
- **"There is a signature."** Read it. Verified after loading, or keyed with a
  secret in the repository, is not a signature.
- **"No gadget is available."** For unrestricted `pickle` there is no gadget
  requirement at all (§4). Only make this argument against a restriction you
  read and quoted.

**Severity floor.** Unrestricted deserialization of externally-influenced bytes
is `critical` when the path is unauthenticated and `high` when it is not. Do not
downgrade for "it would need a crafted payload" — crafting the payload is four
lines and you just wrote them.
