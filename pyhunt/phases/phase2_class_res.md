# Class group RES — resource exhaustion, complexity, unbounded allocation

> Read `phase2_shared.md` first. This file adds the sinks, the bounds that
> actually count as bounds, the false-positive killers and the probe shapes for
> **your** class group only.

You own the class where the attacker does not choose *what* the program does —
they choose **how much**. A size field, a nesting depth, a repetition count, a
precision, a loop bound. The code is doing exactly what it was written to do,
and doing it until the process dies.

| `attack_class` routed here | `vuln_class` to emit | CWE |
|---|---|---|
| `resource_exhaustion` | `resource_exhaustion` | CWE-400 |
| `unbounded_allocation` | `resource_exhaustion` | CWE-770 |
| `memory_exhaustion` | `resource_exhaustion` | CWE-789 |
| `algorithmic_complexity` | `algorithmic_complexity` | CWE-407 |
| `regex_dos` / `redos` | `regex_dos` | CWE-1333 |
| `uncontrolled_recursion` | `uncontrolled_recursion` | CWE-674 |
| `integer_overflow` | `integer_overflow` | CWE-190 |
| `denial_of_service` / `dos` | pick the specific one above | — |

**Not yours:** what the payload *executes* (INJ), where it *points* (NAV), what
it *reconstructs* (DESER), who is *allowed* to send it (LOG). If a parser is
only reachable because an auth check is missing, the exhaustion is yours and the
missing check is a `gaps_observed` entry for LOG.

**This lens exists because of a specific miss.** A sweep once cleared every
`.fake()` method in a library, reasoning that "these methods' entire job is
synthetic test data". Correct for the question it was asking — weak randomness —
and wrong for the one it was not: two of those methods read a schema-supplied
`size` and `max_digits` straight into an allocation. Both were real findings and
both were lost. Read §7 before you dismiss anything.

---

## 1. What the observer can see for your classes

Almost nothing, and you need to know that up front so you do not write a PoC
that can only come back `no_event`.

| Your sink | Audit event | Provable by execution? |
|---|---|---|
| `bytes(n)` / `[x] * n` / a preallocated buffer | none | **no** |
| a quadratic scan, a ReDoS backtrack | none | **no** |
| unbounded recursion in pure Python | none — `RecursionError` is an exception, not an audit event | **no** |
| unbounded recursion into a C parser | none — the process segfaults and takes the hook with it | **no** |
| a generator materialised into a list | none | **no** |

The PEP-578 audit table has no event for "allocated a lot" or "spent a long
time". That is not a hole to work around with a cleverer payload; it is the
wrong instrument. **Your evidence comes from the second oracle** (§6), which
measures rather than watches.

The one exception worth knowing: if the exhaustion path happens to open files or
spawn processes as a side effect, those events fire and are attributable — but
they prove the side effect, not the exhaustion, and a gate outcome of
`sink_reached_unproven` on that basis says nothing about your finding. Do not
chase it.

---

## 2. Sinks to grep for

Allocation driven by an untrusted number:

```
bytes(n)        bytearray(n)      [x] * n        "s" * n        b"\0" * n
os.urandom(n)   secrets.token_bytes(n)           random.randbytes(n)
range(n)        itertools.repeat(x, n)           array(...)     np.zeros(n)
io.BytesIO(...).read(n)          socket.recv(n)  file.read(n)
```

Precision and width driven by an untrusted number:

```
decimal.Decimal / getcontext().prec = n          quantize(Decimal(10) ** -n)
condecimal(max_digits=n)   confixed(size=n)      struct.pack(f"{n}s", ...)
round(x, n)                format(x, f".{n}f")
```

Depth driven by untrusted structure:

```
def parse(node): ... parse(child)         # no depth parameter anywhere
sys.setrecursionlimit(...)                # someone already hit this
json.loads / yaml.safe_load / ET.parse    # each has its own depth behaviour
```

Superlinear work on attacker-sized input:

```
if x in some_list:            # inside a loop  -> O(n²)
result += chunk               # string concat in a loop
sorted(xs, key=lambda ...)    # key re-parses on every comparison
re.compile(r"(a+)+$")         # nested quantifier -> catastrophic backtracking
```

Laziness removed:

```
list(gen)     "".join(gen)    json.dumps(list(gen))    dict(pairs)
```

Unbounded caches:

```
@lru_cache(maxsize=None)      _CACHE[user_supplied_key] = value
functools.cache               a module-level dict that only ever grows
```

---

## 3. What actually clears it

A bound is a bound only if it is **numeric, applied before the allocation, and
on the path the attacker takes.** Each of these clears a finding:

- an explicit ceiling compared before use — `if n > MAX: raise`;
- a clamp — `n = min(n, MAX)`;
- a type or schema constraint that the framework enforces *before* your code
  sees the value (`conint(le=1024)`, a JSON-schema `maximum`, a protobuf field
  type that cannot hold a large enough number);
- a depth counter threaded through the recursion and checked;
- a container-level limit the deployment guarantees — but only if you can point
  at it in this repository (a `resources.limits` in a shipped manifest counts, a
  hypothetical Kubernetes policy does not).

And each of these does **not** clear it, however much it looks like it might:

- **`try/except MemoryError`.** By the time it fires the allocator has already
  taken the memory, and on Linux the OOM killer does not raise anything.
- **A timeout on the request.** The work continues in the worker; the client
  merely stops waiting. Ten of those and the pool is gone.
- **`sys.setrecursionlimit`.** It moves the limit, it does not add one — and
  raising it past the C stack turns a catchable `RecursionError` into a
  segfault, which is strictly worse.
- **"It's O(n²) but n is small in practice."** *In practice* is the attacker's
  variable, not yours. Say what bounds `n` on the untrusted path or treat it as
  unbounded.
- **A downstream validation that runs after the allocation.** Order matters
  more than presence.
- **The value being an `int` rather than a string.** `999999999` is an `int`.

---

## 4. The three shapes, and how to tell them apart

**Unbounded allocation.** One request, one number, memory proportional to it.
The signature is a single arithmetic step between the field and the allocator.
Report the field, the file:line of the allocation, and the multiplier.

**Algorithmic complexity.** Cost grows faster than input size. The signature is
a loop inside a loop, or a linear operation inside a loop, over something the
attacker sizes. Report the exponent you believe it is and the measurement that
would show it.

**Uncontrolled recursion.** Depth proportional to attacker-chosen nesting. Two
different outcomes and you must say which: pure-Python recursion raises
`RecursionError` (the request dies, the process survives); recursion that
crosses into a C extension exhausts the real stack and **segfaults** (the
process dies, and with it every other in-flight request). The second is a
materially worse finding and the difference is visible in the traceback.

---

## 5. Where to look that other lenses will not

Three surfaces this class owns because nobody else asks about size:

1. **Test-data generators.** `.fake()`, `factory()`, `sample()`, `mock_*`,
   Hypothesis strategies. Library consumers call these in *their* test suites
   with schemas they fetched from a registry. "Only test code" describes the
   author's intent, not the reachability, and it is exactly the reasoning that
   lost two findings.
2. **Schema and type registries.** Anything that reads a `size`, `precision`,
   `scale`, `max_length` or `depth` out of a schema document and hands it to a
   constructor. The schema is attacker-controlled in every consumer that fetches
   it from a registry, an API, or an uploaded file.
3. **Round-trip and equality paths.** Serialisers that build a string by
   concatenation, comparators that re-parse, `__eq__` that renders both sides.
   These are hot loops nobody profiles.

---

## 6. Proof — declare a `growth_curve` probe

Your class has a real oracle and you should use it. `phase2_shared.md` §6.8 has
the full contract; this is the shape for RES:

```json
"structural_probe": {
  "kind": "growth_curve",
  "target": "pkg.parser.parse_schema",
  "input_builder": {"kind": "nested_list", "leaf": 0},
  "sizes": [1000, 2000, 4000],
  "benign_size": 10,
  "ratio_threshold": 3.0,
  "memory_limit_mb": 512,
  "cpu_limit_s": 10,
  "rationale": "each nesting level recurses once with no depth parameter"
}
```

The harness runs the callable at every rung in a forked child under `RLIMIT_AS`
and `RLIMIT_CPU`, records wall time, peak RSS and the fate of each rung, and
decides in Python. You supply the ladder; you do not supply the verdict.

It comes back `demonstrated` when either:

- cost is superlinear past `ratio_threshold` across two consecutive doublings, or
- a rung **died** (MemoryError, RecursionError, a signal) while the benign rung
  **completed**.

The benign rung completing is the differential, and it is not a formality: a
function that is slow on every input is slow, not vulnerable.

Builder vocabulary — a closed list, because a spec that could carry code would
be you writing the assertion again:

| `kind` | produces |
|---|---|
| `repeat_str` | `prefix + unit * size + suffix` |
| `list_of` | a list of `size` copies of `leaf` |
| `nested_list` | `size` levels of `[...]` around `leaf` |
| `nested_dict` | `size` levels of `{key: ...}` around `leaf` |
| `repeat_key` | a dict of `size` distinct keys |
| `json_text` | the JSON text of any of the above |

Two practical notes. Pick `sizes` that the *benign* rung clears in well under a
second — the ceiling is the ladder's, not each rung's. And for a recursion
finding, set `memory_limit_mb` generously and let `RLIMIT_CPU` or the crash be
the signal; a memory cap that kills the benign rung produces a `probe_error`,
which says nothing.

If the defect is real but you cannot express the input as a builder, **file it
anyway** with `needs_poc` reasoning in the description and no probe. A
measurement you cannot automate is still a finding; a finding you drop for want
of a probe is a recall bug.

---

## 7. Do not eliminate these

- **"It's in test code."** See §5.1. Say who calls it and with what.
- **"The caller probably validates."** Read the caller. If you cannot, say so in
  `gaps_observed` and file at reduced confidence — do not assume the bound.
- **"Python raises RecursionError, so it's safe."** For pure Python that is a
  survivable request failure and still a finding at lower severity; across a C
  boundary it is a segfault. Establish which.
- **"An attacker gains nothing."** Availability is a security property. The
  victim is every other user of that worker.
- **A whole surface, on one lens's reasoning.** If you clear a file or a family
  of methods, record it per `phase2_shared.md` §8 as `"cleared for
  resource_exhaustion: <why>"`. Phase 3 re-queues cleared surfaces under other
  lenses, and that only works if the dismissal is written down with the question
  attached.
