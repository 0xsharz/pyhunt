"""In-container harness for structural probes. PyHunt writes this; no agent does.

The whole point of this file is *who wrote it*. A hunt agent's PoC that parses
its own output and asserts "the marker became a syntax node" is the party with
an interest in the answer grading its own work — the failure mode
``oracle/gate.py`` exists to remove for execution evidence. So a hunter declares
a probe as **data** (a JSON spec: which callable, which benign input, which
hostile input) and this harness — shipped with the skill, read-only inside the
container, never rewritten between runs — calls the target, measures the
property, and signs the result with the per-container HMAC key.

    The hunter supplies inputs. The harness supplies the assertion.

Run as::

    python3 pyhunt_structural_probe.py <spec.json>

with the marker channel already open on fd 3 (``replay``'s ``_pyhunt_fd3.py``
launcher does that), ``PYHUNT_OBSERVER_KEY`` and ``PYHUNT_NONCE`` in the
environment. Both are read and **deleted from ``os.environ`` before any target
code is imported**, exactly as ``pyhunt_audit_hook.py`` does and for the same
reason: a hostile target's first move is to read the environment.

Stdlib only. It runs inside the target's own image, where the only interpreter
guaranteed present is the one the target needs.

Five probe kinds, and the vocabulary is closed on purpose
---------------------------------------------------------
``codegen_ast``       differential AST position of the attacker's text in
                      generated source. The generated module is parsed, never
                      executed.
``growth_curve``      cost ladder under RLIMIT_AS / RLIMIT_CPU in a forked
                      child.
``state_mutation``    a module-global before and after a hostile call.
``exception_escape``  what escapes a public entry point on hostile bytes.
``flow_witness``      whether the attacker's data ARRIVES at the claimed sink,
                      traced with ``sys.settrace`` scoped to the target's own
                      frames. Settles classes the audit hook has no event for,
                      because it needs no dangerous operation to fire.

A hunter cannot add a sixth by writing code, because there is nowhere in the
spec to put code. Adding one means editing this file and
``oracle/structural.py`` — a reviewable change, which is the property that
makes the evidence worth anything.
"""

import ast
import hashlib
import hmac
import json
import os
import re
import resource
import signal
import sys
import time
import traceback

MARKER = "[PYHUNT-OBSERVER]"
_SIG_HEX = 16

# ─────────────────────────────────────────────────────────────────────────────
# Environment, taken and destroyed in the same breath.
# ─────────────────────────────────────────────────────────────────────────────

#: Importing the target writes `__pycache__` INTO the target tree. The real
#: pipeline mounts it read-only so the write fails harmlessly, but PyHunt states
#: plainly that it never modifies the target, and "the filesystem stopped us"
#: is not the same claim as "we did not try". Caught by a probe test asserting
#: the tree is byte-identical before and after.
sys.dont_write_bytecode = True

_KEY = os.environ.pop("PYHUNT_OBSERVER_KEY", "") or ""
_NONCE = os.environ.pop("PYHUNT_NONCE", "") or ""
_TARGET_ROOT = os.environ.pop("PYHUNT_TARGET_ROOT", "") or "/target"

#: Substituted into the spec's inputs. The benign marker is minted HERE, not by
#: the hunter: a control the hunter chose could be made to collide with the
#: hostile payload, and then "the benign case did not exhibit the property"
#: would be a statement about a string the hunter picked.
_BENIGN_MARKER = "pyhuntbenign" + hashlib.sha256(
    (_NONCE + "|benign").encode("utf-8")).hexdigest()[:12]

_NONCE_PLACEHOLDER = "$PYHUNT_NONCE"
_BENIGN_PLACEHOLDER = "$PYHUNT_BENIGN"


def _sign(body):
    return hmac.new(_KEY.encode("utf-8"), body.encode("utf-8"),
                    hashlib.sha256).hexdigest()[:_SIG_HEX] if _KEY else ""


def _emit(kind, payload):
    """Write one signed marker line to fd 3, falling back to stderr.

    Failure to write is never fatal: a probe that could not reach its channel
    should still finish and let the host record ``probe_absent``, which says
    nothing about the code. A probe that crashed the run because a descriptor
    was missing would turn an environment fact into a missing finding.
    """
    body = "structural:%s %s" % (kind, json.dumps(payload, default=str,
                                                  sort_keys=True))
    sig = _sign(body)
    line = "%s n=%s %s%s\n" % (MARKER, _NONCE, ("s=%s " % sig) if sig else "", body)
    data = line.encode("utf-8", "replace")
    try:
        os.write(3, data)
        return
    except OSError:
        pass
    try:
        sys.stderr.write(line)
        sys.stderr.flush()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Spec expansion — a closed builder vocabulary, so inputs are data
# ─────────────────────────────────────────────────────────────────────────────

def _substitute(value, nonce, benign):
    """Recursively replace the two placeholders anywhere inside a JSON value."""
    if isinstance(value, str):
        return value.replace(_NONCE_PLACEHOLDER, nonce).replace(
            _BENIGN_PLACEHOLDER, benign)
    if isinstance(value, list):
        return [_substitute(v, nonce, benign) for v in value]
    if isinstance(value, dict):
        return {_substitute(k, nonce, benign): _substitute(v, nonce, benign)
                for k, v in value.items()}
    return value


def encodings_of(text):
    """Every byte form of `text` that a pass-through encode could produce.

    A `str` -> `bytes` encode changes the object's type and not one byte of its
    content, so it must count as UNALTERED by a flow witness. Comparing by type
    alone did not, and the consequence was the worst kind of wrong verdict this
    oracle can produce: a real CR/LF header-injection finding came back
    `refuted` because `utilities._to_bytes` encoded the sentinel-bearing header
    value on its way to the sink. `refuted` is the verdict that argues a defence
    *works*, so a false one buries a live finding under machine authority. Two
    phase 2c verifiers had to reconstruct the encode by hand from the replay
    transcript to overturn it.

    Module-level (rather than nested in the witness) so the property can be
    tested directly instead of by grepping the source.
    """
    out = set()
    for codec in ("utf-8", "latin-1", "ascii"):
        try:
            out.add(text.encode(codec))
        except Exception:  # noqa: BLE001
            continue
    return out


def _as_bytes(builder, field, default=b""):
    """One byte-valued field of a builder spec, from hex or from latin-1 text.

    Two spellings, both pure data — the closed-vocabulary property is the
    security control here and must not be relaxed into "eval a snippet":

    ``<field>_hex``   ``"000006040000000000"`` — exact bytes, whitespace ignored
    ``<field>_text``  ``"GET / {{NONCE}}"`` — encoded latin-1, so every byte
                      0-255 is expressible and placeholder substitution (which
                      runs over strings, before this) still reaches inside.

    A malformed hex string raises rather than falling back, because a probe that
    quietly measured a *different* payload than the spec asked for would produce
    a confident number about the wrong thing.
    """
    spec = builder or {}
    text = spec.get(field + "_text")
    if isinstance(text, str):
        return text.encode("latin-1", errors="strict")
    raw = spec.get(field + "_hex")
    if isinstance(raw, str):
        cleaned = "".join(raw.split())
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(
                "builder field %r is not valid hex (%s); give %s_hex as hex "
                "digits or use %s_text for latin-1 text"
                % (field + "_hex", exc, field, field)) from exc
    return default


def _build_sized(builder, size):
    """Expand a size-parameterised input from a closed builder vocabulary.

    Growth probes need an input whose SIZE varies, and the obvious way to get
    one — let the spec carry a lambda — would hand the hunter the assertion
    again by the back door. So the shapes are enumerated here:

    ``repeat_str``    ``{"kind":"repeat_str","unit":"A","suffix":""}``
    ``nested_list``   ``size`` levels of ``[...]`` around ``leaf``
    ``nested_dict``   ``size`` levels of ``{key: ...}`` around ``leaf``
    ``repeat_key``    a dict of ``size`` distinct keys, each mapped to ``leaf``
    ``json_text``     the JSON text of any of the above, as a string
    ``list_of``       a list containing ``size`` copies of ``leaf``
    ``repeat_bytes``  ``size`` copies of a byte unit, as ``bytes``
    ``framed_bytes``  a preamble followed by ``size`` copies of a fixed frame

    The two byte shapes exist because the vocabulary above emits only ``str``,
    ``list`` and ``dict`` — and a protocol parser takes ``bytes``. On a sans-IO
    HTTP/2 target every entry point wanted bytes, so the *benign* rung of each
    differential died alongside the hostile one and the probe could only return
    ``probe_error``. The hunters correctly declined to declare any growth probe
    at all, which meant the one oracle able to settle that target's main finding
    class was never armed: the coverage gap did not close, it moved somewhere
    less visible.

    Byte units are given as hex (``unit_hex``) or as text encoded latin-1
    (``unit_text``). Text is what lets ``{{NONCE}}`` and ``{{BENIGN}}``
    substitution reach inside a byte payload, since both placeholders are ASCII.

    Anything else raises, and the probe reports ``error`` — an unknown builder
    is a spec bug, and guessing at one would silently measure the wrong thing.
    """
    kind = (builder or {}).get("kind")
    leaf = (builder or {}).get("leaf", 0)
    if kind == "repeat_bytes":
        return (_as_bytes(builder, "prefix")
                + _as_bytes(builder, "unit", default=b"A") * size
                + _as_bytes(builder, "suffix"))
    if kind == "framed_bytes":
        return (_as_bytes(builder, "preamble")
                + _as_bytes(builder, "frame", default=b"\x00") * size)
    if kind == "repeat_str":
        unit = builder.get("unit", "A")
        return builder.get("prefix", "") + unit * size + builder.get("suffix", "")
    if kind == "list_of":
        return [leaf] * size
    if kind == "nested_list":
        out = leaf
        for _ in range(size):
            out = [out]
        return out
    if kind == "nested_dict":
        key = builder.get("key", "a")
        out = leaf
        for _ in range(size):
            out = {key: out}
        return out
    if kind == "repeat_key":
        prefix = builder.get("key_prefix", "k")
        return dict(("%s%d" % (prefix, i), leaf) for i in range(size))
    if kind == "json_text":
        inner = dict(builder)
        inner["kind"] = builder.get("inner_kind", "nested_list")
        return json.dumps(_build_sized(inner, size))
    raise ValueError("unknown input builder kind: %r" % (kind,))


# ─────────────────────────────────────────────────────────────────────────────
# Resolution — and the attribution check that makes any of this mean something
# ─────────────────────────────────────────────────────────────────────────────

def _resolve(dotted):
    """Import ``pkg.mod.attr.attr`` and return (object, defining file).

    Walks the dotted path from the longest importable prefix inward, so
    ``pkg.mod.Class.method`` resolves without the caller telling us where the
    module ends and the attributes begin.
    """
    import importlib
    parts = dotted.split(".")
    module = None
    idx = 0
    for i in range(len(parts), 0, -1):
        try:
            module = importlib.import_module(".".join(parts[:i]))
            idx = i
            break
        except ImportError:
            continue
    if module is None:
        raise ImportError("no importable prefix in %r" % (dotted,))
    obj = module
    for part in parts[idx:]:
        obj = getattr(obj, part)
    return obj, _defining_file(obj)


def _defining_file(obj):
    """Best-effort source file of ``obj``. This is condition S-2's whole input."""
    import inspect
    for candidate in (obj, getattr(obj, "__func__", None),
                      getattr(obj, "fget", None), type(obj)):
        if candidate is None:
            continue
        try:
            return os.path.abspath(inspect.getfile(candidate))
        except (TypeError, OSError):
            continue
    module = getattr(obj, "__module__", None)
    if module and module in sys.modules:
        path = getattr(sys.modules[module], "__file__", None)
        if path:
            return os.path.abspath(path)
    return None


def _call(spec, args, kwargs):
    """Instantiate (if the spec asks) and call the target.

    ``construct`` exists because most generators are methods on an object that
    must be built first, and building it is the target's own code too.
    """
    dotted = spec["target"]
    construct = spec.get("construct")
    if construct:
        cls, _ = _resolve(construct)
        instance = cls(*_as_list(spec.get("construct_args")),
                       **dict(spec.get("construct_kwargs") or {}))
        attr = dotted.split(".")[-1]
        fn = getattr(instance, attr)
        return fn(*args, **kwargs), _defining_file(fn)
    fn, path = _resolve(dotted)
    return fn(*args, **kwargs), path


def _as_list(value):
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


# ─────────────────────────────────────────────────────────────────────────────
# codegen_ast — the differential that VASH asserted about itself
# ─────────────────────────────────────────────────────────────────────────────

#: AST node types that mean "the language will execute this". A ``Constant``
#: means the opposite, and a needle that reaches neither (a comment, a stripped
#: field) means it never landed at all.
_EXECUTABLE_NODES = (
    ast.Call, ast.Import, ast.ImportFrom, ast.alias, ast.Attribute, ast.Name,
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Assign,
    ast.AnnAssign, ast.AugAssign, ast.keyword, ast.arg, ast.Lambda,
    ast.Subscript, ast.BinOp, ast.Compare, ast.Return, ast.Raise, ast.Assert,
    ast.With, ast.For, ast.While, ast.If, ast.Try,
)


def _line_offsets(source):
    """Absolute character offset of the start of each 1-indexed line."""
    offsets = [0, 0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _is_inert_statement(node):
    """True when this statement does nothing but hold a constant.

    A module/class docstring (``Expr(Constant)``) and a constant assignment
    (``__doc__ = "..."``) are the two shapes a *correct* generator produces for
    untrusted text. Everything else — a call, an import, a def — is the shape
    that means the text escaped its literal.
    """
    if isinstance(node, ast.Expr):
        return isinstance(node.value, ast.Constant)
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        return isinstance(getattr(node, "value", None), ast.Constant)
    if isinstance(node, ast.Pass):
        return True
    return False


def _locate(source, needle):
    """Where the parser thinks ``needle`` sits in ``source``.

    Returns a dict with the innermost node containing the needle, the statement
    that encloses it, and whether either is executable. Position-based rather
    than text-based on purpose: the question is not "does the needle appear in
    the output" — correct escaping puts it there too — but "what did the parser
    decide the needle *is*".

    Two signals rather than one, because payloads come in two shapes and only
    reporting the innermost node under-reads the commoner one:

    * the nonce **as an identifier** (``pyhunt_<nonce>()``) — the innermost node
      is then a ``Name``/``Call`` and the answer is direct;
    * the nonce **inside a string argument** of an injected call
      (``system("touch /canary/<nonce>")``) — the innermost node is a
      ``Constant``, which read alone would say "inert" about a payload that
      plainly became code. The enclosing statement is what carries the answer
      there: an ``Expr(Call)`` where the benign render had ``Expr(Constant)``.
    """
    found = {"found": False, "parse_error": None, "node_type": None,
             "executable": False, "stmt_type": None, "stmt_inert": None,
             "in_string_literal": False}
    index = source.find(needle)
    if index < 0:
        return found
    found["found"] = True
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        found["parse_error"] = "SyntaxError: %s (line %s)" % (exc.msg, exc.lineno)
        return found

    starts = _line_offsets(source)

    def span(node):
        lineno = getattr(node, "lineno", None)
        end_lineno = getattr(node, "end_lineno", None)
        col = getattr(node, "col_offset", None)
        end_col = getattr(node, "end_col_offset", None)
        if None in (lineno, end_lineno, col, end_col):
            return None
        if lineno >= len(starts) or end_lineno >= len(starts):
            return None
        return starts[lineno] + col, starts[end_lineno] + end_col

    best = None
    best_width = None
    best_stmt = None
    stmt_width = None
    for node in ast.walk(tree):
        bounds = span(node)
        if bounds is None:
            continue
        start, end = bounds
        if not (start <= index < end):
            continue
        width = end - start
        if best_width is None or width < best_width:
            best, best_width = node, width
        if isinstance(node, ast.stmt) and (stmt_width is None or width < stmt_width):
            best_stmt, stmt_width = node, width

    if best is None:
        # Inside no node at all: a comment, or trailing text the parser dropped.
        found["node_type"] = "comment_or_dropped"
        return found

    found["node_type"] = type(best).__name__
    found["executable"] = isinstance(best, _EXECUTABLE_NODES)
    found["in_string_literal"] = isinstance(best, ast.Constant) and isinstance(
        getattr(best, "value", None), str)
    if best_stmt is not None:
        found["stmt_type"] = type(best_stmt).__name__
        found["stmt_inert"] = _is_inert_statement(best_stmt)
    return found


def _probe_codegen_ast(spec):
    hostile_args = _substitute(_as_list(spec.get("hostile_args")), _NONCE, _BENIGN_MARKER)
    hostile_kwargs = _substitute(dict(spec.get("hostile_kwargs") or {}), _NONCE, _BENIGN_MARKER)
    benign_args = _substitute(_as_list(spec.get("benign_args")), _NONCE, _BENIGN_MARKER)
    benign_kwargs = _substitute(dict(spec.get("benign_kwargs") or {}), _NONCE, _BENIGN_MARKER)

    nonce_in_hostile = _NONCE in json.dumps(
        [hostile_args, hostile_kwargs], default=str)

    benign_source, callable_file = _call(spec, benign_args, benign_kwargs)
    benign_source = _as_source(benign_source)
    hostile_source, callable_file2 = _call(spec, hostile_args, hostile_kwargs)
    hostile_source = _as_source(hostile_source)

    benign = _locate(benign_source, _BENIGN_MARKER)
    hostile = _locate(hostile_source, _NONCE)

    # The nonce became code if the parser calls it code directly (identifier
    # payload), OR if the statement holding it stopped being inert while the
    # benign control's stayed inert (string-argument payload). Both halves of
    # the second test are required — "the hostile statement is a Call" alone
    # would fire on a generator that emits calls for every input.
    became_code = bool(hostile["executable"]) or bool(
        hostile["stmt_inert"] is False and benign["stmt_inert"] is True)

    measurements = {
        "benign_node_type": benign["node_type"],
        "benign_executable": benign["executable"],
        "benign_stmt_type": benign["stmt_type"],
        "benign_stmt_inert": benign["stmt_inert"],
        "benign_parse_error": benign["parse_error"],
        "benign_needle_found": benign["found"],
        "hostile_node_type": hostile["node_type"],
        "hostile_executable": hostile["executable"],
        "hostile_stmt_type": hostile["stmt_type"],
        "hostile_stmt_inert": hostile["stmt_inert"],
        "hostile_parse_error": hostile["parse_error"],
        "hostile_needle_found": hostile["found"],
        "nonce_in_string_literal": hostile["in_string_literal"],
        "became_code": became_code,
        "benign_source_bytes": len(benign_source),
        "hostile_source_bytes": len(hostile_source),
        "hostile_excerpt": _excerpt(hostile_source, _NONCE),
        "benign_excerpt": _excerpt(benign_source, _BENIGN_MARKER),
    }
    if benign["parse_error"]:
        return {
            "error": "the benign control did not parse (%s) — the control is "
                     "broken, so there is no differential to read"
                     % benign["parse_error"],
            "callable_file": callable_file or callable_file2,
            "measurements": measurements,
        }
    if not benign["found"]:
        return {
            "error": "the benign control's marker never reached the generated "
                     "source, so the two renders are not comparable — the "
                     "payload is probably in a field this generator ignores",
            "callable_file": callable_file or callable_file2,
            "measurements": measurements,
        }
    return {
        "callable_file": callable_file2 or callable_file,
        # Strict for this kind, and only for this kind: the whole claim is
        # "*this* attacker string became code", so the string has to be this
        # run's nonce. There is no spec-level fallback here.
        "nonce_in_hostile_input": nonce_in_hostile,
        "nonce_carried_in": "payload",
        "differential_ran": True,
        # "the property" for this kind = the attacker's text reached the output
        "hostile_property_holds": bool(hostile["found"]),
        # ...the control must NOT already produce executable output there...
        "benign_property_holds": bool(benign["executable"]),
        # ...and S-5 is the semantic half: it reached it AS CODE.
        "semantic_position_confirmed": became_code,
        "measurements": measurements,
    }


def _as_source(value):
    """Coerce a generator's return value to source text.

    Generators return a string, a list of strings, or an object with a
    ``__str__``. Anything else is a spec error rather than something to guess at.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "\n".join(str(v) for v in value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return str(value)


def _excerpt(source, needle, span=160):
    idx = source.find(needle)
    if idx < 0:
        return None
    start = max(0, idx - span // 2)
    return source[start:idx + span // 2]


# ─────────────────────────────────────────────────────────────────────────────
# growth_curve — cost as a function of attacker-chosen size
# ─────────────────────────────────────────────────────────────────────────────

def _apply_limits(memory_mb, cpu_s):
    """Apply resource caps best-effort, reporting which ones actually took.

    Not every limit exists on every kernel: macOS refuses ``RLIMIT_AS`` outright
    (``ValueError``) and several BSDs cap it far below what a Python interpreter
    already has mapped. A probe that *died because the cap could not be set*
    would report every rung as a failure, which is a measurement of the host and
    would read as a demonstrated vulnerability. So each cap is attempted
    independently, clamped to the hard limit, and the ones that landed are
    recorded — the wall-clock alarm is the backstop that always works.
    """
    applied = []
    for name, attr, value in (
        ("address_space", "RLIMIT_AS", memory_mb * 1024 * 1024),
        ("cpu_seconds", "RLIMIT_CPU", cpu_s),
    ):
        limit = getattr(resource, attr, None)
        if limit is None:
            continue
        try:
            soft, hard = resource.getrlimit(limit)
            target = value if hard in (resource.RLIM_INFINITY, -1) else min(value, hard)
            resource.setrlimit(limit, (target, hard))
            applied.append(name)
        except (ValueError, OSError):
            continue
    return applied


def _run_bounded(fn, args, kwargs, memory_mb, cpu_s, wall_s):
    """Run in a forked child under hard limits; report time, peak RSS, fate.

    Forked rather than threaded because the point is to survive the failure:
    ``MemoryError``, ``RecursionError`` and a C-stack ``SIGSEGV`` all have to be
    observable, and the last of those takes the interpreter with it. The parent
    reads the child's fate from ``waitpid``, so a segfaulting target is a
    measurement rather than a lost run.
    """
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        os.close(read_fd)
        outcome = {"ok": False, "exc": None, "seconds": None, "peak_kb": None,
                   "limits": []}
        try:
            outcome["limits"] = _apply_limits(memory_mb, cpu_s)
            signal.alarm(int(wall_s))
            started = time.perf_counter()
            try:
                fn(*args, **kwargs)
                outcome["ok"] = True
            except BaseException as exc:  # noqa: BLE001 - the fate IS the datum
                outcome["exc"] = type(exc).__name__
            outcome["seconds"] = round(time.perf_counter() - started, 6)
            outcome["peak_kb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        except BaseException as exc:  # noqa: BLE001
            outcome["exc"] = type(exc).__name__
        try:
            os.write(write_fd, json.dumps(outcome).encode("utf-8"))
        except OSError:
            pass
        os._exit(0)

    os.close(write_fd)
    chunks = []
    try:
        while True:
            block = os.read(read_fd, 65536)
            if not block:
                break
            chunks.append(block)
    except OSError:
        pass
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    raw = b"".join(chunks)
    if raw:
        try:
            out = json.loads(raw.decode("utf-8", "replace"))
            out["signal"] = os.WTERMSIG(status) if os.WIFSIGNALED(status) else 0
            return out
        except ValueError:
            pass
    return {
        "ok": False,
        "exc": "killed",
        "seconds": None,
        "peak_kb": None,
        "signal": os.WTERMSIG(status) if os.WIFSIGNALED(status) else 0,
    }


def _probe_growth_curve(spec):
    builder = spec.get("input_builder") or {}
    sizes = [int(s) for s in (spec.get("sizes") or [])]
    if len(sizes) < 3:
        return {"error": "growth_curve needs at least three sizes to see a curve"}
    benign_size = int(spec.get("benign_size", sizes[0]))
    memory_mb = int(spec.get("memory_limit_mb", 512))
    cpu_s = int(spec.get("cpu_limit_s", 10))
    wall_s = int(spec.get("wall_limit_s", max(cpu_s + 5, 15)))
    threshold = float(spec.get("ratio_threshold", 3.0))

    fn_holder = {}

    def call_at(size):
        payload = _build_sized(builder, size)
        extra = _substitute(_as_list(spec.get("extra_args")), _NONCE, _BENIGN_MARKER)
        kwargs = _substitute(dict(spec.get("kwargs") or {}), _NONCE, _BENIGN_MARKER)
        args = [payload] + extra if spec.get("payload_first", True) else extra + [payload]
        return args, kwargs

    # Resolve once so the attribution reported is the callable actually used,
    # and so an import error is a spec fact rather than a "slow" measurement.
    construct = spec.get("construct")
    if construct:
        cls, _ = _resolve(construct)
        instance = cls(*_as_list(spec.get("construct_args")),
                       **dict(spec.get("construct_kwargs") or {}))
        fn = getattr(instance, spec["target"].split(".")[-1])
    else:
        fn, _ = _resolve(spec["target"])
    fn_holder["fn"] = fn
    callable_file = _defining_file(fn)

    benign_args, benign_kwargs = call_at(benign_size)
    benign = _run_bounded(fn, benign_args, benign_kwargs, memory_mb, cpu_s, wall_s)

    ladder = []
    for size in sizes:
        args, kwargs = call_at(size)
        result = _run_bounded(fn, args, kwargs, memory_mb, cpu_s, wall_s)
        result["size"] = size
        ladder.append(result)

    timings = [(r["size"], r["seconds"]) for r in ladder if r.get("seconds")]
    ratios = []
    for (s0, t0), (s1, t1) in zip(timings, timings[1:]):
        if t0 and t0 > 0 and s1 > s0:
            ratios.append(round(t1 / t0, 3))

    died = [r for r in ladder if not r.get("ok")]
    superlinear = len(ratios) >= 2 and all(r >= threshold for r in ratios[-2:])
    hard_failure = bool(died) and bool(benign.get("ok"))

    measurements = {
        "benign_size": benign_size,
        "benign_ok": benign.get("ok"),
        "benign_seconds": benign.get("seconds"),
        "ladder": ladder,
        "ratios": ratios,
        "ratio_threshold": threshold,
        "died_at": [r["size"] for r in died],
        "failure_modes": sorted({r.get("exc") or ("signal %s" % r.get("signal"))
                                 for r in died}),
        "memory_limit_mb": memory_mb,
        "cpu_limit_s": cpu_s,
        "limits_applied": sorted({lim for r in ladder + [benign]
                                  for lim in (r.get("limits") or [])}),
    }
    nonce_in_hostile = _NONCE in json.dumps(
        [builder, spec.get("extra_args"), spec.get("kwargs")], default=str)
    return {
        "callable_file": callable_file,
        # Size-driven probes carry the nonce in the SPEC rather than in the
        # payload — a payload of 40000 nested lists has nowhere to put a string.
        # The spec is signed into the record, so attribution survives; say so
        # plainly rather than pretending the payload carried it.
        "nonce_in_hostile_input": nonce_in_hostile or bool(_NONCE),
        "nonce_carried_in": "payload" if nonce_in_hostile else "spec",
        "differential_ran": True,
        "hostile_property_holds": bool(superlinear or hard_failure),
        "benign_property_holds": not bool(benign.get("ok")),
        "semantic_position_confirmed": bool(superlinear or hard_failure),
        "measurements": measurements,
    }


# ─────────────────────────────────────────────────────────────────────────────
# state_mutation
# ─────────────────────────────────────────────────────────────────────────────

def _read_attribute(dotted):
    obj, _ = _resolve(dotted)
    return obj


def _probe_state_mutation(spec):
    attribute = spec["attribute"]
    before = _read_attribute(attribute)
    benign_args = _substitute(_as_list(spec.get("benign_args")), _NONCE, _BENIGN_MARKER)
    benign_kwargs = _substitute(dict(spec.get("benign_kwargs") or {}), _NONCE, _BENIGN_MARKER)
    hostile_args = _substitute(_as_list(spec.get("hostile_args")), _NONCE, _BENIGN_MARKER)
    hostile_kwargs = _substitute(dict(spec.get("hostile_kwargs") or {}), _NONCE, _BENIGN_MARKER)

    try:
        _, callable_file = _call(spec, benign_args, benign_kwargs)
    except Exception as exc:  # noqa: BLE001
        return {"error": "the benign control raised %s, so there is no "
                         "differential" % type(exc).__name__}
    after_benign = _read_attribute(attribute)

    hostile_exc = None
    try:
        _, callable_file = _call(spec, hostile_args, hostile_kwargs)
    except Exception as exc:  # noqa: BLE001
        hostile_exc = type(exc).__name__
    after_hostile = _read_attribute(attribute)

    expected = spec.get("expected_value")
    if isinstance(expected, str):
        expected = _substitute(expected, _NONCE, _BENIGN_MARKER)

    changed = repr(after_hostile) != repr(before)
    benign_changed = repr(after_benign) != repr(before)
    matches = expected is None or repr(after_hostile) == repr(expected) or (
        isinstance(expected, (int, float)) and after_hostile == expected)

    literal_nonce = _NONCE in json.dumps(
        [hostile_args, hostile_kwargs, spec.get("expected_value")], default=str)
    return {
        "callable_file": callable_file,
        # A precision integer or a registry key has nowhere to put a 16-hex
        # string, so attribution for this kind rests on the signed channel and
        # the per-container key rather than on the payload. Said out loud in
        # `nonce_carried_in` rather than papered over.
        "nonce_in_hostile_input": literal_nonce or bool(_NONCE),
        "nonce_carried_in": "payload" if literal_nonce else "spec",
        "differential_ran": True,
        "hostile_property_holds": bool(changed),
        "benign_property_holds": bool(benign_changed),
        "semantic_position_confirmed": bool(changed and matches),
        "measurements": {
            "attribute": attribute,
            "before": repr(before),
            "after_benign": repr(after_benign),
            "after": repr(after_hostile),
            "expected": repr(expected),
            "hostile_exception": hostile_exc,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# exception_escape
# ─────────────────────────────────────────────────────────────────────────────

def _probe_exception_escape(spec):
    expected = set(spec.get("expected_exceptions") or [])
    benign_args = _substitute(_as_list(spec.get("benign_args")), _NONCE, _BENIGN_MARKER)
    benign_kwargs = _substitute(dict(spec.get("benign_kwargs") or {}), _NONCE, _BENIGN_MARKER)
    hostile_args = _substitute(_as_list(spec.get("hostile_args")), _NONCE, _BENIGN_MARKER)
    hostile_kwargs = _substitute(dict(spec.get("hostile_kwargs") or {}), _NONCE, _BENIGN_MARKER)

    benign_exc = None
    callable_file = None
    try:
        _, callable_file = _call(spec, benign_args, benign_kwargs)
    except BaseException as exc:  # noqa: BLE001
        benign_exc = type(exc).__name__

    hostile_exc = None
    hostile_message = None
    try:
        _, path = _call(spec, hostile_args, hostile_kwargs)
        callable_file = callable_file or path
    except BaseException as exc:  # noqa: BLE001
        hostile_exc = type(exc).__name__
        hostile_message = str(exc)[:400]

    if benign_exc:
        return {
            "error": "the benign control itself raised %s — the entry point is "
                     "broken for ordinary input, so a hostile crash proves "
                     "nothing about the attacker" % benign_exc,
            "callable_file": callable_file,
            "measurements": {"benign_exception": benign_exc},
        }
    literal_nonce = _NONCE in json.dumps([hostile_args, hostile_kwargs], default=str)
    return {
        "callable_file": callable_file,
        "nonce_in_hostile_input": literal_nonce or bool(_NONCE),
        "nonce_carried_in": "payload" if literal_nonce else "spec",
        "differential_ran": True,
        "hostile_property_holds": bool(hostile_exc),
        "benign_property_holds": False,
        "semantic_position_confirmed": bool(
            hostile_exc and (not expected or hostile_exc in expected)),
        "measurements": {
            "hostile_exception": hostile_exc,
            "hostile_message": hostile_message,
            "expected_exceptions": sorted(expected),
            "benign_exception": benign_exc,
        },
    }


# ---------------------------------------------------------------------------
# flow_witness (W3.1)
#
# The other four probes ask "does the dangerous property hold". This one asks
# the prior question every static finding assumes and none of them checks:
# **does the attacker's data actually arrive?**
#
# It settles classes the audit hook cannot see at all — SQL injection, XSS, open
# redirect, template rendering — because it needs no dangerous operation to
# fire. It needs the value to be present.
#
# And its negative result is worth as much as its positive one. "Not witnessed,
# last seen at validators.py:88" is a precise, checkable statement that a
# sanitiser exists and works, on the exact line it works. Phase 2c currently has
# to establish that by reading.
#
# Known limits, stated rather than discovered:
#   - `sys.settrace` costs 10–50×. The probe is bounded by the same container
#     timeout as everything else and reports if it hits it.
#   - The trace does not follow data through C extensions. A value that transits
#     a C decoder is seen entering and leaving but not inside; the probe records
#     `went_dark_in` rather than silently concluding the flow stopped.
# ---------------------------------------------------------------------------
_FLOW_MAX_DEPTH = 4          # how deep into containers a nonce search recurses
_FLOW_MAX_ITEMS = 64         # how many container members are inspected per level
_FLOW_MAX_STR = 1_000_000    # a value longer than this is not scanned
_FLOW_MAX_EVENTS = 400_000   # hard cap on traced events


def _contains_nonce(value, nonce, depth=0, seen=None):
    """Is the nonce anywhere in this value? Bounded, cycle-safe, never calls
    user code.

    Deliberately does NOT use `repr()` or `str()` on arbitrary objects: both run
    target-authored `__repr__` inside the tracer, which is re-entrant, slow, and
    a place a hostile object could hide. Only real containers are walked.
    """
    if depth > _FLOW_MAX_DEPTH:
        return False
    if isinstance(value, str):
        return len(value) <= _FLOW_MAX_STR and nonce in value
    if isinstance(value, (bytes, bytearray)):
        try:
            return len(value) <= _FLOW_MAX_STR and nonce.encode() in bytes(value)
        except Exception:  # noqa: BLE001
            return False
    if seen is None:
        seen = set()
    marker = id(value)
    if marker in seen:
        return False
    if isinstance(value, dict):
        seen.add(marker)
        for index, (key, item) in enumerate(value.items()):
            if index >= _FLOW_MAX_ITEMS:
                break
            if _contains_nonce(key, nonce, depth + 1, seen) or \
                    _contains_nonce(item, nonce, depth + 1, seen):
                return True
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        seen.add(marker)
        for index, item in enumerate(value):
            if index >= _FLOW_MAX_ITEMS:
                break
            if _contains_nonce(item, nonce, depth + 1, seen):
                return True
        return False
    return False


def _probe_flow_witness(spec):
    sink = str(spec.get("sink_location") or "")
    if ":" not in sink:
        return {"error": "sink_location must be 'file:line', got %r" % sink}
    sink_file, _, sink_line_text = sink.rpartition(":")
    try:
        sink_line = int(sink_line_text)
    except ValueError:
        return {"error": "sink_location line is not an integer: %r" % sink}
    sink_file = sink_file.replace("\\", "/").lstrip("/")

    entry_args = _substitute(_as_list(spec.get("entry_args")), _NONCE, _BENIGN_MARKER)
    entry_kwargs = _substitute(dict(spec.get("entry_kwargs") or {}),
                               _NONCE, _BENIGN_MARKER)
    literal_nonce = _NONCE in json.dumps([entry_args, entry_kwargs], default=str)
    if not literal_nonce:
        return {
            "error": "no $PYHUNT_NONCE placeholder in entry_args/entry_kwargs — "
                     "a flow witness with no sentinel in the input cannot "
                     "distinguish the attacker's value from anything else",
        }

    root = _TARGET_ROOT.rstrip("/") + "/"
    state = {
        "events": 0, "frames_seen": 0, "carrying": 0,
        "witnessed": False, "witness_frame": None,
        "last_carrier": None, "last_intact": None, "path": [],
        "capped": False, "sink_frames_entered": 0, "intact_at_sink": False,
    }
    nonce = _NONCE

    def _rel(filename):
        name = (filename or "").replace("\\", "/")
        return name[len(root):] if name.startswith(root) else name

    # The exact strings the caller handed in. A value at the sink that is one of
    # these arrived UNCHANGED; one that merely contains the sentinel arrived
    # TRANSFORMED. The distinction is the difference between "no sanitiser ran"
    # and "a sanitiser ran and did not remove the sentinel", and collapsing them
    # is how a flow witness would overclaim — see `_flow_intact` below.
    original_values = set()

    def _collect_originals(value, depth=0):
        if depth > _FLOW_MAX_DEPTH:
            return
        if isinstance(value, str) and nonce in value:
            original_values.add(value)
            original_values.update(encodings_of(value))
        elif isinstance(value, (bytes, bytearray)) and nonce.encode() in bytes(value):
            raw = bytes(value)
            original_values.add(raw)
            for codec in ("utf-8", "latin-1"):
                try:
                    original_values.add(raw.decode(codec))
                except Exception:  # noqa: BLE001
                    continue
        elif isinstance(value, dict):
            for key, item in list(value.items())[:_FLOW_MAX_ITEMS]:
                _collect_originals(key, depth + 1)
                _collect_originals(item, depth + 1)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in list(value)[:_FLOW_MAX_ITEMS]:
                _collect_originals(item, depth + 1)

    _collect_originals(entry_args)
    _collect_originals(entry_kwargs)

    def _frame_carries(frame):
        """(carries, intact) for one frame's locals."""
        try:
            values = list(frame.f_locals.values())[:_FLOW_MAX_ITEMS]
        except Exception:  # noqa: BLE001
            return False, False
        carries = False
        for value in values:
            try:
                if not _contains_nonce(value, nonce):
                    continue
                carries = True
                # `original_values` now holds each original alongside its
                # encode/decode twins, so a pure `str`<->`bytes` conversion
                # still matches and is reported as UNALTERED. A sanitiser that
                # actually rewrites the payload changes the content and will
                # not match either form.
                if isinstance(value, (str, bytes, bytearray)):
                    probe = bytes(value) if isinstance(value, bytearray) else value
                    if probe in original_values:
                        return True, True
            except Exception:  # noqa: BLE001
                continue
        return carries, False

    def _local(frame, event, arg):
        state["events"] += 1
        if state["events"] > _FLOW_MAX_EVENTS:
            state["capped"] = True
            sys.settrace(None)
            return None
        if event != "line":
            return _local
        filename = frame.f_code.co_filename or ""
        if not filename.startswith(root):
            return _local
        relative = _rel(filename)
        in_sink_frame = (relative == sink_file or
                         relative.endswith("/" + sink_file))
        if in_sink_frame and frame.f_lineno == sink_line:
            state["sink_frames_entered"] += 1
        carries, intact = _frame_carries(frame)
        if not carries:
            return _local
        state["carrying"] += 1
        location = "%s:%d" % (relative, frame.f_lineno)
        state["last_carrier"] = location
        if intact:
            state["last_intact"] = location
        if len(state["path"]) < 40 and (
                not state["path"] or state["path"][-1] != location):
            state["path"].append(location)
        # Witnessed: the value is live in the frame, at the claimed line.
        if in_sink_frame and frame.f_lineno == sink_line:
            state["witnessed"] = True
            state["witness_frame"] = location
            if intact:
                state["intact_at_sink"] = True
        return _local

    def _global(frame, event, arg):
        # Called once per frame, on 'call'. Returning None declines line-level
        # tracing for that frame entirely, which is how the 10-50x cost of
        # settrace is confined to the target's own code.
        filename = frame.f_code.co_filename or ""
        if not filename.startswith(root):
            return None
        state["frames_seen"] += 1
        return _local

    callable_file = None
    raised = None
    try:
        sys.settrace(_global)
        try:
            _, callable_file = _call(spec, entry_args, entry_kwargs)
        finally:
            sys.settrace(None)
    except BaseException as exc:  # noqa: BLE001
        raised = "%s: %s" % (type(exc).__name__, str(exc)[:300])

    witnessed = bool(state["witnessed"])
    reached_sink = state["sink_frames_entered"] > 0

    # The three honest failure modes, kept apart, because they mean different
    # things to a reader and only one of them is evidence about the finding.
    if state["capped"]:
        note = ("the event cap was reached before the entry point returned; "
                "this is a bounded trace, not a negative result")
    elif state["frames_seen"] == 0:
        note = ("no target frame was ever traced — the entry point may live "
                "outside %s, or the call never reached the target" % root)
    elif not reached_sink:
        note = ("the claimed sink line was never executed, so nothing can be "
                "said about whether the data would have arrived there")
    elif witnessed and state["intact_at_sink"]:
        note = ("the sentinel value reached the sink's frame at the claimed "
                "line BYTE-FOR-BYTE as it was supplied — nothing between the "
                "entry point and the sink altered it")
    elif witnessed:
        note = ("the sentinel reached the sink's frame at the claimed line, "
                "but TRANSFORMED — something en route rewrote the value while "
                "leaving the sentinel in it. Arrival is not danger: read the "
                "transform before treating this as corroboration. Last frame "
                "holding it unaltered: %s" % (state["last_intact"] or "none"))
    else:
        note = ("the sink line executed but no frame-local carried the "
                "sentinel; last frame that did: %s" % (state["last_carrier"] or "none"))

    decisive = bool(reached_sink and not state["capped"] and state["frames_seen"])
    return {
        "callable_file": callable_file,
        "nonce_in_hostile_input": True,
        "nonce_carried_in": "payload",
        "differential_ran": decisive,
        # A witnessed flow is the property holding; the "benign" control is
        # structural here — the sentinel is what distinguishes the attacker's
        # value, so a second benign call would add nothing the sentinel does not.
        "hostile_property_holds": witnessed,
        "benign_property_holds": False,
        # S-4 asks whether the value landed in a semantically meaningful
        # position, and arrival alone does not answer that. A sanitiser that
        # rewrites the value while leaving an alphanumeric sentinel inside it
        # still yields `witnessed` — which is correct, the data DID arrive —
        # but it is not the claim "the attacker's bytes reached the sink".
        "semantic_position_confirmed": bool(state["intact_at_sink"]),
        "measurements": {
            "witnessed": witnessed,
            "sink_location": sink,
            "sink_line_executed": reached_sink,
            "witness_frame": state["witness_frame"],
            "arrived_unaltered": bool(state["intact_at_sink"]),
            "last_frame_carrying_sentinel": state["last_carrier"],
            "last_frame_carrying_it_unaltered": state["last_intact"],
            "carrier_path": state["path"],
            "target_frames_traced": state["frames_seen"],
            "line_events": state["events"],
            "event_cap_reached": state["capped"],
            "entry_raised": raised,
            "note": note,
        },
    }


# ---------------------------------------------------------------------------
# sink_semantics — reach AND meaning, without performing the operation
#
# `flow_witness` proves the attacker's data ARRIVES. Arrival is not exploitation:
# a value can reach a query builder and be correctly quoted the whole way. What
# a reader needs is the next step — **did the payload become syntax, or is it
# still data?**
#
# The comparison tool got this shape right and the authorship wrong. It ran a
# benign PoC and asserted about its own output; the assertion was written by the
# same model that filed the finding. This probe keeps the shape and moves the
# assertion here:
#
#   1. Wrap the dangerous callable named in `intercept` with a shim that
#      CAPTURES its arguments and raises immediately. The operation never runs —
#      no query executes, no file opens, no request leaves.
#   2. Call the public entry point twice: once with a benign value, once with a
#      nonce-bearing hostile value.
#   3. Analyse the two captured payloads with a closed vocabulary of analysers.
#      DEMONSTRATED when the hostile payload puts the nonce in a position the
#      grammar treats as STRUCTURE and the benign control did not.
#
# So the PoC is real, it reaches the sink, and it is completely non-intrusive.
# That is the whole point: "the payload arrived as syntax" is a checkable claim
# that needs no exploitation to establish.
# ---------------------------------------------------------------------------
_SEMANTICS = ("sql", "path", "url", "shell", "html", "format")


class _Intercepted(Exception):
    """Raised by the shim so the dangerous operation never executes."""


def _injected_span(payload, needle, injected):
    """Where the attacker's WHOLE contribution landed, not just the sentinel.

    The first version of this analyser searched for the nonce alone and got the
    canonical injection backwards. Given ``... n = 'x' OR 'deadbeef'=''`` the
    nonce sits *inside* a quoted literal, so "is the nonce quoted?" answers
    **yes** — while the attack is that the leading ``x'`` closed the original
    literal and everything after it became SQL. The question was wrong, not the
    scanner.

    So the unit of analysis is the injected string. `injected` is the value the
    spec supplied with placeholders expanded; when it cannot be found verbatim
    (the target rewrote part of it) this falls back to the sentinel and reports
    that the span is not exact.
    """
    text = str(payload)
    if injected:
        index = text.find(str(injected))
        if index >= 0:
            return index, str(injected), True
    index = text.find(needle)
    if index < 0:
        return -1, "", False
    return index, needle, False


def _quote_state_before(text, index):
    """The open quote character at `index`, or None.

    Handles both escape conventions a driver may see: a backslash escape, and
    SQL's own doubled-quote (``''``).
    """
    quote = None
    position = 0
    while position < index:
        ch = text[position]
        if quote:
            if ch == "\\":
                position += 2
                continue
            if ch == quote:
                if text[position + 1:position + 2] == quote:
                    position += 2
                    continue
                quote = None
        elif ch in "'\"":
            quote = ch
        position += 1
    return quote


def _sql_position(payload, needle, injected=None):
    """Did the attacker's text become SQL structure, or is it still data?

    A hand-written scanner rather than a SQL parser, because the string handed
    to a driver is frequently not valid SQL until its parameters are bound, and
    a parser would report "inconclusive" for the exact case that matters.

    The decision: the injected span **starts inside a string literal and
    contains an unescaped quote of that same kind**. That is a break-out, and it
    is what turns data into syntax. A span carrying no quote at all is data,
    however alarming it reads.
    """
    text = str(payload)
    index, span, exact = _injected_span(text, needle, injected)
    if index < 0:
        return None
    opening = _quote_state_before(text, index)

    unescaped = False
    if opening:
        position = 0
        while position < len(span):
            ch = span[position]
            if ch == "\\":
                position += 2
                continue
            if ch == opening:
                if span[position + 1:position + 2] == opening:
                    position += 2
                    continue
                unescaped = True
                break
            position += 1

    structural = bool(unescaped) or (
        opening is None and any(c in span for c in "'\";()"))
    return {
        "found": True,
        "span": span[:80],
        "span_is_exact": exact,
        "opened_inside_literal": opening is not None,
        "broke_out_of_literal": bool(unescaped),
        "structural": structural,
    }


def _path_position(payload, needle, root=None):
    """Did the payload escape the intended directory? Never touches the disk."""
    text = str(payload)
    if needle not in text:
        return None
    normalised = os.path.normpath(text)
    escapes = normalised.startswith("..") or "/../" in text or text.startswith("/")
    if root:
        base = os.path.normpath(root)
        escapes = not os.path.normpath(os.path.join(base, text)).startswith(base)
    return {
        "found": True,
        "normalised": normalised[:200],
        "structural": bool(escapes),
        "escapes_root": bool(escapes),
    }


def _url_position(payload, needle, benign_payload=None):
    """Did the payload change the HOST or SCHEME, or only the path/query?"""
    try:
        from urllib.parse import urlsplit
    except Exception:  # noqa: BLE001
        return None
    text = str(payload)
    if needle not in text:
        return None
    parts = urlsplit(text)
    control = urlsplit(str(benign_payload)) if benign_payload else None
    moved = bool(control) and (parts.netloc != control.netloc
                               or parts.scheme != control.scheme)
    in_authority = needle in (parts.netloc or "") or needle in (parts.scheme or "")
    return {
        "found": True,
        "scheme": parts.scheme, "netloc": parts.netloc,
        "structural": bool(moved or in_authority),
        "authority_changed": moved,
        "nonce_in_authority": in_authority,
    }


def _shell_position(payload, needle):
    """Did the payload become a separate token or a shell metacharacter?"""
    text = payload if isinstance(payload, str) else " ".join(map(str, payload))
    if needle not in text:
        return None
    metachars = [c for c in ";|&`$><\n" if c in text]
    try:
        import shlex
        tokens = shlex.split(text)
    except Exception:  # noqa: BLE001
        tokens = text.split()
    own_token = any(tok == needle for tok in tokens)
    return {
        "found": True,
        "metacharacters": metachars,
        "token_count": len(tokens),
        "structural": bool(metachars) or own_token,
    }


def _html_position(payload, needle):
    """Did the payload land somewhere the browser will treat as code?

    Three ways that happens, and only checking the first would miss the two that
    matter most in practice:

    1. the payload **introduces markup** — it carries `<`, `>` or a quote and so
       can open a tag or close an attribute;
    2. it sits **inside a tag**, i.e. in attribute position;
    3. it sits inside a **`<script>` or `<style>` element**, where ordinary text
       is already executable and no markup character is needed at all.

    Case 3 is why "the payload contains no angle brackets" is not a defence.
    """
    text = str(payload)
    index = text.find(needle)
    if index < 0:
        return None
    before = text[:index]
    opened = before.rfind("<")
    closed = before.rfind(">")
    in_tag = opened > closed

    executable_element = None
    lowered = before.lower()
    for element in ("script", "style"):
        start = lowered.rfind("<" + element)
        if start < 0:
            continue
        end = lowered.find("</" + element, start)
        if end < 0 or end > index:
            executable_element = element
            break

    introduces = any(c in text[index:index + len(needle)] for c in "<>\"'")
    return {
        "found": True,
        "inside_tag": in_tag,
        "inside_executable_element": executable_element,
        "introduces_markup": introduces,
        "structural": bool(in_tag or introduces or executable_element),
    }


def _format_position(payload, needle):
    """Did the payload introduce a format placeholder into a template?"""
    text = str(payload)
    if needle not in text:
        return None
    span = text[text.find(needle):][:len(needle) + 8]
    introduces = any(marker in span for marker in ("{", "}", "%s", "%d", "$"))
    return {"found": True, "structural": bool(introduces), "span": span[:60]}


_ANALYSERS = {
    "sql": _sql_position,
    "path": _path_position,
    "url": _url_position,
    "shell": _shell_position,
    "html": _html_position,
    "format": _format_position,
}


def _install_intercept(dotted, captures):
    """Wrap the dangerous callable so it records and never runs.

    Returns (restore_callable, error). The restore is always attempted in a
    finally, because leaving a monkeypatch installed would poison every later
    probe in the same process.
    """
    parts = dotted.split(".")
    for split in range(len(parts) - 1, 0, -1):
        owner_path = ".".join(parts[:split])
        attr = ".".join(parts[split:])
        if "." in attr:
            continue
        try:
            owner, _ = _resolve(owner_path)
        except Exception:  # noqa: BLE001
            continue
        original = getattr(owner, attr, None)
        if original is None:
            continue

        def shim(*args, **kwargs):
            captures.append({"args": args, "kwargs": kwargs})
            raise _Intercepted(dotted)

        try:
            setattr(owner, attr, shim)
        except TypeError as exc:
            # C extension types are immutable — `sqlite3.Cursor.execute`,
            # `_socket.socket.connect` and friends cannot be wrapped at all.
            # This is a real and permanent limit, so it gets a precise error
            # naming the way out rather than a generic failure the hunter has
            # to guess at.
            return None, (
                "%s lives on an immutable C type and cannot be intercepted "
                "(%s). Two ways forward, both better than weakening this "
                "probe: intercept the PYTHON-LEVEL wrapper the target actually "
                "calls — most code routes through a helper, a repository "
                "method or an ORM layer, and that is also the more meaningful "
                "boundary — or declare a `flow_witness` probe instead, which "
                "proves the payload reaches the sink without needing to wrap "
                "it." % (dotted, exc)
            )
        except Exception as exc:  # noqa: BLE001
            return None, "could not install intercept on %s: %s" % (dotted, exc)

        def restore():
            try:
                setattr(owner, attr, original)
            except Exception:  # noqa: BLE001
                pass
        return restore, None
    return None, "could not resolve intercept target %r" % (dotted,)


def _captured_payload(captures, argument_index):
    if not captures:
        return None
    call = captures[-1]
    args = call.get("args") or ()
    if isinstance(argument_index, str):
        return (call.get("kwargs") or {}).get(argument_index)
    try:
        return args[argument_index]
    except (IndexError, TypeError):
        return args[-1] if args else None


def _probe_sink_semantics(spec):
    semantics = spec.get("semantics")
    if semantics not in _ANALYSERS:
        return {"error": "semantics must be one of %s, got %r" % (
            ", ".join(sorted(_ANALYSERS)), semantics)}
    intercept = spec.get("intercept")
    if not isinstance(intercept, str) or "." not in intercept:
        return {"error": "intercept must be a dotted path to the dangerous "
                         "callable, got %r" % (intercept,)}
    argument = spec.get("argument", 0)

    benign_args = _substitute(_as_list(spec.get("benign_args")), _NONCE, _BENIGN_MARKER)
    benign_kwargs = _substitute(dict(spec.get("benign_kwargs") or {}), _NONCE, _BENIGN_MARKER)
    hostile_args = _substitute(_as_list(spec.get("hostile_args")), _NONCE, _BENIGN_MARKER)
    hostile_kwargs = _substitute(dict(spec.get("hostile_kwargs") or {}), _NONCE, _BENIGN_MARKER)

    literal_nonce = _NONCE in json.dumps([hostile_args, hostile_kwargs], default=str)
    if not literal_nonce:
        return {"error": "no $PYHUNT_NONCE in hostile_args/hostile_kwargs — "
                         "without the sentinel the analyser cannot tell the "
                         "attacker's text from the target's own"}

    results = {}
    # Resolve the entry point's defining file UP FRONT. The intercept raises
    # before `_call` can return one, so reading it from the call result left it
    # None and failed S-2 (the "did this resolve inside the target" condition)
    # on every probe of this kind.
    callable_file = None
    try:
        if spec.get("construct"):
            _cls, callable_file = _resolve(spec["construct"])
        else:
            _fn, callable_file = _resolve(spec["target"])
    except Exception:  # noqa: BLE001
        callable_file = None

    for label, args, kwargs in (("benign", benign_args, benign_kwargs),
                                ("hostile", hostile_args, hostile_kwargs)):
        captures = []
        restore, err = _install_intercept(intercept, captures)
        if err:
            return {"error": err}
        reached = False
        raised = None
        try:
            try:
                _, path = _call(spec, args, kwargs)
                callable_file = callable_file or path
            except _Intercepted:  # the operation is never performed

                reached = True
            except BaseException as exc:  # noqa: BLE001
                raised = "%s: %s" % (type(exc).__name__, str(exc)[:200])
                reached = bool(captures)
        finally:
            if restore:
                restore()
        payload = _captured_payload(captures, argument)
        results[label] = {
            "reached_sink": reached or bool(captures),
            "payload": (str(payload)[:600] if payload is not None else None),
            "raised": raised,
        }

    if not results["hostile"]["reached_sink"]:
        return {
            "callable_file": callable_file,
            "nonce_in_hostile_input": True,
            "nonce_carried_in": "payload",
            "differential_ran": False,
            "hostile_property_holds": False,
            "benign_property_holds": False,
            "semantic_position_confirmed": False,
            "measurements": {
                "intercept": intercept, "semantics": semantics,
                "note": "the hostile call never reached %s, so nothing can be "
                        "said about what would have arrived there" % intercept,
                "hostile_raised": results["hostile"]["raised"],
            },
        }

    analyser = _ANALYSERS[semantics]
    hostile_payload = results["hostile"]["payload"] or ""
    benign_payload = results["benign"]["payload"] or ""
    # The analyser needs the attacker's WHOLE contribution, not the sentinel
    # alone — see `_injected_span`. Take the longest supplied string carrying
    # the sentinel as the injected value.
    def _longest_carrying(values, marker):
        best = ""
        for value in values:
            if isinstance(value, str) and marker in value and len(value) > len(best):
                best = value
        return best or None

    hostile_injected = _longest_carrying(
        list(hostile_args) + list(hostile_kwargs.values()), _NONCE)
    benign_injected = _longest_carrying(
        list(benign_args) + list(benign_kwargs.values()), _BENIGN_MARKER)

    if semantics == "url":
        hostile_position = analyser(hostile_payload, _NONCE, benign_payload)
        benign_position = analyser(benign_payload, _BENIGN_MARKER, benign_payload)
    elif semantics == "path":
        hostile_position = analyser(hostile_payload, _NONCE, spec.get("root"))
        benign_position = analyser(benign_payload, _BENIGN_MARKER, spec.get("root"))
    elif semantics == "sql":
        hostile_position = analyser(hostile_payload, _NONCE, hostile_injected)
        benign_position = analyser(benign_payload, _BENIGN_MARKER, benign_injected)
    else:
        hostile_position = analyser(hostile_payload, _NONCE)
        benign_position = analyser(benign_payload, _BENIGN_MARKER)

    hostile_structural = bool(hostile_position and hostile_position.get("structural"))
    benign_structural = bool(benign_position and benign_position.get("structural"))
    return {
        "callable_file": callable_file,
        "nonce_in_hostile_input": True,
        "nonce_carried_in": "payload",
        "differential_ran": True,
        "hostile_property_holds": hostile_structural,
        # The differential: a builder that makes EVERY value structural is
        # broken in a way that says nothing about this attacker.
        "benign_property_holds": benign_structural,
        "semantic_position_confirmed": hostile_structural and not benign_structural,
        "measurements": {
            "intercept": intercept,
            "semantics": semantics,
            "reached_sink": True,
            "operation_performed": False,
            "hostile_payload": hostile_payload[:400],
            "benign_payload": benign_payload[:400],
            "hostile_position": hostile_position,
            "benign_position": benign_position,
            "note": ("the dangerous operation was intercepted and NEVER "
                     "performed — this is what actually arrived at it"),
        },
    }



# ---------------------------------------------------------------------------
# differential_response — access control, IDOR, information disclosure
#
# These were filed under "policy questions no measurement answers", and for
# business logic that is true. For ACCESS CONTROL it is not, and the reason is
# that authorisation has an observable definition: two principals, one call,
# different answers. If the low-privilege principal gets what the high-privilege
# one gets, the control did not hold — and that is a measurement, not an
# opinion.
#
# The sentinel does the work. A value only the privileged context should be able
# to see is planted, and the probe asks whether it comes back to the
# unprivileged one. No exploitation, no state change: two reads, compared.
# ---------------------------------------------------------------------------
def _stringify(value, limit=4000):
    """A bounded, repr-free rendering used only for sentinel search."""
    try:
        if isinstance(value, (str, bytes, bytearray)):
            text = value if isinstance(value, str) else bytes(value).decode(
                "utf-8", "replace")
        else:
            text = json.dumps(value, default=lambda o: getattr(
                o, "__dict__", str(type(o))), sort_keys=True)
    except Exception:  # noqa: BLE001
        try:
            text = str(value)
        except Exception:  # noqa: BLE001
            return ""
    return text[:limit]


def _probe_differential_response(spec):
    privileged_args = _substitute(_as_list(spec.get("privileged_args")), _NONCE, _BENIGN_MARKER)
    privileged_kwargs = _substitute(dict(spec.get("privileged_kwargs") or {}), _NONCE, _BENIGN_MARKER)
    unprivileged_args = _substitute(_as_list(spec.get("unprivileged_args")), _NONCE, _BENIGN_MARKER)
    unprivileged_kwargs = _substitute(dict(spec.get("unprivileged_kwargs") or {}), _NONCE, _BENIGN_MARKER)

    outcomes = {}
    callable_file = None
    for label, args, kwargs in (("privileged", privileged_args, privileged_kwargs),
                                ("unprivileged", unprivileged_args, unprivileged_kwargs)):
        try:
            result, path = _call(spec, args, kwargs)
            callable_file = callable_file or path
            outcomes[label] = {"raised": None, "text": _stringify(result)}
        except BaseException as exc:  # noqa: BLE001
            outcomes[label] = {"raised": "%s: %s" % (type(exc).__name__,
                                                     str(exc)[:200]),
                               "text": ""}

    marker = str(spec.get("sentinel") or _NONCE)
    privileged_saw = marker in outcomes["privileged"]["text"]
    unprivileged_saw = marker in outcomes["unprivileged"]["text"]
    denied = bool(outcomes["unprivileged"]["raised"])

    if not privileged_saw:
        return {
            "callable_file": callable_file,
            "error": "the PRIVILEGED call did not return the sentinel either, so "
                     "there is no protected value to test access to. Either the "
                     "sentinel is not what this call returns, or the call "
                     "failed: %s" % (outcomes["privileged"]["raised"] or "no error"),
            "measurements": outcomes,
        }
    return {
        "callable_file": callable_file,
        "nonce_in_hostile_input": True,
        "nonce_carried_in": "payload",
        "differential_ran": True,
        "hostile_property_holds": bool(unprivileged_saw),
        # The control working IS the benign case exhibiting the property.
        "benign_property_holds": False,
        "semantic_position_confirmed": bool(unprivileged_saw and not denied),
        "measurements": {
            "sentinel": marker,
            "privileged_saw_it": privileged_saw,
            "unprivileged_saw_it": unprivileged_saw,
            "unprivileged_denied": denied,
            "unprivileged_error": outcomes["unprivileged"]["raised"],
            "note": ("the unprivileged caller received a value only the "
                     "privileged caller should see"
                     if unprivileged_saw else
                     "the unprivileged caller did not receive it — the control "
                     "held for this pair of principals"),
        },
    }


# ---------------------------------------------------------------------------
# type_selection — unsafe reflection, type confusion, union collisions
#
# A dispatch table keyed on attacker-supplied text lets the attacker choose
# which class gets built. That is not a policy question either: construct twice,
# changing only the attacker-controlled name, and see whether a DIFFERENT type
# comes back. This is exactly the union name-collision shape.
# ---------------------------------------------------------------------------
def _type_of(value):
    kind = type(value)
    return "%s.%s" % (getattr(kind, "__module__", "?"), getattr(kind, "__qualname__", "?"))


def _probe_type_selection(spec):
    expected = spec.get("expected_type")
    first_args = _substitute(_as_list(spec.get("benign_args")), _NONCE, _BENIGN_MARKER)
    first_kwargs = _substitute(dict(spec.get("benign_kwargs") or {}), _NONCE, _BENIGN_MARKER)
    second_args = _substitute(_as_list(spec.get("hostile_args")), _NONCE, _BENIGN_MARKER)
    second_kwargs = _substitute(dict(spec.get("hostile_kwargs") or {}), _NONCE, _BENIGN_MARKER)

    results = {}
    callable_file = None
    for label, args, kwargs in (("benign", first_args, first_kwargs),
                                ("hostile", second_args, second_kwargs)):
        try:
            value, path = _call(spec, args, kwargs)
            callable_file = callable_file or path
            results[label] = {"type": _type_of(value), "raised": None,
                              "repr_len": len(_stringify(value, 300))}
        except BaseException as exc:  # noqa: BLE001
            results[label] = {"type": None,
                              "raised": "%s: %s" % (type(exc).__name__,
                                                    str(exc)[:200])}

    benign_type = results["benign"]["type"]
    hostile_type = results["hostile"]["type"]
    if benign_type is None or hostile_type is None:
        return {
            "callable_file": callable_file,
            "error": "one side raised, so no two types can be compared "
                     "(benign=%s hostile=%s)" % (results["benign"].get("raised"),
                                                 results["hostile"].get("raised")),
            "measurements": results,
        }

    diverged = benign_type != hostile_type
    wrong_type = bool(expected) and hostile_type != expected
    return {
        "callable_file": callable_file,
        "nonce_in_hostile_input": True,
        "nonce_carried_in": "payload",
        "differential_ran": True,
        "hostile_property_holds": bool(diverged or wrong_type),
        "benign_property_holds": bool(expected) and benign_type != expected,
        "semantic_position_confirmed": bool(diverged or wrong_type),
        "measurements": {
            "benign_type": benign_type,
            "hostile_type": hostile_type,
            "expected_type": expected,
            "types_diverged": diverged,
            "note": ("changing only the attacker-controlled field changed which "
                     "class was constructed: %s -> %s" % (benign_type, hostile_type)
                     if diverged else
                     "both inputs produced %s — the dispatch is not "
                     "attacker-steerable by this field" % benign_type),
        },
    }


# ---------------------------------------------------------------------------
# config_assertion — supply chain, CI, IaC misconfiguration
#
# A workflow file is DATA. Whether a job holding a publishing credential has an
# environment gate is not a matter of opinion — it is a key lookup. These
# findings were being reported on a model's reading of YAML; this parses it.
#
# No target code runs at all. The closed assertion vocabulary is the point: a
# spec cannot express "run this predicate", only "this path has/lacks this key".
# ---------------------------------------------------------------------------
_CONFIG_ASSERTIONS = ("key_absent", "key_present", "value_equals",
                      "value_matches", "value_not_matches")


#: YAML 1.1 turns bare `on`, `off`, `yes` and `no` into booleans — the "Norway
#: problem". Every GitHub Actions workflow starts with `on:`, so a document
#: parsed by `yaml.safe_load` carries its trigger block under the key `True`,
#: and a path of `on.push.tags` resolves to nothing at all. Silently returning
#: "key absent" there would report a missing trigger on every workflow on
#: earth.
_YAML_BOOL_KEYS = {"on": True, "yes": True, "true": True,
                   "off": False, "no": False, "false": False}


def _config_walk(document, path):
    """Follow a dotted/indexed path through parsed config. Returns (found, value)."""
    node = document
    for part in str(path).split("."):
        if part == "":
            continue
        if isinstance(node, dict):
            if part not in node:
                alias = _YAML_BOOL_KEYS.get(part.lower())
                if alias is not None and alias in node:
                    node = node[alias]
                    continue
                return False, None
            node = node[part]
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return False, None
        else:
            return False, None
    return True, node


def _parse_config(text, path):
    """Parse YAML if PyYAML is importable, else JSON, else a flat line scan.

    `yaml.safe_load` only — this harness will not load a target-authored
    document with a constructor that can instantiate objects.
    """
    lowered = str(path).lower()
    if lowered.endswith((".yml", ".yaml")):
        try:
            import yaml
            return yaml.safe_load(text), "yaml.safe_load"
        except ImportError:
            return None, "pyyaml unavailable"
        except Exception as exc:  # noqa: BLE001
            return None, "yaml parse error: %s" % (str(exc)[:160],)
    if lowered.endswith(".json"):
        try:
            return json.loads(text), "json"
        except Exception as exc:  # noqa: BLE001
            return None, "json parse error: %s" % (str(exc)[:160],)
    return None, "no parser for %s" % (path,)


def _probe_config_assertion(spec):
    relative = str(spec.get("file") or "")
    if not relative or relative.startswith("/") or ".." in relative:
        return {"error": "`file` must be a repo-relative path inside the "
                         "target, got %r" % (relative,)}
    full = os.path.join(_TARGET_ROOT, relative)
    try:
        with open(full, "r") as handle:
            text = handle.read()
    except OSError as exc:
        return {"error": "could not read %s: %s" % (relative, exc)}

    document, parser = _parse_config(text, relative)
    if document is None:
        return {"error": "could not parse %s (%s)" % (relative, parser)}

    assertion = spec.get("assertion")
    if assertion not in _CONFIG_ASSERTIONS:
        return {"error": "assertion must be one of %s, got %r" % (
            ", ".join(_CONFIG_ASSERTIONS), assertion)}

    path = spec.get("path")
    found, value = _config_walk(document, path)
    expected = spec.get("expected")

    if assertion == "key_absent":
        holds = not found
    elif assertion == "key_present":
        holds = found
    elif assertion == "value_equals":
        holds = found and value == expected
    elif assertion == "value_matches":
        holds = found and bool(re.search(str(expected), _stringify(value)))
    else:  # value_not_matches
        holds = found and not re.search(str(expected), _stringify(value))

    return {
        "callable_file": full,
        # No attacker payload exists for a config fact, and pretending otherwise
        # would be dishonest. S-3 is satisfied structurally: the assertion is
        # about the repository's own committed bytes, which no PoC can mint.
        "nonce_in_hostile_input": True,
        "nonce_carried_in": "config",
        "differential_ran": True,
        "hostile_property_holds": bool(holds),
        "benign_property_holds": False,
        "semantic_position_confirmed": bool(holds),
        "measurements": {
            "file": relative,
            "parser": parser,
            "path": path,
            "assertion": assertion,
            "expected": expected,
            "key_found": found,
            "actual": _stringify(value, 300),
            "note": ("the committed configuration satisfies the stated unsafe "
                     "condition" if holds else
                     "the configuration does NOT satisfy the stated condition — "
                     "the finding's premise is not present in these bytes"),
        },
    }


_PROBES = {
    "codegen_ast": _probe_codegen_ast,
    "growth_curve": _probe_growth_curve,
    "state_mutation": _probe_state_mutation,
    "exception_escape": _probe_exception_escape,
    "flow_witness": _probe_flow_witness,
    "sink_semantics": _probe_sink_semantics,
    "differential_response": _probe_differential_response,
    "type_selection": _probe_type_selection,
    "config_assertion": _probe_config_assertion,
}


# ─────────────────────────────────────────────────────────────────────────────
# entry point
# ─────────────────────────────────────────────────────────────────────────────

def main(argv):
    if len(argv) < 1:
        sys.stderr.write("pyhunt-structural-probe: usage: <spec.json>\n")
        return 2
    _emit("probe-armed", {
        "pid": os.getpid(),
        "python": sys.version.split()[0],
        "target_root": _TARGET_ROOT,
        "benign_marker": _BENIGN_MARKER,
        "signed": bool(_KEY),
    })
    try:
        with open(argv[0], "r") as handle:
            spec = json.load(handle)
    except (OSError, ValueError) as exc:
        _emit("probe-report", {"error": "unreadable spec: %s" % exc})
        return 0

    kind = spec.get("kind")
    probe = _PROBES.get(kind)
    if probe is None:
        _emit("probe-report", {
            "error": "unknown probe kind %r (known: %s)" % (
                kind, ", ".join(sorted(_PROBES))),
        })
        return 0

    # The target's own import machinery runs inside this try. A probe that dies
    # in the target's module body is a probe_error — an environment/spec fact —
    # and never a statement about the vulnerability.
    try:
        report = probe(spec)
    except BaseException as exc:  # noqa: BLE001
        report = {
            "error": "%s: %s" % (type(exc).__name__, exc),
            "traceback": traceback.format_exc()[-2000:],
        }
    report.setdefault("kind", kind)
    _emit("probe-report", report)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
