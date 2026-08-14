"""Deterministic entry→sink taint chunking (feature V8).

Recon's LLM only hunts what it *thinks* to hunt. This module makes coverage
deterministic: for every attacker-controllable input F1 already enumerated,
walk the real call graph (``audit.graph``) to every dangerous sink and emit ONE
narrowly-scoped Hunt task per reachable ``(input → sink)`` path — so the Hunter
always sees source AND sink together, the precondition for a confirmed
data-flow finding.

Composition:
  - F1 inputs (``db.get_inputs``)                    → taint *entries*
  - ``PYTHON_SINKS`` regex table (curated here)      → dangerous *sinks*
  - ``GraphQuery.taint_paths`` (ported BFS)           → reachability

Everything here is STATIC: files are read (utf-8, ``errors="replace"``) but the
target's code is NEVER executed. The sink table below is the one genuinely new
artifact — no donor ships a portable Python sink table, so it is authored from
real dangerous Python APIs plus the attack classes named in
``schemas/hunt_task.schema.json``. The BFS is ported; the rest is thin glue.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from lang_hints import EXT_TO_LANG

if TYPE_CHECKING:  # avoid import cost / any cycle — used only for type hints
    from graph.query import GraphQuery


# ---------------------------------------------------------------------------
# Curated Python sink table (AUTHORED — the one genuinely new artifact).
#
# A few high-signal patterns per class beats exhaustive noise. Keys are the
# attack_class strings the hunt_task schema documents. Patterns are matched
# line-by-line against statically-read source; first matching class per line
# wins (so one dangerous line yields at most one sink).
# ---------------------------------------------------------------------------
PYTHON_SINKS: dict[str, list[re.Pattern]] = {
    "command_injection": [
        re.compile(p)
        for p in (
            r"subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(",
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"os\.exec[lv]\w*\s*\(",
            r"os\.spawn\w*\s*\(",
            r"commands\.get(?:output|status)\w*\s*\(",
            r"\bshell\s*=\s*True\b",
            r"pty\.spawn\s*\(",
        )
    ],
    "code_injection": [
        re.compile(p)
        for p in (
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bcompile\s*\(",
            r"__import__\s*\(",
            r"types\.FunctionType\s*\(",
            # Codegen / template injection (CWE-94) — a code generator that
            # interpolates untrusted schema names/types/defaults into a jinja2
            # template or a built-up source string emits injectable code. These
            # render/Template calls are the codegen sink.
            r"\.render\s*\(",
            r"\bTemplate\s*\(",
            r"\bEnvironment\s*\(",
            r"\.from_string\s*\(",
            r"\brender_template(?:_string)?\s*\(",
            # Docstring/comment-terminator injection (CWE-94): a generator that
            # writes an untrusted description/doc/comment field INTO a string
            # literal of the file it emits. The attacker supplies the literal's
            # own terminator, closes it early, and the rest of their text is
            # code that runs when the VICTIM imports the generated file. The
            # sink is the literal-building expression, not eval/exec — hence
            # these shapes, which the render/Template patterns above miss.
            # Precedent: datamodel-code-generator CVE-2026-54621/54656/55415,
            # openapi-python-client GHSA-9x4c-63pf-525f.
            r"f['\"]{3}",          # f-triple-quote — a docstring emitter
            r"['\"]{3}\s*\{",      # triple-quote opening straight into a slot
            r"\.safe_substitute\s*\(",
            r"\.substitute\s*\(",
        )
    ],
    "deserialization": [
        re.compile(p)
        for p in (
            r"(?:c|_)?[pP]ickle\.loads?\s*\(",
            # Exempt only a SAFE loader, not the mere presence of a `Loader=`
            # kwarg: `yaml.load(x, Loader=yaml.Loader)` and `UnsafeLoader` are
            # full deserializers, and `FullLoader` was RCE-capable before
            # PyYAML 5.4 (CVE-2020-14343) — all three were silently exempted
            # by the old `(?![^)]*Loader\s*=)` lookahead.
            r"yaml\.load\s*\((?![^)]*\bC?SafeLoader\b)",
            r"yaml\.(?:unsafe_load|full_load)\s*\(",
            r"marshal\.loads?\s*\(",
            r"dill\.loads?\s*\(",
            r"jsonpickle\.(?:decode|loads)\s*\(",
            r"shelve\.open\s*\(",
            # Pickle wearing a data-science costume. `pandas.read_pickle` and
            # `joblib.load` are unpickle calls with no safe mode. The other two
            # are safe BY DEFAULT on current versions and unsafe when the
            # default is overridden — so match the override, not the call.
            r"(?:pandas|pd)\.read_pickle\s*\(",
            r"joblib\.load\s*\(",
            r"(?:numpy|np)\.load\s*\([^)]*allow_pickle\s*=\s*True",
            r"torch\.load\s*\((?![^)]*weights_only\s*=\s*True)",
        )
    ],
    # CWE-470. Resolving a name is not a lookup: importing runs the module's
    # top-level code, so an allow-list check applied AFTER resolution is
    # already too late. `getattr(obj, name)` is deliberately NOT here — it
    # measured 34 hits across the bench targets, almost all benign dynamic
    # attribute access; it belongs in the lens, not in a table that spends a
    # hunt task per match.
    "unsafe_reflection": [
        re.compile(p)
        for p in (
            r"importlib\.import_module\s*\(",
            r"pydoc\.locate\s*\(",
            r"globals\(\)\s*\[",
        )
    ],
    "path_traversal": [
        re.compile(p)
        for p in (
            r"\bopen\s*\(",
            r"os\.path\.join\s*\(",
            r"shutil\.(?:copy\w*|move|rmtree)\s*\(",
            r"\bsend_file\s*\(",
            r"send_from_directory\s*\(",
            r"os\.(?:remove|unlink)\s*\(",
            r"\bPath\s*\(",
        )
    ],
    "ssrf": [
        re.compile(p)
        for p in (
            r"requests\.(?:get|post|put|delete|head|patch|request)\s*\(",
            r"urllib\.request\.urlopen\s*\(",
            r"\burlopen\s*\(",
            r"httpx\.(?:get|post|put|delete|request|Client|AsyncClient)\s*\(",
            r"aiohttp\.(?:ClientSession|request)\b",
            r"socket\.(?:connect|create_connection)\s*\(",
        )
    ],
    "sql_injection": [
        re.compile(p)
        for p in (
            r"\.execute(?:many|script)?\s*\(",
            r"session\.execute\s*\(",
            r"\btext\s*\(",
            r"\.raw\s*\(",
        )
    ],
    "xxe": [
        re.compile(p)
        for p in (
            r"etree\.(?:parse|fromstring|XML)\s*\(",
            r"\blxml\b",
            r"xml\.dom\.minidom\b",
            r"\bxmlrpc\b",
            r"\bpulldom\b",
            r"sax\.(?:parse|parseString)\s*\(",
        )
    ],
    "ssti": [
        re.compile(p)
        for p in (
            r"\bTemplate\s*\(",
            r"render_template_string\s*\(",
            r"\.from_string\s*\(",
            r"\bEnvironment\s*\(",
        )
    ],
    "open_redirect": [
        re.compile(p)
        for p in (
            r"\bredirect\s*\(",
            r"HttpResponseRedirect\s*\(",
        )
    ],
    # CWE-117. The sink is *eager* interpolation of untrusted text into the log
    # message — an f-string, a `%`/`.format()` applied before the call, or a
    # concatenation — because that is what lets a CR/LF in the value forge a
    # second log record.
    #
    # The pattern used to be `logger.<level>(...%...)`, which matches
    # `logger.debug("Stream ID %d created", stream_id)`. That is *lazy* logging:
    # the `%` is a placeholder the logging module fills in itself, it is the
    # form the stdlib documentation tells you to use, and it is not a sink. The
    # cost was not abstract — on h2 it produced eleven matches inside the
    # analysis scope, every one of them false, and because a sink claims its
    # enclosing function, those eleven were competing for the same task budget
    # as the real unbounded-growth sinks in the same functions. A pattern that
    # fires on correct code does not merely add noise; it displaces signal.
    "log_injection": [
        re.compile(p)
        for p in (
            r"log(?:ging|ger)?\.(?:info|warning|warn|error|debug|critical|exception)\s*\(\s*f['\"]",
            r"log(?:ging|ger)?\.(?:info|warning|warn|error|debug|critical|exception)\s*\([^)]*['\"]\s+%\s+[\w(]",
            r"log(?:ging|ger)?\.(?:info|warning|warn|error|debug|critical|exception)\s*\([^)]*\.format\s*\(",
            r"log(?:ging|ger)?\.(?:info|warning|warn|error|debug|critical|exception)\s*\([^)]*['\"]\s*\+\s*\w",
        )
    ],
    "information_disclosure": [
        re.compile(p)
        for p in (
            # CWE-200: a broad-except handler that prints/formats a traceback can
            # leak secrets carried by objects in scope — e.g. httpx's exception
            # repr embeds the Request, including Authorization headers. NARROW net
            # (traceback-print shape only, to avoid noise); the hunter confirms a
            # secret is actually reachable in the printed expression.
            r"traceback\.(?:format_exc|format_exception|print_exc)\s*\(",
            r"\.format_exc\s*\(",
        )
    ],
    # -----------------------------------------------------------------------
    # STATE AND RESOURCE SINKS.
    #
    # Every class above is an *injection* class: attacker text crosses into an
    # interpreter — a shell, a parser, a query planner, a source file. That is
    # the entire vocabulary of the table, and on a whole category of target it
    # describes nothing that is there.
    #
    # A sans-IO protocol library is the clean case. `python-hyper/h2` owns no
    # socket, no filesystem and no subprocess; grepping its twelve source files
    # for eval/exec/pickle/yaml.load/os.system/subprocess/open/socket/requests
    # returns ZERO hits, and that is a true fact about the library rather than a
    # gap in the search. Run the table above against it and the only matches are
    # false: `def open(self)` (a state-machine property, matched by the
    # path_traversal `open(` pattern) and eleven `logger.debug("...%s", arg)`
    # calls. A generator that stops there queues nothing real and the run
    # reports a clean protocol implementation — the exact shape of failure this
    # project refuses to ship, arrived at honestly.
    #
    # What is dangerous in that code is not interpretation, it is accumulation:
    # a container the peer can grow without bound, a per-frame walk over
    # everything accumulated so far, an accounting variable the peer can drive
    # past its guard. Those are CWE-400 / CWE-770 / CWE-407 / CWE-190, they are
    # where this library's actual CVE history lives, and none of them has an
    # eval-shaped pattern.
    #
    # These three classes are appended LAST on purpose. `find_sinks` takes the
    # first matching class per line in table order, so nothing here can steal a
    # line from an injection class above: `self.cache[k] = subprocess.run(...)`
    # is still command_injection. They can only add coverage.
    #
    # Noise was measured, not assumed — over two unrelated Python targets these
    # patterns produce 31 sinks across h2's 12 files and 12 across a 90-file
    # code-generation library, which is the density an authored table wants.
    # -----------------------------------------------------------------------
    #
    # CWE-400/CWE-770. Growth an attacker drives and nothing bounds. The
    # question the hunter must answer at each of these is the same one: what
    # caps this, and can a peer reach it faster than the cap sweeps it? h2's
    # `self.streams[stream_id] = s` is the archetype — the dict has no cap at
    # all, and closed entries are reclaimed only as a side effect of somebody
    # reading an `open_*_streams` property.
    "resource_exhaustion": [
        re.compile(p)
        for p in (
            # Insertion into an instance-owned container at a caller-chosen key.
            r"self\.\w+\[[^\]\n]{1,60}\]\s*=(?!=)",
            # An unbounded deque. `maxlen=` is the cap, and its absence is the
            # finding — same doctrine as the SafeLoader and weights_only=True
            # exemptions above: match the dangerous configuration, not the API.
            r"\bdeque\s*\((?![^)\n]*maxlen)",
            # Append to an instance-owned container.
            r"self\.\w+\.append\s*\(",
            # A named accumulator that only ever grows on the receive path.
            r"self\.\w*(?:data|buf|buffer|queue|pending|backlog|frames|events)"
            r"\w*\s*\+=",
        )
    ],
    # CWE-407. Superlinear work per attacker-supplied item. A full walk of an
    # instance container is O(n); reached once per inbound message it is O(n^2)
    # over a connection, and the peer chooses n.
    "algorithmic_complexity": [
        re.compile(p)
        for p in (
            r"for\s+\w+(?:\s*,\s*\w+)*\s+in\s+self\._?\w+"
            r"(?:\.(?:items|values|keys)\s*\(\))?\s*:",
        )
    ],
    # CWE-190/CWE-191. Accounting the peer drives. Flow-control windows, sizes
    # and counters that are incremented or decremented from wire values are
    # where a protocol implementation over- or under-flows its own guard.
    "integer_overflow": [
        re.compile(p)
        for p in (
            r"self\.\w*(?:window|size|count|remaining|budget|processed|length)"
            r"\w*\s*[-+*]=",
        )
    ],
}


# ---------------------------------------------------------------------------
# Additional AUTHORED sink tables (JS/TS, Java, Go). Same doctrine as
# PYTHON_SINKS: a few high-signal patterns per class; keys are hunt_task
# attack_class strings; first matching class per line wins. C/C++ deliberately
# excluded (needs sanitizer-driven confirmation, a later phase).
# ---------------------------------------------------------------------------
JAVASCRIPT_SINKS: dict[str, list[re.Pattern]] = {
    "command_injection": [re.compile(p) for p in (
        r"child_process\.(?:exec|execSync|spawn|spawnSync|execFile)\s*\(",
        r"\bshell\s*:\s*true\b",
    )],
    "code_injection": [re.compile(p) for p in (
        r"\beval\s*\(",
        r"\bnew\s+Function\s*\(",
        r"vm\.(?:runInNewContext|runInThisContext|compileFunction)\s*\(",
    )],
    "ssrf": [re.compile(p) for p in (
        r"\b(?:axios|got|fetch|request|superagent)\s*(?:\.\w+)?\s*\(",
        r"https?\.(?:get|request)\s*\(",
    )],
    "sql_injection": [re.compile(p) for p in (
        r"\.query\s*\(",
        r"\.raw\s*\(",
        r"sequelize\.query\s*\(",
    )],
    "path_traversal": [re.compile(p) for p in (
        r"fs\.(?:readFile|readFileSync|createReadStream|readdir|readdirSync)\s*\(",
        r"\.sendFile\s*\(",
    )],
    "prototype_pollution": [re.compile(p) for p in (
        r"__proto__",
        r"(?:_\.)?merge\s*\(",
        r"Object\.assign\s*\(",
    )],
    "deserialization": [re.compile(p) for p in (
        r"node-serialize",
        r"\bunserialize\s*\(",
    )],
}

JAVA_SINKS: dict[str, list[re.Pattern]] = {
    "command_injection": [re.compile(p) for p in (
        r"Runtime\.getRuntime\(\)\.exec\s*\(",
        r"new\s+ProcessBuilder\s*\(",
    )],
    "code_injection": [re.compile(p) for p in (
        r"ScriptEngine\w*\.eval\s*\(",
        r"Ognl\.getValue\s*\(",
        r"SpelExpressionParser|ExpressionParser\b",
        r"MVEL\.eval\w*\s*\(",
    )],
    "sql_injection": [re.compile(p) for p in (
        r"\.createStatement\s*\(",
        r"Statement\b[^;]*\.execute(?:Query|Update)?\s*\(",
        r"\.createQuery\s*\(",
        r"\.createNativeQuery\s*\(",
    )],
    "ssrf": [re.compile(p) for p in (
        r"new\s+URL\s*\([^)]*\)\.openConnection\s*\(",
        r"HttpURLConnection\b",
        r"RestTemplate\b|WebClient\b|HttpClient\b|OkHttpClient\b",
        r"Jsoup\.connect\s*\(",
    )],
    "deserialization": [re.compile(p) for p in (
        r"new\s+ObjectInputStream\s*\(",
        r"\.readObject\s*\(",
        r"new\s+XMLDecoder\s*\(",
        r"XStream\b",
    )],
    "xxe": [re.compile(p) for p in (
        r"DocumentBuilderFactory\b",
        r"SAXParserFactory\b",
        r"XMLInputFactory\b",
    )],
    "path_traversal": [re.compile(p) for p in (
        r"new\s+File\s*\(",
        r"new\s+FileInputStream\s*\(",
        r"Files\.(?:newInputStream|readAllBytes|newBufferedReader|lines)\s*\(",
    )],
    "jndi_injection": [re.compile(p) for p in (
        r"\.lookup\s*\(",
        r"InitialContext\b",
        r"JndiTemplate\b",
    )],
}

GO_SINKS: dict[str, list[re.Pattern]] = {
    "command_injection": [re.compile(p) for p in (
        r"exec\.Command(?:Context)?\s*\(",
    )],
    "code_injection": [re.compile(p) for p in (
        r"plugin\.Open\s*\(",
    )],
    "ssrf": [re.compile(p) for p in (
        r"http\.(?:Get|Post|Head|PostForm|NewRequest)\s*\(",
        r"\.Do\s*\(\s*req",
        r"net\.Dial\s*\(",
    )],
    "sql_injection": [re.compile(p) for p in (
        r"\.(?:Query|QueryRow|Exec)(?:Context)?\s*\(",
    )],
    "path_traversal": [re.compile(p) for p in (
        r"os\.(?:Open|OpenFile|ReadFile)\s*\(",
        r"ioutil\.ReadFile\s*\(",
        r"http\.ServeFile\s*\(",
    )],
    "ssti": [re.compile(p) for p in (
        r"template\.(?:Must|New|Parse)\s*\(",
    )],
}

CSHARP_SINKS: dict[str, list[re.Pattern]] = {
    "command_injection": [re.compile(p) for p in (
        r"Process\.Start\s*\(",
        r"new\s+ProcessStartInfo\s*\(",
    )],
    "code_injection": [re.compile(p) for p in (
        r"CSharpScript\.(?:Eval|RunAsync|Create)\s*\(",
        r"CompileAssemblyFromSource\s*\(",
        r"Assembly\.Load\s*\(",
    )],
    "sql_injection": [re.compile(p) for p in (
        r"new\s+SqlCommand\s*\(",
        r"new\s+OleDbCommand\s*\(",
        r"\.ExecuteReader\s*\(",
        r"\.ExecuteNonQuery\s*\(",
        r"\.ExecuteScalar\s*\(",
        r"\.(?:FromSqlRaw|ExecuteSqlRaw)\s*\(",
    )],
    "ssrf": [re.compile(p) for p in (
        r"new\s+HttpClient\s*\(",
        r"\.(?:GetAsync|PostAsync|GetStringAsync|DownloadString)\s*\(",
        r"WebRequest\.Create\s*\(",
        r"new\s+WebClient\s*\(",
    )],
    "path_traversal": [re.compile(p) for p in (
        r"File\.(?:ReadAllText|ReadAllBytes|ReadAllLines|Open|OpenRead)\s*\(",
        r"new\s+FileStream\s*\(",
        r"new\s+StreamReader\s*\(",
    )],
    "deserialization": [re.compile(p) for p in (
        r"new\s+BinaryFormatter\s*\(",
        r"\.Deserialize\s*\(",
        r"new\s+(?:NetDataContractSerializer|LosFormatter|ObjectStateFormatter)\s*\(",
        r"TypeNameHandling",
    )],
    "xxe": [re.compile(p) for p in (
        r"new\s+XmlDocument\s*\(",
        r"new\s+XmlTextReader\s*\(",
        r"DtdProcessing\s*\.\s*Parse",
    )],
}

SINKS_BY_LANG: dict[str, dict[str, list[re.Pattern]]] = {
    "python": PYTHON_SINKS,
    "javascript": JAVASCRIPT_SINKS,
    "typescript": JAVASCRIPT_SINKS,
    "java": JAVA_SINKS,
    "go": GO_SINKS,
    "csharp": CSHARP_SINKS,
}


@dataclass(frozen=True)
class Sink:
    file: str
    line: int
    symbol_id: str
    attack_class: str


@dataclass(frozen=True)
class Entry:
    file: str
    line: int
    symbol_id: str
    trust_level: str


def _split_location(location: str | None) -> tuple[str, int]:
    """Split an F1 ``location`` ("file:line" / "file:line:col" / "file") into
    ``(file, line)``. Line defaults to 0 when absent."""
    loc = (location or "").strip()
    if not loc:
        return "", 0
    parts = loc.split(":")
    # Drop a trailing column ("file:line:col") so we key on the line.
    if len(parts) >= 3 and parts[-1].strip().isdigit() and parts[-2].strip().isdigit():
        parts = parts[:-1]
    if len(parts) >= 2 and parts[-1].strip().isdigit():
        return ":".join(parts[:-1]).strip(), int(parts[-1].strip())
    return loc, 0


def _file_language(graph: "GraphQuery", rel_file: str) -> str | None:
    """Language of a graph file: prefer a graph node's declared language,
    else fall back to the extension map. Returns None if unknown."""
    from pathlib import PurePosixPath
    nids = graph._by_file.get(rel_file, [])
    for nid in nids:
        lang = graph._doc.nodes[nid].language
        if lang in SINKS_BY_LANG:
            return lang
    return EXT_TO_LANG.get(PurePosixPath(rel_file).suffix.lower())


def in_scope(rel_file: str, scope: tuple[str, ...] | None) -> bool:
    """Whether `rel_file` lies inside the run's declared analysis scope.

    `scope` is the repo-relative prefix list from `manifest.json` /
    `inputs.json`'s ``target_scope`` (e.g. ``("src/h2",)``). ``None`` or empty
    means the whole repository, which is the historical behaviour and stays the
    default for every run that does not declare a scope.
    """
    if not scope:
        return True
    norm = rel_file.replace("\\", "/")
    return any(norm == p or norm.startswith(p.rstrip("/") + "/") for p in scope)


def _files_by_lang(
    graph: "GraphQuery", scope: tuple[str, ...] | None = None,
) -> list[tuple[str, str]]:
    """Every graph file paired with a language that HAS a sink table.
    Files with no table (or unknown language) are dropped, as are files outside
    the declared analysis scope."""
    out: list[tuple[str, str]] = []
    for f in graph._by_file:
        if not in_scope(f, scope):
            continue
        lang = _file_language(graph, f)
        if lang in SINKS_BY_LANG:
            out.append((f, lang))
    return sorted(out)


def _read_static(repo_path: Path, rel_file: str) -> str | None:
    """Read a source file statically. NEVER executes it. None on any OSError."""
    try:
        return (Path(repo_path) / rel_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def find_sinks(
    repo_path: Path, graph: "GraphQuery", scope: tuple[str, ...] | None = None,
) -> list[Sink]:
    """Scan the graph's files for dangerous-API lines, tagging each with its
    attack class and enclosing symbol. Language-parametric: each file is
    matched against the sink table for ITS language (SINKS_BY_LANG). Python
    behavior is unchanged. Deterministic and static-only.

    `scope` restricts the scan to the run's declared analysis scope. A sink in
    an example server or a test fixture is not a sink in the library the run
    says it is auditing, and a task spent on one is budget the declared scope
    does not get back.
    """
    sinks: list[Sink] = []
    for rel_file, lang in _files_by_lang(graph, scope):
        table = SINKS_BY_LANG[lang]
        text = _read_static(repo_path, rel_file)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for attack_class, patterns in table.items():
                if any(pat.search(line) for pat in patterns):
                    symbol_id = graph.symbol_at_line(rel_file, lineno)
                    if symbol_id:
                        sinks.append(Sink(rel_file, lineno, symbol_id, attack_class))
                    break  # one class per line
    return sinks


def _node_file(graph: "GraphQuery", node_id: str) -> str | None:
    node = graph._doc.nodes.get(node_id)
    return node.file if node else None


def _node_label(graph: "GraphQuery", node_id: str) -> str:
    node = graph._doc.nodes.get(node_id)
    return node.name if node else node_id


def _target_files(
    graph: "GraphQuery", path: list[str], entry: Entry, sink: Sink
) -> list[str]:
    """Unique, order-preserved files along the flow (entry → path → sink),
    keeping only files that exist in the graph."""
    files: list[str] = []

    def add(f: str | None) -> None:
        if f and f not in files and f in graph._by_file:
            files.append(f)

    add(entry.file)
    for nid in path:
        add(_node_file(graph, nid))
    add(sink.file)
    return files


def _resolve_entries(
    graph: "GraphQuery", inputs: list[dict]
) -> dict[str, tuple[dict, Entry]]:
    """Resolve each F1 input's ``location`` to its enclosing entry symbol id.

    Returns a mapping ``symbol_id -> (input_dict, Entry)`` deduped by symbol
    (first input wins) and insertion-ordered. The single source of truth for the
    taint *entry set*, shared by ``build_taint_tasks`` (forward) and — via
    ``_entry_ids`` — ``build_sink_backward_tasks`` (which needs only the ids to
    compute which sinks are already forward-reached). Extracted from V8's inline
    loop; behavior-preserving (V8's tests guard it).
    """
    entry_by_id: dict[str, tuple[dict, Entry]] = {}
    for inp in inputs:
        file, line = _split_location(inp.get("location"))
        if not file:
            continue
        symbol_id = graph.symbol_at_line(file, line)
        if not symbol_id or symbol_id in entry_by_id:
            continue
        entry_by_id[symbol_id] = (
            inp, Entry(file, line, symbol_id, inp.get("trust_level") or "unknown")
        )
    return entry_by_id


def _entry_ids(graph: "GraphQuery", inputs: list[dict]) -> list[str]:
    """Ordered, unique entry symbol ids for the F1 inputs (the brief's shared
    helper). Thin wrapper over ``_resolve_entries``."""
    return list(_resolve_entries(graph, inputs))


def build_taint_tasks(
    graph: "GraphQuery",
    inputs: list[dict],
    repo_path: Path,
    *,
    max_tasks: int = 40,
    max_hops: int = 8,
    scope: tuple[str, ...] | None = None,
) -> list[dict]:
    """Emit one ``hunt_task`` dict per reachable ``(input → sink)`` call-graph
    path. Never raises for empty/degenerate input — returns ``[]``.

    Steps (per the V8 brief):
      1. Resolve each F1 input's ``location`` to an entry symbol; keep resolved.
      2. Scan for sinks (``find_sinks``); index by enclosing symbol id.
      3. Multi-source BFS (``graph.taint_paths``) entries → sinks.
      4. Emit a priority-1 ``source="taint"`` hunt_task per (sink, path),
         dedup by ``(entry_symbol, sink_id, frozenset(target_files))``, cap at
         ``max_tasks``.
    """
    # 1. entries (shared derivation — see _resolve_entries / _entry_ids)
    entry_by_id = _resolve_entries(graph, inputs)
    entry_ids = list(entry_by_id)
    if not entry_ids:
        return []

    # 2. sinks
    sinks = find_sinks(repo_path, graph, scope)
    if not sinks:
        return []
    # One sink per (enclosing symbol, attack class) — the same granularity
    # `build_sink_backward_tasks` uses, so the two sources describe loci the
    # same way. A task is "one attack class, one location", and a function is
    # the location: `Settings.__init__` opens six unbounded deques on six
    # consecutive lines, which is one unbounded-settings finding, not six, and
    # emitting six spends six of the forty task slots re-asking one question.
    # Distinct classes in one function still get one task each — h2's
    # `_open_streams` is both an O(n) walk and an unbounded insert, and those
    # are two different bugs in two different sentences.
    sinks_by_id: dict[str, list[Sink]] = defaultdict(list)
    seen_class: set[tuple[str, str]] = set()
    for s in sinks:
        key = (s.symbol_id, s.attack_class)
        if key in seen_class:
            continue
        seen_class.add(key)
        sinks_by_id[s.symbol_id].append(s)

    # 3. reachability (ported BFS)
    paths = graph.taint_paths(entry_ids, list(sinks_by_id.keys()), max_hops)

    # 3b. Zero-hop flows: a sink INSIDE a function that is itself an entry.
    #
    # `taint_paths` seeds `visited` with every entry and records a sink only
    # when it is discovered as a *callee*, so a sink whose enclosing symbol is
    # an entry is structurally unreachable — the BFS marks it visited before it
    # starts. The donor documents this ("an entry that is itself a sink is not
    # recorded"), and on a service with a thin handler layer over a deep call
    # tree it costs nothing, because handlers rarely hold the sink themselves.
    #
    # On a protocol library it costs almost everything, and it gets worse the
    # BETTER phase 1 did its job. h2 is twelve files; a thorough inventory
    # resolved 110 distinct entry symbols across them, which is most of the
    # functions in the library — so 29 of the 32 sink symbols were also entry
    # symbols, and forward taint reported 2 paths out of 32 available. The
    # source the phase file ranks first, and the only one that hands the hunter
    # source and sink in one context, was silenced by the inventory being good.
    #
    # A same-function flow is not a weaker finding than a five-hop one. It is
    # the same finding with nothing in between to sanitise it, which makes it
    # the easiest to confirm and the hardest to argue with. It is emitted here
    # as a one-node path rather than by changing the shared BFS primitive,
    # which other phases also call.
    entry_id_set = set(entry_ids)
    paths = list(paths) + [
        (sink_id, [sink_id]) for sink_id in sinks_by_id
        if sink_id in entry_id_set
    ]

    # 4. emit
    tasks: list[dict] = []
    seen: set[tuple[str, str, frozenset]] = set()
    for sink_id, path in paths:
        start = path[0]
        entry_pair = entry_by_id.get(start)
        if entry_pair is None:
            continue
        inp, entry = entry_pair
        for sink in sinks_by_id.get(sink_id, []):
            target_files = _target_files(graph, path, entry, sink)
            if not target_files:
                continue
            # Keyed on the SINK, not on its enclosing symbol. `sinks_by_id`
            # holds every sink in a function, but the key used to read
            # `sink_id` — the symbol — so the second and later sinks in any one
            # function were dropped after the first had claimed the slot. The
            # loop looked like it emitted a task per sink and emitted one per
            # function, silently.
            #
            # It collapses exactly the distinction a task is supposed to carry.
            # h2's `_begin_new_stream` holds a `logger.debug("...%s")` on line
            # 505 and the unbounded `self.streams[stream_id] = s` on line 508;
            # under the old key the log_injection match won on line order and
            # the unbounded-growth sink — the real one — was never queued. One
            # attack class and one location per task is the contract, so the
            # class and the line belong in the identity.
            key = (entry.symbol_id, sink_id, sink.line, sink.attack_class,
                   frozenset(target_files))
            if key in seen:
                continue
            seen.add(key)
            tasks.append(
                _emit_task(len(tasks) + 1, graph, inp, entry, sink, path, target_files)
            )
            if len(tasks) >= max_tasks:
                return tasks
    return tasks


def _emit_task(
    n: int,
    graph: "GraphQuery",
    inp: dict,
    entry: Entry,
    sink: Sink,
    path: list[str],
    target_files: list[str],
) -> dict:
    sink_name = _node_label(graph, sink.symbol_id)
    chain = " -> ".join(_node_label(graph, nid) for nid in path)
    iid = inp.get("id") or inp.get("input_id") or "input"
    return {
        "task_id": f"t_taint_{n:02d}",
        "source": "taint",
        "attack_class": sink.attack_class,
        "target_files": target_files,
        "scope_hint": (
            f"{entry.trust_level} input at {entry.file}:{entry.line} reaches "
            f"{sink.attack_class} sink {sink_name}() at {sink.file}:{sink.line} "
            f"via {chain}. Verify every hop for sanitization; if none, exploitable."
        ),
        "rationale": (
            f"Deterministic call-graph path from attacker-controllable input "
            f"{iid} ({entry.file}:{entry.line}) to a {sink.attack_class} sink at "
            f"{sink.file}:{sink.line}. F1 marks this input attacker-controllable; "
            f"this reachable flow is the precondition for a confirmed data-flow finding."
        ),
        "priority": 1,
    }


# ---------------------------------------------------------------------------
# Sink-backward hunting (feature F3) — the BACKWARD complement of V8.
#
# V8 (build_taint_tasks) covers sinks reachable FORWARD from an F1-enumerated
# input. The recall gap is **orphan sinks**: dangerous sinks that NO enumerated
# input reaches (F1 missed the source, or it is subtle). F3 hunts those
# backward — starting AT the sink and tracing through its callers so the Hunter
# can discover the source. Because ``orphans = all_sinks − forward_reached``,
# F3's tasks are disjoint from V8's by construction (never re-emitting a sink V8
# already covered) — pure new coverage. Every task re-enters the normal
# Hunt→Validate loop, so precision stays protected by the adversarial Validate.
#
# Reuses V8 wholesale: ``find_sinks``/``PYTHON_SINKS`` for the sink table,
# ``taint_paths`` to compute which sinks are already forward-reached, and
# ``GraphQuery.callers_within`` (the new backward primitive) for the callers.
# ---------------------------------------------------------------------------
# Cap on caller files listed in one backward task — enough to point the Hunter
# at the reachable surface without an unbounded target_files fan-out.
_MAX_BACKWARD_FILES = 15


def build_sink_backward_tasks(
    graph: "GraphQuery",
    inputs: list[dict],
    repo_path: Path,
    *,
    max_tasks: int = 20,
    max_back_hops: int = 3,
    scope: tuple[str, ...] | None = None,
) -> list[dict]:
    """Emit one backward ``hunt_task`` per **orphan sink symbol** — a dangerous
    sink that NO enumerated input reaches forward. Never raises for
    empty/degenerate input — returns ``[]``.

    Steps (per the F3 brief):
      1. Scan for sinks (``find_sinks``); pick one representative per
         (enclosing symbol, attack class) — first-seen wins.
      2. Resolve F1 entry symbols (``_entry_ids``) and run the forward BFS
         (``taint_paths``) to learn which sink symbols are already reached.
      3. ``orphans = sinks whose symbol is NOT forward-reached`` (disjoint from
         V8 by construction — the correctness property F3 rests on).
      4. For each orphan: gather its backward-reachable callers
         (``callers_within``), map to files, and emit a priority-2
         ``source="sink_backward"`` task naming it an orphan sink.
      Dedup by (symbol, class), cap at ``max_tasks``.
    """
    # 1. sinks — one representative per enclosing symbol (deterministic order).
    sinks = find_sinks(repo_path, graph, scope)
    if not sinks:
        return []
    # One representative per (symbol, attack class) — not per symbol. A
    # function that both logs and grows an unbounded container carries two
    # different dangerous properties, and a task naming only the first is a
    # task about the wrong bug. Deterministic: first line of each class wins.
    sink_by_key: dict[tuple[str, str], Sink] = {}
    for s in sinks:
        sink_by_key.setdefault((s.symbol_id, s.attack_class), s)
    sink_by_symbol: dict[str, Sink] = {}
    for (symbol_id, _cls), s in sink_by_key.items():
        sink_by_symbol.setdefault(symbol_id, s)
    sink_ids = list(sink_by_symbol)

    # 2. which sink symbols are already reached FORWARD from an F1 input.
    #    A sink whose enclosing symbol IS an entry counts as reached: forward
    #    taint now emits a zero-hop task for exactly those (see build_taint_tasks
    #    step 3b), and this set is what keeps the two sources disjoint. Omitting
    #    it would re-queue all 29 of h2's same-symbol sinks here as "orphans" —
    #    duplicating a task already generated, and mislabelling a sink that an
    #    enumerated input demonstrably reaches as one that nothing reaches.
    entry_ids = _entry_ids(graph, inputs)
    reached: set[str] = set()
    if entry_ids:
        reached = {sid for sid, _ in graph.taint_paths(entry_ids, sink_ids, max_hops=8)}
        reached |= set(sink_ids) & set(entry_ids)

    # 3. orphans = all sinks − forward-reached (the disjointness property).
    #    Reachability is a property of the SYMBOL — the BFS walks call edges,
    #    which do not know about lines — but the task is about the sink, so a
    #    symbol that is not reached contributes one orphan per distinct class
    #    it carries rather than one orphan total.
    orphans = [s for (symbol_id, _cls), s in sink_by_key.items()
               if symbol_id not in reached]
    if not orphans:
        return []

    # 4. emit one backward task per orphan sink symbol.
    tasks: list[dict] = []
    for sink in orphans:
        back = graph.callers_within([sink.symbol_id], max_back_hops)
        caller_files = sorted({
            f for f in (_node_file(graph, nid) for nid in back)
            if f and f in graph._by_file and f != sink.file
        })
        target_files = ([sink.file] + caller_files)[:_MAX_BACKWARD_FILES]
        tasks.append(
            _emit_sink_backward_task(len(tasks) + 1, graph, sink, len(back), target_files)
        )
        if len(tasks) >= max_tasks:
            break
    return tasks


def _emit_sink_backward_task(
    n: int,
    graph: "GraphQuery",
    sink: Sink,
    n_callers: int,
    target_files: list[str],
) -> dict:
    sink_name = _node_label(graph, sink.symbol_id)
    return {
        "task_id": f"t_sinkback_{n:02d}",
        "source": "sink_backward",
        "attack_class": sink.attack_class,
        "target_files": target_files,
        "scope_hint": (
            f"Backward audit of {sink.attack_class} sink {sink_name}() at "
            f"{sink.file}:{sink.line}. No enumerated input reaches it — trace "
            f"backward through its callers ({n_callers} functions) to find "
            f"whether ANY reachable path carries attacker-controlled data to "
            f"this sink without sanitization."
        ),
        "rationale": (
            f"Orphan sink: forward input-tracing (V8) reached no enumerated "
            f"input for this {sink.attack_class} sink {sink_name}() at "
            f"{sink.file}:{sink.line}. Hunting it BACKWARD from the sink is "
            f"distinct recall — it catches a dangerous sink whose source F1 "
            f"missed, or that no enumerated input flows to."
        ),
        "priority": 2,
    }
