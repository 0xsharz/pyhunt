"""Dict-dispatch call edges — the ones an AST call graph structurally cannot see.

An AST extractor draws a ``calls`` edge when it sees a call whose callee it can
name. It cannot name the callee of::

    self._frame_dispatch_table[frame.__class__](frame)

because the callee is a *value in a dict*, chosen at run time. The extractor
sees a subscript and a call on its result, and emits nothing. Every method the
table points at therefore has **zero** in-edges from the dispatcher, and the
whole layer looks unreachable from the entry point that actually drives it.

This is not a corner case. Dict-of-callables is the dominant Python idiom for
protocol frame handling, opcode interpretation, message routing and state
machines — precisely the code where "what can a hostile peer reach?" is the
whole question. On ``python-hyper/h2`` the table at ``connection.py`` maps
twelve frame classes to twelve ``_receive_*_frame`` methods; without these
edges, ``H2Connection.receive_data`` — the library's *sole* attacker-byte entry
point — reaches nothing, forward taint produces one path in an example script,
and the entire frame-handling surface is queued only by whole-file sweeps.

So this module recovers the edges statically, by AST, and never by execution:

1. Find dict literals bound to a stable name — ``self.<attr> = {...}`` or a
   module/class-level ``NAME = {...}`` — whose *values* are callables referred
   to by name (``self.<method>`` or a bare function ``name``).
2. Find every function that reads that table by subscript (``t[k]``) or
   ``t.get(k)``.
3. Draw a ``calls`` edge from the reader to each callable in the table.

Step 2 is deliberately satisfied by *reading* the table, not only by calling
the subscript result inline. ``handler = self._table[k]`` followed by
``handler(x)`` — often several lines later, or behind a ``None`` check — is the
same dispatch, and demanding the ``Call(Subscript(...))`` shape would miss it.
A function that reads a dispatch table and does not call what it found is rare;
a spurious edge costs one over-broad hunt path, while a missing one costs the
entire handler layer. The asymmetry decides the design.

Bounded by construction: edges are only ever drawn between symbols that already
exist as nodes in the graph, only for tables whose values are all name-resolvable
callables, and only for tables with at least two entries (a one-entry "table" is
not dispatch). Nothing here parses a file the graph does not already know about,
and no target code is imported or executed — ``ast.parse`` only.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from .schema import Edge, GraphDocument

log = logging.getLogger(__name__)

#: A dict with one entry is a special case, not a dispatch table. Requiring two
#: keeps `self.handlers = {"x": self.do_x}` from generating an edge that the
#: extractor would usually have drawn anyway.
_MIN_TABLE_ENTRIES = 2

#: Hard ceiling on synthesized edges per repository. A pathological generated
#: file with a thousand-entry table read from a hundred functions would
#: otherwise add 100k edges and turn the BFS into the bottleneck. Reaching this
#: is reported, never silent.
_MAX_EDGES = 5000


def _callable_name(node: ast.AST) -> str | None:
    """The referenced callable's *name*, for a dict value that is a plain
    reference. ``self.foo`` -> ``foo``; ``foo`` -> ``foo``; anything with a
    call, subscript, lambda or literal in it -> None (not a name reference)."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        # self.foo / cls.foo — the receiver must be a bare name, so that
        # `a.b.foo` (a different module's symbol) does not resolve locally.
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _table_name(target: ast.AST) -> str | None:
    """The stable name a dict literal is bound to, or None if it isn't one.

    ``self._frame_dispatch_table`` -> ``self._frame_dispatch_table``
    ``DISPATCH``                   -> ``DISPATCH``
    """
    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
        return f"{target.value.id}.{target.attr}"
    if isinstance(target, ast.Name):
        return target.id
    return None


def _collect_tables(tree: ast.AST) -> dict[str, list[str]]:
    """Map ``table name -> [callable names it dispatches to]`` for this module.

    A name assigned more than once is dropped entirely rather than merged: two
    different tables under one name means we cannot say which one a given
    reader sees, and inventing edges for both is exactly the "confident wrong
    edge" the reachability gate exists to prevent.
    """
    tables: dict[str, list[str]] = {}
    conflicted: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        else:
            continue

        if not isinstance(value, ast.Dict):
            continue

        names: list[str] = []
        for item in value.values:
            got = _callable_name(item)
            if got is None:
                names = []
                break
            names.append(got)
        if len(names) < _MIN_TABLE_ENTRIES:
            continue

        for target in targets:
            key = _table_name(target)
            if key is None:
                continue
            if key in tables and tables[key] != names:
                conflicted.add(key)
            tables[key] = names

    for key in conflicted:
        tables.pop(key, None)
    return tables


def _reads_table(func: ast.AST, table_names: set[str]) -> set[str]:
    """Names of the dispatch tables this function body reads."""
    seen: set[str] = set()
    for node in ast.walk(func):
        base: ast.AST | None = None
        if isinstance(node, ast.Subscript):
            base = node.value
        elif (isinstance(node, ast.Call)
              and isinstance(node.func, ast.Attribute)
              and node.func.attr in ("get", "pop")):
            base = node.func.value
        if base is None:
            continue
        name = _table_name(base)
        if name in table_names:
            seen.add(name)  # type: ignore[arg-type]
    return seen


def _bare_name(label: str) -> str:
    """The plain identifier inside a graph node's display name.

    graphify labels a method ``._receive_headers_frame`` — leading dot, because
    the label is built as ``<owner>.<attr>`` and the owner is elided. Matching a
    dispatch value (``_receive_headers_frame``, an AST identifier) against that
    label verbatim fails for every method in every table, which is a silent
    total loss: the pass reports success and adds zero edges. Normalizing both
    sides to the bare identifier is what makes the lookup work at all.
    """
    return label.rpartition(".")[2] or label


class _FileIndex:
    """Closest-preceding-definition lookup over one file's graph nodes, plus a
    name -> node id map for resolving a dispatch target to its definition."""

    def __init__(self, doc: GraphDocument, rel_file: str) -> None:
        self._by_line: list[tuple[int, str]] = []
        self._by_name: dict[str, list[str]] = {}
        for nid, node in doc.nodes.items():
            if node.file != rel_file:
                continue
            self._by_line.append((node.line, nid))
            self._by_name.setdefault(_bare_name(node.name), []).append(nid)
        self._by_line.sort()

    def symbol_at(self, line: int) -> str | None:
        found: str | None = None
        for defline, nid in self._by_line:
            if defline <= line:
                found = nid
            else:
                break
        return found

    def unique_symbol_named(self, name: str) -> str | None:
        """The node id for `name` in this file, only when it is unambiguous.

        Two same-named methods in one file (two classes each with `handle`)
        make the target unresolvable from a bare name, and guessing would draw
        an edge into the wrong class.
        """
        hits = self._by_name.get(name) or []
        return hits[0] if len(hits) == 1 else None


def dispatch_edges(root: Path, doc: GraphDocument) -> tuple[list[Edge], list[str]]:
    """Synthesize ``calls`` edges for dict-dispatch tables.

    Returns ``(edges, notes)``. Never raises: a file that will not parse, or a
    table that cannot be resolved, contributes nothing and the rest proceed. A
    graph missing these edges is degraded; a graph that fails to build is worse.
    """
    edges: list[Edge] = []
    notes: list[str] = []
    existing = {(e.src, e.dst) for e in doc.edges if e.kind == "calls"}

    files = sorted({n.file for n in doc.nodes.values()
                    if isinstance(n.file, str) and n.file.endswith(".py")})

    for rel_file in files:
        path = Path(root) / rel_file
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                             filename=rel_file)
        except (OSError, SyntaxError, ValueError, RecursionError):
            continue

        tables = _collect_tables(tree)
        if not tables:
            continue

        index = _FileIndex(doc, rel_file)
        table_names = set(tables)

        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            read = _reads_table(func, table_names)
            if not read:
                continue
            src = index.symbol_at(func.lineno)
            if src is None:
                continue
            for table in sorted(read):
                for callee in tables[table]:
                    dst = index.unique_symbol_named(callee)
                    if dst is None or dst == src:
                        continue
                    if (src, dst) in existing:
                        continue
                    existing.add((src, dst))
                    edges.append(Edge(src=src, dst=dst, kind="calls"))
                    if len(edges) >= _MAX_EDGES:
                        notes.append(
                            f"dispatch: hit the {_MAX_EDGES}-edge cap; later "
                            f"dispatch tables were not expanded",
                        )
                        return edges, notes
    return edges, notes


def augment(root: Path, doc: GraphDocument) -> int:
    """Add dict-dispatch ``calls`` edges to `doc` in place. Returns the count.

    Idempotent: an edge already present (drawn by the extractor, or by a
    previous call) is never duplicated, so this is safe to run against a graph
    loaded from cache as well as a freshly built one.
    """
    try:
        edges, notes = dispatch_edges(Path(root), doc)
    except Exception as exc:  # fail-open: the graph without these beats no graph
        log.warning("graph.dispatch: edge synthesis failed (continuing): %r", exc)
        return 0
    for note in notes:
        log.warning("graph.dispatch: %s", note)
    if edges:
        doc.edges.extend(edges)
        log.info("graph.dispatch: added %d dict-dispatch calls edge(s)", len(edges))
    return len(edges)
