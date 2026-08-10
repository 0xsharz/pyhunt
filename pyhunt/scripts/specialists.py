"""Gated repo-wide specialist Hunt sweeps (feature V12).

Per-task Hunt tasks (recon/taint/sink-backward/gapfill/feedback) each scope a
single file or a narrow (input -> sink) path. They systematically miss
cross-cutting bug classes that only show up when a specialist reasons across
the WHOLE repo at once: weak cryptography, auth/IDOR logic, unsafe
deserialization, batch/ETL data handling, IaC misconfiguration, and codegen
docstring/comment injection (whose defining question — "is the sanitizer
correct at EVERY call site of this field?" — is unanswerable one file at a
time). V12 adds
one repo-wide Hunt task per such specialist — but ONLY for the specialists
whose surface actually exists in this repo (gated), so Validate budget is
never spent proving a guaranteed false positive (e.g. hunting for weak
crypto in a repo with zero crypto usage).

The specialist *lens* (what the researcher is told to look for) is V9's
``SPECIALIST_HINTS`` / ``hints_for(..., specialist=...)`` in
``audit.lang.hints`` — already built, reused here unchanged; this module
supplies the other half: the *gate* (should this specialist even run here?)
and the *task synthesis* (turn "yes" into a valid hunt_task dict that flows
`specialist=` back into that lens via Hunt's one-line wireup).

The regex gate and ``_scan_any`` are PORTED VERBATIM from VVAH's
``vvaharness/pipeline/stages/s3_decompose.py`` (``_CRYPTO_RX`` L735,
``_DESER_RX`` L743, ``_BATCH_ETL_RX`` L749, ``_scan_any`` L768). The surface
predicates (``_has_authz_surface`` / ``_has_batch_surface``, VVAH L779/L758)
are ADAPTED from VVAH's ``ContextPackage`` to audit's recon_output dict shape
(``schemas/recon_output.schema.json``) plus the F1 attacker-input inventory.

Everything here is STATIC: files are read (utf-8, ``errors="replace"``) but
never executed, and every public entry point is safe to call from the
orchestrator's fail-open wireup — a malformed/partial recon dict (e.g. an
``entry_points`` list of bare strings instead of objects) must degrade to
"no signal", never raise.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable, Sequence

from lang_hints import SPECIALIST_HINTS, is_iac_file

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ported verbatim from VVAH s3_decompose.py (_CRYPTO_RX L735, _DESER_RX L743,
# _BATCH_ETL_RX L749).
# ---------------------------------------------------------------------------

_CRYPTO_RX = re.compile(
    r"\b(AES|RSA|HMAC|SHA-?(1|2|256|384|512)|MD5|PBKDF2|bcrypt|scrypt|argon2"
    r"|Cipher|KeyPair|SecretKey|X509|PKCS|TLS|SSLContext|jwt|jose|nacl|sodium"
    r"|hashlib|hmac\.|cryptography\.|javax\.crypto|BouncyCastle|OpenSSL"
    r"|Crypt::|Digest::|Mcrypt|RandomNumberGenerator|SecureRandom)\b",
    re.IGNORECASE,
)

_DESER_RX = re.compile(
    r"\b(ObjectInputStream|readObject|XMLDecoder|XStream|SnakeYAML|yaml\.load"
    r"|pickle\.|marshal\.load|unserialize|BinaryFormatter|Kryo|Hessian"
    r"|JdkSerializationRedisSerializer|Marshal\.load)\b",
)

# AUTHORED supplement to VVAH's _DESER_RX above (left byte-for-byte intact:
# it is a donor artifact). VVAH is JVM-first, so a Python target whose only
# deserializer is `joblib.load` / `pandas.read_pickle` / `torch.load` /
# `dill` / `jsonpickle` gated the specialist OFF entirely.
_DESER_PY_RX = re.compile(
    r"\b(?:joblib\.load|read_pickle|torch\.load|dill\.loads?|jsonpickle\."
    r"(?:decode|loads)|shelve\.open|yaml\.(?:unsafe_load|full_load)|"
    r"allow_pickle\s*=\s*True|weights_only\s*=\s*False|pydoc\.locate|"
    r"importlib\.import_module)\b",
)

# AUTHORED. Both regexes above ask "does this repo reconstruct an object graph
# from bytes the way pickle does". That is one deserialisation family, and the
# tables knew only it — so on `dataclasses-avroschema`, a library whose entire
# documented purpose is turning avro payloads into Python objects, the gate
# reported "no JVM-style or Python-style deserializer in source" and switched
# the lens OFF.
#
# What it was blind to is SCHEMA-DRIVEN BINARY deserialisation: avro, msgpack,
# protobuf, thrift, CBOR, BSON, and the dict→dataclass mappers (dacite,
# pydantic's parse/validate, marshmallow, cattrs, attrs) that usually sit
# behind them. The bug class is different from pickle's — there is no gadget
# chain, because the format cannot name a callable — but it is not smaller:
# schema-controlled recursion depth, unbounded field counts, union resolution
# by attacker-chosen name, and precision/size fields that drive allocation are
# all reachable from bytes.
#
# The class file needs to know this too: `phase2_class_deser.md` says plainly
# that the pickle-shaped questions ("what can the payload import?") do not
# transfer, and gives the schema-driven questions instead.
_DESER_SCHEMA_RX = re.compile(
    r"\b(?:fastavro|avro_schema|schemaless_reader|schemaless_writer|"
    r"msgpack\.(?:unpack|loads?)b?|msgpack\.Unpacker|cbor2?\.loads?|"
    r"bson\.(?:loads|BSON|decode)|ParseFromString|MessageToDict|"
    r"thrift|TBinaryProtocol|"
    r"dacite\.from_dict|from_dict\s*\(|"
    r"parse_obj\s*\(|parse_raw\s*\(|model_validate(?:_json)?\s*\(|"
    r"marshmallow|cattrs|structure\s*\(|"
    r"avro\.(?:io|schema)|DatumReader|BinaryDecoder)\b",
)

# AUTHORED — resource-exhaustion surface. The lens that would have caught the
# `.fake()` misses: a size/precision/depth field read out of untrusted input and
# handed to something that allocates or recurses. Deliberately broad; the cost
# of over-firing is one sweep.
_RESOURCE_RX = re.compile(
    r"\b(?:max_digits|precision|scale|size|length|count|depth|limit|repeat|"
    r"n_items|num_\w+)\b\s*(?:=|:)|"
    r"\brange\s*\(\s*(?:\w+\[[^\]]+\]|\w+\.\w+|int\s*\()|"
    r"\b(?:os\.urandom|secrets\.token_bytes|bytes|bytearray|\[\s*0\s*\]\s*\*)\s*\(?\s*\w+|"
    r"\brecursion|\bsetrecursionlimit|\bwhile\s+True\b",
    re.IGNORECASE,
)

_BATCH_ETL_RX = re.compile(
    r"\b(struct\.(?:un)?pack|codecs\.(?:encode|decode)\([^)]*ebcdic"
    r"|cp037|cp1047|COMP-3|packed[_-]?decimal|RECFM|LRECL"
    r"|glob\.glob|os\.listdir|shutil\.(?:move|copy)|csv\.(?:writer|reader)"
    r"|EXEC\s+PGM=|//\w+\s+DD\b|DISP=\()\b",
    re.IGNORECASE,
)



# ---------------------------------------------------------------------------
# AUTHORED (not from a donor) — codegen surface. A tool that writes source code
# from an untrusted schema is the surface for docstring/comment-terminator
# injection (CWE-94): the generated file's string literal is closed early by
# attacker text and the remainder becomes code the VICTIM executes on import.
# Two halves, both needed: the repo emits generated text (writer signature),
# and it reads free-text schema fields (source signature).
# ---------------------------------------------------------------------------

# A template whose name carries a code extension before the template one
# (`endpoint_module.py.jinja`, `model.ts.j2`) is unambiguous proof of source
# emission — openapi-python-client and datamodel-code-generator both ship these.
_CODE_TEMPLATE_NAME_RX = re.compile(
    r"\.(?:py|pyi|ts|tsx|js|jsx|java|go|cs|rb|php|kt|swift|scala|rs|sql)"
    r"\.(?:jinja2?|j2|mustache|hbs|tmpl|template|mako|tpl)$",
    re.IGNORECASE,
)

_TEMPLATE_EXT_RX = re.compile(r"\.(?:jinja2?|j2|mustache|hbs|tmpl|mako|tpl)$",
                              re.IGNORECASE)

# ...but xsdata's emitters are plain `class.jinja2` / `docstrings.google.jinja2`,
# so the name alone is not enough. A template whose CONTENT is source code
# (a docstring delimiter, a def/class/import/func line) emits source code
# whatever it is called. A chart/HTML/JSON template does not match.
_EMITS_CODE_RX = re.compile(
    r"\"\"\"|'''|^\s*(?:class|def|import|from|func|package|public\s+class|"
    r"interface|@dataclass)\b",
    re.MULTILINE,
)

# An HTML page with an inline <script> contains `class Foo {` and would pass
# _EMITS_CODE_RX, but its output is a web page, not a source file — a different
# bug class (XSS), owned by a different lens. Templates that look like markup
# are excluded before the code test runs.
_MARKUP_TEMPLATE_RX = re.compile(
    r"<!DOCTYPE\s+html|<html\b|<head\b|<body\b|<script\b|<div\b|<svg\b",
    re.IGNORECASE,
)

# Third route: no template engine at all — the source is built and unparsed or
# formatted in Python. Reaching for a code formatter is itself the proof.
_CODE_EMITTER_RX = re.compile(
    r"\bast\.unparse\s*\(|\bastor\.to_source\s*\(|\bblack\.format_str\s*\(|"
    r"\bisort\.code\s*\(|\bautopep8\.fix_code\s*\(",
)

# Fourth route, and the one this gate was missing. A generator with no template
# FILES and no formatter at all: the templates are `string.Template` (or %-format,
# or f-string) constants living inside an ordinary `.py` module.
#
# This is not hypothetical. Measured on dataclasses-avroschema 0.70.2, whose
# `model_generator/lang/python/templates.py` holds
#
#     CLASS_TEMPLATE = """
#     $decorator
#     class $name($base_class):$docstring
#         $fields
#     """
#     METACLASS_SCHEMA_FIELD = '$name = """$schema"""'
#
# and whose `base.py` reads `self.schema.get("doc")` straight into them. Both
# halves of the gate are plainly satisfied and the gate fired OFF, because
# route 1 found no `*.jinja` files and route 3 found no formatter. Thirty
# distinct codegen-injection sites were then found by other lenses reaching the
# same files by accident. A repo with a weaker call graph would have lost them.
#
# The signature is precise rather than "the file mentions Template": a source
# line that opens a def/class/import/decorator AND carries a substitution
# placeholder is code being assembled, and essentially nothing else looks like
# that.
_CODE_STRING_TEMPLATE_RX = re.compile(
    r"(?m)^[ \t]*(?:class|def|async\s+def|import|from|@)\s+[^\n]*"
    r"(?:\$\{?\w+|\{\w*\}|%\(\w+\)s|%s)",
)

#: The substitution machinery, checked in the same file as the code-shaped
#: template above. Present without it, a repo that merely uses `%s` in a log
#: message would match.
_TEMPLATE_ENGINE_RX = re.compile(
    r"\bstring\.Template\s*\(|\bTemplate\s*\(|\.safe_substitute\s*\(|"
    r"\.substitute\s*\(|\.format_map\s*\(",
)

# Free-text schema fields — the untrusted text that lands in the emitted
# literal. `help` is xsdata's name for it; protobuf uses *_comments.
_CODEGEN_SOURCE_RX = re.compile(
    r"\.get\s*\(\s*[\"'](?:doc|description|comment|summary|help|documentation)[\"']\s*\)|"
    r"\.(?:description|comment|summary|docstring|documentation)\b|"
    r"\b(?:obj|attr|field|prop|model|schema|item)\.help\b|"
    r"\b(?:leading|trailing|leading_detached)_comments\b",
)


def _scan_any(repo_root: Path, files: list[str], rx: re.Pattern) -> bool:
    """True as soon as `rx` matches inside any file (statically read, utf-8,
    errors="replace"). Never raises — an unreadable file is just skipped."""
    for rel in files:
        p = repo_root / rel
        try:
            if rx.search(p.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


# ---------------------------------------------------------------------------
# Surface predicates — ADAPTED from VVAH's ContextPackage to audit's
# recon_output dict (schemas/recon_output.schema.json) + the F1 inputs list
# (db.get_inputs). Defensive against partially-shaped recon dicts (e.g. a
# lenient/stubbed recon whose entry_points are bare strings, not objects) —
# a gate must never raise, only under- or over-fire.
# ---------------------------------------------------------------------------

_AUTHZ_ENTRY_KINDS = {"http_route", "rpc", "grpc", "webhook"}
_AUTHZ_CONTROLLABLE_BY = {"anonymous_user", "authenticated_user"}
_AUTHZ_TRUST_LEVELS = {"unauthenticated", "authenticated"}
_BATCH_ENTRY_KINDS = {"cli", "file_input"}


def _has_authz_surface(recon: dict | None, inputs: list[dict] | None) -> bool:
    """True if this repo has ANY externally-reachable or authenticated
    surface — the precondition for access-control (IDOR / privilege
    escalation) findings to be possible at all.

    True when: an entry_point's kind is in {http_route, rpc, grpc, webhook};
    OR an entry_point declares `auth_required` (either value — its mere
    presence means an authorization decision exists to get wrong); OR an
    external_input's controllable_by is {anonymous_user, authenticated_user};
    OR any trust_boundary is declared; OR an F1 input's trust_level is
    {unauthenticated, authenticated}.
    """
    arch = (recon or {}).get("architecture") or {}
    for ep in arch.get("entry_points") or []:
        if not isinstance(ep, dict):
            continue
        if ep.get("kind") in _AUTHZ_ENTRY_KINDS:
            return True
        if "auth_required" in ep:
            return True
    for ei in arch.get("external_inputs") or []:
        if isinstance(ei, dict) and ei.get("controllable_by") in _AUTHZ_CONTROLLABLE_BY:
            return True
    if arch.get("trust_boundaries"):
        return True
    for inp in inputs or []:
        if isinstance(inp, dict) and inp.get("trust_level") in _AUTHZ_TRUST_LEVELS:
            return True
    return False


def _has_batch_surface(recon: dict | None, repo_root: Path, source: list[str]) -> bool:
    """True if this repo has a batch/file/CLI processing surface: an
    entry_point of kind {cli, file_input}, OR the source matches a batch/ETL
    signature (struct.pack, EBCDIC codecs, glob/listdir, csv, mainframe JCL DD
    statements, ...)."""
    arch = (recon or {}).get("architecture") or {}
    for ep in arch.get("entry_points") or []:
        if isinstance(ep, dict) and ep.get("kind") in _BATCH_ENTRY_KINDS:
            return True
    return _scan_any(repo_root, source, _BATCH_ETL_RX)


def _emits_source_code(repo_root: Path, files: list[str]) -> bool:
    """True if this repo EMITS SOURCE CODE (as opposed to HTML, JSON, or a
    chart). Four independent proofs, any one suffices: a template named for
    the code extension it produces; a template whose body IS source code;
    Python that unparses/formats generated source; or a `.py` module holding
    code-shaped string templates and the machinery to substitute into them.

    Deliberately NOT proof: `.write_text(`, `open(..., "w")`, importing
    jinja2, or the word "generator". Every one of those is ubiquitous in
    repos that generate nothing — checking them is the proxy mistake this
    project keeps making (CLAUDE.md, "check a proxy, assume the real thing").
    """
    templates = [f for f in files if _TEMPLATE_EXT_RX.search(f)]
    if any(_CODE_TEMPLATE_NAME_RX.search(f) for f in templates):
        return True
    for rel in templates:
        try:
            body = (repo_root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _MARKUP_TEMPLATE_RX.search(body):
            continue  # renders a web page, not a source file
        if _EMITS_CODE_RX.search(body):
            return True
    if _scan_any(repo_root, files, _CODE_EMITTER_RX):
        return True
    return _has_inline_code_templates(repo_root, files)


def _has_inline_code_templates(repo_root: Path, files: list[str]) -> bool:
    """A `.py` module that both defines a code-shaped template and substitutes.

    Both signals must appear in the SAME file. Checking them repo-wide would
    fire on any project that has a `%s` in a log line and a `.format()`
    somewhere else, which is every project.
    """
    for rel in files:
        if not rel.endswith(".py"):
            continue
        try:
            body = (repo_root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _MARKUP_TEMPLATE_RX.search(body):
            continue
        if _CODE_STRING_TEMPLATE_RX.search(body) and _TEMPLATE_ENGINE_RX.search(body):
            return True
    return False


def _has_codegen_surface(repo_root: Path, files: list[str]) -> bool:
    """True if this repo generates source code from schema-like input.

    Requires BOTH halves, so a repo that renders HTML/charts (emits, but no
    schema free-text) and a repo that parses a schema but emits nothing are
    both gated OFF.

    Measured on the bench targets: fires on openapi-python-client, both
    datamodel-code-generator trees, and xsdata (all four have a real instance
    of this class); silent on data360-mcp, datalibweb, swagger-ts-api,
    vulnerable-code-snippets. KNOWN over-fire: a repo carrying Alembic's
    `alembic/script.py.mako` passes the emitter half honestly — it does
    generate Python — and any unrelated `.description` read satisfies the
    other. Deciding that `${message}` comes from the developer's `-m` flag
    rather than a schema needs dataflow, which a cheap regex gate does not do.
    The cost is one extra sweep, and this gate is deliberately biased that way:
    over-firing spends a hunt task, under-firing loses the bug.
    """
    return (_emits_source_code(repo_root, files)
            and _scan_any(repo_root, files, _CODEGEN_SOURCE_RX))


# ---------------------------------------------------------------------------
# Gating — one predicate per SPECIALIST_HINTS key. `logic-bug` is
# cross-cutting behavioural/state-machine reasoning with no file signature
# (VVAH has no gate for it either), so it is always on; every other
# specialist is dropped unless its surface predicate is true, so Validate
# budget is never spent proving a guaranteed false positive.
# ---------------------------------------------------------------------------


def active_specialists(
    recon: dict | None,
    inputs: list[dict] | None,
    repo_root: Path,
    source_files: list[str],
) -> list[str]:
    """Return the SPECIALIST_HINTS keys whose surface actually exists in this
    repo. Gated-OFF specialists are logged (mirrors VVAH's s3 message) and
    dropped. Never raises."""
    gates: dict[str, Callable[[], bool]] = {
        "crypto": lambda: _scan_any(repo_root, source_files, _CRYPTO_RX),
        "logic-bug": lambda: True,
        "access-control": lambda: _has_authz_surface(recon, inputs),
        "deserialization": lambda: (_scan_any(repo_root, source_files, _DESER_RX)
                                    or _scan_any(repo_root, source_files, _DESER_PY_RX)
                                    or _scan_any(repo_root, source_files, _DESER_SCHEMA_RX)),
        "batch-etl": lambda: _has_batch_surface(recon, repo_root, source_files),
        "iac": lambda: any(is_iac_file(f) for f in source_files),
        "codegen": lambda: _has_codegen_surface(repo_root, source_files),
        "resource": lambda: _scan_any(repo_root, source_files, _RESOURCE_RX),
    }
    kept: list[str] = []
    for name in SPECIALIST_HINTS:  # default enabled = every known specialist
        gate = gates.get(name)
        if gate is None or gate():
            kept.append(name)
        else:
            log.info("specialist '%s' gated OFF — no matching surface in repo", name)
    return kept


# ---------------------------------------------------------------------------
# Task synthesis — one repo-wide hunt_task per active specialist.
# ---------------------------------------------------------------------------

_ATTACK_CLASS: dict[str, str] = {
    "crypto": "weak_crypto",
    "logic-bug": "logic_error",
    "access-control": "auth_bypass",
    "deserialization": "deserialization",
    "batch-etl": "improper_input_handling",
    "iac": "security_misconfiguration",
    "codegen": "codegen_injection",
    "resource": "resource_exhaustion",
}

_FOCUS: dict[str, str] = {
    "crypto": "Weak cryptography, key handling, and protocol-negotiation flaws",
    "logic-bug": "Behavioural / state-machine defects that cross a trust boundary",
    "access-control": "IDOR, missing authorization checks, and privilege escalation",
    "deserialization": "Unsafe deserialization of attacker-influenced bytes",
    "batch-etl": "Unsafe batch/ETL file, encoding, and bulk-data handling",
    "iac": "Infrastructure-as-code and CI/CD misconfiguration",
    "codegen": (
        "Unescaped untrusted schema text written into the source code this "
        "tool generates — docstring/comment terminator breakout (CWE-94)"
    ),
    "resource": (
        "Attacker-chosen size, depth, precision and count fields driving "
        "unbounded allocation, recursion or superlinear work (CWE-400/CWE-770)"
    ),
}


#: Path substrings that make a file interesting to one lens. Cheap, and cheap
#: is the point: this runs over every source path in the repository and must
#: not open any of them.
_LENS_SIGNALS: dict[str, tuple[str, ...]] = {
    "codegen": (
        "template", "jinja", ".j2", "/model", "render", "generate", "codegen",
        "emit", "writer", "scaffold", "stub", "printer", "formatter",
    ),
    # Deliberately narrow. A bare "key" matched `field_extra_keys.py` and
    # filled the crypto lens with test fixtures, so the tokens here have to be
    # ones that only appear in cryptographic code.
    "crypto": (
        "crypt", "cipher", "hash", "digest", "hmac", "keystore", "keyring",
        "keypair", "privkey", "pubkey", "jwt", "jose", "tls", "ssl", "x509",
        "cert", "password", "passwd", "secret", "signing", "signature",
        "nonce", "entropy", "random",
    ),
    "deserialization": (
        "pickle", "yaml", "marshal", "serial", "deserial", "unpack", "decode",
        "parse", "loader", "json", "msgpack", "protobuf", "avro", "shelve",
    ),
    "batch-etl": (
        "etl", "batch", "csv", "ingest", "import", "export", "bulk", "feed",
        "pipeline", "loader", "migrat", "sync", "upload", "download",
    ),
    "iac": (
        ".tf", ".hcl", ".bicep", "dockerfile", "docker-compose", "/.github/",
        "workflow", "k8s", "kubernetes", "helm", "chart", "ansible",
        "terraform", "deploy", "infra", ".yaml", ".yml",
    ),
    "logic-bug": (
        "state", "workflow", "transition", "order", "handler", "service",
        "manager", "controller", "process", "resolve", "validat", "rule",
    ),
    "access-control": (
        "auth", "permission", "role", "acl", "policy", "login", "session",
        "tenant", "owner", "admin", "guard", "middleware",
    ),
    # `fake`, `factory` and `sample` are in here deliberately. A sweep once
    # cleared the entire `.fake()` surface of a library with the reasoning
    # "these methods' entire job is synthetic test data" — correct for the
    # question that sweep was asking (weak randomness) and wrong for the one it
    # was not (a schema-supplied `size` driving an unbounded allocation). Two
    # real findings were lost to that. A file cleared under one lens must still
    # be visible to the others.
    "resource": (
        "field", "type", "parse", "decode", "deserial", "render", "generat",
        "recurs", "walk", "expand", "resolve", "fake", "factory", "sample",
        "buffer", "reader", "writer", "stream", "chunk",
    ),
}


def rank_files_for_lens(name: str, source_files: Sequence[str]) -> list[str]:
    """`source_files` reordered so the ones this lens cares about come first.

    **Every specialist used to receive the same list** — ``source_files`` sliced
    to the first N, which is alphabetical order. On a real repository that
    handed the codegen lens twelve GitHub Actions workflows and no templates,
    while the templates that actually carried a code-injection defect sat far
    down the alphabet and were never in scope. Six lenses were each given an
    identical, arbitrary 2.5% of the repository and asked to find different
    things in it.

    Ranking is by path substring only — no file is opened — and it is a stable
    sort, so files a lens has no opinion about keep their original order and
    still get swept once the interesting ones are exhausted. A lens with no
    signal table falls back to the previous behaviour exactly.
    """
    signals = _LENS_SIGNALS.get(name)
    if not signals:
        return list(source_files)

    def score(path: str) -> int:
        low = path.lower()
        return -sum(1 for token in signals if token in low)

    return sorted(source_files, key=score)


def build_specialist_tasks(
    active: list[str],
    source_files: list[str],
    repo_root: Path,
    *,
    max_files: int = 40,
) -> list[dict]:
    """One `hunt_task` dict per active specialist, scoped to (at most)
    `max_files` repo files, **ranked for that lens** by
    :func:`rank_files_for_lens`. `repo_root` is accepted for interface symmetry
    with `active_specialists`. A specialist with no source files is skipped (the
    schema requires >=1 target_files) rather than emitted empty."""
    tasks: list[dict] = []
    for name in active:
        target_files = rank_files_for_lens(name, source_files)[:max_files]
        if not target_files:
            log.info("specialist '%s' skipped — no source files to scope", name)
            continue
        tasks.append({
            "task_id": f"t_spec_{name.replace('-', '_')}",
            "source": "specialist",
            "specialist": name,
            "attack_class": _ATTACK_CLASS[name],
            "scope_hint": (
                f"Repo-wide {name} specialist sweep. {_FOCUS[name]}. "
                f"Hunt this lens across the listed files."
            ),
            "target_files": target_files,
            "rationale": (
                f"Specialist '{name}' passed its surface gate — this repo has "
                f"matching indicators, so a repo-wide {name} sweep is worth "
                f"Validate budget instead of a guaranteed false positive."
            ),
            "priority": 3,
        })
    return tasks
