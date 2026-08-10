"""Deterministic input-surface enumeration for phase 1 (W6.1, closes D6).

`phase1_recon.md` mandates a **Read/Grep/Glob, no Bash** envelope for the recon
agent, and devotes a section to why: recon reads the most attacker-authored
content in the entire run — README prose, comments, docstrings, filenames — so
the agent that reads it should not be able to execute anything. In the recorded
run the harness could not supply Grep or Glob, the agent delegated the
enumeration to a nested Bash subagent, and the property the phase file argues
for was simply not held. That is defect D6.

Arguing harder in the prompt does not fix it. Removing the *need* for the tools
does. This module does the mechanical part of Steps 2 and 3 — the file
inventory, the extension census, the framework detection, and the entry-point
candidate grep — deterministically, before the agent is dispatched. What is
left for the agent is the part that actually needs judgement: opening each
candidate, deciding what the inputs *are*, and assigning trust levels from
audited code. That needs `Read` and nothing else, and `Read` the harness can
supply.

Three consequences, in the order they matter:

1. **Recall.** A regex sweep does not get bored, does not run low on context at
   file 300, and does not quietly decide that the eleventh CLI flag is like the
   other ten. The recorded run's inventory was model-derived and its sweep later
   found entry points the inventory had missed; that gap is attributed to this
   step.
2. **Reproducibility.** Two scans of the same commit now start from a
   byte-identical candidate set, which is the precondition for attributing any
   later difference to anything else.
3. **Blast radius.** The recon agent loses Bash and Grep for real, not on paper.

**Nothing here is excluded on the grounds of being a test.** The phase file used
to say "exclude `**/tests/**`", and the recorded run found real, severe issues
in exactly that territory — a `publish.yaml` tag trigger among them. Dropping a
file shrinks the denominator invisibly, which is the one failure mode this whole
pipeline is built to prevent. Every source file is enumerated and tagged with a
`reachable_from` tier instead, so a reader can sort by reachability while the
scan still covers everything. Vendored and generated trees are the sole
exception, and each exclusion is recorded with the rule that caused it.

**Hostile input, throughout.** Every path, matched line, and dependency name in
this repository is written by whoever wrote the repository, and all of it flows
into JSON that a model later reads. Matched text goes through `_sanitize()` —
control characters stripped, whitespace collapsed, hard length cap — and is
never interpolated into a command, a shell string, or a regex. No file is
executed, imported, or parsed by anything but `ast` and `re`. Manifests are read
as text; `pyproject.toml` is *not* handed to a TOML parser that could be steered
by a crafted document, because the only fields needed are dependency names.

**Failure is data.** An unreadable file, a binary blob, a decoding error, a file
that trips a bound — each produces a recorded entry with a `status` and a
`reason`, never an exception and never a silent skip. A truncated enumeration
says so, so a bounded inventory can never be mistaken for a complete one.

Contract (see the skill's script conventions):

    python3 scripts/recon_enumerate.py enumerate --repo PATH
        [--results-dir DIR] [--max-files N] [--max-hits-per-category N]
        [--max-file-bytes N] [--include-excluded]

JSON to stdout; human notes to stderr; exit 0 normally, 2 on a contract
violation the skill must not route around, 1 on an internal error.
"""

from __future__ import annotations

# NOTE: stdlib + sibling scripts only — no third-party import, hence no
# `import _bootstrap`. `lang_hints` is a sibling in scripts/, which is
# sys.path[0] when this file is run directly.
import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from lang_hints import EXT_TO_LANG

SCHEMA_ID = "pyhunt.recon_enumeration/1"

# ---------------------------------------------------------------------------
# Bounds. Every one of these is a place a pathological repository could turn
# recon into an unbounded job. Hitting one is recorded in the output, never
# swallowed — see `truncated` in the payload.
# ---------------------------------------------------------------------------
DEFAULT_MAX_FILES = 20_000          # files walked before the inventory truncates
DEFAULT_MAX_HITS_PER_CATEGORY = 400  # candidate rows kept per source category
DEFAULT_MAX_FILE_BYTES = 2_000_000   # per-file read cap; larger files are noted
DEFAULT_MAX_LINE_CHARS = 4_000       # a "line" longer than this is minified data
SANITIZE_LIMIT = 240                 # cap on any single quoted fragment

# ---------------------------------------------------------------------------
# Trees that are genuinely not this project's code. This is the ONLY reason a
# source file is dropped from the inventory, and every drop is recorded with the
# rule that caused it. Tests, examples, CI and scripts are NOT here — they are
# tagged by `reachable_from` and enumerated like everything else.
# ---------------------------------------------------------------------------
_VENDOR_DIR_PARTS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    ".nox", ".eggs", "site-packages", "dist-packages", "vendor", "third_party",
    "thirdparty", "bower_components", ".idea", ".vscode",
})

_VENDOR_SUFFIX_PARTS = (".egg-info", ".dist-info")

# Generated code, by name. A generated file is still enumerated when it is
# checked in and imported — this list is only for artefacts no one edits.
_GENERATED_NAME_RX = re.compile(
    r"(?:_pb2(?:_grpc)?\.py|\.min\.js|\.min\.css|\.map)$", re.I)

# ---------------------------------------------------------------------------
# Reachability tiers. Feeds `reachable_from` on every finding (W5.2) and lets a
# reader sort by urgency WITHOUT anything being dropped from the scan. Order
# matters: the first rule that matches wins, and `public_api` is last precisely
# because it is the fallback for ordinary library code.
# ---------------------------------------------------------------------------
_TIER_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ci", re.compile(
        r"(?:^|/)(?:\.github/|\.gitlab-ci|\.circleci/|\.travis|azure-pipelines"
        r"|Jenkinsfile|\.buildkite/|\.woodpecker)", re.I)),
    ("test", re.compile(
        r"(?:^|/)(?:tests?|testing|spec|specs)/|(?:^|/)(?:test_[^/]+|[^/]+_test"
        r"|conftest)\.py$", re.I)),
    ("example", re.compile(
        r"(?:^|/)(?:examples?|samples?|demos?|docs?|tutorials?|benchmarks?)/",
        re.I)),
    ("build", re.compile(
        r"(?:^|/)(?:setup\.py|setup\.cfg|pyproject\.toml|Makefile|Dockerfile"
        r"|docker-compose\.ya?ml|MANIFEST\.in|noxfile\.py|tasks\.py)$", re.I)),
    ("internal", re.compile(r"(?:^|/)_[^/]+\.py$")),
)
_DEFAULT_TIER = "public_api"

# ---------------------------------------------------------------------------
# Manifest files, read as TEXT. See the module docstring: a crafted
# `pyproject.toml` should not be able to steer a parser, and dependency NAMES
# are all that is needed to pick which source-API tables to sweep with.
# ---------------------------------------------------------------------------
_MANIFEST_NAMES = (
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "requirements-dev.txt", "requirements_dev.txt", "Pipfile", "poetry.lock",
    "environment.yml", "package.json", "go.mod", "Cargo.toml", "pom.xml",
    "build.gradle", "Gemfile", "composer.json",
)

# A lock file enumerates the whole transitive closure of a dev environment. On
# the first real run this made a schema library "detect" tornado, kafka, pika
# and aiohttp — none of which it uses — because `poetry.lock` names them and an
# example's `requirements.txt` names the rest. Dependency evidence from a lock
# file, or from a manifest outside the repository root, is real evidence of
# something, but it is NOT evidence that this project's code uses the framework.
# It is kept and labelled rather than discarded; see `detect_frameworks`.
_LOCK_NAMES = frozenset({"poetry.lock", "Pipfile.lock", "package-lock.json",
                         "yarn.lock", "Cargo.lock", "Gemfile.lock"})

# A dependency line's leading name, before any version specifier or extra.
# Covers `pika==1.3.0`, `  "fastavro>=1.0",` and `'pydantic',`.
_REQ_NAME_RX = re.compile(r"^\s*['\"]?([A-Za-z0-9][A-Za-z0-9._-]*)")

# Lock files and `pyproject.toml` state the name on the right-hand side instead:
# `name = "tornado"`. Without this the leading-token regex above captures the
# literal word `name` from every package stanza and the real dependency is
# never seen — which is how a lock file can look empty while listing 200
# packages.
_TOML_NAME_RX = re.compile(r"^\s*name\s*=\s*['\"]([A-Za-z0-9][A-Za-z0-9._-]*)['\"]")

# Keys whose left-hand side is a dependency name in a TOML/JSON dependency
# table — `fastavro = "^1.0"` under `[tool.poetry.dependencies]`, or
# `"pydantic": "^2"` in package.json.
_TOML_DEP_RX = re.compile(
    r"^\s*['\"]?([A-Za-z0-9][A-Za-z0-9._-]*)['\"]?\s*[=:]\s*['\"{]")

# Left-hand sides that are configuration, not packages. Without this the
# dependency set fills with `version`, `description`, `python` and friends.
_NOT_A_PACKAGE = frozenset({
    "name", "version", "description", "license", "readme", "authors",
    "maintainers", "keywords", "homepage", "repository", "documentation",
    "classifiers", "packages", "include", "exclude", "scripts", "urls",
    "requires", "requires-python", "python", "build-backend", "content-hash",
    "lock-version", "generated", "category", "optional", "files", "hash",
    "file", "marker", "markers", "extras", "source", "type", "url", "main",
    "private", "engines", "workspaces", "resolution", "integrity", "dev",
})

# ---------------------------------------------------------------------------
# Framework detection. A framework is claimed when its name appears in a
# manifest OR its import appears in source — never from a filename alone, which
# is how "it has a `views.py` so it must be Django" goes wrong.
# ---------------------------------------------------------------------------
_FRAMEWORK_MARKERS: dict[str, tuple[tuple[str, ...], re.Pattern[str]]] = {
    "flask":       (("flask",), re.compile(r"\bfrom\s+flask\b|\bimport\s+flask\b")),
    "quart":       (("quart",), re.compile(r"\bfrom\s+quart\b|\bimport\s+quart\b")),
    "django":      (("django",), re.compile(r"\bfrom\s+django\b|\bimport\s+django\b")),
    "fastapi":     (("fastapi",), re.compile(r"\bfrom\s+fastapi\b|\bimport\s+fastapi\b")),
    "starlette":   (("starlette",), re.compile(r"\bfrom\s+starlette\b|\bimport\s+starlette\b")),
    "aiohttp":     (("aiohttp",), re.compile(r"\bimport\s+aiohttp\b|\bfrom\s+aiohttp\b")),
    "tornado":     (("tornado",), re.compile(r"\bimport\s+tornado\b|\bfrom\s+tornado\b")),
    "bottle":      (("bottle",), re.compile(r"\bimport\s+bottle\b|\bfrom\s+bottle\b")),
    "pyramid":     (("pyramid",), re.compile(r"\bfrom\s+pyramid\b")),
    "sanic":       (("sanic",), re.compile(r"\bfrom\s+sanic\b|\bimport\s+sanic\b")),
    "celery":      (("celery",), re.compile(r"\bfrom\s+celery\b|\bimport\s+celery\b")),
    "rq":          (("rq",), re.compile(r"\bfrom\s+rq\b|\bimport\s+rq\b")),
    "dramatiq":    (("dramatiq",), re.compile(r"\bimport\s+dramatiq\b")),
    "kafka":       (("kafka-python", "confluent-kafka", "aiokafka"),
                    re.compile(r"\bimport\s+(?:kafka|confluent_kafka|aiokafka)\b")),
    "pika":        (("pika",), re.compile(r"\bimport\s+pika\b")),
    "boto3":       (("boto3",), re.compile(r"\bimport\s+boto3\b")),
    "jinja2":      (("jinja2",), re.compile(r"\bfrom\s+jinja2\b|\bimport\s+jinja2\b")),
    "mako":        (("mako",), re.compile(r"\bfrom\s+mako\b|\bimport\s+mako\b")),
    "chameleon":   (("chameleon",), re.compile(r"\bfrom\s+chameleon\b")),
    "sqlalchemy":  (("sqlalchemy",), re.compile(r"\bfrom\s+sqlalchemy\b|\bimport\s+sqlalchemy\b")),
    "psycopg":     (("psycopg", "psycopg2", "psycopg2-binary"),
                    re.compile(r"\bimport\s+psycopg2?\b")),
    "pymongo":     (("pymongo",), re.compile(r"\bimport\s+pymongo\b")),
    "sqlite3":     ((), re.compile(r"\bimport\s+sqlite3\b")),
    "pyyaml":      (("pyyaml",), re.compile(r"\bimport\s+yaml\b|\bfrom\s+yaml\b")),
    "pickle":      ((), re.compile(r"\bimport\s+(?:pickle|cPickle)\b")),
    "dill":        (("dill",), re.compile(r"\bimport\s+dill\b")),
    "jsonpickle":  (("jsonpickle",), re.compile(r"\bimport\s+jsonpickle\b")),
    "joblib":      (("joblib",), re.compile(r"\bimport\s+joblib\b")),
    "torch":       (("torch",), re.compile(r"\bimport\s+torch\b")),
    "numpy":       (("numpy",), re.compile(r"\bimport\s+numpy\b")),
    "pandas":      (("pandas",), re.compile(r"\bimport\s+pandas\b")),
    "click":       (("click",), re.compile(r"\bimport\s+click\b|\bfrom\s+click\b")),
    "typer":       (("typer",), re.compile(r"\bimport\s+typer\b|\bfrom\s+typer\b")),
    "fire":        (("fire",), re.compile(r"\bimport\s+fire\b")),
    "argparse":    ((), re.compile(r"\bimport\s+argparse\b")),
    "pydantic":    (("pydantic",), re.compile(r"\bfrom\s+pydantic\b|\bimport\s+pydantic\b")),
    "requests":    (("requests",), re.compile(r"\bimport\s+requests\b")),
    "httpx":       (("httpx",), re.compile(r"\bimport\s+httpx\b")),
    "fastavro":    (("fastavro",), re.compile(r"\bimport\s+fastavro\b|\bfrom\s+fastavro\b")),
    "avro":        (("avro", "avro-python3"), re.compile(r"\bimport\s+avro\b|\bfrom\s+avro\b")),
}

# ---------------------------------------------------------------------------
# The source table. This is the counterpart to `taint.py`'s SINKS_BY_LANG, and
# it is the substance of Step 3: where attacker-influenced data ENTERS.
#
# Each category maps to patterns whose match marks a candidate entry point. A
# hit is a CANDIDATE, never a conclusion — the agent opens it and decides what
# the inputs are and what trust level applies. Erring wide is correct here; the
# expensive mistake in this phase is the input nobody wrote down.
# ---------------------------------------------------------------------------
SOURCE_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "http_flask": (
        re.compile(r"\brequest\.(?:args|form|json|values|files|headers|cookies|data|stream)\b"),
        re.compile(r"\brequest\.get_json\s*\("),
        re.compile(r"@(?:\w+)\.(?:route|get|post|put|patch|delete)\s*\("),
    ),
    "http_django": (
        re.compile(r"\brequest\.(?:GET|POST|body|FILES|META|COOKIES|headers)\b"),
        re.compile(r"\b(?:re_)?path\s*\(\s*['\"]"),
        re.compile(r"\bclass\s+\w+\s*\(\s*(?:forms\.)?(?:ModelForm|Form)\b"),
        re.compile(r"\bserializers\.(?:ModelSerializer|Serializer)\b"),
    ),
    "http_fastapi": (
        re.compile(r"@(?:app|router|\w+_router)\.(?:get|post|put|patch|delete|websocket)\s*\("),
        re.compile(r"\b(?:Body|Query|Header|Cookie|Form|Path|File|Depends)\s*\("),
        re.compile(r"\bUploadFile\b"),
    ),
    "http_other": (
        re.compile(r"\brequest\.(?:query|match_info|rel_url)\b"),
        re.compile(r"\bawait\s+request\.(?:post|json|text|read)\s*\("),
        re.compile(r"\bself\.get_(?:argument|arguments|query_argument|body_argument)\s*\("),
        re.compile(r"\bself\.request\.(?:body|arguments|headers)\b"),
    ),
    "cli": (
        re.compile(r"\badd_argument\s*\("),
        re.compile(r"@\w*\.?(?:option|argument)\s*\("),
        re.compile(r"\bsys\.argv\b"),
        re.compile(r"\bsys\.stdin\b|\binput\s*\(\s*\)"),
        re.compile(r"\bfire\.Fire\s*\("),
        re.compile(r"\btyper\.(?:Option|Argument)\s*\("),
    ),
    "environment": (
        re.compile(r"\bos\.environ(?:\.get)?\s*[\[\(]"),
        re.compile(r"\bos\.getenv\s*\("),
        re.compile(r"\bdotenv\b|\bload_dotenv\s*\("),
        re.compile(r"\bBaseSettings\b"),
    ),
    "file_read": (
        re.compile(r"\bopen\s*\(", ),
        re.compile(r"\b(?:zipfile\.ZipFile|tarfile\.open|gzip\.open|bz2\.open|lzma\.open)\s*\("),
        re.compile(r"\bpandas\.read_\w+\s*\(|\bpd\.read_\w+\s*\("),
        re.compile(r"\bcsv\.(?:reader|DictReader)\s*\("),
        re.compile(r"\bconfigparser\b|\bread_text\s*\(|\bread_bytes\s*\("),
        re.compile(r"\bPath\s*\([^)]*\)\s*\.\s*(?:read_text|read_bytes|open)\s*\("),
    ),
    "deserialise": (
        re.compile(r"\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\("),
        re.compile(r"\byaml\.(?:load|unsafe_load|full_load|load_all)\s*\("),
        re.compile(r"\bmarshal\.loads?\s*\("),
        re.compile(r"\b(?:dill|jsonpickle|joblib)\.loads?\s*\("),
        re.compile(r"\btorch\.load\s*\("),
        re.compile(r"\bnumpy\.load\s*\(|\bnp\.load\s*\("),
        re.compile(r"\bjson\.loads?\s*\("),
        re.compile(r"\bfastavro\.(?:schemaless_)?read\w*\s*\(|\bschemaless_reader\s*\("),
        re.compile(r"\bparse_schema\s*\(|\bavro\.schema\.parse\s*\("),
    ),
    "message_queue": (
        re.compile(r"@(?:app|celery|shared_task)\.task\b|@shared_task\b"),
        re.compile(r"\bdramatiq\.actor\b|@\w*\.?actor\b"),
        re.compile(r"\bbasic_consume\s*\(|\bstart_consuming\s*\("),
        re.compile(r"\breceive_message\s*\(|\bKafkaConsumer\s*\("),
    ),
    "webhook": (
        re.compile(r"\bwebhook\b", re.I),
        re.compile(r"\bX-Hub-Signature\b|\bverify_signature\s*\(", re.I),
    ),
    "template": (
        re.compile(r"\brender_template(?:_string)?\s*\("),
        re.compile(r"\bTemplate\s*\(|\bfrom_string\s*\("),
        re.compile(r"\brender\s*\(\s*\w"),
        re.compile(r"\bget_template\s*\("),
    ),
    "websocket": (
        re.compile(r"\bwebsocket\b", re.I),
        re.compile(r"\bon_message\s*\(|\bWebSocketHandler\b"),
    ),
    "network_response": (
        re.compile(r"\brequests\.(?:get|post|put|patch|delete|request)\s*\("),
        re.compile(r"\bhttpx\.(?:get|post|AsyncClient|Client)\s*\("),
        re.compile(r"\burllib\.request\.urlopen\s*\(|\burlopen\s*\("),
    ),
    "ci_trigger": (
        re.compile(r"^\s*on\s*:"),
        re.compile(r"\bpull_request_target\b|\bworkflow_run\b"),
        re.compile(r"\btags\s*:|\bbranches\s*:"),
        re.compile(r"\$\{\{\s*github\.event\b"),
    ),
}

# Indirect dispatch: a forward trace that stops at the dispatcher loses every
# target behind it. `phase1_recon.md` asks the agent to grep for these; that is
# mechanical, so it happens here.
_INDIRECT_DISPATCH_RX: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bgetattr\s*\([^,]+,\s*[^)]+\)\s*\("),
    re.compile(r"\b\w+\s*\[\s*\w+\s*\]\s*\("),
    re.compile(r"\bsingledispatch\b|\bregister\s*\(|\bentry_points\s*\("),
    re.compile(r"\b__subclasses__\s*\(\)|\b__init_subclass__\b"),
    re.compile(r"\bimportlib\.import_module\s*\(|\b__import__\s*\("),
)


class ContractViolation(Exception):
    """A caller error the skill must not route around — surfaces as exit 2."""


_CONTROL_RX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS_RX = re.compile(r"\s+")


def _sanitize(text: str, limit: int = SANITIZE_LIMIT) -> str:
    """Make repository-authored text safe to place in JSON a model will read.

    Control characters out, whitespace collapsed, backticks and braces
    defanged so a matched line cannot close a fence or open an interpolation
    in whatever renders it downstream, hard length cap with an explicit
    ellipsis so truncation is visible rather than silent.
    """
    cleaned = _CONTROL_RX.sub("", text)
    cleaned = _WS_RX.sub(" ", cleaned).strip()
    cleaned = cleaned.replace("`", "'")
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + " …[truncated]"
    return cleaned


# ---------------------------------------------------------------------------
# File inventory
# ---------------------------------------------------------------------------
@dataclass
class FileRow:
    path: str
    ext: str
    lang: str | None
    bytes: int
    lines: int
    tier: str
    status: str = "read"
    reason: str = ""

    def as_dict(self) -> dict:
        row = {
            "path": self.path, "ext": self.ext, "lang": self.lang,
            "bytes": self.bytes, "lines": self.lines,
            "reachable_from": self.tier, "status": self.status,
        }
        if self.reason:
            row["reason"] = self.reason
        return row


def tier_for(rel_path: str) -> str:
    """Classify a path into a reachability tier. First rule wins."""
    posix = PurePosixPath(rel_path).as_posix()
    for tier, rx in _TIER_RULES:
        if rx.search(posix):
            return tier
    return _DEFAULT_TIER


def _vendor_reason(parts: tuple[str, ...], name: str) -> str | None:
    """Why this path is not this project's code, or None if it is."""
    for part in parts:
        if part in _VENDOR_DIR_PARTS:
            return f"vendored or tooling directory: {part}"
        if part.endswith(_VENDOR_SUFFIX_PARTS):
            return f"packaging metadata directory: {part}"
    if _GENERATED_NAME_RX.search(name):
        return "generated artefact"
    return None


def walk_repo(
    repo: Path, *, max_files: int = DEFAULT_MAX_FILES,
) -> tuple[list[FileRow], list[dict], bool]:
    """Walk the tree once. Returns (kept, excluded, truncated).

    `os.walk` with `followlinks=False`: a repository is untrusted input, and a
    symlink pointing at `/` turns an inventory into an unbounded traversal.
    """
    kept: list[FileRow] = []
    excluded: list[dict] = []
    truncated = False
    seen = 0

    for dirpath, dirnames, filenames in os.walk(repo, followlinks=False):
        rel_dir = Path(dirpath).relative_to(repo)
        parts = rel_dir.parts
        # Prune vendored trees in place so we never descend into them at all.
        pruned = []
        for d in list(dirnames):
            reason = _vendor_reason((d,), d)
            if reason:
                pruned.append(d)
                excluded.append({
                    "path": str(rel_dir / d) if parts else d,
                    "reason": reason, "kind": "directory",
                })
        for d in pruned:
            dirnames.remove(d)
        dirnames.sort()

        for name in sorted(filenames):
            seen += 1
            if seen > max_files:
                truncated = True
                return kept, excluded, truncated
            rel = (rel_dir / name) if parts else Path(name)
            rel_str = rel.as_posix()
            reason = _vendor_reason(parts, name)
            if reason:
                excluded.append({"path": rel_str, "reason": reason, "kind": "file"})
                continue
            full = repo / rel
            try:
                if full.is_symlink() or not full.is_file():
                    continue
                size = full.stat().st_size
            except OSError as exc:
                excluded.append({
                    "path": rel_str, "kind": "file",
                    "reason": f"stat failed: {type(exc).__name__}",
                })
                continue
            ext = full.suffix.lower()
            kept.append(FileRow(
                path=rel_str, ext=ext, lang=EXT_TO_LANG.get(ext),
                bytes=size, lines=0, tier=tier_for(rel_str),
            ))
    return kept, excluded, truncated


def read_lines(
    repo: Path, row: FileRow, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> list[str] | None:
    """Read one file as text, or record why it could not be read.

    Returns None when the file is not analysable, having stamped `status` and
    `reason` on the row. Binary content is a normal outcome, not an error.
    """
    if row.bytes > max_bytes:
        row.status = "skipped"
        row.reason = f"larger than the {max_bytes} byte read cap"
        return None
    try:
        raw = (repo / row.path).read_bytes()
    except OSError as exc:
        row.status = "unreadable"
        row.reason = f"{type(exc).__name__}"
        return None
    if b"\x00" in raw[:8192]:
        row.status = "binary"
        row.reason = "NUL byte in the first 8 KiB"
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        row.reason = "decoded with replacement characters"
    lines = text.splitlines()
    row.lines = len(lines)
    return lines


# ---------------------------------------------------------------------------
# Manifests and frameworks
# ---------------------------------------------------------------------------
def dependency_names(lines: list[str]) -> set[str]:
    """Pull package names out of a manifest read as plain text.

    Three shapes, because the ecosystem has three: a requirements line
    (`pika==1.3.0`), a TOML stanza naming its package on the right
    (`name = "tornado"` — every `[[package]]` in a poetry lock), and a
    dependency table keyed by name (`fastavro = "^1.0"`, `"pydantic": "^2"`).

    Only names are taken. Versions are deliberately not parsed: this is a blind
    scan, and nothing downstream should be able to reason about a version.
    """
    found: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rx in (_TOML_NAME_RX, _TOML_DEP_RX, _REQ_NAME_RX):
            match = rx.match(stripped)
            if not match:
                continue
            dep = match.group(1).lower()
            if len(dep) > 1 and not dep.isdigit() and dep not in _NOT_A_PACKAGE:
                found.add(dep)
            break
    return found


def read_manifests(
    repo: Path, rows: list[FileRow],
) -> tuple[list[dict], dict[str, str]]:
    """Collect manifest files and the dependency names they mention.

    Read as text on purpose — see the module docstring. Names only; versions
    are deliberately not parsed, because nothing downstream should be tempted
    to reason about a version in a blind scan.

    Returns the manifest rows and a map of dependency name to the STRONGEST
    scope that named it: `root` (a real manifest at the repository root),
    `peripheral` (a manifest under examples/, tests/, docs/ …), or `lock` (a
    transitive-closure lock file). The scope is what stops a lock file from
    manufacturing frameworks — see `detect_frameworks`.
    """
    manifests: list[dict] = []
    scope_rank = {"lock": 0, "peripheral": 1, "root": 2}
    dep_scope: dict[str, str] = {}

    for row in rows:
        base = PurePosixPath(row.path).name
        if base not in _MANIFEST_NAMES:
            continue
        at_root = "/" not in row.path
        if base in _LOCK_NAMES:
            scope = "lock"
        elif at_root:
            scope = "root"
        else:
            scope = "peripheral"

        lines = read_lines(repo, row)
        if lines is None:
            manifests.append({"path": row.path, "scope": scope,
                              "status": row.status, "reason": row.reason,
                              "dependencies": []})
            continue
        uniq = sorted(dependency_names(lines))
        for dep in uniq:
            if scope_rank[scope] > scope_rank.get(dep_scope.get(dep, "lock"), -1) \
                    or dep not in dep_scope:
                dep_scope[dep] = scope
        manifests.append({
            "path": row.path, "scope": scope, "status": "read",
            "reachable_from": row.tier,
            "dependencies": [_sanitize(n, 80) for n in uniq[:200]],
        })
    return manifests, dep_scope


# How much a framework claim is worth, strongest first. This is graded rather
# than filtered on purpose: dropping a weak claim shrinks the surface
# invisibly, which is the failure mode this pipeline exists to prevent. A
# grading lets phase 1b spend its budget on `confirmed` while `transitive`
# stays visible and checkable in the record.
_CONFIDENCE_ORDER = ("confirmed", "peripheral", "declared", "transitive")

# Tiers whose imports count as this project actually using the framework.
_FIRST_PARTY_TIERS = frozenset({"public_api", "internal", "build"})


def detect_frameworks(
    dep_scope: dict[str, str], source_index: dict[str, list[str]],
    tiers: dict[str, str] | None = None,
) -> list[dict]:
    """Claim a framework only on manifest evidence or a real import, and grade it.

    Each claim carries its evidence and a confidence, because "detected Django"
    with no reason is exactly the kind of unfalsifiable statement this tool
    exists to avoid — and because the first run of this module claimed four
    frameworks a schema library does not use, purely from a lock file.

    - `confirmed`   — imported by first-party source. The project uses it.
    - `peripheral`  — imported only by examples, tests, docs or CI.
    - `declared`    — named by a root manifest, never imported.
    - `transitive`  — named only by a lock file or a non-root manifest.
    """
    tiers = tiers or {}
    claims: list[dict] = []
    for name, (dep_aliases, import_rx) in sorted(_FRAMEWORK_MARKERS.items()):
        evidence: list[str] = []
        dep_scopes: list[str] = []
        for alias in dep_aliases:
            scope = dep_scope.get(alias)
            if scope:
                evidence.append(f"dependency ({scope}): {alias}")
                dep_scopes.append(scope)

        first_party_import = False
        any_import = False
        for path in sorted(source_index):
            for lineno, line in enumerate(source_index[path], 1):
                if import_rx.search(line):
                    any_import = True
                    if tiers.get(path, _DEFAULT_TIER) in _FIRST_PARTY_TIERS:
                        first_party_import = True
                    evidence.append(f"{path}:{lineno}")
                    break
            if len(evidence) >= 5 and first_party_import:
                break

        if not evidence:
            continue
        if first_party_import:
            confidence = "confirmed"
        elif any_import:
            confidence = "peripheral"
        elif "root" in dep_scopes:
            confidence = "declared"
        else:
            confidence = "transitive"
        claims.append({
            "framework": name,
            "confidence": confidence,
            "evidence": evidence[:5],
        })
    claims.sort(key=lambda c: (_CONFIDENCE_ORDER.index(c["confidence"]),
                               c["framework"]))
    return claims


# ---------------------------------------------------------------------------
# Entry-point candidates
# ---------------------------------------------------------------------------
def scan_sources(
    source_index: dict[str, list[str]], tiers: dict[str, str], *,
    max_hits: int = DEFAULT_MAX_HITS_PER_CATEGORY,
) -> tuple[dict[str, list[dict]], dict[str, int], list[str]]:
    """Sweep every source line against every source category.

    Returns (hits by category, total match counts, categories truncated).
    Counts are kept separately from kept rows so a truncated category still
    reports its true size — a bounded sample must never read as a full one.
    """
    hits: dict[str, list[dict]] = {k: [] for k in SOURCE_PATTERNS}
    totals: dict[str, int] = {k: 0 for k in SOURCE_PATTERNS}
    truncated: list[str] = []

    for path in sorted(source_index):
        lines = source_index[path]
        tier = tiers.get(path, _DEFAULT_TIER)
        for lineno, line in enumerate(lines, 1):
            if len(line) > DEFAULT_MAX_LINE_CHARS:
                continue
            for category, patterns in SOURCE_PATTERNS.items():
                for rx in patterns:
                    if not rx.search(line):
                        continue
                    totals[category] += 1
                    if len(hits[category]) < max_hits:
                        hits[category].append({
                            "location": f"{path}:{lineno}",
                            "reachable_from": tier,
                            "matched": _sanitize(line),
                            "pattern": _sanitize(rx.pattern, 120),
                        })
                    elif category not in truncated:
                        truncated.append(category)
                    break
    return hits, totals, truncated


def scan_indirect_dispatch(
    source_index: dict[str, list[str]], *, max_hits: int = DEFAULT_MAX_HITS_PER_CATEGORY,
) -> tuple[list[dict], int]:
    """Find dispatch tables, registries and dynamic imports.

    Every target behind one of these is an entry point the call graph may not
    carry an edge to, so the agent is told to enumerate them explicitly.
    """
    out: list[dict] = []
    total = 0
    for path in sorted(source_index):
        for lineno, line in enumerate(source_index[path], 1):
            if len(line) > DEFAULT_MAX_LINE_CHARS:
                continue
            for rx in _INDIRECT_DISPATCH_RX:
                if rx.search(line):
                    total += 1
                    if len(out) < max_hits:
                        out.append({
                            "location": f"{path}:{lineno}",
                            "matched": _sanitize(line),
                        })
                    break
    return out, total


# ---------------------------------------------------------------------------
# Public API surface — the part a library target lives or dies by
# ---------------------------------------------------------------------------
def public_api_surface(
    repo: Path, rows: list[FileRow], source_index: dict[str, list[str]],
) -> list[dict]:
    """Enumerate every exported callable and its parameters.

    `phase1_recon.md` is explicit that for a library target "every exported
    function's parameters are the attack surface", and equally explicit that
    reporting an empty inventory for a library is wrong. This computes that
    surface with `ast` rather than asking a model to be thorough about it.

    A parse failure is recorded and skipped: the file is still in the inventory
    with its own row, so nothing disappears.
    """
    surface: list[dict] = []
    by_path = {r.path: r for r in rows}
    for path in sorted(source_index):
        row = by_path.get(path)
        if row is None or row.lang != "python":
            continue
        try:
            tree = ast.parse("\n".join(source_index[path]), filename=path)
        except (SyntaxError, ValueError, RecursionError) as exc:
            surface.append({
                "path": path, "status": "parse_error",
                "reason": _sanitize(f"{type(exc).__name__}: {exc}", 160),
            })
            continue

        declared_all = _dunder_all(tree)
        for node in tree.body:
            entries = _exported_entries(node, path, row.tier, declared_all)
            surface.extend(entries)
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                for sub in node.body:
                    for entry in _exported_entries(
                            sub, path, row.tier, declared_all, owner=node.name):
                        surface.append(entry)
    return surface


def _dunder_all(tree: ast.Module) -> set[str] | None:
    """The names in `__all__`, or None when the module declares none.

    None and the empty set mean different things: no declaration means "every
    public name is exported", an empty declaration means "none are".
    """
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.target is not None:
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                value = node.value
                if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                    names = {
                        elt.value for elt in value.elts
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                    }
                    return names
    return None


def _exported_entries(
    node: ast.AST, path: str, tier: str, declared_all: set[str] | None,
    *, owner: str | None = None,
) -> list[dict]:
    """One row per exported callable, carrying every parameter name."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return []
    name = node.name
    if name.startswith("_") and not (name.startswith("__") and name.endswith("__")):
        return []
    qualname = f"{owner}.{name}" if owner else name
    if declared_all is not None and owner is None and name not in declared_all:
        return []

    if isinstance(node, ast.ClassDef):
        return [{
            "path": path, "symbol": qualname, "kind": "class",
            "line": node.lineno, "reachable_from": tier, "parameters": [],
        }]

    args = node.args
    params: list[str] = []
    for group in (args.posonlyargs, args.args, args.kwonlyargs):
        params.extend(a.arg for a in group)
    if args.vararg:
        params.append(f"*{args.vararg.arg}")
    if args.kwarg:
        params.append(f"**{args.kwarg.arg}")
    params = [p for p in params if p not in ("self", "cls")]
    return [{
        "path": path, "symbol": qualname,
        "kind": "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
        "line": node.lineno, "reachable_from": tier,
        "parameters": params,
    }]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------
def enumerate_repo(
    repo: Path, *,
    max_files: int = DEFAULT_MAX_FILES,
    max_hits: int = DEFAULT_MAX_HITS_PER_CATEGORY,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    include_excluded: bool = False,
) -> dict:
    """Produce the whole enumeration. Never raises on repository content."""
    rows, excluded, files_truncated = walk_repo(repo, max_files=max_files)

    source_index: dict[str, list[str]] = {}
    for row in rows:
        if row.lang is None and PurePosixPath(row.path).name not in _MANIFEST_NAMES \
                and row.ext not in (".yml", ".yaml", ".toml", ".cfg", ".ini",
                                    ".jinja2", ".j2", ".mako", ".html", ".txt"):
            row.status = "not_analysed"
            row.reason = "no language mapping and not a manifest or template"
            continue
        lines = read_lines(repo, row, max_bytes=max_file_bytes)
        if lines is not None:
            source_index[row.path] = lines

    tiers = {r.path: r.tier for r in rows}
    manifests, dep_scope = read_manifests(repo, rows)
    frameworks = detect_frameworks(dep_scope, source_index, tiers)
    hits, totals, cat_truncated = scan_sources(
        source_index, tiers, max_hits=max_hits)
    dispatch, dispatch_total = scan_indirect_dispatch(source_index, max_hits=max_hits)
    api = public_api_surface(repo, rows, source_index)

    census: dict[str, int] = {}
    tier_census: dict[str, int] = {}
    for row in rows:
        census[row.ext or "<none>"] = census.get(row.ext or "<none>", 0) + 1
        tier_census[row.tier] = tier_census.get(row.tier, 0) + 1

    candidate_total = sum(totals.values())
    payload = {
        "schema": SCHEMA_ID,
        "target": str(repo),
        "status": "ok",
        "truncated": {
            "files": files_truncated,
            "categories": cat_truncated,
        },
        "totals": {
            "files_inventoried": len(rows),
            "files_read": len(source_index),
            "files_excluded": len(excluded),
            "entry_point_candidates": candidate_total,
            "indirect_dispatch_sites": dispatch_total,
            "public_api_symbols": len([a for a in api if "symbol" in a]),
        },
        "extension_census": dict(sorted(census.items(), key=lambda kv: (-kv[1], kv[0]))),
        "reachability_census": dict(sorted(tier_census.items())),
        "frameworks": frameworks,
        "manifests": manifests,
        "entry_point_candidates": {
            category: {
                "matched": totals[category],
                "kept": len(rows_),
                "hits": rows_,
            }
            for category, rows_ in sorted(hits.items()) if totals[category]
        },
        "indirect_dispatch": {"matched": dispatch_total, "hits": dispatch},
        "public_api": api,
        "files": [r.as_dict() for r in rows],
    }
    if include_excluded:
        payload["excluded"] = excluded
    else:
        payload["excluded_sample"] = excluded[:50]
    return payload


def _atomic_write_json(path: Path, doc: object) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def write_results(results_dir: Path, payload: dict) -> list[str]:
    logs = results_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    out = logs / "recon_enumeration.json"
    _atomic_write_json(out, payload)
    return [str(out)]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon_enumerate.py",
        description="Deterministic input-surface enumeration for phase 1.")
    sub = parser.add_subparsers(dest="command", required=True)
    enum = sub.add_parser("enumerate", help="walk the target and emit candidates")
    enum.add_argument("--repo", required=True)
    enum.add_argument("--results-dir")
    enum.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    enum.add_argument("--max-hits-per-category", type=int,
                      default=DEFAULT_MAX_HITS_PER_CATEGORY)
    enum.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    enum.add_argument("--include-excluded", action="store_true",
                      help="emit every excluded path, not a 50-entry sample")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        repo = Path(args.repo).expanduser().resolve()
        if not repo.is_dir():
            raise ContractViolation(f"--repo is not a directory: {repo}")
        for name, value in (("--max-files", args.max_files),
                            ("--max-hits-per-category", args.max_hits_per_category),
                            ("--max-file-bytes", args.max_file_bytes)):
            if value < 1:
                raise ContractViolation(f"{name} must be >= 1, got {value}")

        payload = enumerate_repo(
            repo,
            max_files=args.max_files,
            max_hits=args.max_hits_per_category,
            max_file_bytes=args.max_file_bytes,
            include_excluded=args.include_excluded,
        )
        written: list[str] = []
        if args.results_dir:
            written = write_results(Path(args.results_dir).expanduser().resolve(), payload)
            payload["written"] = written
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")

        totals = payload["totals"]
        print(
            f"recon_enumerate: {totals['files_inventoried']} files "
            f"({totals['files_read']} read, {totals['files_excluded']} excluded), "
            f"{totals['entry_point_candidates']} entry-point candidates, "
            f"{totals['public_api_symbols']} public API symbols, "
            f"{len(payload['frameworks'])} frameworks",
            file=sys.stderr)
        if payload["truncated"]["files"] or payload["truncated"]["categories"]:
            print("recon_enumerate: TRUNCATED — the inventory is bounded, not "
                  "complete; see payload.truncated", file=sys.stderr)
        for path in written:
            print(f"recon_enumerate: wrote {path}", file=sys.stderr)
        return 0
    except ContractViolation as exc:
        print(f"recon_enumerate: contract violation: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive
        print(f"recon_enumerate: internal error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
