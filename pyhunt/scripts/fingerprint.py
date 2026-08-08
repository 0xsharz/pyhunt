"""Content-addressed identity for a **finding**.

NOT to be confused with ``scripts/provision/fingerprint.py``, which fingerprints
the **repository environment** (languages, build systems, version pins) to decide
how to build the container image. That module answers *"how do I build this
repo?"*. This one answers *"is this the same vulnerability I saw last week?"*.
They share a word and nothing else — do not merge them.

Why this exists
---------------
PyHunt has no stable name for a vulnerability across runs. ``finding_id`` is
minted per run by whichever hunter happened to find it, so a baseline file, a
suppression list, and regression detection ("did the fix land? did it come
back?") are all impossible. A fingerprint is a hash over the parts of a finding
that describe *which flaw it is*, so the same flaw in two runs hashes the same.

Relationship to dedupe — this SUPPLEMENTS it, it does not replace it
-------------------------------------------------------------------
``pyhunt_old/stages/dedupe.py`` clusters findings by *root cause* using a model,
and sets ``is_canonical``, which is what decides delivery. That stays. What this
module removes is the cheap half of that job: two findings whose fingerprints are
byte-identical are the same finding by construction, and collapsing them needs no
model call. Near-duplicates — same bug reached two ways, same root cause across
two files — are still a judgement, and still the model's.

Collapsing here is **non-destructive**. Every finding keeps its file and its
place in the sidecar; duplicates are marked with ``duplicate_of`` and grouped, so
the skill can hand dedupe only the representatives. Nothing is ever deleted —
the same rule that governs the execution gate governs this module.

What the hash covers, and why
-----------------------------
``path`` — the repo-relative, lexically normalised file path.
    Identity is location-bearing: the same class of flaw in two different files
    is two findings. The path is made repo-relative first so that an absolute
    path, a different checkout directory, a ``./`` prefix, a doubled slash or a
    Windows separator do not change identity. ``/home/ci/build/app/views.py``
    and ``app/views.py`` are the same file and must hash the same.

``attack_class`` — the normalised vulnerability class.
    Two different flaws can live on the same line (a path that is both traversed
    and shell-interpolated). Class is what separates them. It is normalised
    through a synonym table because model prose drifts: ``Command Injection``,
    ``cmd_injection`` and ``os command injection`` are one class, and without
    the table the "same fingerprint across two runs" guarantee dies on wording.
    The table is a stability aid, not a taxonomy — an unrecognised class keeps
    its own slug, so a class PyHunt has never seen can never silently merge into
    one it has.

``cwe`` — the CWE id, normalised to ``CWE-<n>`` with leading zeros stripped.
    The machine-readable statement of what kind of flaw this is, and the join
    key every downstream tracker uses. Note the honest cost: ``cwe`` is OPTIONAL
    in ``finding.schema.json``, so a run that starts supplying a CWE for a
    finding that previously had none changes that finding's fingerprint, and
    ``diff`` will report it as one fixed plus one new. That is visible rather
    than silent — the components are recorded next to every fingerprint, so the
    cause is one look away — and it is preferred to dropping the field, which
    would fuse findings that differ only in the specific weakness they are.

``entry_point`` — the attacker-reachable entry the flaw hangs off.
    The same sink reached from an authenticated admin route and from an
    unauthenticated webhook is two findings with two fixes. Resolved from the
    finding, else from the task that produced it, else the empty string. Absent
    for every finding in a run is stable and simply contributes no
    discrimination; absent in one run and present in the next does move the
    fingerprint, which is again visible in the recorded components.

What the hash deliberately EXCLUDES, and why
--------------------------------------------
Read this before adding a field. Each exclusion was chosen, not forgotten.

``line_start`` / ``line_end`` — **the one everybody wants to add.** Line numbers
    move when an unrelated import is added twenty lines above. Including them
    would make every finding in a file "new" after a formatting commit, which is
    precisely the noise a baseline exists to remove. Location at file
    granularity is deliberate.
``description`` / ``evidence_snippet`` — model prose. Regenerated per run and
    differently worded every time; hashing them means nothing is ever stable.
``severity`` / ``cvss`` / ``confidence`` — judgements about a finding, not the
    finding. A finding re-rated high after a fix to a neighbouring control is
    the same finding; re-rating must not read as "fixed, plus a new one".
``finding_id`` — minted per run. Hashing it would make the fingerprint a
    slower spelling of the thing that already fails to be stable.
``poc`` / ``execution`` — evidence and verdict. The gate's outcome describes
    what a run established about a finding; it is not part of which finding it
    is. Including it would let a flaky container invent a "new" finding.
``task_id`` — an artefact of how work was chunked, not of the flaw.

Versioning
----------
The value is ``fp1_<16 hex>``. The ``fp1`` prefix is the algorithm version and
is part of the string on purpose: if the covered fields ever change, old
baselines become detectably incomparable instead of silently reporting every
finding as new. ``diff`` reports a version mismatch under ``incomparable``.

CLI
---
``fingerprint.py compute  --finding FILE [--repo DIR] [--entry-point STR]``
``fingerprint.py annotate --results-dir DIR [--repo DIR] [--dry-run]``
``fingerprint.py diff     --results-dir DIR --baseline FILE [--repo DIR]``

JSON on stdout, human notes on stderr. Exit 0 on success, 2 on a contract
violation the skill must not route around, 1 on an internal error.

Pure stdlib — no third-party import, hence no ``_bootstrap`` import. Nothing
here executes target code, reads the network, or calls a model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

# --------------------------------------------------------------------------
# Algorithm identity
# --------------------------------------------------------------------------

#: Bumped only when the covered fields or their normalisation change. It is
#: baked into every fingerprint string so a stale baseline is detectable.
FINGERPRINT_VERSION = 1
FINGERPRINT_PREFIX = f"fp{FINGERPRINT_VERSION}"

#: 64 bits of SHA-256. At PyHunt's scale (thousands of findings per baseline at
#: the very most) the collision probability is ~1e-11; the shorter string is
#: worth far more in a report a human has to read than the extra margin.
_DIGEST_CHARS = 16

_FINGERPRINT_RE = re.compile(r"^fp(?P<version>\d+)_(?P<digest>[0-9a-f]{8,64})$")

COVERED_FIELDS = ("path", "attack_class", "cwe", "entry_point")
EXCLUDED_FIELDS = (
    "line_start", "line_end", "severity", "cvss", "confidence",
    "description", "evidence_snippet", "finding_id", "task_id",
    "poc", "execution",
)

SIDECAR_NAME = "fingerprints.json"


class FingerprintError(Exception):
    """A contract violation: the input cannot be fingerprinted at all.

    Raised for a finding carrying neither a file nor a vulnerability class —
    a record ``finding.schema.json`` would already have rejected. Exit code 2;
    the skill must fix the producer rather than route around it.
    """


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------

def _clean(raw: Any) -> str:
    """Coerce a possibly-missing, possibly-non-string field to a stripped str."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw.strip()
    return str(raw).strip()


def _realpath(p: str) -> str:
    """``os.path.realpath`` that never raises.

    Needed because macOS resolves ``/tmp`` to ``/private/tmp``: a results dir
    created under ``/tmp`` records the repo root one way and the finding's file
    path the other, and a naive prefix test then fails to relativise a path that
    is plainly inside the repo.
    """
    try:
        return os.path.realpath(p)
    except (OSError, ValueError):  # pragma: no cover - defensive
        return p


def _lexical(path: str) -> str:
    """Lexically normalise a path string: posix separators, no ``.``/``//``,
    ``a/../b`` collapsed, no trailing slash. Purely textual — the file need not
    exist, which matters because findings are fingerprinted from JSON that may
    have been produced on another machine."""
    s = path.strip().strip('"').strip("'").replace("\\", "/")
    if not s:
        return ""
    normed = posixpath.normpath(s)
    if normed == ".":
        return ""
    # normpath leaves a leading "//" alone on posix; collapse it.
    while normed.startswith("//"):
        normed = normed[1:]
    return normed.rstrip("/") or "/"


def normalise_path(raw: Any, repo_root: str | Path | None = None) -> str:
    """Return the repo-relative, lexically normalised form of a file path.

    An absolute path inside ``repo_root`` is made relative to it, trying both
    the literal and the symlink-resolved form of each side. Leading ``../``
    segments left over from a relative path that climbed out of the repo are
    dropped, since they describe the writer's working directory rather than the
    file. A path that is still absolute afterwards is returned normalised but
    absolute — identity is then checkout-dependent, which
    :func:`compute_fingerprint` reports as a warning rather than hiding.
    """
    s = _lexical(_clean(raw))
    if not s:
        return ""

    if repo_root is not None:
        root_raw = _lexical(str(repo_root))
        roots = [r for r in (root_raw, _lexical(_realpath(root_raw))) if r]
        paths = [s]
        if posixpath.isabs(s):
            resolved = _lexical(_realpath(s))
            if resolved != s:
                paths.append(resolved)
        for cand in paths:
            for root in roots:
                if cand == root:
                    return ""
                prefix = root if root.endswith("/") else root + "/"
                if cand.startswith(prefix):
                    return cand[len(prefix):]

    # A relative path that climbed above its own base tells us about the
    # writer's cwd, not about the file. Drop the climb and keep the tail.
    while s.startswith("../"):
        s = s[3:]
    if s.startswith("./"):
        s = s[2:]
    return s


#: canonical class -> aliases seen in the wild. Matched against the generic
#: slug (lowercase, non-alphanumerics collapsed to "_"). Canonical names follow
#: ``taint.PYTHON_SINKS`` and ``hunt_task.schema.json``'s documented examples so
#: a fingerprint's class component reads the same as the rest of the pipeline.
_CLASS_ALIASES: dict[str, tuple[str, ...]] = {
    "command_injection": (
        "cmd_injection", "os_command_injection", "shell_injection",
        "command_execution", "os_command", "shell_command_injection",
        "argument_injection", "cwe_78",
    ),
    "code_injection": (
        "eval_injection", "code_execution", "arbitrary_code_execution",
        "python_code_injection", "cwe_94",
    ),
    "codegen_injection": ("code_generation_injection", "generated_code_injection"),
    "sql_injection": ("sqli", "sql_inj", "cwe_89"),
    "nosql_injection": ("nosqli", "mongo_injection"),
    "path_traversal": (
        "directory_traversal", "dir_traversal", "relative_path_traversal",
        "arbitrary_file_read", "arbitrary_file_write", "file_path_traversal",
        "cwe_22",
    ),
    "zip_slip": ("archive_path_traversal", "tar_slip"),
    "ssrf": ("server_side_request_forgery", "cwe_918"),
    "ssti": ("server_side_template_injection", "template_injection"),
    "xxe": (
        "xml_external_entity", "xml_external_entity_injection",
        "xml_external_entities", "cwe_611",
    ),
    "deserialization": (
        "deserialisation", "unsafe_deserialization", "unsafe_deserialisation",
        "insecure_deserialization", "insecure_deserialisation",
        "pickle_deserialization", "object_injection", "cwe_502",
    ),
    "unsafe_reflection": ("dynamic_import", "unsafe_import", "cwe_470"),
    "open_redirect": ("unvalidated_redirect", "url_redirection", "cwe_601"),
    "log_injection": ("log_forging", "cwe_117"),
    "regex_dos": (
        "redos", "regular_expression_denial_of_service",
        "catastrophic_backtracking", "cwe_1333",
    ),
    "race_condition": ("toctou", "time_of_check_time_of_use", "cwe_362"),
    "auth_bypass": (
        "authentication_bypass", "broken_authentication", "missing_authentication",
        "missing_auth",
    ),
    "access_control": (
        "broken_access_control", "missing_authorization", "authorization_bypass",
        "authz", "authorization", "improper_access_control",
    ),
    "idor": ("insecure_direct_object_reference", "insecure_direct_object_references"),
    "hardcoded_secret": (
        "hardcoded_credentials", "hardcoded_password", "hardcoded_key",
        "secret_in_source", "cwe_798",
    ),
    "weak_crypto": (
        "cryptographic_failure", "cryptographic_failures", "weak_cryptography",
        "insecure_crypto", "crypto",
    ),
    "xss_reflected": ("reflected_xss",),
    "xss_stored": ("stored_xss", "persistent_xss"),
    "xss_dom": ("dom_xss", "dom_based_xss"),
    "information_disclosure": ("info_disclosure", "information_leak", "data_exposure"),
    "security_misconfiguration": ("misconfiguration", "insecure_configuration"),
    "improper_input_handling": ("improper_input_validation", "input_validation"),
    "logic_error": ("business_logic", "logic_bug", "business_logic_flaw"),
}

_ALIAS_TO_CANONICAL: dict[str, str] = {}
for _canon, _aliases in _CLASS_ALIASES.items():
    _ALIAS_TO_CANONICAL[_canon] = _canon
    for _a in _aliases:
        _ALIAS_TO_CANONICAL[_a] = _canon

#: Suffixes model prose likes to append. Stripped before the alias lookup so
#: "command injection vulnerability" and "command_injection" agree.
_CLASS_NOISE_SUFFIXES = (
    "_vulnerability", "_vulnerabilities", "_vuln", "_flaw", "_issue",
    "_bug", "_weakness", "_attack",
)


def normalise_class(raw: Any) -> str:
    """Canonicalise a vulnerability-class string.

    Lowercases, collapses every non-alphanumeric run to ``_``, strips the noise
    suffixes model prose adds, then maps through the synonym table. An
    unrecognised class returns its own slug — a class this table has never heard
    of must never be absorbed into one it has, because that would merge two
    genuinely different findings under one identity.
    """
    s = _clean(raw).lower()
    if not s:
        return ""
    slug = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    if not slug:
        return ""
    for suffix in _CLASS_NOISE_SUFFIXES:
        if slug.endswith(suffix) and len(slug) > len(suffix):
            slug = slug[: -len(suffix)]
            break
    return _ALIAS_TO_CANONICAL.get(slug, slug)


_CWE_RE = re.compile(r"cwe[\s_\-:]*(\d+)", re.IGNORECASE)


def normalise_cwe(raw: Any) -> str:
    """Canonicalise a CWE id to ``CWE-<n>`` with leading zeros stripped.

    Accepts ``CWE-78``, ``cwe_078``, ``CWE 78`` and a bare ``78``. Anything with
    no number in it normalises to the empty string, which is also what an absent
    (schema-optional) CWE contributes.
    """
    s = _clean(raw)
    if not s:
        return ""
    m = _CWE_RE.search(s)
    if m:
        return f"CWE-{int(m.group(1))}"
    if s.isdigit():
        return f"CWE-{int(s)}"
    return ""


def normalise_entry_point(raw: Any, repo_root: str | Path | None = None) -> str:
    """Canonicalise an entry-point designator.

    Handles the three shapes the pipeline produces: a dotted symbol
    (``app.views.upload``), a ``path/to/file.py:function`` locator, and a route
    (``POST /api/v1/files``). Whitespace is collapsed; the path half of a
    ``file:symbol`` locator is normalised with :func:`normalise_path` so an
    absolute path there is no more identity-bearing than it is in ``file``.
    Symbol case is preserved — Python identifiers are case-sensitive.
    """
    if isinstance(raw, dict):
        for key in ("entry_point", "qualified_name", "symbol", "function", "name", "location"):
            if raw.get(key):
                raw = raw[key]
                break
        else:
            raw = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    s = re.sub(r"\s+", " ", _clean(raw))
    if not s:
        return ""

    # "<path>:<symbol>" / "<path>::<symbol>" — normalise the path half only.
    m = re.match(r"^(?P<path>[^\s:]+\.py)(?P<sep>::?)(?P<rest>.*)$", s)
    if m:
        path = normalise_path(m.group("path"), repo_root)
        return f"{path}:{m.group('rest').strip()}" if path else m.group("rest").strip()
    return s


# --------------------------------------------------------------------------
# Component extraction + hashing
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Components:
    """The four normalised strings the fingerprint is computed over."""

    path: str
    attack_class: str
    cwe: str
    entry_point: str

    def as_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "attack_class": self.attack_class,
            "cwe": self.cwe,
            "entry_point": self.entry_point,
        }

    def preimage(self) -> str:
        """The exact bytes that get hashed.

        A sorted, compact, ASCII-escaped JSON object rather than a delimiter-
        joined string: JSON escaping makes it impossible for a component
        containing the delimiter to impersonate a different split, and
        ``sort_keys`` plus ``ensure_ascii`` make the encoding identical across
        Python versions and locales.
        """
        payload = {"v": FINGERPRINT_VERSION, **self.as_dict()}
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class FindingFingerprint:
    """One finding's identity, plus everything needed to explain it."""

    fingerprint: str
    components: Components
    preimage: str
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "components": self.components.as_dict(),
            "preimage": self.preimage,
            "warnings": list(self.warnings),
        }


def _first_present(finding: dict, keys: Sequence[str]) -> Any:
    for k in keys:
        v = finding.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


def extract_components(
    finding: dict,
    *,
    repo_root: str | Path | None = None,
    entry_point: Any = None,
    task_index: dict[str, Any] | None = None,
) -> tuple[Components, list[str]]:
    """Pull the four identity components out of a finding dict.

    Field aliases are accepted because findings arrive from three shapes — a
    hunter's ``HuntOutput``, a single-finding results file, and a baseline
    record — and a key that is spelled ``file`` in one and ``path`` in another
    must not fork identity.

    Returns ``(components, warnings)``. Warnings are facts about weakened
    identity (an unresolvable absolute path, a missing class), never errors.
    """
    warnings: list[str] = []

    raw_path = _first_present(finding, ("file", "path", "file_path", "location"))
    path = normalise_path(raw_path, repo_root)
    if not path:
        warnings.append(
            "no file path on this finding: identity cannot distinguish it from "
            "another pathless finding of the same class"
        )
    elif posixpath.isabs(path):
        warnings.append(
            f"path {path!r} is absolute and not inside the supplied repo root — "
            f"this fingerprint is checkout-dependent; pass --repo to stabilise it"
        )

    raw_class = _first_present(finding, ("vuln_class", "attack_class", "vulnerability_class", "class"))
    attack_class = normalise_class(raw_class)
    if not attack_class:
        warnings.append("no vulnerability class on this finding: identity is weaker than it should be")

    cwe = normalise_cwe(_first_present(finding, ("cwe", "cwe_id")))

    ep_raw = entry_point
    if ep_raw in (None, "", [], {}):
        ep_raw = _first_present(finding, ("entry_point", "entry", "entrypoint"))
    if ep_raw in (None, "", [], {}) and task_index:
        task_id = _clean(_first_present(finding, ("task_id", "task")))
        if task_id:
            task = task_index.get(task_id)
            if isinstance(task, dict):
                ep_raw = _first_present(task, ("entry_point", "entry", "entrypoint"))
    ep = normalise_entry_point(ep_raw, repo_root)

    if not path and not attack_class:
        raise FingerprintError(
            "finding has neither a file nor a vulnerability class — it carries no "
            "identity at all. finding.schema.json requires both `file` and "
            "`vuln_class`; fix the producer rather than fingerprinting a blank."
        )

    return Components(path=path, attack_class=attack_class, cwe=cwe, entry_point=ep), warnings


def digest_components(components: Components) -> str:
    """SHA-256 the canonical preimage; return ``fp<version>_<16 hex>``."""
    raw = components.preimage().encode("utf-8")
    return f"{FINGERPRINT_PREFIX}_{hashlib.sha256(raw).hexdigest()[:_DIGEST_CHARS]}"


def compute_fingerprint(
    finding: dict,
    *,
    repo_root: str | Path | None = None,
    entry_point: Any = None,
    task_index: dict[str, Any] | None = None,
) -> FindingFingerprint:
    """Fingerprint one finding. Pure — no I/O, no clock, no model.

    Raises :class:`FingerprintError` only for a finding with no identity at all
    (neither file nor class). Every other degradation is a warning, because a
    weak identity is still an identity and losing the finding is not an option.
    """
    components, warnings = extract_components(
        finding, repo_root=repo_root, entry_point=entry_point, task_index=task_index
    )
    return FindingFingerprint(
        fingerprint=digest_components(components),
        components=components,
        preimage=components.preimage(),
        warnings=tuple(warnings),
    )


def fingerprint_version(value: str) -> int | None:
    """Algorithm version encoded in a fingerprint string, or None if it is not
    one. Used by :func:`diff` to refuse to compare across versions."""
    m = _FINGERPRINT_RE.match(_clean(value))
    return int(m.group("version")) if m else None


# --------------------------------------------------------------------------
# Results-directory I/O
# --------------------------------------------------------------------------

@dataclass
class LoadedFinding:
    """One finding plus where it came from, so annotate can write it back."""

    finding: dict
    source: Path
    #: The JSON document the finding lives in. Same object as ``finding`` for a
    #: one-finding-per-file layout; the enclosing ``HuntOutput`` otherwise.
    document: Any
    index: int | None = None
    task_id: str = ""

    @property
    def finding_id(self) -> str:
        return _clean(self.finding.get("finding_id"))


def _iter_finding_files(results_dir: Path) -> Iterator[Path]:
    findings_dir = results_dir / "findings"
    if findings_dir.is_dir():
        yield from sorted(findings_dir.glob("*.json"))


def load_findings(results_dir: str | Path) -> tuple[list[LoadedFinding], list[dict]]:
    """Read every finding under ``<results-dir>/findings/``.

    Tolerates the two shapes that occur in practice: a single finding object per
    file (the results-directory contract), and a whole ``HuntOutput`` with a
    ``findings`` array (what a hunter emits before it is split). A file that
    will not parse is reported as an error and skipped — never silently dropped,
    because a finding that vanished from the sidecar reads as "fixed" in the
    next diff.

    Returns ``(findings, errors)``.
    """
    results_dir = Path(results_dir)
    loaded: list[LoadedFinding] = []
    errors: list[dict] = []

    for path in _iter_finding_files(results_dir):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            errors.append({
                "source": path.name,
                "finding_id": None,
                "reason": f"unreadable finding file: {type(e).__name__}: {e}",
            })
            continue

        if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
            task_id = _clean(doc.get("task_id"))
            for i, f in enumerate(doc["findings"]):
                if isinstance(f, dict):
                    loaded.append(LoadedFinding(f, path, doc, i, task_id))
                else:
                    errors.append({
                        "source": path.name, "finding_id": None,
                        "reason": f"findings[{i}] is {type(f).__name__}, not an object",
                    })
        elif isinstance(doc, list):
            for i, f in enumerate(doc):
                if isinstance(f, dict):
                    loaded.append(LoadedFinding(f, path, doc, i, _clean(f.get("task_id"))))
                else:
                    errors.append({
                        "source": path.name, "finding_id": None,
                        "reason": f"item {i} is {type(f).__name__}, not an object",
                    })
        elif isinstance(doc, dict):
            loaded.append(LoadedFinding(doc, path, doc, None, _clean(doc.get("task_id"))))
        else:
            errors.append({
                "source": path.name, "finding_id": None,
                "reason": f"top-level JSON is {type(doc).__name__}, not an object or array",
            })

    return loaded, errors


def load_task_index(results_dir: str | Path) -> dict[str, Any]:
    """``task_id -> task`` from ``tasks.json``, for entry-point resolution.

    Best-effort: phase 1b may not have run, or may have been written by an older
    build with no ``entry_point`` on its tasks. A missing or malformed file
    simply yields no entry points, which is a stable outcome, not an error.
    """
    path = Path(results_dir) / "tasks.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    tasks = doc.get("tasks") if isinstance(doc, dict) else doc
    if not isinstance(tasks, list):
        return {}
    return {
        _clean(t.get("task_id")): t
        for t in tasks
        if isinstance(t, dict) and _clean(t.get("task_id"))
    }


def resolve_repo_root(results_dir: str | Path, explicit: str | Path | None = None) -> str | None:
    """Repo root for path normalisation: ``--repo`` if given, else the target
    recorded in ``manifest.json``. Returned as a string, or None if neither is
    available (identity then falls back to whatever the paths already are)."""
    if explicit:
        return str(explicit)
    path = Path(results_dir) / "manifest.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    for key in ("target", "repo", "repo_path", "target_path"):
        val = doc.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


# --------------------------------------------------------------------------
# Exact-duplicate collapse
# --------------------------------------------------------------------------

def _is_proven(finding: dict) -> bool:
    ex = finding.get("execution")
    return isinstance(ex, dict) and ex.get("proven") is True


def _representative_key(entry: dict) -> tuple:
    """Ordering that picks which member of an exact-duplicate group represents it.

    Strongest evidence first, so collapsing never buries a proven finding behind
    an unproven twin: proven before unproven, then higher confidence, then the
    earlier line, then ``finding_id`` and source filename as deterministic
    tie-breakers. Every member survives in the group either way — this decides
    which one dedupe and the report lead with, not which one exists.
    """
    return (
        0 if entry["_proven"] else 1,
        -entry["_confidence"],
        entry["_line"],
        entry["finding_id"] or "",
        entry["source"] or "",
    )


def _group_by_fingerprint(entries: list[dict]) -> list[dict]:
    """Collapse exact fingerprint matches into groups, non-destructively.

    This is the half of dedupe that needs no model: identical fingerprint means
    identical file, class, CWE and entry point, which is the same finding found
    twice. Mutates ``entries`` to set ``duplicate_of`` / ``representative`` and
    returns the group list.
    """
    buckets: dict[str, list[dict]] = {}
    for e in entries:
        if e.get("fingerprint"):
            buckets.setdefault(e["fingerprint"], []).append(e)

    groups: list[dict] = []
    for fp_value in sorted(buckets):
        members = sorted(buckets[fp_value], key=_representative_key)
        rep = members[0]
        rep["representative"] = True
        rep["duplicate_of"] = None
        for other in members[1:]:
            other["representative"] = False
            other["duplicate_of"] = rep["finding_id"] or rep["source"]
        groups.append({
            "fingerprint": fp_value,
            "representative_finding_id": rep["finding_id"],
            "member_finding_ids": [m["finding_id"] for m in members],
            "size": len(members),
        })
    return groups


# --------------------------------------------------------------------------
# Subcommand: annotate
# --------------------------------------------------------------------------

def _entry_for(loaded: LoadedFinding, fp: FindingFingerprint | None,
               error: str | None = None) -> dict:
    finding = loaded.finding
    try:
        confidence = float(finding.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    try:
        line = int(finding.get("line_start") or 0)
    except (TypeError, ValueError):
        line = 0
    entry: dict[str, Any] = {
        "finding_id": loaded.finding_id,
        "source": loaded.source.name,
        "task_id": loaded.task_id,
        "file": _clean(finding.get("file")),
        "vuln_class": _clean(finding.get("vuln_class")),
        "cwe": _clean(finding.get("cwe")),
        "fingerprint": fp.fingerprint if fp else None,
        "components": fp.components.as_dict() if fp else None,
        "preimage": fp.preimage if fp else None,
        "warnings": list(fp.warnings) if fp else [],
        "duplicate_of": None,
        "representative": True,
        "_proven": _is_proven(finding),
        "_confidence": confidence,
        "_line": line,
    }
    if error:
        entry["error"] = error
    return entry


def annotate(
    results_dir: str | Path,
    *,
    repo_root: str | Path | None = None,
    write: bool = True,
) -> dict:
    """Fingerprint every finding in a results directory.

    Adds a ``fingerprint`` field to each finding file (the contract), writes the
    ``fingerprints.json`` sidecar, and returns the sidecar document. With
    ``write=False`` nothing on disk changes and the same document is returned —
    which is what ``diff`` uses when a run has not been annotated yet.

    Never deletes or reorders a finding. A finding that cannot be fingerprinted
    keeps its file untouched, appears in the sidecar with ``fingerprint: null``,
    and is listed under ``errors``.
    """
    results_dir = Path(results_dir)
    if not results_dir.is_dir():
        raise FingerprintError(f"results dir does not exist: {results_dir}")

    root = resolve_repo_root(results_dir, repo_root)
    task_index = load_task_index(results_dir)
    loaded, errors = load_findings(results_dir)

    entries: list[dict] = []
    touched: dict[Path, Any] = {}

    for lf in loaded:
        try:
            fp = compute_fingerprint(lf.finding, repo_root=root, task_index=task_index)
        except FingerprintError as e:
            errors.append({
                "source": lf.source.name,
                "finding_id": lf.finding_id or None,
                "reason": str(e),
            })
            entries.append(_entry_for(lf, None, error=str(e)))
            continue
        entries.append(_entry_for(lf, fp))
        if lf.finding.get("fingerprint") != fp.fingerprint:
            lf.finding["fingerprint"] = fp.fingerprint
            touched[lf.source] = lf.document

    groups = _group_by_fingerprint(entries)

    if write:
        for path, document in touched.items():
            path.write_text(
                json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

    public = [{k: v for k, v in e.items() if not k.startswith("_")} for e in entries]
    fingerprinted = [e for e in public if e["fingerprint"]]
    document = {
        "schema": "pyhunt.fingerprints/1",
        "algorithm": {
            "version": FINGERPRINT_VERSION,
            "prefix": FINGERPRINT_PREFIX,
            "digest": "sha256",
            "digest_chars": _DIGEST_CHARS,
            "covers": list(COVERED_FIELDS),
            "excludes": list(EXCLUDED_FIELDS),
        },
        "repo_root": root,
        "findings": public,
        "groups": groups,
        "errors": errors,
        "totals": {
            "findings": len(public),
            "fingerprinted": len(fingerprinted),
            "distinct_fingerprints": len(groups),
            "duplicates_collapsed": len(fingerprinted) - len(groups),
            "errors": len(errors),
        },
    }

    if write:
        (results_dir / SIDECAR_NAME).write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    return document


def fingerprint_set(document: dict) -> set[str]:
    """The distinct fingerprints in an annotate document — the object the
    acceptance criterion ("two runs at the same commit produce the same
    fingerprint set") is stated over."""
    return {g["fingerprint"] for g in document.get("groups", [])}


# --------------------------------------------------------------------------
# Subcommand: diff
# --------------------------------------------------------------------------

def load_baseline(path: str | Path) -> tuple[dict[str, dict], list[str]]:
    """Read a baseline into ``fingerprint -> record``.

    Liberal in what it accepts, because a baseline is a file a human commits and
    edits: a previous run's ``fingerprints.json``; a bare JSON array of
    fingerprint strings or of objects carrying one; ``{"fingerprints": [...]}``;
    a directory containing ``fingerprints.json``; or a plain-text file with one
    fingerprint per line and ``#`` comments.

    Returns ``(records, notes)``.
    """
    p = Path(path)
    if p.is_dir():
        p = p / SIDECAR_NAME
    if not p.is_file():
        raise FingerprintError(f"baseline not found: {p}")

    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise FingerprintError(f"baseline unreadable: {p}: {e}") from e

    notes: list[str] = []
    try:
        doc: Any = json.loads(text)
    except json.JSONDecodeError:
        records: dict[str, dict] = {}
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                records.setdefault(line, {"fingerprint": line})
        if not records:
            raise FingerprintError(
                f"baseline {p} is neither JSON nor a list of fingerprints"
            ) from None
        notes.append("baseline read as a plain fingerprint list")
        return records, notes

    if isinstance(doc, dict):
        items = doc.get("findings")
        if not isinstance(items, list):
            items = doc.get("fingerprints")
        if not isinstance(items, list):
            items = doc.get("groups")
        if not isinstance(items, list):
            raise FingerprintError(
                f"baseline {p} is a JSON object with no `findings`, `fingerprints` "
                f"or `groups` array"
            )
    elif isinstance(doc, list):
        items = doc
    else:
        raise FingerprintError(f"baseline {p} is {type(doc).__name__}, not an object or array")

    records = {}
    for item in items:
        if isinstance(item, str):
            value, record = item, {"fingerprint": item}
        elif isinstance(item, dict):
            value = _clean(item.get("fingerprint"))
            record = item
        else:
            notes.append(f"skipped baseline entry of type {type(item).__name__}")
            continue
        if not value:
            notes.append("skipped baseline entry with no fingerprint")
            continue
        records.setdefault(value, record)
    if not records:
        notes.append("baseline contains no fingerprints — every current finding is new")
    return records, notes


_FIXED_CAVEAT = (
    "`fixed` means present in the baseline and absent from this run. Absence is "
    "not proof of a fix: a narrower scope, a skipped phase, or a hunter that ran "
    "out of budget all produce the same absence. Read it alongside coverage.json."
)


def diff(
    results_dir: str | Path,
    baseline_path: str | Path,
    *,
    repo_root: str | Path | None = None,
) -> dict:
    """Compare this run's fingerprints against a baseline.

    Uses ``<results-dir>/fingerprints.json`` when present, otherwise computes
    the same document in memory, so ``diff`` works on a run that was never
    annotated. Fingerprints written by a different algorithm version are
    reported under ``incomparable`` rather than counted as fixed — a version
    bump must never masquerade as a repo full of resolved vulnerabilities.
    """
    results_dir = Path(results_dir)
    sidecar = results_dir / SIDECAR_NAME
    if sidecar.is_file():
        try:
            current = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise FingerprintError(f"{sidecar} is unreadable: {e}") from e
    else:
        current = annotate(results_dir, repo_root=repo_root, write=False)

    baseline, notes = load_baseline(baseline_path)

    by_fp: dict[str, list[dict]] = {}
    for entry in current.get("findings", []):
        value = entry.get("fingerprint")
        if value:
            by_fp.setdefault(value, []).append(entry)

    incomparable: list[dict] = []
    comparable_baseline: dict[str, dict] = {}
    for value, record in baseline.items():
        version = fingerprint_version(value)
        if version is None:
            incomparable.append({"fingerprint": value, "reason": "not a pyhunt fingerprint"})
        elif version != FINGERPRINT_VERSION:
            incomparable.append({
                "fingerprint": value,
                "reason": f"algorithm version {version}, this build computes version "
                          f"{FINGERPRINT_VERSION} — not comparable",
            })
        else:
            comparable_baseline[value] = record

    def _summary(entry: dict) -> dict:
        comp = entry.get("components") or {}
        return {
            "fingerprint": entry.get("fingerprint"),
            "finding_id": entry.get("finding_id"),
            "file": comp.get("path") or entry.get("file"),
            "attack_class": comp.get("attack_class") or entry.get("vuln_class"),
            "cwe": comp.get("cwe") or entry.get("cwe"),
            "entry_point": comp.get("entry_point", ""),
        }

    new: list[dict] = []
    persisting: list[dict] = []
    for value in sorted(by_fp):
        rep = sorted(by_fp[value], key=lambda e: (e.get("finding_id") or "", e.get("source") or ""))[0]
        summary = _summary(rep)
        summary["occurrences"] = len(by_fp[value])
        (persisting if value in comparable_baseline else new).append(summary)

    fixed = [
        {
            "fingerprint": value,
            "finding_id": comparable_baseline[value].get("finding_id"),
            "file": (comparable_baseline[value].get("components") or {}).get("path")
                    or comparable_baseline[value].get("file"),
            "attack_class": (comparable_baseline[value].get("components") or {}).get("attack_class")
                            or comparable_baseline[value].get("vuln_class"),
        }
        for value in sorted(comparable_baseline)
        if value not in by_fp
    ]

    return {
        "schema": "pyhunt.fingerprint_diff/1",
        "algorithm_version": FINGERPRINT_VERSION,
        "results_dir": str(results_dir),
        "baseline": str(baseline_path),
        "new": new,
        "persisting": persisting,
        "fixed": fixed,
        "incomparable": incomparable,
        "notes": notes,
        "caveat": _FIXED_CAVEAT,
        "totals": {
            "current": len(by_fp),
            "baseline": len(baseline),
            "baseline_comparable": len(comparable_baseline),
            "new": len(new),
            "fixed": len(fixed),
            "persisting": len(persisting),
            "incomparable": len(incomparable),
        },
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _emit(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def _note(msg: str) -> None:
    print(msg, file=sys.stderr)


def _cmd_compute(args: argparse.Namespace) -> int:
    path = Path(args.finding)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise FingerprintError(f"cannot read finding {path}: {e}") from e

    if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        findings = [f for f in doc["findings"] if isinstance(f, dict)]
    elif isinstance(doc, list):
        findings = [f for f in doc if isinstance(f, dict)]
    elif isinstance(doc, dict):
        findings = [doc]
    else:
        raise FingerprintError(f"{path} is {type(doc).__name__}, not a finding")

    if not findings:
        raise FingerprintError(f"{path} contains no findings")

    results = []
    for f in findings:
        fp = compute_fingerprint(f, repo_root=args.repo, entry_point=args.entry_point)
        for w in fp.warnings:
            _note(f"[fingerprint] warning: {w}")
        results.append({"finding_id": _clean(f.get("finding_id")), **fp.as_dict()})

    _emit(results[0] if len(results) == 1 else {"fingerprints": results})
    return 0


def _cmd_annotate(args: argparse.Namespace) -> int:
    document = annotate(args.results_dir, repo_root=args.repo, write=not args.dry_run)
    totals = document["totals"]
    _note(
        f"[fingerprint] {totals['fingerprinted']}/{totals['findings']} findings "
        f"fingerprinted; {totals['distinct_fingerprints']} distinct, "
        f"{totals['duplicates_collapsed']} exact duplicates collapsed without a model call"
        + (" (dry run — nothing written)" if args.dry_run else "")
    )
    for err in document["errors"]:
        _note(f"[fingerprint] ERROR {err['source']}: {err['reason']}")
    _emit(document)
    # Every finding survives either way; a non-zero exit exists so a malformed
    # finding is not silently normalised into the run's identity set.
    return 2 if document["errors"] else 0


def _cmd_diff(args: argparse.Namespace) -> int:
    document = diff(args.results_dir, args.baseline, repo_root=args.repo)
    t = document["totals"]
    _note(
        f"[fingerprint] vs baseline: {t['new']} new, {t['fixed']} fixed, "
        f"{t['persisting']} persisting"
        + (f", {t['incomparable']} incomparable" if t["incomparable"] else "")
    )
    if t["fixed"]:
        _note(f"[fingerprint] {_FIXED_CAVEAT}")
    _emit(document)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fingerprint.py",
        description="Content-addressed identity for findings (not for repos — "
                    "that is scripts/provision/fingerprint.py).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_compute = sub.add_parser("compute", help="fingerprint one finding file")
    p_compute.add_argument("--finding", required=True, help="path to a finding JSON file")
    p_compute.add_argument("--repo", default=None, help="repo root, to make file paths relative")
    p_compute.add_argument("--entry-point", default=None, help="override the entry point component")
    p_compute.set_defaults(func=_cmd_compute)

    p_annotate = sub.add_parser("annotate", help="fingerprint every finding in a results dir")
    p_annotate.add_argument("--results-dir", required=True)
    p_annotate.add_argument("--repo", default=None,
                            help="repo root; defaults to manifest.json's target")
    p_annotate.add_argument("--dry-run", action="store_true",
                            help="compute and print, write nothing")
    p_annotate.set_defaults(func=_cmd_annotate)

    p_diff = sub.add_parser("diff", help="new / fixed / persisting against a baseline")
    p_diff.add_argument("--results-dir", required=True)
    p_diff.add_argument("--baseline", required=True,
                        help="a previous fingerprints.json, a fingerprint list, or a results dir")
    p_diff.add_argument("--repo", default=None)
    p_diff.set_defaults(func=_cmd_diff)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FingerprintError as e:
        _note(f"[fingerprint] contract violation: {e}")
        return 2
    except Exception as e:  # pragma: no cover - internal error path
        _note(f"[fingerprint] internal error: {type(e).__name__}: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
