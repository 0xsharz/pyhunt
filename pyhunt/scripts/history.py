"""Deterministic git-history mining for past security patches (import #10).

`prompts/01-recon.md:136` used to hand this job to the Recon **agent**: run
`git log --grep=...`, read the top commits, spot the fixed idiom, grep for
siblings. That is grep and diff parsing wearing an LLM costume — expensive,
non-reproducible across runs, and it silently varies with model temperature and
context pressure. Everything it did is Layer 1 work, so it lives here instead.

**The thesis.** A past security fix is the project's own recorded statement
about where its dangerous sinks are. The patched file is now hardened; the
*siblings that use the same idiom and were never touched* usually are not. So
the output that matters is not "here are the old CVEs" — it is
**`unpatched_siblings`**: other live call sites of the exact idiom a previous
patch went out of its way to fix. Those become hunt tasks. That is the
acceptance criterion in PLAN.md §6 step 6.

**Two-stage precision.** The `--grep` keyword list (`SECURITY_COMMIT_KEYWORDS`)
is deliberately broad — a cheap pre-filter, not the decision. A commit only
becomes a *hit* if its diff actually touched a line matching the sink tables in
`taint.py`, or added a hardening idiom from `SECURITY_GUARDS` next to one. The
sink table is the precision gate; the keyword grep only decides what is worth
diffing. Broad-and-cheap followed by narrow-and-principled beats one clever
regex.

**Read-only, and defensively so.** Only `rev-parse`, `ls-files`, `log`, and
`show` are ever invoked — never `checkout`, `clean`, `reset`, `fetch`, or
anything that writes. The target repository is untrusted input and is never
modified. It is also never *trusted*: a repository carries its own
`.git/config` and `.gitattributes`, and several git settings (`diff.external`,
textconv filters, `core.fsmonitor`) cause git to **execute a program named by
the repo**. `_GIT_SAFE_CONFIG` plus `--no-ext-diff --no-textconv` neutralise
those, because "we only read the repo" is not true by default.

**Hostile text.** Commit subjects, bodies, and diff hunks are written by
whoever wrote the repository. They flow into JSON a model later reads, so every
one of them goes through `_sanitize()`: control characters stripped, newlines
and backticks collapsed, hard length cap. They are never interpolated into a
command line, a shell string, or a regex.

**Failure is data, not a crash.** No git binary, no `.git`, an empty history, a
shallow clone, a repo git refuses to open — each is a normal outcome that emits
a well-formed empty result carrying a `status` and a `reason`. A truncated mine
records that it was truncated, so a bounded scan can never be mistaken for an
exhaustive one.

Contract (see the skill's script conventions):

    python3 scripts/history.py mine --repo PATH [--since REF]
        [--max-commits N] [--max-patches N] [--max-tasks N] [--results-dir DIR]

JSON to stdout; human notes to stderr; exit 0 normally, 2 on a contract
violation the skill must not route around, 1 on an internal error.
"""

from __future__ import annotations

# NOTE: stdlib + sibling scripts only — no third-party import, hence no
# `import _bootstrap`. `taint` and `lang_hints` are siblings in scripts/, which
# is sys.path[0] when this file is run directly.
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from lang_hints import EXT_TO_LANG
from taint import SINKS_BY_LANG

SCHEMA_ID = "pyhunt.history/1"

# ---------------------------------------------------------------------------
# Bounds. Every one of these is a place a pathological repository could
# otherwise turn a recon step into an unbounded job. Hitting one is recorded in
# the output, never swallowed.
# ---------------------------------------------------------------------------
DEFAULT_MAX_COMMITS = 2000      # matched commits collected from the metadata pass
DEFAULT_MAX_PATCHES = 200       # of those, how many we actually diff-parse
DEFAULT_MAX_TASKS = 20          # hunt tasks emitted
GIT_TIMEOUT = 180               # seconds per git invocation

_MAX_SIBLINGS_PER_HIT = 25      # sibling sites listed on one patch hit
_MAX_SITES_PER_PATTERN = 200    # sites collected repo-wide for one idiom
_MAX_TASK_FILES = 15            # target_files fan-out on one hunt task
_MAX_TRACKED_FILES = 20_000     # tracked source files opened during the sweep
_MAX_FILE_BYTES = 1_000_000     # per-file read cap for the sibling sweep
_MAX_DIFF_SAMPLES = 6           # added/removed lines quoted per hit
_GUARD_WINDOW = 2               # lines either side counted as "guard nearby"

# How far from an ADDED guard line an *unchanged* sink line may sit and still be
# treated as the sink that guard defends. Deliberately tight. A guard wrapping a
# sink is adjacent to it — the same statement, or the line above. Any further and
# the association is a guess, and a guess here mislabels an unrelated sink as
# "hardened" and spends a Validate budget on it. Nothing is lost by being strict:
# if the patch actually edited the sink line, the added/removed scan already has
# it, and this context path only ever handles the guard-added-beside-an-unchanged-
# sink shape.
_GUARD_CONTEXT_WINDOW = 2

# Hostile-text length caps.
_MAX_SUBJECT = 160
_MAX_SNIPPET = 200
_MAX_IDIOM = 60

# `hunt_task.schema.json` has no `history` member in its `source` enum, and that
# schema is not this module's to edit. Recon is the truthful nearest value: this
# runs in phase 1 and its output is recon input (PLAN.md §6 step 6). If the
# schema later grows a `"history"` value, this constant is the only line to change.
_TASK_SOURCE = "recon"

# ---------------------------------------------------------------------------
# Security-patch commit language. ONE named constant, per the brief. Built from
# what `prompts/01-recon.md:141` actually grepped for, widened with the classes
# the sink tables cover.
#
# These are POSIX **extended** regex fragments: they are passed to `git log -E
# -i --grep=`, so no `\b`, no `\d`, no lookarounds — git's regex engine does not
# portably support them. They are also compiled with Python's `re` to report
# which keyword matched, so the intersection of both dialects is the budget.
#
# Deliberately broad. Precision comes from the sink-table match on the diff, not
# from here; a keyword that over-matches costs one extra diff parse, while a
# keyword that under-matches loses a real patch forever.
# ---------------------------------------------------------------------------
SECURITY_COMMIT_KEYWORDS: tuple[str, ...] = (
    # Explicit vulnerability identifiers and process language.
    "cve-[0-9]",
    "cwe-[0-9]",
    "ghsa-",
    "security",
    "vulnerab",
    "vuln",
    "sec:",
    "advisory",
    "exploit",
    "attacker",
    "untrusted",
    "malicious",
    "harden",
    "audit fix",
    # Attack classes, matching the sink-table keys.
    "injection",
    "traversal",
    "zip ?slip",
    "xss",
    "csrf",
    "ssrf",
    "ssti",
    "xxe",
    "rce",
    "sqli",
    "deserializ",
    "deserialis",
    "prototype pollution",
    "open redirect",
    "privilege",
    "escalat",
    "overflow",
    "arbitrary (file|code|command|read|write)",
    # Remediation verbs — what a fix commit says it did.
    "sanitiz",
    "sanitis",
    "unsanitiz",
    "escap",
    "unescap",
    "bypass",
    "unsafe",
    "fix.*auth",
    "fix.*inject",
    "fix.*path",
    # Named hardening idioms, which show up in subjects surprisingly often.
    "shlex",
    "safe_load",
    "safeloader",
    "defusedxml",
    "shell=false",
    "secure_filename",
)

_KEYWORD_RX: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (kw, re.compile(kw, re.IGNORECASE)) for kw in SECURITY_COMMIT_KEYWORDS
)

GREP_PATTERN = "|".join(SECURITY_COMMIT_KEYWORDS)

# ---------------------------------------------------------------------------
# Hardening idioms. When one of these APPEARS IN THE ADDED LINES of a commit
# that also touches a sink, the commit is a patch rather than a refactor — and
# the guard names the defence the siblings are missing.
#
# Curated, not exhaustive, and deliberately conservative: a false "guard added"
# only mislabels a hit's `kind`, but a guard regex broad enough to fire on
# ordinary code (a bare `escape(`, a bare `json.loads(`) would label every
# refactor a security patch. Two idioms per defence, at most.
# ---------------------------------------------------------------------------
SECURITY_GUARDS: dict[str, re.Pattern[str]] = {
    "shlex.quote": re.compile(r"shlex\.quote\s*\("),
    "shlex.split": re.compile(r"shlex\.split\s*\("),
    "shell=False": re.compile(r"shell\s*=\s*False"),
    "yaml.safe_load": re.compile(r"yaml\.safe_load\s*\("),
    "SafeLoader": re.compile(r"\bC?SafeLoader\b"),
    "defusedxml": re.compile(r"\bdefusedxml\b"),
    "resolve_external_entities=False": re.compile(
        r"resolve_entities\s*=\s*False|no_network\s*=\s*True"
    ),
    "html.escape": re.compile(r"(?:html|cgi)\.escape\s*\("),
    "markupsafe.escape": re.compile(r"markupsafe\.escape\s*\(|\bMarkup\s*\("),
    "autoescape=True": re.compile(r"autoescape\s*=\s*True"),
    "urllib quote": re.compile(r"urllib\.parse\.quote(?:_plus)?\s*\(|\bquote_plus\s*\("),
    "re.escape": re.compile(r"re\.escape\s*\("),
    "secure_filename": re.compile(r"\bsecure_filename\s*\("),
    "path realpath/resolve": re.compile(
        r"os\.path\.realpath\s*\(|os\.path\.abspath\s*\(|\.resolve\s*\(\s*\)"
    ),
    "path containment check": re.compile(
        r"os\.path\.commonpath\s*\(|\.is_relative_to\s*\(|\.relative_to\s*\("
    ),
    "allow_pickle=False": re.compile(r"allow_pickle\s*=\s*False"),
    "weights_only=True": re.compile(r"weights_only\s*=\s*True"),
    "hmac.compare_digest": re.compile(r"(?:hmac\.)?compare_digest\s*\("),
    "sanitizer helper": re.compile(
        r"\b(?:sanitiz|sanitis|escape_|_escape|is_safe|validate_)\w*\s*\("
    ),
    "allow-list": re.compile(r"\b(?:allow_?list|white_?list|ALLOWED_\w+|VALID_\w+)\b"),
    "auth guard": re.compile(
        r"@(?:login_required|permission_required|requires?_auth\w*)"
        r"|\babort\s*\(\s*40[13]\b|\braise\s+(?:PermissionDenied|Forbidden)\b"
    ),
}

# ---------------------------------------------------------------------------
# git invocation hardening. A repository is untrusted input, and several git
# settings make git EXECUTE a program the repository names. `-c` on the command
# line outranks the repo's own `.git/config`, so these overrides hold even for a
# hostile target.
#
# Note what is deliberately absent: `safe.directory`. If git refuses to open a
# repo because of ownership, that refusal is a real protection against exactly
# this threat model, so it is reported as a `git_error` rather than overridden.
# ---------------------------------------------------------------------------
_GIT_SAFE_CONFIG: tuple[str, ...] = (
    "-c", "core.fsmonitor=",       # repo-set fsmonitor is an executable git runs
    "-c", "diff.external=",        # diff.external runs a program per diff
    "-c", "core.pager=cat",        # never hand output to a repo-chosen pager
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.quotepath=false",  # keep non-ASCII paths literal, not \NNN-escaped
    "-c", "protocol.ext.allow=never",
)

# Applied to every diff-producing command, for the same reason.
_GIT_SAFE_DIFF: tuple[str, ...] = ("--no-ext-diff", "--no-textconv", "--no-color")

_GIT_SAFE_ENV: dict[str, str] = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",   # never block on a credential prompt
    "GIT_OPTIONAL_LOCKS": "0",    # do not take locks: we are strictly a reader
    "GIT_PAGER": "cat",
    "GIT_EXTERNAL_DIFF": "",
}

# Directories that are never the target's own first-party source. `git ls-files`
# already excludes ignored paths, but plenty of repos commit their vendor tree.
_SKIP_DIR_PARTS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".tox", "vendor", "third_party", "thirdparty", "site-packages", ".mypy_cache",
    ".pytest_cache", "testdata", "fixtures",
})

# ASCII unit / record separators used to frame `git log` output. Chosen because
# git never emits them itself and a commit message realistically never contains
# them; a record that does not parse is skipped, never guessed at.
_US = "\x1f"
_RS = "\x1e"

_CONTROL_RX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS_RX = re.compile(r"\s+")
_HEX40_RX = re.compile(r"^[0-9a-f]{40}$")
_HUNK_RX = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@(.*)$")

# Only files in a language that HAS a sink table can produce a hit, so the diff
# pass is bounded by a pathspec built from exactly those extensions.
_SINK_EXTS: tuple[str, ...] = tuple(sorted(
    ext for ext, lang in EXT_TO_LANG.items() if lang in SINKS_BY_LANG
))
_SINK_PATHSPECS: tuple[str, ...] = tuple(f"*{ext}" for ext in _SINK_EXTS)


class ContractViolation(Exception):
    """A caller error the skill must not route around — surfaces as exit 2."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Commit:
    """One security-language commit, metadata only."""

    sha: str
    date: str
    subject: str
    keywords: tuple[str, ...]

    @property
    def short(self) -> str:
        return self.sha[:7]


@dataclass
class Hunk:
    """One `@@ ... @@` block. `added` carries new-file line numbers because a
    sibling search reports positions the hunter can open; `removed` does not,
    since those lines no longer exist anywhere."""

    new_start: int
    heading: str
    added: list[tuple[int, str]] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    context: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class FileChange:
    """One file's slice of a commit's diff."""

    path: str
    old_path: str | None
    status: str  # added | modified | deleted | renamed
    hunks: list[Hunk] = field(default_factory=list)


@dataclass
class SinkTouch:
    """The aggregate of what one commit did to one attack class in one file.

    This, not the raw diff, is what a hit is built from — a patch that edits the
    same sink across four hunks is one statement about the codebase, not four.
    """

    attack_class: str
    lang: str
    patterns: set[re.Pattern[str]] = field(default_factory=set)
    idioms: set[str] = field(default_factory=set)
    guards: set[str] = field(default_factory=set)
    functions: list[str] = field(default_factory=list)
    added_samples: list[str] = field(default_factory=list)
    removed_samples: list[str] = field(default_factory=list)
    in_added: bool = False
    in_removed: bool = False
    guarded_context: bool = False

    @property
    def kind(self) -> str:
        """How to read this change, most informative label first.

        `hardened` is the one that matters: a defence appeared beside a sink.
        `sink_removed` is the `yaml.load` → `yaml.safe_load` shape — the
        dangerous call left and nothing dangerous replaced it. `sink_added`
        records the uncomfortable case of a commit whose message claims a
        security fix while introducing a sink; it is reported, never hidden.
        """
        if self.guards:
            return "hardened"
        if self.in_removed and not self.in_added:
            return "sink_removed"
        if self.in_added and not self.in_removed:
            return "sink_added"
        return "sink_modified"


# ---------------------------------------------------------------------------
# Hostile-text handling
# ---------------------------------------------------------------------------
def _sanitize(text: str, limit: int) -> str:
    """Render repo-authored text safe to embed in JSON a model will read.

    Control characters go (they can forge the separators used to frame git
    output and confuse anything downstream that renders the string), whitespace
    runs collapse to one space so a subject cannot become ten lines of
    instructions, and backticks become apostrophes so the text cannot open a
    code fence in a markdown-rendering phase. Then a hard length cap.

    This is a containment measure, not a trust decision: the phases that consume
    these strings must still treat them as untrusted quotations.
    """
    cleaned = _CONTROL_RX.sub(" ", text or "")
    cleaned = cleaned.replace("`", "'")
    cleaned = _WS_RX.sub(" ", cleaned).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 3].rstrip() + "..."
    return cleaned


# ---------------------------------------------------------------------------
# git plumbing — read-only
# ---------------------------------------------------------------------------
def git_available() -> bool:
    return shutil.which("git") is not None


def _git(repo: Path, *args: str, timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Run one read-only git command in `repo`.

    Never `shell=True`; argv is always a fixed list, so no repo-authored string
    can ever become a token of a command line. `_GIT_SAFE_CONFIG` is injected
    ahead of the subcommand so the repository's own config cannot make git
    execute a program on our behalf.
    """
    env = dict(os.environ)
    env.update(_GIT_SAFE_ENV)
    return subprocess.run(
        ["git", "-C", str(repo), *_GIT_SAFE_CONFIG, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
        check=False,
    )


def is_git_repo(repo: Path) -> bool:
    try:
        return _git(repo, "rev-parse", "--git-dir").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def is_shallow(repo: Path) -> bool:
    """A shallow clone answers `--grep` only over the commits it actually has.
    Callers need this to know an empty result may be an artefact of the clone."""
    try:
        proc = _git(repo, "rev-parse", "--is-shallow-repository")
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def has_commits(repo: Path) -> bool:
    try:
        return _git(repo, "rev-parse", "--verify", "--quiet", "HEAD").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def resolve_ref(repo: Path, ref: str) -> str | None:
    """Resolve `ref` to a commit sha, or None. Refs starting with `-` are
    rejected before git sees them: a ref is positional, and one that looks like
    a flag would be parsed as one."""
    if not ref or ref.startswith("-"):
        return None
    try:
        proc = _git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() or None if proc.returncode == 0 else None


def _matched_keywords(text: str) -> tuple[str, ...]:
    """Which keyword fragments fired, for the record. Recomputed in Python
    rather than inferred from git, so the output says what actually matched."""
    return tuple(kw for kw, rx in _KEYWORD_RX if rx.search(text))


def list_security_commits(
    repo: Path,
    *,
    since_ref: str | None = None,
    max_commits: int = DEFAULT_MAX_COMMITS,
) -> tuple[list[Commit], bool, list[str]]:
    """Metadata-only pass: every non-merge commit whose message uses
    security-patch language.

    Returns `(commits, truncated, notes)`. Metadata only — subjects and bodies
    are tiny, so this pass stays cheap even over a long history, and the
    expensive diff pass is bounded separately.

    Deliberately no pathspec here: a pathspec switches `git log` into history
    simplification, which can prune commits that genuinely touched the tree. The
    diff pass narrows by path instead, where doing so cannot lose a commit.
    """
    notes: list[str] = []
    fmt = f"--format={_RS}%H{_US}%aI{_US}%s{_US}%b"
    args = [
        "log", "--no-merges", "-i", "-E", f"--grep={GREP_PATTERN}",
        f"-n{max_commits + 1}", fmt,
    ]
    if since_ref:
        args.append(f"{since_ref}..HEAD")

    try:
        proc = _git(repo, *args)
    except subprocess.TimeoutExpired:
        return [], False, [f"git log timed out after {GIT_TIMEOUT}s; no commits mined"]
    except (OSError, subprocess.SubprocessError) as exc:
        return [], False, [f"git log failed: {type(exc).__name__}"]

    if proc.returncode != 0:
        return [], False, [f"git log exited {proc.returncode}: {_sanitize(proc.stderr, 200)}"]

    commits: list[Commit] = []
    malformed = 0
    for record in proc.stdout.split(_RS):
        if not record.strip():
            continue
        parts = record.split(_US, 3)
        if len(parts) < 3:
            malformed += 1
            continue
        sha, date, subject = parts[0].strip(), parts[1].strip(), parts[2]
        body = parts[3] if len(parts) > 3 else ""
        # A repo-authored message could embed our record separator and forge a
        # record. A forged one cannot survive this: the sha must be real hex.
        if not _HEX40_RX.match(sha):
            malformed += 1
            continue
        commits.append(Commit(
            sha=sha,
            date=date,
            subject=_sanitize(subject, _MAX_SUBJECT),
            keywords=_matched_keywords(f"{subject}\n{body}"),
        ))

    if malformed:
        notes.append(
            f"{malformed} git log record(s) did not parse and were skipped "
            f"(separator characters in a commit message)"
        )

    truncated = len(commits) > max_commits
    if truncated:
        commits = commits[:max_commits]
    return commits, truncated, notes


def _commit_patches(repo: Path, shas: list[str]) -> tuple[dict[str, list[FileChange]], list[str]]:
    """Diff-parse the given commits in ONE `git show`.

    One subprocess for N commits rather than N: over a couple of hundred commits
    that is the difference between a recon step and a coffee break. Bounded by a
    pathspec restricted to languages that have a sink table, which is also the
    only thing that keeps the captured output to a sane size on a repo with big
    generated assets.
    """
    notes: list[str] = []
    if not shas:
        return {}, notes

    fmt = f"--format={_RS}%H{_US}%aI{_US}%s{_US}"
    args = [
        "show", *_GIT_SAFE_DIFF, "--patch", "--unified=3",
        "--find-renames", "--no-notes", fmt, *shas, "--", *_SINK_PATHSPECS,
    ]
    try:
        proc = _git(repo, *args)
    except subprocess.TimeoutExpired:
        return {}, [f"git show timed out after {GIT_TIMEOUT}s; no diffs parsed"]
    except (OSError, subprocess.SubprocessError) as exc:
        return {}, [f"git show failed: {type(exc).__name__}"]

    if proc.returncode != 0:
        return {}, [f"git show exited {proc.returncode}: {_sanitize(proc.stderr, 200)}"]

    out: dict[str, list[FileChange]] = {}
    for record in proc.stdout.split(_RS):
        if not record.strip():
            continue
        parts = record.split(_US, 3)
        if len(parts) < 4 or not _HEX40_RX.match(parts[0].strip()):
            continue
        out[parts[0].strip()] = parse_diff(parts[3])
    return out, notes


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------
def _unquote_path(raw: str) -> str:
    """Undo git's C-style path quoting.

    `core.quotepath=false` (see `_GIT_SAFE_CONFIG`) already stops git quoting
    non-ASCII, so what remains is the rare path containing a quote, tab, or
    newline. `json.loads` handles exactly those escapes; anything it cannot
    parse degrades to the literal text rather than raising.
    """
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return raw[1:-1]
    return raw


def _strip_prefix(path: str) -> str:
    """Drop git's `a/` or `b/` diff prefix."""
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def parse_diff(patch: str) -> list[FileChange]:
    """Parse a unified diff into per-file, per-hunk structure.

    Hand-rolled rather than delegated because the payload needs three things a
    line-oriented grep over the diff cannot give: the new-file line number of
    each added line (so a sibling report can cite a position), the hunk's section
    heading (git's guess at the enclosing function, free of charge), and the
    context lines of a hunk (so a `shlex.quote` added beside an *unchanged*
    `subprocess.run(` line is still recognised as hardening that sink).

    Never raises on malformed input: a diff we cannot read yields fewer hits,
    which is a smaller failure than an exception taking the run down.
    """
    files: list[FileChange] = []
    current: FileChange | None = None
    hunk: Hunk | None = None
    new_line = 0
    pending_old: str | None = None

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            current, hunk, pending_old = None, None, None
            continue

        if line.startswith("--- "):
            raw = line[4:].strip()
            pending_old = None if raw == "/dev/null" else _strip_prefix(_unquote_path(raw))
            continue

        if line.startswith("+++ "):
            raw = line[4:].strip()
            if raw == "/dev/null":
                # Deletion. The removed lines still name the idiom that was
                # excised, and its siblings elsewhere are exactly the point.
                if pending_old is None:
                    current = None
                    continue
                current = FileChange(path=pending_old, old_path=pending_old, status="deleted")
            else:
                new_path = _strip_prefix(_unquote_path(raw))
                if pending_old is None:
                    status = "added"
                elif pending_old != new_path:
                    status = "renamed"
                else:
                    status = "modified"
                current = FileChange(path=new_path, old_path=pending_old, status=status)
            files.append(current)
            hunk = None
            continue

        if current is None:
            continue

        m = _HUNK_RX.match(line)
        if m:
            new_line = int(m.group(1))
            hunk = Hunk(new_start=new_line, heading=_sanitize(m.group(3), 120))
            current.hunks.append(hunk)
            continue

        if hunk is None:
            continue

        if line.startswith("+"):
            hunk.added.append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-"):
            hunk.removed.append(line[1:])
        elif line.startswith("\\"):
            continue  # "\ No newline at end of file"
        else:
            # A context line; also covers the empty string git emits for a blank
            # context line, which has no leading space. Line numbers are kept so
            # a guard can only be credited to a sink it actually sits beside.
            hunk.context.append((new_line, line[1:] if line.startswith(" ") else line))
            new_line += 1

    return [f for f in files if f.hunks]


# ---------------------------------------------------------------------------
# Sink / guard matching
# ---------------------------------------------------------------------------
def language_of(path: str) -> str | None:
    return EXT_TO_LANG.get(PurePosixPath(path).suffix.lower())


def sink_table_for(path: str) -> tuple[str, dict[str, list[re.Pattern[str]]]] | None:
    """`(language, table)` for a path, or None when we have no table for it."""
    lang = language_of(path)
    if lang and lang in SINKS_BY_LANG:
        return lang, SINKS_BY_LANG[lang]
    return None


def match_sink(line: str, table: dict[str, list[re.Pattern[str]]]) -> tuple[str, re.Pattern[str], str] | None:
    """First matching `(attack_class, pattern, matched_text)` for a line.

    First-class-wins mirrors `taint.find_sinks`, so one dangerous line yields at
    most one class here too — otherwise the same line would be counted once per
    overlapping table entry and inflate every total downstream.
    """
    for attack_class, patterns in table.items():
        for pattern in patterns:
            m = pattern.search(line)
            if m:
                return attack_class, pattern, m.group(0)
    return None


def guards_in(lines: list[str]) -> set[str]:
    return {name for name, rx in SECURITY_GUARDS.items() if any(rx.search(ln) for ln in lines)}


def analyse_file_change(change: FileChange) -> dict[str, SinkTouch]:
    """Reduce one file's diff to `attack_class -> SinkTouch`.

    Guards are computed per hunk as *added minus removed*: a `shlex.quote` that
    was already on both sides of the diff is pre-existing code that happened to
    move, not a defence this commit introduced. Only when a hunk genuinely added
    a guard do its context lines get scanned for sinks — that is what catches the
    canonical shape where the patch adds `shlex.quote(name)` and leaves the
    `subprocess.run(...)` line itself untouched.

    That context scan is confined to `_GUARD_CONTEXT_WINDOW` lines around the
    added guard. Without the window a hunk that hardens a `subprocess` call also
    credits itself with hardening an unrelated `yaml.load` three lines further
    down, which is how a precise miner quietly turns into a noisy one.
    """
    table_info = sink_table_for(change.path)
    if table_info is None:
        return {}
    lang, table = table_info

    touches: dict[str, SinkTouch] = {}

    def touch(attack_class: str) -> SinkTouch:
        return touches.setdefault(attack_class, SinkTouch(attack_class=attack_class, lang=lang))

    for hunk in change.hunks:
        # A guard present on both sides of the diff is pre-existing code that
        # moved, not a defence this commit introduced. Guard LINE NUMBERS are
        # kept so an unchanged sink can only inherit a guard it sits next to.
        removed_guards = guards_in(hunk.removed)
        hunk_guards: set[str] = set()
        guard_lines: list[int] = []
        for lineno, text in hunk.added:
            fired = {n for n, rx in SECURITY_GUARDS.items() if rx.search(text)} - removed_guards
            if fired:
                hunk_guards |= fired
                guard_lines.append(lineno)

        for _, text in hunk.added:
            hit = match_sink(text, table)
            if hit is None:
                continue
            attack_class, pattern, matched = hit
            t = touch(attack_class)
            t.in_added = True
            t.patterns.add(pattern)
            t.idioms.add(_sanitize(matched, _MAX_IDIOM))
            if len(t.added_samples) < _MAX_DIFF_SAMPLES:
                t.added_samples.append(_sanitize(text.strip(), _MAX_SNIPPET))

        for text in hunk.removed:
            hit = match_sink(text, table)
            if hit is None:
                continue
            attack_class, pattern, matched = hit
            t = touch(attack_class)
            t.in_removed = True
            t.patterns.add(pattern)
            t.idioms.add(_sanitize(matched, _MAX_IDIOM))
            if len(t.removed_samples) < _MAX_DIFF_SAMPLES:
                t.removed_samples.append(_sanitize(text.strip(), _MAX_SNIPPET))

        if guard_lines:
            for lineno, text in hunk.context:
                near = any(abs(lineno - g) <= _GUARD_CONTEXT_WINDOW for g in guard_lines)
                if not near:
                    continue
                hit = match_sink(text, table)
                if hit is None:
                    continue
                attack_class, pattern, matched = hit
                t = touch(attack_class)
                t.guarded_context = True
                t.patterns.add(pattern)
                t.idioms.add(_sanitize(matched, _MAX_IDIOM))

        for attack_class in list(touches):
            t = touches[attack_class]
            if hunk_guards and (t.in_added or t.in_removed or t.guarded_context):
                t.guards |= hunk_guards
            if hunk.heading and hunk.heading not in t.functions:
                t.functions.append(hunk.heading)

    return touches


# ---------------------------------------------------------------------------
# The payload: unpatched siblings
# ---------------------------------------------------------------------------
def tracked_source_files(repo: Path) -> tuple[list[str], list[str]]:
    """Tracked files in a language that has a sink table.

    `git ls-files` rather than a filesystem walk: it is the repo's own answer to
    "what is my source", so ignored build output, caches, and virtualenvs are
    excluded for free.
    """
    notes: list[str] = []
    try:
        proc = _git(repo, "ls-files", "-z", "--cached")
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return [], [f"git ls-files failed: {type(exc).__name__}; sibling sweep skipped"]
    if proc.returncode != 0:
        return [], [f"git ls-files exited {proc.returncode}; sibling sweep skipped"]

    out: list[str] = []
    for rel in proc.stdout.split("\0"):
        if not rel:
            continue
        parts = PurePosixPath(rel).parts
        if _SKIP_DIR_PARTS.intersection(parts):
            continue
        if language_of(rel) in SINKS_BY_LANG:
            out.append(rel)

    if len(out) > _MAX_TRACKED_FILES:
        notes.append(
            f"repo has {len(out)} tracked source files; sibling sweep limited to the "
            f"first {_MAX_TRACKED_FILES} in git order"
        )
        out = out[:_MAX_TRACKED_FILES]
    return out, notes


def _guard_nearby(lines: list[str], lineno: int) -> bool:
    """Whether a hardening idiom sits within `_GUARD_WINDOW` lines of a site.

    A hint for ranking only. It never removes a sibling: nothing in this module
    deletes a candidate, because "there is a guard two lines away" is not the
    same fact as "this call site is safe".
    """
    lo = max(0, lineno - 1 - _GUARD_WINDOW)
    hi = min(len(lines), lineno + _GUARD_WINDOW)
    window = lines[lo:hi]
    return any(rx.search(ln) for rx in SECURITY_GUARDS.values() for ln in window)


def scan_sibling_sites(
    repo: Path,
    tracked: list[str],
    wanted: dict[tuple[str, str], re.Pattern[str]],
) -> tuple[dict[tuple[str, str], list[dict]], list[str]]:
    """One sweep of the working tree for every idiom any patch touched.

    Keyed `(language, pattern) -> sites`. Collecting every idiom in a single
    pass matters: the alternative is re-reading the whole tree once per hit,
    which on a large repo is quadratic in something the operator did not choose.

    The working tree, not HEAD, is read — it is what the hunter will open, and a
    site that only exists in HEAD is not a site the hunter can hunt.
    """
    notes: list[str] = []
    sites: dict[tuple[str, str], list[dict]] = {k: [] for k in wanted}
    if not wanted:
        return sites, notes

    by_lang: dict[str, list[tuple[tuple[str, str], re.Pattern[str]]]] = {}
    for key, pattern in wanted.items():
        by_lang.setdefault(key[0], []).append((key, pattern))

    unreadable = 0
    for rel in tracked:
        lang = language_of(rel)
        candidates = by_lang.get(lang or "")
        if not candidates:
            continue
        path = repo / rel
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unreadable += 1
            continue

        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for key, pattern in candidates:
                bucket = sites[key]
                if len(bucket) >= _MAX_SITES_PER_PATTERN:
                    continue
                if pattern.search(line):
                    bucket.append({
                        "file": rel,
                        "line": lineno,
                        "snippet": _sanitize(line.strip(), _MAX_SNIPPET),
                        "guard_nearby": _guard_nearby(lines, lineno),
                    })

    if unreadable:
        notes.append(f"{unreadable} tracked file(s) could not be read during the sibling sweep")
    return sites, notes


# ---------------------------------------------------------------------------
# Hits and tasks
# ---------------------------------------------------------------------------
def build_hits(
    commits: list[Commit],
    diffs: dict[str, list[FileChange]],
) -> list[dict]:
    """One hit per `(commit, file, attack_class)` the patch actually touched.

    Emitted in `git log` order (newest first) and, within a commit, in diff
    order — so two runs at the same commit produce byte-identical output. That
    determinism is the whole reason this replaced an agent.
    """
    hits: list[dict] = []
    for commit in commits:
        for change in diffs.get(commit.sha, []):
            for attack_class, touch in sorted(analyse_file_change(change).items()):
                hits.append({
                    "commit": commit.sha,
                    "short_commit": commit.short,
                    "date": commit.date,
                    "subject": commit.subject,
                    "matched_keywords": list(commit.keywords),
                    "file": change.path,
                    "file_status": change.status,
                    "language": touch.lang,
                    "sink": attack_class,
                    "sink_patterns": sorted(p.pattern for p in touch.patterns),
                    "idioms": sorted(touch.idioms),
                    "change": {
                        "kind": touch.kind,
                        "guards_added": sorted(touch.guards),
                        "sink_in_added": touch.in_added,
                        "sink_in_removed": touch.in_removed,
                        "sink_in_guarded_context": touch.guarded_context,
                        "functions": touch.functions[:_MAX_DIFF_SAMPLES],
                        "added_lines": touch.added_samples,
                        "removed_lines": touch.removed_samples,
                    },
                    # Filled in by attach_siblings; kept here so a hit always has
                    # the key even when the sibling sweep could not run.
                    "unpatched_siblings": [],
                    "sibling_count": 0,
                    "siblings_truncated": False,
                    "_patterns": sorted((touch.lang, p.pattern) for p in touch.patterns),
                })
    return hits


def attach_siblings(hits: list[dict], sites: dict[tuple[str, str], list[dict]]) -> None:
    """Attach, to each hit, the call sites of its idiom that the patch missed.

    The patched file is excluded wholesale, following the recon prompt's rule
    ("do not re-test the already-patched file — look for siblings"). It is also
    the sound choice: the diff's line numbers belong to the commit's version of
    the file, so re-deriving which of *today's* lines that patch covered would be
    guesswork wearing a line number.
    """
    for hit in hits:
        patched_file = hit["file"]
        seen: set[tuple[str, int]] = set()
        siblings: list[dict] = []
        total = 0
        for key in hit["_patterns"]:
            for site in sites.get(tuple(key), []):
                if site["file"] == patched_file:
                    continue
                ident = (site["file"], site["line"])
                if ident in seen:
                    continue
                seen.add(ident)
                total += 1
                if len(siblings) < _MAX_SIBLINGS_PER_HIT:
                    siblings.append(site)
        hit["unpatched_siblings"] = siblings
        hit["sibling_count"] = total
        hit["siblings_truncated"] = total > len(siblings)


def build_history_tasks(hits: list[dict], *, max_tasks: int = DEFAULT_MAX_TASKS) -> list[dict]:
    """Turn hits with surviving siblings into hunt tasks.

    Deduped on `(attack_class, sibling sites)`: three commits that hardened the
    same idiom describe one unpatched surface, not three, and emitting it three
    times would spend three Validate budgets to learn one thing.

    `source` is `"recon"` because that is what `hunt_task.schema.json` allows
    today — history mining feeds recon (PLAN.md §6 step 6). If the schema later
    grows a `"history"` value, this constant is the only line that changes.
    """
    tasks: list[dict] = []
    seen: set[tuple[str, tuple]] = set()

    for hit in hits:
        siblings = hit["unpatched_siblings"]
        if not siblings:
            continue
        key = (hit["sink"], tuple(sorted((s["file"], s["line"]) for s in siblings)))
        if key in seen:
            continue
        seen.add(key)

        files: list[str] = []
        for site in siblings:
            if site["file"] not in files:
                files.append(site["file"])
        files = files[:_MAX_TASK_FILES]

        idiom = ", ".join(hit["idioms"][:3]) or hit["sink"]
        guards = ", ".join(hit["change"]["guards_added"])
        defence = f" The patch added: {guards}." if guards else ""
        located = "; ".join(f"{s['file']}:{s['line']}" for s in siblings[:8])
        more = "" if len(siblings) <= 8 else f" (+{hit['sibling_count'] - 8} more)"

        tasks.append({
            "task_id": f"t_hist_{len(tasks) + 1:02d}",
            "source": _TASK_SOURCE,
            "attack_class": hit["sink"],
            "target_files": files,
            "scope_hint": _sanitize(
                f"Commit {hit['short_commit']} ({hit['date'][:10]}) — untrusted subject: "
                f"\"{hit['subject']}\" — {hit['change']['kind']} the {hit['sink']} idiom "
                f"{idiom} in {hit['file']}.{defence} {hit['sibling_count']} call site(s) of "
                f"the same idiom were NOT touched by that patch: {located}{more}. For each, "
                f"trace whether attacker-controlled data reaches it without the defence the "
                f"patch introduced.",
                1200,
            ),
            "rationale": _sanitize(
                f"This project already fixed {hit['sink']} at {hit['file']} in commit "
                f"{hit['short_commit']}, so the maintainers agree the idiom {idiom} is "
                f"dangerous here. The listed sites use the same idiom and were never "
                f"patched. Deterministic git-history mining, not model inference: same "
                f"commit range, same result.",
                1200,
            ),
            "priority": 2,
        })
        if len(tasks) >= max_tasks:
            break
    return tasks


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def _empty_payload(repo: Path, status: str, reason: str, **extra) -> dict:
    """A well-formed result for every non-`ok` outcome.

    Same keys as a successful mine, so a consumer never has to branch on shape —
    only on `status`. An absent git binary and a repo with no security commits
    are different facts and get different statuses; neither is an error.
    """
    payload = {
        "schema": SCHEMA_ID,
        "status": status,
        "reason": reason,
        "repo": str(repo),
        "since": None,
        "shallow": False,
        "limits": {
            "max_commits": DEFAULT_MAX_COMMITS,
            "max_patches": DEFAULT_MAX_PATCHES,
            "max_tasks": DEFAULT_MAX_TASKS,
        },
        "commits_matched": 0,
        "commits_analysed": 0,
        "truncated": False,
        "truncation_reason": "",
        "notes": [],
        "patches": [],
        "tasks": [],
        "totals": {"patches": 0, "with_siblings": 0, "siblings": 0, "tasks": 0},
    }
    payload.update(extra)
    return payload


def mine(
    repo: Path,
    *,
    since: str | None = None,
    max_commits: int = DEFAULT_MAX_COMMITS,
    max_patches: int = DEFAULT_MAX_PATCHES,
    max_tasks: int = DEFAULT_MAX_TASKS,
) -> dict:
    """Mine `repo` for security patches and the siblings they left behind.

    Never raises for an unusable repository. Every way this can come back empty
    — no git, no `.git`, no commits, no security-language commits, a shallow
    clone that does not reach far enough — is a distinct `status`/`reason`, so a
    barren result can always be told apart from a broken one. That distinction is
    the same discipline the execution gate applies to findings: a thing that did
    not happen and a thing that could not be attempted are different facts.
    """
    repo = Path(repo)
    if not repo.is_dir():
        raise ContractViolation(f"--repo is not a directory: {repo}")

    if not git_available():
        return _empty_payload(repo, "git_absent", "git binary not found on PATH")
    if not is_git_repo(repo):
        return _empty_payload(repo, "not_a_repo", f"no git repository at {repo}")
    if not has_commits(repo):
        return _empty_payload(repo, "no_history", "repository has no commits (unborn HEAD)")

    shallow = is_shallow(repo)
    notes: list[str] = []
    if shallow:
        notes.append(
            "shallow clone: history is truncated by the clone itself, so an empty or "
            "small result is not evidence that no security patches exist"
        )

    since_ref: str | None = None
    if since:
        since_ref = resolve_ref(repo, since)
        if since_ref is None:
            raise ContractViolation(f"--since ref does not resolve to a commit: {since!r}")

    commits, cap_hit, log_notes = list_security_commits(
        repo, since_ref=since_ref, max_commits=max_commits
    )
    notes.extend(log_notes)

    payload = _empty_payload(repo, "ok", "")
    payload.update({
        "since": since,
        "since_resolved": since_ref,
        "shallow": shallow,
        "limits": {
            "max_commits": max_commits,
            "max_patches": max_patches,
            "max_tasks": max_tasks,
        },
        "commits_matched": len(commits),
        "keyword_count": len(SECURITY_COMMIT_KEYWORDS),
    })

    truncation: list[str] = []
    if cap_hit:
        truncation.append(
            f"more than max_commits ({max_commits}) commits matched the security keyword "
            f"filter; only the {max_commits} most recent were considered"
        )

    if not commits:
        payload["reason"] = "no commits matched the security-patch keyword filter"
        payload["notes"] = notes
        return payload

    analysed = commits[:max_patches]
    if len(commits) > max_patches:
        truncation.append(
            f"{len(commits)} matched commits exceeded max_patches ({max_patches}); only the "
            f"{max_patches} most recent had their diffs parsed"
        )

    diffs, show_notes = _commit_patches(repo, [c.sha for c in analysed])
    notes.extend(show_notes)

    hits = build_hits(analysed, diffs)

    tracked, ls_notes = tracked_source_files(repo)
    notes.extend(ls_notes)

    wanted: dict[tuple[str, str], re.Pattern[str]] = {}
    for hit in hits:
        for lang, pattern_str in hit["_patterns"]:
            wanted.setdefault((lang, pattern_str), re.compile(pattern_str))

    sites, scan_notes = scan_sibling_sites(repo, tracked, wanted)
    notes.extend(scan_notes)
    attach_siblings(hits, sites)

    for hit in hits:
        hit.pop("_patterns", None)

    tasks = build_history_tasks(hits, max_tasks=max_tasks)
    with_siblings = sum(1 for h in hits if h["unpatched_siblings"])

    payload.update({
        "commits_analysed": len(analysed),
        "truncated": bool(truncation),
        "truncation_reason": "; ".join(truncation),
        "notes": notes,
        "patches": hits,
        "tasks": tasks,
        "totals": {
            "patches": len(hits),
            "with_siblings": with_siblings,
            "siblings": sum(h["sibling_count"] for h in hits),
            "tasks": len(tasks),
        },
    })
    if not hits:
        payload["reason"] = (
            f"{len(analysed)} security-language commit(s) examined; none touched a line "
            f"matching the sink tables"
        )
    return payload


def _atomic_write_json(path: Path, doc: object) -> None:
    """Write via a sibling temp file + `os.replace`, so a crash mid-write cannot
    leave a half-written results file that later parses as truth."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def write_results(results_dir: Path, payload: dict) -> list[str]:
    """Persist into the run's results directory.

    Two files, on purpose. `inputs.json["history"]` is the list the results
    contract specifies (`{inputs:[...], history:[...]}`), so phase 1's consumer
    finds what it was promised. `logs/history.json` beside it keeps the full
    payload — status, truncation, notes, tasks — because a list of hits alone
    cannot say "I was truncated", and a truncated mine that looks exhaustive is
    exactly the dishonesty this project treats as a release gate.

    **The path is `logs/history.json`, and it was `history.json` for one
    release too long.** `tasks.py:gen_history` reads `logs/history.json` and
    `phase1_recon.md` step 1 tells the recon agent to read the same path; this
    function wrote to the results-directory root, so neither found it. The
    consequences were not loud: `tasks.py` recorded
    `history: {"status": "skipped:no_history_file"}` and carried on, so a real
    scan of datamodel-code-generator mined 69 commits, emitted 18 hunt tasks,
    and queued **none** of them — while the run still reported success. History
    mining is one of this design's differentiators and it was contributing
    nothing.

    `inputs.json` is merged, never replaced. If it exists but does not parse, we
    refuse rather than overwrite: silently discarding phase 1's inventory would
    take the coverage ledger with it.
    """
    if not results_dir.is_dir():
        raise ContractViolation(f"--results-dir is not a directory: {results_dir}")

    written: list[str] = []
    logs_dir = results_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    history_path = logs_dir / "history.json"
    _atomic_write_json(history_path, payload)
    written.append(str(history_path))

    inputs_path = results_dir / "inputs.json"
    doc: dict = {"inputs": []}
    if inputs_path.exists():
        try:
            loaded = json.loads(inputs_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ContractViolation(
                f"{inputs_path} exists but could not be read as JSON ({exc}); refusing to "
                f"overwrite it — the input inventory would be lost"
            ) from exc
        if not isinstance(loaded, dict):
            raise ContractViolation(
                f"{inputs_path} is not a JSON object; refusing to overwrite it"
            )
        doc = loaded
        doc.setdefault("inputs", [])

    doc["history"] = payload["patches"]
    _atomic_write_json(inputs_path, doc)
    written.append(str(inputs_path))
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="history.py",
        description="Mine a target repository's git history for past security patches "
                    "and the unpatched sibling call sites they left behind.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    mine_p = sub.add_parser("mine", help="mine security patches and unpatched siblings")
    mine_p.add_argument("--repo", required=True, help="path to the target repository")
    mine_p.add_argument("--since", default=None,
                        help="only consider commits after this ref (REF..HEAD)")
    mine_p.add_argument("--max-commits", type=int, default=DEFAULT_MAX_COMMITS,
                        help=f"cap on matched commits collected (default {DEFAULT_MAX_COMMITS})")
    mine_p.add_argument("--max-patches", type=int, default=DEFAULT_MAX_PATCHES,
                        help=f"cap on commits diff-parsed (default {DEFAULT_MAX_PATCHES})")
    mine_p.add_argument("--max-tasks", type=int, default=DEFAULT_MAX_TASKS,
                        help=f"cap on hunt tasks emitted (default {DEFAULT_MAX_TASKS})")
    mine_p.add_argument("--results-dir", default=None,
                        help="run results directory; writes history.json and merges "
                             "inputs.json['history']")
    return parser


def _validate_limits(args: argparse.Namespace) -> None:
    for name in ("max_commits", "max_patches", "max_tasks"):
        if getattr(args, name) < 1:
            raise ContractViolation(f"--{name.replace('_', '-')} must be >= 1")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _validate_limits(args)
        payload = mine(
            Path(args.repo).expanduser(),
            since=args.since,
            max_commits=args.max_commits,
            max_patches=args.max_patches,
            max_tasks=args.max_tasks,
        )
        if args.results_dir:
            written = write_results(Path(args.results_dir).expanduser(), payload)
            for path in written:
                print(f"wrote {path}", file=sys.stderr)

        print(json.dumps(payload, indent=2))
        totals = payload["totals"]
        print(
            f"status={payload['status']} commits_matched={payload['commits_matched']} "
            f"patches={totals['patches']} siblings={totals['siblings']} "
            f"tasks={totals['tasks']} truncated={payload['truncated']}",
            file=sys.stderr,
        )
        for note in payload["notes"]:
            print(f"note: {note}", file=sys.stderr)
        if payload["truncation_reason"]:
            print(f"truncated: {payload['truncation_reason']}", file=sys.stderr)
        return 0

    except ContractViolation as exc:
        print(json.dumps({"schema": SCHEMA_ID, "status": "contract_violation",
                          "reason": str(exc)}, indent=2))
        print(f"contract violation: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # internal error — exit 1, per the script contract
        print(json.dumps({"schema": SCHEMA_ID, "status": "error",
                          "reason": f"{type(exc).__name__}: {exc}"}, indent=2))
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
