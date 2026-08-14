"""The PoC run recipe and its runtime observer.

PyHunt does not merely *describe* an exploit — Hunt writes one and **runs it in
the sandbox**, and :mod:`pyhunt.oracle` then decides in Python whether it proved
anything.

Inherited from VASH, which carried five languages here. PyHunt is Python-only,
so this module is one :class:`Runtime` and one :class:`Observer`, and the four
deleted paths (node `--require` preload, Java Flight Recorder, `strace` for Go
and C#) took their whole class of "the toolchain is missing so we cannot judge"
failure modes with them. A Python target always has a Python interpreter.

* :data:`RUNTIMES` — how to run a PoC, and (the part that actually decides
  whether a PoC is worth anything) how to reach the **target's own
  dependencies**. A PoC that cannot import the target proves only that
  hello-world runs.
* :class:`Observer` — instrumentation that answers "did the vulnerable
  behaviour actually *fire*?" rather than "did the script exit 0?". A PoC can
  exit 0 because the sink swallowed an exception; a nonce-stamped
  `subprocess.Popen` audit event attributed to the target's own frame cannot.

**Honesty rule (load-bearing, not a nicety).** An observer is OPTIONAL. When its
output is absent the PoC still runs unwrapped, and **the absence of observer
evidence is never read as "the vulnerability did not reproduce"** — the gate
returns ``OBSERVER_ABSENT``, which leaves the finding exactly as the static
analysis left it. What changed from VASH is the other direction: the *presence*
of observer evidence is no longer judged by the model either. See
:mod:`pyhunt.oracle.gate`.

**Safety.** Nothing in this module executes anything. It produces command
*strings* and copies the observer helper into a scratch directory; the agent,
inside the sandbox (where `pyhunt.runner` has granted it Bash), is what runs
them. On a bare host Hunt has no Bash and these recipes are simply unused.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Observer assets live next to this module as real, readable files so they can
# be reviewed (and unit-tested) like any other source, not smuggled in as
# escaped string literals.
OBSERVER_DIR = Path(__file__).resolve().parent / "observers"

# Every marker line an observer prints starts with this, so a single grep
# separates instrumentation output from the PoC's own chatter.
from oracle.markers import MARKER  # single definition, shared with the gate
from oracle.nonce import (canary_path, ensure_durable_secret,
                          nonce_for, secret_is_durable)

# Appended to every Observer.notes. The wording is deliberately blunt: this is
# the one inference that would turn optional instrumentation into a source of
# false negatives.
_HONESTY = (
    "This observer is OPTIONAL instrumentation — run `available_check` first "
    "and, if it fails, run the PoC unwrapped and say so in the finding. "
    "The absence of observer evidence is NOT evidence that the vulnerability "
    "did not reproduce; only the PoC's own assertions decide that."
)


@dataclass(frozen=True)
class Observer:
    """Optional instrumentation that proves the vulnerable behaviour fired.

    `wrap` is a shell template containing ``{cmd}``; the agent substitutes the
    (already compiled) run command into it. Every observer here wraps via an
    environment prefix or a wrapper script rather than by editing the run
    command's internals, so `wrap.format(cmd=run_cmd)` is always a valid
    command line.

    `evidence_markers` are substrings whose *presence* in the combined output
    proves the behaviour fired. Their absence proves nothing (see the module
    docstring) — that asymmetry is the whole design.
    """

    name: str
    kind: str
    asset: str | None
    wrap: str
    evidence_markers: tuple[str, ...]
    available_check: str
    notes: str


@dataclass(frozen=True)
class Runtime:
    """How to build and run a PoC for one language, in the target's own env.

    `deps_hint` is the field that decides whether a PoC is meaningful: it tells
    the agent how to reach the TARGET's dependencies (classpath, node_modules,
    module context, installed package). It is prose because the answer is
    genuinely repo-shaped — the agent has Bash and can run the probe commands
    it names.
    """

    language: str
    poc_filename: str
    compile_cmd: str | None
    run_cmd: str
    observer: Observer | None
    deps_hint: str


# ─────────────────────────────────────────────────────────────────────────────
# Observers
# ─────────────────────────────────────────────────────────────────────────────

# Python: a real PEP-578 audit hook. Audit events are raised by CPython below
# the Python API, so they fire however the sink is reached — including from C
# extensions and pickle gadget chains, which a monkey-patch would miss.
PYTHON_AUDIT_HOOK = Observer(
    name="python-audit-hook",
    kind=("PEP-578 sys.addaudithook: CPython raises audit events for process "
          "spawn, file open, socket connect, exec/compile and pickle/marshal "
          "loads; the wrapper runs the PoC via runpy with the hook armed and "
          "prints one marker line per event. Optional instrumentation."),
    asset="pyhunt_audit_hook.py",
    # {observer} is substituted with the ABSOLUTE materialized asset path by
    # poc_execution_block. A relative name (or $PWD) breaks the moment the
    # agent follows deps_hint and `cd /target` — node/python then abort at
    # startup having never run the PoC, which reads as "no evidence".
    wrap='python3 {observer} {cmd} 2>&1',
    evidence_markers=(
        MARKER + " audit:subprocess.Popen",
        MARKER + " audit:os.system",
        MARKER + " audit:os.exec",
        MARKER + " audit:os.spawn",
        MARKER + " audit:open",
        MARKER + " audit:socket.connect",
        MARKER + " audit:exec",
        MARKER + " audit:compile",
        MARKER + " audit:pickle.find_class",
        MARKER + " audit:marshal.load",
        MARKER + " audit:ctypes.dlopen",
    ),
    available_check=(
        "python3 -c 'import sys; raise SystemExit(0 if hasattr(sys, \"addaudithook\") "
        "else 1)'"
    ),
    notes=(
        "Run from the scratch dir (the Hunt prompt already `cd $scratch_dir`), "
        "where materialize_observer wrote pyhunt_audit_hook.py. The wrapper "
        "tolerates a leading `python3` in {cmd} and strips it; `-c` and `-m` "
        "forms are NOT observable, use a script file. Markers go to stderr "
        "(the wrap already folds stderr into stdout). A `hook-armed` banner "
        "line proves the hook ran, which is how you tell 'observer saw "
        "nothing' apart from 'observer never ran'. Import-time noise (opening "
        ".py files, compiling the PoC itself) is filtered out on purpose. "
        "Each marker carries `<- from file:line in func` naming the code that "
        "caused the event (interpreter/stdlib frames are skipped): if it names "
        "the TARGET's file the vulnerable path really ran; if it names your PoC "
        "the PoC hit the sink directly and proves nothing about the target. " +
        _HONESTY
    ),
)





# Languages whose files are compiled or interpreted programs. A Hunt task
# scoped to one of these is a task about executable code, so "no runtime for it"
# means "PyHunt cannot prove this by execution" — not "use the repo's default".
# Deliberately excludes the markup/config/IaC values in EXT_TO_LANG
# (web-template, terraform, bicep, sql, ...), which are exactly the cases the
# repo-wide fallback exists to serve.
_EXECUTABLE_LANGUAGES = frozenset({
    "python", "javascript", "typescript", "java", "go", "csharp", "ruby",
    "php", "c-cpp", "rust", "kotlin", "scala", "swift", "objective-c",
    "perl", "shell", "powershell", "batch", "lua", "dart", "elixir",
    "erlang", "clojure", "groovy", "haskell", "ocaml", "fsharp", "vbnet",
    "julia", "r", "nim", "crystal", "zig", "solidity", "assembly",
    "abap", "cobol", "jcl",
})


# ─────────────────────────────────────────────────────────────────────────────
# Runtimes
# ─────────────────────────────────────────────────────────────────────────────

RUNTIMES: dict[str, Runtime] = {    "python": Runtime(
        language="python",
        poc_filename="poc.py",
        compile_cmd=None,
        run_cmd="python3 poc.py",
        observer=PYTHON_AUDIT_HOOK,
        deps_hint=(
            "Phase 2 provisioning pip-installs the target into the image "
            "(`pip install -e .` plus `-r requirements.txt`), so the target "
            "package is importable directly: `import <pkg>` works from any "
            "cwd. Confirm with `python3 -c 'import <pkg>, sys; "
            "print(<pkg>.__file__)'` before trusting a PoC. If the import "
            "fails (provisioning was skipped, or the repo is not installable), "
            "run with `PYTHONPATH=/target python3 poc.py` or `cd /target` "
            "first — and record in the finding that the PoC ran against the "
            "source tree rather than an installed distribution."
        ),
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Selection / materialization
# ─────────────────────────────────────────────────────────────────────────────

def runtime_for(languages: list[str],
                project_env: dict | None = None) -> Runtime | None:
    """Pick the Runtime for a Hunt task, or None when nothing matches.

    The TASK's own languages win. They come from `detect_languages(
    task.target_files)` — the actual files this hunt is about, and the file the
    sink lives in is the file the PoC must exploit. Letting the repo-wide
    `primary_language` outrank them handed a Hunt task that explicitly targets a
    `.java` sink in a Python-majority polyglot repo the Python recipe: `poc.py`,
    `python3`, and an audit hook that can never see a JVM.

    `project_env` (Phase 2's `ProvisionResult.agent_summary()`, which the agent
    already sees as `project_environment`) is the FALLBACK: repo-wide evidence
    for when the task's own files say nothing useful — a task scoped to a
    template, a config file, or a language Phase 3 does not cover.

    Returning None is a normal outcome (COBOL, templates, a language Phase 3
    does not cover). Callers must degrade to a static, unexecuted PoC.
    """
    for lang in languages or ():
        rt = RUNTIMES.get(lang)
        if rt is not None:
            return rt

    # A task whose files ARE code, in a language with no runtime, must get no
    # recipe. Falling through to the repo's primary language would hand a task
    # about a `.java` sink `poc.py` and an audit hook that can never see a JVM —
    # a PoC that cannot fail informatively, because it was never pointed at the
    # code under test. VASH avoided this by shipping a Java runtime; PyHunt is
    # Python-only, so it has to be said out loud instead.
    if any(lang in _EXECUTABLE_LANGUAGES for lang in (languages or ())):
        return None

    # Reaching here means the task's files carried no executable language at
    # all — a template, a config file, an IaC manifest. The repo-wide primary
    # language is then the best available evidence about what a PoC should be
    # written in, which is the case this fallback was added for.
    if project_env:
        primary = project_env.get("primary_language")
        if primary and primary in RUNTIMES:
            return RUNTIMES[primary]
    return None


def materialize_observer(rt: Runtime, scratch_dir: Path) -> list[Path]:
    """Copy `rt`'s observer asset into `scratch_dir`; return what was written.

    Idempotent (re-running rewrites identical bytes) and confined: the only
    path ever written is ``scratch_dir / <asset basename>``. Runtimes whose
    observer is pure command recipe (JFR, strace) or absent (C#) write
    nothing and return []. This function never executes anything.
    """
    obs = rt.observer
    if obs is None or not obs.asset:
        return []
    name = Path(obs.asset).name          # defensive: assets are never nested
    source = OBSERVER_DIR / name
    body = source.read_text(encoding="utf-8")
    scratch_dir = Path(scratch_dir)
    scratch_dir.mkdir(parents=True, exist_ok=True)
    dest = scratch_dir / name
    # A scratch dir can be reused across resumes. If something left a SYMLINK
    # at the asset path, both the exists() probe and the write would follow it
    # and land outside scratch_dir — so replace a symlink rather than write
    # through it. (`is_symlink` does not follow; `exists` does.)
    if dest.is_symlink():
        dest.unlink()
    if not dest.exists() or dest.read_text(encoding="utf-8") != body:
        dest.write_text(body, encoding="utf-8")
    return [dest]


def poc_execution_block(languages: list[str], project_env: dict | None,
                        scratch_dir: Path, *,
                        materialize: bool = False,
                        nonce: str | None = None,
                        run_id: str | None = None,
                        task_id: str | None = None,
                        results_dir: Path | str | None = None) -> dict | None:
    """The per-task PoC recipe injected into the Hunt agent's `user_input`.

    Returns None when no Runtime matches — Hunt then falls back to its existing
    generic "run a PoC in the target language" instruction, which is exactly
    the pre-Phase-3 behaviour, so an unknown language degrades instead of
    breaking.

    `materialize=False` (the default) is pure text: nothing is written to disk,
    and `observer["files"]` is empty. Pass `materialize=True` only when the
    scratch dir is real and the agent is actually going to run the PoC — i.e.
    inside the sandbox.

    **A null nonce is not producible by omission.** This used to accept
    ``nonce=None`` and quietly emit ``"nonce": null`` with a null canary path,
    which is a silent, total loss of gate condition 3: the payload carries no
    run-derived value, so replay has nothing to match and a real proof degrades
    to ``sink_reached_unproven``. It happened — 24 tasks of a real run were
    dispatched that way, and it was caught only because every hunt agent
    noticed and said so unprompted. So now: pass a nonce, or pass
    ``run_id``/``task_id`` and one is minted here via
    :func:`oracle.nonce.nonce_for`; pass neither and this raises.

    **A nonce keyed to an unpersisted secret is not producible either.** Minting
    from ``run_id``/``task_id`` requires the secret to survive this process,
    because the phase that verifies the proof is a different one. Pass
    ``results_dir=`` and the secret is written to ``.run_secret``; otherwise
    ``PYHUNT_RUN_SECRET`` must already be set. Neither, and this raises rather
    than handing back a well-formed nonce that replay can never reproduce.
    """
    rt = runtime_for(languages, project_env)
    if rt is None:
        return None

    if not nonce:
        if run_id and task_id:
            if results_dir is not None:
                ensure_durable_secret(results_dir)
            elif not secret_is_durable():
                raise ValueError(
                    "poc_execution_block was asked to mint a nonce from "
                    f"run_id={run_id!r}/task_id={task_id!r}, but the run secret "
                    "that keys it exists nowhere outside this process: "
                    "PYHUNT_RUN_SECRET is unset and no `results_dir=` was given "
                    "to persist a new one. The nonce would look correct and be "
                    "unreproducible — replay would derive a different value, "
                    "match nothing, and report `sink_reached_unproven` with no "
                    "indication why. Pass `results_dir=` so the secret is "
                    "written to `.run_secret`, or export PYHUNT_RUN_SECRET / set "
                    "manifest.json:run_secret before dispatching."
                )
            nonce = nonce_for(run_id, task_id)
        else:
            raise ValueError(
                "poc_execution_block needs a nonce: pass `nonce=`, or pass "
                "`run_id=` and `task_id=` so one can be derived with "
                "oracle.nonce.nonce_for(run_id, task_id). Emitting a block with "
                "a null nonce silently disables gate condition 3 — the payload "
                "would carry nothing replay could attribute to this PoC, and a "
                "real proof would come back `sink_reached_unproven` with no "
                "indication why."
            )

    observer: dict | None = None
    if rt.observer is not None:
        files = materialize_observer(rt, scratch_dir) if materialize else []
        # Resolve {observer} to the ABSOLUTE materialized path so the wrap
        # survives the `cd /target` that deps_hint often calls for. Un-
        # materialized (the text-only path) falls back to the bare asset name,
        # which is all that can honestly be promised without a real scratch dir.
        wrap = rt.observer.wrap
        if "{observer}" in wrap:
            if files:
                asset_path = str(files[0].resolve())
            elif rt.observer.asset:
                asset_path = str(Path(scratch_dir) / Path(rt.observer.asset).name)
            else:
                asset_path = ""
            wrap = wrap.replace("{observer}", asset_path)
        # The nonce rides in front of the wrap as an environment assignment.
        # It has to be IN the command rather than merely in the agent's
        # environment: the hunter composes its own run line (often with a
        # `cd /target` and a PYTHONPATH), and an env var set three shells ago
        # is exactly the kind of thing that silently does not survive. The
        # observer's own `_apply_env_assignments` understands the form.
        if nonce:
            wrap = f"PYHUNT_NONCE={nonce} " + wrap
        observer = {
            "name": rt.observer.name,
            "kind": rt.observer.kind,
            "wrap": wrap,
            "evidence_markers": list(rt.observer.evidence_markers),
            "available_check": rt.observer.available_check,
            "notes": rt.observer.notes,
            "files": [str(p) for p in files],
        }
    return {
        "language": rt.language,
        "poc_filename": rt.poc_filename,
        "compile_cmd": rt.compile_cmd,
        "run_cmd": rt.run_cmd,
        "deps_hint": rt.deps_hint,
        "observer": observer,
        # Surfaced to the prompt so the payload itself can carry the nonce
        # (`; touch /tmp/pyhunt-canary/<nonce>`). An event whose arguments
        # contain the nonce is attributable even if the marker stamp is lost —
        # two independent paths to the same attribution.
        "nonce": nonce,
        "canary_path": canary_path(nonce) if nonce else None,
        # Stated in the block itself because getting this backwards costs a
        # real proof and leaves no trace: a PoC written as
        # `os.environ.get("PYHUNT_NONCE") or "<literal>"` silently uses the
        # literal, every time, and the run reports `sink_reached_unproven` —
        # which is indistinguishable, in the report, from a working defence.
        "nonce_transport": (
            "Embed this nonce as a LITERAL in the payload, at authoring time. "
            "`os.environ.get('PYHUNT_NONCE')` is ALWAYS None inside a PoC: "
            "pyhunt_audit_hook pops PYHUNT_NONCE and PYHUNT_OBSERVER_KEY out of "
            "os.environ at import, before any PoC or target code runs. That "
            "deletion is deliberate anti-forgery (a hostile repository must not "
            "be able to read the nonce and print a well-formed marker line), so "
            "reading the nonce from the environment is not merely discouraged — "
            "it is guaranteed to fail, quietly."
        ),
    }
