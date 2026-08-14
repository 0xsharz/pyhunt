"""Host-side driver for structural probes — the second evidence path.

``replay.py`` proves that a dangerous operation *fired*. This module proves, for
the classes no audit event can reach, that the target's own code *transformed
attacker text into an executable construct* — or that it did not.

It reuses replay's container machinery wholesale (image resolution, the mount
layout, the fd-3 marker channel, the environment allowlist, the argv builder)
and swaps exactly one thing: instead of running the hunt agent's ``poc.py``
under the audit hook, it runs **PyHunt's own harness**
(``observers/pyhunt_structural_probe.py``) against a **declarative spec** the
hunt agent wrote. The agent supplies inputs; the harness supplies the
assertion; :mod:`oracle.structural` folds the signed result.

Why the spec is validated twice
-------------------------------
Once here, before anything is written into the container, and once inside the
harness. The host check is the one that matters for the security property: this
function is the last place a spec is a *host-side* object, and the only property
worth enforcing is that it contains **no code**. Every value is JSON scalars,
lists and dicts; every key is on an allowlist; unknown keys are a contract
violation (exit 2) rather than something to ignore, because an ignored key is
how a "just one more field" edit reintroduces the thing this design removes.

Usage::

    python3 scripts/structural.py run --results-dir DIR --finding-id f_x
    python3 scripts/structural.py kinds
    python3 scripts/structural.py validate --spec probe.json

JSON on stdout, notes on stderr, ``structural/<finding_id>.json`` written into
the results directory. Exit 0 whatever the outcome — a refuted probe is a
result. Exit 2 on a contract violation. Exit 1 on an internal error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

try:  # pragma: no cover - bundled-venv shim, mirrors replay.py
    import _bootstrap  # noqa: F401
except ModuleNotFoundError:
    pass

import replay as _replay
from oracle.nonce import nonce_for
from oracle.structural import (
    PROBE_KINDS,
    STRUCTURAL_REPEATS,
    StructuralOutcome,
    StructuralVerdict,
    aggregate_structural,
    judge_structural,
    probe_kind_for,
)

#: The harness asset, shipped beside the audit hook and copied read-only into
#: the container. Same directory, same guarantee: the agent never writes it.
PROBE_ASSET = Path(__file__).resolve().parent / "observers" / "pyhunt_structural_probe.py"

#: Basename the spec is written under inside the read-only payload mount.
SPEC_FILENAME = "probe_spec.json"

#: A probe reads and parses; it does not need two minutes. The exception is
#: ``growth_curve``, which is *supposed* to spend time — its own rlimits bound
#: each rung, and this ceiling bounds the ladder.
DEFAULT_TIMEOUT_S = 180

#: Keys a spec may carry, per kind. Anything else is a contract violation.
#: Deliberately not a schema file: the enforcement point is "no code reaches the
#: harness", which is a statement about *this* allowlist, and splitting it into
#: a JSON document one directory away is how it drifts out of sync with the
#: harness that consumes it.
_COMMON_KEYS = frozenset({
    "kind", "target", "construct", "construct_args", "construct_kwargs",
    "rationale",
})
_KEYS_BY_KIND: dict[str, frozenset[str]] = {
    "codegen_ast": _COMMON_KEYS | {
        "benign_args", "benign_kwargs", "hostile_args", "hostile_kwargs",
    },
    "growth_curve": _COMMON_KEYS | {
        "input_builder", "sizes", "benign_size", "ratio_threshold",
        "memory_limit_mb", "cpu_limit_s", "wall_limit_s", "extra_args",
        "kwargs", "payload_first",
    },
    "state_mutation": _COMMON_KEYS | {
        "attribute", "expected_value", "benign_args", "benign_kwargs",
        "hostile_args", "hostile_kwargs",
    },
    "exception_escape": _COMMON_KEYS | {
        "expected_exceptions", "benign_args", "benign_kwargs",
        "hostile_args", "hostile_kwargs",
    },
    "flow_witness": _COMMON_KEYS | {
        "entry_args", "entry_kwargs", "sink_location",
    },
    "sink_semantics": _COMMON_KEYS | {
        "intercept", "argument", "semantics", "root",
        "benign_args", "benign_kwargs", "hostile_args", "hostile_kwargs",
    },
    "differential_response": _COMMON_KEYS | {
        "privileged_args", "privileged_kwargs",
        "unprivileged_args", "unprivileged_kwargs", "sentinel",
    },
    "type_selection": _COMMON_KEYS | {
        "expected_type", "benign_args", "benign_kwargs",
        "hostile_args", "hostile_kwargs",
    },
    # `target` is not used by this kind — the assertion is over committed bytes,
    # not over a callable — but it stays required so every probe record names
    # the code the finding is about.
    "config_assertion": _COMMON_KEYS | {
        "file", "path", "assertion", "expected",
    },
}

_DOTTED_RX = re.compile(r"^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+$")


class SpecContractError(RuntimeError):
    """A probe spec violated the contract. Exit 2; never routed around."""


# ─────────────────────────────────────────────────────────────────────────────
# spec validation
# ─────────────────────────────────────────────────────────────────────────────

def validate_spec(spec: Any) -> dict:
    """Return the spec, or raise :class:`SpecContractError`.

    The checks are shallow on purpose. This is not trying to decide whether a
    probe is *good* — it is enforcing that a probe is *data*, so that the only
    executable thing in the container is PyHunt's own harness.
    """
    if not isinstance(spec, dict):
        raise SpecContractError("a probe spec must be a JSON object")

    kind = spec.get("kind")
    if kind not in PROBE_KINDS:
        raise SpecContractError(
            f"unknown probe kind {kind!r}. Known kinds: "
            f"{', '.join(sorted(PROBE_KINDS))}. A kind that is not in this list "
            "has no measurement function, and inventing one in the spec is "
            "exactly what the spec must not be able to do."
        )

    allowed = _KEYS_BY_KIND[kind]
    unknown = sorted(set(spec) - allowed)
    if unknown:
        raise SpecContractError(
            f"probe spec for kind {kind!r} carries unknown key(s): "
            f"{', '.join(unknown)}. Allowed: {', '.join(sorted(allowed))}. "
            "Unknown keys are refused rather than ignored — an ignored key is "
            "how a code-carrying field gets reintroduced."
        )

    target = spec.get("target")
    if not isinstance(target, str) or not _DOTTED_RX.match(target):
        raise SpecContractError(
            f"`target` must be a dotted import path (got {target!r}). The "
            "harness resolves it with importlib; there is no eval anywhere in "
            "this path."
        )
    construct = spec.get("construct")
    if construct is not None and (not isinstance(construct, str)
                                  or not _DOTTED_RX.match(construct)):
        raise SpecContractError(
            f"`construct` must be a dotted import path (got {construct!r})")

    if kind == "growth_curve":
        sizes = spec.get("sizes")
        if not isinstance(sizes, list) or len(sizes) < 3:
            raise SpecContractError(
                "growth_curve needs `sizes` with at least three rungs — two "
                "points are a line, and a line is not a curve")
        if not all(isinstance(s, int) and s > 0 for s in sizes):
            raise SpecContractError("`sizes` must be positive integers")
        if sorted(sizes) != sizes:
            raise SpecContractError("`sizes` must be ascending")
        builder = spec.get("input_builder")
        if not isinstance(builder, dict) or "kind" not in builder:
            raise SpecContractError(
                "growth_curve needs an `input_builder` with a `kind` from the "
                "closed builder vocabulary (repeat_str, list_of, nested_list, "
                "nested_dict, repeat_key, json_text, repeat_bytes, "
                "framed_bytes)")
    if kind == "state_mutation":
        attribute = spec.get("attribute")
        if not isinstance(attribute, str) or not _DOTTED_RX.match(attribute):
            raise SpecContractError(
                "state_mutation needs `attribute` as a dotted path to the "
                "module global being contaminated")
    if kind == "config_assertion":
        relative = spec.get("file")
        if not isinstance(relative, str) or not relative or \
                relative.startswith("/") or ".." in relative:
            raise SpecContractError(
                "config_assertion needs `file` as a repo-relative path inside "
                "the target (got %r). Absolute paths and `..` are refused: the "
                "assertion is about THIS repository's committed bytes"
                % (relative,))
        assertion = spec.get("assertion")
        if assertion not in ("key_absent", "key_present", "value_equals",
                             "value_matches", "value_not_matches"):
            raise SpecContractError(
                f"`assertion` must be one of key_absent, key_present, "
                f"value_equals, value_matches, value_not_matches (got "
                f"{assertion!r}). The vocabulary is closed so a spec cannot "
                "express 'run this predicate'")
        if not isinstance(spec.get("path"), str):
            raise SpecContractError(
                "config_assertion needs `path` as a dotted/indexed path into "
                "the parsed document")

    if kind == "differential_response":
        for field in ("privileged_args", "unprivileged_args"):
            if spec.get(field) is None and spec.get(field.replace("_args", "_kwargs")) is None:
                raise SpecContractError(
                    f"differential_response needs `{field}` or "
                    f"`{field.replace('_args', '_kwargs')}` — the whole "
                    "measurement is the comparison between two principals, and "
                    "one of them is missing")

    if kind == "type_selection":
        payload = json.dumps(
            [spec.get("hostile_args"), spec.get("hostile_kwargs")], default=str)
        if "$PYHUNT_NONCE" not in payload:
            raise SpecContractError(
                "type_selection needs `$PYHUNT_NONCE` in the hostile input. "
                "Without the sentinel, 'the type changed' could be any two "
                "different inputs producing two different types, which is what "
                "a dispatch table is supposed to do")

    if kind == "sink_semantics":
        intercept = spec.get("intercept")
        if not isinstance(intercept, str) or not _DOTTED_RX.match(intercept):
            raise SpecContractError(
                "sink_semantics needs `intercept` as a dotted path to the "
                "dangerous callable to wrap (sqlite3.Cursor.execute, "
                "builtins.open, requests.get). The harness replaces it with a "
                "shim that captures and raises, so the operation is never "
                "performed — that is what makes this probe non-intrusive")
        semantics = spec.get("semantics")
        if semantics not in ("sql", "path", "url", "shell", "html", "format"):
            raise SpecContractError(
                f"`semantics` must be one of sql, path, url, shell, html, "
                f"format (got {semantics!r}). The analyser vocabulary is closed "
                "for the same reason the builder vocabulary is: an open one is "
                "a place to put code")
        argument = spec.get("argument", 0)
        if not isinstance(argument, (int, str)):
            raise SpecContractError(
                "`argument` must be a positional index or a keyword name")
        payload = json.dumps(
            [spec.get("hostile_args"), spec.get("hostile_kwargs")], default=str)
        if "$PYHUNT_NONCE" not in payload:
            raise SpecContractError(
                "sink_semantics needs `$PYHUNT_NONCE` in `hostile_args` or "
                "`hostile_kwargs`. Without the sentinel the analyser cannot "
                "tell the attacker's text from the target's own, and "
                "'something ended up outside the quotes' is not a finding")

    if kind == "flow_witness":
        sink = spec.get("sink_location")
        if not isinstance(sink, str) or ":" not in sink:
            raise SpecContractError(
                "flow_witness needs `sink_location` as `file:line` — the "
                "witness is the claim that the sentinel is live in THAT "
                "frame at THAT line, so an approximate location makes the "
                "verdict meaningless")
        _, _, line = sink.rpartition(":")
        if not line.isdigit() or int(line) < 1:
            raise SpecContractError(
                f"flow_witness `sink_location` line must be a positive "
                f"integer, got {sink!r}")
        payload = json.dumps([spec.get("entry_args"), spec.get("entry_kwargs")],
                             default=str)
        if "$PYHUNT_NONCE" not in payload:
            raise SpecContractError(
                "flow_witness needs `$PYHUNT_NONCE` somewhere in `entry_args` "
                "or `entry_kwargs`. The sentinel is the entire mechanism: "
                "without it the tracer cannot tell the attacker's value from "
                "any other string the target happens to be holding")

    if kind == "exception_escape":
        expected = spec.get("expected_exceptions")
        if expected is not None and not (
                isinstance(expected, list)
                and all(isinstance(e, str) for e in expected)):
            raise SpecContractError(
                "`expected_exceptions` must be a list of exception type names")

    _assert_no_code(spec)
    return spec


_SUSPICIOUS_VALUE_RX = re.compile(
    r"\b(?:__import__|eval\s*\(|exec\s*\(|compile\s*\(|lambda\s|os\.system|"
    r"subprocess\.)", re.I)


def _assert_no_code(spec: dict) -> None:
    """Refuse a spec whose *structural* fields smell like code.

    Only the fields the harness treats as identifiers are checked. Payload
    values are explicitly NOT checked: a codegen probe's whole job is to hand
    the target a hostile string that looks like ``__import__('os').system(...)``,
    and refusing that would refuse the measurement. The distinction is where the
    string goes — into the *target's* input, never into anything PyHunt runs.
    """
    for key in ("target", "construct", "attribute"):
        value = spec.get(key)
        if isinstance(value, str) and _SUSPICIOUS_VALUE_RX.search(value):
            raise SpecContractError(
                f"`{key}` must be a plain dotted path; {value!r} is not one")
    builder = spec.get("input_builder")
    if isinstance(builder, dict) and not isinstance(builder.get("kind"), str):
        raise SpecContractError("`input_builder.kind` must be a string")


# ─────────────────────────────────────────────────────────────────────────────
# loading
# ─────────────────────────────────────────────────────────────────────────────

def load_probe(results_dir: Path, finding_id: str) -> tuple[dict | None, Any, str | None]:
    """Read ``findings/<id>.json`` and take **the probe spec and nothing else**.

    The same trust-boundary discipline as :func:`replay.load_poc`: the finding
    document is read into a local, the spec is copied out, and the document goes
    out of scope. No transcript, no ``succeeded``, no notes.
    """
    finding_id = _replay.validate_finding_id(finding_id)
    path = Path(results_dir) / "findings" / f"{finding_id}.json"
    document = _replay._read_json(path, required=True)

    finding: dict | None = None
    task_id = document.get("task_id") if isinstance(document.get("task_id"), str) else None
    if isinstance(document.get("findings"), list):
        for candidate in document["findings"]:
            if isinstance(candidate, dict) and candidate.get("finding_id") == finding_id:
                finding = candidate
                break
    elif document.get("finding_id") is not None:
        finding = document
    if finding is None:
        raise SpecContractError(
            f"{path} is neither a finding object nor a {{findings: [...]}} "
            f"wrapper containing {finding_id!r}")

    ref = _replay.FindingRef(
        finding_id=finding_id,
        task_id=task_id or (finding.get("task_id")
                            if isinstance(finding.get("task_id"), str) else None),
        vuln_class=finding.get("vuln_class")
        if isinstance(finding.get("vuln_class"), str) else None,
        file=finding.get("file") if isinstance(finding.get("file"), str) else None,
    )

    spec = finding.get("structural_probe")
    if spec is None:
        suggested = probe_kind_for(ref.vuln_class)
        reason = "the finding declares no `structural_probe`"
        if suggested:
            reason += (
                f" — and its class ({ref.vuln_class}) is one the audit hook "
                f"cannot see, so a `{suggested}` probe is the only evidence "
                "path open to it. This finding will be reported on its static "
                "argument alone."
            )
        return None, ref, reason
    return validate_spec(spec), ref, None


# ─────────────────────────────────────────────────────────────────────────────
# running
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProbeRun:
    index: int
    verdict: StructuralVerdict
    exit_code: int
    timed_out: bool
    stderr_tail: str
    log_dir: str

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "verdict": self.verdict.to_dict(),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stderr_tail": self.stderr_tail,
            "log_dir": self.log_dir,
        }


def _stage_probe(stage: Path, spec: dict, *, results_root: Path) -> tuple[Path, Path, Path]:
    """Lay out one probe run: read-only payload, empty canary, empty channel.

    Identical in shape to :func:`replay._stage_run` and rebuilt from scratch for
    the same reason — a stale marker file would let one run's evidence be read
    as another's.
    """
    poc_dir = stage / "probe"
    canary_dir = stage / "canary"
    marks_dir = stage / "marks"
    for directory in (poc_dir, canary_dir, marks_dir):
        if directory.exists():
            _replay._safe_rmtree(directory, inside=results_root)
        directory.mkdir(parents=True, exist_ok=True)
    (poc_dir / SPEC_FILENAME).write_text(
        json.dumps(spec, indent=2, sort_keys=True), encoding="utf-8")
    shutil.copyfile(PROBE_ASSET, poc_dir / PROBE_ASSET.name)
    (poc_dir / _replay.LAUNCHER_NAME).write_text(
        _replay._LAUNCHER_SOURCE, encoding="utf-8")
    return poc_dir, canary_dir, marks_dir


def build_probe_spec(*, image: str, poc_dir: Path, canary_dir: Path,
                     marks_dir: Path, nonce: str, observer_key: str,
                     run_id: str, finding_id: str, index: int, timeout_s: int,
                     target_root: str = _replay.CONTAINER_TARGET_ROOT
                     ) -> _replay.ContainerSpec:
    """Describe one probe container — replay's mounts, replay's environment.

    The command is the fd-3 launcher, then PyHunt's harness, then the spec path.
    The harness is the only executable the container runs, and it came from this
    repository rather than from a model.
    """
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-",
                  f"{run_id}-{finding_id}-probe-{index}").strip("-")
    return _replay.ContainerSpec(
        image=image,
        command=(
            "python3",
            f"{_replay.CONTAINER_PYHUNT_DIR}/{_replay.LAUNCHER_NAME}",
            _replay.CONTAINER_MARKER_PATH,
            f"{_replay.CONTAINER_PYHUNT_DIR}/{PROBE_ASSET.name}",
            f"{_replay.CONTAINER_PYHUNT_DIR}/{SPEC_FILENAME}",
        ),
        binds=(
            (str(poc_dir), _replay.CONTAINER_PYHUNT_DIR, "ro"),
            (str(canary_dir), _replay.CONTAINER_CANARY_ROOT, "rw"),
            (str(marks_dir), _replay.CONTAINER_MARKER_DIR, "rw"),
        ),
        tmpfs=(
            (_replay.CONTAINER_WORKDIR, "rw,size=64m,mode=1777"),
            ("/tmp", "rw,size=64m,mode=1777"),
        ),
        env=_replay._container_env(nonce, target_root, observer_key),
        workdir=_replay.CONTAINER_WORKDIR,
        labels=(
            ("pyhunt.run_id", run_id),
            ("pyhunt.finding_id", finding_id),
            ("pyhunt.phase", "structural"),
        ),
        network="none",
        name=f"pyhunt-probe-{safe}"[:120],
        timeout_s=timeout_s,
    )


def probe_once(*, runner: Any, spec: dict, image: str, nonce: str, run_id: str,
               finding_id: str, index: int, stage: Path, timeout_s: int,
               target_roots: Sequence[str], probe_kind: str,
               results_root: Path,
               target_root: str = _replay.CONTAINER_TARGET_ROOT) -> ProbeRun:
    """One fresh container, one structural verdict."""
    poc_dir, canary_dir, marks_dir = _stage_probe(
        stage, spec, results_root=results_root)
    observer_key = secrets.token_hex(16)
    container = build_probe_spec(
        image=image, poc_dir=poc_dir, canary_dir=canary_dir, marks_dir=marks_dir,
        nonce=nonce, observer_key=observer_key, run_id=run_id,
        finding_id=finding_id, index=index, timeout_s=timeout_s,
        target_root=target_root)
    result = runner.run(container)
    markers = _replay._read_marker_channel(marks_dir)
    # The private channel first, then the merged transcript. A harness that
    # could not open fd 3 fell back to stderr, and losing the evidence because
    # a descriptor did not open would turn an environment fact into a silence.
    output = markers if markers.strip() else (result.stdout + "\n" + result.stderr)

    failure = _replay._container_failure(result)
    if failure:
        verdict = StructuralVerdict(
            outcome=StructuralOutcome.PROBE_ERROR,
            reason=(f"probe {index}: {failure}. An environment that could not "
                    "run the harness has said nothing about the code."),
            probe_kind=probe_kind, nonce=nonce,
        )
    else:
        verdict = judge_structural(
            probe_output=output, nonce=nonce, probe_kind=probe_kind,
            target_roots=target_roots, observer_key=observer_key,
        )
        if result.timed_out and verdict.outcome is not StructuralOutcome.DEMONSTRATED:
            verdict = StructuralVerdict(
                outcome=StructuralOutcome.PROBE_ERROR,
                reason=(f"probe {index} was killed at the {timeout_s}s ceiling "
                        f"(the oracle had said: {verdict.outcome.value}). A "
                        "truncated run's silence is not evidence."),
                probe_kind=probe_kind, evidence=verdict.evidence,
                measurements=verdict.measurements, nonce=nonce,
            )

    (stage / "probe_output.txt").write_text(output, encoding="utf-8")
    (stage / "verdict.json").write_text(
        json.dumps(verdict.to_dict(), indent=2), encoding="utf-8")
    return ProbeRun(index=index, verdict=verdict, exit_code=result.exit_code,
                    timed_out=result.timed_out,
                    stderr_tail=(result.stderr or "")[-2000:], log_dir=str(stage))


def probe_finding(results_dir: str | Path, finding_id: str, *,
                  repeats: int = STRUCTURAL_REPEATS,
                  image_override: str | None = None,
                  timeout_s: int = DEFAULT_TIMEOUT_S,
                  runner: Any | None = None) -> dict:
    """Run every repeat, aggregate, and write ``structural/<id>.json``."""
    results = Path(results_dir).resolve()
    manifest = _replay.load_manifest(results)
    run_id = str(manifest.get("run_id") or results.name)

    spec, ref, reason = load_probe(results, finding_id)
    probe_kind = (spec or {}).get("kind") or probe_kind_for(ref.vuln_class)

    if spec is None:
        record = _record(results, ref, run_id, probe_kind, StructuralVerdict(
            outcome=StructuralOutcome.NOT_ATTEMPTED, reason=reason or "",
            probe_kind=probe_kind), [], image=None)
        return record

    # Order matters: resolving the run secret is what puts PYHUNT_RUN_SECRET
    # into this process's environment, and `nonce_for` derives from it. Minting
    # the nonce first would derive it from a *fresh* secret and silently produce
    # a value the finding was never authored with.
    secret, secret_source = _replay.resolve_run_secret(results, manifest)
    nonce_key, nonce_source = _replay._nonce_key(None, ref)
    nonce = nonce_for(run_id, nonce_key)

    image, image_source = _replay.resolve_image(manifest, image_override)
    if not image:
        record = _record(results, ref, run_id, probe_kind, StructuralVerdict(
            outcome=StructuralOutcome.PROBE_ERROR,
            reason=(f"no image to run in ({image_source}). Provision the target "
                    "image first; a missing image is an environment fact."),
            probe_kind=probe_kind), [], image=None)
        return record

    tier, tier_source = _replay.resolve_isolation_tier(manifest, None)
    if tier in _replay.PROOF_REFUSED_TIERS:
        record = _record(results, ref, run_id, probe_kind, StructuralVerdict(
            outcome=StructuralOutcome.NOT_ATTEMPTED,
            reason=(f"isolation tier {tier!r} ({tier_source}) is below the bar "
                    "for executing target code. A structural probe imports the "
                    "target, which is target code — it is refused here for the "
                    "same reason a replay is."),
            probe_kind=probe_kind), [], image=image)
        return record

    runner = runner or _replay.DockerRunner()
    target_roots = _replay._target_roots(manifest, [])
    stage_root = results / "logs" / "structural" / finding_id

    runs: list[ProbeRun] = []
    for index in range(1, max(1, int(repeats)) + 1):
        stage = stage_root / f"run{index}"
        stage.mkdir(parents=True, exist_ok=True)
        runs.append(probe_once(
            runner=runner, spec=spec, image=image, nonce=nonce, run_id=run_id,
            finding_id=finding_id, index=index, stage=stage,
            timeout_s=timeout_s, target_roots=target_roots,
            probe_kind=probe_kind, results_root=results))

    final = aggregate_structural([r.verdict for r in runs])
    record = _record(results, ref, run_id, probe_kind, final, runs, image=image,
                     extra={
                         "nonce_key": nonce_key,
                         "nonce_source": nonce_source,
                         "run_secret_source": secret_source,
                         "isolation_tier": tier,
                         "isolation_tier_source": tier_source,
                         "image_source": image_source,
                         "spec": spec,
                         "repeats": len(runs),
                     })
    return record


def _record(results: Path, ref: Any, run_id: str, probe_kind: str | None,
            verdict: StructuralVerdict, runs: Sequence[ProbeRun], *,
            image: str | None, extra: dict | None = None) -> dict:
    record = {
        "finding_id": ref.finding_id,
        "task_id": ref.task_id,
        "vuln_class": ref.vuln_class,
        "file": ref.file,
        "run_id": run_id,
        "probe_kind": probe_kind,
        "image": image,
        "verdict": verdict.to_dict(),
        "runs": [r.to_dict() for r in runs],
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    # Whether a hunter could plausibly fix this by re-authoring the payload, as
    # opposed to it being an environment fact. The distinction matters because
    # the repair loop must retry exactly once on the first kind and never on the
    # second: retrying a container that would not start just burns the budget.
    outcome = verdict.outcome
    spec_side = outcome in (StructuralOutcome.INCONCLUSIVE,)
    if outcome is StructuralOutcome.PROBE_ERROR:
        # A probe_error is spec-side when the harness reached the code and
        # disliked the inputs; environment-side when it never got that far.
        spec_side = bool(verdict.callable_file) or "benign control" in verdict.reason
    record["repairable"] = bool(spec_side)
    record["repair_hint"] = verdict.reason if spec_side else None
    record.update(extra or {})
    out_dir = results / "structural"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{ref.finding_id}.json").write_text(
        json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return record


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="structural.py",
        description="Run one finding's structural probe in a fresh container.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run one finding's structural probe")
    run.add_argument("--results-dir", required=True)
    run.add_argument("--finding-id", required=True)
    run.add_argument("--repeats", type=int, default=STRUCTURAL_REPEATS)
    run.add_argument("--image", default=None)
    run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)

    sub.add_parser("kinds", help="print the probe vocabulary as JSON")

    validate = sub.add_parser("validate", help="validate a spec file")
    validate.add_argument("--spec", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "kinds":
            print(json.dumps({"kinds": PROBE_KINDS,
                              "keys_by_kind": {k: sorted(v)
                                               for k, v in _KEYS_BY_KIND.items()}},
                             indent=2))
            return 0
        if args.cmd == "validate":
            spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
            validate_spec(spec)
            print(json.dumps({"ok": True, "kind": spec["kind"]}))
            return 0
        record = probe_finding(
            args.results_dir, args.finding_id, repeats=args.repeats,
            image_override=args.image, timeout_s=args.timeout)
        print(json.dumps(record, indent=2, sort_keys=True))
        outcome = record["verdict"]["outcome"]
        sys.stderr.write(f"structural: {args.finding_id} -> {outcome}\n")
        return 0
    except SpecContractError as exc:
        sys.stderr.write(f"contract violation: {exc}\n")
        return 2
    except _replay.ReplayContractError as exc:
        sys.stderr.write(f"contract violation: {exc}\n")
        return 2
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"internal error: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
