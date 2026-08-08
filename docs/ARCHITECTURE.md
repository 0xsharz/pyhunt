# PyHunt Architecture

How PyHunt is put together, phase by phase, and where each artefact comes from.
Every diagram on this page renders natively on GitHub.

For what the tool *is* and how to run it, start with the
[README](../README.md).

---

## Contents

- [1. System overview](#1-system-overview)
- [2. The two halves: agent and oracle](#2-the-two-halves-agent-and-oracle)
- [3. The pipeline end to end](#3-the-pipeline-end-to-end)
- [4. Phase by phase](#4-phase-by-phase)
- [5. The proof path in detail](#5-the-proof-path-in-detail)
- [6. The gate: five conditions, eight outcomes](#6-the-gate-five-conditions-eight-outcomes)
- [7. Contract A: how a marker is trusted](#7-contract-a-how-a-marker-is-trusted)
- [8. Isolation tiers](#8-isolation-tiers)
- [9. Artefacts on disk](#9-artefacts-on-disk)
- [10. Trust boundaries](#10-trust-boundaries)

---

## 1. System overview

PyHunt has no daemon, no server and no `pyhunt` binary. It is a directory of
markdown that Claude Code executes, plus Python that Claude Code shells out to.

```mermaid
flowchart LR
    OP["Operator"] -->|"/pyhunt &lt;target&gt;"| CC["Claude Code"]

    subgraph SKILL["The skill — ~/.claude/skills/pyhunt"]
        SM["SKILL.md<br/><i>orchestrator</i>"]
        PHM["phases/*.md<br/><i>methodology</i>"]
        REF["references/*.md<br/><i>sinks, gate, contracts</i>"]
        SCH["schemas/*.json<br/><i>output validation</i>"]
    end

    subgraph DET["Deterministic Python — scripts/"]
        TA["taint.py + graph/"]
        PR["provision/"]
        RP["replay.py"]
        OC["oracle/"]
        CV["coverage.py"]
        RB["reporting/"]
    end

    subgraph SBX["Sandbox — separate kernel"]
        CT["Fresh container<br/>per PoC run"]
        AH["PEP-578 audit hook"]
    end

    CC --> SM
    SM --> PHM
    SM --> DET
    PHM -.reads.-> REF
    DET -.validated by.-> SCH

    RP --> CT
    CT --> AH
    AH -->|"signed markers, fd 3"| OC
    OC --> RB
    RB --> OUT["report.json<br/>report.md"]

    style SKILL fill:#eef4ff,stroke:#5b8def
    style DET fill:#eefaf0,stroke:#3fa15c
    style SBX fill:#fff3e6,stroke:#e08c2e
```

The split is the whole design. Markdown decides *what to look at*; Python
decides *what counts as proof*.

---

## 2. The two halves: agent and oracle

An agent that writes an exploit is not allowed to grade it. That is the
single structural rule the rest of the system is built to enforce.

```mermaid
flowchart TB
    subgraph JUDGEMENT["Agent — judgement, may be wrong"]
        direction LR
        A1["Enumerate inputs"] --> A2["Rank attack surface"]
        A2 --> A3["Write the finding"]
        A3 --> A4["Write a PoC"]
        A4 --> A5["Argue against it"]
    end

    subgraph MECHANISM["Python — mechanism, cannot be argued with"]
        direction LR
        M1["Build the call graph"] --> M2["Provision an image"]
        M2 --> M3["Run the PoC in a fresh container ×3"]
        M3 --> M4["Compute the verdict"]
        M4 --> M5["Assemble the report"]
    end

    A4 -->|"PoC source only —<br/>never the transcript"| M3
    M4 -->|"proven / not proven"| A5

    style JUDGEMENT fill:#eef4ff,stroke:#5b8def
    style MECHANISM fill:#eefaf0,stroke:#3fa15c
```

The hunt agent's transcript is never read as evidence. `replay.py` takes the
PoC *source*, arms the observer itself, captures the output itself, and runs it
three times in containers the agent never touched.

---

## 3. The pipeline end to end

```mermaid
flowchart TD
    START(["/pyhunt &lt;target&gt;"]) --> P0

    P0["<b>Phase 0 — Preflight</b><br/>authorisation, language gate,<br/>isolation tier, mode"]
    P0 -->|"preflight.json<br/>manifest.json"| P1

    P1["<b>Phase 1 — Recon</b><br/>enumerate every untrusted input,<br/>mine git history"]
    P1 -->|"inputs.json<br/>logs/history.json"| P1B

    P1B["<b>Phase 1b — Taint</b><br/>call graph, entry→sink paths,<br/>task generation"]
    P1B -->|"tasks.json"| P2

    P2["<b>Phase 2 — Hunt</b><br/>one attack class, one location,<br/>one agent per task"]
    P2 -->|"findings/<br/>task_outcomes.json"| P2B

    P2B["<b>Phase 2b — Prove</b><br/>PoC → 3 fresh containers → gate"]
    P2B -->|"replay verdicts"| P2C

    P2C["<b>Phase 2c — Verify</b><br/>adversarial disproof,<br/>different model"]
    P2C -->|"verify/&lt;id&gt;.json"| P3

    P3["<b>Phase 3 — Sweep</b><br/>sibling instances,<br/>input dispositions"]
    P3 -->|"coverage.json"| P4

    P4["<b>Phase 4 — Report</b><br/>CVSS, precision, caveats"]
    P4 --> END(["report.json + report.md"])

    P2B -.->|"Static mode:<br/>skipped entirely"| P2C

    style P0 fill:#f5f5f5,stroke:#888
    style P2B fill:#fff3e6,stroke:#e08c2e
    style P2C fill:#fdeaea,stroke:#c0392b
    style END fill:#eefaf0,stroke:#3fa15c
```

Each phase writes its output to the results directory and records itself in
`manifest.json`. Re-invoking `/pyhunt` on an existing results directory resumes
at the first phase the manifest does not list.

---

## 4. Phase by phase

### Phase 0 — Preflight

Refuses early rather than degrading quietly.

```mermaid
flowchart TD
    S(["start"]) --> AUTH{"Operator confirms<br/>authorisation?"}
    AUTH -->|no| STOP1(["refuse"])
    AUTH -->|yes| LANG{"Target majority<br/>Python?"}
    LANG -->|no| STOP2(["refuse —<br/>analysing it badly<br/>is worse than not"])
    LANG -->|yes| TIER["sandbox.py detect"]
    TIER --> MODE{"Requested mode"}
    MODE -->|"Static"| OKS(["Static run<br/>no target code executes"])
    MODE -->|"Proof"| GATE{"Tier is vm<br/>or gvisor?"}
    GATE -->|yes| OKP(["Proof run"])
    GATE -->|no| STOP3(["<b>refused, not downgraded</b>"])

    style STOP3 fill:#fdeaea,stroke:#c0392b
    style OKP fill:#eefaf0,stroke:#3fa15c
```

A silent downgrade would fill the report with `not_attempted`, which reads like
"we looked and found nothing". So it is refused instead.

### Phase 1 — Recon

Two independent sources of attack surface, deliberately not merged early.

```mermaid
flowchart LR
    T["Target repository"] --> E["Input enumeration<br/><i>CLI args, files, env,<br/>network, deserialised data</i>"]
    T --> H["Git history mining<br/><i>past fixes, reverts,<br/>security-shaped commits</i>"]
    E --> IJ["inputs.json<br/><i>every input, with an id</i>"]
    H --> HJ["logs/history.json"]
    IJ --> LEDGER["Completeness ledger:<br/>every input must reach<br/>a disposition"]
    HJ --> TASKS["History-derived<br/>hunt tasks"]

    style LEDGER fill:#eef4ff,stroke:#5b8def
```

The ledger is the reason coverage can be reported honestly later: an input that
reaches no finding and no task scope becomes `uncovered`, and `uncovered` is a
number in the report rather than a silence.

### Phase 1b — Taint

```mermaid
flowchart LR
    SRC["Source files"] --> AST["AST parse"]
    AST --> CG["Call graph<br/><i>scripts/graph/</i>"]
    CG --> PATHS["entry → sink paths"]
    SINKS["references/python-sinks.md"] -.-> PATHS
    PATHS --> CHUNK["Chunk into narrow tasks"]
    CHUNK --> SPEC["Specialist tasks<br/><i>per lens, ranked files</i>"]
    CHUNK --> CATCH["Catch-all sweep<br/><i>everything else</i>"]
    SPEC --> TJ["tasks.json"]
    CATCH --> TJ
```

Specialist lenses each get a *relevance-ranked* file list, not the same
alphabetical slice: the codegen lens leads with Jinja templates, the IaC lens
with workflow YAML.

### Phase 2 — Hunt

```mermaid
flowchart TD
    TJ["tasks.json"] --> FAN{"one task =<br/>one agent"}
    FAN --> A1["Agent: injection"]
    FAN --> A2["Agent: deserialization"]
    FAN --> A3["Agent: navigation"]
    FAN --> A4["Agent: logging"]
    FAN --> A5["Agent: catch-all"]

    A1 & A2 & A3 & A4 & A5 --> RULE["<b>One finding per SITE</b><br/>not per family"]
    RULE --> REC["findings_io record"]
    REC --> FD["findings/&lt;id&gt;.json"]
    REC --> TO["task_outcomes.json<br/><i>findings | clean</i>"]

    style RULE fill:#eef4ff,stroke:#5b8def
```

`task_outcomes.json` is what makes "hunted and clean" distinguishable from
"never hunted" — without it, coverage can never legitimately be complete.

### Phase 2b — Prove

Detailed in [section 5](#5-the-proof-path-in-detail).

### Phase 2c — Verify

```mermaid
flowchart LR
    F["Finding"] --> V["Adversarial reviewer<br/><i>different model</i>"]
    V --> Q1["Is the source really untrusted?"]
    V --> Q2["Is the sink really reachable?"]
    V --> Q3["Is there a defence in the path?"]
    Q1 & Q2 & Q3 --> D{"Survives?"}
    D -->|yes| KEEP["confirmed"]
    D -->|no| KILL["rejected"]
    KEEP & KILL --> VJ["verify/&lt;id&gt;.json<br/><i>records the model that ran</i>"]

    style KILL fill:#fdeaea,stroke:#c0392b
```

**Findings die here, never in the execution path.** A PoC that fails is a fact
about the PoC. Only an argument about the code can remove a finding.

### Phase 3 — Sweep

```mermaid
flowchart TD
    F["Confirmed findings"] --> SIB["Find sibling instances<br/><i>same bug, other sites</i>"]
    SIB --> REC["coverage.py reconcile"]
    IJ["inputs.json"] --> REC
    TO["task_outcomes.json"] --> REC
    REC --> CLS["coverage.py classify"]
    CLS --> DISP{"every input has<br/>a disposition?"}
    DISP -->|no| REQ["re-queue as tasks"]
    REQ --> SIB
    DISP -->|yes| AC["coverage.py assert-complete"]
    AC --> CJ["coverage.json"]
```

### Phase 4 — Report

```mermaid
flowchart LR
    FD["findings/"] --> RB["report_build.py"]
    VJ["verify/"] --> RB
    RV["replay verdicts"] --> RB
    CJ["coverage.json"] --> RB
    IJ["inputs.json"] --> RB

    RB --> CVSS["CVSS vector<br/><i>AV:L unless recon found<br/>a network entry point</i>"]
    RB --> PREC["Precision<br/><i>TP / TP+FP, or 'not computed'</i>"]
    RB --> CAV["Caveats<br/><i>uncovered inputs, tier,<br/>unprovable classes</i>"]

    CVSS & PREC & CAV --> OUT["report.json --strict<br/>report.md"]
```

Nothing is inferred upward. A finding no one judged is not a rejected finding,
and precision says `not computed` rather than `0.0%`.

---

## 5. The proof path in detail

This is where the design earns its keep.

```mermaid
sequenceDiagram
    autonumber
    participant HA as Hunt agent
    participant RP as replay.py
    participant IM as Provisioned image
    participant CT as Fresh container
    participant TG as Target code
    participant AH as Audit hook
    participant GT as oracle gate

    HA->>RP: PoC source only
    Note over HA,RP: the transcript is never<br/>passed and never read

    loop 3 independent runs
        RP->>IM: build container from unmodified image
        IM->>CT: start, PYHUNT_TARGET_ROOT set
        RP->>CT: install audit hook, derive nonce
        AH->>AH: scrub observer key from os.environ
        CT->>TG: run the PoC
        TG->>AH: CPython audit event fires
        AH->>AH: attribute the calling frame
        AH-->>GT: HMAC-signed marker on fd 3
    end

    GT->>GT: five conditions, per run
    alt 3 of 3 unanimous proven
        GT-->>RP: proven
    else any disagreement
        GT-->>RP: not proven
    end
```

Three unanimous runs or no promotion. One run is an anecdote; three fresh
containers rule out a container that happened to be dirty.

---

## 6. The gate: five conditions, eight outcomes

```mermaid
flowchart TD
    S(["replay finished"]) --> C0{"PoC ran at all?"}
    C0 -->|no| O7(["not_attempted"])
    C0 -->|yes| C1{"1. Observer armed?"}
    C1 -->|no| O6(["observer_absent"])
    C1 -->|yes| C2{"2. Watched audit<br/>event fired?"}
    C2 -->|no| O5(["no_event"])
    C2 -->|yes| C3{"3. Carried this<br/>PoC's nonce?"}
    C3 -->|no| O4(["nonce_mismatch"])
    C3 -->|yes| C4{"4. Frame inside the<br/><b>target</b>, not the PoC?"}
    C4 -->|no| O3(["self_attributed"])
    C4 -->|yes| C5{"5. Payload<br/><b>interpreted</b>,<br/>not merely carried?"}
    C5 -->|no| O2(["sink_reached_unproven"])
    C5 -->|yes| O1(["<b>proven</b>"])

    style O1 fill:#eefaf0,stroke:#3fa15c
    style O3 fill:#fdeaea,stroke:#c0392b
    style O4 fill:#fdeaea,stroke:#c0392b
```

An eighth outcome, `not_applicable`, covers classes this observer structurally
cannot witness — code generated for *later* execution, for instance, where
nothing runs inside the observed process.

**Only `proven` promotes a finding, and nothing demotes one.**

Condition 5 exists because a test caught the gate promoting a *defended* sink:

```python
subprocess.run("echo " + name, shell=True)   # ('/bin/sh', ['-c', 'echo hi; touch …'])  → proven
subprocess.run(["echo", name])               # ('/bin/echo', ['echo', 'hi; touch …'])   → not proven
```

Both spawn a process from the target's own frame with the payload sitting in
argv. Only the first parsed it as a command. A gate without condition 5
launders a working defence into "confirmed by execution", which is worse than
having no gate at all.

---

## 7. Contract A: how a marker is trusted

```mermaid
flowchart LR
    subgraph PROC["One CPython process"]
        TC["Target code"]
        AH["Audit hook"]
        K["Per-run HMAC key<br/><i>scrubbed from os.environ<br/>before target code runs</i>"]
    end

    AH -->|"sign(line, key)"| FD3["fd 3<br/><i>private channel</i>"]
    TC -.->|"can write<br/>unsigned lines"| FD3
    FD3 --> P["oracle parser"]
    P --> V{"signature valid?"}
    V -->|yes| EV["counted as an event"]
    V -->|no| FL["forged_lines += 1<br/><i>zero events</i>"]

    style FL fill:#fdeaea,stroke:#c0392b
    style K fill:#eef4ff,stroke:#5b8def
```

The **signature** is the control, not the secrecy of the nonce or of fd 3. The
PoC source embeds the nonce and the target can write to fd 3 — neither matters,
because an unsigned line parses to nothing.

The honest limit: target and hook share an interpreter, so a target written
specifically to attack PyHunt can still recover the key from process memory.
This defeats opportunistic forgery and forces any attack to be deliberate and
PyHunt-specific. Out-of-process observation is the real fix and is out of
scope.

---

## 8. Isolation tiers

```mermaid
flowchart TD
    D["sandbox.py detect"] --> Q1{"Docker usable?"}
    Q1 -->|no| T0["<b>none</b><br/>Static only"]
    Q1 -->|yes| Q2{"Linux with runsc?"}
    Q2 -->|yes| TG["<b>gvisor</b><br/>syscall interception"]
    Q2 -->|no| Q3{"Separate kernel?<br/><i>Docker Desktop,<br/>Lima, Colima</i>"}
    Q3 -->|yes| TV["<b>vm</b><br/>separate kernel in a VM"]
    Q3 -->|no| TR["<b>runc</b><br/>namespaces, shared kernel"]

    TG --> ALLOW(["Proof mode allowed"])
    TV --> ALLOW
    TR --> REFUSE(["<b>refused</b>"])
    T0 --> REFUSE

    style ALLOW fill:#eefaf0,stroke:#3fa15c
    style REFUSE fill:#fdeaea,stroke:#c0392b
```

`runc` is refused even though it is "a container": namespaces share the host
kernel with code you have just concluded is exploitable. The achieved tier is
recorded in the manifest and restated in the report, so a `vm` scan can never
claim `gvisor`.

---

## 9. Artefacts on disk

```mermaid
flowchart TD
    R["&lt;target&gt;_PYHUNT_RESULTS_&lt;timestamp&gt;/"]
    R --> M["manifest.json<br/><i>phases completed, tier, mode</i>"]
    R --> PF["preflight.json"]
    R --> IJ["inputs.json"]
    R --> TJ["tasks.json"]
    R --> TO["task_outcomes.json<br/><i>append-only</i>"]
    R --> FD["findings/&lt;id&gt;.json"]
    R --> VD["verify/&lt;id&gt;.json"]
    R --> CJ["coverage.json"]
    R --> LG["logs/<br/><i>history.json, replay output</i>"]
    R --> RJ["report.json<br/><i>schema-validated, --strict</i>"]
    R --> RM["report.md<br/><i>the advisory</i>"]

    style R fill:#eef4ff,stroke:#5b8def
    style RM fill:#eefaf0,stroke:#3fa15c
```

Every one of these is written as its phase completes, so a disconnect costs one
phase, not one run.

---

## 10. Trust boundaries

```mermaid
flowchart TB
    subgraph HOST["Host — never runs target code"]
        CC["Claude Code + skill"]
        SCR["scripts/ — analysis only"]
        GATE["oracle/ — the verdict"]
    end

    subgraph VM["Separate kernel"]
        subgraph CONT["Fresh container, one per run"]
            POC["PoC"]
            TGT["Target code"]
            HOOK["Audit hook"]
        end
    end

    CC -->|"reads source,<br/>never executes it"| SCR
    SCR -->|"PoC source"| CONT
    HOOK -->|"signed markers"| GATE
    GATE -->|"verdict"| CC

    B1{{"Boundary 1: host / VM<br/>separate kernel"}}
    B2{{"Boundary 2: agent / oracle<br/>judgement cannot grade itself"}}
    B3{{"Boundary 3: target / observer<br/>same process — signature, not secrecy"}}

    style HOST fill:#eef4ff,stroke:#5b8def
    style VM fill:#fff3e6,stroke:#e08c2e
    style B3 fill:#fdeaea,stroke:#c0392b
```

Boundary 3 is the weakest and is documented as such. Boundaries 1 and 2 are
structural; boundary 3 raises the cost of an attack without eliminating it.

---

## Further reading

| Document | What it holds |
|---|---|
| [`README.md`](../README.md) | What PyHunt is, install, usage, measured results |
| [`pyhunt/SKILL.md`](../pyhunt/SKILL.md) | The orchestrator Claude Code actually executes |
| [`pyhunt/phases/`](../pyhunt/phases/) | The methodology, one file per phase |
| [`pyhunt/references/execution-gate.md`](../pyhunt/references/execution-gate.md) | The gate specified in prose |
| [`pyhunt/references/python-sinks.md`](../pyhunt/references/python-sinks.md) | The sink catalogue |
| [`pyhunt/references/honest-reporting.md`](../pyhunt/references/honest-reporting.md) | What may and may not be claimed |
| [`pyhunt/references/output-contracts.md`](../pyhunt/references/output-contracts.md) | The shape every phase must emit |
