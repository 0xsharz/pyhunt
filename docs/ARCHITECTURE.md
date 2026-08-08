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
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","clusterBkg":"#11161d","clusterBorder":"#3d444d","fontSize":"14px"}}}%%
flowchart LR
    OP["Operator"] -->|"/pyhunt target"| CC["Claude Code"]

    subgraph SKILL["The skill · ~/.claude/skills/pyhunt"]
        SM["SKILL.md<br/>orchestrator"]
        PHM["phases/*.md<br/>methodology"]
        REF["references/*.md<br/>sinks, gate, contracts"]
        SCH["schemas/*.json<br/>output validation"]
    end

    subgraph DET["Deterministic Python · scripts/"]
        TA["taint.py + graph/"]
        RP["replay.py"]
        OC["oracle/"]
        RB["reporting/"]
    end

    subgraph SBX["Sandbox · separate kernel"]
        CT["Fresh container<br/>per PoC run"]
        AH["PEP-578 audit hook"]
    end

    CC --> SM
    SM --> PHM
    SM -->|"analysis"| TA
    SM -->|"proof"| RP
    PHM -.reads.-> REF
    TA -.validated by.-> SCH

    RP --> CT
    CT --> AH
    AH -->|"signed markers, fd 3"| OC
    OC --> RB
    RB --> OUT["report.json<br/>report.md"]

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef run fill:#2a2113,stroke:#9e7b28,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    class OP,CC,SM,PHM,REF,SCH,TA,RP,RB base
    class CT,AH run
    class OC,OUT good
```

The split is the whole design. Markdown decides *what to look at*; Python
decides *what counts as proof*.

---

## 2. The two halves: agent and oracle

An agent that writes an exploit is not allowed to grade it. That is the single
structural rule the rest of the system is built to enforce.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","clusterBkg":"#11161d","clusterBorder":"#3d444d","fontSize":"14px"}}}%%
flowchart TB
    subgraph JUDGEMENT["Agent · judgement, may be wrong"]
        direction LR
        A1["Enumerate inputs"] --> A2["Rank attack surface"]
        A2 --> A3["Write the finding"]
        A3 --> A4["Write a PoC"]
        A4 --> A5["Argue against it"]
    end

    subgraph MECHANISM["Python · mechanism, cannot be argued with"]
        direction LR
        M1["Build the call graph"] --> M2["Provision an image"]
        M2 --> M3["Run the PoC ×3<br/>in fresh containers"]
        M3 --> M4["Compute the verdict"]
        M4 --> M5["Assemble the report"]
    end

    A4 -->|"PoC source only —<br/>never the transcript"| M3
    M4 -->|"proven / not proven"| A5

    classDef soft fill:#1a2333,stroke:#3b6ea5,color:#ffffff
    classDef hard fill:#12261c,stroke:#2ea043,color:#ffffff
    class A1,A2,A3,A4,A5 soft
    class M1,M2,M3,M4,M5 hard
```

The hunt agent's transcript is never read as evidence. `replay.py` takes the
PoC *source*, arms the observer itself, captures the output itself, and runs it
three times in containers the agent never touched.

---

## 3. The pipeline end to end

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart TD
    START(["/pyhunt target"]) --> P0

    P0["Phase 0 · Preflight<br/>authorisation, language gate,<br/>isolation tier, mode"]
    P0 -->|"preflight.json · manifest.json"| P1

    P1["Phase 1 · Recon<br/>enumerate every untrusted input,<br/>mine git history"]
    P1 -->|"inputs.json · logs/history.json"| P1B

    P1B["Phase 1b · Taint<br/>call graph, entry to sink paths,<br/>task generation"]
    P1B -->|"tasks.json"| P2

    P2["Phase 2 · Hunt<br/>one attack class, one location,<br/>one agent per task"]
    P2 -->|"findings/ · task_outcomes.json"| P2B

    P2B["Phase 2b · Prove<br/>PoC into 3 fresh containers,<br/>then the gate"]
    P2B -->|"replay verdicts"| P2C

    P2C["Phase 2c · Verify<br/>adversarial disproof,<br/>different model"]
    P2C -->|"verify/id.json"| P3

    P3["Phase 3 · Sweep<br/>sibling instances,<br/>input dispositions"]
    P3 -->|"coverage.json"| P4

    P4["Phase 4 · Report<br/>CVSS, precision, caveats"]
    P4 --> END(["report.json + report.md"])

    P2B -.->|"Static mode:<br/>skipped entirely"| P2C

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef run fill:#2a2113,stroke:#9e7b28,color:#ffffff
    classDef kill fill:#2a1215,stroke:#b3474f,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    class START,P0,P1,P1B,P2,P3,P4 base
    class P2B run
    class P2C kill
    class END good
```

Each phase writes its output to the results directory and records itself in
`manifest.json`. Re-invoking `/pyhunt` on an existing results directory resumes
at the first phase the manifest does not list.

---

## 4. Phase by phase

### Phase 0 — Preflight

Refuses early rather than degrading quietly.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart TD
    S(["start"]) --> AUTH{"Operator confirms<br/>authorisation?"}
    AUTH -->|no| STOP1(["refuse"])
    AUTH -->|yes| LANG{"Target majority<br/>Python?"}
    LANG -->|no| STOP2(["refuse — analysing it<br/>badly is worse than not"])
    LANG -->|yes| TIER["sandbox.py detect"]
    TIER --> MODE{"Requested mode"}
    MODE -->|"Static"| OKS(["Static run ·<br/>no target code executes"])
    MODE -->|"Proof"| GATE{"Tier is vm<br/>or gvisor?"}
    GATE -->|yes| OKP(["Proof run"])
    GATE -->|no| STOP3(["refused, not downgraded"])

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef bad fill:#2a1215,stroke:#b3474f,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    class S,AUTH,LANG,TIER,MODE,GATE base
    class STOP1,STOP2,STOP3 bad
    class OKS,OKP good
```

A silent downgrade would fill the report with `not_attempted`, which reads like
"we looked and found nothing". So it is refused instead.

### Phase 1 — Recon

Two independent sources of attack surface, deliberately not merged early.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart LR
    T["Target repository"] --> E["Input enumeration<br/>CLI args, files, env,<br/>network, deserialised data"]
    T --> H["Git history mining<br/>past fixes, reverts,<br/>security-shaped commits"]
    E --> IJ["inputs.json<br/>every input, with an id"]
    H --> HJ["logs/history.json"]
    IJ --> LEDGER["Completeness ledger:<br/>every input must reach<br/>a disposition"]
    HJ --> TASKS["History-derived<br/>hunt tasks"]

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef key fill:#1a2333,stroke:#3b6ea5,color:#ffffff
    class T,E,H,IJ,HJ,TASKS base
    class LEDGER key
```

The ledger is why coverage can be reported honestly later: an input that reaches
no finding and no task scope becomes `uncovered`, and `uncovered` is a number in
the report rather than a silence.

### Phase 1b — Taint

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart LR
    SRC["Source files"] --> AST["AST parse"]
    AST --> CG["Call graph<br/>scripts/graph/"]
    CG --> PATHS["entry to sink paths"]
    SINKS["references/<br/>python-sinks.md"] -.-> PATHS
    PATHS --> CHUNK["Chunk into narrow tasks"]
    CHUNK --> SPEC["Specialist tasks<br/>per lens, ranked files"]
    CHUNK --> CATCH["Catch-all sweep<br/>everything else"]
    SPEC --> TJ["tasks.json"]
    CATCH --> TJ

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    class SRC,AST,CG,PATHS,SINKS,CHUNK,SPEC,CATCH,TJ base
```

Specialist lenses each get a *relevance-ranked* file list, not the same
alphabetical slice: the codegen lens leads with templates, the IaC lens with
workflow YAML.

### Phase 2 — Hunt

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart TD
    TJ["tasks.json"] --> FAN{"one task =<br/>one agent"}
    FAN --> A1["injection"]
    FAN --> A2["deserialization"]
    FAN --> A3["navigation"]
    FAN --> A4["logging"]
    FAN --> A5["catch-all"]

    A1 & A2 & A3 & A4 & A5 --> RULE["One finding per SITE<br/>not per family"]
    RULE --> REC["findings_io record"]
    REC --> FD["findings/id.json"]
    REC --> TO["task_outcomes.json<br/>findings | clean"]

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef key fill:#1a2333,stroke:#3b6ea5,color:#ffffff
    class TJ,FAN,A1,A2,A3,A4,A5,REC,FD,TO base
    class RULE key
```

`task_outcomes.json` is what makes "hunted and clean" distinguishable from
"never hunted" — without it, coverage can never legitimately be complete.

### Phase 2b — Prove

Detailed in [section 5](#5-the-proof-path-in-detail).

### Phase 2c — Verify

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart LR
    F["Finding"] --> V["Adversarial reviewer<br/>different model"]
    V --> Q1["Is the source<br/>really untrusted?"]
    V --> Q2["Is the sink<br/>really reachable?"]
    V --> Q3["Is there a defence<br/>in the path?"]
    Q1 & Q2 & Q3 --> D{"Survives?"}
    D -->|yes| KEEP["confirmed"]
    D -->|no| KILL["rejected"]
    KEEP & KILL --> VJ["verify/id.json<br/>records the model that ran"]

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    classDef bad fill:#2a1215,stroke:#b3474f,color:#ffffff
    class F,V,Q1,Q2,Q3,D,VJ base
    class KEEP good
    class KILL bad
```

**Findings die here, never in the execution path.** A PoC that fails is a fact
about the PoC. Only an argument about the code can remove a finding.

### Phase 3 — Sweep

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart TD
    F["Confirmed findings"] --> SIB["Find sibling instances<br/>same bug, other sites"]
    SIB --> REC["coverage.py reconcile"]
    IJ["inputs.json"] --> REC
    TO["task_outcomes.json"] --> REC
    REC --> CLS["coverage.py classify"]
    CLS --> DISP{"every input has<br/>a disposition?"}
    DISP -->|no| REQ["re-queue as tasks"]
    REQ --> SIB
    DISP -->|yes| AC["coverage.py assert-complete"]
    AC --> CJ["coverage.json"]

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    class F,SIB,REC,IJ,TO,CLS,DISP,REQ base
    class AC,CJ good
```

### Phase 4 — Report

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart LR
    FD["findings/"] --> RB["report_build.py"]
    VJ["verify/"] --> RB
    RV["replay verdicts"] --> RB
    CJ["coverage.json"] --> RB
    IJ["inputs.json"] --> RB

    RB --> CVSS["CVSS vector<br/>AV:L unless recon found<br/>a network entry point"]
    RB --> PREC["Precision<br/>TP / TP+FP, or not computed"]
    RB --> CAV["Caveats<br/>uncovered inputs, tier,<br/>unprovable classes"]

    CVSS & PREC & CAV --> OUT["report.json --strict<br/>report.md"]

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    class FD,VJ,RV,CJ,IJ,RB,CVSS,PREC,CAV base
    class OUT good
```

Nothing is inferred upward. A finding no one judged is not a rejected finding,
and precision says `not computed` rather than `0.0%`.

---

## 5. The proof path in detail

This is where the design earns its keep.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","textColor":"#ffffff","actorBkg":"#161b22","actorTextColor":"#ffffff","actorLineColor":"#9aa4b2","actorBorder":"#3d444d","signalColor":"#9aa4b2","signalTextColor":"#ffffff","labelBoxBkgColor":"#1c2128","labelBoxBorderColor":"#3d444d","labelTextColor":"#ffffff","loopTextColor":"#ffffff","noteBkgColor":"#1a2333","noteTextColor":"#ffffff","noteBorderColor":"#3b6ea5","altBackground":"#11161d","sequenceNumberColor":"#0d1117","fontSize":"14px"}}}%%
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
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart TD
    S(["replay finished"]) --> C0{"PoC ran at all?"}
    C0 -->|no| O7(["not_attempted"])
    C0 -->|yes| C1{"1 · Observer armed?"}
    C1 -->|no| O6(["observer_absent"])
    C1 -->|yes| C2{"2 · Watched audit<br/>event fired?"}
    C2 -->|no| O5(["no_event"])
    C2 -->|yes| C3{"3 · Carried this<br/>PoC's nonce?"}
    C3 -->|no| O4(["nonce_mismatch"])
    C3 -->|yes| C4{"4 · Frame inside the<br/>target, not the PoC?"}
    C4 -->|no| O3(["self_attributed"])
    C4 -->|yes| C5{"5 · Payload interpreted,<br/>not merely carried?"}
    C5 -->|no| O2(["sink_reached_unproven"])
    C5 -->|yes| O1(["proven"])

    classDef step fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef fail fill:#241a1d,stroke:#8f4a52,color:#ffffff
    classDef hard fill:#2a1215,stroke:#b3474f,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    class S,C0,C1,C2,C3,C4,C5 step
    class O7,O6,O5,O2 fail
    class O4,O3 hard
    class O1 good
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
argv. Only the first parsed it as a command. A gate without condition 5 launders
a working defence into "confirmed by execution", which is worse than having no
gate at all.

---

## 7. Contract A: how a marker is trusted

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","clusterBkg":"#11161d","clusterBorder":"#3d444d","fontSize":"14px"}}}%%
flowchart LR
    subgraph PROC["One CPython process"]
        TC["Target code"]
        AH["Audit hook"]
        K["Per-run HMAC key<br/>scrubbed from os.environ<br/>before target code runs"]
    end

    AH -->|"sign line with key"| FD3["fd 3<br/>private channel"]
    TC -.->|"can write<br/>unsigned lines"| FD3
    FD3 --> P["oracle parser"]
    P --> V{"signature valid?"}
    V -->|yes| EV["counted as an event"]
    V -->|no| FL["forged_lines + 1<br/>zero events"]

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef key fill:#1a2333,stroke:#3b6ea5,color:#ffffff
    classDef bad fill:#2a1215,stroke:#b3474f,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    class TC,AH,FD3,P,V base
    class K key
    class FL bad
    class EV good
```

The **signature** is the control, not the secrecy of the nonce or of fd 3. The
PoC source embeds the nonce and the target can write to fd 3 — neither matters,
because an unsigned line parses to nothing.

The honest limit: target and hook share an interpreter, so a target written
specifically to attack PyHunt can still recover the key from process memory.
This defeats opportunistic forgery and forces any attack to be deliberate and
PyHunt-specific. Out-of-process observation is the real fix and is out of scope.

---

## 8. Isolation tiers

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart TD
    D["sandbox.py detect"] --> Q1{"Docker usable?"}
    Q1 -->|no| T0["none<br/>Static only"]
    Q1 -->|yes| Q2{"Linux with runsc?"}
    Q2 -->|yes| TG["gvisor<br/>syscall interception"]
    Q2 -->|no| Q3{"Separate kernel?<br/>Docker Desktop,<br/>Lima, Colima, WSL2"}
    Q3 -->|yes| TV["vm<br/>separate kernel in a VM"]
    Q3 -->|no| TR["runc<br/>namespaces, shared kernel"]

    TG --> ALLOW(["Proof mode allowed"])
    TV --> ALLOW
    TR --> REFUSE(["refused"])
    T0 --> REFUSE

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    classDef bad fill:#2a1215,stroke:#b3474f,color:#ffffff
    class D,Q1,Q2,Q3 base
    class TG,TV,ALLOW good
    class TR,T0,REFUSE bad
```

`runc` is refused even though it is "a container": namespaces share the host
kernel with code you have just concluded is exploitable. The achieved tier is
recorded in the manifest and restated in the report, so a `vm` scan can never
claim `gvisor`.

---

## 9. Artefacts on disk

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","fontSize":"14px"}}}%%
flowchart TD
    R["target_PYHUNT_RESULTS_timestamp/"]
    R --> M["manifest.json<br/>phases completed, tier, mode"]
    R --> PF["preflight.json"]
    R --> IJ["inputs.json"]
    R --> TJ["tasks.json"]
    R --> TO["task_outcomes.json<br/>append-only"]
    R --> FD["findings/id.json"]
    R --> VD["verify/id.json"]
    R --> CJ["coverage.json"]
    R --> LG["logs/<br/>history.json, replay output"]
    R --> RJ["report.json<br/>schema-validated"]
    R --> RM["report.md<br/>the advisory"]

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef key fill:#1a2333,stroke:#3b6ea5,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    class M,PF,IJ,TJ,TO,FD,VD,CJ,LG,RJ base
    class R key
    class RM good
```

Every one of these is written as its phase completes, so a disconnect costs one
phase, not one run.

---

## 10. Trust boundaries

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0d1117","primaryColor":"#161b22","primaryTextColor":"#ffffff","primaryBorderColor":"#3d444d","lineColor":"#9aa4b2","secondaryColor":"#1c2128","tertiaryColor":"#21262d","mainBkg":"#161b22","textColor":"#ffffff","nodeTextColor":"#ffffff","edgeLabelBackground":"#161b22","clusterBkg":"#11161d","clusterBorder":"#3d444d","fontSize":"14px"}}}%%
flowchart TB
    subgraph HOST["Host · never runs target code"]
        CC["Claude Code + skill"]
        SCR["scripts/ · analysis only"]
        GATE["oracle/ · the verdict"]
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

    B1{{"Boundary 1 · host / VM<br/>separate kernel"}}
    B2{{"Boundary 2 · agent / oracle<br/>judgement cannot grade itself"}}
    B3{{"Boundary 3 · target / observer<br/>same process — signature, not secrecy"}}

    classDef base fill:#161b22,stroke:#3d444d,color:#ffffff
    classDef run fill:#2a2113,stroke:#9e7b28,color:#ffffff
    classDef good fill:#12261c,stroke:#2ea043,color:#ffffff
    classDef weak fill:#2a1215,stroke:#b3474f,color:#ffffff
    class CC,SCR,POC,TGT,HOOK base
    class GATE good
    class B1,B2 good
    class B3 weak
```

Boundary 3 is the weakest and is documented as such. Boundaries 1 and 2 are
structural; boundary 3 raises the cost of an attack without eliminating it.

---

## Further reading

| Document | What it holds |
|---|---|
| [`README.md`](../README.md) | What PyHunt is, install, usage, comparison |
| [`pyhunt/SKILL.md`](../pyhunt/SKILL.md) | The orchestrator Claude Code actually executes |
| [`pyhunt/phases/`](../pyhunt/phases/) | The methodology, one file per phase |
| [`pyhunt/references/execution-gate.md`](../pyhunt/references/execution-gate.md) | The gate specified in prose |
| [`pyhunt/references/python-sinks.md`](../pyhunt/references/python-sinks.md) | The sink catalogue |
| [`pyhunt/references/honest-reporting.md`](../pyhunt/references/honest-reporting.md) | What may and may not be claimed |
| [`pyhunt/references/output-contracts.md`](../pyhunt/references/output-contracts.md) | The shape every phase must emit |
