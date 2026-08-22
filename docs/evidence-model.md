# Evidence Model

The evidence system is the heart of the platform. It is what separates this project from an LLM
wrapper: findings are not assertions a model made, they are claims bound to observations that a
deterministic tool produced, with the binding checked at write time.

Referenced from `acip/core/evidence/store.py`, `acip/types.py`, and `acip/agents/base.py`.

## 1. Assertion classes

Every claim carries an epistemic status. This is the vocabulary from §3, implemented as
`AssertionClass` in `acip/types.py`.

| Class | Meaning | May a tool produce it? | May reasoning produce it? |
|---|---|---|---|
| `FACT` | Directly observed by a deterministic tool or authoritative source | yes | **no** |
| `INFERENCE` | Derived from one or more facts by explicit stated reasoning | no | yes |
| `HYPOTHESIS` | A candidate explanation that still requires validation | no | yes |
| `UNKNOWN` | Cannot currently be established; recorded so the gap stays visible | n/a | yes |

The rule that makes this real: **an LLM can never create a `FACT`.** Not by policy — by
construction. A `FACT` must cite evidence whose `tool_run_id` is non-NULL, and only the tool runner
sets `tool_run_id`. Reasoning output enters the system as `INFERENCE` or `HYPOTHESIS`, permanently
marked as such, and the report renders it under a different heading.

`UNKNOWN` is not a failure state. Recording what could not be established is a research
requirement: §37 demands the system answer "what remains unknown?", and an investigation that
silently omits its gaps is less useful than one that names them.

## 2. Evidence

An evidence row is an immutable observation with provenance.

```python
Evidence(
    kind=EvidenceKind.AUTH_EVENT,     # what class of observation
    source_tool="auth_log_parser",     # which adapter produced it
    observed_at=...,                   # when the event happened  (nullable)
    time_confidence=EXACT,             # how much to trust observed_at
    collected_at=...,                  # when the platform recorded it
    data={...},                        # normalized, tool-specific payload
    entities={"refs": [...]},          # typed EntityRefs for the graph
    confidence=1.0,                    # tool's confidence in the observation
    content_hash="…",                  # dedupe key
    artifact_id=..., tool_run_id=..., agent_run_id=...,   # provenance
)
```

### Immutability

`Evidence` and `AuditLog` reject `UPDATE` and `DELETE` through SQLAlchemy mapper events
(`before_update`, `before_delete` → `RuntimeError`). A correction is a new row, never an edit. The
history of what the platform believed and when is itself evidence. Phase 5 adds database-level
enforcement by revoking the grants in PostgreSQL, so the guarantee survives code that bypasses the
ORM.

### Two timestamps

`observed_at` and `collected_at` are separate and must never be conflated — merging them corrupts
the timeline, which is a primary output. `time_confidence` records the trustworthiness of
`observed_at`:

| Value | When |
|---|---|
| `EXACT` | The source carried an unambiguous timestamp |
| `DERIVED` | Reconstructed — e.g. syslog omits the year, so it was inferred from context |
| `APPROXIMATE` | Known only to a coarse window |
| `UNKNOWN` | No usable time information |

A `DERIVED` timestamp presented as fact is a subtle way to fabricate a timeline; recording the
distinction prevents it.

### Content hashing and deduplication

`EvidenceDraft.content_hash(source_tool)` digests `kind`, `source_tool`, `observed_at`, `data`, and
sorted normalized entities — **not** `collected_at`, run ids, or confidence. So the same observation
seen twice hashes identically, and a `UNIQUE(investigation_id, content_hash)` constraint plus an
in-batch guard makes re-running a tool idempotent. Evidence counts are therefore meaningful as a
metric rather than an artifact of how many times a tool ran.

### Entity normalization

`normalize_entity_value()` canonicalizes entity values at draft time so the same real-world thing
has exactly one representation: IPs through `ipaddress` (collapsing `203.0.113.045` and
`2001:0db8::0001`), domains lowercased with the trailing dot stripped, hashes lowercased, URL
schemes lowercased. Entity resolution in Phase 5 depends on this being deterministic and applied
*before* storage, so evidence collected in M1 is already graph-ready and investigations need not be
re-run.

## 3. Findings

A finding is a claim about the investigation, bound to its supporting evidence.

```python
Finding(
    title=..., description=...,
    assertion_class=...,          # FACT | INFERENCE | HYPOTHESIS | UNKNOWN
    severity=..., confidence=...,
    evidence_ids=[...],           # citations
    reasoning=...,                # required for INFERENCE and HYPOTHESIS
    detection_rule=...,           # deterministic rule id, when applicable
    agent_run_id=...,             # who asserted it
)
```

`evidence_ids` is a list of ids rather than a join table in M1 so the report layer can cite without
a join. A proper `finding_evidence` join table with a support/contradiction role arrives in Phase 5
alongside the graph — see [evidence-graph.md](evidence-graph.md).

## 4. Grounding invariants

Enforced in `EvidenceStore.add_finding()`. A violation raises `GroundingError`.

| ID | Invariant |
|---|---|
| **G0** | Every cited evidence id must exist **and** belong to the same investigation |
| **G1** | `FACT` requires ≥1 cited evidence row with `tool_run_id` set |
| **G2** | `INFERENCE` requires ≥1 cited evidence row **and** non-empty `reasoning` |
| **G3** | `HYPOTHESIS` requires `reasoning` stating what would confirm or refute it |
| **G4** | `UNKNOWN` must not carry a severity above `INFO` |

G0 blocks cross-investigation citation, which would otherwise let evidence from one case silently
support a conclusion in another.

G3 is deliberately demanding: a hypothesis that does not say what would refute it is not a
hypothesis, it is a guess. §5.9 requires the platform to actively attempt disproof, and that is only
possible if the refutation condition was written down when the hypothesis was created.

**Violations raise rather than downgrade.** Silently demoting an unsupported `FACT` to `INFERENCE`
would hide precisely the behaviour the research measures — the rate at which reasoning over-claims.
A `GroundingError` is an agent bug and must be visible. The rate of these errors per model and per
prompt version is a headline metric in [experiments.md](experiments.md).

### Planned invariants

| ID | Invariant | Phase |
|---|---|---|
| G5 | A `FACT` may not cite evidence whose `time_confidence` is `UNKNOWN` while asserting a time | 5 |
| G6 | Contradicting evidence, once linked, must be acknowledged in `reasoning` | 6 |
| G7 | An ATT&CK mapping must cite evidence and a technique id present in the loaded catalog | 4 |
| G8 | A severity above `MEDIUM` requires at least one `FACT` in its support set | 6 |

## 5. Confidence

Two distinct numbers, deliberately not merged:

- **Evidence confidence** — the tool's confidence that the observation is correct (a regex match on
  a well-formed log line is 1.0; a heuristic classification is lower).
- **Finding confidence** — how strongly the evidence supports the claim.

Finding confidence is set by the asserting agent and, for rule-derived findings, by the deterministic
rule. It is *not* an LLM-chosen number for anything that feeds risk scoring — see
[research.md](research.md) on why LLM-assigned severity is excluded from the roll-up.

## 6. Risk roll-up

`core/risk.py` computes investigation severity and risk score from findings by a fixed formula:
per-severity weights out of 100, with `HYPOTHESIS`-class findings contributing at a 0.5 discount
because they are not yet established. An LLM may later *propose* an adjustment, but it is recorded
as a separate attributed opinion and never overwrites the computed value (§5.11: do not let the LLM
arbitrarily assign "Critical").

## 7. Traceability

Every claim in a generated report resolves downward to bytes on disk:

```text
Finding  ──cites──▶  Evidence  ──tool_run_id──▶  ToolRun  ──artifact_id──▶  Artifact (sha256)
   │                     │                          │
   └──agent_run_id──▶ AgentRun ◄──agent_run_id──────┘
```

This chain is what makes the platform defensible academically: for any statement in the output, the
tool, arguments, agent, timestamp, and input file that produced it can be named.
