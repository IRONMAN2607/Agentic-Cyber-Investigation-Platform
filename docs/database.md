# Database Design

## 1. Conventions

- **UUID primary keys** (`sa.Uuid`). Investigation ids appear in URLs and reports; sequential integers
  would leak volume and allow enumeration.
- **Display ids** are derived, not stored: `INV-`, `ART-`, `EVD-`, `FND-` + first 8 hex chars. Human
  labels in reports without a second identity column to keep in sync.
- **Enums stored as strings**, not native SQL enums, so the schema is portable between SQLite and
  PostgreSQL and adding a member needs no migration. `types.py` holds the vocabulary.
- **All timestamps timezone-aware UTC.** `EvidenceDraft` rejects naive datetimes at the boundary.
- **No ORM `relationship()` declarations.** Async SQLAlchemy raises on implicit lazy loads and every
  access path is an explicit query, so relationships would add failure modes without adding value.
- **`ondelete` is explicit**: `CASCADE` for investigation-owned rows, `SET NULL` for actor references
  so deleting a user cannot erase the record of what happened.

## 2. Current schema (9 tables)

```text
users
  id PK · username UQ · email · password_hash · role · is_active · created_at

investigations
  id PK · title · target_type · target_value · status IX
  severity · confidence · risk_score            ← deterministic roll-ups
  created_by FK→users SET NULL · created_at IX · started_at · completed_at · error

artifacts
  id PK · investigation_id FK→investigations CASCADE IX
  kind · original_filename · sha256 IX · size_bytes · storage_path
  uploaded_at · uploaded_by FK→users SET NULL

agent_runs                                       ← execution trace
  id PK · investigation_id FK CASCADE IX
  task_id · agent_name IX · agent_version · status
  rationale                                      ← why this task existed
  inputs JSON · outputs JSON
  started_at · finished_at · duration_ms · error

tool_runs                                        ← audit of every invocation
  id PK · investigation_id FK CASCADE IX · agent_run_id FK SET NULL
  tool_name IX · tool_version · sandbox_tier · args JSON
  status · exit_status · evidence_count · warnings JSON
  started_at · finished_at · duration_ms · error

evidence                                         ← append-only
  id PK · investigation_id FK CASCADE IX
  kind · source_tool
  observed_at · time_confidence · collected_at
  data JSON · entities JSON · confidence · content_hash IX
  artifact_id FK SET NULL · tool_run_id FK SET NULL · agent_run_id FK SET NULL
  UNIQUE (investigation_id, content_hash)
  INDEX (investigation_id, kind) · (investigation_id, observed_at)

findings
  id PK · investigation_id FK CASCADE IX
  title · description · assertion_class · severity · confidence
  evidence_ids JSON · reasoning · detection_rule
  agent_run_id FK SET NULL · created_at

reports
  id PK · investigation_id FK CASCADE IX · fmt · content · generated_at
  agent_run_id FK SET NULL

audit_log                                        ← append-only
  id PK · ts IX · actor · action IX
  resource_type · resource_id · outcome · detail JSON
```

### Append-only enforcement

`evidence` and `audit_log` reject `UPDATE`/`DELETE` via SQLAlchemy mapper events. Enforcing it at the
mapper means a mistake anywhere in the codebase fails loudly rather than silently rewriting history.
Phase 5 adds database-level enforcement by revoking the grants in PostgreSQL, so the guarantee holds
even against code that bypasses the ORM.

### Index rationale

`UNIQUE(investigation_id, content_hash)` is the deduplication mechanism, not merely an optimisation —
it makes re-running a tool idempotent. `(investigation_id, observed_at)` serves timeline
construction, the dominant read pattern. `(investigation_id, kind)` serves the filtered evidence
list. `artifacts.sha256` is indexed to detect the same artifact submitted across investigations.

## 3. Planned schema

### Phase 5 — graph and citation

```text
entities                    resolved real-world things
  id PK · investigation_id FK CASCADE
  type · value_normalized · value_raw_first_seen
  first_seen_at · last_seen_at · observation_count
  UNIQUE (investigation_id, type, value_normalized)

entity_edges                relationships
  id PK · investigation_id FK CASCADE
  src_entity_id FK · dst_entity_id FK · relation
  evidence_id FK→evidence          ← every edge is evidence-backed
  observed_at · confidence
  INDEX (investigation_id, src_entity_id) · (investigation_id, dst_entity_id)
  UNIQUE (investigation_id, src_entity_id, dst_entity_id, relation, evidence_id)

finding_evidence            replaces findings.evidence_ids JSON
  finding_id FK · evidence_id FK · role   ← SUPPORTS | CONTRADICTS
  PRIMARY KEY (finding_id, evidence_id, role)
```

`entity_edges.evidence_id` is **NOT NULL**: an edge with no evidence is an assertion, and this system
does not store unbacked assertions. `finding_evidence.role` is what makes §3's "contradicting
observations" storable and G6 enforceable.

### Phase 7 — hypotheses

```text
hypotheses
  id PK · investigation_id FK CASCADE
  statement · status                  ← PROPOSED | SUPPORTED | REFUTED | UNRESOLVED
  confidence · refutation_condition   ← NOT NULL: G3
  agent_run_id FK · created_at

hypothesis_evidence
  hypothesis_id FK · evidence_id FK · role   ← SUPPORTS | CONTRADICTS
  PRIMARY KEY (hypothesis_id, evidence_id, role)

hypothesis_gaps                       what is missing to decide
  id PK · hypothesis_id FK · description · required_tool · resolved
```

`refutation_condition` is `NOT NULL` at the schema level, enforcing G3 in the database as well as the
store. `hypothesis_gaps` is what lets the orchestrator decide whether more investigation is warranted
(§2 item 18) from data rather than from a model's opinion.

### Phase 6 — model observability

```text
llm_calls                             the research dataset
  id PK · investigation_id FK · agent_run_id FK
  task_class · provider · model · prompt_name · prompt_version
  tokens_in · tokens_out · latency_ms · cost_estimate_usd
  finish_reason · retries · schema_valid · fallback_from
  temperature · seed · nondeterminism_risk · grounding_violations
  created_at
```

### Phase 4 — knowledge and intel

```text
attack_mappings
  id PK · investigation_id FK · finding_id FK
  tactic_id · technique_id · sub_technique_id
  catalog_version                     ← which ATT&CK release; ids drift
  explanation · evidence_id FK · confidence

threat_intel_lookups
  id PK · investigation_id FK · tool_run_id FK
  source · query_type · query_value · queried_at
  verdict · score · raw_response JSON · cache_expires_at
```

`attack_mappings.catalog_version` exists because ATT&CK technique ids are revised between releases; a
mapping without its catalog version is unreproducible. `threat_intel_lookups` is separate from
`evidence` because an intel result is evidence *that a source said something* at a point in time —
cacheable and expiring — not evidence about the indicator itself.

## 4. Migrations

**Current state: `create_all()`, no migrations.** Acceptable only while no data is worth keeping.

**Alembic is introduced in Phase 1′**, before any real investigation data exists. Rules once adopted:
autogenerate then hand-review every revision (autogenerate misses index and constraint intent);
every revision has a tested downgrade; data migrations are separate revisions from schema migrations.

## 5. Retention and privacy

Investigation data contains usernames, hostnames, and IP addresses — personal data under most
regimes, and sensitive operational data regardless. Phase 5 adds:

- Configurable retention with hard deletion of `artifacts` (the raw bytes) while preserving evidence
  and audit rows.
- A documented redaction path for exported reports.
- Confirmation that `CASCADE` on `investigations` is sufficient for a deletion request — with the
  deliberate exception of `audit_log`, which is append-only by design and must survive.

This tension is real and stated rather than hidden: an append-only audit log and a right-to-erasure
request are in conflict, and the resolution (audit rows retain actor and action but never artifact
content) needs to be a documented decision before any non-lab data is processed.
