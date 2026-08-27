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
- **`ondelete` is explicit**: `CASCADE` is limited to disposable, investigation-owned operational
  rows. Evidence preservation, raw-artifact destruction, and administrative purge use documented
  lifecycle operations rather than treating parent deletion as an integrity policy.
- **Bounded records:** application inputs and outputs have explicit per-investigation quotas. Tool
  output is retained only within its declared cap and records deterministic truncation metadata; an
  upload limit alone does not bound storage or query cost.

## 2. Current schema (14 tables)

```text
users
  id PK · username UQ · email · password_hash · role · is_active · created_at

investigations
  id PK · title · target_type · target_value · status IX
  severity · confidence · risk_score · retention_state
  created_by FK→users SET NULL · created_at IX · started_at · completed_at · error

artifacts
  id PK · investigation_id FK→investigations CASCADE IX
  kind · original_filename · sha256 IX · size_bytes · storage_path · retention_state
  uploaded_at · uploaded_by FK→users SET NULL

task_runs                                        ← execution trace per plan task
  id PK · investigation_id FK CASCADE IX
  task_id IX · task_type · status · rationale
  inputs JSON · outputs JSON
  started_at · finished_at · duration_ms · error

agent_runs                                       ← execution trace per agent invocation
  id PK · investigation_id FK CASCADE IX
  task_id · agent_name IX · agent_version · status
  rationale · inputs JSON · outputs JSON
  started_at · finished_at · duration_ms · error

tool_runs                                        ← audit of every tool invocation
  id PK · investigation_id FK CASCADE IX · agent_run_id FK SET NULL · task_id
  tool_name IX · tool_version · sandbox_tier · args JSON
  status · exit_status · evidence_count · warnings JSON
  started_at · finished_at · duration_ms · error

evidence                                         ← append-only, content-hash deduplicated
  id PK · investigation_id FK RESTRICT IX
  kind · source_tool
  observed_at · time_confidence · collected_at
  data JSON · entities JSON · confidence · content_hash IX
  artifact_id FK RESTRICT · tool_run_id FK RESTRICT · agent_run_id FK RESTRICT
  UNIQUE (investigation_id, content_hash)
  INDEX (investigation_id, kind) · (investigation_id, observed_at)

findings
  id PK · investigation_id FK CASCADE IX
  title · description · assertion_class · severity · confidence
  evidence_ids JSON · reasoning · detection_rule
  agent_run_id FK SET NULL · created_at

finding_evidence                                 ← relational citation linking
  id PK · finding_id FK CASCADE · evidence_id FK CASCADE
  role                                           ← SUPPORTS | CONTRADICTS
  created_at
  UNIQUE (finding_id, evidence_id, role)

hypotheses                                       ← competing hypotheses (G3)
  id PK · investigation_id FK CASCADE
  statement · status                             ← PROPOSED | SUPPORTED | REFUTED | UNRESOLVED
  confidence · refutation_condition              ← NOT NULL (Invariant G3)
  agent_run_id FK SET NULL · created_at

hypothesis_evidence                              ← hypothesis citation linking
  id PK · hypothesis_id FK CASCADE · evidence_id FK CASCADE
  role                                           ← SUPPORTS | CONTRADICTS
  created_at
  UNIQUE (hypothesis_id, evidence_id, role)

hypothesis_gaps                                  ← declared evidence gaps
  id PK · hypothesis_id FK CASCADE
  description · required_tool · resolved · created_at

llm_calls                                        ← model executions trace (append-only)
  id PK · investigation_id FK RESTRICT IX · agent_run_id FK RESTRICT
  task_id · task_class · provider · model · prompt_name · prompt_version
  tokens_in · tokens_out · latency_ms · cost_estimate_usd
  finish_reason · retries · schema_valid · fallback_from
  temperature · seed · nondeterminism_risk · grounding_violations · created_at

reports
  id PK · investigation_id FK CASCADE · fmt · content · generated_at
  agent_run_id FK SET NULL

audit_log                                        ← append-only security audit trail
  id PK · ts IX · actor · action IX
  resource_type · resource_id · outcome · detail JSON
```

### Append-only enforcement

`evidence`, `audit_log`, and `llm_calls` reject `UPDATE`/`DELETE` via two complementary layers:
1. **Mapper events:** reject instance-level mutation (`before_update`, `before_delete` → `RuntimeError`).
2. **Session-level bulk DML guard (`do_orm_execute` event):** blocks `session.execute(update(...))` and `session.execute(delete(...))` across all append-only tables, preventing ungrounded bulk rewrites.
3. **Foreign key `RESTRICT`:** foreign keys pointing to `evidence` and `llm_calls` are `RESTRICT`, preventing parent deletion (`CASCADE`) or ungrounding (`SET NULL` on `tool_run_id`) beneath the ORM.

Deliberate destruction (such as GDPR/compliance investigation purges) requires the explicit `authorized_purge()` context manager and is audited before execution. Phase 5 adds database-level enforcement by revoking the grants in PostgreSQL.

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

**Current state: Alembic migrations active.**
- `0001_initial_schema`: Initial 9 core tables (`users`, `investigations`, `artifacts`, `agent_runs`, `tool_runs`, `evidence`, `findings`, `reports`, `audit_log`).
- `0002_core_domain_models`: Added domain models (`task_runs`, `finding_evidence`, `hypotheses`, `hypothesis_evidence`, `hypothesis_gaps`, `llm_calls`).
- `0003_evidence_provenance_restrict`: Upgraded foreign keys on append-only tables (`evidence`, `llm_calls`) to `RESTRICT` across `investigation_id`, `artifact_id`, `tool_run_id`, and `agent_run_id` to prevent silent deletion or ungrounding beneath the ORM.

Migrations are managed through Alembic and validated against head on startup (`alembic upgrade head`). Fresh installs and upgrades from released revisions are verified. Irreversible revisions document backup recovery procedures. The test suite automatically runs against the migrated SQLite schema.

## 5. Retention and privacy

Investigation data contains usernames, hostnames, and IP addresses — personal data under most
regimes, and sensitive operational data regardless. Retention is a per-investigation state, not an
accidental result of `CASCADE`:

- `reproducible`: encrypted source artifacts and derived outputs remain available for a declared
  period.
- `derived-only`: source bytes are destroyed while grounded evidence and audit metadata remain; the
  report states that byte-level replay is no longer possible.
- `minimal/audit-only`: only justified metadata remains.

An authorised purge uses a distinct audited lifecycle operation and records what was removed.
Evidence corrections append superseding records; they never mutate prior observations. A redaction
path exists for exported reports before non-lab data is processed.

Backups pair database and artifact storage, are encrypted, and restore-tested together. Integrity
validation fails if a `reproducible` investigation references an artifact absent from the restore.
