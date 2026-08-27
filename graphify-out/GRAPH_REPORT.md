# Graph Report - AACIP  (2026-08-28)

## Corpus Check
- 119 files · ~66,880 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1079 nodes · 2875 edges · 105 communities (75 shown, 30 thin omitted)
- Extraction: 80% EXTRACTED · 20% INFERRED · 0% AMBIGUOUS · INFERRED: 563 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `6982624a`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- logging.py
- store.py
- tools/runner.py
- Artifact
- InvestigationRunner
- models.py
- investigations.py
- test_migrations.py
- Evidence
- types.py
- ioc_extractor.py
- errors.py
- Hypothesis
- test_rate_limit.py
- contracts.py
- conftest.py
- Grounding Invariants G0-G4
- tokens.py
- cli.py
- test_grounding.py
- InvestigationStatus
- CLAUDE.md
- bootstrap.py
- Services
- agentrouter
- Investigation
- HypothesisDraft
- db/base.py
- orchestrator.py
- test_types.py
- app.js
- config.py
- Three-Transaction Orchestrator
- Settings
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- app.py
- store_stream
- AdaptivePlanner
- Reporting Agent
- FastAPI REST API
- Milestone 1 (M1) Vertical Slice
- Localhost Single-User Deployment Boundary
- Two-Tier Conservative Entity Resolution
- Provider Error Taxonomy and Fallback Policy
- ReplayProvider Test Double
- RQ5 Analyst Study Scoping Decision
- 0003_evidence_provenance_restrict.py
- detection/__init__.py
- orchestration/__init__.py
- security/__init__.py
- tools/__init__.py
- Validation Agent
- Retention Lifecycle (Reproducible, Derived-Only, Audit-Only)
- Database Schema Conventions
- Phase 4+ Lab Network Topology
- Graph Entity Types
- Three-Tier Dataset Strategy
- React/Vite/Cytoscape.js Frontend Stack and Views
- Schema Validation and Structured Output
- Core Architectural Assumptions (A1-A14)
- Phased Delivery Schedule (Phases 0 to 10)
- acip
- AACIP Platform Overview
- _get_python_files
- .opencode/opencode.json
- ModelExecution
- test_auth.py
- ScorableFinding
- test_capabilities.py
- graphify.js
- test_health
- test_auth_log_incident_scenario
- AGENTS.md
- AgentContext
- Database
- EvidenceStore
- Severity
- AgentRegistry
- upload_artifact
- deps.py
- log_context
- auth.py
- get_session
- test_upload_security.py
- _sqlite_pragmas
- test_deleting_an_investigation_no_longer_cascades_into_evidence
- test_investigation_lifecycle.py
- session.py

## God Nodes (most connected - your core abstractions)
1. `EvidenceStore` - 55 edges
2. `Database` - 55 edges
3. `Investigation` - 46 edges
4. `Severity` - 44 edges
5. `Evidence` - 43 edges
6. `Role` - 40 edges
7. `Settings` - 36 edges
8. `AgentContext` - 34 edges
9. `AssertionClass` - 34 edges
10. `Orchestrator` - 32 edges

## Surprising Connections (you probably didn't know these)
- `test_sliding_window_rate_limiter_unit()` --uses--> `SlidingWindowRateLimiter`  [INFERRED]
  tests/security/test_rate_limit.py → src/acip/core/security/ratelimit.py
- `test_role_values()` --uses--> `Role`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_investigation_status_terminal()` --uses--> `InvestigationStatus`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_severity_ordering()` --uses--> `Severity`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_assertion_class_values()` --uses--> `AssertionClass`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **End-to-End Evidence Provenance Pipeline** — docs_tools_tool_adapter_contract, docs_evidence_model_evidence_record, docs_evidence_model_traceability_chain, docs_frontend_provenance_ui_rules, docs_evidence_graph_relationships [EXTRACTED 1.00]
- **Experimental Evaluation and Ablation Framework** — docs_experiments_comparison_conditions, docs_experiments_ablations, docs_experiments_evaluation_metrics, docs_research_central_question, docs_model_abstraction_replay_double [EXTRACTED 1.00]
- **Grounding Invariants Enforcement Subsystem** — docs_evidence_model_grounding_invariants, docs_agents_agent_contract, docs_model_abstraction_core_llm, docs_experiments_evaluation_metrics, docs_research_central_question [EXTRACTED 1.00]

## Communities (105 total, 30 thin omitted)

### Community 0 - "logging.py"
Cohesion: 0.21
Nodes (9): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, Structured logging with investigation correlation. Every log record emitted…, Merge the ambient context into each record., One JSON object per line, suitable for ingestion by a log pipeline. (+1 more)

### Community 1 - "store.py"
Cohesion: 0.13
Nodes (17): Collection, ColumnElement, _evidence_after(), _evidence_cursor(), EvidencePage, Append-only evidence store and grounding enforcement. This module is where the…, One page of evidence in timeline order, with a cursor for the next. The sort…, Every matching row up to ``cap``, and whether the cap cut the read short.… (+9 more)

### Community 2 - "tools/runner.py"
Cohesion: 0.06
Nodes (40): One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun, A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError, ValidationError, Everything an adapter is permitted to know about its invocation., ToolContext (+32 more)

### Community 3 - "Artifact"
Cohesion: 0.22
Nodes (5): Planner, Protocol, Chooses which agents run, in what order, and why., Artifact, An uploaded input, stored content-addressed under the quarantine dir.

### Community 4 - "InvestigationRunner"
Cohesion: 0.16
Nodes (9): InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle., Cancel an in-flight investigation task., Await every scheduled investigation. Used by tests and shutdown. (+1 more)

### Community 5 - "models.py"
Cohesion: 0.13
Nodes (19): DeclarativeBase, Mapped, Base, Base class for all ORM models., AuditLog, FindingEvidence, _forbid_mutation(), HypothesisEvidence (+11 more)

### Community 6 - "investigations.py"
Cohesion: 0.13
Nodes (28): Investigation lifecycle endpoints., AgentRunResponse, AuditLogResponse, ErrorResponse, EvidenceResponse, FindingEvidenceResponse, FindingResponse, HypothesisCreate (+20 more)

### Community 7 - "test_migrations.py"
Cohesion: 0.31
Nodes (8): _current_revision(), Connection, The migration chain is the schema, so the suite runs on it. Every fixture…, The fixture's schema came from Alembic, not from ``create_all``., ``Base.metadata`` describes exactly what the migrations build., _schema_diff(), test_bootstrap_stamps_the_database_at_head(), test_models_and_migrations_do_not_drift()

### Community 8 - "Evidence"
Cohesion: 0.16
Nodes (10): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, RiskAssessment, Evidence, Finding (+2 more)

### Community 9 - "types.py"
Cohesion: 0.18
Nodes (8): parametrize, Agent registry. Agents are looked up by name or capability rather than imported…, Investigation planning. A plan is an ordered list of :class:`Task`, each naming…, Shared enumerations. These are the vocabulary of the platform. They are stored…, AsyncClient, test_investigation_crud_and_lifecycle(), AsyncClient, test_endpoint_role_matrix()

### Community 10 - "ioc_extractor.py"
Cohesion: 0.05
Nodes (56): IPv4Address, IPv6Address, Match, EntityRef, normalize_entity_value(), Canonicalise an entity value so the same thing has one representation. Entity…, A typed reference to a real-world entity observed in evidence., AuthLogParserArgs (+48 more)

### Community 11 - "errors.py"
Cohesion: 0.11
Nodes (18): Exception, Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, Thread-safe sliding window rate limiter., Check whether the key is within rate limits; increments counter if allowed.…, Clear all rate limit history (useful in tests)., FastAPI dependency for rate limiting endpoints by client IP. (+10 more)

### Community 12 - "Hypothesis"
Cohesion: 0.33
Nodes (4): Hypothesis, A competing candidate explanation, requiring a refutation condition (G3)., HypothesisStatus, Status of a competing explanatory hypothesis.

### Community 13 - "test_rate_limit.py"
Cohesion: 0.40
Nodes (5): AsyncClient, The investigation limiter was defined and wired to nothing. Login was the only…, test_auth_login_rate_limiting(), test_investigation_creation_is_rate_limited(), test_sliding_window_rate_limiter_unit()

### Community 14 - "contracts.py"
Cohesion: 0.21
Nodes (10): EvidenceDraft, datetime, Evidence and finding contracts. Agents and tools exchange these Pydantic models…, Stable digest of the observation, used to deduplicate evidence. Covers only…, An observation produced by a tool, before persistence. ``observed_at`` is when…, EvidenceKind, test_evidence_deduplication(), test_finding_evidence_relational_citation() (+2 more)

### Community 15 - "conftest.py"
Cohesion: 0.29
Nodes (13): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+5 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "tokens.py"
Cohesion: 0.21
Nodes (16): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, JWT access tokens. Short-lived bearer tokens signed with HS256. Refresh tokens…, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`. (+8 more)

### Community 18 - "cli.py"
Cohesion: 0.22
Nodes (12): ArgumentParser, build_parser(), _capabilities(), _create_user(), _init(), main(), Command-line entry point. Provides the operational commands a fresh checkout…, Print the real capability set, probed rather than assumed. (+4 more)

### Community 19 - "test_grounding.py"
Cohesion: 0.44
Nodes (8): _create_tool_run(), _draft_evidence(), AsyncSession, UUID, test_grounding_invariant_cross_investigation_isolated(), test_grounding_invariant_g1_fact_requires_deterministic_tool_evidence(), test_grounding_invariant_g2_inference_requires_evidence_and_reasoning(), test_valid_fact_with_evidence_persisted()

### Community 20 - "InvestigationStatus"
Cohesion: 0.16
Nodes (21): Investigator, patch, cancel_investigation(), create_investigation(), post, Update investigation metadata (title, target_value, retention_state)., Queue the investigation for execution., Cancel / Halt an in-progress or queued investigation. (+13 more)

### Community 22 - "bootstrap.py"
Cohesion: 0.19
Nodes (13): Application bootstrap. Migrates the schema to head and, outside production,…, Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), hash_password(), needs_rehash(), Password hashing. Argon2id via ``argon2-cffi``, which is the current OWASP…, Return whether the password matches. Never raises on a bad password., True when the hash was produced with weaker parameters than current. (+5 more)

### Community 23 - "Services"
Cohesion: 0.13
Nodes (24): Admin, get_services(), get_settings_dep(), Depends, Request, Everything built once at startup., Services, admin_capabilities() (+16 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "Investigation"
Cohesion: 0.17
Nodes (11): build_default_registry(), The agents available in this milestone. Phase 2 adds the network, endpoint,…, Plan, An ordered set of tasks plus the reason the shape was chosen., Investigation, TargetType, MockPlanner, Any (+3 more)

### Community 26 - "HypothesisDraft"
Cohesion: 0.15
Nodes (13): FindingEvidenceDraft, HypothesisDraft, HypothesisGapDraft, BaseModel, field_validator, A citation connecting evidence to a finding with a supporting or contradicting…, A competing candidate explanation under evaluation (Invariant G3)., A declared gap in evidence preventing resolution of a hypothesis. (+5 more)

### Community 27 - "db/base.py"
Cohesion: 0.29
Nodes (7): Dialect, datetime, Declarative base and portable column types. The schema deliberately avoids…, Store timezone-aware datetimes as UTC and read them back aware. Rejects naive…, Timezone-aware current time. Used as a column default., UTCDateTime, utcnow()

### Community 28 - "orchestrator.py"
Cohesion: 0.22
Nodes (17): _derive_status(), InvestigationOutcome, _load_artifacts(), _load_investigation(), Orchestrator, AsyncSession, UUID, Investigation orchestration. Executes a plan task by task, recording an… (+9 more)

### Community 29 - "test_types.py"
Cohesion: 0.33
Nodes (5): test_assertion_class_values(), test_investigation_status_terminal(), test_role_values(), test_severity_ordering(), test_time_confidence_values()

### Community 30 - "app.js"
Cohesion: 0.56
Nodes (8): api(), checkCurrentUser(), escapeHtml(), loadInvestigations(), renderWorkspace(), selectInvestigation(), setAuth(), showLogin()

### Community 31 - "config.py"
Cohesion: 0.22
Nodes (11): do_run_migrations(), Connection, Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_offline(), run_migrations_online() (+3 more)

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "Settings"
Cohesion: 0.11
Nodes (18): BaseSettings, Config, model_validator, field_validator, Create runtime directories. Called once at startup., Resolved application settings., Require a real secret in production; generate an ephemeral one otherwise. A…, Settings (+10 more)

### Community 34 - "ToolAdapter Base Contract"
Cohesion: 0.40
Nodes (5): End-to-End Evidence Traceability Chain, Command Injection Prevention by Construction, Phase 4 SSRF Protection Design, Sandbox Tiers (T0_IN_PROCESS to T3_NETWORK), ToolAdapter Base Contract

### Community 35 - "auth_log_parser Tool"
Cohesion: 0.50
Nodes (4): Log Analysis Agent, Triage Agent, auth_log_parser Tool, ioc_extractor Tool

### Community 36 - "Argon2id and HS256 JWT Security"
Cohesion: 0.50
Nodes (4): Role-Based Access Control (Viewer/Investigator/Admin), Environment Settings and Fail-Closed Prod Secret, In-Memory Auth Token Handling, Argon2id and HS256 JWT Security

### Community 37 - "Phase 5 Graph Entities & Edges Schema"
Cohesion: 0.50
Nodes (4): Decision: SQLite Dev to PostgreSQL Prod, Phase 5 Graph Entities & Edges Schema, Evidence-Backed Relationships, Evidence Record and Dual Timestamps

### Community 38 - "Phase 1' Verification Retrofit"
Cohesion: 0.50
Nodes (4): Ranked Architectural Risks (R1-R13), Phase 1' Verification Retrofit, Definition of Done (9 Criteria), Phase 0 Status and Verification Debt

### Community 39 - "Decision: PostgreSQL Relational Graph vs Neo4j"
Cohesion: 0.67
Nodes (3): Decision: PostgreSQL Relational Graph vs Neo4j, Depth-Bounded Recursive CTE Traversal, Decisions Requiring Team Sign-Off (D1-D10)

### Community 40 - "app.py"
Cohesion: 0.18
Nodes (12): RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, _serialisable_errors(), bootstrap() (+4 more)

### Community 41 - "store_stream"
Cohesion: 0.17
Nodes (19): Path, Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Remove group/other access and any execute bit where the OS supports it., Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, Result of a successful intake., Reduce a client-supplied filename to a safe display label. The result is used…, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, read_text() (+11 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 72 - "_get_python_files"
Cohesion: 0.44
Nodes (8): _get_python_files(), Path, The schema has one source of truth: the Alembic chain. ``create_all`` was the…, A reserved key in ``extra`` raises KeyError only when the record is emitted.…, test_no_direct_llm_sdk_imports_in_agents(), test_no_metadata_create_all_in_src(), test_no_reserved_logrecord_keys_in_log_extra(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 74 - "ModelExecution"
Cohesion: 0.33
Nodes (8): ModelExecutionDraft, Structured record of an LLM call for experimental tracking., ModelExecution, Audited execution trace of any LLM invocation (append-only research dataset).…, FinishReason, LLM completion termination reason., test_model_execution_append_only(), test_model_execution_draft()

### Community 75 - "test_auth.py"
Cohesion: 0.60
Nodes (4): AsyncClient, test_auth_login_invalid_password(), test_auth_login_success(), test_auth_me_endpoint()

### Community 76 - "ScorableFinding"
Cohesion: 0.33
Nodes (3): Protocol, Structural type covering both ORM findings and drafts., ScorableFinding

### Community 77 - "test_capabilities.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_admin_capabilities_access_control(), test_public_capabilities()

### Community 81 - "test_auth_log_incident_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_auth_log_incident_scenario(), test_clean_log_scenario()

### Community 83 - "AgentContext"
Cohesion: 0.07
Nodes (47): Agent, AgentContext, AgentResult, ABC, Any, BaseModel, Agent contract. Agents receive a typed context and return a typed result (spec…, Everything an agent is given for one execution. (+39 more)

### Community 90 - "Database"
Cohesion: 0.15
Nodes (21): AsyncEngine, Database, Yield a session, committing on success and rolling back on error., Owns the engine and session factory for one database URL., AsyncSession, The guard must bound its own blast radius: reads stay unaffected., One named escape hatch, so deliberate destruction is greppable., An investigation with evidence, for the bulk-DML cases below. (+13 more)

### Community 91 - "EvidenceStore"
Cohesion: 0.16
Nodes (12): EvidenceStore, AsyncSession, UUID, Writes evidence and findings for a single investigation., Persist drafts, skipping observations already recorded. Deduplication is by…, Validate a claim against the grounding invariants and persist it., Validate a hypothesis and persist it with supporting/contradicting links., Record an explicit knowledge gap preventing hypothesis resolution. (+4 more)

### Community 92 - "Severity"
Cohesion: 0.22
Nodes (13): Report agent. Renders a deterministic Markdown investigation report from stored…, Declared limitations of this deployment. A single source for what the platform…, assess(), Deterministic risk scoring. Severity and risk are computed from findings by a…, Roll findings up into an investigation-level severity and risk score., AssertionClass, Epistemic status of a claim. See docs/evidence-model.md. The distinction is…, Severity (+5 more)

### Community 93 - "AgentRegistry"
Cohesion: 0.14
Nodes (8): AgentRegistry, Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint., build_services(), Compose the object graph. Pure wiring, no I/O., Rule-based planner: reproducible, and the control condition for the study.…, StaticPlanner, test_recovery_interrupted_investigation()

### Community 94 - "upload_artifact"
Cohesion: 0.18
Nodes (14): File, Form, _chunks(), Accept an artifact into content-addressed quarantine storage., Stream an upload without buffering it whole., upload_artifact(), ArtifactResponse, InvestigationUpdate (+6 more)

### Community 95 - "deps.py"
Cohesion: 0.16
Nodes (21): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), AsyncSession, CurrentUser, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,… (+13 more)

### Community 96 - "log_context"
Cohesion: 0.67
Nodes (3): log_context(), Any, Temporarily bind values to the logging context.

### Community 97 - "auth.py"
Cohesion: 0.21
Nodes (12): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+4 more)

### Community 98 - "get_session"
Cohesion: 0.10
Nodes (40): alias, delete, description, ge, le, LoadedInvestigation, MAX_EVIDENCE_PAGE, Query (+32 more)

### Community 99 - "test_upload_security.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_upload_empty_file_rejected(), test_upload_path_traversal_sanitized()

### Community 101 - "_sqlite_pragmas"
Cohesion: 0.29
Nodes (5): async_sessionmaker, Any, AsyncSession, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., _sqlite_pragmas()

### Community 103 - "test_investigation_lifecycle.py"
Cohesion: 0.43
Nodes (6): investigator_auth(), AsyncClient, FastAPI, fixture, test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 104 - "session.py"
Cohesion: 0.14
Nodes (12): Logger, ORMExecuteState, Audit trail writes. Security-relevant actions are recorded in an append-only…, Background execution of investigations. M1 runs investigations as asyncio tasks…, authorized_purge(), _forbid_bulk_dml(), Async engine and session management. Exposed as a class rather than module…, Strip credentials before a URL reaches the logs. (+4 more)

## Knowledge Gaps
- **61 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+56 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **30 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Severity` to `store.py`, `models.py`, `investigations.py`, `Evidence`, `types.py`, `contracts.py`, `test_auth_log_incident_scenario`, `AgentContext`, `InvestigationStatus`, `test_grounding.py`, `Database`, `EvidenceStore`, `test_types.py`, `upload_artifact`?**
  _High betweenness centrality (0.045) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `tools/runner.py`, `Artifact`, `InvestigationRunner`, `test_migrations.py`, `contracts.py`, `conftest.py`, `cli.py`, `test_grounding.py`, `bootstrap.py`, `Services`, `Investigation`, `orchestrator.py`, `app.py`, `ModelExecution`, `AgentRegistry`, `deps.py`, `get_session`, `_sqlite_pragmas`, `test_deleting_an_investigation_no_longer_cascades_into_evidence`, `session.py`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Why does `Settings` connect `Settings` to `Artifact`, `test_investigation_lifecycle.py`, `app.py`, `orchestrator.py`, `conftest.py`, `cli.py`, `AgentContext`, `bootstrap.py`, `Services`, `Investigation`, `config.py`, `AgentRegistry`, `deps.py`?**
  _High betweenness centrality (0.042) - this node is a cross-community bridge._
- **Are the 34 inferred relationships involving `EvidenceStore` (e.g. with `AgentContext` and `list_evidence()`) actually correct?**
  _`EvidenceStore` has 34 INFERRED edges - model-reasoned connections that need verification._
- **Are the 37 inferred relationships involving `Database` (e.g. with `build_services()` and `Services`) actually correct?**
  _`Database` has 37 INFERRED edges - model-reasoned connections that need verification._
- **Are the 28 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 28 INFERRED edges - model-reasoned connections that need verification._
- **Are the 30 inferred relationships involving `Severity` (e.g. with `LogAnalysisAgent` and `ReportAgent`) actually correct?**
  _`Severity` has 30 INFERRED edges - model-reasoned connections that need verification._