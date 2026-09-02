# Graph Report - AACIP  (2026-09-03)

## Corpus Check
- 144 files · ~84,213 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1407 nodes · 4058 edges · 123 communities (94 shown, 29 thin omitted)
- Extraction: 78% EXTRACTED · 22% INFERRED · 0% AMBIGUOUS · INFERRED: 897 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `fd862eed`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Evidence
- _evidence_after
- ReportAgent
- TimeConfidence
- InvestigationRunner
- backup.py
- schemas.py
- evaluate_auth_rules
- TriageAnalysis
- ValueError
- ioc_extractor.py
- ratelimit.py
- test_ssrf.py
- test_orchestrator_agent_with_model_router_triage
- triage.py
- conftest.py
- Grounding Invariants G0-G4
- tokens.py
- Settings
- types.py
- InvestigationStatus
- CLAUDE.md
- passwords.py
- system.py
- agentrouter
- test_artifact_validation.py
- models.py
- validation.py
- ValidationError
- test_artifact_ingestion_api.py
- app.js
- env.py
- Three-Transaction Orchestrator
- test_migrations.py
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- files.py
- AgentContext
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
- .complete
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
- orchestration/orchestrator.py
- _get_python_files
- .opencode/opencode.json
- investigations.py
- get_not_implemented
- llm/contracts.py
- Role
- graphify.js
- test_health
- test_auth.py
- AGENTS.md
- ProviderRateLimited
- EvidenceStore
- upgrade_to_head
- Severity
- NvidiaNIMProvider
- router.py
- Services
- ProviderAvailability
- Database
- AsyncSession
- _forbid_bulk_dml
- _build_chain
- acip/errors.py
- test_investigation_lifecycle.py
- Investigation
- app.py
- OrchestratorAgent
- auth.py
- _coerce
- db/base.py
- unit/test_domain_models.py
- test_auth_log_incident_scenario
- test_upload_security.py
- test_investigation_crud_and_lifecycle
- ToolRegistry
- ._perform_triage_analysis
- get_evidence_provenance
- SafeHTTPFetcher
- test_orchestrator_agent_end_to_end_lifecycle
- test_orchestrator_failure_rollback
- ToolInvocation
- MessageRole
- _sqlite_pragmas

## God Nodes (most connected - your core abstractions)
1. `Database` - 73 edges
2. `EvidenceStore` - 64 edges
3. `Investigation` - 64 edges
4. `Settings` - 59 edges
5. `Severity` - 51 edges
6. `AgentContext` - 48 edges
7. `Evidence` - 47 edges
8. `Role` - 44 edges
9. `Artifact` - 42 edges
10. `OrchestratorAgent` - 41 edges

## Surprising Connections (you probably didn't know these)
- `test_hypothesis_draft_invariant_g3_refutation_required()` --uses--> `HypothesisDraft`  [INFERRED]
  tests/unit/test_domain_models.py → src/acip/core/evidence/contracts.py
- `test_hypothesis_draft_valid()` --uses--> `HypothesisDraft`  [INFERRED]
  tests/unit/test_domain_models.py → src/acip/core/evidence/contracts.py
- `test_hypothesis_gap_draft()` --uses--> `HypothesisGapDraft`  [INFERRED]
  tests/unit/test_domain_models.py → src/acip/core/evidence/contracts.py
- `test_role_values()` --uses--> `Role`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_investigation_status_terminal()` --uses--> `InvestigationStatus`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **End-to-End Evidence Provenance Pipeline** — docs_tools_tool_adapter_contract, docs_evidence_model_evidence_record, docs_evidence_model_traceability_chain, docs_frontend_provenance_ui_rules, docs_evidence_graph_relationships [EXTRACTED 1.00]
- **Experimental Evaluation and Ablation Framework** — docs_experiments_comparison_conditions, docs_experiments_ablations, docs_experiments_evaluation_metrics, docs_research_central_question, docs_model_abstraction_replay_double [EXTRACTED 1.00]
- **Grounding Invariants Enforcement Subsystem** — docs_evidence_model_grounding_invariants, docs_agents_agent_contract, docs_model_abstraction_core_llm, docs_experiments_evaluation_metrics, docs_research_central_question [EXTRACTED 1.00]

## Communities (123 total, 29 thin omitted)

### Community 0 - "Evidence"
Cohesion: 0.15
Nodes (12): Logger, Log analysis agent. Parses authentication logs with a deterministic tool, then…, Report agent. Renders a deterministic Markdown investigation report from stored…, Application bootstrap. Migrates the schema to head and, outside production,…, Audit trail writes. Security-relevant actions are recorded in an append-only…, Background execution of investigations. M1 runs investigations as asyncio tasks…, Schema creation, through Alembic and only through Alembic. The migration chain…, Evidence (+4 more)

### Community 1 - "_evidence_after"
Cohesion: 0.12
Nodes (16): Collection, ColumnElement, _evidence_after(), _evidence_cursor(), EvidencePage, One page of evidence in timeline order, with a cursor for the next. The sort…, Every matching row up to ``cap``, and whether the cap cut the read short.…, One page of evidence, plus the cursor that continues it. (+8 more)

### Community 2 - "ReportAgent"
Cohesion: 0.13
Nodes (16): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, RiskAssessment, One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun (+8 more)

### Community 3 - "TimeConfidence"
Cohesion: 0.09
Nodes (29): Match, EntityRef, normalize_entity_value(), Canonicalise an entity value so the same thing has one representation. Entity…, A typed reference to a real-world entity observed in evidence., AuthLogParserArgs, LinuxAuthLogParser, Any (+21 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.14
Nodes (11): Orchestrator, InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle., Cancel an in-flight investigation task. (+3 more)

### Community 5 - "backup.py"
Cohesion: 0.23
Nodes (21): BackupIntegrityError, create_backup(), Path, Portable SQLite backup and restore with artifact-integrity verification. The…, A backup is incomplete or its artifact bytes do not match the database., Create and verify a consistent SQLite/artifact snapshot at ``destination``.…, Verify and restore ``source`` into empty configured SQLite/artifact paths.…, Raise when a backup lacks required source bytes or has a digest mismatch. (+13 more)

### Community 6 - "schemas.py"
Cohesion: 0.11
Nodes (30): get_investigation_detail(), Everything a workspace view needs, in one round trip., AgentRunResponse, AuditLogResponse, ErrorResponse, FindingEvidenceResponse, FindingResponse, HypothesisCreate (+22 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.17
Nodes (21): AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after(), Deterministic detection rules. These are pure functions over normalised events:… (+13 more)

### Community 8 - "TriageAnalysis"
Cohesion: 0.15
Nodes (20): Deterministic rule-based triage used when model router is unavailable., EvidenceGap, ExtractedEntity, IndicatorAssessment, InputClassification, PlannedTaskProposal, BaseModel, Structured output schemas for the Triage Agent. (+12 more)

### Community 9 - "ValueError"
Cohesion: 0.15
Nodes (8): parametrize, field_validator, field_validator, datetime, field_validator, AsyncClient, test_endpoint_role_matrix(), ValueError

### Community 10 - "ioc_extractor.py"
Cohesion: 0.08
Nodes (38): Linux authentication log parser. A deterministic, dependency-free parser for…, NoArgs, ABC, BaseModel, Tool adapter contract. A tool is the only thing in the platform allowed to…, Honest report of whether a tool can actually run right now. Surfaced through…, Everything an adapter is permitted to know about its invocation., What an adapter returns. (+30 more)

### Community 11 - "ratelimit.py"
Cohesion: 0.15
Nodes (12): Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, Thread-safe sliding window rate limiter., Clear all rate limit history (useful in tests)., FastAPI dependency for rate limiting endpoints by client IP., SlidingWindowRateLimiter, AsyncClient (+4 more)

### Community 12 - "test_ssrf.py"
Cohesion: 0.17
Nodes (17): patch, is_ip_forbidden(), IPv4Address, IPv6Address, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Check if an IP address falls into a private, loopback, or cloud metadata range., validate_url_ssrf_safe(), test_is_ip_allowed_public_ips() (+9 more)

### Community 13 - "test_orchestrator_agent_with_model_router_triage"
Cohesion: 0.11
Nodes (33): ChatMessage, Any, A single conversation turn., CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains. (+25 more)

### Community 14 - "triage.py"
Cohesion: 0.12
Nodes (17): Agent, ABC, Base class for all agents., AgentRegistry, build_default_registry(), Agent registry. Agents are looked up by name or capability rather than imported…, Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint. (+9 more)

### Community 15 - "conftest.py"
Cohesion: 0.29
Nodes (13): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+5 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "tokens.py"
Cohesion: 0.19
Nodes (15): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, JWT access tokens. Short-lived bearer tokens signed with HS256. Refresh tokens…, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`. (+7 more)

### Community 18 - "Settings"
Cohesion: 0.12
Nodes (24): ArgumentParser, BaseSettings, Run migrations in 'offline' mode., run_migrations_offline(), _backup(), build_parser(), _capabilities(), _create_user() (+16 more)

### Community 19 - "types.py"
Cohesion: 0.16
Nodes (13): Agent contract. Agents receive a typed context and return a typed result (spec…, Application configuration. All configuration arrives from the environment (or a…, ModelExecutionDraft, Evidence and finding contracts. Agents and tools exchange these Pydantic models…, Structured record of an LLM call for experimental tracking., Append-only evidence store and grounding enforcement. This module is where the…, Async engine and session management. Exposed as a class rather than module…, Strip credentials before a URL reaches the logs. (+5 more)

### Community 20 - "InvestigationStatus"
Cohesion: 0.15
Nodes (24): Investigator, get_session(), One transaction per request, committed on a clean response., cancel_investigation(), create_investigation(), create_task(), Depends, post (+16 more)

### Community 22 - "passwords.py"
Cohesion: 0.21
Nodes (12): Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), hash_password(), needs_rehash(), Password hashing. Argon2id via ``argon2-cffi``, which is the current OWASP…, Return whether the password matches. Never raises on a bad password., True when the hash was produced with weaker parameters than current., verify_password() (+4 more)

### Community 23 - "system.py"
Cohesion: 0.16
Nodes (18): Admin, admin_capabilities(), capabilities(), health(), AsyncSession, Depends, get, Health and capability endpoints. ``/capabilities`` is a first-class endpoint,… (+10 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "test_artifact_validation.py"
Cohesion: 0.22
Nodes (12): detect_artifact_kind(), detect_magic_bytes(), Classify an artifact based on header magic bytes, filename, and declared kind.…, Inspect the first bytes of a file to detect its format and MIME type., asyncio, Path, test_detect_artifact_kind_executable_disguised_as_log_rejected(), test_detect_artifact_kind_pcap_mismatch_rejected() (+4 more)

### Community 26 - "models.py"
Cohesion: 0.08
Nodes (32): DeclarativeBase, Mapped, Record an immutable LLM execution trace., Base, Base class for all ORM models., AuditLog, FindingEvidence, _forbid_mutation() (+24 more)

### Community 27 - "validation.py"
Cohesion: 0.13
Nodes (17): model_validator, Input and indicator validation primitives. Provides strict, deterministic…, Validate and canonicalize a target value for investigation creation., Validate and canonicalize an IPv4 or IPv6 address string. Returns the canonical…, Validate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512). Returns the…, Validate and canonicalize a fully qualified domain name. Returns the lowercased…, Validate and canonicalize a URL structure. Enforces RFC 3986 compliance and…, validate_domain() (+9 more)

### Community 28 - "ValidationError"
Cohesion: 0.33
Nodes (7): SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Fetch remote URL safely, validating every hop and streaming the body., Result of an SSRF-safe HTTP request., SafeFetchResult, PayloadTooLargeError, SSRFProtectionError, ValidationError

### Community 29 - "test_artifact_ingestion_api.py"
Cohesion: 0.53
Nodes (5): AsyncClient, test_ingest_text_artifact_endpoint(), test_ingest_url_artifact_blocks_ssrf(), test_upload_pcap_artifact_success(), test_upload_pcap_mismatch_rejected()

### Community 30 - "app.js"
Cohesion: 0.51
Nodes (9): api(), checkCurrentUser(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderWorkspace(), selectInvestigation(), setAuth() (+1 more)

### Community 31 - "env.py"
Cohesion: 0.43
Nodes (6): do_run_migrations(), Connection, In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_online()

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "test_migrations.py"
Cohesion: 0.31
Nodes (8): _current_revision(), Connection, The migration chain is the schema, so the suite runs on it. Every fixture…, The fixture's schema came from Alembic, not from ``create_all``., ``Base.metadata`` describes exactly what the migrations build., _schema_diff(), test_bootstrap_stamps_the_database_at_head(), test_models_and_migrations_do_not_drift()

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

### Community 40 - "files.py"
Cohesion: 0.16
Nodes (20): Path, Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Convenience helper to store an in-memory byte buffer into quarantine storage., Remove group/other access and any execute bit where the OS supports it., Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, Result of a successful intake., Reduce a client-supplied filename to a safe display label. The result is used… (+12 more)

### Community 41 - "AgentContext"
Cohesion: 0.17
Nodes (12): AgentContext, AgentResult, Any, BaseModel, Everything an agent is given for one execution., Structured outcome of one agent execution., Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure., LogAnalysisAgent (+4 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - ".complete"
Cohesion: 0.19
Nodes (10): Any, AsyncSession, BaseModel, UUID, Execute a completion for a TaskClass with optional structured schema…, Execute a candidate model, handling structured output repair retries., Persist execution telemetry to llm_calls (ModelExecution)., Generate a clean example JSON structure from a Pydantic model for prompt… (+2 more)

### Community 68 - "orchestration/orchestrator.py"
Cohesion: 0.12
Nodes (20): build_services(), Compose the object graph. Pure wiring, no I/O., Investigation planning and orchestration., InvestigationOutcome, Investigation orchestration and Orchestrator Agent. Executes a dynamic or…, Final outcome of an orchestrated investigation., Plan, Planner (+12 more)

### Community 72 - "_get_python_files"
Cohesion: 0.44
Nodes (8): _get_python_files(), Path, The schema has one source of truth: the Alembic chain. ``create_all`` was the…, A reserved key in ``extra`` raises KeyError only when the record is emitted.…, test_no_direct_llm_sdk_imports_in_agents(), test_no_metadata_create_all_in_src(), test_no_reserved_logrecord_keys_in_log_extra(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 74 - "investigations.py"
Cohesion: 0.19
Nodes (18): File, Form, _chunks(), ingest_text_artifact(), ingest_url_artifact(), Investigation lifecycle endpoints., Accept an artifact into content-addressed quarantine storage with magic byte…, Ingest content from a remote URL via SSRF-protected safe HTTP fetch. (+10 more)

### Community 75 - "get_not_implemented"
Cohesion: 0.20
Nodes (10): CaptureFixture, get_not_implemented(), Any, Declared limitations of this deployment. A single source for what the platform…, Return declared capability limitations reflecting the active runtime…, AsyncClient, test_admin_capabilities_access_control(), test_capabilities_limitations_reflects_active_llm_flag() (+2 more)

### Community 76 - "llm/contracts.py"
Cohesion: 0.20
Nodes (12): LLMRequest, LLMResponse, LLMUsage, Contracts and data models for model-provider abstraction. Defines the message…, Request payload sent to an LLM provider., Token accounting telemetry returned by a provider., Standardized response received from an LLM provider., Send a completion request to the provider for a specific model. (+4 more)

### Community 77 - "Role"
Cohesion: 0.28
Nodes (12): CurrentUser, FastAPI dependencies. Shared services (database, registries, orchestrator,…, require_admin(), require_investigator(), has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``., require_role() (+4 more)

### Community 81 - "test_auth.py"
Cohesion: 0.60
Nodes (4): AsyncClient, test_auth_login_invalid_password(), test_auth_login_success(), test_auth_me_endpoint()

### Community 83 - "ProviderRateLimited"
Cohesion: 0.50
Nodes (3): ProviderRateLimited, Any, Transient rate limit hit. Retry once, then fall back.

### Community 90 - "EvidenceStore"
Cohesion: 0.09
Nodes (22): EvidenceDraft, HypothesisDraft, HypothesisGapDraft, BaseModel, Stable digest of the observation, used to deduplicate evidence. Covers only…, A competing candidate explanation under evaluation (Invariant G3)., A declared gap in evidence preventing resolution of a hypothesis., An observation produced by a tool, before persistence. ``observed_at`` is when… (+14 more)

### Community 91 - "upgrade_to_head"
Cohesion: 0.17
Nodes (12): Config, model_validator, Require a real secret in production; generate an ephemeral one otherwise. A…, alembic_config(), Connection, Build an Alembic config without reading ``alembic.ini``. The ini file carries a…, Bring the database at ``url`` up to ``revision``, creating it if absent., _upgrade() (+4 more)

### Community 92 - "Severity"
Cohesion: 0.14
Nodes (27): FindingDraft, A claim an agent wishes to record. The store validates this against the…, assess(), Protocol, Deterministic risk scoring. Severity and risk are computed from findings by a…, Structural type covering both ORM findings and drafts., Roll findings up into an investigation-level severity and risk score., ScorableFinding (+19 more)

### Community 93 - "NvidiaNIMProvider"
Cohesion: 0.24
Nodes (11): MonkeyPatch, ProviderQuotaExceeded, ProviderUnavailable, The provider quota/credits are exhausted. Safe to fall back to secondary., Network connection failure or 5xx error from provider. Safe to fall back., NvidiaNIMProvider, Provider interface for NVIDIA NIM endpoints., asyncio (+3 more)

### Community 94 - "router.py"
Cohesion: 0.14
Nodes (25): BudgetExceededError, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderRefused, ProviderTimeout, Typed errors for LLM providers and model routing. Enforces the fallback…, All candidate models for a task class failed. (+17 more)

### Community 95 - "Services"
Cohesion: 0.17
Nodes (16): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), get_services(), get_settings_dep(), AsyncSession, Depends (+8 more)

### Community 96 - "ProviderAvailability"
Cohesion: 0.29
Nodes (4): ProviderAvailability, Health and model discovery status for an LLM provider., Probe provider connectivity, authentication, and available models., Probe NVIDIA NIM endpoint to verify API key and model availability.

### Community 97 - "Database"
Cohesion: 0.12
Nodes (23): async_sessionmaker, AsyncEngine, Database, AsyncSession, Yield a session, committing on success and rolling back on error., Owns the engine and session factory for one database URL., AsyncSession, The guard must bound its own blast radius: reads stay unaffected. (+15 more)

### Community 98 - "AsyncSession"
Cohesion: 0.12
Nodes (27): alias, delete, description, ge, le, LoadedInvestigation, MAX_EVIDENCE_PAGE, Query (+19 more)

### Community 99 - "_forbid_bulk_dml"
Cohesion: 0.67
Nodes (3): ORMExecuteState, _forbid_bulk_dml(), Reject bulk UPDATE/DELETE against an append-only table.

### Community 101 - "_build_chain"
Cohesion: 0.15
Nodes (18): _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker., The defect this file exists for: SET NULL used to unground every citing FACT., Evidence must stay traceable to the bytes it came from. (+10 more)

### Community 102 - "acip/errors.py"
Cohesion: 0.16
Nodes (13): Exception, Check whether the key is within rate limits; increments counter if allowed.…, ACIPError, AgentError, AuthenticationError, Any, RateLimitExceededError, Typed application errors. Each error carries an HTTP status and a stable… (+5 more)

### Community 103 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 104 - "Investigation"
Cohesion: 0.17
Nodes (26): AgentRun, Investigation, One execution of one agent. Part of the investigation execution trace., build_default_registry(), The tools available in M1. Phase 4 adds Zeek, Suricata, TShark, YARA and Sigma…, Executes tools for one investigation, recording each invocation., ToolRunner, Path (+18 more)

### Community 105 - "app.py"
Cohesion: 0.21
Nodes (10): RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, _serialisable_errors(), bootstrap() (+2 more)

### Community 106 - "OrchestratorAgent"
Cohesion: 0.11
Nodes (24): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, _derive_status(), InvestigationState, _load_artifacts(), _load_investigation(), OrchestratorAgent, AsyncSession, UUID (+16 more)

### Community 107 - "auth.py"
Cohesion: 0.21
Nodes (12): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+4 more)

### Community 108 - "_coerce"
Cohesion: 0.18
Nodes (9): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, Any, Merge the ambient context into each record., One JSON object per line, suitable for ingestion by a log pipeline. (+1 more)

### Community 109 - "db/base.py"
Cohesion: 0.29
Nodes (7): Dialect, datetime, Declarative base and portable column types. The schema deliberately avoids…, Store timezone-aware datetimes as UTC and read them back aware. Rejects naive…, Timezone-aware current time. Used as a column default., UTCDateTime, utcnow()

### Community 110 - "unit/test_domain_models.py"
Cohesion: 0.22
Nodes (8): FindingEvidenceDraft, A citation connecting evidence to a finding with a supporting or contradicting…, test_finding_evidence_draft_roles(), test_hypothesis_draft_invariant_g3_refutation_required(), test_hypothesis_draft_valid(), test_hypothesis_gap_draft(), test_model_execution_draft(), test_status_enums()

### Community 111 - "test_auth_log_incident_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_auth_log_incident_scenario(), test_clean_log_scenario()

### Community 112 - "test_upload_security.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_upload_empty_file_rejected(), test_upload_path_traversal_sanitized()

### Community 114 - "ToolRegistry"
Cohesion: 0.25
Nodes (4): A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry, AsyncSession

### Community 115 - "._perform_triage_analysis"
Cohesion: 0.43
Nodes (4): _path(), Any, Perform structured model-driven triage analysis with fallback to heuristics., _read_artifact_snippet()

### Community 116 - "get_evidence_provenance"
Cohesion: 0.29
Nodes (7): get_evidence_provenance(), UUID, Resolve one observation to the tool, arguments, agent and artifact behind it., EvidenceResponse, ProvenanceChainResponse, An observation with its provenance chain intact., One observation resolved down to the bytes it came from. evidence-model.md s7…

### Community 117 - "SafeHTTPFetcher"
Cohesion: 0.40
Nodes (5): Asynchronous HTTP fetcher with anti-SSRF protection and resource bounding., SafeHTTPFetcher, asyncio, test_safe_http_fetcher_blocks_empty_or_malformed_urls(), test_safe_http_fetcher_blocks_redirect_to_metadata()

### Community 118 - "test_orchestrator_agent_end_to_end_lifecycle"
Cohesion: 0.40
Nodes (6): asyncio, Path, When StaticPlanner is configured, OrchestratorAgent executes its plan verbatim., OrchestratorAgent receives an investigation, calls Triage, interprets result,…, test_orchestrator_agent_end_to_end_lifecycle(), test_orchestrator_agent_respects_static_planner_verbatim()

### Community 119 - "test_orchestrator_failure_rollback"
Cohesion: 0.40
Nodes (3): MockPlanner, Any, test_orchestrator_failure_rollback()

### Community 120 - "ToolInvocation"
Cohesion: 0.50
Nodes (3): UUID, Outcome of one audited tool call., ToolInvocation

### Community 121 - "MessageRole"
Cohesion: 0.67
Nodes (3): MessageRole, StrEnum, Role of a message sender in a chat conversation.

### Community 122 - "_sqlite_pragmas"
Cohesion: 0.67
Nodes (3): Any, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., _sqlite_pragmas()

## Knowledge Gaps
- **61 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+56 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **29 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `EvidenceStore` connect `EvidenceStore` to `Evidence`, `_evidence_after`, `AsyncSession`, `Database`, `orchestration/orchestrator.py`, `_build_chain`, `Investigation`, `AgentContext`, `investigations.py`, `OrchestratorAgent`, `ToolRegistry`, `types.py`, `models.py`, `Severity`?**
  _High betweenness centrality (0.051) - this node is a cross-community bridge._
- **Why does `Settings` connect `Settings` to `Evidence`, `InvestigationRunner`, `backup.py`, `TriageAnalysis`, `ValueError`, `test_orchestrator_agent_with_model_router_triage`, `triage.py`, `conftest.py`, `types.py`, `passwords.py`, `AgentContext`, `orchestration/orchestrator.py`, `get_not_implemented`, `Role`, `upgrade_to_head`, `Services`, `test_investigation_lifecycle.py`, `Investigation`, `app.py`, `OrchestratorAgent`, `test_orchestrator_agent_end_to_end_lifecycle`, `test_orchestrator_failure_rollback`?**
  _High betweenness centrality (0.048) - this node is a cross-community bridge._
- **Why does `Role` connect `Role` to `Evidence`, `TimeConfidence`, `schemas.py`, `ValueError`, `ratelimit.py`, `conftest.py`, `tokens.py`, `Settings`, `types.py`, `passwords.py`, `models.py`, `test_artifact_ingestion_api.py`, `get_not_implemented`, `test_auth.py`, `test_investigation_lifecycle.py`, `auth.py`, `test_auth_log_incident_scenario`, `test_upload_security.py`, `test_investigation_crud_and_lifecycle`?**
  _High betweenness centrality (0.043) - this node is a cross-community bridge._
- **Are the 54 inferred relationships involving `Database` (e.g. with `build_services()` and `Services`) actually correct?**
  _`Database` has 54 INFERRED edges - model-reasoned connections that need verification._
- **Are the 43 inferred relationships involving `EvidenceStore` (e.g. with `AgentContext` and `list_evidence()`) actually correct?**
  _`EvidenceStore` has 43 INFERRED edges - model-reasoned connections that need verification._
- **Are the 45 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 45 INFERRED edges - model-reasoned connections that need verification._
- **Are the 43 inferred relationships involving `Settings` (e.g. with `AgentContext` and `build_services()`) actually correct?**
  _`Settings` has 43 INFERRED edges - model-reasoned connections that need verification._