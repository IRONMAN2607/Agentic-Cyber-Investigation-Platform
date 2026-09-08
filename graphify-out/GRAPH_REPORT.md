# Graph Report - AACIP  (2026-09-03)

## Corpus Check
- 144 files · ~84,477 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1408 nodes · 4060 edges · 119 communities (90 shown, 29 thin omitted)
- Extraction: 78% EXTRACTED · 22% INFERRED · 0% AMBIGUOUS · INFERRED: 897 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a98bdd85`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- EntityRef
- _evidence_after
- ReportAgent
- TimeConfidence
- InvestigationRunner
- backup.py
- investigations.py
- evaluate_auth_rules
- IOCExtractor
- ValueError
- ioc_extractor.py
- ratelimit.py
- test_ssrf.py
- test_orchestrator_agent_with_model_router_triage
- triage.py
- conftest.py
- Grounding Invariants G0-G4
- tokens.py
- cli.py
- types.py
- InvestigationStatus
- CLAUDE.md
- auth.py
- Services
- agentrouter
- ArtifactKind
- test_historical_migration_0002_to_0003_populated_upgrade
- TargetType
- acip/errors.py
- test_artifact_ingestion_api.py
- app.js
- env.py
- Three-Transaction Orchestrator
- migrate.py
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- store_stream
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
- ScorableFinding
- _get_python_files
- .opencode/opencode.json
- upload_artifact
- test_capabilities.py
- llm/contracts.py
- Role
- graphify.js
- test_health
- test_auth.py
- AGENTS.md
- ProviderRateLimited
- EvidenceStore
- test_types.py
- Severity
- NvidiaNIMProvider
- router.py
- deps.py
- ProviderAvailability
- Database
- get_session
- _forbid_bulk_dml
- _build_chain
- _ip_scope
- test_investigation_lifecycle.py
- Investigation
- Settings
- orchestration/orchestrator.py
- logging.py
- HypothesisDraft
- test_auth_log_incident_scenario
- test_upload_security.py
- test_investigation_crud_and_lifecycle
- ToolRegistry
- Evidence
- SafeHTTPFetcher
- AgentResult
- tools/runner.py
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
- `test_hypothesis_gap_draft()` --uses--> `HypothesisGapDraft`  [INFERRED]
  tests/unit/test_domain_models.py → src/acip/core/evidence/contracts.py
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

## Communities (119 total, 29 thin omitted)

### Community 0 - "EntityRef"
Cohesion: 0.18
Nodes (14): EntityRef, normalize_entity_value(), Stable digest of the observation, used to deduplicate evidence. Covers only…, Canonicalise an entity value so the same thing has one representation. Entity…, A typed reference to a real-world entity observed in evidence., EntityType, StrEnum, Node types for the evidence graph. Recorded on evidence in M1 so that Phase 5… (+6 more)

### Community 1 - "_evidence_after"
Cohesion: 0.12
Nodes (16): Collection, ColumnElement, _evidence_after(), _evidence_cursor(), EvidencePage, One page of evidence in timeline order, with a cursor for the next. The sort…, Every matching row up to ``cap``, and whether the cap cut the read short.…, One page of evidence, plus the cursor that continues it. (+8 more)

### Community 2 - "ReportAgent"
Cohesion: 0.25
Nodes (8): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, RiskAssessment, One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun

### Community 3 - "TimeConfidence"
Cohesion: 0.20
Nodes (12): Match, AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime, Parsing options. Note the absence of any path argument., Parses Linux authentication logs into normalised auth events. (+4 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.13
Nodes (12): Orchestrator, build_services(), Compose the object graph. Pure wiring, no I/O., InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency. (+4 more)

### Community 5 - "backup.py"
Cohesion: 0.23
Nodes (21): BackupIntegrityError, create_backup(), Path, Portable SQLite backup and restore with artifact-integrity verification. The…, A backup is incomplete or its artifact bytes do not match the database., Create and verify a consistent SQLite/artifact snapshot at ``destination``.…, Verify and restore ``source`` into empty configured SQLite/artifact paths.…, Raise when a backup lacks required source bytes or has a digest mismatch. (+13 more)

### Community 6 - "investigations.py"
Cohesion: 0.09
Nodes (48): login(), AsyncSession, Depends, post, Exchange credentials for a short-lived access token., get_evidence_provenance(), get_investigation_detail(), UUID (+40 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.17
Nodes (21): AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after(), Deterministic detection rules. These are pure functions over normalised events:… (+13 more)

### Community 8 - "IOCExtractor"
Cohesion: 0.16
Nodes (14): _context(), IOCExtractor, IOCExtractorArgs, Any, BaseModel, Extracts and validates indicators from text., Extract indicators from ``text``. Directly testable., Undo common defanging so indicators can be matched. (+6 more)

### Community 9 - "ValueError"
Cohesion: 0.09
Nodes (16): Dialect, parametrize, field_validator, model_validator, field_validator, datetime, field_validator, datetime (+8 more)

### Community 10 - "ioc_extractor.py"
Cohesion: 0.14
Nodes (20): Linux authentication log parser. A deterministic, dependency-free parser for…, NoArgs, ABC, BaseModel, Tool adapter contract. A tool is the only thing in the platform allowed to…, Honest report of whether a tool can actually run right now. Surfaced through…, Everything an adapter is permitted to know about its invocation., What an adapter returns. (+12 more)

### Community 11 - "ratelimit.py"
Cohesion: 0.11
Nodes (15): Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, Thread-safe sliding window rate limiter., Check whether the key is within rate limits; increments counter if allowed.…, Clear all rate limit history (useful in tests)., FastAPI dependency for rate limiting endpoints by client IP., SlidingWindowRateLimiter (+7 more)

### Community 12 - "test_ssrf.py"
Cohesion: 0.17
Nodes (17): patch, is_ip_forbidden(), IPv4Address, IPv6Address, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Check if an IP address falls into a private, loopback, or cloud metadata range., validate_url_ssrf_safe(), test_is_ip_allowed_public_ips() (+9 more)

### Community 13 - "test_orchestrator_agent_with_model_router_triage"
Cohesion: 0.11
Nodes (33): ChatMessage, Any, A single conversation turn., CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains. (+25 more)

### Community 14 - "triage.py"
Cohesion: 0.14
Nodes (17): Agent, ABC, Agent contract. Agents receive a typed context and return a typed result (spec…, Base class for all agents., Log analysis agent. Parses authentication logs with a deterministic tool, then…, AgentRegistry, build_default_registry(), Agent registry. Agents are looked up by name or capability rather than imported… (+9 more)

### Community 15 - "conftest.py"
Cohesion: 0.29
Nodes (13): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+5 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "tokens.py"
Cohesion: 0.18
Nodes (16): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, JWT access tokens. Short-lived bearer tokens signed with HS256. Refresh tokens…, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`. (+8 more)

### Community 18 - "cli.py"
Cohesion: 0.16
Nodes (17): ArgumentParser, _backup(), build_parser(), _capabilities(), _create_user(), _init(), main(), Path (+9 more)

### Community 19 - "types.py"
Cohesion: 0.09
Nodes (35): Mapped, ModelExecutionDraft, Evidence and finding contracts. Agents and tools exchange these Pydantic models…, Structured record of an LLM call for experimental tracking., Append-only evidence store and grounding enforcement. This module is where the…, _forbid_mutation(), ModelExecution, Any (+27 more)

### Community 20 - "InvestigationStatus"
Cohesion: 0.17
Nodes (21): Investigator, cancel_investigation(), create_investigation(), ingest_text_artifact(), ingest_url_artifact(), post, Ingest content from a remote URL via SSRF-protected safe HTTP fetch., Ingest raw text/log/indicator directly into quarantine storage. (+13 more)

### Community 22 - "auth.py"
Cohesion: 0.11
Nodes (21): Logger, me(), CurrentUser, get, Authentication endpoints., Application bootstrap. Migrates the schema to head and, outside production,…, Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin() (+13 more)

### Community 23 - "Services"
Cohesion: 0.11
Nodes (27): Admin, get_services(), get_settings_dep(), Request, Everything built once at startup., Services, admin_capabilities(), capabilities() (+19 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "ArtifactKind"
Cohesion: 0.19
Nodes (19): detect_artifact_kind(), detect_magic_bytes(), Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Classify an artifact based on header magic bytes, filename, and declared kind.…, Convenience helper to store an in-memory byte buffer into quarantine storage., Result of a successful intake., Inspect the first bytes of a file to detect its format and MIME type., store_bytes() (+11 more)

### Community 26 - "test_historical_migration_0002_to_0003_populated_upgrade"
Cohesion: 0.16
Nodes (13): DeclarativeBase, Base, Base class for all ORM models., AuditLog, FindingEvidence, HypothesisEvidence, Phase 5 schema scaffolding: relational citation mapping evidence to findings.…, Phase 7 schema scaffolding: relational citation linking evidence to a… (+5 more)

### Community 27 - "TargetType"
Cohesion: 0.14
Nodes (17): Input and indicator validation primitives. Provides strict, deterministic…, Validate and canonicalize a target value for investigation creation., Validate and canonicalize an IPv4 or IPv6 address string. Returns the canonical…, Validate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512). Returns the…, Validate and canonicalize a fully qualified domain name. Returns the lowercased…, Validate and canonicalize a URL structure. Enforces RFC 3986 compliance and…, validate_domain(), validate_hash() (+9 more)

### Community 28 - "acip/errors.py"
Cohesion: 0.23
Nodes (12): Exception, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Fetch remote URL safely, validating every hop and streaming the body., Result of an SSRF-safe HTTP request., SafeFetchResult, ACIPError, AgentError, PayloadTooLargeError (+4 more)

### Community 29 - "test_artifact_ingestion_api.py"
Cohesion: 0.53
Nodes (5): AsyncClient, test_ingest_text_artifact_endpoint(), test_ingest_url_artifact_blocks_ssrf(), test_upload_pcap_artifact_success(), test_upload_pcap_mismatch_rejected()

### Community 30 - "app.js"
Cohesion: 0.45
Nodes (10): api(), checkCurrentUser(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderWorkspace(), selectInvestigation(), setAuth() (+2 more)

### Community 31 - "env.py"
Cohesion: 0.31
Nodes (8): do_run_migrations(), Connection, Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_offline(), run_migrations_online()

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "migrate.py"
Cohesion: 0.12
Nodes (21): Config, model_validator, Require a real secret in production; generate an ephemeral one otherwise. A…, alembic_config(), Connection, Schema creation, through Alembic and only through Alembic. The migration chain…, Build an Alembic config without reading ``alembic.ini``. The ini file carries a…, Bring the database at ``url`` up to ``revision``, creating it if absent. (+13 more)

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

### Community 40 - "store_stream"
Cohesion: 0.19
Nodes (15): Path, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Remove group/other access and any execute bit where the OS supports it., Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, Reduce a client-supplied filename to a safe display label. The result is used…, read_text(), _restrict_permissions(), sanitize_filename() (+7 more)

### Community 41 - "AgentContext"
Cohesion: 0.27
Nodes (8): AgentContext, Everything an agent is given for one execution., LogAnalysisAgent, Any, Project stored evidence into the rule engine's view type. The read is bounded…, Parses authentication logs and applies deterministic detection rules., FindingDraft, A claim an agent wishes to record. The store validates this against the…

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - ".complete"
Cohesion: 0.19
Nodes (10): Any, AsyncSession, BaseModel, UUID, Execute a completion for a TaskClass with optional structured schema…, Execute a candidate model, handling structured output repair retries., Persist execution telemetry to llm_calls (ModelExecution)., Generate a clean example JSON structure from a Pydantic model for prompt… (+2 more)

### Community 68 - "ScorableFinding"
Cohesion: 0.33
Nodes (3): Protocol, Structural type covering both ORM findings and drafts., ScorableFinding

### Community 72 - "_get_python_files"
Cohesion: 0.44
Nodes (8): _get_python_files(), Path, The schema has one source of truth: the Alembic chain. ``create_all`` was the…, A reserved key in ``extra`` raises KeyError only when the record is emitted.…, test_no_direct_llm_sdk_imports_in_agents(), test_no_metadata_create_all_in_src(), test_no_reserved_logrecord_keys_in_log_extra(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 74 - "upload_artifact"
Cohesion: 0.33
Nodes (7): File, Form, _chunks(), Accept an artifact into content-addressed quarantine storage with magic byte…, Stream an upload without buffering it whole., upload_artifact(), UploadFile

### Community 75 - "test_capabilities.py"
Cohesion: 0.33
Nodes (6): CaptureFixture, AsyncClient, test_admin_capabilities_access_control(), test_capabilities_limitations_reflects_active_llm_flag(), test_cli_capabilities_output(), test_public_capabilities()

### Community 76 - "llm/contracts.py"
Cohesion: 0.20
Nodes (12): LLMRequest, LLMResponse, LLMUsage, Contracts and data models for model-provider abstraction. Defines the message…, Request payload sent to an LLM provider., Token accounting telemetry returned by a provider., Standardized response received from an LLM provider., Send a completion request to the provider for a specific model. (+4 more)

### Community 77 - "Role"
Cohesion: 0.28
Nodes (11): CurrentUser, require_admin(), require_investigator(), has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``., require_role(), User (+3 more)

### Community 81 - "test_auth.py"
Cohesion: 0.60
Nodes (4): AsyncClient, test_auth_login_invalid_password(), test_auth_login_success(), test_auth_me_endpoint()

### Community 83 - "ProviderRateLimited"
Cohesion: 0.50
Nodes (3): ProviderRateLimited, Any, Transient rate limit hit. Retry once, then fall back.

### Community 90 - "EvidenceStore"
Cohesion: 0.09
Nodes (19): HypothesisGapDraft, A declared gap in evidence preventing resolution of a hypothesis., EvidenceStore, AsyncSession, UUID, Writes evidence and findings for a single investigation., Persist drafts, skipping observations already recorded. Deduplication is by…, Validate a claim against the grounding invariants and persist it. (+11 more)

### Community 91 - "test_types.py"
Cohesion: 0.33
Nodes (5): test_assertion_class_values(), test_investigation_status_terminal(), test_role_values(), test_severity_ordering(), test_time_confidence_values()

### Community 92 - "Severity"
Cohesion: 0.21
Nodes (10): assess(), Deterministic risk scoring. Severity and risk are computed from findings by a…, Roll findings up into an investigation-level severity and risk score., Finding, A claim about the investigation, bound to the evidence supporting it., Severity, _make_finding(), test_empty_findings_risk() (+2 more)

### Community 93 - "NvidiaNIMProvider"
Cohesion: 0.24
Nodes (11): MonkeyPatch, ProviderQuotaExceeded, ProviderUnavailable, The provider quota/credits are exhausted. Safe to fall back to secondary., Network connection failure or 5xx error from provider. Safe to fall back., NvidiaNIMProvider, Provider interface for NVIDIA NIM endpoints., asyncio (+3 more)

### Community 94 - "router.py"
Cohesion: 0.14
Nodes (25): BudgetExceededError, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderRefused, ProviderTimeout, Typed errors for LLM providers and model routing. Enforces the fallback…, All candidate models for a task class failed. (+17 more)

### Community 95 - "deps.py"
Cohesion: 0.21
Nodes (12): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), AsyncSession, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,…, Load an investigation or 404. M1 has no per-investigation ownership: any… (+4 more)

### Community 96 - "ProviderAvailability"
Cohesion: 0.29
Nodes (4): ProviderAvailability, Health and model discovery status for an LLM provider., Probe provider connectivity, authentication, and available models., Probe NVIDIA NIM endpoint to verify API key and model availability.

### Community 97 - "Database"
Cohesion: 0.12
Nodes (29): async_sessionmaker, AsyncEngine, EvidenceDraft, An observation produced by a tool, before persistence. ``observed_at`` is when…, Database, AsyncSession, Yield a session, committing on success and rolling back on error., Owns the engine and session factory for one database URL. (+21 more)

### Community 98 - "get_session"
Cohesion: 0.11
Nodes (35): alias, delete, description, ge, le, LoadedInvestigation, MAX_EVIDENCE_PAGE, Query (+27 more)

### Community 99 - "_forbid_bulk_dml"
Cohesion: 0.67
Nodes (3): ORMExecuteState, _forbid_bulk_dml(), Reject bulk UPDATE/DELETE against an append-only table.

### Community 101 - "_build_chain"
Cohesion: 0.15
Nodes (18): _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker., The defect this file exists for: SET NULL used to unground every citing FACT., Evidence must stay traceable to the bytes it came from. (+10 more)

### Community 102 - "_ip_scope"
Cohesion: 0.50
Nodes (4): _ip_scope(), IPv4Address, IPv6Address, Classify an address. Non-global addresses are weak indicators.

### Community 103 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 104 - "Investigation"
Cohesion: 0.10
Nodes (44): Deterministic rule-based triage used when model router is unavailable., EvidenceGap, ExtractedEntity, IndicatorAssessment, InputClassification, PlannedTaskProposal, BaseModel, Structured output schemas for the Triage Agent. (+36 more)

### Community 105 - "Settings"
Cohesion: 0.15
Nodes (16): BaseSettings, RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, _serialisable_errors() (+8 more)

### Community 106 - "orchestration/orchestrator.py"
Cohesion: 0.06
Nodes (57): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, Investigation planning and orchestration., _derive_status(), InvestigationOutcome, InvestigationState, _load_artifacts(), _load_investigation(), OrchestratorAgent (+49 more)

### Community 108 - "logging.py"
Cohesion: 0.21
Nodes (9): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, Structured logging with investigation correlation. Every log record emitted…, Merge the ambient context into each record., One JSON object per line, suitable for ingestion by a log pipeline. (+1 more)

### Community 110 - "HypothesisDraft"
Cohesion: 0.22
Nodes (10): FindingEvidenceDraft, HypothesisDraft, BaseModel, A citation connecting evidence to a finding with a supporting or contradicting…, A competing candidate explanation under evaluation (Invariant G3)., test_finding_evidence_draft_roles(), test_hypothesis_draft_invariant_g3_refutation_required(), test_hypothesis_draft_valid() (+2 more)

### Community 111 - "test_auth_log_incident_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_auth_log_incident_scenario(), test_clean_log_scenario()

### Community 112 - "test_upload_security.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_upload_empty_file_rejected(), test_upload_path_traversal_sanitized()

### Community 114 - "ToolRegistry"
Cohesion: 0.17
Nodes (7): A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolExecutionError, ToolUnavailableError, A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry

### Community 115 - "Evidence"
Cohesion: 0.25
Nodes (6): _path(), Any, Perform structured model-driven triage analysis with fallback to heuristics., _read_artifact_snippet(), Evidence, An immutable observation with full provenance. ``tool_run_id`` being non-NULL…

### Community 117 - "SafeHTTPFetcher"
Cohesion: 0.40
Nodes (5): Asynchronous HTTP fetcher with anti-SSRF protection and resource bounding., SafeHTTPFetcher, asyncio, test_safe_http_fetcher_blocks_empty_or_malformed_urls(), test_safe_http_fetcher_blocks_redirect_to_metadata()

### Community 119 - "AgentResult"
Cohesion: 0.20
Nodes (8): AgentResult, Any, BaseModel, Structured outcome of one agent execution., Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure., MockFailingAgent, Any, test_orchestrator_failure_rollback()

### Community 120 - "tools/runner.py"
Cohesion: 0.16
Nodes (12): Any, BaseModel, datetime, Path, UUID, Audited tool invocation. Every tool call passes through :class:`ToolRunner`,…, Reject any artifact path outside the configured storage root., Keep the audit record useful without copying bulk input into it. (+4 more)

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

- **Why does `EvidenceStore` connect `EvidenceStore` to `Database`, `get_session`, `_evidence_after`, `_build_chain`, `investigations.py`, `Investigation`, `AgentContext`, `orchestration/orchestrator.py`, `triage.py`, `HypothesisDraft`, `types.py`, `Evidence`, `tools/runner.py`, `test_historical_migration_0002_to_0003_populated_upgrade`, `Severity`?**
  _High betweenness centrality (0.051) - this node is a cross-community bridge._
- **Why does `Settings` connect `Settings` to `migrate.py`, `InvestigationRunner`, `backup.py`, `test_investigation_lifecycle.py`, `Investigation`, `AgentContext`, `ValueError`, `orchestration/orchestrator.py`, `test_capabilities.py`, `test_orchestrator_agent_with_model_router_triage`, `triage.py`, `conftest.py`, `cli.py`, `AgentResult`, `auth.py`, `Services`, `deps.py`?**
  _High betweenness centrality (0.048) - this node is a cross-community bridge._
- **Why does `Role` connect `Role` to `EntityRef`, `investigations.py`, `test_investigation_lifecycle.py`, `ValueError`, `test_capabilities.py`, `ratelimit.py`, `conftest.py`, `test_auth_log_incident_scenario`, `tokens.py`, `cli.py`, `types.py`, `test_auth.py`, `test_investigation_crud_and_lifecycle`, `auth.py`, `test_upload_security.py`, `test_types.py`, `test_artifact_ingestion_api.py`, `deps.py`?**
  _High betweenness centrality (0.043) - this node is a cross-community bridge._
- **Are the 54 inferred relationships involving `Database` (e.g. with `build_services()` and `Services`) actually correct?**
  _`Database` has 54 INFERRED edges - model-reasoned connections that need verification._
- **Are the 43 inferred relationships involving `EvidenceStore` (e.g. with `AgentContext` and `list_evidence()`) actually correct?**
  _`EvidenceStore` has 43 INFERRED edges - model-reasoned connections that need verification._
- **Are the 45 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 45 INFERRED edges - model-reasoned connections that need verification._
- **Are the 43 inferred relationships involving `Settings` (e.g. with `AgentContext` and `build_services()`) actually correct?**
  _`Settings` has 43 INFERRED edges - model-reasoned connections that need verification._