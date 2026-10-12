# Graph Report - AACIP  (2026-09-24)

## Corpus Check
- 150 files · ~92,337 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1503 nodes · 4383 edges · 104 communities (75 shown, 29 thin omitted)
- Extraction: 77% EXTRACTED · 23% INFERRED · 0% AMBIGUOUS · INFERRED: 987 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `def59816`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Database
- _evidence_after
- ReportAgent
- TimeConfidence
- InvestigationRunner
- env.py
- investigations.py
- evaluate_auth_rules
- WebServerLogParser
- ToolRegistry
- .extract
- ratelimit.py
- test_ssrf.py
- ModelRouter
- AgentContext
- Settings
- Grounding Invariants G0-G4
- Role
- ProviderAvailability
- Severity
- InvestigationStatus
- CLAUDE.md
- Services
- agentrouter
- ArtifactKind
- EntityType
- ValidationError
- evaluate_web_rules
- app.js
- app.py
- Three-Transaction Orchestrator
- test_historical_migration_0002_to_0003_populated_upgrade
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- store_stream
- get_session
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
- get_not_implemented
- llm/__init__.py
- graphify.js
- test_health
- AGENTS.md
- .__init__
- EvidenceStore
- types.py
- router.py
- acip/errors.py
- Investigation
- list_evidence
- ModelExecution
- ToolRun
- triage.py
- cli.py
- orchestration/orchestrator.py
- AgentRun
- deps.py
- AgentResult
- test_triage_agent_flag_disabled_uses_deterministic_fallback
- TriageAnalysis
- _PinnedIPNetworkBackend
- Evidence
- ToolRunner

## God Nodes (most connected - your core abstractions)
1. `Database` - 74 edges
2. `Investigation` - 65 edges
3. `Severity` - 65 edges
4. `EvidenceStore` - 64 edges
5. `Settings` - 60 edges
6. `AgentContext` - 51 edges
7. `Evidence` - 49 edges
8. `Role` - 46 edges
9. `OrchestratorAgent` - 43 edges
10. `Artifact` - 43 edges

## Surprising Connections (you probably didn't know these)
- `test_investigation_status_terminal()` --uses--> `InvestigationStatus`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_severity_ordering()` --uses--> `Severity`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_assertion_class_values()` --uses--> `AssertionClass`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_time_confidence_values()` --uses--> `TimeConfidence`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `MockFailingAgent` --uses--> `AgentContext`  [INFERRED]
  tests/integration/test_orchestrator.py → src/acip/agents/base.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **End-to-End Evidence Provenance Pipeline** — docs_tools_tool_adapter_contract, docs_evidence_model_evidence_record, docs_evidence_model_traceability_chain, docs_frontend_provenance_ui_rules, docs_evidence_graph_relationships [EXTRACTED 1.00]
- **Experimental Evaluation and Ablation Framework** — docs_experiments_comparison_conditions, docs_experiments_ablations, docs_experiments_evaluation_metrics, docs_research_central_question, docs_model_abstraction_replay_double [EXTRACTED 1.00]
- **Grounding Invariants Enforcement Subsystem** — docs_evidence_model_grounding_invariants, docs_agents_agent_contract, docs_model_abstraction_core_llm, docs_experiments_evaluation_metrics, docs_research_central_question [EXTRACTED 1.00]

## Communities (104 total, 29 thin omitted)

### Community 0 - "Database"
Cohesion: 0.09
Nodes (20): async_sessionmaker, AsyncEngine, Orchestrator, ORMExecuteState, Database, _forbid_bulk_dml(), Any, AsyncSession (+12 more)

### Community 1 - "_evidence_after"
Cohesion: 0.22
Nodes (9): ColumnElement, _evidence_after(), Match rows strictly after the cursor, in the evidence sort order., decode_cursor(), encode_cursor(), Any, Opaque cursors for stable keyset pagination. api.md s5 requires "a bounded…, Encode a sort-key tuple as an opaque cursor. (+1 more)

### Community 2 - "ReportAgent"
Cohesion: 0.22
Nodes (8): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, RiskAssessment, Finding, A claim about the investigation, bound to the evidence supporting it.

### Community 3 - "TimeConfidence"
Cohesion: 0.07
Nodes (46): Match, EntityRef, A typed reference to a real-world entity observed in evidence., AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime (+38 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.15
Nodes (10): InvestigationRunner, UUID, Background execution of investigations. M1 runs investigations as asyncio tasks…, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle., Cancel an in-flight investigation task. (+2 more)

### Community 5 - "env.py"
Cohesion: 0.31
Nodes (8): do_run_migrations(), Connection, Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_offline(), run_migrations_online()

### Community 6 - "investigations.py"
Cohesion: 0.12
Nodes (41): get_evidence_provenance(), get_investigation_detail(), UUID, Investigation lifecycle endpoints., Everything a workspace view needs, in one round trip., Resolve one observation to the tool, arguments, agent and artifact behind it., AgentRunResponse, ArtifactResponse (+33 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.24
Nodes (14): AuthEventView, evaluate_auth_rules(), _find_failure_bursts(), _first_success_after(), Group failures by source address and return those forming a dense burst. Events…, Earliest successful authentication from ``source_ip`` related to ``burst``., A parsed authentication event, decoupled from the ORM., Evaluate all authentication rules over ``events``. Returns hits ordered by… (+6 more)

### Community 8 - "WebServerLogParser"
Cohesion: 0.15
Nodes (18): _detect_attacks(), _parse_request(), BaseModel, Parses Apache, Nginx, and W3C web server access logs into structured events., Parse log text deterministically. Separated from execute for direct testing., Parse HTTP request line: e.g. 'GET /path?query=val HTTP/1.1'., Evaluate deterministic attack signatures across request components., Execution options for web server access log parsing. (+10 more)

### Community 9 - "ToolRegistry"
Cohesion: 0.06
Nodes (40): Dialect, parametrize, field_validator, model_validator, field_validator, BackupIntegrityError, create_backup(), Path (+32 more)

### Community 10 - ".extract"
Cohesion: 0.13
Nodes (15): _context(), IOCExtractorArgs, _ip_scope(), Any, BaseModel, IPv4Address, IPv6Address, Extract indicators from ``text``. Directly testable. (+7 more)

### Community 11 - "ratelimit.py"
Cohesion: 0.11
Nodes (15): Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, Thread-safe sliding window rate limiter., Check whether the key is within rate limits; increments counter if allowed.…, Clear all rate limit history (useful in tests)., FastAPI dependency for rate limiting endpoints by client IP., SlidingWindowRateLimiter (+7 more)

### Community 12 - "test_ssrf.py"
Cohesion: 0.11
Nodes (26): patch, is_ip_forbidden(), PinnedIPTransport, IPv4Address, IPv6Address, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Async HTTP transport establishing socket connection directly to a pinned IP. (+18 more)

### Community 13 - "ModelRouter"
Cohesion: 0.15
Nodes (31): CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains., Retrieve the routing rule and candidate list for a given task class., Create standard routing policy with Llama 3.2 11B and GPT-OSS 20B candidates., RoutingPolicy (+23 more)

### Community 14 - "AgentContext"
Cohesion: 0.21
Nodes (9): AuthDetectionHit, AgentContext, Everything an agent is given for one execution., LogAnalysisAgent, Any, Project stored auth evidence into the rule engine's view type., Project stored web evidence into the web rule engine's view type., Parses authentication and web access logs and applies deterministic detection… (+1 more)

### Community 15 - "Settings"
Cohesion: 0.12
Nodes (23): BaseSettings, CaptureFixture, _capabilities(), Print the real capability set, probed rather than assumed., model_validator, Create runtime directories. Called once at startup., Resolved application settings., Require a real secret in production; generate an ephemeral one otherwise. A… (+15 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "Role"
Cohesion: 0.05
Nodes (50): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, JWT access tokens. Short-lived bearer tokens signed with HS256. Refresh tokens…, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`. (+42 more)

### Community 18 - "ProviderAvailability"
Cohesion: 0.25
Nodes (4): ProviderAvailability, Health and model discovery status for an LLM provider., Probe provider connectivity, authentication, and available models., Probe NVIDIA NIM endpoint to verify API key and model availability.

### Community 19 - "Severity"
Cohesion: 0.17
Nodes (26): FindingDraft, A claim an agent wishes to record. The store validates this against the…, assess(), Deterministic risk scoring. Severity and risk are computed from findings by a…, Roll findings up into an investigation-level severity and risk score., Yield a session, committing on success and rolling back on error., AssertionClass, Epistemic status of a claim. See docs/evidence-model.md. The distinction is… (+18 more)

### Community 20 - "InvestigationStatus"
Cohesion: 0.11
Nodes (42): delete, description, File, Form, Investigator, LoadedInvestigation, _append_only_counts(), cancel_investigation() (+34 more)

### Community 23 - "Services"
Cohesion: 0.14
Nodes (23): Admin, get_services(), get_settings_dep(), Request, Everything built once at startup., Services, admin_capabilities(), capabilities() (+15 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "ArtifactKind"
Cohesion: 0.19
Nodes (19): detect_artifact_kind(), detect_magic_bytes(), Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Classify an artifact based on header magic bytes, filename, and declared kind.…, Convenience helper to store an in-memory byte buffer into quarantine storage., Result of a successful intake., Inspect the first bytes of a file to detect its format and MIME type., store_bytes() (+11 more)

### Community 26 - "EntityType"
Cohesion: 0.13
Nodes (21): normalize_entity_value(), Canonicalise an entity value so the same thing has one representation. Entity…, EntityType, Node types for the evidence graph. Recorded on evidence in M1 so that Phase 5…, AsyncSession, The guard must bound its own blast radius: reads stay unaffected., One named escape hatch, so deliberate destruction is greppable., An investigation with evidence, for the bulk-DML cases below. (+13 more)

### Community 27 - "ValidationError"
Cohesion: 0.13
Nodes (20): Fetch remote URL safely, validating every hop and streaming the body., Input and indicator validation primitives. Provides strict, deterministic…, Validate and canonicalize a target value for investigation creation., Validate and canonicalize an IPv4 or IPv6 address string. Returns the canonical…, Validate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512). Returns the…, Validate and canonicalize a fully qualified domain name. Returns the lowercased…, Validate and canonicalize a URL structure. Enforces RFC 3986 compliance and…, validate_domain() (+12 more)

### Community 28 - "evaluate_web_rules"
Cohesion: 0.20
Nodes (19): DetectionHit, evaluate_web_rules(), _find_error_bursts(), UUID, Deterministic detection rules for web access logs. Pure functions over…, A parsed web access event, decoupled from the ORM., Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS., Group 4xx/5xx error responses into bursts per IP. (+11 more)

### Community 30 - "app.js"
Cohesion: 0.45
Nodes (10): api(), checkCurrentUser(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderWorkspace(), selectInvestigation(), setAuth() (+2 more)

### Community 31 - "app.py"
Cohesion: 0.10
Nodes (22): ArgumentParser, RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, _serialisable_errors() (+14 more)

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "test_historical_migration_0002_to_0003_populated_upgrade"
Cohesion: 0.15
Nodes (16): AuditLog, Append-only record of security-relevant actions (spec s13)., test_bulk_dml_blocked_on_audit_log(), _current_revision(), Connection, Path, The migration chain is the schema, so the suite runs on it. Every fixture…, The fixture's schema came from Alembic, not from ``create_all``. (+8 more)

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

### Community 41 - "get_session"
Cohesion: 0.12
Nodes (23): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), get_session(), AsyncSession, Depends, Load an investigation or 404. M1 has no per-investigation ownership: any… (+15 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 68 - "ScorableFinding"
Cohesion: 0.33
Nodes (3): Protocol, Structural type covering both ORM findings and drafts., ScorableFinding

### Community 72 - "_get_python_files"
Cohesion: 0.44
Nodes (8): _get_python_files(), Path, The schema has one source of truth: the Alembic chain. ``create_all`` was the…, A reserved key in ``extra`` raises KeyError only when the record is emitted.…, test_no_direct_llm_sdk_imports_in_agents(), test_no_metadata_create_all_in_src(), test_no_reserved_logrecord_keys_in_log_extra(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 75 - "get_not_implemented"
Cohesion: 0.24
Nodes (8): get_not_implemented(), Any, Declared limitations of this deployment. A single source for what the platform…, Return declared capability limitations reflecting the active runtime…, AsyncClient, test_admin_capabilities_access_control(), test_capabilities_limitations_reflects_active_llm_flag(), test_public_capabilities()

### Community 76 - "llm/__init__.py"
Cohesion: 0.12
Nodes (30): MonkeyPatch, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderQuotaExceeded, ProviderRateLimited, ProviderRefused, ProviderTimeout (+22 more)

### Community 90 - "EvidenceStore"
Cohesion: 0.07
Nodes (47): EvidenceDraft, FindingEvidenceDraft, HypothesisDraft, HypothesisGapDraft, ModelExecutionDraft, BaseModel, Evidence and finding contracts. Agents and tools exchange these Pydantic models…, Stable digest of the observation, used to deduplicate evidence. Covers only… (+39 more)

### Community 92 - "types.py"
Cohesion: 0.09
Nodes (30): Mapped, Agent, ABC, Agent contract. Agents receive a typed context and return a typed result (spec…, Base class for all agents., Log analysis agent. Parses authentication logs and web server access logs using…, Agent registry. Agents are looked up by name or capability rather than imported…, Report agent. Renders a deterministic Markdown investigation report from stored… (+22 more)

### Community 94 - "router.py"
Cohesion: 0.09
Nodes (25): LLMResponse, MessageRole, StrEnum, Role of a message sender in a chat conversation., Standardized response received from an LLM provider., BudgetExceededError, Investigation token or cost ceiling exceeded., LLMProvider (+17 more)

### Community 95 - "acip/errors.py"
Cohesion: 0.20
Nodes (13): Exception, has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, ACIPError, AgentError, AuthorizationError, PayloadTooLargeError, Typed application errors. Each error carries an HTTP status and a stable… (+5 more)

### Community 96 - "Investigation"
Cohesion: 0.09
Nodes (20): AgentRegistry, build_default_registry(), Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint., The agents available in this milestone. Phase 4 adds the network, endpoint,…, build_services(), Compose the object graph. Pure wiring, no I/O., Planner (+12 more)

### Community 98 - "list_evidence"
Cohesion: 0.17
Nodes (15): alias, ge, le, MAX_EVIDENCE_PAGE, Query, get_investigation_progress(), get_report(), list_evidence() (+7 more)

### Community 99 - "ModelExecution"
Cohesion: 0.29
Nodes (6): ModelExecution, Phase 6 schema scaffolding: audited execution trace of LLM invocations.…, authorized_purge(), Permit append-only deletion within this block. The single sanctioned…, FinishReason, LLM completion termination reason.

### Community 101 - "ToolRun"
Cohesion: 0.17
Nodes (16): One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun, _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker. (+8 more)

### Community 104 - "triage.py"
Cohesion: 0.13
Nodes (29): Triage agent. Extracts investigation entities, classifies the submission,…, Deterministic rule-based triage used when model router is unavailable., Classifies the submission, extracts entities, assesses indicators, and plans…, EvidenceGap, ExtractedEntity, IndicatorAssessment, InputClassification, PlannedTaskProposal (+21 more)

### Community 105 - "cli.py"
Cohesion: 0.09
Nodes (32): Config, Logger, bootstrap(), Application bootstrap. Migrates the schema to head and, outside production,…, Prepare storage and seed development data., Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), _create_user() (+24 more)

### Community 106 - "orchestration/orchestrator.py"
Cohesion: 0.07
Nodes (44): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, Investigation planning and orchestration., _derive_status(), InvestigationOutcome, InvestigationState, _load_artifacts(), _load_investigation(), OrchestratorAgent (+36 more)

### Community 108 - "AgentRun"
Cohesion: 0.23
Nodes (9): DeclarativeBase, Base, Base class for all ORM models., AgentRun, One execution of one agent. Part of the investigation execution trace., Report, Path, test_report_discloses_missing_source_bytes() (+1 more)

### Community 109 - "deps.py"
Cohesion: 0.10
Nodes (20): LogRecord, CurrentUser, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,…, require_admin(), require_investigator(), Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``., require_role() (+12 more)

### Community 113 - "AgentResult"
Cohesion: 0.22
Nodes (6): AgentResult, Any, BaseModel, Structured outcome of one agent execution., Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure., Any

### Community 114 - "test_triage_agent_flag_disabled_uses_deterministic_fallback"
Cohesion: 0.29
Nodes (10): build_default_registry(), The tools available in the platform. Provides deterministic adapters for…, asyncio, Path, Representative Case 4: Graceful deterministic fallback when router is None., Representative Case 5: Model output schema repair loop in Triage., When ACIP_ENABLE_LLM_TRIAGE=False (default), TriageAgent bypasses ModelRouter., test_triage_agent_deterministic_fallback_when_no_router() (+2 more)

### Community 115 - "TriageAnalysis"
Cohesion: 0.12
Nodes (22): Complete structured triage output schema., TriageAnalysis, ChatMessage, LLMRequest, LLMUsage, Any, Contracts and data models for model-provider abstraction. Defines the message…, A single conversation turn. (+14 more)

### Community 117 - "_PinnedIPNetworkBackend"
Cohesion: 0.22
Nodes (6): AsyncNetworkStream, AutoBackend, SOCKET_OPTION, _PinnedIPNetworkBackend, Any, Network backend pinning TCP socket connections to a pre-validated IP address.

### Community 118 - "Evidence"
Cohesion: 0.13
Nodes (13): Collection, _path(), Any, Perform structured model-driven triage analysis with fallback to heuristics., _read_artifact_snippet(), _evidence_cursor(), EvidencePage, One page of evidence in timeline order, with a cursor for the next. The sort… (+5 more)

### Community 120 - "ToolRunner"
Cohesion: 0.15
Nodes (14): Any, AsyncSession, BaseModel, datetime, Path, UUID, Reject any artifact path outside the configured storage root., Keep the audit record useful without copying bulk input into it. (+6 more)

## Knowledge Gaps
- **61 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+56 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **29 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `EvidenceStore` connect `EvidenceStore` to `list_evidence`, `ReportAgent`, `ModelExecution`, `TimeConfidence`, `investigations.py`, `ToolRun`, `triage.py`, `orchestration/orchestrator.py`, `AgentRun`, `AgentContext`, `test_triage_agent_flag_disabled_uses_deterministic_fallback`, `Severity`, `Evidence`, `ToolRunner`, `EntityType`, `types.py`?**
  _High betweenness centrality (0.058) - this node is a cross-community bridge._
- **Why does `Settings` connect `Settings` to `Investigation`, `Database`, `test_historical_migration_0002_to_0003_populated_upgrade`, `triage.py`, `cli.py`, `ToolRegistry`, `orchestration/orchestrator.py`, `get_not_implemented`, `deps.py`, `AgentContext`, `ModelRouter`, `AgentRun`, `Role`, `test_triage_agent_flag_disabled_uses_deterministic_fallback`, `Services`, `types.py`, `app.py`?**
  _High betweenness centrality (0.053) - this node is a cross-community bridge._
- **Why does `Severity` connect `Severity` to `ReportAgent`, `investigations.py`, `evaluate_auth_rules`, `triage.py`, `evaluate_web_rules`, `AgentContext`, `ModelRouter`, `Role`, `TriageAnalysis`, `EvidenceStore`, `types.py`?**
  _High betweenness centrality (0.051) - this node is a cross-community bridge._
- **Are the 55 inferred relationships involving `Database` (e.g. with `build_services()` and `Services`) actually correct?**
  _`Database` has 55 INFERRED edges - model-reasoned connections that need verification._
- **Are the 46 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 46 INFERRED edges - model-reasoned connections that need verification._
- **Are the 48 inferred relationships involving `Severity` (e.g. with `LogAnalysisAgent` and `ReportAgent`) actually correct?**
  _`Severity` has 48 INFERRED edges - model-reasoned connections that need verification._
- **Are the 43 inferred relationships involving `EvidenceStore` (e.g. with `AgentContext` and `list_evidence()`) actually correct?**
  _`EvidenceStore` has 43 INFERRED edges - model-reasoned connections that need verification._