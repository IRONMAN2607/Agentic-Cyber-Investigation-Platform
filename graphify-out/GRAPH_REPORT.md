# Graph Report - AACIP  (2026-10-12)

## Corpus Check
- 200 files · ~114,459 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1814 nodes · 5528 edges · 141 communities (103 shown, 38 thin omitted)
- Extraction: 77% EXTRACTED · 23% INFERRED · 0% AMBIGUOUS · INFERRED: 1292 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `3215485c`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- _sqlite_pragmas
- EvidenceStore
- Finding
- TimeConfidence
- InvestigationRunner
- _forbid_bulk_dml
- investigations.py
- evaluate_auth_rules
- web_log_parser.py
- backup.py
- IOCExtractorArgs
- acip/errors.py
- test_ssrf.py
- ModelRouter
- AgentContext
- conftest.py
- Grounding Invariants G0-G4
- tokens.py
- execute_condition
- Severity
- InvestigationStatus
- CLAUDE.md
- Evidence
- Services
- agentrouter
- store_stream
- Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms
- security/validation.py
- evaluate_web_rules
- ValueError
- app.js
- Settings
- Three-Transaction Orchestrator
- migrate.py
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- AgentRun
- auth.py
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
- EntityType
- _get_python_files
- .opencode/opencode.json
- ACIP Empirical Evaluation Results
- get_not_implemented
- router.py
- run_subprocess_sandboxed
- graphify.js
- test_health.py
- .run
- AGENTS.md
- detection/mitre.py
- ModelExecution
- CorrelationAgent
- types.py
- Database
- _uuid_pk
- EvidenceKind
- Artifact
- ProviderAvailability
- get_session
- .complete
- ValidationError
- TargetType
- Plan
- TriageAgent
- cli.py
- OrchestratorAgent
- test_investigation_lifecycle.py
- test_reasoning_and_hypothesis_full_pipeline
- datasets/__init__.py
- experiments/__init__.py
- env.py
- metrics/__init__.py
- Role
- RunStatus
- llm/contracts.py
- test_artifact_ingestion_api.py
- SafeHTTPFetcher
- test_types.py
- test_auth.py
- _build_chain
- results/__init__.py
- test_evidence_graph_and_timeline_pipeline
- test_auth_log_incident_scenario
- test_clean_web_log_scenario
- ArtifactKind
- test_upload_security.py
- runners/__init__.py
- _coerce
- test_investigation_crud_and_lifecycle
- _fetch_hypotheses_detail
- _forbid_mutation
- _redact
- test_orchestrator_agent_end_to_end_lifecycle
- test_rate_limit.py
- test_hypothesis_agent_generates_competing_hypotheses_with_g3
- _chunks
- reproduce.sh script
- authorized_purge

## God Nodes (most connected - your core abstractions)
1. `Database` - 89 edges
2. `Investigation` - 81 edges
3. `Severity` - 81 edges
4. `Settings` - 73 edges
5. `AgentContext` - 71 edges
6. `EvidenceStore` - 70 edges
7. `Evidence` - 57 edges
8. `FindingDraft` - 50 edges
9. `Artifact` - 50 edges
10. `RunStatus` - 49 edges

## Surprising Connections (you probably didn't know these)
- `test_hypothesis_gap_draft()` --uses--> `HypothesisGapDraft`  [INFERRED]
  tests/unit/test_domain_models.py → src/acip/core/evidence/contracts.py
- `test_sliding_window_rate_limiter_unit()` --uses--> `SlidingWindowRateLimiter`  [INFERRED]
  tests/security/test_rate_limit.py → src/acip/core/security/ratelimit.py
- `test_role_values()` --uses--> `Role`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_investigation_status_terminal()` --uses--> `InvestigationStatus`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_severity_ordering()` --uses--> `Severity`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **End-to-End Evidence Provenance Pipeline** — docs_tools_tool_adapter_contract, docs_evidence_model_evidence_record, docs_evidence_model_traceability_chain, docs_frontend_provenance_ui_rules, docs_evidence_graph_relationships [EXTRACTED 1.00]
- **Experimental Evaluation and Ablation Framework** — docs_experiments_comparison_conditions, docs_experiments_ablations, docs_experiments_evaluation_metrics, docs_research_central_question, docs_model_abstraction_replay_double [EXTRACTED 1.00]
- **Grounding Invariants Enforcement Subsystem** — docs_evidence_model_grounding_invariants, docs_agents_agent_contract, docs_model_abstraction_core_llm, docs_experiments_evaluation_metrics, docs_research_central_question [EXTRACTED 1.00]

## Communities (141 total, 38 thin omitted)

### Community 0 - "_sqlite_pragmas"
Cohesion: 0.29
Nodes (5): async_sessionmaker, Any, AsyncSession, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., _sqlite_pragmas()

### Community 1 - "EvidenceStore"
Cohesion: 0.12
Nodes (17): HypothesisGapDraft, A declared gap in evidence preventing resolution of a hypothesis., EvidenceStore, AsyncSession, UUID, Writes evidence and findings for a single investigation., Persist drafts, skipping observations already recorded. Deduplication is by…, Validate a claim against the grounding invariants and persist it. (+9 more)

### Community 2 - "Finding"
Cohesion: 0.20
Nodes (7): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, Finding, A claim about the investigation, bound to the evidence supporting it.

### Community 3 - "TimeConfidence"
Cohesion: 0.17
Nodes (13): Match, AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime, Parsing options. Note the absence of any path argument., Parses Linux authentication logs into normalised auth events. (+5 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.17
Nodes (9): InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle., Cancel an in-flight investigation task., Await every scheduled investigation. Used by tests and shutdown. (+1 more)

### Community 5 - "_forbid_bulk_dml"
Cohesion: 0.67
Nodes (3): ORMExecuteState, _forbid_bulk_dml(), Reject bulk UPDATE/DELETE against an append-only table.

### Community 6 - "investigations.py"
Cohesion: 0.10
Nodes (47): get_evidence_provenance(), get_investigation_detail(), Investigation lifecycle endpoints., Everything a workspace view needs, in one round trip., Resolve one observation to the tool, arguments, agent and artifact behind it., AgentRunResponse, ArtifactResponse, AuditLogResponse (+39 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.17
Nodes (21): AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after(), Deterministic detection rules. These are pure functions over normalised events:… (+13 more)

### Community 8 - "web_log_parser.py"
Cohesion: 0.12
Nodes (24): _build_evidence_draft(), _detect_attacks(), _parse_request(), _parse_timestamp(), BaseModel, datetime, Deterministic web server access log parser and attack detection adapter. Parses…, Parses Apache, Nginx, and W3C web server access logs into structured events. (+16 more)

### Community 9 - "backup.py"
Cohesion: 0.23
Nodes (21): BackupIntegrityError, create_backup(), Path, Portable SQLite backup and restore with artifact-integrity verification. The…, A backup is incomplete or its artifact bytes do not match the database., Create and verify a consistent SQLite/artifact snapshot at ``destination``.…, Verify and restore ``source`` into empty configured SQLite/artifact paths.…, Raise when a backup lacks required source bytes or has a digest mismatch. (+13 more)

### Community 10 - "IOCExtractorArgs"
Cohesion: 0.20
Nodes (10): IOCExtractorArgs, _ip_scope(), Any, BaseModel, IPv4Address, IPv6Address, Return the canonical value plus extra fields, or ``None`` to reject., Classify an address. Non-global addresses are weak indicators. (+2 more)

### Community 11 - "acip/errors.py"
Cohesion: 0.11
Nodes (18): Exception, Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, Thread-safe sliding window rate limiter., Check whether the key is within rate limits; increments counter if allowed.…, Clear all rate limit history (useful in tests)., FastAPI dependency for rate limiting endpoints by client IP. (+10 more)

### Community 12 - "test_ssrf.py"
Cohesion: 0.17
Nodes (17): patch, is_ip_forbidden(), IPv4Address, IPv6Address, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Check if an IP address falls into a private, loopback, or cloud metadata range., validate_url_ssrf_safe(), test_is_ip_allowed_public_ips() (+9 more)

### Community 13 - "ModelRouter"
Cohesion: 0.13
Nodes (37): CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains., Retrieve the routing rule and candidate list for a given task class., Create standard routing policy with Llama 3.2 11B and GPT-OSS 20B candidates., RoutingPolicy (+29 more)

### Community 14 - "AgentContext"
Cohesion: 0.09
Nodes (30): AuthDetectionHit, AgentContext, AgentResult, Any, BaseModel, Everything an agent is given for one execution., Structured outcome of one agent execution., Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure. (+22 more)

### Community 15 - "conftest.py"
Cohesion: 0.29
Nodes (13): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+5 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "tokens.py"
Cohesion: 0.19
Nodes (15): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, JWT access tokens. Short-lived bearer tokens signed with HS256. Refresh tokens…, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`. (+7 more)

### Community 18 - "execute_condition"
Cohesion: 0.06
Nodes (52): GroundTruthFinding, GroundTruthScenario, Ground truth schemas for evaluation., A ground-truth malicious event or attack step to be detected., A benchmark scenario with raw artifacts and ground truth labels., Benchmark evaluation scenarios with authentic telemetry and ground truth., MetricCalculator, Any (+44 more)

### Community 19 - "Severity"
Cohesion: 0.17
Nodes (17): assess(), assess_with_model_opinion(), Protocol, Deterministic risk scoring. Severity and risk are computed from findings by a…, Assess risk deterministically, attaching an attributed model opinion. The model…, Structural type covering both ORM findings and drafts., Roll findings up into an investigation-level severity and risk score., RiskAssessment (+9 more)

### Community 20 - "InvestigationStatus"
Cohesion: 0.13
Nodes (37): delete, File, Form, Investigator, LoadedInvestigation, cancel_investigation(), create_investigation(), create_task() (+29 more)

### Community 22 - "Evidence"
Cohesion: 0.08
Nodes (30): Collection, ColumnElement, _evidence_after(), _evidence_cursor(), EvidencePage, One page of evidence in timeline order, with a cursor for the next. The sort…, Every matching row up to ``cap``, and whether the cap cut the read short.…, One page of evidence, plus the cursor that continues it. (+22 more)

### Community 23 - "Services"
Cohesion: 0.13
Nodes (24): Admin, get_services(), get_settings_dep(), Request, Everything built once at startup., Services, Server-Sent Events (SSE) stream for real-time investigation progress., stream_investigation_events() (+16 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "store_stream"
Cohesion: 0.19
Nodes (15): Path, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Remove group/other access and any execute bit where the OS supports it., Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, Reduce a client-supplied filename to a safe display label. The result is used…, read_text(), _restrict_permissions(), sanitize_filename() (+7 more)

### Community 26 - "Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms"
Cohesion: 0.08
Nodes (23): 1. Evidence Graph Engine, 2. Competing Hypotheses & Adversarial Validation, A. Maximum Bipartite Cardinality Matching, Abstract, Analysis of Research Questions, Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms, B. Benchmark Scenarios, C. Experimental Conditions (+15 more)

### Community 27 - "security/validation.py"
Cohesion: 0.15
Nodes (16): Input and indicator validation primitives. Provides strict, deterministic…, Validate and canonicalize a target value for investigation creation., Validate and canonicalize an IPv4 or IPv6 address string. Returns the canonical…, Validate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512). Returns the…, Validate and canonicalize a fully qualified domain name. Returns the lowercased…, Validate and canonicalize a URL structure. Enforces RFC 3986 compliance and…, validate_domain(), validate_hash() (+8 more)

### Community 28 - "evaluate_web_rules"
Cohesion: 0.20
Nodes (19): DetectionHit, evaluate_web_rules(), _find_error_bursts(), UUID, Deterministic detection rules for web access logs. Pure functions over…, A parsed web access event, decoupled from the ORM., Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS., Group 4xx/5xx error responses into bursts per IP. (+11 more)

### Community 29 - "ValueError"
Cohesion: 0.09
Nodes (16): Dialect, parametrize, field_validator, model_validator, field_validator, datetime, field_validator, datetime (+8 more)

### Community 30 - "app.js"
Cohesion: 0.37
Nodes (14): api(), checkCurrentUser(), closeEventStream(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderSvgGraph(), renderWorkspace() (+6 more)

### Community 31 - "Settings"
Cohesion: 0.14
Nodes (14): BaseSettings, RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, _serialisable_errors() (+6 more)

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

### Community 40 - "AgentRun"
Cohesion: 0.11
Nodes (18): AgentRun, One execution of one agent. Part of the investigation execution trace., Report, A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry, AsyncSession, asyncio (+10 more)

### Community 41 - "auth.py"
Cohesion: 0.12
Nodes (22): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+14 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - "orchestration/__init__.py"
Cohesion: 0.14
Nodes (9): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, Investigation planning and orchestration., InvestigationOutcome, InvestigationState, Final outcome of an orchestrated investigation., Retrieve the in-memory state of an active or recent investigation., In-memory and durable state representation of an active investigation., InvestigationState computes task progress metrics correctly. (+1 more)

### Community 68 - "EntityType"
Cohesion: 0.26
Nodes (11): normalize_entity_value(), Canonicalise an entity value so the same thing has one representation. Entity…, EntityType, StrEnum, Node types for the evidence graph. Recorded on evidence in M1 so that Phase 5…, test_content_hash_invariance_and_sensitivity(), test_naive_datetime_rejected(), test_normalize_entity_domain() (+3 more)

### Community 72 - "_get_python_files"
Cohesion: 0.44
Nodes (8): _get_python_files(), Path, The schema has one source of truth: the Alembic chain. ``create_all`` was the…, A reserved key in ``extra`` raises KeyError only when the record is emitted.…, test_no_direct_llm_sdk_imports_in_agents(), test_no_metadata_create_all_in_src(), test_no_reserved_logrecord_keys_in_log_extra(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 75 - "get_not_implemented"
Cohesion: 0.20
Nodes (10): CaptureFixture, get_not_implemented(), Any, Declared limitations of this deployment. A single source for what the platform…, Return declared capability limitations reflecting the active runtime…, AsyncClient, test_admin_capabilities_access_control(), test_capabilities_limitations_reflects_active_llm_flag() (+2 more)

### Community 76 - "router.py"
Cohesion: 0.11
Nodes (31): MessageRole, StrEnum, Role of a message sender in a chat conversation., BudgetExceededError, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderQuotaExceeded (+23 more)

### Community 77 - "run_subprocess_sandboxed"
Cohesion: 0.24
Nodes (12): ToolExecutionError, Path, Tier 1 tool execution sandbox. Executes external tools as isolated subprocesses…, Execute a command in Tier 1 subprocess isolation. Guarantees: - Never uses…, run_subprocess_sandboxed(), SandboxResult, asyncio, Path (+4 more)

### Community 80 - "test_health.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_capabilities(), test_health()

### Community 81 - ".run"
Cohesion: 0.23
Nodes (8): Any, BaseModel, Path, UUID, Reject any artifact path outside the configured storage root., Keep the audit record useful without copying bulk input into it., Validate, execute and audit a single tool call., _redact_args()

### Community 83 - "detection/mitre.py"
Cohesion: 0.29
Nodes (9): AttackTechnique, get_attack_technique(), map_rule_to_technique(), MITRE ATT&CK catalog and mapping validation. Enforces Invariant G7: no finding…, Lookup a technique in the catalog. Enforces Invariant G7: raises GroundingError…, Deterministically map a detection rule to its ATT&CK technique., test_mitre_catalog_version_and_contents(), test_mitre_deterministic_rule_mapping() (+1 more)

### Community 90 - "ModelExecution"
Cohesion: 0.14
Nodes (18): FindingEvidenceDraft, HypothesisDraft, ModelExecutionDraft, BaseModel, A citation connecting evidence to a finding with a supporting or contradicting…, A competing candidate explanation under evaluation (Invariant G3)., Structured record of an LLM call for experimental tracking., ModelExecution (+10 more)

### Community 91 - "CorrelationAgent"
Cohesion: 0.06
Nodes (39): DeclarativeBase, CorrelationAgent, Any, UUID, Extract all typed EntityRef instances from an evidence row., Derive directed, typed relationship edges backed by this evidence row., Deterministic evidence graph correlation and entity resolution agent., GraphSubgraph (+31 more)

### Community 92 - "types.py"
Cohesion: 0.09
Nodes (39): Implementation of benchmark comparison conditions and ablations. Conditions: -…, Logger, Agent, ABC, Agent contract. Agents receive a typed context and return a typed result (spec…, Base class for all agents., Evidence graph correlation and entity resolution agent. Performs Tier 1…, Hypothesis Generation Agent. Formulates competing candidate explanations for… (+31 more)

### Community 93 - "Database"
Cohesion: 0.13
Nodes (26): AsyncEngine, Orchestrator, Investigation, Database, Yield a session, committing on success and rolling back on error., Owns the engine and session factory for one database URL., test_audit_log_immutability(), test_bulk_dml_blocked_on_audit_log() (+18 more)

### Community 94 - "_uuid_pk"
Cohesion: 0.67
Nodes (3): Mapped, UUID, _uuid_pk()

### Community 95 - "EvidenceKind"
Cohesion: 0.06
Nodes (58): EntityRef, A typed reference to a real-world entity observed in evidence., A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError, Linux authentication log parser. A deterministic, dependency-free parser for…, NoArgs, ABC (+50 more)

### Community 96 - "Artifact"
Cohesion: 0.20
Nodes (8): Planner, Protocol, Chooses which agents run, in what order, and why., Artifact, An uploaded input, stored content-addressed under the quarantine dir., Path, OrchestratorAgent falls back to deterministic rules if triage fails or is…, test_interpret_triage_result_fallback_when_unsuccessful()

### Community 97 - "ProviderAvailability"
Cohesion: 0.18
Nodes (7): ProviderAvailability, Health and model discovery status for an LLM provider., LLMProvider, Protocol, Abstract protocol for all LLM backend adapters., Probe provider connectivity, authentication, and available models., Probe NVIDIA NIM endpoint to verify API key and model availability.

### Community 98 - "get_session"
Cohesion: 0.15
Nodes (27): alias, description, ge, le, MAX_EVIDENCE_PAGE, Query, get_session(), Depends (+19 more)

### Community 99 - ".complete"
Cohesion: 0.19
Nodes (10): Any, AsyncSession, BaseModel, UUID, Execute a completion for a TaskClass with optional structured schema…, Execute a candidate model, handling structured output repair retries., Persist execution telemetry to llm_calls (ModelExecution)., Generate a clean example JSON structure from a Pydantic model for prompt… (+2 more)

### Community 101 - "ValidationError"
Cohesion: 0.27
Nodes (9): PinnedIPTransport, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Async HTTP transport establishing socket connection directly to a pinned IP., Fetch remote URL safely, validating every hop and streaming the body., Result of an SSRF-safe HTTP request., SafeFetchResult, PayloadTooLargeError, SSRFProtectionError (+1 more)

### Community 102 - "TargetType"
Cohesion: 0.12
Nodes (17): AgentRegistry, build_default_registry(), Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint., The agents available in this milestone. Phase 4 adds the network, endpoint,…, build_services(), Compose the object graph. Pure wiring, no I/O., AdaptivePlanner (+9 more)

### Community 103 - "Plan"
Cohesion: 0.33
Nodes (3): Plan, An ordered set of tasks plus the reason the shape was chosen., MockPlanner

### Community 104 - "TriageAgent"
Cohesion: 0.11
Nodes (36): _path(), Any, Perform structured model-driven triage analysis with fallback to heuristics., Deterministic rule-based triage used when model router is unavailable., Classifies the submission, extracts entities, assesses indicators, and plans…, _read_artifact_snippet(), EvidenceGap, ExtractedEntity (+28 more)

### Community 105 - "cli.py"
Cohesion: 0.17
Nodes (18): ArgumentParser, _backup(), build_parser(), _capabilities(), _create_user(), _init(), main(), Path (+10 more)

### Community 106 - "OrchestratorAgent"
Cohesion: 0.17
Nodes (17): _derive_status(), _load_artifacts(), _load_investigation(), OrchestratorAgent, AsyncSession, UUID, First functional Orchestrator Agent. Coordinates the investigation lifecycle:…, Run the full investigation lifecycle. Never raises for task-level failures. (+9 more)

### Community 107 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 108 - "test_reasoning_and_hypothesis_full_pipeline"
Cohesion: 0.24
Nodes (7): Hypothesis, Phase 7 schema scaffolding: competing candidate explanation requiring…, HypothesisStatus, Status of a competing explanatory hypothesis., asyncio, Path, test_reasoning_and_hypothesis_full_pipeline()

### Community 111 - "env.py"
Cohesion: 0.31
Nodes (8): do_run_migrations(), Connection, Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_offline(), run_migrations_online()

### Community 113 - "Role"
Cohesion: 0.14
Nodes (24): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), AsyncSession, CurrentUser, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,… (+16 more)

### Community 114 - "RunStatus"
Cohesion: 0.13
Nodes (24): EvidenceDraft, Stable digest of the observation, used to deduplicate evidence. Covers only…, An observation produced by a tool, before persistence. ``observed_at`` is when…, One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun, build_default_registry(), The tools available in the platform. Provides deterministic adapters for…, datetime (+16 more)

### Community 115 - "llm/contracts.py"
Cohesion: 0.11
Nodes (26): MonkeyPatch, ChatMessage, LLMRequest, LLMResponse, LLMUsage, Any, Contracts and data models for model-provider abstraction. Defines the message…, A single conversation turn. (+18 more)

### Community 116 - "test_artifact_ingestion_api.py"
Cohesion: 0.53
Nodes (5): AsyncClient, test_ingest_text_artifact_endpoint(), test_ingest_url_artifact_blocks_ssrf(), test_upload_pcap_artifact_success(), test_upload_pcap_mismatch_rejected()

### Community 117 - "SafeHTTPFetcher"
Cohesion: 0.16
Nodes (12): AsyncNetworkStream, AutoBackend, SOCKET_OPTION, _PinnedIPNetworkBackend, Any, Network backend pinning TCP socket connections to a pre-validated IP address., Asynchronous HTTP fetcher with anti-SSRF protection and resource bounding., SafeHTTPFetcher (+4 more)

### Community 118 - "test_types.py"
Cohesion: 0.33
Nodes (5): test_assertion_class_values(), test_investigation_status_terminal(), test_role_values(), test_severity_ordering(), test_time_confidence_values()

### Community 119 - "test_auth.py"
Cohesion: 0.60
Nodes (4): AsyncClient, test_auth_login_invalid_password(), test_auth_login_success(), test_auth_me_endpoint()

### Community 120 - "_build_chain"
Cohesion: 0.15
Nodes (18): _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker., The defect this file exists for: SET NULL used to unground every citing FACT., Evidence must stay traceable to the bytes it came from. (+10 more)

### Community 122 - "test_evidence_graph_and_timeline_pipeline"
Cohesion: 0.67
Nodes (3): AsyncClient, asyncio, test_evidence_graph_and_timeline_pipeline()

### Community 123 - "test_auth_log_incident_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_auth_log_incident_scenario(), test_clean_log_scenario()

### Community 124 - "test_clean_web_log_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_clean_web_log_scenario(), test_web_log_attack_scenario()

### Community 125 - "ArtifactKind"
Cohesion: 0.19
Nodes (19): detect_artifact_kind(), detect_magic_bytes(), Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Classify an artifact based on header magic bytes, filename, and declared kind.…, Convenience helper to store an in-memory byte buffer into quarantine storage., Result of a successful intake., Inspect the first bytes of a file to detect its format and MIME type., store_bytes() (+11 more)

### Community 126 - "test_upload_security.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_upload_empty_file_rejected(), test_upload_path_traversal_sanitized()

### Community 129 - "_coerce"
Cohesion: 0.18
Nodes (9): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, Any, Merge the ambient context into each record., One JSON object per line, suitable for ingestion by a log pipeline. (+1 more)

### Community 131 - "_fetch_hypotheses_detail"
Cohesion: 0.33
Nodes (7): _append_only_counts(), _fetch_hypotheses_detail(), list_investigation_hypotheses(), UUID, List competing hypotheses, refutation conditions, and gaps., Count the records a purge would destroy, before any of them are gone., HypothesisDetailResponse

### Community 134 - "test_orchestrator_agent_end_to_end_lifecycle"
Cohesion: 0.40
Nodes (6): asyncio, Path, When StaticPlanner is configured, OrchestratorAgent executes its plan verbatim., OrchestratorAgent receives an investigation, calls Triage, interprets result,…, test_orchestrator_agent_end_to_end_lifecycle(), test_orchestrator_agent_respects_static_planner_verbatim()

### Community 135 - "test_rate_limit.py"
Cohesion: 0.40
Nodes (5): AsyncClient, The investigation limiter was defined and wired to nothing. Login was the only…, test_auth_login_rate_limiting(), test_investigation_creation_is_rate_limited(), test_sliding_window_rate_limiter_unit()

### Community 136 - "test_hypothesis_agent_generates_competing_hypotheses_with_g3"
Cohesion: 0.40
Nodes (6): asyncio, Path, Invariant G3: A hypothesis without a refutation condition raises GroundingError., HypothesisAgent generates competing hypotheses enforcing Invariant G3., test_hypothesis_agent_generates_competing_hypotheses_with_g3(), test_invariant_g3_empty_refutation_condition_rejected()

### Community 137 - "_chunks"
Cohesion: 0.67
Nodes (3): _chunks(), Stream an upload without buffering it whole., UploadFile

## Knowledge Gaps
- **80 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+75 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **38 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Settings` connect `Settings` to `test_orchestrator_agent_end_to_end_lifecycle`, `test_hypothesis_agent_generates_competing_hypotheses_with_g3`, `backup.py`, `ModelRouter`, `AgentContext`, `conftest.py`, `execute_condition`, `Services`, `ValueError`, `migrate.py`, `AgentRun`, `get_not_implemented`, `types.py`, `Database`, `Artifact`, `TargetType`, `TriageAgent`, `cli.py`, `OrchestratorAgent`, `test_investigation_lifecycle.py`, `test_reasoning_and_hypothesis_full_pipeline`, `Role`, `RunStatus`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `_sqlite_pragmas`, `EvidenceStore`, `InvestigationRunner`, `test_orchestrator_agent_end_to_end_lifecycle`, `test_hypothesis_agent_generates_competing_hypotheses_with_g3`, `backup.py`, `ModelRouter`, `conftest.py`, `execute_condition`, `Evidence`, `Services`, `Settings`, `migrate.py`, `AgentRun`, `ModelExecution`, `CorrelationAgent`, `types.py`, `Artifact`, `TargetType`, `TriageAgent`, `cli.py`, `OrchestratorAgent`, `test_reasoning_and_hypothesis_full_pipeline`, `Role`, `RunStatus`, `_build_chain`?**
  _High betweenness centrality (0.042) - this node is a cross-community bridge._
- **Why does `Severity` connect `Severity` to `EvidenceStore`, `Finding`, `investigations.py`, `evaluate_auth_rules`, `ModelRouter`, `AgentContext`, `execute_condition`, `evaluate_web_rules`, `EntityType`, `CorrelationAgent`, `types.py`, `Database`, `TriageAgent`, `RunStatus`, `llm/contracts.py`, `test_types.py`, `_build_chain`, `test_auth_log_incident_scenario`, `test_clean_web_log_scenario`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **Are the 68 inferred relationships involving `Database` (e.g. with `execute_condition()` and `BenchmarkRunner`) actually correct?**
  _`Database` has 68 INFERRED edges - model-reasoned connections that need verification._
- **Are the 59 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 59 INFERRED edges - model-reasoned connections that need verification._
- **Are the 58 inferred relationships involving `Severity` (e.g. with `GroundTruthFinding` and `execute_condition()`) actually correct?**
  _`Severity` has 58 INFERRED edges - model-reasoned connections that need verification._
- **Are the 56 inferred relationships involving `Settings` (e.g. with `execute_condition()` and `setup_scenario_investigation()`) actually correct?**
  _`Settings` has 56 INFERRED edges - model-reasoned connections that need verification._