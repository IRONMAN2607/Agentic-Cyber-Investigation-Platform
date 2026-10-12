# Graph Report - AACIP  (2026-10-12)

## Corpus Check
- 166 files · ~100,814 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1641 nodes · 4899 edges · 132 communities (101 shown, 31 thin omitted)
- Extraction: 77% EXTRACTED · 23% INFERRED · 0% AMBIGUOUS · INFERRED: 1107 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `838350f9`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Database
- _evidence_after
- Evidence
- TimeConfidence
- InvestigationRunner
- _forbid_bulk_dml
- investigations.py
- evaluate_auth_rules
- web_log_parser.py
- backup.py
- read_text
- ACIPError
- test_ssrf.py
- ModelRouter
- AgentContext
- conftest.py
- Grounding Invariants G0-G4
- Role
- ToolResult
- ScorableFinding
- get_session
- CLAUDE.md
- orchestration/orchestrator.py
- admin_capabilities
- agentrouter
- ArtifactKind
- EvidenceDraft
- test_artifact_validation.py
- evaluate_web_rules
- ValueError
- app.js
- app.py
- Three-Transaction Orchestrator
- migrate.py
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- Artifact
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
- threat_intel.py
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
- test_grounding.py
- _get_python_files
- .opencode/opencode.json
- ToolRegistry
- get_not_implemented
- router.py
- run_subprocess_sandboxed
- graphify.js
- test_health
- deps.py
- AGENTS.md
- .__init__
- EvidenceStore
- GraphSubgraph
- types.py
- .session
- CyberReasoningProvider
- acip/errors.py
- Investigation
- ProviderAvailability
- AsyncSession
- ModelExecution
- passwords.py
- AgentRegistry
- TaskRun
- Severity
- Settings
- OrchestratorAgent
- test_investigation_lifecycle.py
- models.py
- ValidationError
- .run
- env.py
- test_pcap_parser_extracts_flows_and_dns
- authz.py
- AgentRun
- llm/contracts.py
- test_artifact_ingestion_api.py
- _PinnedIPNetworkBackend
- test_types.py
- test_auth.py
- _build_chain
- audit.py
- test_evidence_graph_and_timeline_pipeline
- test_auth_log_incident_scenario
- test_clean_web_log_scenario
- test_store_bytes_successful_intake
- test_upload_security.py
- _chunks
- log_context
- test_investigation_crud_and_lifecycle
- authorized_purge

## God Nodes (most connected - your core abstractions)
1. `Database` - 78 edges
2. `Severity` - 72 edges
3. `Investigation` - 69 edges
4. `EvidenceStore` - 66 edges
5. `Settings` - 62 edges
6. `AgentContext` - 59 edges
7. `Evidence` - 57 edges
8. `Role` - 47 edges
9. `OrchestratorAgent` - 43 edges
10. `Artifact` - 43 edges

## Surprising Connections (you probably didn't know these)
- `test_role_values()` --uses--> `Role`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_investigation_status_terminal()` --uses--> `InvestigationStatus`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_severity_ordering()` --uses--> `Severity`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_assertion_class_values()` --uses--> `AssertionClass`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_time_confidence_values()` --uses--> `TimeConfidence`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **End-to-End Evidence Provenance Pipeline** — docs_tools_tool_adapter_contract, docs_evidence_model_evidence_record, docs_evidence_model_traceability_chain, docs_frontend_provenance_ui_rules, docs_evidence_graph_relationships [EXTRACTED 1.00]
- **Experimental Evaluation and Ablation Framework** — docs_experiments_comparison_conditions, docs_experiments_ablations, docs_experiments_evaluation_metrics, docs_research_central_question, docs_model_abstraction_replay_double [EXTRACTED 1.00]
- **Grounding Invariants Enforcement Subsystem** — docs_evidence_model_grounding_invariants, docs_agents_agent_contract, docs_model_abstraction_core_llm, docs_experiments_evaluation_metrics, docs_research_central_question [EXTRACTED 1.00]

## Communities (132 total, 31 thin omitted)

### Community 0 - "Database"
Cohesion: 0.14
Nodes (11): async_sessionmaker, AsyncEngine, Database, Any, AsyncSession, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., Owns the engine and session factory for one database URL., _sqlite_pragmas() (+3 more)

### Community 1 - "_evidence_after"
Cohesion: 0.12
Nodes (16): Collection, ColumnElement, _evidence_after(), _evidence_cursor(), EvidencePage, One page of evidence in timeline order, with a cursor for the next. The sort…, Every matching row up to ``cap``, and whether the cap cut the read short.…, One page of evidence, plus the cursor that continues it. (+8 more)

### Community 2 - "Evidence"
Cohesion: 0.17
Nodes (11): UUID, Extract all typed EntityRef instances from an evidence row., Derive directed, typed relationship edges backed by this evidence row., _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent (+3 more)

### Community 3 - "TimeConfidence"
Cohesion: 0.20
Nodes (12): Match, AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime, Parsing options. Note the absence of any path argument., Parses Linux authentication logs into normalised auth events. (+4 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.20
Nodes (8): InvestigationRunner, UUID, Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle., Cancel an in-flight investigation task., Await every scheduled investigation. Used by tests and shutdown., Cancel outstanding work after giving it a chance to finish.

### Community 5 - "_forbid_bulk_dml"
Cohesion: 0.67
Nodes (3): ORMExecuteState, _forbid_bulk_dml(), Reject bulk UPDATE/DELETE against an append-only table.

### Community 6 - "investigations.py"
Cohesion: 0.10
Nodes (48): get_evidence_provenance(), get_investigation_detail(), Investigation lifecycle endpoints., Everything a workspace view needs, in one round trip., Resolve one observation to the tool, arguments, agent and artifact behind it., AgentCapabilityInfo, AgentRunResponse, ArtifactResponse (+40 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.17
Nodes (21): AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after(), Deterministic detection rules. These are pure functions over normalised events:… (+13 more)

### Community 8 - "web_log_parser.py"
Cohesion: 0.12
Nodes (24): _build_evidence_draft(), _detect_attacks(), _parse_request(), _parse_timestamp(), BaseModel, datetime, Deterministic web server access log parser and attack detection adapter. Parses…, Parses Apache, Nginx, and W3C web server access logs into structured events. (+16 more)

### Community 9 - "backup.py"
Cohesion: 0.23
Nodes (21): BackupIntegrityError, create_backup(), Path, Portable SQLite backup and restore with artifact-integrity verification. The…, A backup is incomplete or its artifact bytes do not match the database., Create and verify a consistent SQLite/artifact snapshot at ``destination``.…, Verify and restore ``source`` into empty configured SQLite/artifact paths.…, Raise when a backup lacks required source bytes or has a digest mismatch. (+13 more)

### Community 10 - "read_text"
Cohesion: 0.11
Nodes (18): Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, read_text(), _context(), IOCExtractorArgs, _ip_scope(), Any, BaseModel, IPv4Address (+10 more)

### Community 11 - "ACIPError"
Cohesion: 0.07
Nodes (30): Exception, AttackTechnique, get_attack_technique(), map_rule_to_technique(), MITRE ATT&CK catalog and mapping validation. Enforces Invariant G7: no finding…, Lookup a technique in the catalog. Enforces Invariant G7: raises GroundingError…, Deterministically map a detection rule to its ATT&CK technique., Request (+22 more)

### Community 12 - "test_ssrf.py"
Cohesion: 0.14
Nodes (19): patch, is_ip_forbidden(), IPv4Address, IPv6Address, Check if an IP address falls into a private, loopback, or cloud metadata range., asyncio, test_is_ip_allowed_public_ips(), test_is_ip_forbidden_cgnat_and_multicast_and_unspecified() (+11 more)

### Community 13 - "ModelRouter"
Cohesion: 0.15
Nodes (31): CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains., Retrieve the routing rule and candidate list for a given task class., Create standard routing policy with Llama 3.2 11B and GPT-OSS 20B candidates., RoutingPolicy (+23 more)

### Community 14 - "AgentContext"
Cohesion: 0.13
Nodes (19): AuthDetectionHit, AgentContext, AgentResult, Any, BaseModel, Everything an agent is given for one execution., Structured outcome of one agent execution., Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure. (+11 more)

### Community 15 - "conftest.py"
Cohesion: 0.29
Nodes (13): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+5 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "Role"
Cohesion: 0.20
Nodes (17): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, JWT access tokens. Short-lived bearer tokens signed with HS256. Refresh tokens…, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`. (+9 more)

### Community 18 - "ToolResult"
Cohesion: 0.17
Nodes (12): NoArgs, BaseModel, What an adapter returns., For adapters that take no options., Do the work. Raise :class:`~acip.errors.ToolError` on failure., ToolResult, _parse_dns_qname(), PcapParserArgs (+4 more)

### Community 19 - "ScorableFinding"
Cohesion: 0.33
Nodes (3): Protocol, Structural type covering both ORM findings and drafts., ScorableFinding

### Community 20 - "get_session"
Cohesion: 0.11
Nodes (45): delete, File, Form, Investigator, LoadedInvestigation, get_services(), get_session(), get_settings_dep() (+37 more)

### Community 22 - "orchestration/orchestrator.py"
Cohesion: 0.11
Nodes (16): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, Investigation planning and orchestration., _derive_status(), InvestigationOutcome, InvestigationState, Investigation orchestration and Orchestrator Agent. Executes a dynamic or…, Final outcome of an orchestrated investigation., Outcome of an individual task execution. (+8 more)

### Community 23 - "admin_capabilities"
Cohesion: 0.25
Nodes (9): Admin, admin_capabilities(), capabilities(), Depends, get, Coarse capability report for clients without disclosing internal diagnostics., Detailed diagnostic capability report with live probe outputs for…, AdminCapabilitiesResponse (+1 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "ArtifactKind"
Cohesion: 0.16
Nodes (21): Path, Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Convenience helper to store an in-memory byte buffer into quarantine storage., Remove group/other access and any execute bit where the OS supports it., Result of a successful intake., Reduce a client-supplied filename to a safe display label. The result is used…, _restrict_permissions() (+13 more)

### Community 26 - "EvidenceDraft"
Cohesion: 0.16
Nodes (20): EntityRef, EvidenceDraft, normalize_entity_value(), Stable digest of the observation, used to deduplicate evidence. Covers only…, Canonicalise an entity value so the same thing has one representation. Entity…, A typed reference to a real-world entity observed in evidence., An observation produced by a tool, before persistence. ``observed_at`` is when…, EntityType (+12 more)

### Community 27 - "test_artifact_validation.py"
Cohesion: 0.11
Nodes (24): detect_artifact_kind(), detect_magic_bytes(), Classify an artifact based on header magic bytes, filename, and declared kind.…, Inspect the first bytes of a file to detect its format and MIME type., Input and indicator validation primitives. Provides strict, deterministic…, Validate and canonicalize a target value for investigation creation., Validate and canonicalize an IPv4 or IPv6 address string. Returns the canonical…, Validate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512). Returns the… (+16 more)

### Community 28 - "evaluate_web_rules"
Cohesion: 0.20
Nodes (19): DetectionHit, evaluate_web_rules(), _find_error_bursts(), UUID, Deterministic detection rules for web access logs. Pure functions over…, A parsed web access event, decoupled from the ORM., Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS., Group 4xx/5xx error responses into bursts per IP. (+11 more)

### Community 29 - "ValueError"
Cohesion: 0.09
Nodes (16): Dialect, parametrize, field_validator, model_validator, field_validator, datetime, field_validator, datetime (+8 more)

### Community 30 - "app.js"
Cohesion: 0.45
Nodes (10): api(), checkCurrentUser(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderWorkspace(), selectInvestigation(), setAuth() (+2 more)

### Community 31 - "app.py"
Cohesion: 0.09
Nodes (23): LogRecord, RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, _serialisable_errors() (+15 more)

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "migrate.py"
Cohesion: 0.12
Nodes (19): Config, model_validator, Require a real secret in production; generate an ephemeral one otherwise. A…, alembic_config(), Connection, Schema creation, through Alembic and only through Alembic. The migration chain…, Build an Alembic config without reading ``alembic.ini``. The ini file carries a…, _upgrade() (+11 more)

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

### Community 40 - "Artifact"
Cohesion: 0.21
Nodes (11): Artifact, An uploaded input, stored content-addressed under the quarantine dir., TargetType, asyncio, Path, OrchestratorAgent works with model-routed Triage analysis to dynamically create…, When StaticPlanner is configured, OrchestratorAgent executes its plan verbatim., OrchestratorAgent receives an investigation, calls Triage, interprets result,… (+3 more)

### Community 41 - "auth.py"
Cohesion: 0.21
Nodes (12): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+4 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - "threat_intel.py"
Cohesion: 0.26
Nodes (12): Everything an adapter is permitted to know about its invocation., ToolContext, BaseModel, Tier 3 Threat Intelligence tool adapter. Queries indicator reputation…, Options for threat intelligence reputation lookup., Tier 3 Threat Intelligence tool adapter., ThreatIntelArgs, ThreatIntelTool (+4 more)

### Community 68 - "test_grounding.py"
Cohesion: 0.44
Nodes (8): _create_tool_run(), _draft_evidence(), AsyncSession, UUID, test_grounding_invariant_cross_investigation_isolated(), test_grounding_invariant_g1_fact_requires_deterministic_tool_evidence(), test_grounding_invariant_g2_inference_requires_evidence_and_reasoning(), test_valid_fact_with_evidence_persisted()

### Community 72 - "_get_python_files"
Cohesion: 0.44
Nodes (8): _get_python_files(), Path, The schema has one source of truth: the Alembic chain. ``create_all`` was the…, A reserved key in ``extra`` raises KeyError only when the record is emitted.…, test_no_direct_llm_sdk_imports_in_agents(), test_no_metadata_create_all_in_src(), test_no_reserved_logrecord_keys_in_log_extra(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 74 - "ToolRegistry"
Cohesion: 0.24
Nodes (6): A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry, Path, test_report_discloses_missing_source_bytes(), test_report_discloses_retention_state_and_intact_bytes()

### Community 75 - "get_not_implemented"
Cohesion: 0.20
Nodes (10): CaptureFixture, get_not_implemented(), Any, Declared limitations of this deployment. A single source for what the platform…, Return declared capability limitations reflecting the active runtime…, AsyncClient, test_admin_capabilities_access_control(), test_capabilities_limitations_reflects_active_llm_flag() (+2 more)

### Community 76 - "router.py"
Cohesion: 0.13
Nodes (30): MessageRole, StrEnum, Role of a message sender in a chat conversation., BudgetExceededError, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderQuotaExceeded (+22 more)

### Community 77 - "run_subprocess_sandboxed"
Cohesion: 0.24
Nodes (12): ToolExecutionError, Path, Tier 1 tool execution sandbox. Executes external tools as isolated subprocesses…, Execute a command in Tier 1 subprocess isolation. Guarantees: - Never uses…, run_subprocess_sandboxed(), SandboxResult, asyncio, Path (+4 more)

### Community 81 - "deps.py"
Cohesion: 0.15
Nodes (18): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), AsyncSession, CurrentUser, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,… (+10 more)

### Community 90 - "EvidenceStore"
Cohesion: 0.07
Nodes (40): FindingEvidenceDraft, HypothesisDraft, HypothesisGapDraft, ModelExecutionDraft, BaseModel, Evidence and finding contracts. Agents and tools exchange these Pydantic models…, A citation connecting evidence to a finding with a supporting or contradicting…, A competing candidate explanation under evaluation (Invariant G3). (+32 more)

### Community 91 - "GraphSubgraph"
Cohesion: 0.11
Nodes (12): GraphSubgraph, Any, AsyncSession, UUID, Fetch the full evidence graph for this investigation, capped to limit., Find entities and edges within max_depth hops of start_entity_id. Cycle-safe…, Find all distinct paths connecting src_entity_id to dst_entity_id., Extract the evidence graph connected to a specific finding's cited evidence. (+4 more)

### Community 92 - "types.py"
Cohesion: 0.12
Nodes (26): Logger, Agent, ABC, Agent contract. Agents receive a typed context and return a typed result (spec…, Base class for all agents., CorrelationAgent, Evidence graph correlation and entity resolution agent. Performs Tier 1…, Deterministic evidence graph correlation and entity resolution agent. (+18 more)

### Community 93 - ".session"
Cohesion: 0.17
Nodes (15): Mark orphan running investigations as interrupted on startup., Yield a session, committing on success and rolling back on error., AsyncSession, The guard must bound its own blast radius: reads stay unaffected., One named escape hatch, so deliberate destruction is greppable., An investigation with evidence, for the bulk-DML cases below., The mapper guards never see bulk DML, so the session guard must.…, _seed_evidence() (+7 more)

### Community 94 - "CyberReasoningProvider"
Cohesion: 0.18
Nodes (9): CyberReasoningProvider, Analyze prompt content and construct an epistemically grounded TriageAnalysis., Intelligent local cyber investigation reasoning provider. Adheres strictly to…, build_default_router(), Any, BaseModel, Construct a default ModelRouter from application settings., Generate a clean example JSON structure from a Pydantic model for prompt… (+1 more)

### Community 95 - "acip/errors.py"
Cohesion: 0.13
Nodes (21): Typed application errors. Each error carries an HTTP status and a stable…, A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError, Linux authentication log parser. A deterministic, dependency-free parser for…, ABC, Tool adapter contract. A tool is the only thing in the platform allowed to…, Honest report of whether a tool can actually run right now. Surfaced through… (+13 more)

### Community 96 - "Investigation"
Cohesion: 0.13
Nodes (13): Orchestrator, Planner, Protocol, Chooses which agents run, in what order, and why., Investigation, InvestigationStatus, asyncio, Path (+5 more)

### Community 97 - "ProviderAvailability"
Cohesion: 0.14
Nodes (9): ProviderAvailability, Health and model discovery status for an LLM provider., LLMProvider, Protocol, LLMProvider protocol definition., Abstract protocol for all LLM backend adapters., Send a completion request to the provider for a specific model., Probe provider connectivity, authentication, and available models. (+1 more)

### Community 98 - "AsyncSession"
Cohesion: 0.15
Nodes (29): alias, description, ge, le, MAX_EVIDENCE_PAGE, Query, _append_only_counts(), get_finding_subgraph() (+21 more)

### Community 99 - "ModelExecution"
Cohesion: 0.18
Nodes (12): LLMResponse, Standardized response received from an LLM provider., AsyncSession, UUID, Execute a completion for a TaskClass with optional structured schema…, Execute a candidate model, handling structured output repair retries., Persist execution telemetry to llm_calls (ModelExecution)., ModelExecution (+4 more)

### Community 101 - "passwords.py"
Cohesion: 0.26
Nodes (10): hash_password(), needs_rehash(), Password hashing. Argon2id via ``argon2-cffi``, which is the current OWASP…, Return whether the password matches. Never raises on a bad password., True when the hash was produced with weaker parameters than current., verify_password(), test_needs_rehash(), test_password_hash_and_verify() (+2 more)

### Community 102 - "AgentRegistry"
Cohesion: 0.12
Nodes (13): AgentRegistry, build_default_registry(), Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint., The agents available in this milestone. Phase 4 adds the network, endpoint,…, build_services(), Compose the object graph. Pure wiring, no I/O., Plan (+5 more)

### Community 103 - "TaskRun"
Cohesion: 0.31
Nodes (8): get_investigation_progress(), list_tasks(), Compute real-time progress metrics for the investigation., List all scheduled and executed tasks in the investigation plan., One scheduled or executed unit of work in an investigation plan., TaskRun, TaskStatus, test_task_run_lifecycle()

### Community 104 - "Severity"
Cohesion: 0.10
Nodes (38): _path(), Any, Triage agent. Extracts investigation entities, classifies the submission,…, Perform structured model-driven triage analysis with fallback to heuristics., Deterministic rule-based triage used when model router is unavailable., Classifies the submission, extracts entities, assesses indicators, and plans…, _read_artifact_snippet(), EvidenceGap (+30 more)

### Community 105 - "Settings"
Cohesion: 0.14
Nodes (22): ArgumentParser, BaseSettings, bootstrap(), Prepare storage and seed development data., _backup(), build_parser(), _capabilities(), _create_user() (+14 more)

### Community 106 - "OrchestratorAgent"
Cohesion: 0.19
Nodes (14): _load_artifacts(), _load_investigation(), OrchestratorAgent, AsyncSession, UUID, First functional Orchestrator Agent. Coordinates the investigation lifecycle:…, Retrieve the in-memory state of an active or recent investigation., Run the full investigation lifecycle. Never raises for task-level failures. (+6 more)

### Community 107 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 108 - "models.py"
Cohesion: 0.08
Nodes (28): DeclarativeBase, Mapped, Evidence graph traversal engine. Confined to this module per docs/evidence-…, Base, Base class for all ORM models., Entity, EntityEdge, Finding (+20 more)

### Community 109 - "ValidationError"
Cohesion: 0.27
Nodes (10): PinnedIPTransport, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Async HTTP transport establishing socket connection directly to a pinned IP., Fetch remote URL safely, validating every hop and streaming the body., Result of an SSRF-safe HTTP request., SafeFetchResult, validate_url_ssrf_safe() (+2 more)

### Community 110 - ".run"
Cohesion: 0.29
Nodes (7): Any, BaseModel, Path, Reject any artifact path outside the configured storage root., Keep the audit record useful without copying bulk input into it., Validate, execute and audit a single tool call., _redact_args()

### Community 111 - "env.py"
Cohesion: 0.31
Nodes (8): do_run_migrations(), Connection, Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_offline(), run_migrations_online()

### Community 112 - "test_pcap_parser_extracts_flows_and_dns"
Cohesion: 0.43
Nodes (6): _build_test_pcap(), asyncio, Path, Build a deterministic, valid in-memory libpcap byte sequence., test_pcap_parser_degrades_gracefully_on_corrupt_input(), test_pcap_parser_extracts_flows_and_dns()

### Community 113 - "authz.py"
Cohesion: 0.47
Nodes (5): has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``., require_role(), AuthorizationError

### Community 114 - "AgentRun"
Cohesion: 0.10
Nodes (33): AgentRun, One execution of one agent. Part of the investigation execution trace., One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun, build_default_registry(), The tools available in the platform. Provides deterministic adapters for…, AsyncSession, datetime (+25 more)

### Community 115 - "llm/contracts.py"
Cohesion: 0.13
Nodes (22): MonkeyPatch, ChatMessage, LLMRequest, LLMUsage, Any, Contracts and data models for model-provider abstraction. Defines the message…, A single conversation turn., Request payload sent to an LLM provider. (+14 more)

### Community 116 - "test_artifact_ingestion_api.py"
Cohesion: 0.53
Nodes (5): AsyncClient, test_ingest_text_artifact_endpoint(), test_ingest_url_artifact_blocks_ssrf(), test_upload_pcap_artifact_success(), test_upload_pcap_mismatch_rejected()

### Community 117 - "_PinnedIPNetworkBackend"
Cohesion: 0.22
Nodes (6): AsyncNetworkStream, AutoBackend, SOCKET_OPTION, _PinnedIPNetworkBackend, Any, Network backend pinning TCP socket connections to a pre-validated IP address.

### Community 118 - "test_types.py"
Cohesion: 0.33
Nodes (5): test_assertion_class_values(), test_investigation_status_terminal(), test_role_values(), test_severity_ordering(), test_time_confidence_values()

### Community 119 - "test_auth.py"
Cohesion: 0.60
Nodes (4): AsyncClient, test_auth_login_invalid_password(), test_auth_login_success(), test_auth_me_endpoint()

### Community 120 - "_build_chain"
Cohesion: 0.15
Nodes (18): _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker., The defect this file exists for: SET NULL used to unground every citing FACT., Evidence must stay traceable to the bytes it came from. (+10 more)

### Community 121 - "audit.py"
Cohesion: 0.50
Nodes (3): Audit trail writes. Security-relevant actions are recorded in an append-only…, AuditLog, Append-only record of security-relevant actions (spec s13).

### Community 122 - "test_evidence_graph_and_timeline_pipeline"
Cohesion: 0.67
Nodes (3): AsyncClient, asyncio, test_evidence_graph_and_timeline_pipeline()

### Community 123 - "test_auth_log_incident_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_auth_log_incident_scenario(), test_clean_log_scenario()

### Community 124 - "test_clean_web_log_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_clean_web_log_scenario(), test_web_log_attack_scenario()

### Community 125 - "test_store_bytes_successful_intake"
Cohesion: 0.67
Nodes (4): asyncio, Path, test_store_bytes_enforces_size_limit(), test_store_bytes_successful_intake()

### Community 126 - "test_upload_security.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_upload_empty_file_rejected(), test_upload_path_traversal_sanitized()

### Community 128 - "_chunks"
Cohesion: 0.67
Nodes (3): _chunks(), Stream an upload without buffering it whole., UploadFile

### Community 129 - "log_context"
Cohesion: 0.67
Nodes (3): log_context(), Any, Temporarily bind values to the logging context.

## Knowledge Gaps
- **61 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+56 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **31 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Severity` to `Evidence`, `EvidenceDraft`, `test_grounding.py`, `investigations.py`, `evaluate_auth_rules`, `Artifact`, `models.py`, `evaluate_web_rules`, `AgentContext`, `test_clean_web_log_scenario`, `AgentRun`, `llm/contracts.py`, `test_types.py`, `_build_chain`, `EvidenceStore`, `test_auth_log_incident_scenario`, `types.py`, `CyberReasoningProvider`?**
  _High betweenness centrality (0.051) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `InvestigationRunner`, `backup.py`, `ModelRouter`, `conftest.py`, `get_session`, `orchestration/orchestrator.py`, `EvidenceDraft`, `app.py`, `migrate.py`, `Artifact`, `test_grounding.py`, `ToolRegistry`, `deps.py`, `EvidenceStore`, `types.py`, `.session`, `Investigation`, `AgentRegistry`, `TaskRun`, `Severity`, `Settings`, `OrchestratorAgent`, `models.py`, `AgentRun`, `_build_chain`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **Why does `Role` connect `Role` to `test_investigation_crud_and_lifecycle`, `investigations.py`, `ACIPError`, `conftest.py`, `EvidenceDraft`, `ValueError`, `app.py`, `auth.py`, `get_not_implemented`, `deps.py`, `types.py`, `Settings`, `test_investigation_lifecycle.py`, `models.py`, `authz.py`, `test_artifact_ingestion_api.py`, `test_types.py`, `test_auth.py`, `test_evidence_graph_and_timeline_pipeline`, `test_auth_log_incident_scenario`, `test_clean_web_log_scenario`, `test_upload_security.py`?**
  _High betweenness centrality (0.041) - this node is a cross-community bridge._
- **Are the 59 inferred relationships involving `Database` (e.g. with `build_services()` and `Services`) actually correct?**
  _`Database` has 59 INFERRED edges - model-reasoned connections that need verification._
- **Are the 52 inferred relationships involving `Severity` (e.g. with `CorrelationAgent` and `LogAnalysisAgent`) actually correct?**
  _`Severity` has 52 INFERRED edges - model-reasoned connections that need verification._
- **Are the 50 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 50 INFERRED edges - model-reasoned connections that need verification._
- **Are the 45 inferred relationships involving `EvidenceStore` (e.g. with `AgentContext` and `list_evidence()`) actually correct?**
  _`EvidenceStore` has 45 INFERRED edges - model-reasoned connections that need verification._