# Graph Report - AACIP  (2026-10-12)

## Corpus Check
- 196 files · ~112,279 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1779 nodes · 5479 edges · 134 communities (97 shown, 37 thin omitted)
- Extraction: 76% EXTRACTED · 24% INFERRED · 0% AMBIGUOUS · INFERRED: 1289 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a0f93c89`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- _sqlite_pragmas
- GroundingError
- Evidence
- TimeConfidence
- InvestigationRunner
- _forbid_bulk_dml
- investigations.py
- evaluate_auth_rules
- web_log_parser.py
- backup.py
- IOCExtractor
- acip/errors.py
- test_ssrf.py
- ModelRouter
- AgentContext
- conftest.py
- Grounding Invariants G0-G4
- tokens.py
- benchmark_runner.py
- Severity
- InvestigationStatus
- CLAUDE.md
- test_triage_agent_auth_attack_representative_case
- Services
- agentrouter
- store_stream
- test_reasoning_agent_discovers_attack_chains_over_graph
- ValidationError
- log_analysis.py
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
- CorrelationAgent
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
- TriageAgent
- _get_python_files
- .opencode/opencode.json
- ACIP Empirical Evaluation Results
- get_not_implemented
- llm/__init__.py
- run_subprocess_sandboxed
- graphify.js
- test_health.py
- deps.py
- AGENTS.md
- .__init__
- EvidenceKind
- Finding
- types.py
- Database
- _uuid_pk
- EvidenceDraft
- Investigation
- ProviderAvailability
- get_session
- .complete
- passwords.py
- execute_condition
- TaskRun
- triage.py
- Settings
- OrchestratorAgent
- test_investigation_lifecycle.py
- EvidenceStore
- datasets/__init__.py
- experiments/__init__.py
- env.py
- metrics/__init__.py
- Role
- RunStatus
- router.py
- test_artifact_ingestion_api.py
- _PinnedIPNetworkBackend
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
- log_context
- test_investigation_crud_and_lifecycle
- AsyncSession
- _forbid_mutation
- _redact

## God Nodes (most connected - your core abstractions)
1. `Database` - 88 edges
2. `Investigation` - 81 edges
3. `Severity` - 81 edges
4. `Settings` - 72 edges
5. `AgentContext` - 71 edges
6. `EvidenceStore` - 70 edges
7. `Evidence` - 57 edges
8. `FindingDraft` - 50 edges
9. `Artifact` - 50 edges
10. `RunStatus` - 49 edges

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

## Communities (134 total, 37 thin omitted)

### Community 0 - "_sqlite_pragmas"
Cohesion: 0.29
Nodes (5): async_sessionmaker, Any, AsyncSession, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., _sqlite_pragmas()

### Community 1 - "GroundingError"
Cohesion: 0.07
Nodes (25): Collection, AttackTechnique, get_attack_technique(), map_rule_to_technique(), MITRE ATT&CK catalog and mapping validation. Enforces Invariant G7: no finding…, Lookup a technique in the catalog. Enforces Invariant G7: raises GroundingError…, Deterministically map a detection rule to its ATT&CK technique., _evidence_cursor() (+17 more)

### Community 2 - "Evidence"
Cohesion: 0.23
Nodes (7): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, Evidence, An immutable observation with full provenance. ``tool_run_id`` being non-NULL…

### Community 3 - "TimeConfidence"
Cohesion: 0.20
Nodes (12): Match, AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime, Parsing options. Note the absence of any path argument., Parses Linux authentication logs into normalised auth events. (+4 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.11
Nodes (18): Orchestrator, build_services(), Compose the object graph. Pure wiring, no I/O., Rule-based planner: reproducible, and the control condition for the study.…, StaticPlanner, InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup. (+10 more)

### Community 5 - "_forbid_bulk_dml"
Cohesion: 0.67
Nodes (3): ORMExecuteState, _forbid_bulk_dml(), Reject bulk UPDATE/DELETE against an append-only table.

### Community 6 - "investigations.py"
Cohesion: 0.11
Nodes (41): _fetch_hypotheses_detail(), get_evidence_provenance(), list_investigation_hypotheses(), UUID, Investigation lifecycle endpoints., List competing hypotheses, refutation conditions, and gaps., Resolve one observation to the tool, arguments, agent and artifact behind it., AgentRunResponse (+33 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.17
Nodes (21): AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after(), Deterministic detection rules. These are pure functions over normalised events:… (+13 more)

### Community 8 - "web_log_parser.py"
Cohesion: 0.11
Nodes (26): Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, read_text(), _build_evidence_draft(), _detect_attacks(), _parse_request(), _parse_timestamp(), BaseModel, datetime (+18 more)

### Community 9 - "backup.py"
Cohesion: 0.23
Nodes (21): BackupIntegrityError, create_backup(), Path, Portable SQLite backup and restore with artifact-integrity verification. The…, A backup is incomplete or its artifact bytes do not match the database., Create and verify a consistent SQLite/artifact snapshot at ``destination``.…, Verify and restore ``source`` into empty configured SQLite/artifact paths.…, Raise when a backup lacks required source bytes or has a digest mismatch. (+13 more)

### Community 10 - "IOCExtractor"
Cohesion: 0.12
Nodes (18): _context(), IOCExtractor, IOCExtractorArgs, _ip_scope(), Any, BaseModel, IPv4Address, IPv6Address (+10 more)

### Community 11 - "acip/errors.py"
Cohesion: 0.09
Nodes (21): Exception, Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, Thread-safe sliding window rate limiter., Check whether the key is within rate limits; increments counter if allowed.…, Clear all rate limit history (useful in tests)., FastAPI dependency for rate limiting endpoints by client IP. (+13 more)

### Community 12 - "test_ssrf.py"
Cohesion: 0.10
Nodes (30): patch, is_ip_forbidden(), PinnedIPTransport, IPv4Address, IPv6Address, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Async HTTP transport establishing socket connection directly to a pinned IP. (+22 more)

### Community 13 - "ModelRouter"
Cohesion: 0.14
Nodes (31): CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains., Retrieve the routing rule and candidate list for a given task class., Create standard routing policy with Llama 3.2 11B and GPT-OSS 20B candidates., RoutingPolicy (+23 more)

### Community 14 - "AgentContext"
Cohesion: 0.12
Nodes (20): AuthDetectionHit, AgentContext, AgentResult, BaseModel, Everything an agent is given for one execution., Structured outcome of one agent execution., Any, LogAnalysisAgent (+12 more)

### Community 15 - "conftest.py"
Cohesion: 0.29
Nodes (13): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+5 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "tokens.py"
Cohesion: 0.18
Nodes (16): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, JWT access tokens. Short-lived bearer tokens signed with HS256. Refresh tokens…, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`. (+8 more)

### Community 18 - "benchmark_runner.py"
Cohesion: 0.06
Nodes (42): GroundTruthFinding, GroundTruthScenario, Ground truth schemas for evaluation., A ground-truth malicious event or attack step to be detected., A benchmark scenario with raw artifacts and ground truth labels., Benchmark evaluation scenarios with authentic telemetry and ground truth., MetricCalculator, Any (+34 more)

### Community 19 - "Severity"
Cohesion: 0.15
Nodes (17): assess(), assess_with_model_opinion(), Protocol, Deterministic risk scoring. Severity and risk are computed from findings by a…, Assess risk deterministically, attaching an attributed model opinion. The model…, Structural type covering both ORM findings and drafts., Roll findings up into an investigation-level severity and risk score., RiskAssessment (+9 more)

### Community 20 - "InvestigationStatus"
Cohesion: 0.12
Nodes (31): File, Form, Investigator, cancel_investigation(), _chunks(), create_investigation(), ingest_text_artifact(), ingest_url_artifact() (+23 more)

### Community 22 - "test_triage_agent_auth_attack_representative_case"
Cohesion: 0.21
Nodes (16): build_default_registry(), The tools available in the platform. Provides deterministic adapters for…, asyncio, Path, Representative Case 2: Phishing URL target triage., Representative Case 3: Malware Hash target triage., Representative Case 4: Graceful deterministic fallback when router is None., Representative Case 5: Model output schema repair loop in Triage. (+8 more)

### Community 23 - "Services"
Cohesion: 0.14
Nodes (23): Admin, get_services(), get_settings_dep(), Request, Everything built once at startup., Services, admin_capabilities(), capabilities() (+15 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "store_stream"
Cohesion: 0.22
Nodes (13): Path, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Remove group/other access and any execute bit where the OS supports it., Reduce a client-supplied filename to a safe display label. The result is used…, _restrict_permissions(), sanitize_filename(), store_stream(), Path (+5 more)

### Community 26 - "test_reasoning_agent_discovers_attack_chains_over_graph"
Cohesion: 0.22
Nodes (10): EntityEdge, Phase 5 evidence graph edge: verified, evidence-backed relationship., asyncio, Test subgraph extraction for findings and chronological timeline generation., Test cycle-safe BFS neighbor discovery and depth bounding., test_graph_traversal_finding_subgraph_and_timeline(), test_graph_traversal_neighbours_and_cycles(), asyncio (+2 more)

### Community 27 - "ValidationError"
Cohesion: 0.10
Nodes (26): ColumnElement, _evidence_after(), Match rows strictly after the cursor, in the evidence sort order., decode_cursor(), encode_cursor(), Any, Opaque cursors for stable keyset pagination. api.md s5 requires "a bounded…, Encode a sort-key tuple as an opaque cursor. (+18 more)

### Community 28 - "log_analysis.py"
Cohesion: 0.18
Nodes (20): Log analysis agent. Parses authentication logs and web server access logs using…, DetectionHit, evaluate_web_rules(), _find_error_bursts(), UUID, Deterministic detection rules for web access logs. Pure functions over…, A parsed web access event, decoupled from the ORM., Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS. (+12 more)

### Community 29 - "ValueError"
Cohesion: 0.09
Nodes (16): Dialect, parametrize, field_validator, model_validator, field_validator, datetime, field_validator, datetime (+8 more)

### Community 30 - "app.js"
Cohesion: 0.37
Nodes (14): api(), checkCurrentUser(), closeEventStream(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderSvgGraph(), renderWorkspace() (+6 more)

### Community 31 - "app.py"
Cohesion: 0.15
Nodes (15): RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, _serialisable_errors(), bootstrap() (+7 more)

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

### Community 40 - "Artifact"
Cohesion: 0.13
Nodes (22): DeclarativeBase, Base, Base class for all ORM models., AgentRun, Artifact, AuditLog, An uploaded input, stored content-addressed under the quarantine dir., One execution of one agent. Part of the investigation execution trace. (+14 more)

### Community 41 - "auth.py"
Cohesion: 0.21
Nodes (12): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+4 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - "CorrelationAgent"
Cohesion: 0.31
Nodes (6): CorrelationAgent, Any, UUID, Extract all typed EntityRef instances from an evidence row., Derive directed, typed relationship edges backed by this evidence row., Deterministic evidence graph correlation and entity resolution agent.

### Community 68 - "TriageAgent"
Cohesion: 0.36
Nodes (6): _path(), Any, Perform structured model-driven triage analysis with fallback to heuristics., Classifies the submission, extracts entities, assesses indicators, and plans…, _read_artifact_snippet(), TriageAgent

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
Cohesion: 0.13
Nodes (33): MonkeyPatch, LLMRequest, Request payload sent to an LLM provider., BudgetExceededError, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderQuotaExceeded (+25 more)

### Community 77 - "run_subprocess_sandboxed"
Cohesion: 0.24
Nodes (12): ToolExecutionError, Path, Tier 1 tool execution sandbox. Executes external tools as isolated subprocesses…, Execute a command in Tier 1 subprocess isolation. Guarantees: - Never uses…, run_subprocess_sandboxed(), SandboxResult, asyncio, Path (+4 more)

### Community 80 - "test_health.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_capabilities(), test_health()

### Community 81 - "deps.py"
Cohesion: 0.23
Nodes (11): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), AsyncSession, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,…, Load an investigation or 404. M1 has no per-investigation ownership: any… (+3 more)

### Community 90 - "EvidenceKind"
Cohesion: 0.08
Nodes (43): Evidence graph correlation and entity resolution agent. Performs Tier 1…, EntityRef, FindingEvidenceDraft, HypothesisDraft, HypothesisGapDraft, ModelExecutionDraft, normalize_entity_value(), BaseModel (+35 more)

### Community 91 - "Finding"
Cohesion: 0.09
Nodes (19): GraphSubgraph, GraphTraversal, Any, AsyncSession, UUID, Evidence graph traversal engine. Confined to this module per docs/evidence-…, Bounded, cycle-safe traversal engine over relational evidence graphs., Fetch the full evidence graph for this investigation, capped to limit. (+11 more)

### Community 92 - "types.py"
Cohesion: 0.11
Nodes (30): Implementation of benchmark comparison conditions and ablations. Conditions: -…, Logger, Agent contract. Agents receive a typed context and return a typed result (spec…, Hypothesis Generation Agent. Formulates competing candidate explanations for…, MITRE ATT&CK Mapping Agent. Maps deterministic detection findings from triage,…, Reasoning Agent. Performs cross-source attack-chain construction over the…, Agent registry. Agents are looked up by name or capability rather than imported…, Report agent. Renders a deterministic Markdown investigation report from stored… (+22 more)

### Community 93 - "Database"
Cohesion: 0.13
Nodes (29): AsyncEngine, Database, Yield a session, committing on success and rolling back on error., Owns the engine and session factory for one database URL., AsyncSession, The guard must bound its own blast radius: reads stay unaffected., One named escape hatch, so deliberate destruction is greppable., An investigation with evidence, for the bulk-DML cases below. (+21 more)

### Community 94 - "_uuid_pk"
Cohesion: 0.67
Nodes (3): Mapped, UUID, _uuid_pk()

### Community 95 - "EvidenceDraft"
Cohesion: 0.07
Nodes (50): EvidenceDraft, Stable digest of the observation, used to deduplicate evidence. Covers only…, An observation produced by a tool, before persistence. ``observed_at`` is when…, A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError, Linux authentication log parser. A deterministic, dependency-free parser for…, NoArgs (+42 more)

### Community 96 - "Investigation"
Cohesion: 0.14
Nodes (11): Planner, Protocol, Chooses which agents run, in what order, and why., Investigation, A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry, MockPlanner (+3 more)

### Community 97 - "ProviderAvailability"
Cohesion: 0.15
Nodes (8): ProviderAvailability, Health and model discovery status for an LLM provider., LLMProvider, Protocol, Abstract protocol for all LLM backend adapters., Send a completion request to the provider for a specific model., Probe provider connectivity, authentication, and available models., Probe NVIDIA NIM endpoint to verify API key and model availability.

### Community 98 - "get_session"
Cohesion: 0.12
Nodes (35): alias, description, ge, le, LoadedInvestigation, MAX_EVIDENCE_PAGE, Query, get_session() (+27 more)

### Community 99 - ".complete"
Cohesion: 0.19
Nodes (10): Any, AsyncSession, BaseModel, UUID, Execute a completion for a TaskClass with optional structured schema…, Execute a candidate model, handling structured output repair retries., Persist execution telemetry to llm_calls (ModelExecution)., Generate a clean example JSON structure from a Pydantic model for prompt… (+2 more)

### Community 101 - "passwords.py"
Cohesion: 0.26
Nodes (10): hash_password(), needs_rehash(), Password hashing. Argon2id via ``argon2-cffi``, which is the current OWASP…, Return whether the password matches. Never raises on a bad password., True when the hash was produced with weaker parameters than current., verify_password(), test_needs_rehash(), test_password_hash_and_verify() (+2 more)

### Community 102 - "execute_condition"
Cohesion: 0.15
Nodes (17): execute_condition(), Execute a single scenario under a specified condition or ablation., Agent, ABC, Any, Base class for all agents., Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure., HypothesisAgent (+9 more)

### Community 103 - "TaskRun"
Cohesion: 0.27
Nodes (10): create_task(), get_investigation_progress(), Compute real-time progress metrics for the investigation., Manually append a task to the investigation., InvestigationProgress, TaskRunResponse, One scheduled or executed unit of work in an investigation plan., TaskRun (+2 more)

### Community 104 - "triage.py"
Cohesion: 0.12
Nodes (30): Triage agent. Extracts investigation entities, classifies the submission,…, Deterministic rule-based triage used when model router is unavailable., EvidenceGap, ExtractedEntity, IndicatorAssessment, InputClassification, PlannedTaskProposal, BaseModel (+22 more)

### Community 105 - "Settings"
Cohesion: 0.15
Nodes (21): ArgumentParser, BaseSettings, CaptureFixture, _backup(), _benchmark(), build_parser(), _capabilities(), _create_user() (+13 more)

### Community 106 - "OrchestratorAgent"
Cohesion: 0.06
Nodes (38): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, AgentRegistry, Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint., AdaptivePlanner, Adaptive Investigation Planner. Phase 7 implementation of the Planner protocol.…, Dynamic, evidence-driven planner implementing the Planner protocol., Investigation planning and orchestration. (+30 more)

### Community 107 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 108 - "EvidenceStore"
Cohesion: 0.13
Nodes (16): EvidenceStore, Writes evidence and findings for a single investigation., Record an explicit knowledge gap preventing hypothesis resolution., Hypothesis, HypothesisGap, Phase 7 schema scaffolding: competing candidate explanation requiring…, Phase 7 schema scaffolding: declared missing evidence or tool capability., asyncio (+8 more)

### Community 111 - "env.py"
Cohesion: 0.31
Nodes (8): do_run_migrations(), Connection, Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_offline(), run_migrations_online()

### Community 113 - "Role"
Cohesion: 0.24
Nodes (13): CurrentUser, require_admin(), require_investigator(), Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``. (+5 more)

### Community 114 - "RunStatus"
Cohesion: 0.09
Nodes (30): One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun, Any, AsyncSession, BaseModel, datetime, Path, UUID (+22 more)

### Community 115 - "router.py"
Cohesion: 0.13
Nodes (16): ChatMessage, LLMResponse, LLMUsage, MessageRole, Any, StrEnum, Contracts and data models for model-provider abstraction. Defines the message…, Role of a message sender in a chat conversation. (+8 more)

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

### Community 129 - "log_context"
Cohesion: 0.15
Nodes (11): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, log_context(), Any, Temporarily bind values to the logging context. (+3 more)

### Community 131 - "AsyncSession"
Cohesion: 0.19
Nodes (12): delete, _append_only_counts(), delete_investigation(), get_investigation_detail(), AsyncSession, Everything a workspace view needs, in one round trip., Count the records a purge would destroy, before any of them are gone., Delete an investigation; destroying append-only records requires an explicit… (+4 more)

## Knowledge Gaps
- **62 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+57 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **37 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Severity` to `Evidence`, `investigations.py`, `evaluate_auth_rules`, `AgentContext`, `benchmark_runner.py`, `test_triage_agent_auth_attack_representative_case`, `test_reasoning_agent_discovers_attack_chains_over_graph`, `log_analysis.py`, `CorrelationAgent`, `TriageAgent`, `EvidenceKind`, `Finding`, `types.py`, `Database`, `execute_condition`, `triage.py`, `EvidenceStore`, `RunStatus`, `test_types.py`, `_build_chain`, `test_auth_log_incident_scenario`, `test_clean_web_log_scenario`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._
- **Why does `Settings` connect `Settings` to `InvestigationRunner`, `backup.py`, `AgentContext`, `conftest.py`, `benchmark_runner.py`, `test_triage_agent_auth_attack_representative_case`, `Services`, `test_reasoning_agent_discovers_attack_chains_over_graph`, `ValueError`, `app.py`, `migrate.py`, `Artifact`, `get_not_implemented`, `deps.py`, `types.py`, `Investigation`, `execute_condition`, `triage.py`, `OrchestratorAgent`, `test_investigation_lifecycle.py`, `EvidenceStore`, `Role`, `RunStatus`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **Why does `Role` connect `Role` to `test_investigation_crud_and_lifecycle`, `investigations.py`, `acip/errors.py`, `conftest.py`, `tokens.py`, `ValueError`, `app.py`, `auth.py`, `get_not_implemented`, `deps.py`, `EvidenceKind`, `types.py`, `Settings`, `test_investigation_lifecycle.py`, `test_artifact_ingestion_api.py`, `test_types.py`, `test_auth.py`, `test_evidence_graph_and_timeline_pipeline`, `test_auth_log_incident_scenario`, `test_clean_web_log_scenario`, `test_upload_security.py`?**
  _High betweenness centrality (0.039) - this node is a cross-community bridge._
- **Are the 67 inferred relationships involving `Database` (e.g. with `execute_condition()` and `BenchmarkRunner`) actually correct?**
  _`Database` has 67 INFERRED edges - model-reasoned connections that need verification._
- **Are the 59 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 59 INFERRED edges - model-reasoned connections that need verification._
- **Are the 58 inferred relationships involving `Severity` (e.g. with `GroundTruthFinding` and `execute_condition()`) actually correct?**
  _`Severity` has 58 INFERRED edges - model-reasoned connections that need verification._
- **Are the 55 inferred relationships involving `Settings` (e.g. with `execute_condition()` and `setup_scenario_investigation()`) actually correct?**
  _`Settings` has 55 INFERRED edges - model-reasoned connections that need verification._