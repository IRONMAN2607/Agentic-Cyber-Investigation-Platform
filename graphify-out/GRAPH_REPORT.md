# Graph Report - AACIP  (2026-10-12)

## Corpus Check
- 201 files · ~116,026 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1839 nodes · 5552 edges · 132 communities (97 shown, 35 thin omitted)
- Extraction: 77% EXTRACTED · 23% INFERRED · 0% AMBIGUOUS · INFERRED: 1292 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a8254df1`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- RunStatus
- EvidenceStore
- Evidence
- TimeConfidence
- InvestigationStatus
- _forbid_bulk_dml
- investigations.py
- evaluate_auth_rules
- web_log_parser.py
- backup.py
- .extract
- acip/errors.py
- test_ssrf.py
- ModelRouter
- AgentContext
- conftest.py
- Grounding Invariants G0-G4
- tokens.py
- execute_condition
- Severity
- Services
- CLAUDE.md
- .session
- system.py
- agentrouter
- store_stream
- Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms
- test_artifact_validation.py
- evaluate_web_rules
- ToolRegistry
- app.js
- ACIP: Comprehensive End-to-End User Manual & Learning Guide
- Three-Transaction Orchestrator
- Database
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- threat_intel.py
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
- get_session
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
- EvidenceKind
- _get_python_files
- .opencode/opencode.json
- ACIP Empirical Evaluation Results
- get_not_implemented
- router.py
- run_subprocess_sandboxed
- graphify.js
- test_health.py
- passwords.py
- AGENTS.md
- detection/mitre.py
- _evidence_after
- evidence/contracts.py
- types.py
- LoadedInvestigation
- ConfigurationError
- ioc_extractor.py
- TimelineEvent
- ProviderAvailability
- AsyncSession
- LLMResponse
- test_pcap_parser_extracts_flows_and_dns
- Investigation
- triage.py
- Settings
- OrchestratorAgent
- test_investigation_lifecycle.py
- datasets/__init__.py
- experiments/__init__.py
- env.py
- metrics/__init__.py
- Role
- ToolRun
- llm/contracts.py
- test_artifact_ingestion_api.py
- _PinnedIPNetworkBackend
- test_types.py
- test_auth.py
- _build_chain
- results/__init__.py
- test_evidence_graph_and_timeline_pipeline
- test_auth_log_incident_scenario
- test_clean_web_log_scenario
- files.py
- test_upload_security.py
- runners/__init__.py
- app.py
- test_investigation_crud_and_lifecycle
- SlidingWindowRateLimiter
- reproduce.sh script

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

## Communities (132 total, 35 thin omitted)

### Community 0 - "RunStatus"
Cohesion: 0.13
Nodes (29): Agent, AgentResult, ABC, Any, BaseModel, Agent contract. Agents receive a typed context and return a typed result (spec…, Structured outcome of one agent execution., Base class for all agents. (+21 more)

### Community 1 - "EvidenceStore"
Cohesion: 0.06
Nodes (45): Collection, HypothesisDraft, HypothesisGapDraft, ModelExecutionDraft, BaseModel, A competing candidate explanation under evaluation (Invariant G3)., A declared gap in evidence preventing resolution of a hypothesis., Structured record of an LLM call for experimental tracking. (+37 more)

### Community 2 - "Evidence"
Cohesion: 0.16
Nodes (16): DeclarativeBase, _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, Base, Base class for all ORM models. (+8 more)

### Community 3 - "TimeConfidence"
Cohesion: 0.17
Nodes (15): Match, Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, read_text(), AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime (+7 more)

### Community 4 - "InvestigationStatus"
Cohesion: 0.12
Nodes (16): Orchestrator, build_services(), Compose the object graph. Pure wiring, no I/O., InvestigationRunner, UUID, Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle. (+8 more)

### Community 5 - "_forbid_bulk_dml"
Cohesion: 0.67
Nodes (3): ORMExecuteState, _forbid_bulk_dml(), Reject bulk UPDATE/DELETE against an append-only table.

### Community 6 - "investigations.py"
Cohesion: 0.09
Nodes (47): _fetch_hypotheses_detail(), get_evidence_provenance(), get_investigation_detail(), list_investigation_hypotheses(), UUID, Investigation lifecycle endpoints., List competing hypotheses, refutation conditions, and gaps., Everything a workspace view needs, in one round trip. (+39 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.17
Nodes (21): AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after(), Deterministic detection rules. These are pure functions over normalised events:… (+13 more)

### Community 8 - "web_log_parser.py"
Cohesion: 0.12
Nodes (24): _build_evidence_draft(), _detect_attacks(), _parse_request(), _parse_timestamp(), BaseModel, datetime, Deterministic web server access log parser and attack detection adapter. Parses…, Parses Apache, Nginx, and W3C web server access logs into structured events. (+16 more)

### Community 9 - "backup.py"
Cohesion: 0.23
Nodes (21): BackupIntegrityError, create_backup(), Path, Portable SQLite backup and restore with artifact-integrity verification. The…, A backup is incomplete or its artifact bytes do not match the database., Create and verify a consistent SQLite/artifact snapshot at ``destination``.…, Verify and restore ``source`` into empty configured SQLite/artifact paths.…, Raise when a backup lacks required source bytes or has a digest mismatch. (+13 more)

### Community 10 - ".extract"
Cohesion: 0.12
Nodes (16): _context(), IOCExtractorArgs, _ip_scope(), Any, BaseModel, IPv4Address, IPv6Address, Extract indicators from ``text``. Directly testable. (+8 more)

### Community 11 - "acip/errors.py"
Cohesion: 0.14
Nodes (17): Exception, Check whether the key is within rate limits; increments counter if allowed.…, PinnedIPTransport, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Async HTTP transport establishing socket connection directly to a pinned IP., Fetch remote URL safely, validating every hop and streaming the body., Result of an SSRF-safe HTTP request., SafeFetchResult (+9 more)

### Community 12 - "test_ssrf.py"
Cohesion: 0.13
Nodes (23): patch, is_ip_forbidden(), IPv4Address, IPv6Address, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Asynchronous HTTP fetcher with anti-SSRF protection and resource bounding., Check if an IP address falls into a private, loopback, or cloud metadata range., SafeHTTPFetcher (+15 more)

### Community 13 - "ModelRouter"
Cohesion: 0.13
Nodes (35): CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains., Retrieve the routing rule and candidate list for a given task class., Create standard routing policy with Llama 3.2 11B and GPT-OSS 20B candidates., RoutingPolicy (+27 more)

### Community 14 - "AgentContext"
Cohesion: 0.13
Nodes (17): AuthDetectionHit, AgentContext, Everything an agent is given for one execution., Any, LogAnalysisAgent, Any, Project stored auth evidence into the rule engine's view type., Project stored web evidence into the web rule engine's view type. (+9 more)

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
Nodes (51): GroundTruthFinding, GroundTruthScenario, Ground truth schemas for evaluation., A ground-truth malicious event or attack step to be detected., A benchmark scenario with raw artifacts and ground truth labels., Benchmark evaluation scenarios with authentic telemetry and ground truth., MetricCalculator, Any (+43 more)

### Community 19 - "Severity"
Cohesion: 0.10
Nodes (32): assess(), assess_with_model_opinion(), Protocol, Deterministic risk scoring. Severity and risk are computed from findings by a…, Assess risk deterministically, attaching an attributed model opinion. The model…, Structural type covering both ORM findings and drafts., Roll findings up into an investigation-level severity and risk score., RiskAssessment (+24 more)

### Community 20 - "Services"
Cohesion: 0.10
Nodes (40): File, Form, Investigator, get_services(), get_settings_dep(), Request, Everything built once at startup., Services (+32 more)

### Community 22 - ".session"
Cohesion: 0.09
Nodes (28): Mark orphan running investigations as interrupted on startup., FindingEvidence, HypothesisEvidence, Phase 5 schema scaffolding: relational citation mapping evidence to findings.…, Phase 7 schema scaffolding: relational citation linking evidence to a…, Yield a session, committing on success and rolling back on error., EvidenceRole, Relationship between an evidence observation and a finding or hypothesis. (+20 more)

### Community 23 - "system.py"
Cohesion: 0.16
Nodes (18): Admin, admin_capabilities(), capabilities(), health(), AsyncSession, Depends, get, Health and capability endpoints. ``/capabilities`` is a first-class endpoint,… (+10 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "store_stream"
Cohesion: 0.22
Nodes (13): Path, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Remove group/other access and any execute bit where the OS supports it., Reduce a client-supplied filename to a safe display label. The result is used…, _restrict_permissions(), sanitize_filename(), store_stream(), Path (+5 more)

### Community 26 - "Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms"
Cohesion: 0.08
Nodes (23): 1. Evidence Graph Engine, 2. Competing Hypotheses & Adversarial Validation, A. Maximum Bipartite Cardinality Matching, Abstract, Analysis of Research Questions, Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms, B. Benchmark Scenarios, C. Experimental Conditions (+15 more)

### Community 27 - "test_artifact_validation.py"
Cohesion: 0.10
Nodes (28): detect_artifact_kind(), detect_magic_bytes(), Classify an artifact based on header magic bytes, filename, and declared kind.…, Inspect the first bytes of a file to detect its format and MIME type., Input and indicator validation primitives. Provides strict, deterministic…, Validate and canonicalize a target value for investigation creation., Validate and canonicalize an IPv4 or IPv6 address string. Returns the canonical…, Validate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512). Returns the… (+20 more)

### Community 28 - "evaluate_web_rules"
Cohesion: 0.20
Nodes (19): DetectionHit, evaluate_web_rules(), _find_error_bursts(), UUID, Deterministic detection rules for web access logs. Pure functions over…, A parsed web access event, decoupled from the ORM., Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS., Group 4xx/5xx error responses into bursts per IP. (+11 more)

### Community 29 - "ToolRegistry"
Cohesion: 0.07
Nodes (19): Dialect, parametrize, field_validator, model_validator, field_validator, datetime, field_validator, datetime (+11 more)

### Community 30 - "app.js"
Cohesion: 0.37
Nodes (14): api(), checkCurrentUser(), closeEventStream(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderSvgGraph(), renderWorkspace() (+6 more)

### Community 31 - "ACIP: Comprehensive End-to-End User Manual & Learning Guide"
Cohesion: 0.08
Nodes (24): 1. What is ACIP? (In Plain English), 2. Quickstart: Launching the System in 60 Seconds, 3. Step-by-Step Walkthrough: Running Your First Investigation, 4. Visual UI Guide: What Every Element Does, 5. What is the "About & Limitations" Button?, 6. Command Line Interface (CLI) Guide, 7. Plain-English Concept Glossary, 8. Summary: How to Demonstrate ACIP to Others (+16 more)

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "Database"
Cohesion: 0.10
Nodes (19): async_sessionmaker, AsyncEngine, Database, Any, AsyncSession, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., Owns the engine and session factory for one database URL., _sqlite_pragmas() (+11 more)

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

### Community 40 - "threat_intel.py"
Cohesion: 0.19
Nodes (15): A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError, Everything an adapter is permitted to know about its invocation., ToolContext, BaseModel, Tier 3 Threat Intelligence tool adapter. Queries indicator reputation…, Options for threat intelligence reputation lookup. (+7 more)

### Community 41 - "auth.py"
Cohesion: 0.13
Nodes (16): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+8 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - "get_session"
Cohesion: 0.17
Nodes (16): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), get_session(), AsyncSession, Depends, Load an investigation or 404. M1 has no per-investigation ownership: any… (+8 more)

### Community 68 - "EvidenceKind"
Cohesion: 0.22
Nodes (12): EntityRef, EvidenceDraft, Stable digest of the observation, used to deduplicate evidence. Covers only…, A typed reference to a real-world entity observed in evidence., An observation produced by a tool, before persistence. ``observed_at`` is when…, EvidenceKind, StrEnum, test_evidence_immutability() (+4 more)

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

### Community 81 - "passwords.py"
Cohesion: 0.21
Nodes (12): Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), hash_password(), needs_rehash(), Password hashing. Argon2id via ``argon2-cffi``, which is the current OWASP…, Return whether the password matches. Never raises on a bad password., True when the hash was produced with weaker parameters than current., verify_password() (+4 more)

### Community 83 - "detection/mitre.py"
Cohesion: 0.29
Nodes (9): AttackTechnique, get_attack_technique(), map_rule_to_technique(), MITRE ATT&CK catalog and mapping validation. Enforces Invariant G7: no finding…, Lookup a technique in the catalog. Enforces Invariant G7: raises GroundingError…, Deterministically map a detection rule to its ATT&CK technique., test_mitre_catalog_version_and_contents(), test_mitre_deterministic_rule_mapping() (+1 more)

### Community 90 - "_evidence_after"
Cohesion: 0.22
Nodes (9): ColumnElement, _evidence_after(), Match rows strictly after the cursor, in the evidence sort order., decode_cursor(), encode_cursor(), Any, Opaque cursors for stable keyset pagination. api.md s5 requires "a bounded…, Encode a sort-key tuple as an opaque cursor. (+1 more)

### Community 91 - "evidence/contracts.py"
Cohesion: 0.07
Nodes (34): CorrelationAgent, Any, UUID, Evidence graph correlation and entity resolution agent. Performs Tier 1…, Extract all typed EntityRef instances from an evidence row., Derive directed, typed relationship edges backed by this evidence row., Deterministic evidence graph correlation and entity resolution agent., FindingEvidenceDraft (+26 more)

### Community 92 - "types.py"
Cohesion: 0.14
Nodes (19): Implementation of benchmark comparison conditions and ablations. Conditions: -…, Mapped, Application configuration. All configuration arrives from the environment (or a…, Investigation orchestration and Orchestrator Agent. Executes a dynamic or…, Background execution of investigations. M1 runs investigations as asyncio tasks…, _forbid_mutation(), Any, UUID (+11 more)

### Community 93 - "LoadedInvestigation"
Cohesion: 0.19
Nodes (17): LoadedInvestigation, create_task(), get_investigation_progress(), list_tasks(), get, Server-Sent Events (SSE) stream for real-time investigation progress., Compute real-time progress metrics for the investigation., List all scheduled and executed tasks in the investigation plan. (+9 more)

### Community 94 - "ConfigurationError"
Cohesion: 0.22
Nodes (8): Config, model_validator, Require a real secret in production; generate an ephemeral one otherwise. A…, alembic_config(), Connection, Build an Alembic config without reading ``alembic.ini``. The ini file carries a…, _upgrade(), ConfigurationError

### Community 95 - "ioc_extractor.py"
Cohesion: 0.10
Nodes (27): NoArgs, ABC, BaseModel, Tool adapter contract. A tool is the only thing in the platform allowed to…, Honest report of whether a tool can actually run right now. Surfaced through…, What an adapter returns., For adapters that take no options., Base class for all tool adapters. (+19 more)

### Community 96 - "TimelineEvent"
Cohesion: 0.29
Nodes (4): Any, Construct a chronologically ordered event timeline over stored evidence., An ordered timeline observation with provenance., TimelineEvent

### Community 97 - "ProviderAvailability"
Cohesion: 0.33
Nodes (3): ProviderAvailability, Health and model discovery status for an LLM provider., Probe NVIDIA NIM endpoint to verify API key and model availability.

### Community 98 - "AsyncSession"
Cohesion: 0.12
Nodes (31): alias, delete, description, ge, le, MAX_EVIDENCE_PAGE, Query, _append_only_counts() (+23 more)

### Community 99 - "LLMResponse"
Cohesion: 0.12
Nodes (17): LLMResponse, Standardized response received from an LLM provider., LLMProvider, Protocol, Abstract protocol for all LLM backend adapters., Send a completion request to the provider for a specific model., Probe provider connectivity, authentication, and available models., Any (+9 more)

### Community 101 - "test_pcap_parser_extracts_flows_and_dns"
Cohesion: 0.43
Nodes (6): _build_test_pcap(), asyncio, Path, Build a deterministic, valid in-memory libpcap byte sequence., test_pcap_parser_degrades_gracefully_on_corrupt_input(), test_pcap_parser_extracts_flows_and_dns()

### Community 102 - "Investigation"
Cohesion: 0.08
Nodes (40): AgentRegistry, Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint., AdaptivePlanner, Adaptive Investigation Planner. Phase 7 implementation of the Planner protocol.…, Dynamic, evidence-driven planner implementing the Planner protocol., Plan, Planner (+32 more)

### Community 104 - "triage.py"
Cohesion: 0.10
Nodes (42): _path(), Any, Triage agent. Extracts investigation entities, classifies the submission,…, Perform structured model-driven triage analysis with fallback to heuristics., Deterministic rule-based triage used when model router is unavailable., Classifies the submission, extracts entities, assesses indicators, and plans…, _read_artifact_snippet(), EvidenceGap (+34 more)

### Community 105 - "Settings"
Cohesion: 0.13
Nodes (25): ArgumentParser, BaseSettings, bootstrap(), Prepare storage and seed development data., _backup(), _benchmark(), build_parser(), _capabilities() (+17 more)

### Community 106 - "OrchestratorAgent"
Cohesion: 0.10
Nodes (28): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, Investigation planning and orchestration., _derive_status(), InvestigationOutcome, InvestigationState, _load_artifacts(), _load_investigation(), OrchestratorAgent (+20 more)

### Community 107 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 111 - "env.py"
Cohesion: 0.43
Nodes (6): do_run_migrations(), Connection, In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_online()

### Community 113 - "Role"
Cohesion: 0.25
Nodes (13): CurrentUser, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,…, require_admin(), require_investigator(), has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``. (+5 more)

### Community 114 - "ToolRun"
Cohesion: 0.10
Nodes (25): One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun, Any, AsyncSession, BaseModel, datetime, Path, UUID (+17 more)

### Community 115 - "llm/contracts.py"
Cohesion: 0.12
Nodes (23): MonkeyPatch, ChatMessage, LLMRequest, LLMUsage, Any, Contracts and data models for model-provider abstraction. Defines the message…, A single conversation turn., Request payload sent to an LLM provider. (+15 more)

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
Cohesion: 0.17
Nodes (16): _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker., The defect this file exists for: SET NULL used to unground every citing FACT., Evidence must stay traceable to the bytes it came from. (+8 more)

### Community 122 - "test_evidence_graph_and_timeline_pipeline"
Cohesion: 0.67
Nodes (3): AsyncClient, asyncio, test_evidence_graph_and_timeline_pipeline()

### Community 123 - "test_auth_log_incident_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_auth_log_incident_scenario(), test_clean_log_scenario()

### Community 124 - "test_clean_web_log_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_clean_web_log_scenario(), test_web_log_attack_scenario()

### Community 125 - "files.py"
Cohesion: 0.40
Nodes (5): Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Convenience helper to store an in-memory byte buffer into quarantine storage., Result of a successful intake., store_bytes(), StoredArtifact

### Community 126 - "test_upload_security.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_upload_empty_file_rejected(), test_upload_path_traversal_sanitized()

### Community 129 - "app.py"
Cohesion: 0.08
Nodes (28): Logger, LogRecord, Run migrations in 'offline' mode., run_migrations_offline(), RequestValidationError, create_app(), _install_error_handlers(), FastAPI (+20 more)

### Community 135 - "SlidingWindowRateLimiter"
Cohesion: 0.20
Nodes (8): Thread-safe sliding window rate limiter., Clear all rate limit history (useful in tests)., SlidingWindowRateLimiter, AsyncClient, The investigation limiter was defined and wired to nothing. Login was the only…, test_auth_login_rate_limiting(), test_investigation_creation_is_rate_limited(), test_sliding_window_rate_limiter_unit()

## Knowledge Gaps
- **99 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+94 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **35 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Settings` connect `Settings` to `RunStatus`, `app.py`, `Evidence`, `EvidenceStore`, `InvestigationStatus`, `backup.py`, `ModelRouter`, `AgentContext`, `conftest.py`, `execute_condition`, `Severity`, `Services`, `ToolRegistry`, `Database`, `get_not_implemented`, `passwords.py`, `types.py`, `ConfigurationError`, `Investigation`, `triage.py`, `OrchestratorAgent`, `test_investigation_lifecycle.py`, `Role`, `ToolRun`?**
  _High betweenness centrality (0.054) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `app.py`, `Evidence`, `EvidenceStore`, `InvestigationStatus`, `backup.py`, `ModelRouter`, `conftest.py`, `execute_condition`, `Severity`, `Services`, `.session`, `EvidenceKind`, `passwords.py`, `evidence/contracts.py`, `types.py`, `LoadedInvestigation`, `Investigation`, `triage.py`, `Settings`, `OrchestratorAgent`, `Role`, `ToolRun`, `_build_chain`?**
  _High betweenness centrality (0.042) - this node is a cross-community bridge._
- **Why does `Severity` connect `Severity` to `RunStatus`, `EvidenceStore`, `Evidence`, `investigations.py`, `evaluate_auth_rules`, `AgentContext`, `execute_condition`, `Services`, `.session`, `evaluate_web_rules`, `EvidenceKind`, `evidence/contracts.py`, `types.py`, `Investigation`, `triage.py`, `llm/contracts.py`, `test_types.py`, `test_auth_log_incident_scenario`, `test_clean_web_log_scenario`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Are the 68 inferred relationships involving `Database` (e.g. with `execute_condition()` and `BenchmarkRunner`) actually correct?**
  _`Database` has 68 INFERRED edges - model-reasoned connections that need verification._
- **Are the 59 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 59 INFERRED edges - model-reasoned connections that need verification._
- **Are the 58 inferred relationships involving `Severity` (e.g. with `GroundTruthFinding` and `execute_condition()`) actually correct?**
  _`Severity` has 58 INFERRED edges - model-reasoned connections that need verification._
- **Are the 56 inferred relationships involving `Settings` (e.g. with `execute_condition()` and `setup_scenario_investigation()`) actually correct?**
  _`Settings` has 56 INFERRED edges - model-reasoned connections that need verification._