# Graph Report - AACIP  (2026-10-29)

## Corpus Check
- 209 files · ~129,541 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1942 nodes · 5920 edges · 150 communities (114 shown, 36 thin omitted)
- Extraction: 76% EXTRACTED · 24% INFERRED · 0% AMBIGUOUS · INFERRED: 1394 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `34880e82`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- log_context
- models.py
- Evidence
- TimeConfidence
- InvestigationRunner
- _forbid_bulk_dml
- investigations.py
- evaluate_auth_rules
- auth_log_parser.py
- ValueError
- .run
- RunStatus
- test_ssrf.py
- ModelRouter
- AgentContext
- test_files.py
- Grounding Invariants G0-G4
- tokens.py
- BenchmarkRunner
- backup.py
- InvestigationStatus
- CLAUDE.md
- unit/test_orchestrator_agent.py
- get_not_implemented
- agentrouter
- ValidationError
- Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms
- GroundingError
- evaluate_web_rules
- web_log_parser.py
- app.js
- ACIP: Comprehensive End-to-End User Manual & Learning Guide
- Three-Transaction Orchestrator
- test_migrations.py
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- threat_intel.py
- ArtifactKind
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
- Severity
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
- conftest.py
- _get_python_files
- .opencode/opencode.json
- ACIP Empirical Evaluation Results
- Database
- router.py
- acip/errors.py
- graphify.js
- test_health.py
- ioc_extractor.py
- AGENTS.md
- ProviderAvailability
- summarize_investigation
- EvidenceKind
- Investigation
- triage.py
- _PinnedIPNetworkBackend
- pcap_parser.py
- CorrelationAgent
- passwords.py
- AsyncSession
- LLMResponse
- detection/mitre.py
- AgentRegistry
- types.py
- TriageAgent
- cli.py
- OrchestratorAgent
- test_investigation_lifecycle.py
- env.py
- datasets/__init__.py
- experiments/__init__.py
- auth.py
- metrics/__init__.py
- demo.py
- Artifact
- ChatMessage
- _sqlite_pragmas
- TimelineEvent
- app.py
- .__init__
- _build_chain
- results/__init__.py
- EvidenceStore
- ToolRegistry
- Role
- test_investigations.py
- HypothesisDraft
- runners/__init__.py
- deps.py
- ModelExecution
- Settings
- test_types.py
- test_auth.py
- ratelimit.py
- test_evidence_graph_and_timeline_pipeline
- test_clean_web_log_scenario
- reproduce.sh script
- ACIPError
- upload_artifact
- build_default_router
- test_artifact_ingestion_api.py
- ToolError
- test_auth_log_incident_scenario
- test_upload_security.py
- test_invariant_g3_empty_refutation_condition_rejected
- stream_investigation_events
- authorized_purge

## God Nodes (most connected - your core abstractions)
1. `Severity` - 99 edges
2. `Database` - 95 edges
3. `Investigation` - 89 edges
4. `Settings` - 79 edges
5. `AgentContext` - 73 edges
6. `EvidenceStore` - 72 edges
7. `Evidence` - 61 edges
8. `Artifact` - 56 edges
9. `AssertionClass` - 54 edges
10. `EvidenceKind` - 54 edges

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

## Communities (150 total, 36 thin omitted)

### Community 0 - "log_context"
Cohesion: 0.15
Nodes (11): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, log_context(), Any, Temporarily bind values to the logging context. (+3 more)

### Community 1 - "models.py"
Cohesion: 0.09
Nodes (26): Logger, Mapped, Structured output schemas for the Triage Agent., Application bootstrap. Migrates the schema to head and, outside production,…, Application configuration. All configuration arrives from the environment (or a…, Audit trail writes. Security-relevant actions are recorded in an append-only…, Investigation orchestration and Orchestrator Agent. Executes a dynamic or…, Background execution of investigations. M1 runs investigations as asyncio tasks… (+18 more)

### Community 2 - "Evidence"
Cohesion: 0.15
Nodes (12): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, Evidence, Finding, An immutable observation with full provenance. ``tool_run_id`` being non-NULL… (+4 more)

### Community 3 - "TimeConfidence"
Cohesion: 0.20
Nodes (12): Match, AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime, Parsing options. Note the absence of any path argument., Parses Linux authentication logs into normalised auth events. (+4 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.14
Nodes (11): Orchestrator, InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle., Cancel an in-flight investigation task. (+3 more)

### Community 5 - "_forbid_bulk_dml"
Cohesion: 0.67
Nodes (3): ORMExecuteState, _forbid_bulk_dml(), Reject bulk UPDATE/DELETE against an append-only table.

### Community 6 - "investigations.py"
Cohesion: 0.09
Nodes (50): get_investigation_detail(), Investigation lifecycle endpoints., Everything a workspace view needs, in one round trip., AdminCapabilitiesResponse, AgentRunResponse, ArtifactResponse, AuditLogResponse, EntityEdgeResponse (+42 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.17
Nodes (21): AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after(), Deterministic detection rules. These are pure functions over normalised events:… (+13 more)

### Community 8 - "auth_log_parser.py"
Cohesion: 0.13
Nodes (15): Linux authentication log parser. A deterministic, dependency-free parser for…, NoArgs, ABC, BaseModel, Tool adapter contract. A tool is the only thing in the platform allowed to…, Honest report of whether a tool can actually run right now. Surfaced through…, For adapters that take no options., Base class for all tool adapters. (+7 more)

### Community 9 - "ValueError"
Cohesion: 0.09
Nodes (16): Dialect, field_validator, model_validator, field_validator, datetime, field_validator, datetime, Declarative base and portable column types. The schema deliberately avoids… (+8 more)

### Community 10 - ".run"
Cohesion: 0.17
Nodes (11): Any, BaseModel, datetime, Path, UUID, Reject any artifact path outside the configured storage root., Keep the audit record useful without copying bulk input into it., Outcome of one audited tool call. (+3 more)

### Community 11 - "RunStatus"
Cohesion: 0.13
Nodes (25): Implementation of benchmark comparison conditions and ablations. Conditions: -…, Agent, AgentResult, ABC, Any, BaseModel, Agent contract. Agents receive a typed context and return a typed result (spec…, Structured outcome of one agent execution. (+17 more)

### Community 12 - "test_ssrf.py"
Cohesion: 0.10
Nodes (32): patch, is_ip_forbidden(), PinnedIPTransport, IPv4Address, IPv6Address, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Async HTTP transport establishing socket connection directly to a pinned IP. (+24 more)

### Community 13 - "ModelRouter"
Cohesion: 0.13
Nodes (33): CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains., Retrieve the routing rule and candidate list for a given task class., Create standard routing policy with Llama 3.2 11B and GPT-OSS 20B candidates., RoutingPolicy (+25 more)

### Community 14 - "AgentContext"
Cohesion: 0.12
Nodes (24): AuthDetectionHit, execute_condition(), Execute a single scenario under a specified condition or ablation., AgentContext, Everything an agent is given for one execution., LogAnalysisAgent, Any, Project stored auth evidence into the rule engine's view type. (+16 more)

### Community 15 - "test_files.py"
Cohesion: 0.31
Nodes (8): Reduce a client-supplied filename to a safe display label. The result is used…, sanitize_filename(), Path, test_read_text_utf8_and_latin1(), test_sanitize_filename(), test_store_stream_empty_rejected(), test_store_stream_oversized_rejected(), test_store_stream_success()

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "tokens.py"
Cohesion: 0.19
Nodes (15): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, JWT access tokens. Short-lived bearer tokens signed with HS256. Refresh tokens…, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`. (+7 more)

### Community 18 - "BenchmarkRunner"
Cohesion: 0.06
Nodes (45): GroundTruthFinding, GroundTruthScenario, Ground truth schemas for evaluation., A ground-truth malicious event or attack step to be detected., A benchmark scenario with raw artifacts and ground truth labels., Benchmark evaluation scenarios with authentic telemetry and ground truth., MetricCalculator, Any (+37 more)

### Community 19 - "backup.py"
Cohesion: 0.23
Nodes (21): BackupIntegrityError, create_backup(), Path, Portable SQLite backup and restore with artifact-integrity verification. The…, A backup is incomplete or its artifact bytes do not match the database., Create and verify a consistent SQLite/artifact snapshot at ``destination``.…, Verify and restore ``source`` into empty configured SQLite/artifact paths.…, Raise when a backup lacks required source bytes or has a digest mismatch. (+13 more)

### Community 20 - "InvestigationStatus"
Cohesion: 0.10
Nodes (41): Admin, Investigator, get_services(), get_session(), get_settings_dep(), Depends, Request, Everything built once at startup. (+33 more)

### Community 22 - "unit/test_orchestrator_agent.py"
Cohesion: 0.14
Nodes (13): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, _derive_status(), Outcome of an individual task execution., Terminal status from task outcomes. Ordering matters: a halt or a failure must…, TaskOutcome, Path, Unit tests for the Orchestrator Agent., OrchestratorAgent falls back to deterministic rules if triage fails or is… (+5 more)

### Community 23 - "get_not_implemented"
Cohesion: 0.20
Nodes (10): CaptureFixture, get_not_implemented(), Any, Declared limitations of this deployment. A single source for what the platform…, Return declared capability limitations reflecting the active runtime…, AsyncClient, test_admin_capabilities_access_control(), test_capabilities_limitations_reflects_active_llm_flag() (+2 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "ValidationError"
Cohesion: 0.10
Nodes (28): ColumnElement, _evidence_after(), Match rows strictly after the cursor, in the evidence sort order., decode_cursor(), encode_cursor(), Any, Opaque cursors for stable keyset pagination. api.md s5 requires "a bounded…, Encode a sort-key tuple as an opaque cursor. (+20 more)

### Community 26 - "Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms"
Cohesion: 0.08
Nodes (23): 1. Evidence Graph Engine, 2. Competing Hypotheses & Adversarial Validation, A. Maximum Bipartite Cardinality Matching, Abstract, Analysis of Research Questions, Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms, B. Benchmark Scenarios, C. Experimental Conditions (+15 more)

### Community 27 - "GroundingError"
Cohesion: 0.10
Nodes (14): Collection, _evidence_cursor(), EvidencePage, AsyncSession, UUID, Persist drafts, skipping observations already recorded. Deduplication is by…, Validate a claim against the grounding invariants and persist it., Fetch cited evidence, enforcing G0. (+6 more)

### Community 28 - "evaluate_web_rules"
Cohesion: 0.20
Nodes (19): DetectionHit, evaluate_web_rules(), _find_error_bursts(), UUID, Deterministic detection rules for web access logs. Pure functions over…, A parsed web access event, decoupled from the ORM., Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS., Group 4xx/5xx error responses into bursts per IP. (+11 more)

### Community 29 - "web_log_parser.py"
Cohesion: 0.12
Nodes (25): _build_evidence_draft(), _detect_attacks(), _parse_request(), _parse_timestamp(), BaseModel, datetime, Deterministic web server access log parser and attack detection adapter. Parses…, Execution options for web server access log parsing. (+17 more)

### Community 30 - "app.js"
Cohesion: 0.37
Nodes (14): api(), checkCurrentUser(), closeEventStream(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderSvgGraph(), renderWorkspace() (+6 more)

### Community 31 - "ACIP: Comprehensive End-to-End User Manual & Learning Guide"
Cohesion: 0.07
Nodes (27): Sample Investigations, Seed and evaluate, 1. What is ACIP? (In Plain English), 2. Quickstart: Launching the System in 60 Seconds, 3. Step-by-Step Walkthrough: Running Your First Investigation, 4. Visual UI Guide: What Every Element Does, 5. What is the "About & Limitations" Button?, 6. Command Line Interface (CLI) Guide (+19 more)

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "test_migrations.py"
Cohesion: 0.18
Nodes (13): Config, alembic_config(), Connection, Build an Alembic config without reading ``alembic.ini``. The ini file carries a…, _upgrade(), _current_revision(), Connection, The migration chain is the schema, so the suite runs on it. Every fixture… (+5 more)

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
Cohesion: 0.27
Nodes (13): Everything an adapter is permitted to know about its invocation., ToolContext, BaseModel, Local deterministic threat-intelligence evaluation adapter. The bundled entries…, Options for threat intelligence reputation lookup., Local evaluation-feed lookup; no external reputation service is queried., ThreatIntelArgs, ThreatIntelTool (+5 more)

### Community 41 - "ArtifactKind"
Cohesion: 0.16
Nodes (24): detect_artifact_kind(), detect_magic_bytes(), Path, Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Classify an artifact based on header magic bytes, filename, and declared kind.…, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Convenience helper to store an in-memory byte buffer into quarantine storage., Remove group/other access and any execute bit where the OS supports it. (+16 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - "Severity"
Cohesion: 0.14
Nodes (27): assess(), assess_with_model_opinion(), Protocol, Hybrid 50/50 risk scoring: blending AI decisions and deterministic mechanisms.…, Assess risk blending 50% AI decision and 50% deterministic mechanism., Structural type covering both ORM findings and drafts., Compute risk score and categorical severity. When an AI decision is provided or…, RiskAssessment (+19 more)

### Community 68 - "conftest.py"
Cohesion: 0.26
Nodes (14): app(), auth_headers(), client(), database(), Any, AsyncClient, FastAPI, fixture (+6 more)

### Community 72 - "_get_python_files"
Cohesion: 0.44
Nodes (8): _get_python_files(), Path, The schema has one source of truth: the Alembic chain. ``create_all`` was the…, A reserved key in ``extra`` raises KeyError only when the record is emitted.…, test_no_direct_llm_sdk_imports_in_agents(), test_no_metadata_create_all_in_src(), test_no_reserved_logrecord_keys_in_log_extra(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 75 - "Database"
Cohesion: 0.09
Nodes (33): async_sessionmaker, AsyncEngine, Database, AsyncSession, Yield a session, committing on success and rolling back on error., Owns the engine and session factory for one database URL., The guard must bound its own blast radius: reads stay unaffected., One named escape hatch, so deliberate destruction is greppable. (+25 more)

### Community 76 - "router.py"
Cohesion: 0.12
Nodes (35): MessageRole, StrEnum, Role of a message sender in a chat conversation., BudgetExceededError, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderQuotaExceeded (+27 more)

### Community 77 - "acip/errors.py"
Cohesion: 0.20
Nodes (14): Typed application errors. Each error carries an HTTP status and a stable…, ToolExecutionError, Path, Tier 1 tool execution sandbox. Executes external tools as isolated subprocesses…, Execute a command in Tier 1 subprocess isolation. Guarantees: - Never uses…, run_subprocess_sandboxed(), SandboxResult, asyncio (+6 more)

### Community 80 - "test_health.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_capabilities(), test_health()

### Community 81 - "ioc_extractor.py"
Cohesion: 0.12
Nodes (21): Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, read_text(), _context(), IOCExtractor, IOCExtractorArgs, _ip_scope(), Any, BaseModel (+13 more)

### Community 83 - "ProviderAvailability"
Cohesion: 0.14
Nodes (9): ProviderAvailability, Health and model discovery status for an LLM provider., LLMProvider, Protocol, LLMProvider protocol definition., Abstract protocol for all LLM backend adapters., Send a completion request to the provider for a specific model., Probe provider connectivity, authentication, and available models. (+1 more)

### Community 90 - "summarize_investigation"
Cohesion: 0.22
Nodes (9): create_task(), CurrentUser, Manually append a task to the investigation., Generate an executive plain-English layman summary using NVIDIA Nemotron 3…, summarize_investigation(), Any, AsyncSession, Append one audit row. ``actor`` is a username or ``"system"``; never a raw… (+1 more)

### Community 91 - "EvidenceKind"
Cohesion: 0.14
Nodes (23): EntityRef, EvidenceDraft, normalize_entity_value(), BaseModel, Stable digest of the observation, used to deduplicate evidence. Covers only…, Canonicalise an entity value so the same thing has one representation. Entity…, A typed reference to a real-world entity observed in evidence., An observation produced by a tool, before persistence. ``observed_at`` is when… (+15 more)

### Community 92 - "Investigation"
Cohesion: 0.16
Nodes (20): Investigation, TargetType, asyncio, Path, When StaticPlanner is configured, OrchestratorAgent executes its plan verbatim., OrchestratorAgent receives an investigation, calls Triage, interprets result,…, test_orchestrator_agent_end_to_end_lifecycle(), test_orchestrator_agent_respects_static_planner_verbatim() (+12 more)

### Community 93 - "triage.py"
Cohesion: 0.13
Nodes (21): _extract_host_from_url(), _is_ip_address(), Triage agent. Extracts investigation entities, classifies the submission,…, Safely extract the domain or IP hostname from a URL candidate., Check if string is a valid IPv4 or IPv6 address., decompose_url_target(), DetectionHit, evaluate_url_rules() (+13 more)

### Community 94 - "_PinnedIPNetworkBackend"
Cohesion: 0.22
Nodes (6): AsyncNetworkStream, AutoBackend, SOCKET_OPTION, _PinnedIPNetworkBackend, Any, Network backend pinning TCP socket connections to a pre-validated IP address.

### Community 95 - "pcap_parser.py"
Cohesion: 0.16
Nodes (17): What an adapter returns., ToolResult, _parse_dns_qname(), PcapParser, PcapParserArgs, BaseModel, Deterministic PCAP and packet capture parser adapter. Parses libpcap packet…, Parse basic PCAPNG blocks. (+9 more)

### Community 96 - "CorrelationAgent"
Cohesion: 0.09
Nodes (29): CorrelationAgent, Any, Extract all typed EntityRef instances from an evidence row., Derive directed, typed relationship edges backed by this evidence row., Deterministic evidence graph correlation and entity resolution agent., GraphSubgraph, GraphTraversal, AsyncSession (+21 more)

### Community 97 - "passwords.py"
Cohesion: 0.21
Nodes (12): Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), hash_password(), needs_rehash(), Password hashing. Argon2id via ``argon2-cffi``, which is the current OWASP…, Return whether the password matches. Never raises on a bad password., True when the hash was produced with weaker parameters than current., verify_password() (+4 more)

### Community 98 - "AsyncSession"
Cohesion: 0.12
Nodes (41): alias, delete, description, ge, le, LoadedInvestigation, MAX_EVIDENCE_PAGE, Query (+33 more)

### Community 99 - "LLMResponse"
Cohesion: 0.27
Nodes (8): LLMResponse, Standardized response received from an LLM provider., AsyncSession, UUID, Execute a completion for a TaskClass with optional structured schema…, Execute a candidate model, handling structured output repair retries., Persist execution telemetry to llm_calls (ModelExecution)., T

### Community 101 - "detection/mitre.py"
Cohesion: 0.26
Nodes (10): AttackTechnique, get_attack_technique(), map_rule_to_technique(), MITRE ATT&CK catalog and mapping validation. Enforces Invariant G7: no finding…, Lookup a technique in the catalog. Enforces Invariant G7: raises GroundingError…, Deterministically map a detection rule to its ATT&CK technique., test_mitre_catalog_version_and_contents(), test_mitre_deterministic_rule_mapping() (+2 more)

### Community 102 - "AgentRegistry"
Cohesion: 0.10
Nodes (21): AgentRegistry, build_default_registry(), Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint., The agents available in this milestone. The registry contains the agents…, AdaptivePlanner, Adaptive Investigation Planner. Phase 7 implementation of the Planner protocol.…, Dynamic, evidence-driven planner implementing the Planner protocol. (+13 more)

### Community 103 - "types.py"
Cohesion: 0.26
Nodes (7): HypothesisGapDraft, Evidence and finding contracts. Agents and tools exchange these Pydantic models…, A declared gap in evidence preventing resolution of a hypothesis., Append-only evidence store and grounding enforcement. This module is where the…, Tool registry. Agents resolve tools by name through the registry rather than…, Audited tool invocation. Every tool call passes through :class:`ToolRunner`,…, Shared enumerations. These are the vocabulary of the platform. They are stored…

### Community 104 - "TriageAgent"
Cohesion: 0.13
Nodes (31): _path(), Any, Perform structured model-driven triage analysis with fallback to heuristics., Deterministic rule-based triage used when model router is unavailable., Classifies the submission, extracts entities, assesses indicators, and plans…, _read_artifact_snippet(), EvidenceGap, ExtractedEntity (+23 more)

### Community 105 - "cli.py"
Cohesion: 0.16
Nodes (22): ArgumentParser, bootstrap(), Prepare storage and seed development data., _backup(), _benchmark(), build_parser(), _capabilities(), _create_user() (+14 more)

### Community 106 - "OrchestratorAgent"
Cohesion: 0.14
Nodes (17): InvestigationState, _load_artifacts(), _load_investigation(), OrchestratorAgent, AsyncSession, UUID, First functional Orchestrator Agent. Coordinates the investigation lifecycle:…, Retrieve the in-memory state of an active or recent investigation. (+9 more)

### Community 107 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 108 - "env.py"
Cohesion: 0.43
Nodes (6): do_run_migrations(), Connection, In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_online()

### Community 111 - "auth.py"
Cohesion: 0.21
Nodes (12): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+4 more)

### Community 113 - "demo.py"
Cohesion: 0.12
Nodes (18): build_services(), Compose the object graph. Pure wiring, no I/O., build_demo_pcap(), demo_investigations_by_type(), DemoArtifact, DemoInvestigation, Synthetic investigations used by the local demo-data seed command. The values…, An artifact to attach to a synthetic investigation. (+10 more)

### Community 114 - "Artifact"
Cohesion: 0.18
Nodes (9): Any, UUID, Create investigation row and store raw scenario artifacts., setup_scenario_investigation(), Planner, Protocol, Chooses which agents run, in what order, and why., Artifact (+1 more)

### Community 115 - "ChatMessage"
Cohesion: 0.11
Nodes (22): ChatMessage, LLMRequest, LLMUsage, Any, Contracts and data models for model-provider abstraction. Defines the message…, A single conversation turn., Request payload sent to an LLM provider., Token accounting telemetry returned by a provider. (+14 more)

### Community 116 - "_sqlite_pragmas"
Cohesion: 0.67
Nodes (3): Any, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., _sqlite_pragmas()

### Community 117 - "TimelineEvent"
Cohesion: 0.29
Nodes (4): Any, Construct a chronologically ordered event timeline over stored evidence., An ordered timeline observation with provenance., TimelineEvent

### Community 118 - "app.py"
Cohesion: 0.15
Nodes (14): Run migrations in 'offline' mode., run_migrations_offline(), RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of… (+6 more)

### Community 120 - "_build_chain"
Cohesion: 0.17
Nodes (16): _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker., The defect this file exists for: SET NULL used to unground every citing FACT., Evidence must stay traceable to the bytes it came from. (+8 more)

### Community 122 - "EvidenceStore"
Cohesion: 0.06
Nodes (55): DeclarativeBase, EvidenceStore, Writes evidence and findings for a single investigation., Validate a hypothesis and persist it with supporting/contradicting links., Record an explicit knowledge gap preventing hypothesis resolution., Base, Base class for all ORM models., AgentRun (+47 more)

### Community 123 - "ToolRegistry"
Cohesion: 0.17
Nodes (6): A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry, MockPlanner, Any, test_orchestrator_failure_rollback()

### Community 124 - "Role"
Cohesion: 0.28
Nodes (11): CurrentUser, require_admin(), require_investigator(), has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``., require_role(), User (+3 more)

### Community 125 - "test_investigations.py"
Cohesion: 0.38
Nodes (6): AsyncClient, Verify that all target types can be created with canonicalization and defanging., Verify that validation errors return a descriptive formatted message., test_investigation_creation_all_target_types(), test_investigation_crud_and_lifecycle(), test_investigation_validation_error_formatting()

### Community 126 - "HypothesisDraft"
Cohesion: 0.18
Nodes (10): Any, FindingEvidenceDraft, HypothesisDraft, A citation connecting evidence to a finding with a supporting or contradicting…, A competing candidate explanation under evaluation (Invariant G3)., test_finding_evidence_draft_roles(), test_hypothesis_draft_invariant_g3_refutation_required(), test_hypothesis_draft_valid() (+2 more)

### Community 129 - "deps.py"
Cohesion: 0.22
Nodes (12): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), AsyncSession, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,…, Load an investigation or 404. M1 has no per-investigation ownership: any… (+4 more)

### Community 130 - "ModelExecution"
Cohesion: 0.27
Nodes (9): ModelExecutionDraft, Structured record of an LLM call for experimental tracking., Record an immutable LLM execution trace., ModelExecution, Audited execution trace of model invocations. Provenance foreign keys are…, FinishReason, LLM completion termination reason., test_model_execution_append_only() (+1 more)

### Community 131 - "Settings"
Cohesion: 0.18
Nodes (8): BaseSettings, model_validator, Require a real secret in production; generate an ephemeral one otherwise. A…, Create runtime directories. Called once at startup., Resolved application settings., Settings, A second engine on ``:memory:`` would migrate a different database., test_in_memory_is_refused_rather_than_silently_unmigrated()

### Community 133 - "test_types.py"
Cohesion: 0.33
Nodes (5): test_assertion_class_values(), test_investigation_status_terminal(), test_role_values(), test_severity_ordering(), test_time_confidence_values()

### Community 134 - "test_auth.py"
Cohesion: 0.60
Nodes (4): AsyncClient, test_auth_login_invalid_password(), test_auth_login_success(), test_auth_me_endpoint()

### Community 135 - "ratelimit.py"
Cohesion: 0.15
Nodes (13): Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, Thread-safe sliding window rate limiter., Clear all rate limit history (useful in tests)., FastAPI dependency for rate limiting endpoints by client IP., SlidingWindowRateLimiter, AsyncClient (+5 more)

### Community 136 - "test_evidence_graph_and_timeline_pipeline"
Cohesion: 0.67
Nodes (3): AsyncClient, asyncio, test_evidence_graph_and_timeline_pipeline()

### Community 137 - "test_clean_web_log_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_clean_web_log_scenario(), test_web_log_attack_scenario()

### Community 139 - "ACIPError"
Cohesion: 0.22
Nodes (7): Exception, Check whether the key is within rate limits; increments counter if allowed.…, ACIPError, AgentError, Any, RateLimitExceededError, Base class for all application errors.

### Community 141 - "upload_artifact"
Cohesion: 0.33
Nodes (7): File, Form, _chunks(), Stream an upload without buffering it whole., Accept an artifact into content-addressed quarantine storage with magic byte…, upload_artifact(), UploadFile

### Community 142 - "build_default_router"
Cohesion: 0.33
Nodes (6): build_default_router(), Any, BaseModel, Construct a default ModelRouter from application settings., Generate a clean example JSON structure from a Pydantic model for prompt…, _schema_to_template()

### Community 143 - "test_artifact_ingestion_api.py"
Cohesion: 0.53
Nodes (5): AsyncClient, test_ingest_text_artifact_endpoint(), test_ingest_url_artifact_blocks_ssrf(), test_upload_pcap_artifact_success(), test_upload_pcap_mismatch_rejected()

### Community 144 - "ToolError"
Cohesion: 0.50
Nodes (3): A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError

### Community 145 - "test_auth_log_incident_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_auth_log_incident_scenario(), test_clean_log_scenario()

### Community 146 - "test_upload_security.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_upload_empty_file_rejected(), test_upload_path_traversal_sanitized()

### Community 147 - "test_invariant_g3_empty_refutation_condition_rejected"
Cohesion: 0.50
Nodes (4): asyncio, Path, Invariant G3: A hypothesis without a refutation condition raises GroundingError., test_invariant_g3_empty_refutation_condition_rejected()

### Community 148 - "stream_investigation_events"
Cohesion: 0.67
Nodes (3): Server-Sent Events (SSE) stream for real-time investigation progress., stream_investigation_events(), StreamingResponse

## Knowledge Gaps
- **101 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+96 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **36 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Severity` to `models.py`, `Evidence`, `test_types.py`, `investigations.py`, `evaluate_auth_rules`, `auth_log_parser.py`, `test_clean_web_log_scenario`, `RunStatus`, `ModelRouter`, `AgentContext`, `test_auth_log_incident_scenario`, `BenchmarkRunner`, `evaluate_web_rules`, `Database`, `Investigation`, `triage.py`, `CorrelationAgent`, `types.py`, `TriageAgent`, `demo.py`, `ChatMessage`, `EvidenceStore`?**
  _High betweenness centrality (0.064) - this node is a cross-community bridge._
- **Why does `Settings` connect `Settings` to `deps.py`, `models.py`, `Evidence`, `InvestigationRunner`, `ValueError`, `RunStatus`, `ModelRouter`, `AgentContext`, `BenchmarkRunner`, `backup.py`, `InvestigationStatus`, `unit/test_orchestrator_agent.py`, `get_not_implemented`, `conftest.py`, `Database`, `Investigation`, `passwords.py`, `TriageAgent`, `cli.py`, `OrchestratorAgent`, `test_investigation_lifecycle.py`, `demo.py`, `Artifact`, `app.py`, `EvidenceStore`, `ToolRegistry`?**
  _High betweenness centrality (0.043) - this node is a cross-community bridge._
- **Why does `Role` connect `Role` to `deps.py`, `models.py`, `test_types.py`, `investigations.py`, `test_auth.py`, `auth_log_parser.py`, `test_evidence_graph_and_timeline_pipeline`, `test_clean_web_log_scenario`, `ValueError`, `ratelimit.py`, `test_artifact_ingestion_api.py`, `tokens.py`, `test_auth_log_incident_scenario`, `test_upload_security.py`, `get_not_implemented`, `conftest.py`, `passwords.py`, `types.py`, `cli.py`, `test_investigation_lifecycle.py`, `auth.py`, `test_investigations.py`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Are the 74 inferred relationships involving `Severity` (e.g. with `GroundTruthFinding` and `execute_condition()`) actually correct?**
  _`Severity` has 74 INFERRED edges - model-reasoned connections that need verification._
- **Are the 71 inferred relationships involving `Database` (e.g. with `execute_condition()` and `BenchmarkRunner`) actually correct?**
  _`Database` has 71 INFERRED edges - model-reasoned connections that need verification._
- **Are the 65 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 65 INFERRED edges - model-reasoned connections that need verification._
- **Are the 60 inferred relationships involving `Settings` (e.g. with `execute_condition()` and `setup_scenario_investigation()`) actually correct?**
  _`Settings` has 60 INFERRED edges - model-reasoned connections that need verification._