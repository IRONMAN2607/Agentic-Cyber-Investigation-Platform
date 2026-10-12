# Graph Report - AACIP  (2026-10-12)

## Corpus Check
- 202 files · ~118,016 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1854 nodes · 5633 edges · 133 communities (97 shown, 36 thin omitted)
- Extraction: 76% EXTRACTED · 24% INFERRED · 0% AMBIGUOUS · INFERRED: 1327 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `8c557770`
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
- read_text
- acip/errors.py
- ValidationError
- ModelRouter
- AgentContext
- conftest.py
- Grounding Invariants G0-G4
- Role
- BenchmarkRunner
- Severity
- AsyncSession
- CLAUDE.md
- .session
- Services
- agentrouter
- files.py
- Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms
- test_artifact_validation.py
- log_analysis.py
- ValueError
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
- models.py
- _get_python_files
- .opencode/opencode.json
- ACIP Empirical Evaluation Results
- get_not_implemented
- router.py
- run_subprocess_sandboxed
- graphify.js
- test_health.py
- bootstrap.py
- AGENTS.md
- detection/mitre.py
- _evidence_after
- EvidenceKind
- types.py
- GroundTruthFinding
- test_validation_agent_evaluates_refutations_and_bounds_loops
- tools/registry.py
- GraphTraversal
- ProviderAvailability
- get_finding_subgraph
- ModelExecution
- EvidenceDraft
- Artifact
- Investigation
- test_triage_agent_auth_attack_representative_case
- Settings
- orchestration/orchestrator.py
- test_investigation_lifecycle.py
- ToolRun
- datasets/__init__.py
- experiments/__init__.py
- env.py
- metrics/__init__.py
- triage.py
- ToolRunner
- llm/contracts.py
- test_reasoning_agent_discovers_attack_chains_over_graph
- _PinnedIPNetworkBackend
- app.py
- test_orchestrator_agent_with_model_router_triage
- _build_chain
- results/__init__.py
- test_migrations.py
- test_orchestrator.py
- .run
- .run
- .__init__
- runners/__init__.py
- log_context
- SlidingWindowRateLimiter
- reproduce.sh script

## God Nodes (most connected - your core abstractions)
1. `Database` - 90 edges
2. `Investigation` - 85 edges
3. `Severity` - 83 edges
4. `Settings` - 74 edges
5. `AgentContext` - 71 edges
6. `EvidenceStore` - 70 edges
7. `Evidence` - 61 edges
8. `Artifact` - 54 edges
9. `EvidenceKind` - 54 edges
10. `FindingDraft` - 50 edges

## Surprising Connections (you probably didn't know these)
- `test_investigation_status_terminal()` --uses--> `InvestigationStatus`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_severity_ordering()` --uses--> `Severity`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_assertion_class_values()` --uses--> `AssertionClass`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_time_confidence_values()` --uses--> `TimeConfidence`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `GroundTruthFinding` --uses--> `Severity`  [INFERRED]
  experiments/datasets/ground_truth.py → src/acip/types.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **End-to-End Evidence Provenance Pipeline** — docs_tools_tool_adapter_contract, docs_evidence_model_evidence_record, docs_evidence_model_traceability_chain, docs_frontend_provenance_ui_rules, docs_evidence_graph_relationships [EXTRACTED 1.00]
- **Experimental Evaluation and Ablation Framework** — docs_experiments_comparison_conditions, docs_experiments_ablations, docs_experiments_evaluation_metrics, docs_research_central_question, docs_model_abstraction_replay_double [EXTRACTED 1.00]
- **Grounding Invariants Enforcement Subsystem** — docs_evidence_model_grounding_invariants, docs_agents_agent_contract, docs_model_abstraction_core_llm, docs_experiments_evaluation_metrics, docs_research_central_question [EXTRACTED 1.00]

## Communities (133 total, 36 thin omitted)

### Community 0 - "RunStatus"
Cohesion: 0.12
Nodes (35): execute_condition(), Implementation of benchmark comparison conditions and ablations. Conditions: -…, Execute a single scenario under a specified condition or ablation., Logger, Agent, AgentResult, BaseModel, Structured outcome of one agent execution. (+27 more)

### Community 1 - "EvidenceStore"
Cohesion: 0.13
Nodes (14): EvidenceStore, AsyncSession, UUID, Writes evidence and findings for a single investigation., Persist drafts, skipping observations already recorded. Deduplication is by…, Validate a claim against the grounding invariants and persist it., Validate a hypothesis and persist it with supporting/contradicting links., Record an explicit knowledge gap preventing hypothesis resolution. (+6 more)

### Community 2 - "Evidence"
Cohesion: 0.23
Nodes (7): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, Evidence, An immutable observation with full provenance. ``tool_run_id`` being non-NULL…

### Community 3 - "TimeConfidence"
Cohesion: 0.16
Nodes (15): Match, AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime, Linux authentication log parser. A deterministic, dependency-free parser for…, Parsing options. Note the absence of any path argument. (+7 more)

### Community 4 - "InvestigationStatus"
Cohesion: 0.11
Nodes (18): Orchestrator, build_services(), Compose the object graph. Pure wiring, no I/O., InvestigationRunner, UUID, Background execution of investigations. M1 runs investigations as asyncio tasks…, Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency. (+10 more)

### Community 5 - "_forbid_bulk_dml"
Cohesion: 0.67
Nodes (3): ORMExecuteState, _forbid_bulk_dml(), Reject bulk UPDATE/DELETE against an append-only table.

### Community 6 - "investigations.py"
Cohesion: 0.10
Nodes (46): _fetch_hypotheses_detail(), get_evidence_provenance(), get_investigation_detail(), get_investigation_progress(), list_investigation_hypotheses(), UUID, Investigation lifecycle endpoints., List competing hypotheses, refutation conditions, and gaps. (+38 more)

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
Cohesion: 0.12
Nodes (17): Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, read_text(), _context(), IOCExtractorArgs, _ip_scope(), Any, BaseModel, IPv4Address (+9 more)

### Community 11 - "acip/errors.py"
Cohesion: 0.11
Nodes (19): Config, Exception, model_validator, Require a real secret in production; generate an ephemeral one otherwise. A…, Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, alembic_config(), Connection, Schema creation, through Alembic and only through Alembic. The migration chain… (+11 more)

### Community 12 - "ValidationError"
Cohesion: 0.11
Nodes (31): patch, is_ip_forbidden(), PinnedIPTransport, IPv4Address, IPv6Address, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Async HTTP transport establishing socket connection directly to a pinned IP. (+23 more)

### Community 13 - "ModelRouter"
Cohesion: 0.13
Nodes (33): CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains., Retrieve the routing rule and candidate list for a given task class., Create standard routing policy with Llama 3.2 11B and GPT-OSS 20B candidates., RoutingPolicy (+25 more)

### Community 14 - "AgentContext"
Cohesion: 0.14
Nodes (16): AuthDetectionHit, AgentContext, Everything an agent is given for one execution., Any, LogAnalysisAgent, Any, Project stored auth evidence into the rule engine's view type., Project stored web evidence into the web rule engine's view type. (+8 more)

### Community 15 - "conftest.py"
Cohesion: 0.29
Nodes (13): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+5 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "Role"
Cohesion: 0.05
Nodes (54): CurrentUser, FastAPI dependencies. Shared services (database, registries, orchestrator,…, require_admin(), require_investigator(), has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``., require_role() (+46 more)

### Community 18 - "BenchmarkRunner"
Cohesion: 0.10
Nodes (26): Any, Evaluation metrics for a single condition on a scenario., ScenarioMetrics, EvaluationReportGenerator, Path, Formats benchmark suite evaluation results into IEEE paper-ready markdown and…, Generates Markdown and JSON summary tables from benchmark results., BenchmarkRunner (+18 more)

### Community 19 - "Severity"
Cohesion: 0.14
Nodes (20): assess(), assess_with_model_opinion(), Protocol, Deterministic risk scoring. Severity and risk are computed from findings by a…, Assess risk deterministically, attaching an attributed model opinion. The model…, Structural type covering both ORM findings and drafts., Roll findings up into an investigation-level severity and risk score., RiskAssessment (+12 more)

### Community 20 - "AsyncSession"
Cohesion: 0.12
Nodes (39): File, Form, Investigator, LoadedInvestigation, _append_only_counts(), cancel_investigation(), _chunks(), create_investigation() (+31 more)

### Community 22 - ".session"
Cohesion: 0.13
Nodes (24): Mark orphan running investigations as interrupted on startup., Yield a session, committing on success and rolling back on error., AsyncSession, The guard must bound its own blast radius: reads stay unaffected., One named escape hatch, so deliberate destruction is greppable., An investigation with evidence, for the bulk-DML cases below., The mapper guards never see bulk DML, so the session guard must.…, _seed_evidence() (+16 more)

### Community 23 - "Services"
Cohesion: 0.14
Nodes (23): Admin, get_services(), get_settings_dep(), Request, Everything built once at startup., Services, admin_capabilities(), capabilities() (+15 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "files.py"
Cohesion: 0.14
Nodes (23): Path, Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Convenience helper to store an in-memory byte buffer into quarantine storage., Remove group/other access and any execute bit where the OS supports it., Result of a successful intake., Reduce a client-supplied filename to a safe display label. The result is used…, _restrict_permissions() (+15 more)

### Community 26 - "Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms"
Cohesion: 0.08
Nodes (23): 1. Evidence Graph Engine, 2. Competing Hypotheses & Adversarial Validation, A. Maximum Bipartite Cardinality Matching, Abstract, Analysis of Research Questions, Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms, B. Benchmark Scenarios, C. Experimental Conditions (+15 more)

### Community 27 - "test_artifact_validation.py"
Cohesion: 0.11
Nodes (24): detect_artifact_kind(), detect_magic_bytes(), Classify an artifact based on header magic bytes, filename, and declared kind.…, Inspect the first bytes of a file to detect its format and MIME type., Input and indicator validation primitives. Provides strict, deterministic…, Validate and canonicalize a target value for investigation creation., Validate and canonicalize an IPv4 or IPv6 address string. Returns the canonical…, Validate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512). Returns the… (+16 more)

### Community 28 - "log_analysis.py"
Cohesion: 0.18
Nodes (20): Log analysis agent. Parses authentication logs and web server access logs using…, DetectionHit, evaluate_web_rules(), _find_error_bursts(), UUID, Deterministic detection rules for web access logs. Pure functions over…, A parsed web access event, decoupled from the ORM., Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS. (+12 more)

### Community 29 - "ValueError"
Cohesion: 0.10
Nodes (13): Dialect, parametrize, field_validator, model_validator, field_validator, datetime, field_validator, datetime (+5 more)

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
Cohesion: 0.12
Nodes (14): async_sessionmaker, AsyncEngine, Database, Any, AsyncSession, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., Owns the engine and session factory for one database URL., _sqlite_pragmas() (+6 more)

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
Cohesion: 0.26
Nodes (12): Everything an adapter is permitted to know about its invocation., ToolContext, BaseModel, Tier 3 Threat Intelligence tool adapter. Queries indicator reputation…, Options for threat intelligence reputation lookup., Tier 3 Threat Intelligence tool adapter., ThreatIntelArgs, ThreatIntelTool (+4 more)

### Community 41 - "auth.py"
Cohesion: 0.15
Nodes (15): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+7 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - "get_session"
Cohesion: 0.16
Nodes (17): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), get_session(), AsyncSession, Depends, UUID (+9 more)

### Community 68 - "models.py"
Cohesion: 0.08
Nodes (29): DeclarativeBase, Mapped, Audit trail writes. Security-relevant actions are recorded in an append-only…, Evidence graph traversal engine. Confined to this module per docs/evidence-…, Base, Declarative base and portable column types. The schema deliberately avoids…, Base class for all ORM models., Timezone-aware current time. Used as a column default. (+21 more)

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
Nodes (36): MessageRole, StrEnum, Role of a message sender in a chat conversation., BudgetExceededError, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderQuotaExceeded (+28 more)

### Community 77 - "run_subprocess_sandboxed"
Cohesion: 0.24
Nodes (12): ToolExecutionError, Path, Tier 1 tool execution sandbox. Executes external tools as isolated subprocesses…, Execute a command in Tier 1 subprocess isolation. Guarantees: - Never uses…, run_subprocess_sandboxed(), SandboxResult, asyncio, Path (+4 more)

### Community 80 - "test_health.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_capabilities(), test_health()

### Community 81 - "bootstrap.py"
Cohesion: 0.17
Nodes (15): bootstrap(), Application bootstrap. Migrates the schema to head and, outside production,…, Prepare storage and seed development data., Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), hash_password(), needs_rehash(), Password hashing. Argon2id via ``argon2-cffi``, which is the current OWASP… (+7 more)

### Community 83 - "detection/mitre.py"
Cohesion: 0.29
Nodes (9): AttackTechnique, get_attack_technique(), map_rule_to_technique(), MITRE ATT&CK catalog and mapping validation. Enforces Invariant G7: no finding…, Lookup a technique in the catalog. Enforces Invariant G7: raises GroundingError…, Deterministically map a detection rule to its ATT&CK technique., test_mitre_catalog_version_and_contents(), test_mitre_deterministic_rule_mapping() (+1 more)

### Community 90 - "_evidence_after"
Cohesion: 0.12
Nodes (16): Collection, ColumnElement, _evidence_after(), _evidence_cursor(), EvidencePage, One page of evidence in timeline order, with a cursor for the next. The sort…, Every matching row up to ``cap``, and whether the cap cut the read short.…, One page of evidence, plus the cursor that continues it. (+8 more)

### Community 91 - "EvidenceKind"
Cohesion: 0.16
Nodes (20): Extract all typed EntityRef instances from an evidence row., EntityRef, FindingEvidenceDraft, normalize_entity_value(), Evidence and finding contracts. Agents and tools exchange these Pydantic models…, A citation connecting evidence to a finding with a supporting or contradicting…, Canonicalise an entity value so the same thing has one representation. Entity…, A typed reference to a real-world entity observed in evidence. (+12 more)

### Community 92 - "types.py"
Cohesion: 0.18
Nodes (12): ABC, Agent contract. Agents receive a typed context and return a typed result (spec…, Application configuration. All configuration arrives from the environment (or a…, Append-only evidence store and grounding enforcement. This module is where the…, Async engine and session management. Exposed as a class rather than module…, Strip credentials before a URL reaches the logs., _redact(), Audited tool invocation. Every tool call passes through :class:`ToolRunner`,… (+4 more)

### Community 93 - "GroundTruthFinding"
Cohesion: 0.13
Nodes (24): GroundTruthFinding, GroundTruthScenario, Ground truth schemas for evaluation., A ground-truth malicious event or attack step to be detected., A benchmark scenario with raw artifacts and ground truth labels., Benchmark evaluation scenarios with authentic telemetry and ground truth., MetricCalculator, Metric calculation harness for evaluation. (+16 more)

### Community 94 - "test_validation_agent_evaluates_refutations_and_bounds_loops"
Cohesion: 0.12
Nodes (18): HypothesisDraft, HypothesisGapDraft, ModelExecutionDraft, BaseModel, A competing candidate explanation under evaluation (Invariant G3)., A declared gap in evidence preventing resolution of a hypothesis., Structured record of an LLM call for experimental tracking., HypothesisStatus (+10 more)

### Community 95 - "tools/registry.py"
Cohesion: 0.11
Nodes (21): A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError, NoArgs, ABC, BaseModel, Tool adapter contract. A tool is the only thing in the platform allowed to…, Honest report of whether a tool can actually run right now. Surfaced through… (+13 more)

### Community 96 - "GraphTraversal"
Cohesion: 0.12
Nodes (14): GraphSubgraph, GraphTraversal, Any, AsyncSession, UUID, Bounded, cycle-safe traversal engine over relational evidence graphs., Fetch the full evidence graph for this investigation, capped to limit., Find entities and edges within max_depth hops of start_entity_id. Cycle-safe… (+6 more)

### Community 97 - "ProviderAvailability"
Cohesion: 0.25
Nodes (4): ProviderAvailability, Health and model discovery status for an LLM provider., Probe provider connectivity, authentication, and available models., Probe NVIDIA NIM endpoint to verify API key and model availability.

### Community 98 - "get_finding_subgraph"
Cohesion: 0.11
Nodes (31): alias, delete, description, ge, le, MAX_EVIDENCE_PAGE, Query, delete_investigation() (+23 more)

### Community 99 - "ModelExecution"
Cohesion: 0.12
Nodes (17): LLMResponse, Standardized response received from an LLM provider., Send a completion request to the provider for a specific model., Any, AsyncSession, BaseModel, UUID, Execute a completion for a TaskClass with optional structured schema… (+9 more)

### Community 101 - "EvidenceDraft"
Cohesion: 0.13
Nodes (19): EvidenceDraft, Stable digest of the observation, used to deduplicate evidence. Covers only…, An observation produced by a tool, before persistence. ``observed_at`` is when…, What an adapter returns., ToolResult, _parse_dns_qname(), PcapParser, PcapParserArgs (+11 more)

### Community 102 - "Artifact"
Cohesion: 0.09
Nodes (27): AgentRegistry, Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint., AdaptivePlanner, Adaptive Investigation Planner. Phase 7 implementation of the Planner protocol.…, Dynamic, evidence-driven planner implementing the Planner protocol., Investigation planning and orchestration., Plan (+19 more)

### Community 103 - "Investigation"
Cohesion: 0.24
Nodes (14): Investigation, TargetType, Path, test_tool_runner_records_quota_drop_warning(), _build_test_pcap(), asyncio, Path, Integration tests for all investigation target and file types. Verifies end-to-… (+6 more)

### Community 104 - "test_triage_agent_auth_attack_representative_case"
Cohesion: 0.13
Nodes (30): Deterministic rule-based triage used when model router is unavailable., EvidenceGap, ExtractedEntity, IndicatorAssessment, InputClassification, PlannedTaskProposal, BaseModel, Structured output schemas for the Triage Agent. (+22 more)

### Community 105 - "Settings"
Cohesion: 0.10
Nodes (30): ArgumentParser, BaseSettings, _backup(), build_parser(), _capabilities(), _create_user(), _init(), main() (+22 more)

### Community 106 - "orchestration/orchestrator.py"
Cohesion: 0.10
Nodes (29): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, _derive_status(), InvestigationOutcome, InvestigationState, _load_artifacts(), _load_investigation(), OrchestratorAgent, AsyncSession (+21 more)

### Community 107 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 108 - "ToolRun"
Cohesion: 0.21
Nodes (11): FindingEvidence, HypothesisEvidence, One audited tool invocation (spec s12). Every tool call is recorded before it…, Phase 5 schema scaffolding: relational citation mapping evidence to findings.…, Phase 7 schema scaffolding: relational citation linking evidence to a…, ToolRun, EvidenceRole, Relationship between an evidence observation and a finding or hypothesis. (+3 more)

### Community 111 - "env.py"
Cohesion: 0.31
Nodes (8): do_run_migrations(), Connection, Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_offline(), run_migrations_online()

### Community 113 - "triage.py"
Cohesion: 0.23
Nodes (9): _extract_host_from_url(), _is_ip_address(), _path(), Any, Triage agent. Extracts investigation entities, classifies the submission,…, Perform structured model-driven triage analysis with fallback to heuristics., Safely extract the domain or IP hostname from a URL candidate., Check if string is a valid IPv4 or IPv6 address. (+1 more)

### Community 114 - "ToolRunner"
Cohesion: 0.10
Nodes (20): A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry, Any, AsyncSession, BaseModel, datetime, Path (+12 more)

### Community 115 - "llm/contracts.py"
Cohesion: 0.13
Nodes (22): MonkeyPatch, ChatMessage, LLMRequest, LLMUsage, Any, Contracts and data models for model-provider abstraction. Defines the message…, A single conversation turn., Request payload sent to an LLM provider. (+14 more)

### Community 116 - "test_reasoning_agent_discovers_attack_chains_over_graph"
Cohesion: 0.17
Nodes (13): EntityEdge, Phase 5 evidence graph edge: verified, evidence-backed relationship., asyncio, Path, test_correlation_agent_extracts_entities_and_builds_edges(), asyncio, Test subgraph extraction for findings and chronological timeline generation., Test cycle-safe BFS neighbor discovery and depth bounding. (+5 more)

### Community 117 - "_PinnedIPNetworkBackend"
Cohesion: 0.22
Nodes (6): AsyncNetworkStream, AutoBackend, SOCKET_OPTION, _PinnedIPNetworkBackend, Any, Network backend pinning TCP socket connections to a pre-validated IP address.

### Community 118 - "app.py"
Cohesion: 0.24
Nodes (8): RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, _serialisable_errors(), Agentic Cyber Investigation Platform.

### Community 119 - "test_orchestrator_agent_with_model_router_triage"
Cohesion: 0.29
Nodes (9): asyncio, Path, Integration tests for the Orchestrator Agent., OrchestratorAgent works with model-routed Triage analysis to dynamically create…, When StaticPlanner is configured, OrchestratorAgent executes its plan verbatim., OrchestratorAgent receives an investigation, calls Triage, interprets result,…, test_orchestrator_agent_end_to_end_lifecycle(), test_orchestrator_agent_respects_static_planner_verbatim() (+1 more)

### Community 120 - "_build_chain"
Cohesion: 0.15
Nodes (18): _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker., The defect this file exists for: SET NULL used to unground every citing FACT., Evidence must stay traceable to the bytes it came from. (+10 more)

### Community 122 - "test_migrations.py"
Cohesion: 0.31
Nodes (8): _current_revision(), Connection, The migration chain is the schema, so the suite runs on it. Every fixture…, The fixture's schema came from Alembic, not from ``create_all``., ``Base.metadata`` describes exactly what the migrations build., _schema_diff(), test_bootstrap_stamps_the_database_at_head(), test_models_and_migrations_do_not_drift()

### Community 123 - "test_orchestrator.py"
Cohesion: 0.40
Nodes (3): MockPlanner, Any, test_orchestrator_failure_rollback()

### Community 124 - ".run"
Cohesion: 0.40
Nodes (3): Any, UUID, Derive directed, typed relationship edges backed by this evidence row.

### Community 129 - "log_context"
Cohesion: 0.15
Nodes (11): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, log_context(), Any, Temporarily bind values to the logging context. (+3 more)

### Community 135 - "SlidingWindowRateLimiter"
Cohesion: 0.17
Nodes (9): Thread-safe sliding window rate limiter., Check whether the key is within rate limits; increments counter if allowed.…, Clear all rate limit history (useful in tests)., SlidingWindowRateLimiter, AsyncClient, The investigation limiter was defined and wired to nothing. Login was the only…, test_auth_login_rate_limiting(), test_investigation_creation_is_rate_limited() (+1 more)

## Knowledge Gaps
- **99 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+94 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **36 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Settings` connect `Settings` to `RunStatus`, `InvestigationStatus`, `backup.py`, `acip/errors.py`, `ModelRouter`, `AgentContext`, `conftest.py`, `Role`, `BenchmarkRunner`, `Severity`, `Services`, `ValueError`, `Database`, `models.py`, `get_not_implemented`, `bootstrap.py`, `types.py`, `GroundTruthFinding`, `test_validation_agent_evaluates_refutations_and_bounds_loops`, `Artifact`, `Investigation`, `test_triage_agent_auth_attack_representative_case`, `orchestration/orchestrator.py`, `test_investigation_lifecycle.py`, `ToolRunner`, `test_reasoning_agent_discovers_attack_chains_over_graph`, `app.py`, `test_orchestrator_agent_with_model_router_triage`, `test_orchestrator.py`?**
  _High betweenness centrality (0.049) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `RunStatus`, `TimeConfidence`, `InvestigationStatus`, `backup.py`, `ModelRouter`, `conftest.py`, `Role`, `BenchmarkRunner`, `Severity`, `.session`, `Services`, `models.py`, `bootstrap.py`, `EvidenceKind`, `types.py`, `test_validation_agent_evaluates_refutations_and_bounds_loops`, `Artifact`, `Investigation`, `test_triage_agent_auth_attack_representative_case`, `Settings`, `orchestration/orchestrator.py`, `ToolRun`, `ToolRunner`, `test_reasoning_agent_discovers_attack_chains_over_graph`, `app.py`, `test_orchestrator_agent_with_model_router_triage`, `_build_chain`, `test_migrations.py`, `test_orchestrator.py`?**
  _High betweenness centrality (0.041) - this node is a cross-community bridge._
- **Why does `AgentContext` connect `AgentContext` to `RunStatus`, `EvidenceStore`, `Evidence`, `ModelRouter`, `Severity`, `log_analysis.py`, `Database`, `types.py`, `test_validation_agent_evaluates_refutations_and_bounds_loops`, `Artifact`, `Investigation`, `test_triage_agent_auth_attack_representative_case`, `Settings`, `orchestration/orchestrator.py`, `triage.py`, `ToolRunner`, `test_reasoning_agent_discovers_attack_chains_over_graph`, `.run`, `.run`?**
  _High betweenness centrality (0.035) - this node is a cross-community bridge._
- **Are the 68 inferred relationships involving `Database` (e.g. with `execute_condition()` and `BenchmarkRunner`) actually correct?**
  _`Database` has 68 INFERRED edges - model-reasoned connections that need verification._
- **Are the 63 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 63 INFERRED edges - model-reasoned connections that need verification._
- **Are the 60 inferred relationships involving `Severity` (e.g. with `GroundTruthFinding` and `execute_condition()`) actually correct?**
  _`Severity` has 60 INFERRED edges - model-reasoned connections that need verification._
- **Are the 56 inferred relationships involving `Settings` (e.g. with `execute_condition()` and `setup_scenario_investigation()`) actually correct?**
  _`Settings` has 56 INFERRED edges - model-reasoned connections that need verification._