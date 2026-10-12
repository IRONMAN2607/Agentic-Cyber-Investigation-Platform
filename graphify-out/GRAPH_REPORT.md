# Graph Report - AACIP  (2026-10-12)

## Corpus Check
- 202 files · ~118,901 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1860 nodes · 5647 edges · 142 communities (107 shown, 35 thin omitted)
- Extraction: 76% EXTRACTED · 24% INFERRED · 0% AMBIGUOUS · INFERRED: 1329 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `c18b3651`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- RunStatus
- EvidenceStore
- Evidence
- TimeConfidence
- InvestigationRunner
- session.py
- investigations.py
- evaluate_auth_rules
- web_log_parser.py
- backup.py
- ioc_extractor.py
- acip/errors.py
- test_ssrf.py
- ModelRouter
- AgentContext
- conftest.py
- Grounding Invariants G0-G4
- decode_access_token
- BenchmarkRunner
- Severity
- InvestigationStatus
- CLAUDE.md
- Database
- deps.py
- agentrouter
- ArtifactKind
- Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms
- ValidationError
- evaluate_web_rules
- ValueError
- app.js
- ACIP: Comprehensive End-to-End User Manual & Learning Guide
- Three-Transaction Orchestrator
- test_hypothesis_agent_generates_competing_hypotheses_with_g3
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- EvidenceKind
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
- orchestration/orchestrator.py
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
- .run
- AGENTS.md
- detection/mitre.py
- Role
- EvidenceDraft
- types.py
- GroundTruthFinding
- StrEnum
- ToolAdapter
- CorrelationAgent
- llm/contracts.py
- get_finding_subgraph
- LLMResponse
- PcapParser
- Artifact
- TargetType
- test_triage_agent_auth_attack_representative_case
- cli.py
- OrchestratorAgent
- test_investigation_lifecycle.py
- test_files.py
- datasets/__init__.py
- experiments/__init__.py
- env.py
- metrics/__init__.py
- TriageAgent
- ToolRunner
- ChatMessage
- AgentRegistry
- _PinnedIPNetworkBackend
- Settings
- test_orchestrator_agent_end_to_end_lifecycle
- AgentRun
- results/__init__.py
- test_migrations.py
- Investigation
- test_investigations.py
- datetime
- .__init__
- runners/__init__.py
- _coerce
- execute_condition
- build_default_router
- test_artifact_ingestion_api.py
- test_types.py
- test_auth.py
- test_rate_limit.py
- test_evidence_graph_and_timeline_pipeline
- test_auth_log_incident_scenario
- reproduce.sh script
- test_clean_web_log_scenario
- test_upload_security.py

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
- `test_hypothesis_draft_invariant_g3_refutation_required()` --uses--> `HypothesisDraft`  [INFERRED]
  tests/unit/test_domain_models.py → src/acip/core/evidence/contracts.py
- `test_hypothesis_draft_valid()` --uses--> `HypothesisDraft`  [INFERRED]
  tests/unit/test_domain_models.py → src/acip/core/evidence/contracts.py
- `test_hypothesis_gap_draft()` --uses--> `HypothesisGapDraft`  [INFERRED]
  tests/unit/test_domain_models.py → src/acip/core/evidence/contracts.py
- `test_sliding_window_rate_limiter_unit()` --uses--> `SlidingWindowRateLimiter`  [INFERRED]
  tests/security/test_rate_limit.py → src/acip/core/security/ratelimit.py
- `test_role_values()` --uses--> `Role`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **End-to-End Evidence Provenance Pipeline** — docs_tools_tool_adapter_contract, docs_evidence_model_evidence_record, docs_evidence_model_traceability_chain, docs_frontend_provenance_ui_rules, docs_evidence_graph_relationships [EXTRACTED 1.00]
- **Experimental Evaluation and Ablation Framework** — docs_experiments_comparison_conditions, docs_experiments_ablations, docs_experiments_evaluation_metrics, docs_research_central_question, docs_model_abstraction_replay_double [EXTRACTED 1.00]
- **Grounding Invariants Enforcement Subsystem** — docs_evidence_model_grounding_invariants, docs_agents_agent_contract, docs_model_abstraction_core_llm, docs_experiments_evaluation_metrics, docs_research_central_question [EXTRACTED 1.00]

## Communities (142 total, 35 thin omitted)

### Community 0 - "RunStatus"
Cohesion: 0.14
Nodes (27): Implementation of benchmark comparison conditions and ablations. Conditions: -…, Logger, Agent, ABC, Agent contract. Agents receive a typed context and return a typed result (spec…, Base class for all agents., Evidence graph correlation and entity resolution agent. Performs Tier 1…, HypothesisAgent (+19 more)

### Community 1 - "EvidenceStore"
Cohesion: 0.09
Nodes (21): Collection, HypothesisGapDraft, A declared gap in evidence preventing resolution of a hypothesis., _evidence_cursor(), EvidencePage, EvidenceStore, AsyncSession, UUID (+13 more)

### Community 2 - "Evidence"
Cohesion: 0.16
Nodes (14): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, Evidence, One audited tool invocation (spec s12). Every tool call is recorded before it…, An immutable observation with full provenance. ``tool_run_id`` being non-NULL… (+6 more)

### Community 3 - "TimeConfidence"
Cohesion: 0.18
Nodes (14): Match, AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime, Linux authentication log parser. A deterministic, dependency-free parser for…, Parsing options. Note the absence of any path argument. (+6 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.13
Nodes (13): Orchestrator, build_services(), Compose the object graph. Pure wiring, no I/O., InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency. (+5 more)

### Community 5 - "session.py"
Cohesion: 0.10
Nodes (17): ORMExecuteState, Background execution of investigations. M1 runs investigations as asyncio tasks…, _forbid_bulk_dml(), Any, Async engine and session management. Exposed as a class rather than module…, Strip credentials before a URL reaches the logs., SQLite ignores foreign keys unless asked, and defaults to slow sync writes., Reject bulk UPDATE/DELETE against an append-only table. (+9 more)

### Community 6 - "investigations.py"
Cohesion: 0.09
Nodes (52): _append_only_counts(), _fetch_hypotheses_detail(), get_evidence_provenance(), get_investigation_detail(), get_investigation_progress(), list_investigation_hypotheses(), UUID, Investigation lifecycle endpoints. (+44 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.17
Nodes (21): AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after(), Deterministic detection rules. These are pure functions over normalised events:… (+13 more)

### Community 8 - "web_log_parser.py"
Cohesion: 0.12
Nodes (26): _build_evidence_draft(), _detect_attacks(), _parse_request(), _parse_timestamp(), BaseModel, datetime, Deterministic web server access log parser and attack detection adapter. Parses…, Parses Apache, Nginx, and W3C web server access logs into structured events. (+18 more)

### Community 9 - "backup.py"
Cohesion: 0.23
Nodes (21): BackupIntegrityError, create_backup(), Path, Portable SQLite backup and restore with artifact-integrity verification. The…, A backup is incomplete or its artifact bytes do not match the database., Create and verify a consistent SQLite/artifact snapshot at ``destination``.…, Verify and restore ``source`` into empty configured SQLite/artifact paths.…, Raise when a backup lacks required source bytes or has a digest mismatch. (+13 more)

### Community 10 - "ioc_extractor.py"
Cohesion: 0.10
Nodes (23): Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, read_text(), A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError, _context(), IOCExtractor, IOCExtractorArgs (+15 more)

### Community 11 - "acip/errors.py"
Cohesion: 0.21
Nodes (9): Exception, Check whether the key is within rate limits; increments counter if allowed.…, ACIPError, AgentError, PayloadTooLargeError, Any, RateLimitExceededError, Typed application errors. Each error carries an HTTP status and a stable… (+1 more)

### Community 12 - "test_ssrf.py"
Cohesion: 0.10
Nodes (30): patch, is_ip_forbidden(), PinnedIPTransport, IPv4Address, IPv6Address, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Async HTTP transport establishing socket connection directly to a pinned IP. (+22 more)

### Community 13 - "ModelRouter"
Cohesion: 0.14
Nodes (31): CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains., Retrieve the routing rule and candidate list for a given task class., Create standard routing policy with Llama 3.2 11B and GPT-OSS 20B candidates., RoutingPolicy (+23 more)

### Community 14 - "AgentContext"
Cohesion: 0.12
Nodes (21): AuthDetectionHit, AgentContext, AgentResult, Any, BaseModel, Everything an agent is given for one execution., Structured outcome of one agent execution., Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure. (+13 more)

### Community 15 - "conftest.py"
Cohesion: 0.29
Nodes (13): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+5 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "decode_access_token"
Cohesion: 0.18
Nodes (14): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`., TokenPayload (+6 more)

### Community 18 - "BenchmarkRunner"
Cohesion: 0.10
Nodes (26): Any, Evaluation metrics for a single condition on a scenario., ScenarioMetrics, EvaluationReportGenerator, Path, Formats benchmark suite evaluation results into IEEE paper-ready markdown and…, Generates Markdown and JSON summary tables from benchmark results., BenchmarkRunner (+18 more)

### Community 19 - "Severity"
Cohesion: 0.13
Nodes (21): MitreMappingAgent, Any, MITRE ATT&CK Mapping Agent. Maps deterministic detection findings from triage,…, Deterministic MITRE ATT&CK mapping agent., assess(), assess_with_model_opinion(), Protocol, Deterministic risk scoring. Severity and risk are computed from findings by a… (+13 more)

### Community 20 - "InvestigationStatus"
Cohesion: 0.13
Nodes (39): File, Form, Investigator, LoadedInvestigation, cancel_investigation(), _chunks(), create_investigation(), create_task() (+31 more)

### Community 22 - "Database"
Cohesion: 0.09
Nodes (35): async_sessionmaker, AsyncEngine, Database, AsyncSession, Yield a session, committing on success and rolling back on error., Owns the engine and session factory for one database URL., AsyncSession, The guard must bound its own blast radius: reads stay unaffected. (+27 more)

### Community 23 - "deps.py"
Cohesion: 0.09
Nodes (38): Admin, _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), get_services(), get_session(), get_settings_dep() (+30 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "ArtifactKind"
Cohesion: 0.16
Nodes (24): detect_artifact_kind(), detect_magic_bytes(), Path, Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Classify an artifact based on header magic bytes, filename, and declared kind.…, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Convenience helper to store an in-memory byte buffer into quarantine storage., Remove group/other access and any execute bit where the OS supports it. (+16 more)

### Community 26 - "Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms"
Cohesion: 0.08
Nodes (23): 1. Evidence Graph Engine, 2. Competing Hypotheses & Adversarial Validation, A. Maximum Bipartite Cardinality Matching, Abstract, Analysis of Research Questions, Architecturally Enforced Evidence Grounding in Multi-Agent Cyber Investigation Platforms, B. Benchmark Scenarios, C. Experimental Conditions (+15 more)

### Community 27 - "ValidationError"
Cohesion: 0.10
Nodes (28): ColumnElement, _evidence_after(), Match rows strictly after the cursor, in the evidence sort order., decode_cursor(), encode_cursor(), Any, Opaque cursors for stable keyset pagination. api.md s5 requires "a bounded…, Encode a sort-key tuple as an opaque cursor. (+20 more)

### Community 28 - "evaluate_web_rules"
Cohesion: 0.20
Nodes (19): DetectionHit, evaluate_web_rules(), _find_error_bursts(), UUID, Deterministic detection rules for web access logs. Pure functions over…, A parsed web access event, decoupled from the ORM., Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS., Group 4xx/5xx error responses into bursts per IP. (+11 more)

### Community 29 - "ValueError"
Cohesion: 0.12
Nodes (9): parametrize, field_validator, model_validator, field_validator, datetime, field_validator, AsyncClient, test_endpoint_role_matrix() (+1 more)

### Community 30 - "app.js"
Cohesion: 0.37
Nodes (14): api(), checkCurrentUser(), closeEventStream(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderSvgGraph(), renderWorkspace() (+6 more)

### Community 31 - "ACIP: Comprehensive End-to-End User Manual & Learning Guide"
Cohesion: 0.08
Nodes (24): 1. What is ACIP? (In Plain English), 2. Quickstart: Launching the System in 60 Seconds, 3. Step-by-Step Walkthrough: Running Your First Investigation, 4. Visual UI Guide: What Every Element Does, 5. What is the "About & Limitations" Button?, 6. Command Line Interface (CLI) Guide, 7. Plain-English Concept Glossary, 8. Summary: How to Demonstrate ACIP to Others (+16 more)

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "test_hypothesis_agent_generates_competing_hypotheses_with_g3"
Cohesion: 0.20
Nodes (11): HypothesisDraft, A competing candidate explanation under evaluation (Invariant G3)., asyncio, Path, Invariant G3: A hypothesis without a refutation condition raises GroundingError., HypothesisAgent generates competing hypotheses enforcing Invariant G3., test_hypothesis_agent_generates_competing_hypotheses_with_g3(), test_invariant_g3_empty_refutation_condition_rejected() (+3 more)

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

### Community 40 - "EvidenceKind"
Cohesion: 0.26
Nodes (13): Everything an adapter is permitted to know about its invocation., ToolContext, BaseModel, Tier 3 Threat Intelligence tool adapter. Queries indicator reputation…, Options for threat intelligence reputation lookup., Tier 3 Threat Intelligence tool adapter., ThreatIntelArgs, ThreatIntelTool (+5 more)

### Community 41 - "auth.py"
Cohesion: 0.09
Nodes (22): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+14 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - "orchestration/orchestrator.py"
Cohesion: 0.11
Nodes (17): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, Adaptive Investigation Planner. Phase 7 implementation of the Planner protocol.…, Investigation planning and orchestration., _derive_status(), InvestigationOutcome, InvestigationState, Investigation orchestration and Orchestrator Agent. Executes a dynamic or…, Final outcome of an orchestrated investigation. (+9 more)

### Community 68 - "models.py"
Cohesion: 0.07
Nodes (39): DeclarativeBase, Mapped, Append-only evidence store and grounding enforcement. This module is where the…, Base, Declarative base and portable column types. The schema deliberately avoids…, Base class for all ORM models., Timezone-aware current time. Used as a column default., utcnow() (+31 more)

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
Cohesion: 0.15
Nodes (27): BudgetExceededError, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderQuotaExceeded, ProviderRateLimited, ProviderRefused, ProviderTimeout (+19 more)

### Community 77 - "run_subprocess_sandboxed"
Cohesion: 0.24
Nodes (12): ToolExecutionError, Path, Tier 1 tool execution sandbox. Executes external tools as isolated subprocesses…, Execute a command in Tier 1 subprocess isolation. Guarantees: - Never uses…, run_subprocess_sandboxed(), SandboxResult, asyncio, Path (+4 more)

### Community 80 - "test_health.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_capabilities(), test_health()

### Community 81 - ".run"
Cohesion: 0.19
Nodes (9): Any, BaseModel, datetime, Path, UUID, Reject any artifact path outside the configured storage root., Keep the audit record useful without copying bulk input into it., Validate, execute and audit a single tool call. (+1 more)

### Community 83 - "detection/mitre.py"
Cohesion: 0.29
Nodes (9): AttackTechnique, get_attack_technique(), map_rule_to_technique(), MITRE ATT&CK catalog and mapping validation. Enforces Invariant G7: no finding…, Lookup a technique in the catalog. Enforces Invariant G7: raises GroundingError…, Deterministically map a detection rule to its ATT&CK technique., test_mitre_catalog_version_and_contents(), test_mitre_deterministic_rule_mapping() (+1 more)

### Community 90 - "Role"
Cohesion: 0.27
Nodes (10): CurrentUser, require_admin(), require_investigator(), has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``., require_role(), AuthorizationError (+2 more)

### Community 91 - "EvidenceDraft"
Cohesion: 0.16
Nodes (18): Extract all typed EntityRef instances from an evidence row., EntityRef, EvidenceDraft, normalize_entity_value(), Stable digest of the observation, used to deduplicate evidence. Covers only…, Canonicalise an entity value so the same thing has one representation. Entity…, A typed reference to a real-world entity observed in evidence., An observation produced by a tool, before persistence. ``observed_at`` is when… (+10 more)

### Community 92 - "types.py"
Cohesion: 0.19
Nodes (9): Evidence and finding contracts. Agents and tools exchange these Pydantic models…, Tool adapter contract. A tool is the only thing in the platform allowed to…, Deterministic PCAP and packet capture parser adapter. Parses libpcap packet…, Tool registry. Agents resolve tools by name through the registry rather than…, Audited tool invocation. Every tool call passes through :class:`ToolRunner`,…, Shared enumerations. These are the vocabulary of the platform. They are stored…, test_auth_log_parser_max_lines_truncation(), test_evidence_store_quota_and_truncation() (+1 more)

### Community 93 - "GroundTruthFinding"
Cohesion: 0.16
Nodes (20): GroundTruthFinding, GroundTruthScenario, Ground truth schemas for evaluation., A ground-truth malicious event or attack step to be detected., A benchmark scenario with raw artifacts and ground truth labels., Benchmark evaluation scenarios with authentic telemetry and ground truth., MetricCalculator, Metric calculation harness for evaluation. (+12 more)

### Community 94 - "StrEnum"
Cohesion: 0.16
Nodes (13): FindingEvidenceDraft, ModelExecutionDraft, BaseModel, A citation connecting evidence to a finding with a supporting or contradicting…, Structured record of an LLM call for experimental tracking., FinishReason, StrEnum, LLM completion termination reason. (+5 more)

### Community 95 - "ToolAdapter"
Cohesion: 0.15
Nodes (10): NoArgs, ABC, BaseModel, Honest report of whether a tool can actually run right now. Surfaced through…, For adapters that take no options., Base class for all tool adapters., Report runtime availability. In-process adapters are always available. Adapters…, Do the work. Raise :class:`~acip.errors.ToolError` on failure. (+2 more)

### Community 96 - "CorrelationAgent"
Cohesion: 0.08
Nodes (29): CorrelationAgent, UUID, Derive directed, typed relationship edges backed by this evidence row., Deterministic evidence graph correlation and entity resolution agent., GraphSubgraph, GraphTraversal, Any, AsyncSession (+21 more)

### Community 97 - "llm/contracts.py"
Cohesion: 0.14
Nodes (10): MessageRole, ProviderAvailability, StrEnum, Contracts and data models for model-provider abstraction. Defines the message…, Role of a message sender in a chat conversation., Health and model discovery status for an LLM provider., LLMProvider protocol definition., Probe NVIDIA NIM endpoint to verify API key and model availability. (+2 more)

### Community 98 - "get_finding_subgraph"
Cohesion: 0.11
Nodes (32): alias, delete, description, ge, le, MAX_EVIDENCE_PAGE, Query, delete_investigation() (+24 more)

### Community 99 - "LLMResponse"
Cohesion: 0.15
Nodes (13): LLMResponse, Standardized response received from an LLM provider., LLMProvider, Protocol, Abstract protocol for all LLM backend adapters., Send a completion request to the provider for a specific model., Probe provider connectivity, authentication, and available models., AsyncSession (+5 more)

### Community 101 - "PcapParser"
Cohesion: 0.18
Nodes (14): _parse_dns_qname(), PcapParser, PcapParserArgs, BaseModel, Parse basic PCAPNG blocks., Execution options for packet capture parsing., Parse a DNS domain name from packet payload starting at offset., Deterministic parser for PCAP packet captures. (+6 more)

### Community 102 - "Artifact"
Cohesion: 0.13
Nodes (15): AdaptivePlanner, Dynamic, evidence-driven planner implementing the Planner protocol., Plan, Planner, Protocol, An ordered set of tasks plus the reason the shape was chosen., Chooses which agents run, in what order, and why., Artifact (+7 more)

### Community 103 - "TargetType"
Cohesion: 0.39
Nodes (11): TargetType, _build_test_pcap(), asyncio, Path, Integration tests for all investigation target and file types. Verifies end-to-…, Build a deterministic in-memory libpcap byte sequence., _setup_test_env(), test_domain_investigation_pipeline() (+3 more)

### Community 104 - "test_triage_agent_auth_attack_representative_case"
Cohesion: 0.12
Nodes (36): Deterministic rule-based triage used when model router is unavailable., EvidenceGap, ExtractedEntity, IndicatorAssessment, InputClassification, PlannedTaskProposal, BaseModel, Structured output schemas for the Triage Agent. (+28 more)

### Community 105 - "cli.py"
Cohesion: 0.08
Nodes (40): ArgumentParser, Config, bootstrap(), Application bootstrap. Migrates the schema to head and, outside production,…, Prepare storage and seed development data., Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), _backup() (+32 more)

### Community 106 - "OrchestratorAgent"
Cohesion: 0.17
Nodes (15): _load_artifacts(), _load_investigation(), OrchestratorAgent, AsyncSession, UUID, First functional Orchestrator Agent. Coordinates the investigation lifecycle:…, Retrieve the in-memory state of an active or recent investigation., Run the full investigation lifecycle. Never raises for task-level failures. (+7 more)

### Community 107 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 108 - "test_files.py"
Cohesion: 0.31
Nodes (8): Reduce a client-supplied filename to a safe display label. The result is used…, sanitize_filename(), Path, test_read_text_utf8_and_latin1(), test_sanitize_filename(), test_store_stream_empty_rejected(), test_store_stream_oversized_rejected(), test_store_stream_success()

### Community 111 - "env.py"
Cohesion: 0.31
Nodes (8): do_run_migrations(), Connection, Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_offline(), run_migrations_online()

### Community 113 - "TriageAgent"
Cohesion: 0.21
Nodes (10): _extract_host_from_url(), _is_ip_address(), _path(), Any, Perform structured model-driven triage analysis with fallback to heuristics., Classifies the submission, extracts entities, assesses indicators, and plans…, Safely extract the domain or IP hostname from a URL candidate., Check if string is a valid IPv4 or IPv6 address. (+2 more)

### Community 114 - "ToolRunner"
Cohesion: 0.13
Nodes (14): A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry, AsyncSession, Executes tools for one investigation, recording each invocation., ToolRunner, Path, test_tool_runner_records_quota_drop_warning() (+6 more)

### Community 115 - "ChatMessage"
Cohesion: 0.11
Nodes (22): MonkeyPatch, ChatMessage, LLMRequest, LLMUsage, Any, A single conversation turn., Request payload sent to an LLM provider., Token accounting telemetry returned by a provider. (+14 more)

### Community 116 - "AgentRegistry"
Cohesion: 0.25
Nodes (3): AgentRegistry, Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint.

### Community 117 - "_PinnedIPNetworkBackend"
Cohesion: 0.22
Nodes (6): AsyncNetworkStream, AutoBackend, SOCKET_OPTION, _PinnedIPNetworkBackend, Any, Network backend pinning TCP socket connections to a pre-validated IP address.

### Community 118 - "Settings"
Cohesion: 0.11
Nodes (17): BaseSettings, RequestValidationError, create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, _serialisable_errors() (+9 more)

### Community 119 - "test_orchestrator_agent_end_to_end_lifecycle"
Cohesion: 0.40
Nodes (6): asyncio, Path, When StaticPlanner is configured, OrchestratorAgent executes its plan verbatim., OrchestratorAgent receives an investigation, calls Triage, interprets result,…, test_orchestrator_agent_end_to_end_lifecycle(), test_orchestrator_agent_respects_static_planner_verbatim()

### Community 120 - "AgentRun"
Cohesion: 0.16
Nodes (16): AgentRun, One execution of one agent. Part of the investigation execution trace., _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker. (+8 more)

### Community 122 - "test_migrations.py"
Cohesion: 0.24
Nodes (10): _current_revision(), Connection, The migration chain is the schema, so the suite runs on it. Every fixture…, The fixture's schema came from Alembic, not from ``create_all``., ``Base.metadata`` describes exactly what the migrations build., A second engine on ``:memory:`` would migrate a different database., _schema_diff(), test_bootstrap_stamps_the_database_at_head() (+2 more)

### Community 123 - "Investigation"
Cohesion: 0.16
Nodes (8): Rule-based planner: reproducible, and the control condition for the study.…, StaticPlanner, Investigation, MockPlanner, Any, test_orchestrator_failure_rollback(), test_static_planner_with_auth_log(), test_static_planner_without_artifacts()

### Community 124 - "test_investigations.py"
Cohesion: 0.38
Nodes (6): AsyncClient, Verify that all target types can be created with canonicalization and defanging., Verify that validation errors return a descriptive formatted message., test_investigation_creation_all_target_types(), test_investigation_crud_and_lifecycle(), test_investigation_validation_error_formatting()

### Community 125 - "datetime"
Cohesion: 0.47
Nodes (4): Dialect, datetime, Store timezone-aware datetimes as UTC and read them back aware. Rejects naive…, UTCDateTime

### Community 129 - "_coerce"
Cohesion: 0.18
Nodes (9): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, Any, Merge the ambient context into each record., One JSON object per line, suitable for ingestion by a log pipeline. (+1 more)

### Community 130 - "execute_condition"
Cohesion: 0.33
Nodes (6): execute_condition(), Any, UUID, Create investigation row and store raw scenario artifacts., Execute a single scenario under a specified condition or ablation., setup_scenario_investigation()

### Community 131 - "build_default_router"
Cohesion: 0.33
Nodes (6): build_default_router(), Any, BaseModel, Construct a default ModelRouter from application settings., Generate a clean example JSON structure from a Pydantic model for prompt…, _schema_to_template()

### Community 132 - "test_artifact_ingestion_api.py"
Cohesion: 0.53
Nodes (5): AsyncClient, test_ingest_text_artifact_endpoint(), test_ingest_url_artifact_blocks_ssrf(), test_upload_pcap_artifact_success(), test_upload_pcap_mismatch_rejected()

### Community 133 - "test_types.py"
Cohesion: 0.33
Nodes (5): test_assertion_class_values(), test_investigation_status_terminal(), test_role_values(), test_severity_ordering(), test_time_confidence_values()

### Community 134 - "test_auth.py"
Cohesion: 0.60
Nodes (4): AsyncClient, test_auth_login_invalid_password(), test_auth_login_success(), test_auth_me_endpoint()

### Community 135 - "test_rate_limit.py"
Cohesion: 0.40
Nodes (5): AsyncClient, The investigation limiter was defined and wired to nothing. Login was the only…, test_auth_login_rate_limiting(), test_investigation_creation_is_rate_limited(), test_sliding_window_rate_limiter_unit()

### Community 136 - "test_evidence_graph_and_timeline_pipeline"
Cohesion: 0.67
Nodes (3): AsyncClient, asyncio, test_evidence_graph_and_timeline_pipeline()

### Community 137 - "test_auth_log_incident_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_auth_log_incident_scenario(), test_clean_log_scenario()

### Community 139 - "test_clean_web_log_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_clean_web_log_scenario(), test_web_log_attack_scenario()

### Community 141 - "test_upload_security.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_upload_empty_file_rejected(), test_upload_path_traversal_sanitized()

## Knowledge Gaps
- **99 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+94 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **35 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Severity` to `RunStatus`, `EvidenceStore`, `execute_condition`, `Evidence`, `test_types.py`, `investigations.py`, `evaluate_auth_rules`, `test_auth_log_incident_scenario`, `test_clean_web_log_scenario`, `ModelRouter`, `AgentContext`, `InvestigationStatus`, `Database`, `evaluate_web_rules`, `models.py`, `types.py`, `GroundTruthFinding`, `StrEnum`, `CorrelationAgent`, `TargetType`, `test_triage_agent_auth_attack_representative_case`, `TriageAgent`, `ToolRunner`, `ChatMessage`?**
  _High betweenness centrality (0.059) - this node is a cross-community bridge._
- **Why does `Role` connect `Role` to `test_artifact_ingestion_api.py`, `test_types.py`, `investigations.py`, `test_auth.py`, `test_evidence_graph_and_timeline_pipeline`, `test_auth_log_incident_scenario`, `test_rate_limit.py`, `test_clean_web_log_scenario`, `test_upload_security.py`, `conftest.py`, `decode_access_token`, `deps.py`, `ValueError`, `auth.py`, `models.py`, `get_not_implemented`, `types.py`, `StrEnum`, `cli.py`, `test_investigation_lifecycle.py`, `test_investigations.py`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Why does `Settings` connect `Settings` to `RunStatus`, `execute_condition`, `Evidence`, `InvestigationRunner`, `session.py`, `backup.py`, `ModelRouter`, `AgentContext`, `conftest.py`, `BenchmarkRunner`, `deps.py`, `ValueError`, `test_hypothesis_agent_generates_competing_hypotheses_with_g3`, `orchestration/orchestrator.py`, `get_not_implemented`, `CorrelationAgent`, `Artifact`, `TargetType`, `test_triage_agent_auth_attack_representative_case`, `cli.py`, `OrchestratorAgent`, `test_investigation_lifecycle.py`, `ToolRunner`, `test_orchestrator_agent_end_to_end_lifecycle`, `test_migrations.py`, `Investigation`?**
  _High betweenness centrality (0.049) - this node is a cross-community bridge._
- **Are the 68 inferred relationships involving `Database` (e.g. with `execute_condition()` and `BenchmarkRunner`) actually correct?**
  _`Database` has 68 INFERRED edges - model-reasoned connections that need verification._
- **Are the 63 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 63 INFERRED edges - model-reasoned connections that need verification._
- **Are the 60 inferred relationships involving `Severity` (e.g. with `GroundTruthFinding` and `execute_condition()`) actually correct?**
  _`Severity` has 60 INFERRED edges - model-reasoned connections that need verification._
- **Are the 56 inferred relationships involving `Settings` (e.g. with `execute_condition()` and `setup_scenario_investigation()`) actually correct?**
  _`Settings` has 56 INFERRED edges - model-reasoned connections that need verification._