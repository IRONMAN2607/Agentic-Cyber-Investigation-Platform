# Graph Report - AACIP  (2026-10-12)

## Corpus Check
- 160 files · ~96,203 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1572 nodes · 4631 edges · 118 communities (90 shown, 28 thin omitted)
- Extraction: 78% EXTRACTED · 22% INFERRED · 0% AMBIGUOUS · INFERRED: 1036 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `8848bf76`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Database
- _evidence_after
- Evidence
- TimeConfidence
- InvestigationRunner
- types.py
- investigations.py
- evaluate_auth_rules
- web_log_parser.py
- backup.py
- ioc_extractor.py
- SlidingWindowRateLimiter
- test_ssrf.py
- ChatMessage
- AgentContext
- conftest.py
- Grounding Invariants G0-G4
- Role
- pcap_parser.py
- AssertionClass
- InvestigationStatus
- CLAUDE.md
- orchestration/orchestrator.py
- admin_capabilities
- agentrouter
- files.py
- EvidenceDraft
- ValidationError
- Severity
- ValueError
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
- ArtifactKind
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
- EvidenceKind
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
- .session
- _get_python_files
- .opencode/opencode.json
- Artifact
- Settings
- router.py
- run_subprocess_sandboxed
- graphify.js
- test_health
- store.py
- AGENTS.md
- NvidiaNIMProvider
- EvidenceStore
- GroundingError
- RunStatus
- detection/mitre.py
- build_default_router
- acip/errors.py
- Investigation
- HypothesisDraft
- delete_investigation
- ModelExecution
- db/base.py
- AgentRegistry
- get_evidence_provenance
- test_triage_agent_auth_attack_representative_case
- cli.py
- OrchestratorAgent
- test_investigation_lifecycle.py
- models.py
- _coerce
- test_cyber_reasoning.py
- ratelimit.py
- test_mitre_mapping_agent_maps_rules_to_techniques
- test_triage_agent.py
- llm/contracts.py
- ssrf.py
- TriageAgent
- ToolRun

## God Nodes (most connected - your core abstractions)
1. `Database` - 75 edges
2. `Severity` - 69 edges
3. `Investigation` - 66 edges
4. `EvidenceStore` - 65 edges
5. `Settings` - 61 edges
6. `AgentContext` - 55 edges
7. `Evidence` - 49 edges
8. `Role` - 46 edges
9. `OrchestratorAgent` - 43 edges
10. `Artifact` - 43 edges

## Surprising Connections (you probably didn't know these)
- `test_hypothesis_gap_draft()` --uses--> `HypothesisGapDraft`  [INFERRED]
  tests/unit/test_domain_models.py → src/acip/core/evidence/contracts.py
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

## Communities (118 total, 28 thin omitted)

### Community 0 - "Database"
Cohesion: 0.11
Nodes (15): async_sessionmaker, AsyncEngine, Orchestrator, build_services(), Compose the object graph. Pure wiring, no I/O., Database, Any, AsyncSession (+7 more)

### Community 1 - "_evidence_after"
Cohesion: 0.22
Nodes (9): ColumnElement, _evidence_after(), Match rows strictly after the cursor, in the evidence sort order., decode_cursor(), encode_cursor(), Any, Opaque cursors for stable keyset pagination. api.md s5 requires "a bounded…, Encode a sort-key tuple as an opaque cursor. (+1 more)

### Community 2 - "Evidence"
Cohesion: 0.16
Nodes (11): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, RiskAssessment, Evidence, Finding (+3 more)

### Community 3 - "TimeConfidence"
Cohesion: 0.16
Nodes (15): Match, AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime, Parsing options. Note the absence of any path argument., Parses Linux authentication logs into normalised auth events. (+7 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.17
Nodes (9): InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle., Cancel an in-flight investigation task., Await every scheduled investigation. Used by tests and shutdown. (+1 more)

### Community 5 - "types.py"
Cohesion: 0.11
Nodes (18): Logger, ORMExecuteState, Audit trail writes. Security-relevant actions are recorded in an append-only…, Background execution of investigations. M1 runs investigations as asyncio tasks…, _forbid_bulk_dml(), Async engine and session management. Exposed as a class rather than module…, Strip credentials before a URL reaches the logs., Reject bulk UPDATE/DELETE against an append-only table. (+10 more)

### Community 6 - "investigations.py"
Cohesion: 0.10
Nodes (46): get_investigation_detail(), Investigation lifecycle endpoints., Everything a workspace view needs, in one round trip., Health and capability endpoints. ``/capabilities`` is a first-class endpoint,…, AdminCapabilitiesResponse, AgentCapabilityInfo, AgentRunResponse, ArtifactResponse (+38 more)

### Community 7 - "evaluate_auth_rules"
Cohesion: 0.17
Nodes (21): AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after(), Deterministic detection rules. These are pure functions over normalised events:… (+13 more)

### Community 8 - "web_log_parser.py"
Cohesion: 0.12
Nodes (24): _build_evidence_draft(), _detect_attacks(), _parse_request(), _parse_timestamp(), BaseModel, datetime, Deterministic web server access log parser and attack detection adapter. Parses…, Parses Apache, Nginx, and W3C web server access logs into structured events. (+16 more)

### Community 9 - "backup.py"
Cohesion: 0.23
Nodes (21): BackupIntegrityError, create_backup(), Path, Portable SQLite backup and restore with artifact-integrity verification. The…, A backup is incomplete or its artifact bytes do not match the database., Create and verify a consistent SQLite/artifact snapshot at ``destination``.…, Verify and restore ``source`` into empty configured SQLite/artifact paths.…, Raise when a backup lacks required source bytes or has a digest mismatch. (+13 more)

### Community 10 - "ioc_extractor.py"
Cohesion: 0.08
Nodes (31): Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, read_text(), A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError, Linux authentication log parser. A deterministic, dependency-free parser for…, ABC, Tool adapter contract. A tool is the only thing in the platform allowed to… (+23 more)

### Community 11 - "SlidingWindowRateLimiter"
Cohesion: 0.20
Nodes (8): Thread-safe sliding window rate limiter., Clear all rate limit history (useful in tests)., SlidingWindowRateLimiter, AsyncClient, The investigation limiter was defined and wired to nothing. Login was the only…, test_auth_login_rate_limiting(), test_investigation_creation_is_rate_limited(), test_sliding_window_rate_limiter_unit()

### Community 12 - "test_ssrf.py"
Cohesion: 0.17
Nodes (17): patch, is_ip_forbidden(), IPv4Address, IPv6Address, Validate a URL against SSRF rules and resolve its DNS records. Raises…, Check if an IP address falls into a private, loopback, or cloud metadata range., validate_url_ssrf_safe(), test_is_ip_allowed_public_ips() (+9 more)

### Community 13 - "ChatMessage"
Cohesion: 0.15
Nodes (26): ChatMessage, Any, A single conversation turn., CandidateModel, Routing policies and candidate model fallback chains for task classes., A specific model candidate configured under a provider., Routing and fallback candidates for a single TaskClass., Configurable routing table mapping TaskClasses to candidate priority chains. (+18 more)

### Community 14 - "AgentContext"
Cohesion: 0.19
Nodes (13): AuthDetectionHit, AgentContext, Everything an agent is given for one execution., LogAnalysisAgent, Any, Project stored auth evidence into the rule engine's view type., Project stored web evidence into the web rule engine's view type., Parses authentication and web access logs and applies deterministic detection… (+5 more)

### Community 15 - "conftest.py"
Cohesion: 0.29
Nodes (13): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+5 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "Role"
Cohesion: 0.05
Nodes (53): CurrentUser, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,…, require_admin(), require_investigator(), has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``. (+45 more)

### Community 18 - "pcap_parser.py"
Cohesion: 0.11
Nodes (23): NoArgs, BaseModel, Honest report of whether a tool can actually run right now. Surfaced through…, What an adapter returns., For adapters that take no options., Do the work. Raise :class:`~acip.errors.ToolError` on failure., ToolAvailability, ToolResult (+15 more)

### Community 19 - "AssertionClass"
Cohesion: 0.15
Nodes (15): assess(), Protocol, Deterministic risk scoring. Severity and risk are computed from findings by a…, Structural type covering both ORM findings and drafts., Roll findings up into an investigation-level severity and risk score., ScorableFinding, AssertionClass, Epistemic status of a claim. See docs/evidence-model.md. The distinction is… (+7 more)

### Community 20 - "InvestigationStatus"
Cohesion: 0.12
Nodes (38): File, Form, Investigator, LoadedInvestigation, _append_only_counts(), cancel_investigation(), _chunks(), create_investigation() (+30 more)

### Community 22 - "orchestration/orchestrator.py"
Cohesion: 0.13
Nodes (16): Orchestrator Agent. Re-exports the core OrchestratorAgent, state tracking, and…, Investigation planning and orchestration., _derive_status(), InvestigationOutcome, InvestigationState, Investigation orchestration and Orchestrator Agent. Executes a dynamic or…, Final outcome of an orchestrated investigation., Outcome of an individual task execution. (+8 more)

### Community 23 - "admin_capabilities"
Cohesion: 0.24
Nodes (10): Admin, admin_capabilities(), capabilities(), health(), AsyncSession, Depends, get, Liveness plus a real database round trip. (+2 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "files.py"
Cohesion: 0.11
Nodes (30): detect_artifact_kind(), detect_magic_bytes(), Path, Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Classify an artifact based on header magic bytes, filename, and declared kind.…, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, Convenience helper to store an in-memory byte buffer into quarantine storage., Remove group/other access and any execute bit where the OS supports it. (+22 more)

### Community 26 - "EvidenceDraft"
Cohesion: 0.11
Nodes (28): EntityRef, EvidenceDraft, normalize_entity_value(), Evidence and finding contracts. Agents and tools exchange these Pydantic models…, Stable digest of the observation, used to deduplicate evidence. Covers only…, Canonicalise an entity value so the same thing has one representation. Entity…, A typed reference to a real-world entity observed in evidence., An observation produced by a tool, before persistence. ``observed_at`` is when… (+20 more)

### Community 27 - "ValidationError"
Cohesion: 0.14
Nodes (19): Fetch remote URL safely, validating every hop and streaming the body., Input and indicator validation primitives. Provides strict, deterministic…, Validate and canonicalize a target value for investigation creation., Validate and canonicalize an IPv4 or IPv6 address string. Returns the canonical…, Validate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512). Returns the…, Validate and canonicalize a fully qualified domain name. Returns the lowercased…, Validate and canonicalize a URL structure. Enforces RFC 3986 compliance and…, validate_domain() (+11 more)

### Community 28 - "Severity"
Cohesion: 0.18
Nodes (21): Log analysis agent. Parses authentication logs and web server access logs using…, DetectionHit, evaluate_web_rules(), _find_error_bursts(), UUID, Deterministic detection rules for web access logs. Pure functions over…, A parsed web access event, decoupled from the ORM., Collect distinct evidence UUIDs preserving order, capped at _MAX_CITED_EVENTS. (+13 more)

### Community 29 - "ValueError"
Cohesion: 0.12
Nodes (9): parametrize, field_validator, model_validator, field_validator, datetime, field_validator, AsyncClient, test_endpoint_role_matrix() (+1 more)

### Community 30 - "app.js"
Cohesion: 0.45
Nodes (10): api(), checkCurrentUser(), escapeHtml(), loadInvestigations(), renderMarkdown(), renderWorkspace(), selectInvestigation(), setAuth() (+2 more)

### Community 31 - "app.py"
Cohesion: 0.11
Nodes (21): do_run_migrations(), Connection, Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode. ``acip.db.migrate`` passes an already-open…, run_async_migrations(), run_migrations_offline(), run_migrations_online() (+13 more)

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "test_historical_migration_0002_to_0003_populated_upgrade"
Cohesion: 0.19
Nodes (13): _current_revision(), Connection, Path, The migration chain is the schema, so the suite runs on it. Every fixture…, The fixture's schema came from Alembic, not from ``create_all``., ``Base.metadata`` describes exactly what the migrations build., A second engine on ``:memory:`` would migrate a different database., A populated 0002 database upgrades to 0003 preserving data and enforcing… (+5 more)

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

### Community 40 - "ArtifactKind"
Cohesion: 0.18
Nodes (15): One scheduled or executed unit of work in an investigation plan., TaskRun, ArtifactKind, Declared or detected kind of an uploaded or ingested artifact. Declared by the…, TaskStatus, test_task_run_lifecycle(), asyncio, Path (+7 more)

### Community 41 - "get_session"
Cohesion: 0.10
Nodes (30): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), get_services(), get_session(), get_settings_dep(), AsyncSession (+22 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 53 - "EvidenceKind"
Cohesion: 0.26
Nodes (13): Everything an adapter is permitted to know about its invocation., ToolContext, BaseModel, Tier 3 Threat Intelligence tool adapter. Queries indicator reputation…, Options for threat intelligence reputation lookup., Tier 3 Threat Intelligence tool adapter., ThreatIntelArgs, ThreatIntelTool (+5 more)

### Community 68 - ".session"
Cohesion: 0.26
Nodes (13): Yield a session, committing on success and rolling back on error., test_audit_log_immutability(), test_bulk_dml_blocked_on_audit_log(), _create_tool_run(), _draft_evidence(), AsyncSession, UUID, test_grounding_invariant_cross_investigation_isolated() (+5 more)

### Community 72 - "_get_python_files"
Cohesion: 0.44
Nodes (8): _get_python_files(), Path, The schema has one source of truth: the Alembic chain. ``create_all`` was the…, A reserved key in ``extra`` raises KeyError only when the record is emitted.…, test_no_direct_llm_sdk_imports_in_agents(), test_no_metadata_create_all_in_src(), test_no_reserved_logrecord_keys_in_log_extra(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 74 - "Artifact"
Cohesion: 0.18
Nodes (8): Artifact, An uploaded input, stored content-addressed under the quarantine dir., A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry, Path, test_report_discloses_missing_source_bytes(), test_report_discloses_retention_state_and_intact_bytes()

### Community 75 - "Settings"
Cohesion: 0.11
Nodes (18): BaseSettings, CaptureFixture, _capabilities(), Print the real capability set, probed rather than assumed., model_validator, Create runtime directories. Called once at startup., Resolved application settings., Require a real secret in production; generate an ephemeral one otherwise. A… (+10 more)

### Community 76 - "router.py"
Cohesion: 0.12
Nodes (28): MessageRole, StrEnum, Role of a message sender in a chat conversation., BudgetExceededError, LLMError, NoAvailableProviderError, ProviderAuthError, ProviderRefused (+20 more)

### Community 77 - "run_subprocess_sandboxed"
Cohesion: 0.24
Nodes (12): ToolExecutionError, Path, Tier 1 tool execution sandbox. Executes external tools as isolated subprocesses…, Execute a command in Tier 1 subprocess isolation. Guarantees: - Never uses…, run_subprocess_sandboxed(), SandboxResult, asyncio, Path (+4 more)

### Community 81 - "store.py"
Cohesion: 0.26
Nodes (8): Append-only evidence store and grounding enforcement. This module is where the…, FindingEvidence, HypothesisEvidence, Phase 5 schema scaffolding: relational citation mapping evidence to findings.…, Phase 7 schema scaffolding: relational citation linking evidence to a…, EvidenceRole, Relationship between an evidence observation and a finding or hypothesis., test_finding_evidence_relational_citation()

### Community 83 - "NvidiaNIMProvider"
Cohesion: 0.15
Nodes (15): MonkeyPatch, ProviderQuotaExceeded, ProviderRateLimited, ProviderUnavailable, Any, The provider quota/credits are exhausted. Safe to fall back to secondary., Transient rate limit hit. Retry once, then fall back., Network connection failure or 5xx error from provider. Safe to fall back. (+7 more)

### Community 90 - "EvidenceStore"
Cohesion: 0.13
Nodes (16): Collection, HypothesisGapDraft, A declared gap in evidence preventing resolution of a hypothesis., _evidence_cursor(), EvidencePage, EvidenceStore, Writes evidence and findings for a single investigation., Persist drafts, skipping observations already recorded. Deduplication is by… (+8 more)

### Community 91 - "GroundingError"
Cohesion: 0.23
Nodes (7): AsyncSession, UUID, Validate a claim against the grounding invariants and persist it., Validate a hypothesis and persist it with supporting/contradicting links., Fetch cited evidence, enforcing G0., GroundingError, Raised when a claim violates an evidence-grounding invariant. This is a…

### Community 92 - "RunStatus"
Cohesion: 0.15
Nodes (21): Agent, AgentResult, ABC, Any, BaseModel, Agent contract. Agents receive a typed context and return a typed result (spec…, Structured outcome of one agent execution., Base class for all agents. (+13 more)

### Community 93 - "detection/mitre.py"
Cohesion: 0.29
Nodes (9): AttackTechnique, get_attack_technique(), map_rule_to_technique(), MITRE ATT&CK catalog and mapping validation. Enforces Invariant G7: no finding…, Lookup a technique in the catalog. Enforces Invariant G7: raises GroundingError…, Deterministically map a detection rule to its ATT&CK technique., test_mitre_catalog_version_and_contents(), test_mitre_deterministic_rule_mapping() (+1 more)

### Community 94 - "build_default_router"
Cohesion: 0.17
Nodes (10): LLMProvider, Protocol, Abstract protocol for all LLM backend adapters., Probe provider connectivity, authentication, and available models., build_default_router(), Any, BaseModel, Construct a default ModelRouter from application settings. (+2 more)

### Community 95 - "acip/errors.py"
Cohesion: 0.21
Nodes (9): Exception, Check whether the key is within rate limits; increments counter if allowed.…, ACIPError, AgentError, PayloadTooLargeError, Any, RateLimitExceededError, Typed application errors. Each error carries an HTTP status and a stable… (+1 more)

### Community 96 - "Investigation"
Cohesion: 0.14
Nodes (15): Plan, Planner, Protocol, Investigation planning. A plan is an ordered list of :class:`Task`, each naming…, An ordered set of tasks plus the reason the shape was chosen., Chooses which agents run, in what order, and why., Rule-based planner: reproducible, and the control condition for the study.…, StaticPlanner (+7 more)

### Community 97 - "HypothesisDraft"
Cohesion: 0.22
Nodes (10): FindingEvidenceDraft, HypothesisDraft, BaseModel, A citation connecting evidence to a finding with a supporting or contradicting…, A competing candidate explanation under evaluation (Invariant G3)., test_finding_evidence_draft_roles(), test_hypothesis_draft_invariant_g3_refutation_required(), test_hypothesis_draft_valid() (+2 more)

### Community 98 - "delete_investigation"
Cohesion: 0.16
Nodes (15): alias, delete, description, ge, le, MAX_EVIDENCE_PAGE, Query, delete_investigation() (+7 more)

### Community 99 - "ModelExecution"
Cohesion: 0.27
Nodes (9): ModelExecutionDraft, Structured record of an LLM call for experimental tracking., Record an immutable LLM execution trace., ModelExecution, Phase 6 schema scaffolding: audited execution trace of LLM invocations.…, FinishReason, LLM completion termination reason., test_model_execution_append_only() (+1 more)

### Community 101 - "db/base.py"
Cohesion: 0.29
Nodes (7): Dialect, datetime, Declarative base and portable column types. The schema deliberately avoids…, Store timezone-aware datetimes as UTC and read them back aware. Rejects naive…, Timezone-aware current time. Used as a column default., UTCDateTime, utcnow()

### Community 102 - "AgentRegistry"
Cohesion: 0.22
Nodes (3): AgentRegistry, Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint.

### Community 103 - "get_evidence_provenance"
Cohesion: 0.25
Nodes (9): get_evidence_provenance(), get_investigation_progress(), get_report(), CurrentUser, get, UUID, Compute real-time progress metrics for the investigation., Resolve one observation to the tool, arguments, agent and artifact behind it. (+1 more)

### Community 104 - "test_triage_agent_auth_attack_representative_case"
Cohesion: 0.10
Nodes (37): Deterministic rule-based triage used when model router is unavailable., EvidenceGap, ExtractedEntity, IndicatorAssessment, InputClassification, PlannedTaskProposal, BaseModel, Structured output schemas for the Triage Agent. (+29 more)

### Community 105 - "cli.py"
Cohesion: 0.09
Nodes (36): ArgumentParser, Config, bootstrap(), Application bootstrap. Migrates the schema to head and, outside production,…, Prepare storage and seed development data., Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), _backup() (+28 more)

### Community 106 - "OrchestratorAgent"
Cohesion: 0.19
Nodes (14): _load_artifacts(), _load_investigation(), OrchestratorAgent, AsyncSession, UUID, First functional Orchestrator Agent. Coordinates the investigation lifecycle:…, Retrieve the in-memory state of an active or recent investigation., Run the full investigation lifecycle. Never raises for task-level failures. (+6 more)

### Community 107 - "test_investigation_lifecycle.py"
Cohesion: 0.36
Nodes (8): investigator_auth(), AsyncClient, FastAPI, fixture, Concurrent start requests elect exactly one starter; the rest receive 409…, test_investigation_concurrent_start_requests(), test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 108 - "models.py"
Cohesion: 0.13
Nodes (15): DeclarativeBase, Mapped, Base, Base class for all ORM models., AuditLog, _forbid_mutation(), Hypothesis, Any (+7 more)

### Community 109 - "_coerce"
Cohesion: 0.20
Nodes (8): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, Merge the ambient context into each record., One JSON object per line, suitable for ingestion by a log pipeline., Human-readable single-line format for local development.

### Community 110 - "test_cyber_reasoning.py"
Cohesion: 0.43
Nodes (6): asyncio, Unit tests for the CyberReasoningProvider., test_cyber_reasoning_malware_hash(), test_cyber_reasoning_probe(), test_cyber_reasoning_ssh_brute_force(), test_cyber_reasoning_web_server_attack()

### Community 111 - "ratelimit.py"
Cohesion: 0.40
Nodes (4): Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, FastAPI dependency for rate limiting endpoints by client IP.

### Community 112 - "test_mitre_mapping_agent_maps_rules_to_techniques"
Cohesion: 0.67
Nodes (3): asyncio, Path, test_mitre_mapping_agent_maps_rules_to_techniques()

### Community 114 - "test_triage_agent.py"
Cohesion: 0.20
Nodes (9): Test double that returns deterministic pre-configured responses or simulated…, ReplayProvider, _make_triage_router(), Unit and integration tests for the model-driven Triage Agent., Construct a test ModelRouter backed by ReplayProvider., Representative Case 5: Model output schema repair loop in Triage., When ACIP_ENABLE_LLM_TRIAGE=False (default), TriageAgent bypasses ModelRouter., test_triage_agent_flag_disabled_uses_deterministic_fallback() (+1 more)

### Community 115 - "llm/contracts.py"
Cohesion: 0.15
Nodes (16): LLMRequest, LLMResponse, LLMUsage, ProviderAvailability, Contracts and data models for model-provider abstraction. Defines the message…, Request payload sent to an LLM provider., Token accounting telemetry returned by a provider., Standardized response received from an LLM provider. (+8 more)

### Community 117 - "ssrf.py"
Cohesion: 0.12
Nodes (17): AsyncNetworkStream, AutoBackend, SOCKET_OPTION, _PinnedIPNetworkBackend, PinnedIPTransport, Any, SSRF (Server-Side Request Forgery) protection subsystem. Enforces strict…, Network backend pinning TCP socket connections to a pre-validated IP address. (+9 more)

### Community 118 - "TriageAgent"
Cohesion: 0.33
Nodes (6): _path(), Any, Perform structured model-driven triage analysis with fallback to heuristics., Classifies the submission, extracts entities, assesses indicators, and plans…, _read_artifact_snippet(), TriageAgent

### Community 120 - "ToolRun"
Cohesion: 0.08
Nodes (32): One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun, Any, AsyncSession, BaseModel, datetime, Path, UUID (+24 more)

## Knowledge Gaps
- **61 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+56 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **28 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `EvidenceStore` connect `EvidenceStore` to `Evidence`, `TimeConfidence`, `types.py`, `investigations.py`, `AgentContext`, `AssertionClass`, `orchestration/orchestrator.py`, `EvidenceDraft`, `Severity`, `.session`, `Artifact`, `store.py`, `GroundingError`, `RunStatus`, `HypothesisDraft`, `delete_investigation`, `ModelExecution`, `test_triage_agent_auth_attack_representative_case`, `OrchestratorAgent`, `models.py`, `test_mitre_mapping_agent_maps_rules_to_techniques`, `test_triage_agent.py`, `ToolRun`?**
  _High betweenness centrality (0.048) - this node is a cross-community bridge._
- **Why does `Database` connect `Database` to `TimeConfidence`, `InvestigationRunner`, `types.py`, `backup.py`, `conftest.py`, `Role`, `AssertionClass`, `orchestration/orchestrator.py`, `EvidenceDraft`, `app.py`, `test_historical_migration_0002_to_0003_populated_upgrade`, `ArtifactKind`, `get_session`, `.session`, `Artifact`, `store.py`, `EvidenceStore`, `Investigation`, `ModelExecution`, `test_triage_agent_auth_attack_representative_case`, `cli.py`, `OrchestratorAgent`, `test_mitre_mapping_agent_maps_rules_to_techniques`, `test_triage_agent.py`, `ToolRun`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **Why does `Settings` connect `Settings` to `Database`, `backup.py`, `AgentContext`, `conftest.py`, `Role`, `orchestration/orchestrator.py`, `ValueError`, `app.py`, `test_historical_migration_0002_to_0003_populated_upgrade`, `ArtifactKind`, `get_session`, `Artifact`, `RunStatus`, `Investigation`, `test_triage_agent_auth_attack_representative_case`, `cli.py`, `OrchestratorAgent`, `test_investigation_lifecycle.py`, `test_mitre_mapping_agent_maps_rules_to_techniques`, `test_triage_agent.py`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **Are the 56 inferred relationships involving `Database` (e.g. with `build_services()` and `Services`) actually correct?**
  _`Database` has 56 INFERRED edges - model-reasoned connections that need verification._
- **Are the 50 inferred relationships involving `Severity` (e.g. with `LogAnalysisAgent` and `MitreMappingAgent`) actually correct?**
  _`Severity` has 50 INFERRED edges - model-reasoned connections that need verification._
- **Are the 47 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 47 INFERRED edges - model-reasoned connections that need verification._
- **Are the 44 inferred relationships involving `EvidenceStore` (e.g. with `AgentContext` and `list_evidence()`) actually correct?**
  _`EvidenceStore` has 44 INFERRED edges - model-reasoned connections that need verification._