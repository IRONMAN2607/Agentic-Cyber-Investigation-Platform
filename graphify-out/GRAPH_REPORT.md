# Graph Report - AACIP  (2026-08-26)

## Corpus Check
- 120 files · ~61,241 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1015 nodes · 2676 edges · 105 communities (73 shown, 32 thin omitted)
- Extraction: 82% EXTRACTED · 18% INFERRED · 0% AMBIGUOUS · INFERRED: 493 edges (avg confidence: 0.95)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `c55a7d79`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- logging.py
- ValidationError
- cli.py
- LinuxAuthLogParser
- InvestigationRunner
- Role
- investigations.py
- RunStatus
- ReportAgent
- InvestigationStatus
- .extract
- errors.py
- log_analysis.py
- run_subprocess_sandboxed
- types.py
- conftest.py
- Grounding Invariants G0-G4
- tokens.py
- tools/runner.py
- EvidenceStore
- get_session
- CLAUDE.md
- passwords.py
- system.py
- agentrouter
- Artifact
- HypothesisDraft
- db/base.py
- orchestrator.py
- mitre.py
- app.js
- env.py
- Three-Transaction Orchestrator
- Settings
- ToolAdapter Base Contract
- auth_log_parser Tool
- Argon2id and HS256 JWT Security
- Phase 5 Graph Entities & Edges Schema
- Phase 1' Verification Retrofit
- Decision: PostgreSQL Relational Graph vs Neo4j
- app.py
- test_types.py
- AdaptivePlanner
- Reporting Agent
- FastAPI REST API
- Milestone 1 (M1) Vertical Slice
- Localhost Single-User Deployment Boundary
- Two-Tier Conservative Entity Resolution
- Provider Error Taxonomy and Fallback Policy
- ReplayProvider Test Double
- RQ5 Analyst Study Scoping Decision
- test_auth.py
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
- _get_python_files
- .opencode/opencode.json
- test_endpoint_role_matrix
- test_capabilities.py
- test_auth_log_incident_scenario
- test_upload_security.py
- graphify.js
- test_health
- test_investigation_crud_and_lifecycle
- AGENTS.md
- AgentContext
- session.py
- models.py
- Severity
- reporting.py
- .add_finding
- deps.py
- Evidence
- auth.py
- list_investigations
- ToolRegistry
- test_orchestrator.py
- ._strip
- test_investigation_lifecycle.py
- .engine

## God Nodes (most connected - your core abstractions)
1. `EvidenceStore` - 49 edges
2. `Investigation` - 43 edges
3. `Database` - 43 edges
4. `Severity` - 43 edges
5. `Role` - 39 edges
6. `Settings` - 35 edges
7. `AgentContext` - 33 edges
8. `AssertionClass` - 33 edges
9. `Orchestrator` - 32 edges
10. `Evidence` - 31 edges

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

## Communities (105 total, 32 thin omitted)

### Community 0 - "logging.py"
Cohesion: 0.13
Nodes (15): Logger, LogRecord, Audit trail writes. Security-relevant actions are recorded in an append-only…, _coerce(), ConsoleFormatter, ContextFilter, get_logger(), JSONFormatter (+7 more)

### Community 1 - "ValidationError"
Cohesion: 0.07
Nodes (43): patch, Path, Safe artifact intake. Uploaded artifacts are untrusted by definition — in later…, Remove group/other access and any execute bit where the OS supports it., Result of a successful intake., Reduce a client-supplied filename to a safe display label. The result is used…, Consume ``chunks`` into content-addressed storage under ``dest_dir``. Raises…, _restrict_permissions() (+35 more)

### Community 2 - "cli.py"
Cohesion: 0.21
Nodes (12): ArgumentParser, build_parser(), _capabilities(), _create_user(), _init(), main(), Command-line entry point. Provides the operational commands a fresh checkout…, Print the real capability set, probed rather than assumed. (+4 more)

### Community 3 - "LinuxAuthLogParser"
Cohesion: 0.22
Nodes (11): Match, AuthLogParserArgs, LinuxAuthLogParser, Any, BaseModel, datetime, Parsing options. Note the absence of any path argument., Parses Linux authentication logs into normalised auth events. (+3 more)

### Community 4 - "InvestigationRunner"
Cohesion: 0.16
Nodes (9): InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle., Cancel an in-flight investigation task., Await every scheduled investigation. Used by tests and shutdown. (+1 more)

### Community 5 - "Role"
Cohesion: 0.23
Nodes (13): CurrentUser, require_admin(), require_investigator(), Application bootstrap. Creates the schema and, outside production, seeds an…, Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), has_role(), Role-based authorization. Roles are ordered: an admin can do anything an… (+5 more)

### Community 6 - "investigations.py"
Cohesion: 0.14
Nodes (32): get_investigation_detail(), Investigation lifecycle endpoints., Everything a workspace view needs, in one round trip., AgentRunResponse, ArtifactResponse, AuditLogResponse, ErrorResponse, EvidenceResponse (+24 more)

### Community 7 - "RunStatus"
Cohesion: 0.18
Nodes (11): AgentResult, Any, BaseModel, Structured outcome of one agent execution., Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure., _path(), Any, Triage agent. Extracts and inventories indicators from the investigation target… (+3 more)

### Community 8 - "ReportAgent"
Cohesion: 0.23
Nodes (10): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, RiskAssessment, AgentRun, One execution of one agent. Part of the investigation execution trace. (+2 more)

### Community 9 - "InvestigationStatus"
Cohesion: 0.13
Nodes (14): description, File, Form, _chunks(), Accept an artifact into content-addressed quarantine storage., Stream an upload without buffering it whole., upload_artifact(), ArtifactKind (+6 more)

### Community 10 - ".extract"
Cohesion: 0.13
Nodes (15): IPv4Address, IPv6Address, _context(), IOCExtractorArgs, _ip_scope(), Any, BaseModel, Extract indicators from ``text``. Directly testable. (+7 more)

### Community 11 - "errors.py"
Cohesion: 0.10
Nodes (19): Exception, Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, Thread-safe sliding window rate limiter., Check whether the key is within rate limits; increments counter if allowed.…, Clear all rate limit history (useful in tests)., FastAPI dependency for rate limiting endpoints by client IP. (+11 more)

### Community 12 - "log_analysis.py"
Cohesion: 0.16
Nodes (22): Log analysis agent. Parses authentication logs with a deterministic tool, then…, AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after() (+14 more)

### Community 13 - "run_subprocess_sandboxed"
Cohesion: 0.26
Nodes (11): ToolExecutionError, Path, Tier 1 tool execution sandbox. Executes external tools as isolated subprocesses…, Execute a command in Tier 1 subprocess isolation. Guarantees: - Never uses…, run_subprocess_sandboxed(), SandboxResult, Path, test_sandbox_empty_args_rejected() (+3 more)

### Community 14 - "types.py"
Cohesion: 0.11
Nodes (23): EntityRef, EvidenceDraft, normalize_entity_value(), datetime, field_validator, Evidence and finding contracts. Agents and tools exchange these Pydantic models…, Stable digest of the observation, used to deduplicate evidence. Covers only…, Canonicalise an entity value so the same thing has one representation. Entity… (+15 more)

### Community 15 - "conftest.py"
Cohesion: 0.35
Nodes (11): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+3 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "tokens.py"
Cohesion: 0.21
Nodes (16): create_access_token(), decode_access_token(), BaseModel, datetime, UUID, JWT access tokens. Short-lived bearer tokens signed with HS256. Refresh tokens…, Validated token claims., Decode and validate a token, or raise :class:`AuthenticationError`. (+8 more)

### Community 18 - "tools/runner.py"
Cohesion: 0.10
Nodes (30): Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, read_text(), A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolUnavailableError, Linux authentication log parser. A deterministic, dependency-free parser for…, NoArgs, ABC (+22 more)

### Community 19 - "EvidenceStore"
Cohesion: 0.17
Nodes (29): FindingDraft, A claim an agent wishes to record. The store validates this against the…, EvidenceStore, Writes evidence and findings for a single investigation., Investigation, Database, Owns the engine and session factory for one database URL., Yield a session, committing on success and rolling back on error. (+21 more)

### Community 20 - "get_session"
Cohesion: 0.13
Nodes (36): delete, Investigator, LoadedInvestigation, get_session(), One transaction per request, committed on a clean response., cancel_investigation(), create_investigation(), create_task() (+28 more)

### Community 22 - "passwords.py"
Cohesion: 0.26
Nodes (10): hash_password(), needs_rehash(), Password hashing. Argon2id via ``argon2-cffi``, which is the current OWASP…, Return whether the password matches. Never raises on a bad password., True when the hash was produced with weaker parameters than current., verify_password(), test_needs_rehash(), test_password_hash_and_verify() (+2 more)

### Community 23 - "system.py"
Cohesion: 0.14
Nodes (19): Admin, admin_capabilities(), capabilities(), health(), AsyncSession, Depends, get, Health and capability endpoints. ``/capabilities`` is a first-class endpoint,… (+11 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "Artifact"
Cohesion: 0.15
Nodes (14): build_default_registry(), The agents available in this milestone. Phase 2 adds the network, endpoint,…, Plan, Planner, Protocol, Investigation planning. A plan is an ordered list of :class:`Task`, each naming…, An ordered set of tasks plus the reason the shape was chosen., Chooses which agents run, in what order, and why. (+6 more)

### Community 26 - "HypothesisDraft"
Cohesion: 0.16
Nodes (15): FindingEvidenceDraft, HypothesisDraft, HypothesisGapDraft, ModelExecutionDraft, BaseModel, A citation connecting evidence to a finding with a supporting or contradicting…, A competing candidate explanation under evaluation (Invariant G3)., A declared gap in evidence preventing resolution of a hypothesis. (+7 more)

### Community 27 - "db/base.py"
Cohesion: 0.29
Nodes (7): Dialect, datetime, Declarative base and portable column types. The schema deliberately avoids…, Store timezone-aware datetimes as UTC and read them back aware. Rejects naive…, Timezone-aware current time. Used as a column default., UTCDateTime, utcnow()

### Community 28 - "orchestrator.py"
Cohesion: 0.18
Nodes (16): _derive_status(), InvestigationOutcome, _load_artifacts(), _load_investigation(), Orchestrator, AsyncSession, UUID, Investigation orchestration. Executes a plan task by task, recording an… (+8 more)

### Community 29 - "mitre.py"
Cohesion: 0.29
Nodes (9): AttackTechnique, get_attack_technique(), map_rule_to_technique(), MITRE ATT&CK catalog and mapping validation. Enforces Invariant G7: no finding…, Lookup a technique in the catalog. Enforces Invariant G7: raises GroundingError…, Deterministically map a detection rule to its ATT&CK technique., test_mitre_catalog_version_and_contents(), test_mitre_deterministic_rule_mapping() (+1 more)

### Community 30 - "app.js"
Cohesion: 0.56
Nodes (8): api(), checkCurrentUser(), escapeHtml(), loadInvestigations(), renderWorkspace(), selectInvestigation(), setAuth(), showLogin()

### Community 31 - "env.py"
Cohesion: 0.28
Nodes (8): Connection, do_run_migrations(), Run migrations in 'offline' mode., In this scenario we need to create an Engine and associate a connection with…, Run migrations in 'online' mode., run_async_migrations(), run_migrations_offline(), run_migrations_online()

### Community 32 - "Three-Transaction Orchestrator"
Cohesion: 0.33
Nodes (6): Three-Transaction Orchestrator, Decision: Custom Asyncio Orchestration, Append-Only Table Enforcement, Content-Addressed Storage and In-Stream Size Enforcement, Security Controls Matrix (16 Controls), Assets and Adversary Taxonomy (A1-A6)

### Community 33 - "Settings"
Cohesion: 0.16
Nodes (9): BaseSettings, model_validator, field_validator, Application configuration. All configuration arrives from the environment (or a…, Create runtime directories. Called once at startup., Resolved application settings., Require a real secret in production; generate an ephemeral one otherwise. A…, Settings (+1 more)

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

### Community 40 - "app.py"
Cohesion: 0.18
Nodes (13): RequestValidationError, build_services(), create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and…, Strip non-JSON values (e.g. uploaded bytes, exception objects in ctx) out of…, Compose the object graph. Pure wiring, no I/O. (+5 more)

### Community 41 - "test_types.py"
Cohesion: 0.33
Nodes (5): test_assertion_class_values(), test_investigation_status_terminal(), test_role_values(), test_severity_ordering(), test_time_confidence_values()

### Community 51 - "test_auth.py"
Cohesion: 0.60
Nodes (4): AsyncClient, test_auth_login_invalid_password(), test_auth_login_success(), test_auth_me_endpoint()

### Community 72 - "_get_python_files"
Cohesion: 0.80
Nodes (4): _get_python_files(), Path, test_no_direct_llm_sdk_imports_in_agents(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 74 - "test_endpoint_role_matrix"
Cohesion: 0.50
Nodes (3): AsyncClient, parametrize, test_endpoint_role_matrix()

### Community 75 - "test_capabilities.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_admin_capabilities_access_control(), test_public_capabilities()

### Community 76 - "test_auth_log_incident_scenario"
Cohesion: 0.67
Nodes (3): AsyncClient, test_auth_log_incident_scenario(), test_clean_log_scenario()

### Community 77 - "test_upload_security.py"
Cohesion: 0.67
Nodes (3): AsyncClient, test_upload_empty_file_rejected(), test_upload_path_traversal_sanitized()

### Community 83 - "AgentContext"
Cohesion: 0.31
Nodes (6): AgentContext, Everything an agent is given for one execution., LogAnalysisAgent, Any, Project stored evidence into the rule engine's view type., Parses authentication logs and applies deterministic detection rules.

### Community 90 - "session.py"
Cohesion: 0.14
Nodes (9): async_sessionmaker, Any, AsyncSession, Async engine and session management. Exposed as a class rather than module…, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., Create the schema. M1 uses ``create_all`` deliberately: there is no deployed…, Strip credentials before a URL reaches the logs., _redact() (+1 more)

### Community 91 - "models.py"
Cohesion: 0.09
Nodes (25): DeclarativeBase, Mapped, Append-only evidence store and grounding enforcement. This module is where the…, Record an immutable LLM execution trace., Base, Base class for all ORM models., AuditLog, FindingEvidence (+17 more)

### Community 92 - "Severity"
Cohesion: 0.14
Nodes (13): assess(), Protocol, Deterministic risk scoring. Severity and risk are computed from findings by a…, Structural type covering both ORM findings and drafts., Roll findings up into an investigation-level severity and risk score., ScorableFinding, Finding, A claim about the investigation, bound to the evidence supporting it. (+5 more)

### Community 93 - "reporting.py"
Cohesion: 0.15
Nodes (11): Agent, ABC, Agent contract. Agents receive a typed context and return a typed result (spec…, Base class for all agents., AgentRegistry, Agent registry. Agents are looked up by name or capability rather than imported…, Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint. (+3 more)

### Community 94 - ".add_finding"
Cohesion: 0.18
Nodes (8): AsyncSession, UUID, Validate a claim against the grounding invariants and persist it., Validate a hypothesis and persist it with supporting/contradicting links., Record an explicit knowledge gap preventing hypothesis resolution., Fetch cited evidence, enforcing G0., HypothesisGap, Missing evidence or tool capability needed to decide a hypothesis.

### Community 95 - "deps.py"
Cohesion: 0.18
Nodes (18): _bearer, HTTPAuthorizationCredentials, get_current_user(), get_investigation(), get_services(), get_settings_dep(), AsyncSession, Depends (+10 more)

### Community 96 - "Evidence"
Cohesion: 0.22
Nodes (5): Persist drafts, skipping observations already recorded. Deduplication is by…, Evidence, An immutable observation with full provenance. ``tool_run_id`` being non-NULL…, Outcome of one audited tool call., ToolInvocation

### Community 97 - "auth.py"
Cohesion: 0.21
Nodes (11): login(), me(), AsyncSession, CurrentUser, Depends, get, post, Authentication endpoints. (+3 more)

### Community 98 - "list_investigations"
Cohesion: 0.24
Nodes (10): alias, ge, le, Query, list_evidence(), list_investigations(), CurrentUser, List investigations with optional status and target_type filtering. (+2 more)

### Community 99 - "ToolRegistry"
Cohesion: 0.29
Nodes (3): A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry

### Community 101 - "test_orchestrator.py"
Cohesion: 0.36
Nodes (4): MockFailingAgent, MockPlanner, Any, test_orchestrator_failure_rollback()

### Community 103 - "test_investigation_lifecycle.py"
Cohesion: 0.43
Nodes (6): investigator_auth(), AsyncClient, FastAPI, fixture, test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

## Knowledge Gaps
- **61 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+56 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **32 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Severity` to `list_investigations`, `test_orchestrator.py`, `investigations.py`, `RunStatus`, `ReportAgent`, `InvestigationStatus`, `test_types.py`, `log_analysis.py`, `test_auth_log_incident_scenario`, `types.py`, `AgentContext`, `EvidenceStore`, `models.py`, `reporting.py`?**
  _High betweenness centrality (0.039) - this node is a cross-community bridge._
- **Why does `EvidenceStore` connect `EvidenceStore` to `Evidence`, `ValidationError`, `orchestrator.py`, `types.py`, `tools/runner.py`, `AgentContext`, `HypothesisDraft`, `models.py`, `Severity`, `reporting.py`, `.add_finding`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **Why does `Database` connect `EvidenceStore` to `cli.py`, `InvestigationRunner`, `Role`, `test_orchestrator.py`, `app.py`, `.engine`, `types.py`, `conftest.py`, `Artifact`, `session.py`, `orchestrator.py`, `deps.py`?**
  _High betweenness centrality (0.031) - this node is a cross-community bridge._
- **Are the 30 inferred relationships involving `EvidenceStore` (e.g. with `AgentContext` and `EvidenceDraft`) actually correct?**
  _`EvidenceStore` has 30 INFERRED edges - model-reasoned connections that need verification._
- **Are the 27 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 27 INFERRED edges - model-reasoned connections that need verification._
- **Are the 24 inferred relationships involving `Database` (e.g. with `build_services()` and `Services`) actually correct?**
  _`Database` has 24 INFERRED edges - model-reasoned connections that need verification._
- **Are the 29 inferred relationships involving `Severity` (e.g. with `LogAnalysisAgent` and `ReportAgent`) actually correct?**
  _`Severity` has 29 INFERRED edges - model-reasoned connections that need verification._