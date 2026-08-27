# Graph Report - AACIP  (2026-08-27)

## Corpus Check
- 123 files · ~65,904 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1092 nodes · 2894 edges · 105 communities (75 shown, 30 thin omitted)
- Extraction: 80% EXTRACTED · 20% INFERRED · 0% AMBIGUOUS · INFERRED: 566 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `c5d6585d`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- _coerce
- ValidationError
- _build_chain
- TimeConfidence
- InvestigationRunner
- models.py
- investigations.py
- triage.py
- Evidence
- types.py
- .extract
- ACIPError
- log_analysis.py
- errors.py
- contracts.py
- conftest.py
- Grounding Invariants G0-G4
- Role
- ioc_extractor.py
- GroundingError
- get_session
- CLAUDE.md
- cli.py
- system.py
- agentrouter
- Investigation
- HypothesisDraft
- db/base.py
- Orchestrator
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
- ToolResult
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
- _get_python_files
- .opencode/opencode.json
- ModelExecution
- delete_investigation
- ScorableFinding
- .create_all
- graphify.js
- test_health
- me
- AGENTS.md
- AgentContext
- Database
- EvidenceStore
- Severity
- reporting.py
- _chunks
- deps.py
- orchestrator.py
- login
- list_evidence
- ToolRegistry
- _sqlite_pragmas
- ._strip
- test_investigation_lifecycle.py
- _forbid_bulk_dml

## God Nodes (most connected - your core abstractions)
1. `EvidenceStore` - 55 edges
2. `Database` - 54 edges
3. `Investigation` - 46 edges
4. `Severity` - 44 edges
5. `Evidence` - 43 edges
6. `Role` - 39 edges
7. `Settings` - 35 edges
8. `AgentContext` - 34 edges
9. `AssertionClass` - 34 edges
10. `Orchestrator` - 32 edges

## Surprising Connections (you probably didn't know these)
- `test_investigation_status_terminal()` --uses--> `InvestigationStatus`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_severity_ordering()` --uses--> `Severity`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_assertion_class_values()` --uses--> `AssertionClass`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_time_confidence_values()` --uses--> `TimeConfidence`  [INFERRED]
  tests/unit/test_types.py → src/acip/types.py
- `test_orchestrator_failure_rollback()` --uses--> `AgentRegistry`  [INFERRED]
  tests/integration/test_orchestrator.py → src/acip/agents/registry.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **End-to-End Evidence Provenance Pipeline** — docs_tools_tool_adapter_contract, docs_evidence_model_evidence_record, docs_evidence_model_traceability_chain, docs_frontend_provenance_ui_rules, docs_evidence_graph_relationships [EXTRACTED 1.00]
- **Experimental Evaluation and Ablation Framework** — docs_experiments_comparison_conditions, docs_experiments_ablations, docs_experiments_evaluation_metrics, docs_research_central_question, docs_model_abstraction_replay_double [EXTRACTED 1.00]
- **Grounding Invariants Enforcement Subsystem** — docs_evidence_model_grounding_invariants, docs_agents_agent_contract, docs_model_abstraction_core_llm, docs_experiments_evaluation_metrics, docs_research_central_question [EXTRACTED 1.00]

## Communities (105 total, 30 thin omitted)

### Community 0 - "_coerce"
Cohesion: 0.18
Nodes (9): LogRecord, _coerce(), ConsoleFormatter, ContextFilter, JSONFormatter, Any, Merge the ambient context into each record., One JSON object per line, suitable for ingestion by a log pipeline. (+1 more)

### Community 1 - "ValidationError"
Cohesion: 0.05
Nodes (54): Collection, ColumnElement, patch, _evidence_after(), _evidence_cursor(), EvidencePage, One page of evidence in timeline order, with a cursor for the next. The sort…, Every matching row up to ``cap``, and whether the cap cut the read short.… (+46 more)

### Community 2 - "_build_chain"
Cohesion: 0.15
Nodes (18): _build_chain(), ChainIds, AsyncSession, UUID, Provenance survives the deletion of everything it points at. Regression tests…, Whether the row still carries the G1 deterministic-origin marker., The defect this file exists for: SET NULL used to unground every citing FACT., Evidence must stay traceable to the bytes it came from. (+10 more)

### Community 3 - "TimeConfidence"
Cohesion: 0.29
Nodes (8): Match, LinuxAuthLogParser, Any, datetime, Parses Linux authentication logs into normalised auth events., Parse log text. Separated from :meth:`execute` so it is directly testable., How much to trust an evidence timestamp. Log formats such as syslog omit the…, TimeConfidence

### Community 4 - "InvestigationRunner"
Cohesion: 0.16
Nodes (9): InvestigationRunner, UUID, Mark orphan running investigations as interrupted on startup., Record an orchestrator-level crash on the investigation row., Schedules investigations with bounded concurrency., Schedule an investigation and return its task handle., Cancel an in-flight investigation task., Await every scheduled investigation. Used by tests and shutdown. (+1 more)

### Community 5 - "models.py"
Cohesion: 0.16
Nodes (16): DeclarativeBase, Mapped, Base, Base class for all ORM models., AuditLog, _forbid_mutation(), Any, UUID (+8 more)

### Community 6 - "investigations.py"
Cohesion: 0.09
Nodes (49): get_evidence_provenance(), get_investigation_detail(), Investigation lifecycle endpoints., Everything a workspace view needs, in one round trip., Resolve one observation to the tool, arguments, agent and artifact behind it., AgentRunResponse, ArtifactResponse, AuditLogResponse (+41 more)

### Community 7 - "triage.py"
Cohesion: 0.31
Nodes (7): _path(), Any, Triage agent. Extracts and inventories indicators from the investigation target…, Classifies the submission and inventories its indicators., TriageAgent, AgentCapability, What an agent can do. The planner selects agents by capability rather than by…

### Community 8 - "Evidence"
Cohesion: 0.23
Nodes (7): _cell(), Any, Produces the investigation report and the risk roll-up., Make text safe for a Markdown table cell and single-line contexts., ReportAgent, Evidence, An immutable observation with full provenance. ``tool_run_id`` being non-NULL…

### Community 9 - "types.py"
Cohesion: 0.29
Nodes (4): InvestigationOutcome, InvestigationStatus, Shared enumerations. These are the vocabulary of the platform. They are stored…, test_recovery_interrupted_investigation()

### Community 10 - ".extract"
Cohesion: 0.13
Nodes (15): IPv4Address, IPv6Address, _context(), IOCExtractorArgs, _ip_scope(), Any, BaseModel, Extract indicators from ``text``. Directly testable. (+7 more)

### Community 11 - "ACIPError"
Cohesion: 0.10
Nodes (17): Exception, Request, rate_limit(), Sliding-window rate limiter for sensitive endpoints. Provides deterministic…, Thread-safe sliding window rate limiter., Check whether the key is within rate limits; increments counter if allowed.…, Clear all rate limit history (useful in tests)., FastAPI dependency for rate limiting endpoints by client IP. (+9 more)

### Community 12 - "log_analysis.py"
Cohesion: 0.16
Nodes (22): Log analysis agent. Parses authentication logs with a deterministic tool, then…, AuthEventView, DetectionHit, evaluate_auth_rules(), _evaluate_privilege_escalation(), _evaluate_user_enumeration(), _find_failure_bursts(), _first_success_after() (+14 more)

### Community 13 - "errors.py"
Cohesion: 0.20
Nodes (14): Typed application errors. Each error carries an HTTP status and a stable…, A tool adapter failed. Recorded against the tool run, not hidden., ToolError, ToolExecutionError, Path, Tier 1 tool execution sandbox. Executes external tools as isolated subprocesses…, Execute a command in Tier 1 subprocess isolation. Guarantees: - Never uses…, run_subprocess_sandboxed() (+6 more)

### Community 14 - "contracts.py"
Cohesion: 0.13
Nodes (21): EntityRef, EvidenceDraft, normalize_entity_value(), datetime, field_validator, Evidence and finding contracts. Agents and tools exchange these Pydantic models…, Stable digest of the observation, used to deduplicate evidence. Covers only…, Canonicalise an entity value so the same thing has one representation. Entity… (+13 more)

### Community 15 - "conftest.py"
Cohesion: 0.35
Nodes (11): app(), auth_headers(), client(), database(), AsyncClient, FastAPI, fixture, Path (+3 more)

### Community 16 - "Grounding Invariants G0-G4"
Cohesion: 0.11
Nodes (18): Agent Contract and AgentContext, Uniform Error Envelope and ACIPError, Server-Sent Events Progress Reporting, Phase 7 Hypotheses Schema, Phase 6 LLM Calls Observability Schema, Assertion Taxonomy (FACT, INFERENCE, HYPOTHESIS, UNKNOWN), Grounding Invariants G0-G4, Four Ablation Experiments (Invariants, Graph, Multi-Agent, Planning) (+10 more)

### Community 17 - "Role"
Cohesion: 0.06
Nodes (46): has_role(), Role-based authorization. Roles are ordered: an admin can do anything an…, Raise :class:`AuthorizationError` unless ``actual`` satisfies ``required``., require_role(), create_access_token(), decode_access_token(), BaseModel, datetime (+38 more)

### Community 18 - "ioc_extractor.py"
Cohesion: 0.19
Nodes (14): Linux authentication log parser. A deterministic, dependency-free parser for…, ABC, Tool adapter contract. A tool is the only thing in the platform allowed to…, Honest report of whether a tool can actually run right now. Surfaced through…, Base class for all tool adapters., Report runtime availability. In-process adapters are always available. Adapters…, ToolAdapter, ToolAvailability (+6 more)

### Community 19 - "GroundingError"
Cohesion: 0.31
Nodes (12): GroundingError, Raised when a claim violates an evidence-grounding invariant. This is a…, _create_tool_run(), _draft_evidence(), AsyncSession, UUID, test_grounding_invariant_cross_investigation_isolated(), test_grounding_invariant_g1_fact_requires_deterministic_tool_evidence() (+4 more)

### Community 20 - "get_session"
Cohesion: 0.11
Nodes (42): _bearer, File, Form, HTTPAuthorizationCredentials, Investigator, LoadedInvestigation, get_current_user(), get_services() (+34 more)

### Community 22 - "cli.py"
Cohesion: 0.13
Nodes (23): ArgumentParser, bootstrap(), Application bootstrap. Creates the schema and, outside production, seeds an…, Prepare storage and seed development data., Create the bootstrap admin if it does not already exist. Returns ``None`` when…, seed_admin(), build_parser(), _create_user() (+15 more)

### Community 23 - "system.py"
Cohesion: 0.15
Nodes (17): Admin, admin_capabilities(), capabilities(), health(), AsyncSession, Depends, get, Health and capability endpoints. ``/capabilities`` is a first-class endpoint,… (+9 more)

### Community 24 - "agentrouter"
Cohesion: 0.17
Nodes (11): models, name, npm, options, name, model, gpt-5.6.sol, baseURL (+3 more)

### Community 25 - "Investigation"
Cohesion: 0.14
Nodes (15): Plan, Planner, Protocol, Investigation planning. A plan is an ordered list of :class:`Task`, each naming…, An ordered set of tasks plus the reason the shape was chosen., Chooses which agents run, in what order, and why., Rule-based planner: reproducible, and the control condition for the study.…, StaticPlanner (+7 more)

### Community 26 - "HypothesisDraft"
Cohesion: 0.19
Nodes (12): FindingEvidenceDraft, HypothesisDraft, HypothesisGapDraft, BaseModel, A citation connecting evidence to a finding with a supporting or contradicting…, A competing candidate explanation under evaluation (Invariant G3)., A declared gap in evidence preventing resolution of a hypothesis., test_finding_evidence_draft_roles() (+4 more)

### Community 27 - "db/base.py"
Cohesion: 0.29
Nodes (7): Dialect, datetime, Declarative base and portable column types. The schema deliberately avoids…, Store timezone-aware datetimes as UTC and read them back aware. Rejects naive…, Timezone-aware current time. Used as a column default., UTCDateTime, utcnow()

### Community 28 - "Orchestrator"
Cohesion: 0.26
Nodes (12): _load_artifacts(), _load_investigation(), Orchestrator, AsyncSession, UUID, Plans and executes one investigation at a time., Run the full investigation. Never raises for task-level failures., TaskOutcome (+4 more)

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
Cohesion: 0.12
Nodes (20): RequestValidationError, build_default_registry(), The agents available in this milestone. Phase 2 adds the network, endpoint,…, build_services(), create_app(), _install_error_handlers(), FastAPI, FastAPI application factory. ``create_app`` takes optional settings and… (+12 more)

### Community 41 - "ToolResult"
Cohesion: 0.16
Nodes (13): Read an artifact as text. Returns ``(text, lossy)``. Log files are frequently…, read_text(), AuthLogParserArgs, BaseModel, Parsing options. Note the absence of any path argument., NoArgs, BaseModel, Everything an adapter is permitted to know about its invocation. (+5 more)

### Community 51 - "0003_evidence_provenance_restrict.py"
Cohesion: 0.31
Nodes (10): _apply(), downgrade(), _evidence_table(), _llm_calls_table(), Append-only provenance foreign keys become RESTRICT Revision ID:…, The evidence table, parameterised by the FK behaviour under test., The llm_calls table, parameterised by the FK behaviour under test., _rebuild() (+2 more)

### Community 72 - "_get_python_files"
Cohesion: 0.57
Nodes (6): _get_python_files(), Path, A reserved key in ``extra`` raises KeyError only when the record is emitted.…, test_no_direct_llm_sdk_imports_in_agents(), test_no_reserved_logrecord_keys_in_log_extra(), test_no_shell_true_in_codebase()

### Community 73 - ".opencode/opencode.json"
Cohesion: 0.50
Nodes (3): plugin, $schema, .opencode/plugins/graphify.js

### Community 74 - "ModelExecution"
Cohesion: 0.27
Nodes (8): ModelExecutionDraft, Structured record of an LLM call for experimental tracking., Record an immutable LLM execution trace., ModelExecution, Audited execution trace of any LLM invocation (append-only research dataset).…, FinishReason, LLM completion termination reason., test_model_execution_draft()

### Community 75 - "delete_investigation"
Cohesion: 0.22
Nodes (9): delete, description, _append_only_counts(), delete_investigation(), UUID, Count the records a purge would destroy, before any of them are gone., Delete an investigation; destroying append-only records requires an explicit…, authorized_purge() (+1 more)

### Community 76 - "ScorableFinding"
Cohesion: 0.33
Nodes (3): Protocol, Structural type covering both ORM findings and drafts., ScorableFinding

### Community 77 - ".create_all"
Cohesion: 0.50
Nodes (3): Create the schema. M1 uses ``create_all`` deliberately: there is no deployed…, Strip credentials before a URL reaches the logs., _redact()

### Community 81 - "me"
Cohesion: 0.67
Nodes (3): me(), CurrentUser, get

### Community 83 - "AgentContext"
Cohesion: 0.16
Nodes (15): AgentContext, AgentResult, Any, BaseModel, Everything an agent is given for one execution., Structured outcome of one agent execution., Execute. Raise :class:`~acip.errors.AgentError` on unrecoverable failure., LogAnalysisAgent (+7 more)

### Community 90 - "Database"
Cohesion: 0.13
Nodes (21): async_sessionmaker, AsyncEngine, Database, AsyncSession, Yield a session, committing on success and rolling back on error., Owns the engine and session factory for one database URL., AsyncSession, The guard must bound its own blast radius: reads stay unaffected. (+13 more)

### Community 91 - "EvidenceStore"
Cohesion: 0.10
Nodes (20): EvidenceStore, AsyncSession, UUID, Append-only evidence store and grounding enforcement. This module is where the…, Writes evidence and findings for a single investigation., Persist drafts, skipping observations already recorded. Deduplication is by…, Validate a claim against the grounding invariants and persist it., Validate a hypothesis and persist it with supporting/contradicting links. (+12 more)

### Community 92 - "Severity"
Cohesion: 0.20
Nodes (14): assess(), Deterministic risk scoring. Severity and risk are computed from findings by a…, Roll findings up into an investigation-level severity and risk score., RiskAssessment, Finding, A claim about the investigation, bound to the evidence supporting it., AssertionClass, Epistemic status of a claim. See docs/evidence-model.md. The distinction is… (+6 more)

### Community 93 - "reporting.py"
Cohesion: 0.15
Nodes (10): Agent, ABC, Agent contract. Agents receive a typed context and return a typed result (spec…, Base class for all agents., AgentRegistry, Agent registry. Agents are looked up by name or capability rather than imported…, Name/capability lookup over the available agents., Inventory for the ``/system/capabilities`` endpoint. (+2 more)

### Community 94 - "_chunks"
Cohesion: 0.67
Nodes (3): _chunks(), Stream an upload without buffering it whole., UploadFile

### Community 95 - "deps.py"
Cohesion: 0.15
Nodes (16): Logger, get_investigation(), CurrentUser, UUID, FastAPI dependencies. Shared services (database, registries, orchestrator,…, Load an investigation or 404. M1 has no per-investigation ownership: any…, require_admin(), require_investigator() (+8 more)

### Community 96 - "orchestrator.py"
Cohesion: 0.15
Nodes (16): _derive_status(), Investigation orchestration. Executes a plan task by task, recording an…, Terminal status from task outcomes. Ordering matters: a halt or a failure must…, One audited tool invocation (spec s12). Every tool call is recorded before it…, ToolRun, log_context(), Temporarily bind values to the logging context., AsyncSession (+8 more)

### Community 97 - "login"
Cohesion: 0.40
Nodes (5): login(), AsyncSession, Depends, post, Exchange credentials for a short-lived access token.

### Community 98 - "list_evidence"
Cohesion: 0.19
Nodes (13): alias, ge, le, MAX_EVIDENCE_PAGE, Query, list_evidence(), list_investigations(), list_tasks() (+5 more)

### Community 99 - "ToolRegistry"
Cohesion: 0.24
Nodes (4): ToolUnavailableError, A name-to-adapter mapping with availability reporting., Probe every tool. Used by ``GET /capabilities``., ToolRegistry

### Community 101 - "_sqlite_pragmas"
Cohesion: 0.67
Nodes (3): Any, SQLite ignores foreign keys unless asked, and defaults to slow sync writes., _sqlite_pragmas()

### Community 103 - "test_investigation_lifecycle.py"
Cohesion: 0.43
Nodes (6): investigator_auth(), AsyncClient, FastAPI, fixture, test_investigation_full_lifecycle_api(), test_investigation_lifecycle_failure_paths()

### Community 104 - "_forbid_bulk_dml"
Cohesion: 0.67
Nodes (3): ORMExecuteState, _forbid_bulk_dml(), Reject bulk UPDATE/DELETE against an append-only table.

## Knowledge Gaps
- **61 isolated node(s):** `$schema`, `.opencode/plugins/graphify.js`, `$schema`, `npm`, `name` (+56 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **30 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Severity` to `_build_chain`, `models.py`, `investigations.py`, `triage.py`, `Evidence`, `types.py`, `log_analysis.py`, `contracts.py`, `Role`, `AgentContext`, `GroundingError`, `Database`, `EvidenceStore`, `reporting.py`?**
  _High betweenness centrality (0.052) - this node is a cross-community bridge._
- **Why does `EvidenceStore` connect `EvidenceStore` to `orchestrator.py`, `ValidationError`, `list_evidence`, `_build_chain`, `Database`, `investigations.py`, `Evidence`, `ModelExecution`, `Orchestrator`, `contracts.py`, `AgentContext`, `GroundingError`, `HypothesisDraft`, `Severity`, `reporting.py`?**
  _High betweenness centrality (0.049) - this node is a cross-community bridge._
- **Why does `InvestigationRunner` connect `InvestigationRunner` to `app.py`, `types.py`, `get_session`, `Investigation`, `Database`, `Orchestrator`, `deps.py`?**
  _High betweenness centrality (0.035) - this node is a cross-community bridge._
- **Are the 34 inferred relationships involving `EvidenceStore` (e.g. with `AgentContext` and `list_evidence()`) actually correct?**
  _`EvidenceStore` has 34 INFERRED edges - model-reasoned connections that need verification._
- **Are the 35 inferred relationships involving `Database` (e.g. with `build_services()` and `Services`) actually correct?**
  _`Database` has 35 INFERRED edges - model-reasoned connections that need verification._
- **Are the 28 inferred relationships involving `Investigation` (e.g. with `AgentContext` and `get_investigation()`) actually correct?**
  _`Investigation` has 28 INFERRED edges - model-reasoned connections that need verification._
- **Are the 30 inferred relationships involving `Severity` (e.g. with `LogAnalysisAgent` and `ReportAgent`) actually correct?**
  _`Severity` has 30 INFERRED edges - model-reasoned connections that need verification._