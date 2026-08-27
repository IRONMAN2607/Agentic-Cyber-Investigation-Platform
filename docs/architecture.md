# Architecture

Phase 0 architecture for AACIP. This document is the authority on system shape, layering, and
technology choices. Where it records a decision, the decision block states what was chosen, why,
what was rejected, and the condition under which it should be revisited.

## 1. Repository assessment (as of Phase 0)

The repository already contained ~6,200 lines of Python implementing much of Phases 1–3 before any
architecture was written. That code is unusually coherent — it encodes the assertion-class model,
provenance, append-only evidence, sandbox tiers, and entity types staged for the graph — but it was
never validated and never documented.

| Area | State |
|---|---|
| Package | `src/acip/`, installable, imports cleanly |
| API | FastAPI, 3 routers, 10 endpoints, JWT auth |
| Agents | 3 — `triage`, `log_analysis`, `reporting` |
| Tools | 2 — `auth_log_parser`, `ioc_extractor` (both T0 in-process) |
| Evidence | Contracts + append-only store, invariants G0–G4 enforced |
| Database | 9 tables, async SQLAlchemy 2, SQLite |
| Security | argon2 passwords, JWT, RBAC, content-addressed artifact intake |
| Tests | **none** (fixtures only) |
| Model abstraction | **absent** |
| Frontend | **absent** |
| Docs | **absent** before this pass |
| Git | **absent** before this pass |

Conclusion: **keep and harden, do not rewrite.** The existing design is consistent with the spec's
central rule and rewriting it would discard sound work. Phase 1′ (see
[roadmap.md](roadmap.md)) retrofits tests and fixes the lint/type debt rather than replacing code.

## 2. System architecture

```text
┌──────────────────────────────────────────────────────────────┐
│  Web UI (React + TS, Phase 8)                                │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTPS / JSON
┌───────────────────────────▼──────────────────────────────────┐
│  API layer — FastAPI                                         │
│  routers · schemas · authn/authz · error envelope            │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  Orchestration                                               │
│  InvestigationRunner (bounded concurrency)                   │
│  Orchestrator (executes plan, writes execution trace)        │
│  Planner  ◄── static | LLM-backed (swappable, Phase 7)       │
└───────────────────────────┬──────────────────────────────────┘
                            │ AgentContext / AgentResult
┌───────────────────────────▼──────────────────────────────────┐
│  Agents  triage · log_analysis · reporting · (Phase 4+ …)     │
│  may reason; may only assert through the evidence store      │
└──────────┬─────────────────────────────────┬─────────────────┘
           │ ToolRunner                      │ ModelRouter (Phase 6)
┌──────────▼──────────────┐      ┌───────────▼─────────────────┐
│  Tool adapters          │      │  core/llm                   │
│  the ONLY producers of  │      │  providers · routing ·      │
│  evidence · audited ·   │      │  fallback · budget · trace  │
│  sandbox tiers T0–T3    │      └─────────────────────────────┘
└──────────┬──────────────┘
           │ EvidenceDraft
┌──────────▼──────────────────────────────────────────────────┐
│  Evidence store — append-only, provenance, invariants G0–G4  │
└──────────┬──────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────┐
│  Persistence — SQLAlchemy 2 async · SQLite → PostgreSQL      │
│  evidence · findings · runs · audit · graph (Phase 5)        │
└─────────────────────────────────────────────────────────────┘
```

Deviation from the spec diagram (§4): the spec draws Evidence Normalizer, Hypothesis Engine,
Validation Engine, and Risk/ATT&CK as pipeline stages between the store and the report. They are
implemented as **agents and pure modules invoked by the orchestrator**, not as fixed stages,
because §2 requires a genuinely agentic system rather than "a fixed pipeline disguised as an agent
system." Normalization belongs to the tool adapter that produces the evidence (it is part of
producing a well-formed observation); risk scoring is a pure function over findings
(`core/risk.py`); hypothesis and validation are agents the planner may or may not schedule.

### Layering rule

Dependencies point inward only:

```text
api → orchestration → agents → tools → core/evidence → db → config/types
```

Enforced conventions:

- `core/detection/` is **pure functions** over normalized events: no database, no I/O, no LLM.
  This is what makes detection rules unit-testable and reusable as research Baseline A.
- Tool adapters never import agents. Agents never import API code.
- Nothing writes evidence except through `EvidenceStore`.
- Nothing calls an LLM provider directly; agents call `ModelRouter` (§7 of the spec).
- `types.py` and `config.py` are leaves — they import nothing from the package.

## 3. Technology stack

| Concern | Choice | Rationale |
|---|---|---|
| Language | Python 3.12 | `StrEnum`, `match`, modern typing; ecosystem for security tooling |
| API | FastAPI | Async, Pydantic-native, generates OpenAPI the frontend consumes |
| Validation | Pydantic v2 | §6 requires typed structured messages; used at every boundary |
| ORM | SQLAlchemy 2 (async) | Mature async support; mapper events enforce append-only |
| DB (dev) | SQLite + aiosqlite | Zero-setup for a 4-person team |
| DB (prod) | PostgreSQL + asyncpg | Needed from Phase 5 for JSONB, recursive CTEs, real constraints |
| Migrations | Alembic | The only schema creation path; migrations are exercised by every test fixture |
| Passwords | argon2-cffi | Memory-hard KDF; current OWASP guidance |
| Tokens | PyJWT, HS256 | Symmetric is sufficient for a single-service deployment |
| Task execution | custom asyncio | See decision below |
| LLM access | provider-agnostic `core/llm` | §7 forbids hard-coded providers |
| Frontend | React + TypeScript + Vite | Phase 8; CORS already expects `localhost:5173` |
| Tests | pytest + pytest-asyncio + httpx | Async-native; httpx drives the ASGI app in-process |
| Lint / types | ruff, mypy | Already configured strictly in `pyproject.toml` |

Deliberately **not** adopted now: Celery, Dramatiq, Temporal, LangGraph, Neo4j, Redis, a vector
database. Each is reconsidered at the phase that creates real need for it. §16: do not add
infrastructure to make the project look complex.

### Decision — task orchestration: custom asyncio, not a framework

**Chosen:** the existing `InvestigationRunner` + `Orchestrator` (asyncio tasks in the API process,
bounded by a semaphore).

**Why:** the execution trace *is* the research artifact. The orchestrator writes `agent_runs` and
`tool_runs` rows with rationale, duration, and outcome exactly as [experiments.md](experiments.md)
needs them; a general framework would have to be adapted to emit the same trace. LangGraph would
additionally couple planning to one agent framework, whereas the study requires static and
LLM-backed planners to be swappable behind one interface — already achieved by the `Planner`
protocol. Celery/Dramatiq would introduce a broker for work that is currently in-process text
parsing. Temporal is operationally heavy for a four-person capstone.

**Accepted cost:** execution remains single-process and single-worker. A restart cannot resume work; instead, Phase 1′ defines deterministic recovery: at startup, the runner marks every `queued` or `running` investigation and agent run without a live in-process owner as `interrupted`, records an audit reason, and requires an explicit retry that creates a new attempt. A database-backed claim prevents duplicate starts while the supported single worker is running. This is a recoverable local prototype, not durable job execution or horizontal scale.

**Revisit when:** container-isolated tools, a second worker, or any need to resume work after restart requires an external queue. `InvestigationRunner.submit()` is the seam; its body then becomes a queue publish, with leases and heartbeats owned by that queue.

### Decision — SQLite now, PostgreSQL from Phase 5

**Chosen:** keep SQLite for Phases 1–4; move to PostgreSQL when the evidence graph lands.

**Why:** the schema deliberately avoids SQLite-specific and PostgreSQL-specific features (enums are
stored as strings, `sa.Uuid` and generic JSON are used) so the same models run on both. Recursive
CTE graph traversal, JSONB indexing, and revoking `UPDATE`/`DELETE` grants on append-only tables
all require PostgreSQL, and all first matter in Phase 5.

**Accepted cost:** one migration event, and a period where CI does not exercise the production
engine. Mitigation: Alembic arrives in Phase 1′, and the test suite runs against both engines from
Phase 5.

## 4. Directory structure

The spec's suggested layout (§24) puts `agents/`, `core/`, `tools/` at the repository root as
separate top-level packages. This project uses a **single installable package** instead:

```text
AACIP/
├── src/acip/               single import root, `pip install -e .`
│   ├── api/                routers, schemas, dependencies
│   ├── agents/             one module per agent + registry
│   ├── tools/              one module per adapter + registry + runner
│   ├── core/
│   │   ├── evidence/       contracts, store
│   │   ├── orchestration/  planner, orchestrator, runner
│   │   ├── detection/      pure rules
│   │   ├── security/       passwords, tokens, authz, files
│   │   ├── llm/            Phase 6 — providers, router, budget, trace
│   │   ├── graph/          Phase 5 — entity resolution, edges, traversal
│   │   ├── risk.py
│   │   └── limitations.py
│   ├── db/                 models, session, migrations
│   ├── cli.py  config.py  types.py  errors.py  logging.py  bootstrap.py
├── web/                    Phase 8 frontend
├── tests/                  unit · integration · e2e · security · scenarios
├── datasets/               manifests only; raw data gitignored
├── experiments/            runners, configs, results
├── docs/
├── scripts/
└── infrastructure/         Phase 4+ container definitions
```

§24 explicitly permits modification. A single package gives one import root, avoids namespace-
package pitfalls, and keeps `mypy`/`ruff`/packaging configuration trivial. `prompts/` from the spec
becomes `core/llm/prompts/` so prompt versions sit beside the router that selects them.

## 5. Cross-cutting design commitments

**Immutability of evidence.** `Evidence` and `AuditLog` reject `UPDATE`/`DELETE` at the SQLAlchemy
mapper level, so a mistake anywhere fails loudly instead of rewriting history. Database-level
enforcement follows in Phase 5.

**Provenance is structural, not advisory.** Every evidence row carries `artifact_id`,
`tool_run_id`, and `agent_run_id`. A non-NULL `tool_run_id` is the machine-checkable marker of
deterministic origin, and the grounding invariants depend on it.

**Deduplication by content hash.** Evidence is hashed over intrinsic content only — never over
collection time or run ids — so re-running a tool over the same artifact does not inflate evidence
counts. This matters for the evaluation metrics.

**Two timestamps, never conflated.** `observed_at` is when the event happened; `collected_at` is
when the platform saw it. `time_confidence` records how much to trust `observed_at`, because syslog
omits the year and host clocks drift. A derived timestamp must never be reported as observed fact.

**Failure is data.** A failing task does not abort the investigation; later tasks still run and the
report states what failed. Terminal status is derived from the set of outcomes, so an investigation
is never reported `completed` when part of it did not run.

**Bounded execution.** Per-investigation wall-clock budget, max task count, and a reporting grace
budget so a halted investigation still produces a report — a halt with no report is
indistinguishable from a crash.

**Honest capability reporting.** `core/limitations.py` is the single source consumed by both
`GET /capabilities` and the report renderer, so the API and the report cannot disagree about what
the platform does not do.

## 6. First implementation milestone (M1)

The vertical slice defined by §36, and the gate on all further agent work:

```text
authenticate → create investigation → upload Linux auth.log
  → orchestrator plans → triage agent extracts IOCs
  → log_analysis agent runs auth_log_parser + detection rules
  → evidence persisted with provenance → findings recorded under G0–G4
  → deterministic risk roll-up → report generated → API serves it
```

The code for this exists. **It has never been run.** M1 is therefore not complete, and completing
it — with tests, and with the slice actually executed — is the first task of Phase 1′. See
[roadmap.md](roadmap.md) and the definition of done in [testing.md](testing.md).

## 7. Related documents

Agent contracts: [agents.md](agents.md) · Evidence: [evidence-model.md](evidence-model.md) ·
Graph: [evidence-graph.md](evidence-graph.md) · Schema: [database.md](database.md) ·
API: [api.md](api.md) · Tools: [tools.md](tools.md) ·
LLM: [model-abstraction.md](model-abstraction.md) · Security: [security.md](security.md) ·
Threats: [threat-model.md](threat-model.md) · Tests: [testing.md](testing.md) ·
Frontend: [frontend.md](frontend.md) · Deployment: [deployment.md](deployment.md) ·
Evaluation: [experiments.md](experiments.md) · Research: [research.md](research.md) ·
Roadmap: [roadmap.md](roadmap.md) · Risks: [risks-and-assumptions.md](risks-and-assumptions.md)
