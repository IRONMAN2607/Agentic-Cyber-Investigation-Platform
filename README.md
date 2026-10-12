# AACIP — Agentic Cyber Investigation Platform

An evidence-driven, multi-agent cybersecurity investigation platform. A user submits an
investigation target (log file, IP, URL, hash, PCAP, incident description); the platform plans an
investigation, runs deterministic analysis tools, records immutable evidence with provenance,
derives findings that are bound to that evidence, and produces a report that distinguishes what
was **observed** from what was **inferred** from what remains **unknown**.

Two-semester Computer Engineering capstone, four-member team, intended to support an IEEE-style
research publication.

## The one rule that shapes everything

> LLMs reason over evidence. Deterministic cybersecurity tools produce evidence.
> An LLM is never the unquestioned source of truth.

This is enforced mechanically, not by convention. Evidence rows carry a `tool_run_id`; a finding
classified `FACT` is rejected at write time unless it cites evidence that came from a deterministic
tool. See [docs/evidence-model.md](docs/evidence-model.md).

## Status

**Phases 0–8 verified. Phase 5 (Evidence Graph & Correlation Engine), Phase 6 (Model Abstraction & Reasoning Provider), Phase 7 (Reasoning Agents, Adversarial Validation & Adaptive Planning), and Phase 8 (Frontend Expansion: Evidence Graph, Interactive Timeline, Hypotheses & Validation Panel, Real-time SSE streaming, Honest Limitations Modal) are complete. Phase 9 (Evaluation & Benchmark Harness) is unblocked.** [docs/roadmap.md](docs/roadmap.md) is the authority on phase numbering.

| Quality Gate | Status |
|---|---|
| Tests | **211 tests passing** across `unit/`, `integration/`, `api/`, `security/`, and `scenarios/` |
| Lint | **0 ruff errors** (`ruff check src tests`) |
| Formatting | **100% formatted** across 144 files (`ruff format --check src tests`) |
| Types | **0 mypy errors** across 144 source files (`mypy src tests`) |
| Vertical slice | **100% verified end to end** with SQLite database, real auth and web attacks, clean baselines, MITRE mapping, graph reasoning, and hypothesis generation |
| Orchestrator Agent & Planner | `OrchestratorAgent` coordinates lifecycle, `AdaptivePlanner` dynamically plans investigative workflows based on artifact types, tool capabilities, and investigation progression |
| Reasoning & Validation Agents | `HypothesisAgent` (competing explanations with Invariant G3 refutation conditions and gap detection), `ReasoningAgent` (multi-hop graph attack chain synthesis), `ValidationAgent` (adversarial review with bounded execution loops), Risk assessment with attributed model opinion |
| Evidence Graph Engine | In-database graph (`entities`, `entity_edges`), Tier-1 Canonical Correlation (`CorrelationAgent`), cycle-safe depth-bounded BFS traversal (`GraphTraversal`), and subgraph extraction |
| Frontend Workspace | **Interactive multi-tab dashboard** in `web/` served directly by FastAPI: Evidence Graph SVG canvas, Correlated Forensic Timeline, Competing Hypotheses & Validation, Server-Sent Events (SSE) streaming with polling fallback, honest capabilities & limitations disclosure modal |
| Security Invariants | Grounding invariants G0–G4, Invariant G7 (MITRE ATT&CK catalog bounds), append-only immutability (incl. bulk DML), provenance integrity, token safety, role authz matrix, request rate limits, anti-SSRF protection, magic-byte intake validation, T1 sandbox isolation (no `shell=True`) |
| Model Abstraction & Routing | `ModelRouter`, `RoutingPolicy`, OpenAI-compatible `NvidiaNIMProvider` (Nemotron, DeepSeek R1), local `CyberReasoningProvider` dynamic evaluation engine, Pydantic structured output repair, deterministic `ReplayProvider` test double |
| Active Phase 4 Capabilities | Deterministic Web Server Access Log Parser (`web_server_log_parser`), Linux Auth Log Parser (`auth_log_parser`), PCAP Packet Capture Parser (`pcap_parser`), Threat Intelligence adapter (`threat_intel`), IOC Extractor (`ioc_extractor`), MITRE ATT&CK Mapping Agent (`mitre`), Tier 1 Subprocess Sandbox |
| Active Focus (Phase 9) | Evaluation harness: benchmark datasets, baselines A–C, ablations 1–4, and reproduction runner |

`GET /capabilities` and `acip capabilities` report what this deployment can actually do, and
`src/acip/core/limitations.py` is the single source for what it cannot. Both are wired into the
generated report so the API, the CLI, and the report cannot drift into disagreeing.

## Quickstart

Requires Python 3.12+.

```bash
python -m venv .venv && .venv/Scripts/python.exe -m pip install -e ".[dev]"
```

```bash
cp .env.example .env
```

```bash
.venv/Scripts/python.exe -m acip.cli init
```

```bash
.venv/Scripts/python.exe -m acip.cli serve
```

Then open `http://127.0.0.1:8000/docs`. `acip capabilities` prints the honest capability list
without starting a server.

### Reproducibility Runner

To execute the complete empirical evaluation matrix across all conditions (A through D) and verify formal grounding invariants in one command:

```bash
python scripts/reproduce_results.py experiments/results
```

(Or `./scripts/reproduce.sh` on POSIX / `powershell scripts/reproduce.ps1` on Windows). Output reports and certified SHA256 checksums are stored in `experiments/results/`.

## Layout

```text
src/acip/
├── api/            FastAPI app, routers, request/response schemas
├── agents/         Agents: triage, log_analysis, mitre, correlation, reporting
├── tools/          Tool adapters — the only producers of evidence
├── core/
│   ├── evidence/   Evidence contracts + append-only store (grounding invariants)
│   ├── graph/      Evidence graph traversal engine (depth-bounded, cycle-safe)
│   ├── orchestration/  Planner, orchestrator, background runner
│   ├── detection/  Pure deterministic detection rules & MITRE catalog
│   ├── security/   Passwords, tokens, authz, safe artifact intake
│   ├── risk.py     Deterministic severity/risk scoring
│   └── limitations.py  Declared capability gaps
├── db/             ORM models, session management
└── config.py       Environment-driven settings
```

## Documentation

| Doc | Contents |
|---|---|
| [architecture.md](docs/architecture.md) | System architecture, tech stack, layering, directory structure |
| [agents.md](docs/agents.md) | Agent roster, contracts, orchestration and planning |
| [evidence-model.md](docs/evidence-model.md) | Evidence, assertion classes, grounding invariants G0–G4 |
| [evidence-graph.md](docs/evidence-graph.md) | Graph design; Neo4j vs PostgreSQL decision |
| [database.md](docs/database.md) | Schema, keys, indexes, migration strategy |
| [api.md](docs/api.md) | Endpoints, auth, error envelope, versioning |
| [tools.md](docs/tools.md) | Tool adapter contract, sandbox tiers T0–T3 |
| [model-abstraction.md](docs/model-abstraction.md) | LLMProvider, ModelRouter, routing, fallback, cost |
| [frontend.md](docs/frontend.md) | Frontend architecture, views, provenance-first UI rules |
| [security.md](docs/security.md) | Security architecture and controls |
| [threat-model.md](docs/threat-model.md) | Assets, adversaries, attack surface, mitigations |
| [testing.md](docs/testing.md) | Test architecture and the definition of done |
| [experiments.md](docs/experiments.md) | Evaluation methodology, baselines, ablations, metrics |
| [research.md](docs/research.md) | Research question and contribution |
| [roadmap.md](docs/roadmap.md) | Phases and two-semester plan |
| [paper/IEEE_PAPER_DRAFT.md](docs/paper/IEEE_PAPER_DRAFT.md) | IEEE conference research paper draft & formal proofs |
| [deployment.md](docs/deployment.md) | Environments, configuration, operations |
| [risks-and-assumptions.md](docs/risks-and-assumptions.md) | Architectural risks; assumptions needing confirmation |

## Safety and scope

Potentially malicious artifacts are never executed. Artifacts are stored content-addressed,
non-executable, and are only ever read as bytes by tool adapters. All offensive activity used to
generate datasets stays inside an authorized lab environment. See
[docs/threat-model.md](docs/threat-model.md).
