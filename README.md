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

**Phases 0–3 verified. Phase 1′ (verification retrofit) is substantially complete — 11 of its 15
exit criteria are met. Phase 4 is planned, not partially shipped.** [docs/roadmap.md](docs/roadmap.md)
is the authority on phase numbering
and §3.1 there marks every criterion individually; the four open ones are an atomic start claim, a
backup/restore integrity check, retention disclosure in the report, and the operating boundary in the
capability output.

| Quality Gate | Status |
|---|---|
| Tests | **97 tests passing** across `unit/`, `integration/`, `api/`, `security/`, and `scenarios/` |
| Lint | **0 ruff errors** (`ruff check src tests`) |
| Types | **0 mypy errors** across 52 source files (`mypy src`) |
| Vertical slice | **100% verified end to end** with SQLite database, real auth log attacks, and clean log baselines |
| Security Invariants | Grounding invariants G0–G4, append-only immutability (incl. bulk DML), provenance integrity, token safety, role authz matrix, request rate limits, no `shell=True`, no reserved `LogRecord` keys |
| Deferred Phase 4 capabilities | URL tools and SSRF enforcement, T1 subprocess tools, and MITRE ATT&CK mapping are not present in `src/`; reports and `/capabilities` do not claim them |
| Frontend | **Interactive dashboard** in `web/` served directly by FastAPI |

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

## Layout

```text
src/acip/
├── api/            FastAPI app, routers, request/response schemas
├── agents/         Agents: triage, log_analysis, reporting
├── tools/          Tool adapters — the only producers of evidence
├── core/
│   ├── evidence/   Evidence contracts + append-only store (grounding invariants)
│   ├── orchestration/  Planner, orchestrator, background runner
│   ├── detection/  Pure deterministic detection rules
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
| [deployment.md](docs/deployment.md) | Environments, configuration, operations |
| [risks-and-assumptions.md](docs/risks-and-assumptions.md) | Architectural risks; assumptions needing confirmation |

## Safety and scope

Potentially malicious artifacts are never executed. Artifacts are stored content-addressed,
non-executable, and are only ever read as bytes by tool adapters. All offensive activity used to
generate datasets stays inside an authorized lab environment. See
[docs/threat-model.md](docs/threat-model.md).
