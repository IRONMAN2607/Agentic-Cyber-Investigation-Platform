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

**Current phase: Phase 0 (Architecture) — complete. Phase 1–3 code exists but is unverified.**

The implementation in `src/acip/` was written before this architecture pass and has **not** been
validated. Specifically:

| | |
|---|---|
| Tests | **0 test files** (`tests/conftest.py` has fixtures only) |
| Lint | 18 ruff findings |
| Types | 11 mypy errors in 3 files |
| Vertical slice | **never executed end to end** — no database has ever been created |
| Model abstraction (§7) | **not implemented** |
| Frontend | **not started** |

Nothing in this repository should be described as working until it has been run. See
[docs/risks-and-assumptions.md](docs/risks-and-assumptions.md) for the full assessment and
[docs/roadmap.md](docs/roadmap.md) for what happens next.

**Next: Phase 1′ — verification retrofit.** Tests, CI, Alembic, the outstanding lint and type
findings, and executing the vertical slice for the first time. No new features until it passes.

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
