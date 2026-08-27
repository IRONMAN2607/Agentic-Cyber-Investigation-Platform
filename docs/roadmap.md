# Roadmap

Covers §25 and §26. **This document is the authority on phase numbering.** Where a docstring in
`src/` cites a different phase number, the docstring predates this roadmap and is corrected in
Phase 1′ — those references are stale, not a second plan.

## 0. Phase numbering was corrected here

While writing this document a dependency error in the earlier design docs surfaced and is worth
recording rather than quietly fixing: the reasoning agents (hypothesis, validation, adaptive planner)
had been scheduled **before** the model abstraction layer they depend on. Corrected ordering:

- **Phase 6 — model abstraction**, then
- **Phase 7 — reasoning agents.**

A consequence worth keeping deliberately: **the platform contains no language model at all until
Phase 6.** Everything through Phase 5 is deterministic. That is not a compromise — it means
Baseline A in [experiments.md](experiments.md) *is* the Phase 5 system, measured on the same code
path rather than reimplemented as a comparison artefact.

## 1. Phase status

| Phase | Content | Status |
|---|---|---|
| 0 | Architecture, contracts, evidence model, schema, security design, roadmap | **complete** |
| 1 | Foundation: config, types, errors, logging, DB, auth, API skeleton | **verified** |
| 2 | Evidence store, grounding invariants, tool layer, artifact intake | **verified** |
| 3 | Agents, planner, orchestrator, runner, reporting | **verified** |
| **1′** | **Verification retrofit** | **substantially complete** — 11 of 15 exit criteria met (97 tests, clean ruff/mypy, live UI); see §3 |
| 4 | Tool and knowledge expansion; sandboxing; hardening | **next**; no Phase 4 implementation is shipped early |
| 5 | Evidence graph, correlation, PostgreSQL | not started |
| 6 | Model abstraction and routing | not started |
| 7 | Reasoning agents | not started |
| 8 | Frontend and interaction | initial UI in `web/`; full React app deferred |
| 9 | Evaluation | not started |
| 10 | Writing | not started |

**"Verified" means a live command result, not a claim inferred from source.** As of 2026-08-28,
after removing inactive Phase 4 prototypes from the running system:

```text
pytest                    97 passed
ruff check src tests      All checks passed!
ruff format --check       87 files already formatted
mypy src                  Success: no issues found in 52 source files
```

The vertical slice executes end to end — `tests/scenarios/test_auth_log_scenario.py` runs create →
upload → start → agents → evidence → findings → report against the auth-log fixture, with a clean-log
negative baseline beside it. Every fixture creates its schema by upgrading Alembic to head; the migration
tests assert both the revision stamp and model/migration parity, including the `0003` SQLite table rebuild.

**Earlier revisions of this section claimed the opposite** — "zero tests run against them", "the
development database has never been created" — and that text survived long after it stopped being
true. It is recorded here rather than quietly deleted because a status document that lags its own
project is worse than no status document: it is the one file a reader trusts to know what is real.
Re-derive these figures from a live run before citing them.

What remains open in Phase 1′ is enumerated in §3 with each criterion marked: an atomic start claim,
a backup/restore integrity check, retention disclosure in the report, and the operating boundary in the
capability output. These are Phase 1′ debt, tracked explicitly rather than assumed closed.

## 2. Delivery scope and gates

**Deliverable scope:** a verified, localhost-only, single-user M1 vertical slice: authentication,
creation, bounded auth-log upload, deterministic extraction/detection, grounded evidence/findings,
and an auditable generated report. This is the product that must be reliable.

**Research scope:** only the smallest controlled extension required to test the grounding question:
one model/provider path, one controlled baseline, and labelled scenarios. The graph, adaptive planner,
multiple intelligence providers, routing failover, investigator chat, analyst study, broad endpoint or
PCAP tooling, and a rich frontend are deferred unless a written experiment need demonstrates they are
necessary.

No phase starts merely because its predecessor is numbered complete: its exit criteria must be met and
the supported deployment boundary must still hold. Feature development beyond M1 is blocked until
Phase 1′ exits.

## 3. Phase 1′ — verification retrofit

The one phase with no new features. It exists because Phases 1–3 were implemented before any design
documentation or tests, which §32 forbids, and the cheapest moment to correct that is now — before
more code depends on it.

**Exit criteria, all required:**

1. `pytest` runs and passes, covering [testing.md](testing.md) §2's `unit/`, `integration/`, `api/`,
   and `security/` layers.
2. **The vertical slice actually executes**: create investigation → upload the auth-log fixture →
   start → agents run → evidence written → findings produced → report generated. Observed, not
   assumed.
3. The grounding invariants G0–G4 each have a passing test proving `GroundingError` is *raised*.
4. Append-only enforcement tested for `evidence` and `audit_log`.
5. Startup recovery marks interrupted work terminally, preserves its trace, and requires an explicit
   retry; duplicate start attempts are rejected by a database-backed claim.
6. Database/artifact size quotas, deterministic truncation markers, cursor pagination, and a
   backup/restore integrity check are implemented and tested.
7. A written raw-artifact retention state (`reproducible`, `derived-only`, or `minimal/audit-only`)
   is recorded per investigation; reports disclose when source bytes no longer exist.
8. `ruff check` clean.
9. `mypy src` clean.
10. Alembic introduced with a baseline revision, replacing `create_all()`.
11. CI in GitHub Actions: ruff, ruff format, mypy, pytest, `pip-audit` — all gating.
12. Pre-commit hooks including a secret scan.
13. Stale phase references in `src/` docstrings corrected against this document.
14. The status table in [README.md](../README.md) updated to reflect what tests now prove.
15. The localhost/single-user operating boundary is tested as configuration and documented in the
    capability output.

### 3.1 Where each criterion actually stands

Audited 2026-08-28. **Met** means a command was run or a test was read, not that the code looks
present.

| # | Criterion | State | Evidence, or what is missing |
|---|---|---|---|
| 1 | pytest across the four layers | met | 97 passed; `unit/ integration/ api/ security/` plus `scenarios/` |
| 2 | Vertical slice executes | met | `tests/scenarios/test_auth_log_scenario.py`, plus a clean-log baseline |
| 3 | G0–G4 each raise `GroundingError` | met | `integration/test_grounding.py`; G0's case is `test_grounding_invariant_cross_investigation_isolated` — renaming it would make the mapping legible without inference |
| 4 | Append-only tested for `evidence`, `audit_log` | met | row-level and bulk-DML cases for both, plus the sanctioned purge |
| 5 | Recovery terminal, explicit retry, **DB-backed start claim** | **partial** | recovery and retry are tested; `start_investigation` still reads status then writes it, so two concurrent starts can both observe `CREATED`. Needs a rowcount-checked conditional `UPDATE` and a concurrency test |
| 6 | Quotas, truncation markers, pagination, **backup/restore check** | **partial** | quota and truncation markers implemented but no test names either; cursor pagination implemented and tested; backup/restore integrity check does not exist |
| 7 | Retention state recorded, **reports disclose lost bytes** | **partial** | `retention_state` on `Investigation` and `Artifact`, PATCH-able, and the provenance endpoint discloses a chain ending at derived records; `reporting.py` §9 never mentions retention |
| 8 | `ruff check` clean | met | `All checks passed!` |
| 9 | `mypy src` clean | met | 54 source files, no issues |
| 10 | Alembic **replacing** `create_all()` | met | `bootstrap()`, `acip init`, and every test fixture upgrade Alembic to head; migration tests assert the head stamp and metadata parity, and a static invariant rejects `create_all()` in `src/` |
| 11 | CI gating, including `pip-audit` | met | `pip-audit` and a `uv.lock` consistency check now gate; CI also runs on all branches |
| 12 | Pre-commit incl. secret scan | met | `.pre-commit-config.yaml` with `detect-secrets` |
| 13 | Stale phase refs corrected | met | corrected against this document |
| 14 | README status table current | met | measured figures, and the phase vocabulary matches this table |
| 15 | Localhost/single-user boundary in capability output | **not met** | `/capabilities` returns environment, tools, agents, planner, `not_implemented`; the operating boundary appears in none of them and no test asserts it |

Four criteria remain: **5, 6, 7 and 15.** They are Phase 1′ debt, they are not Phase 4 blockers, and
they are listed here so that "1′ complete" cannot be read off a table without meeting them.

**Estimate: 2–3 weeks with the full team.** Anything that ships before this completes inherits an
unverified foundation, and the first place that surfaces is the evaluation, where a silent bug becomes
a published number.

## 4. Phases 4–10

### Phase 4 — Tools, knowledge, and hardening

The largest phase, and the one that changes the threat model.

- **Sandboxing first.** T1 subprocess isolation, then T2 containers (read-only rootfs,
  `--network=none`, non-root, dropped capabilities, resource limits). No parser handling binary or
  untrusted input ships before its tier exists.
- **Security controls land with their first real caller.** The request rate limiter is active on the
  sensitive current routes. URL/SSRF enforcement, T1 subprocess isolation, and MITRE/G7 mapping were
  intentionally removed from `src/` because they had no caller and would have made the suite appear to
  cover running capabilities it did not. The preserved session commit contains their prototypes. Phase
  4 introduces each only with its integration: SSRF with the first URL tool and redirect test matrix;
  sandboxing with the first subprocess adapter; and MITRE with a versioned local catalog plus a mapping
  agent that cannot emit an identifier absent from that catalog. Per-tool timeouts and third-party key
  handling are also still absent.
- Network tools: TShark, Zeek, Suricata. Endpoint: EVTX, process/persistence analysis, YARA, Sigma.
- Threat intelligence (T3): VirusTotal, AbuseIPDB, OTX, Shodan — per-investigation opt-in, every
  lookup recorded, outbound rate limits.
- ATT&CK catalog loaded locally with a recorded `catalog_version`; the MITRE agent maps
  deterministically from detection rules and **cannot emit an id absent from the catalog** (G7).
- **LLM de-risking spike**, in parallel: one throwaway call per provider to confirm the six unknowns
  in [model-abstraction.md](model-abstraction.md) §10 — model identifiers, structured-output support,
  context windows, rate limits, pricing, data-handling terms. Discarded code; the point is to learn
  before Phase 6 whether the two-provider comparison is even possible.

Retires threat-model.md's operating restrictions on binary artifacts and outbound requests. Until it
lands, those restrictions are the security architecture.

### Phase 5 — Evidence graph and PostgreSQL

- `entities`, `entity_edges` (evidence-backed, `NOT NULL`), `finding_evidence` with SUPPORTS /
  CONTRADICTS.
- Correlation agent: entity resolution (Tier 1 canonical only, automatic), edge construction,
  timeline.
- Traversal confined to `core/graph/traversal.py`, depth-bounded and result-capped.
- **PostgreSQL becomes the primary engine**; tests run against both. Append-only enforced by revoking
  grants, not only by mapper events.
- Retention and redaction, per [database.md](database.md) §5.

### Phase 6 — Model abstraction

Build `core/llm/` as designed: provider protocol, router, config-driven routing table, error taxonomy
with the deliberate no-fallback cases, structured output with no best-effort parse, `llm_calls`
observability, budget and circuit breaker, versioned prompts, `replay.py` test double.

**First real LLM use lands here**, on the narrative and extraction task classes — the lowest-risk
entry point. The test asserting no `agents/` module imports a provider SDK is written in this phase, so
§7 is enforced from the start rather than retrofitted.

### Phase 7 — Reasoning agents

- `hypothesis` — competing explanations, each with a `NOT NULL` refutation condition (G3 at schema
  level).
- `reasoning` — cross-source attack-chain construction over the graph.
- `validation` — adversarial review; the one component permitted to send an investigation backwards,
  bounded by the task cap and loop detection.
- `risk` — deterministic score plus an attributed model opinion that never overwrites the score.
- `AdaptivePlanner` behind the existing `Planner` Protocol, so ablation 4 compares one interface's two
  implementations rather than two codebases.

### Phase 8 — Frontend

React + TypeScript + Vite, per [frontend.md](frontend.md). Investigation views, evidence browser with
provenance links, graph and timeline visualisation, ATT&CK matrix, report view and export, investigator
chat, SSE progress. §15's rule governs: **no animated agent activity that is not actually happening.**

### Phase 9 — Evaluation

Datasets, baselines A–C, the metric harness *and its tests*, N≥5 runs, ablations 1–4, statistical
analysis. Per [experiments.md](experiments.md).

### Phase 10 — Writing

IEEE-format paper, artifact packaging, reproducibility check: a second team member regenerates every
reported number from a commit hash and a config path.

## 4. Two-semester plan

Assumes ~15 teaching weeks per semester and four members. Week numbers are planning targets, not
commitments.

### Semester 1 — a working deterministic platform

| Weeks | Engineering | Research |
|---|---|---|
| 1–3 | **Phase 1′** — tests, CI, Alembic, lint/type debt, run the slice | Literature survey begins |
| 4–6 | Phase 4a — T1/T2 sandboxing, rate limiting, SSRF, per-tool timeouts | Survey continues; **RQ5 retain-or-drop decision by week 4** |
| 7–9 | Phase 4b — network and endpoint tools; ATT&CK catalog | Survey complete → positioning table; **dataset availability verified** |
| 10–12 | Phase 4c — threat intelligence (T3); **LLM de-risking spike** | Dataset acquisition and labelling; synthetic generator |
| 13–15 | Phase 5 — graph, correlation, PostgreSQL migration | Baseline A implemented; metric harness started |

**Semester 1 exit gate — all four required:**

1. An end-to-end investigation on multi-source input, tested, with the graph populated.
2. No unmitigated item in [security.md](security.md) §1 that the current tool roster can trigger.
3. Datasets obtained with usable ground truth, and the tuning/evaluation split fixed.
4. Provider capabilities confirmed, so the Phase 6 design is known to be buildable.

Gate 4 is the one to watch. If both providers are unavailable, the evaluation is rescoped in
**semester 1**, not discovered in semester 2 week 8.

### Semester 2 — reasoning, evaluation, paper

| Weeks | Engineering | Research |
|---|---|---|
| 1–3 | Phase 6 — model abstraction; first LLM calls | Baselines B and C implemented; harness tested |
| 4–6 | Phase 7a — hypothesis and reasoning agents | Pilot runs; metric sanity-checking |
| 7–9 | Phase 7b — validation, risk, adaptive planner | Full experiment matrix + ablations 1–4 |
| 10–12 | Phase 8 — frontend | Analysis; **paper draft**; analyst study if retained |
| 13–15 | Hardening, artifact packaging, demo | Paper revision; reproducibility check |

Experiments begin in week 4 rather than week 10 on purpose. Deferring measurement to the end is the
standard way a capstone discovers in the final fortnight that its numbers do not support its claims.

## 5. Work allocation

Proposed, and requires team confirmation — it is a design proposal, not an assignment:

| Area | Owns |
|---|---|
| Platform | Orchestration, evidence store, database, API, migrations |
| Security and tools | Tool adapters, sandboxing, SSRF, rate limiting, `tests/security/` |
| Reasoning | Model abstraction, prompts, reasoning agents, `llm_calls` |
| Evaluation and frontend | Datasets, baselines, metric harness, frontend, paper figures |

Two rules that matter more than the split: **every PR is reviewed by someone who does not own the
area**, and **the person who owns a subsystem does not solely own its evaluation** — the conflict of
interest in [research.md](research.md) §9 is managed structurally, not by good intentions.

## 6. Cut list, decided in advance

If the schedule slips, these are dropped in this order. Deciding now prevents the far worse failure
mode of cutting the evaluation to keep features:

1. Investigator chat (Phase 8)
2. Analyst study (RQ5) → structural argument plus provenance-completeness metric
3. Memory forensics / Volatility
4. Adaptive planner → static only, and ablation 4 is dropped with the reason stated
5. Frontend → reduced to a read-only investigation and evidence view
6. Second model provider → single-provider evaluation, and the multi-model claim is withdrawn

**Never cut:** the grounding invariants, provenance, the append-only audit trail, the security controls
in Phase 4, the test suite, or the evaluation. Those are the contribution. Features are negotiable;
the thing being claimed is not.
