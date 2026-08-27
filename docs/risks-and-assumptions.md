# Architectural Risks and Assumptions

The closing deliverable of Phase 0 (§35). Three parts: **assumptions** that must be confirmed before
they are built on, **risks** ranked by expected damage, and **decisions requiring team sign-off** —
places where this architecture deviates from the specification or resolves something the specification
left open.

Nothing here is rhetorical. Each item states what happens if it turns out badly and what would make it
visible early rather than late.

## 1. Assumptions requiring confirmation

Ranked by how much depends on them. "Confirm by" refers to the schedule in [roadmap.md](roadmap.md).

| # | Assumption | If wrong | Confirm by |
|---|---|---|---|
| **A1** | Two model providers are available with usable credit | The multi-model comparison (§8) and single-vs-multi-model ablation cannot run; the evaluation is rescoped | **Semester 1, week 10** |
| **A2** | The named candidate models exist under some API identifier, support structured output, and have documented pricing | Routing tiers are meaningless; structured output falls back to retry-with-repair, which is measurably worse | Semester 1, week 10 |
| **A3** | Public security datasets with **finding-level** ground truth are obtainable and licensed for this use | No precision/recall is computable; evaluation collapses to synthetic data and the external-validity claim is withdrawn | **Semester 1, week 9** |
| **A4** | Sending investigation content to a hosted provider is acceptable under the team's data-handling obligations | A local model becomes mandatory, changing hardware needs and latency budgets | Semester 1, week 10 |
| **A5** | An isolated lab segment exists (or can exist) for Phase 4 network and sample work | T2/T3 tools cannot be exercised safely; the tool roster shrinks and ATT&CK ground truth via Atomic Red Team is unavailable | Semester 1, week 4 |
| **A6** | Docker (or Podman) is available on all development machines | Container isolation is impossible; malware handling stays out of scope permanently | Semester 1, week 4 |
| **A7** | ~15-week semesters, four members, sustained availability | Phases 7–9 compress into the period reserved for analysis and writing | Week 1 |
| **A8** | If RQ5 is retained, ethics approval is obtainable in time | The analyst study is dropped mid-project rather than by decision | **Week 4** |
| **A9** | PostgreSQL is available in the deployment/lab environment by Phase 5 | The graph stays on SQLite: no JSONB, no `ARRAY` cycle guard in recursive CTEs, no grant-level append-only | Semester 1, week 12 |
| **A10** | Data processed is synthetic or sanitised — no real personal or client data | Retention, redaction, and erasure obligations become binding immediately, and the append-only audit log conflicts with them | **Ongoing — this is a standing rule, not a one-off check** |
| **A11** | The target venue accepts a system-plus-evaluation paper at capstone scope | Framing and depth are wrong late, when they are expensive to change | Week 4, with the supervisor |
| **A12** | Deployment remains one trusted developer on localhost with synthetic/sanitised data only | Missing object-level authorization, rate limiting, and artifact-at-rest protections become active vulnerabilities | Before any second user, lab, network binding, or non-sanitised data |
| **A13** | Python 3.12+ on all machines | `StrEnum`, `match`, and `datetime.UTC` usage breaks | Week 1 |
| **A14** | A git remote with CI minutes is available | The Phase 1′ CI gate cannot be enforced, and verification depends on individual discipline | Week 1 |

**A1–A4 are the ones to chase first.** They are the only assumptions whose failure changes the
*research design* rather than the engineering plan, and all four are answerable with a few hours of
account checks and licence reading. Doing that in week 1 rather than week 10 is the single
highest-leverage risk reduction available to this project.

A2 deserves one honest restatement: the specification names *"GPT-5.6 Tera"* and *"NVIDIA Nemotron 3
Ultra 550B"*. **I cannot verify that either identifier exists.** The architecture is designed so this
does not matter — models are configuration values and no model name appears in code
([model-abstraction.md](model-abstraction.md) §10) — but somebody must open the provider consoles and
write down what is actually there.

## 2. Architectural risks

Ranked by expected damage — probability × consequence — not by how uncomfortable they are to state.

### R1 — Six thousand lines of unverified code · **likelihood: certain · impact: high**

Phases 1–3 exist with zero executed tests and a vertical slice that has never run. The database has
never been created. There are certainly defects; their number and location are unknown.

*Why it ranks first:* every later phase inherits it, and the evaluation converts undetected defects
into published numbers. A grounding-invariant bug would corrupt the primary metric while looking
entirely healthy.

*Mitigation:* Phase 1′ before anything else, with an explicit exit gate including "the slice actually
executed, observed". *Trigger for escalation:* if Phase 1′ exceeds three weeks, the code is worse than
assumed and a partial rewrite of the affected module becomes the cheaper option.

### R2 — Scope · **likelihood: high · impact: high**

Ten phases, four members, two semesters, plus a paper. Comparable capstones routinely deliver 60–70%
of an initial plan. The dangerous version of this failure is not missing a feature; it is arriving at
semester 2 week 12 with a large system and no evaluation.

*Mitigation:* the pre-committed cut list ([roadmap.md](roadmap.md) §6), decided **now** so it is not
negotiated under pressure. Experiments start in semester 2 week 4, not week 10. The invariants,
provenance, security controls, tests, and evaluation are marked never-cut; everything else is
negotiable.

### R3 — Enforced grounding may cost more recall than it buys precision · **likelihood: medium · impact: high (research)**

RQ2. A model forbidden from asserting an unsupported `FACT` may report nothing instead of reporting a
properly labelled `INFERENCE`. If the full system misses substantially more true findings than
Baseline B, the central architectural claim is weakened by the project's own data.

*Mitigation:* measure it deliberately (ablation 1, sharing one code path so the comparison is clean),
and pre-commit to reporting it either way ([experiments.md](experiments.md) §7). *This risk is not
mitigable by engineering* — it is a property of the idea, and the honest response is to measure and
report rather than to design the experiment so it cannot surface.

### R4 — Ground truth · **likelihood: medium-high · impact: high**

Labelling is the bottleneck for every accuracy metric. Public datasets tend to carry flow-level or
host-level labels, while this system produces finding-level output; the mapping between them is
lossy and disputable.

*Mitigation:* three-tier dataset strategy; the matching rule fixed **before** results are seen;
Atomic Red Team in an authorized lab for ATT&CK labels that are correct by construction; a held-out
split fixed before any threshold tuning.

### R5 — No sandbox · **likelihood: low (given the rules) · impact: severe**

No container, no VM, no privilege separation. Every tool runs in-process as the API user. A single
real malware sample submitted to a Phase 4 binary parser is host compromise.

*Why likelihood is low rather than negligible:* the only control is a rule people follow, and this is
a security project where handling a real sample will feel like the natural next step to someone
mid-semester.

*Mitigation:* T1 then T2 ship **first** in Phase 4, before any binary parser. The operating rule
(synthetic or sanitised samples only) is written into [threat-model.md](threat-model.md) §5 and
[README.md](../README.md) rather than assumed.

### R6 — Evaluation conflict of interest · **likelihood: high · impact: high (credibility)**

The team implements the system and its baselines. Weak baselines produce impressive, worthless
results, and the bias operates without anyone intending it.

*Mitigation:* equal tools, equal token ceilings, baseline prompts frozen before seeing system results,
one harness for all conditions, and the person who owns a subsystem does not solely own its
evaluation.

### R7 — SQLite/PostgreSQL divergence · **likelihood: medium · impact: medium**

Development on SQLite, Phase 5 onward on PostgreSQL. The graph traversal design already uses
PostgreSQL-specific constructs (`ARRAY` for the cycle guard); JSON vs JSONB semantics differ; grant-level
append-only has no SQLite equivalent. Bugs found only in production-like environments are the expensive
kind.

*Mitigation:* run the test suite against both engines from Phase 5; Alembic from Phase 1′; keep
engine-specific SQL confined to `core/graph/traversal.py`.

### R8 — Prompt injection · **likelihood: high (attempts) · impact: medium (contained)**

Evidence content is attacker-authored and reaches model prompts. Prevention is not available.

*Mitigation and its honest limit:* containment is structural — no command execution, no
model-authored evidence, no model-authored `FACT`. The worst outcome is a wrong or suppressed
inference, attributed and refutable. Detection of successful manipulation is future work, not a
current capability.

### R9 — Single-process orchestration · **likelihood: low (at capstone scale) · impact: medium**

Investigations run as asyncio tasks in the API process. Multiple uvicorn workers would each hold an
independent semaphore, breaking `max_concurrent` and allowing duplicate scheduling.

*Mitigation:* single worker for now; `InvestigationRunner.submit()` exists as the documented seam for
an external queue. Accepted deliberately — see the orchestration decision in
[architecture.md](architecture.md).

### R10 — Windows as the development platform · **likelihood: certain · impact: low-medium**

`0o600` is a no-op, so artifacts are readable by any process running as the same user. Container
tooling behaves differently under WSL2. Path handling differs.

*Mitigation:* `pathlib` throughout; CI runs on Linux so POSIX behaviour is exercised; the permission
gap is stated in [deployment.md](deployment.md) §4 rather than assumed away.

### R11 — The literature gap may already be filled · **likelihood: medium · impact: medium**

If an existing system already enforces provenance on model-generated security claims, the contribution
narrows to the measurement methodology and the ablations.

*Mitigation:* survey in weeks 1–4, **before** the experimental design is frozen. Narrowing the claim in
week 4 is routine; discovering it at review is not. Note the fallback is still publishable — which is
why this is medium rather than high impact.

### R12 — Model drift · **likelihood: medium · impact: medium**

Provider-side model updates can change results between semester 1 and semester 2, making early and
late numbers non-comparable.

*Mitigation:* record `provider`, `model`, `model_snapshot`, `temperature`, `seed`, and a
`nondeterminism_risk` flag per call; run each condition N≥5 times and report variance; re-run the full
matrix in one window rather than accumulating results across months.

### R13 — Documentation drift · **likelihood: high · impact: medium**

Sixteen design documents now describe a system whose code does not yet match them in several places.
Documents that describe intentions as if they were controls are how a project starts lying to itself —
and this suite is deliberately full of "not implemented" markers that must be removed as features land.

*Mitigation:* `core/limitations.py` and `/capabilities` are machine-readable status, tested against
reality ([testing.md](testing.md) §2 `api/`). §38's definition of done includes updating docs in the
same change. The status tables are the first thing to check in review.

## 3. Decisions requiring team sign-off

Places where this architecture either departs from the specification or resolves something it left
open. Each is defensible; none should be discovered later as a surprise.

| # | Decision | Departs from | Rationale |
|---|---|---|---|
| **D1** | Keep and harden the existing Phase 1–3 code rather than rewrite | — | It is coherent and genuinely encodes the central rule; the gap is verification, not design |
| **D2** | Single package `src/acip/` with internal layering | §24's suggested layout | One import root, enforced layering, no namespace-package complexity for four people |
| **D3** | Evidence normalisation, hypothesis, validation, and risk are **agents and pure modules**, not fixed pipeline stages | §4's pipeline diagram | §2 requires a genuinely agentic system; a fixed pipeline is a workflow with agent-shaped labels |
| **D4** | **Reject Neo4j**; relational graph in PostgreSQL | §10 required the evaluation, not the outcome | Shallow queries at 10²–10⁴ nodes; `entity_edges.evidence_id` cannot be a foreign key across datastores; reversible ([evidence-graph.md](evidence-graph.md)) |
| **D5** | Custom asyncio orchestration, no Celery/Temporal/LangGraph | — | The execution trace *is* the research dataset and must be first-class, not a framework's internal state ([architecture.md](architecture.md)) |
| **D6** | Phase 6 = model abstraction, Phase 7 = reasoning agents | Earlier drafts of these docs | The reasoning agents depend on the model layer; the original order was a dependency error ([roadmap.md](roadmap.md) §0) |
| **D7** | No language model anywhere before Phase 6 | — | Makes Baseline A the actual Phase 5 system rather than a reimplementation |
| **D8** | Confidence lives on findings, not on agent messages | §6's envelope | One number per run averages claims of different strength and cannot be audited |
| **D9** | `EVENT` is not a graph node type | §10's node list | Events are evidence rows; promoting them duplicates the evidence table |
| **D10** | Grounding violations raise, never downgrade | — | A silent downgrade is unobservable; the raise is the research metric |

D3 is the one most worth a deliberate conversation, because it is the difference between building what
the specification's diagram shows and building what its stated intent requires.

## 4. Known debt inventory

Concrete, countable, and all assigned to Phase 1′ unless noted:

| Item | Detail |
|---|---|
| Tests | **Zero.** `conftest.py` has eight fixtures; no test file uses them |
| Vertical slice | **Never executed.** `data/` contains only `.gitkeep` |
| Lint | 18 `ruff` findings |
| Types | 11 `mypy` findings. One is genuine — `orchestrator.py:308` types an agent class as bare `type` where `type[Agent]` is meant. The rest are variable-shadowing inference complaints in `reporting.py` and are not runtime bugs |
| Migrations | `create_all()` only; no Alembic |
| CI | None |
| Secret scanning | None |
| `findings.evidence_ids` | JSON array rather than a join table; blocks CONTRADICTS and G6 until Phase 5 |
| Phase references in `src/` | Several docstrings cite phase numbers predating [roadmap.md](roadmap.md) |
| Rate limiting | Absent (Phase 4) |
| Object-level authz | Absent (before multi-team use) |
| Token revocation / refresh | Absent |
| Model abstraction | Absent (Phase 6) |
| Frontend | Absent (Phase 8) |

## 5. What would make this project fail

Stated bluntly, since a risk register that avoids the summary is not useful:

1. **Building features on the unverified foundation.** Everything downstream inherits the defects, and
   the evaluation publishes them.
2. **Deferring measurement to the end.** The most common capstone failure, and the reason experiments
   are scheduled for semester 2 week 4.
3. **Discovering in semester 2 that no model provider is usable.** Answerable in week 1; if it is not
   answered in week 1, it will be discovered in week 20.
4. **Weak baselines.** Produces numbers that look like a result and are not one.
5. **Cutting the evaluation to keep features.** The cut list exists to make this decision in advance,
   while it is still a judgement rather than a panic.

Items 1–3 are addressed by the schedule. Items 4 and 5 are addressed only by the team choosing to
honour commitments made here, before there was anything at stake in breaking them.
