# Agent Architecture and Contracts

## 1. What an agent is

An agent is a unit of investigative work with a typed input and a typed output. It may reason, but
it may only **assert** through the evidence store, which enforces the grounding invariants. That is
the structural reason an agent cannot become an unquestioned source of truth.

Agents do not talk to each other. The orchestrator passes results along. This keeps the execution
trace linear and auditable, and it means adding an agent cannot create a hidden coupling to another
agent's internals.

## 2. The contract

From `acip/agents/base.py`:

```python
@dataclass
class AgentContext:
    investigation: Investigation
    artifacts: list[Artifact]
    session: AsyncSession
    store: EvidenceStore  # the only way to assert
    tools: ToolRunner  # the only way to produce evidence
    settings: Settings
    agent_run_id: uuid.UUID


class AgentResult(BaseModel):
    status: RunStatus = SUCCEEDED
    summary: str = ""
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    metrics: dict[str, Any] = {}
    next_actions: list[str] = []  # advisory; the orchestrator decides
    errors: list[str] = []


class Agent(ABC):
    name: ClassVar[str]
    version: ClassVar[str]
    capability: ClassVar[AgentCapability]

    async def run(self, ctx: AgentContext, inputs: dict[str, Any]) -> AgentResult: ...
```

`next_actions` is explicitly advisory. An agent may believe further work is warranted; only the
orchestrator schedules it. Without that boundary an agent could drive the investigation from inside
a task and the plan would stop being a reviewable artifact.

Agents are selected by **capability**, not by name (`AgentCapability` in `types.py`). A new agent
becomes eligible for planning by declaring a capability and registering — the planner needs no edit.

### Relationship to the spec's message envelope

§6 specifies a structured envelope with `investigation_id`, `task_id`, `agent`, `status`, `findings`,
`evidence_refs`, `confidence`, `next_actions`, `errors`. That envelope is realised as the pair
`(AgentRun row, AgentResult)` rather than as a message on a bus:

| §6 field | Where it lives |
|---|---|
| `investigation_id`, `task_id`, `agent` | `agent_runs` columns |
| `status`, `errors`, `next_actions` | `AgentResult` → persisted into `agent_runs.outputs` |
| `findings`, `evidence_refs` | `finding_ids` / `evidence_ids`, resolvable to real rows |
| `confidence` | On each finding, not on the message — see below |

Confidence sits on findings rather than on the agent's message deliberately. A single agent run
routinely produces claims of differing strength; one number for the whole run would be an average
that means nothing and cannot be audited.

Communication is through the database rather than a broker because the trace must be durable and
queryable after the fact — it is the research dataset ([experiments.md](experiments.md)).

## 3. Orchestration

`Orchestrator.execute()` runs a plan task by task. Each task spans three short transactions:

1. Insert the `AgentRun` as `running` and **commit** — the attempt is durable, so a crash mid-task
   leaves visible evidence it was tried.
2. Run the agent. Commit on success; **roll back on failure**, discarding partial evidence and tool
   rows from the failing task. Partial output from a failed tool must not become citable evidence.
3. Update the `AgentRun` with its outcome and commit.

**Restart recovery.** This durable trace is not durable execution. On API startup, Phase 1′ recovery
marks unfinished `queued`/`running` investigations and agent runs as `interrupted`, writes an audit
reason, and never silently resumes or overwrites them. An explicit retry creates a new attempt. The
single supported runner holds a database-backed claim before scheduling, preventing a second process
from starting the same investigation; multiple workers remain unsupported until an external queue
owns leases and heartbeats.

**Failure policy.** A failing task does not abort the investigation. Later tasks still run, and the
report records what failed — "step three crashed" is itself a finding a reader needs. Terminal
status is derived from the outcome set:

| Outcomes | Status |
|---|---|
| all succeeded | `completed` |
| some succeeded, some failed | `partial` |
| all failed / none ran | `failed` |
| budget exhausted | `halted` |

An investigation is therefore never reported `completed` when part of it did not run.

**Budgets.** A wall-clock budget (`max_investigation_seconds`) and task cap
(`max_tasks_per_investigation`) bound every run. Reporting receives a grace budget even past the
deadline, because a halted investigation with no report is indistinguishable from one that produced
nothing.

## 4. Planning

```python
@dataclass(frozen=True)
class Task:
    task_id: str
    agent_name: str
    rationale: str  # the recorded reason this task exists
    inputs: dict[str, Any]


class Planner(Protocol):
    name: str

    def plan(self, investigation, artifacts) -> Plan: ...
```

`rationale` is mandatory and persisted on the agent run, then rendered in the report, so an
investigation can always answer "why was this step taken?". A plan that cannot explain itself is not
auditable.

Two implementations, one interface — this is a **research seam**, not a refactoring convenience:

- **`StaticPlanner`** (implemented). Every branch is a stated rule over observable inputs, so the
  same submission always yields the same plan. Reproducibility is what makes it usable as the control
  condition.
- **`AdaptivePlanner`** (Phase 7). LLM-backed, constrained to emitting `Task` objects that name
  **registered** agents. It selects among known capabilities and can never invent an executable step.
  It also cannot exceed the task cap or bypass the budget.

Both are measured on identical inputs. §22 requires a static-vs-dynamic ablation; keeping them behind
one interface is what makes that comparison valid rather than a comparison of two codebases.

The planner also degrades explicitly: if a planned agent is not registered, it is dropped and the
omission is recorded in `Plan.notes` and surfaced in the report, rather than failing the whole
investigation or silently skipping work.

## 5. Roster

### Implemented

| Agent | Capability | Does |
|---|---|---|
| `triage` | `TRIAGE` | Classifies the submission, extracts IOCs, inventories entities, estimates initial severity |
| `log_analysis` | `LOG_ANALYSIS` | Runs `auth_log_parser`, applies deterministic detection rules, records auth findings |
| `reporting` | `REPORTING` | Renders the report from stored records; computes the risk roll-up |

The reporting agent's narrative is **template-produced from stored records** — no language model is
involved anywhere in the current build. `core/limitations.py` states this in the report itself.

### Planned

| Agent | Phase | Notes |
|---|---|---|
| `network_analysis` | 4 | PCAP via Zeek/TShark/Suricata |
| `endpoint_analysis` | 4 | Processes, persistence, registry, YARA; never executes samples |
| `threat_intelligence` | 4 | Reputation lookups; T3 tools; records source/query/timestamp |
| `mitre` | 4 | Maps behaviour to tactics/techniques; validated against the local catalog |
| `correlation` | 5 | Entity resolution, evidence graph construction, timeline |
| `hypothesis` | 7 | Generates competing explanations; must state refutation conditions |
| `reasoning` | 7 | Cross-source attack-chain reasoning |
| `validation` | 7 | Challenges conclusions; can return the investigation to the orchestrator |
| `risk` | 7 | Deterministic score + attributed LLM opinion, never overwriting the score |
| `investigator_chat` | 8 | Answers questions from structured investigation data only |

Everything in this roster through Phase 5 is deterministic. The first agent to use a language model
arrives in Phase 6, after the model abstraction layer exists — see [roadmap.md](roadmap.md) §0.

The MITRE agent must never emit a technique id absent from the loaded catalog — planned invariant G7
in [evidence-model.md](evidence-model.md). §5.7: never hallucinate ATT&CK IDs.

The validation agent is the one component permitted to send an investigation backwards. Its
re-entry path is bounded by the same task cap and wall-clock budget, and loop detection (§29) caps
re-validation cycles so a disagreement between two agents cannot spin indefinitely.

## 6. Adding an agent

1. Declare a capability in `AgentCapability` if none fits.
2. Subclass `Agent`; set `name`, `version`, `capability`.
3. Implement `run()`. Produce evidence only through `ctx.tools`; assert only through `ctx.store`.
4. Register in `agents/registry.py::build_default_registry()`.
5. Teach the planner when the agent is applicable, with a written `rationale`.
6. Tests: unit tests for the agent's logic, an integration test that it writes the expected evidence
   and findings, and a grounding test that it cannot produce a `FACT` without tool-backed evidence.
7. Update this roster and prune the matching line from `core/limitations.py`.

Version bumps matter: `agent_version` is recorded on every run, and the evaluation compares agent
versions across experiment runs. Changing an agent's output without bumping its version corrupts the
research dataset.
