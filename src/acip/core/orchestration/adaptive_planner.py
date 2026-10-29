"""Adaptive Investigation Planner.

Phase 7 implementation of the Planner protocol. Uses domain heuristics,
observed evidence signals, and capability matching to dynamically compose
investigation plans.

Adheres strictly to the same protocol as StaticPlanner so the two can be
swapped in ablation studies on identical inputs. Constrained to emitting
tasks that name only registered agents and never exceeds the investigation task cap.
"""

from __future__ import annotations

from acip.agents.registry import AgentRegistry
from acip.core.orchestration.planner import Plan, Task
from acip.db.models import Artifact, Investigation
from acip.logging import get_logger
from acip.types import ArtifactKind, TargetType

logger = get_logger(__name__)

DEFAULT_MAX_TASKS = 10


class AdaptivePlanner:
    """Dynamic, evidence-driven planner implementing the Planner protocol."""

    name: str = "adaptive"

    def __init__(
        self,
        registry: AgentRegistry,
        *,
        max_tasks: int = DEFAULT_MAX_TASKS,
    ) -> None:
        self._registry = registry
        self._max_tasks = max_tasks

    def plan(self, investigation: Investigation, artifacts: list[Artifact]) -> Plan:
        tasks: list[Task] = []
        notes: list[str] = []

        step = 1

        # 1. Triage always runs first: establishes initial inventory and boundaries
        if self._registry.has("triage"):
            tasks.append(
                Task(
                    task_id=f"t{step}-triage",
                    agent_name="triage",
                    rationale=(
                        "Initial triage inventories indicators and entities in the submission, "
                        "establishing scope and severity boundaries."
                    ),
                )
            )
            step += 1

        # 2. Inspect submitted artifacts for log, text, or packet data
        has_logs = (
            any(
                a.kind
                in {
                    ArtifactKind.LINUX_AUTH_LOG.value,
                    ArtifactKind.WEB_SERVER_LOG.value,
                    ArtifactKind.SYS_LOG.value,
                    ArtifactKind.GENERIC_LOG.value,
                    ArtifactKind.GENERIC_TEXT.value,
                    ArtifactKind.URL_RESPONSE.value,
                }
                or a.kind == ArtifactKind.UNKNOWN.value
                for a in artifacts
            )
            or investigation.target_type == TargetType.LOG.value
        )

        has_pcap = (
            any(a.kind == ArtifactKind.PCAP.value for a in artifacts)
            or investigation.target_type == TargetType.PCAP.value
        )

        if has_logs and self._registry.has("log_analysis"):
            tasks.append(
                Task(
                    task_id=f"t{step}-log-analysis",
                    agent_name="log_analysis",
                    rationale=(
                        f"Detected {len(artifacts)} candidate artifact(s) containing log "
                        "records; scheduling deterministic authentication and web log parsers."
                    ),
                )
            )
            step += 1

        if has_pcap and self._registry.has("network_analysis"):
            tasks.append(
                Task(
                    task_id=f"t{step}-network-analysis",
                    agent_name="network_analysis",
                    rationale="Packet capture artifact present; extracting flows and DNS queries.",
                )
            )
            step += 1

        # MITRE mapping for detection rules from triage, log, or web analysis
        if self._registry.has("mitre"):
            tasks.append(
                Task(
                    task_id=f"t{step}-mitre",
                    agent_name="mitre",
                    rationale=(
                        "Maps deterministic detection rule findings directly to verified "
                        "MITRE ATT&CK Enterprise tactics and techniques (Invariant G7)."
                    ),
                )
            )
            step += 1

        # 3. Evidence Graph Correlation
        if self._registry.has("correlation"):
            tasks.append(
                Task(
                    task_id=f"t{step}-correlation",
                    agent_name="correlation",
                    rationale=(
                        "Resolves canonical entities across all collected evidence and constructs "
                        "the verified, evidence-backed relational graph."
                    ),
                )
            )
            step += 1

        # 4. Attack Chain Reasoning over the Graph
        if self._registry.has("reasoning"):
            tasks.append(
                Task(
                    task_id=f"t{step}-reasoning",
                    agent_name="reasoning",
                    rationale=(
                        "Performs multi-hop graph path analysis to reconstruct cross-source "
                        "attack progressions and lateral movement."
                    ),
                )
            )
            step += 1

        # 5. Hypothesis Generation (Invariant G3)
        if self._registry.has("hypothesis"):
            tasks.append(
                Task(
                    task_id=f"t{step}-hypothesis",
                    agent_name="hypothesis",
                    rationale=(
                        "Generates competing candidate explanations declaring mandatory "
                        "falsification/refutation conditions (Invariant G3)."
                    ),
                )
            )
            step += 1

        # 6. Adversarial Validation
        if self._registry.has("validation"):
            tasks.append(
                Task(
                    task_id=f"t{step}-validation",
                    agent_name="validation",
                    rationale=(
                        "Challenging hypotheses and claims against observed evidence; "
                        "evaluates refutation conditions to mark hypotheses SUPPORTED or REFUTED."
                    ),
                )
            )
            step += 1

        # 7. Reporting always runs last
        if self._registry.has("reporting"):
            tasks.append(
                Task(
                    task_id=f"t{step}-report",
                    agent_name="reporting",
                    rationale=(
                        "Synthesizes grounded findings, validated hypotheses, and computed "
                        "deterministic risk roll-up into the final investigation report."
                    ),
                )
            )

        # Enforce Task Cap and Filter Unavailable Agents
        valid_tasks: list[Task] = []
        for t in tasks:
            if not self._registry.has(t.agent_name):
                notes.append(f"Dropped unregistered capability: {t.agent_name}")
                continue
            if len(valid_tasks) >= self._max_tasks:
                notes.append(f"Plan truncated at max_tasks cap ({self._max_tasks})")
                break
            valid_tasks.append(t)

        notes.append(
            "Adaptive planner dynamically scheduled tasks based on "
            "artifact types and active capabilities."
        )

        return Plan(
            tasks=tuple(valid_tasks),
            strategy=self.name,
            notes=tuple(notes),
        )
