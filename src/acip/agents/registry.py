"""Agent registry.

Agents are looked up by name or capability rather than imported directly by the
orchestrator, so a plan can name an agent it does not have a compile-time
dependency on, and a missing agent surfaces as an explicit error rather than an
import failure at startup.
"""

from __future__ import annotations

from acip.agents.base import Agent
from acip.agents.log_analysis import LogAnalysisAgent
from acip.agents.reporting import ReportAgent
from acip.agents.triage import TriageAgent
from acip.errors import NotFoundError
from acip.types import AgentCapability


class AgentRegistry:
    """Name/capability lookup over the available agents."""

    def __init__(self) -> None:
        self._agents: dict[str, Agent] = {}

    def register(self, agent: Agent) -> None:
        name = type(agent).name
        if name in self._agents:
            raise ValueError(f"Agent '{name}' is already registered")
        self._agents[name] = agent

    def get(self, name: str) -> Agent:
        try:
            return self._agents[name]
        except KeyError:
            raise NotFoundError(f"Unknown agent: {name!r}") from None

    def has(self, name: str) -> bool:
        return name in self._agents

    def by_capability(self, capability: AgentCapability) -> list[Agent]:
        return [agent for agent in self._agents.values() if type(agent).capability is capability]

    def names(self) -> list[str]:
        return sorted(self._agents)

    def describe(self) -> list[dict[str, str]]:
        """Inventory for the ``/system/capabilities`` endpoint."""
        return [
            {
                "name": type(agent).name,
                "version": type(agent).version,
                "capability": type(agent).capability.value,
                "description": type(agent).description,
            }
            for agent in sorted(self._agents.values(), key=lambda a: type(a).name)
        ]


def build_default_registry() -> AgentRegistry:
    """The agents available in this milestone.

    Phase 4 adds the network, endpoint, malware, and threat-intelligence adapters,
    and Phase 7 adds the hypothesis agents; each registers here once its tools exist.
    """
    registry = AgentRegistry()
    registry.register(TriageAgent())
    registry.register(LogAnalysisAgent())
    registry.register(ReportAgent())
    return registry
