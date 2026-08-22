"""Tool registry.

Agents resolve tools by name through the registry rather than importing them, so
the set of available tools is a runtime property that can be inspected,
restricted per deployment, and reported honestly through the API.
"""

from __future__ import annotations

from acip.errors import ToolUnavailableError
from acip.tools.auth_log_parser import LinuxAuthLogParser
from acip.tools.base import ToolAdapter, ToolAvailability
from acip.tools.ioc_extractor import IOCExtractor


class ToolRegistry:
    """A name-to-adapter mapping with availability reporting."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolAdapter] = {}

    def register(self, tool: ToolAdapter) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolAdapter:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolUnavailableError(
                f"unknown tool: {name}", detail={"available_tools": sorted(self._tools)}
            )
        return tool

    def has(self, name: str) -> bool:
        return name in self._tools

    def names(self) -> list[str]:
        return sorted(self._tools)

    def capabilities(self) -> list[ToolAvailability]:
        """Probe every tool. Used by ``GET /capabilities``."""
        return [self._tools[name].probe() for name in self.names()]


def build_default_registry() -> ToolRegistry:
    """The tools available in M1.

    Phase 4 adds Zeek, Suricata, TShark, YARA and Sigma adapters here, each
    reporting availability through ``probe`` so a missing binary degrades the
    investigation explicitly instead of silently.
    """
    registry = ToolRegistry()
    registry.register(LinuxAuthLogParser())
    registry.register(IOCExtractor())
    return registry
