"""Shared enumerations.

These are the vocabulary of the platform. They are stored as strings in the
database (not native SQL enums) so the schema stays portable between SQLite and
PostgreSQL and so adding a member does not require a migration.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """Coarse RBAC roles. Checked by :mod:`acip.core.security.authz`."""

    VIEWER = "viewer"
    INVESTIGATOR = "investigator"
    ADMIN = "admin"


class InvestigationStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    HALTED = "halted"

    @property
    def terminal(self) -> bool:
        return self in {
            InvestigationStatus.COMPLETED,
            InvestigationStatus.PARTIAL,
            InvestigationStatus.FAILED,
            InvestigationStatus.HALTED,
        }


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AssertionClass(StrEnum):
    """Epistemic status of a claim. See docs/evidence-model.md.

    The distinction is enforced, not decorative: :mod:`acip.core.evidence.store`
    refuses to persist a FACT that is not backed by deterministic tool output.
    """

    FACT = "fact"
    """Directly observed by a deterministic tool or authoritative source."""

    INFERENCE = "inference"
    """Derived from one or more facts by explicit reasoning."""

    HYPOTHESIS = "hypothesis"
    """A candidate explanation that still requires validation."""

    UNKNOWN = "unknown"
    """Cannot currently be established; recorded so gaps stay visible."""


class TimeConfidence(StrEnum):
    """How much to trust an evidence timestamp.

    Log formats such as syslog omit the year, and host clocks drift. Recording
    this prevents a derived timestamp from being reported as observed fact.
    """

    EXACT = "exact"
    DERIVED = "derived"
    APPROXIMATE = "approximate"
    UNKNOWN = "unknown"


class TargetType(StrEnum):
    URL = "url"
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    FILE = "file"
    LOG = "log"
    PCAP = "pcap"
    DESCRIPTION = "description"


class ArtifactKind(StrEnum):
    """Declared or detected kind of an uploaded or ingested artifact.

    Declared by the client and treated as untrusted: intake sanitizers and tool
    adapters validate content headers and magic bytes directly.
    """

    LINUX_AUTH_LOG = "linux_auth_log"
    SYS_LOG = "syslog"
    WEB_SERVER_LOG = "web_server_log"
    GENERIC_LOG = "generic_log"
    PCAP = "pcap"
    PCAP_NG = "pcapng"
    URL_RESPONSE = "url_response"
    URL = "url"
    IP = "ip"
    HASH = "hash"
    BINARY_FILE = "binary_file"
    GENERIC_TEXT = "generic_text"
    UNKNOWN = "unknown"


class EvidenceKind(StrEnum):
    AUTH_EVENT = "auth_event"
    PRIVILEGE_EVENT = "privilege_event"
    SESSION_EVENT = "session_event"
    IOC = "ioc"


class SandboxTier(StrEnum):
    """Isolation level a tool adapter requires. See docs/tools.md.

    Only T0 is implemented in M1; higher tiers are introduced in Phase 4 when
    external binaries and untrusted samples are involved.
    """

    T0_IN_PROCESS = "t0_in_process"
    T1_SUBPROCESS = "t1_subprocess"
    T2_CONTAINER = "t2_container"
    T3_NETWORK = "t3_network"


class EntityType(StrEnum):
    """Node types for the evidence graph.

    Recorded on evidence in M1 so that Phase 5 can build the graph from data
    already collected, without re-running investigations.
    """

    USER = "user"
    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE = "file"
    HASH = "hash"
    PROCESS = "process"
    PORT = "port"
    EMAIL = "email"


class AgentCapability(StrEnum):
    """What an agent can do.

    The planner selects agents by capability rather than by name, so a new agent
    becomes eligible for selection by declaring a capability and registering.
    """

    TRIAGE = "triage"
    LOG_ANALYSIS = "log_analysis"
    REPORTING = "reporting"
    HYPOTHESIS = "hypothesis"
    VALIDATION = "validation"
    ORCHESTRATION = "orchestration"


class RetentionState(StrEnum):
    """Lifecycle retention state of investigation raw artifacts."""

    REPRODUCIBLE = "reproducible"
    DERIVED_ONLY = "derived_only"
    MINIMAL_AUDIT_ONLY = "minimal_audit_only"


class HypothesisStatus(StrEnum):
    """Status of a competing explanatory hypothesis."""

    PROPOSED = "proposed"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNRESOLVED = "unresolved"


class EvidenceRole(StrEnum):
    """Relationship between an evidence observation and a finding or hypothesis."""

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"


class FinishReason(StrEnum):
    """LLM completion termination reason."""

    STOP = "stop"
    LENGTH = "length"
    TOOL_CALLS = "tool_calls"
    CONTENT_FILTER = "content_filter"
    ERROR = "error"


class TaskClass(StrEnum):
    """Abstract classification of an LLM task.

    Agents request a task class rather than a model identifier. The ModelRouter
    resolves candidates and fallback chains based on configuration.
    """

    PLANNING = "planning"
    EXTRACTION = "extraction"
    CLASSIFICATION = "classification"
    CORRELATION = "correlation"
    HYPOTHESIS = "hypothesis"
    VALIDATION = "validation"
    NARRATIVE = "narrative"
    CHAT = "chat"
