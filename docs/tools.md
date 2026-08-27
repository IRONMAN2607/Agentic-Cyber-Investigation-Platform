# Tool Architecture

A tool adapter is the only component permitted to produce evidence. Everything the platform claims
as observed fact enters through this layer, so the contract is deliberately narrow.

Referenced from `acip/types.py` (`SandboxTier`) and `acip/tools/base.py`.

## 1. The contract

```python
class ToolAdapter(ABC):
    name: ClassVar[str]
    version: ClassVar[str]              # bumped when output changes; recorded on every run
    tier: ClassVar[SandboxTier]
    args_model: ClassVar[type[BaseModel]] = NoArgs
    requires_artifact: ClassVar[bool] = False

    def probe(self) -> ToolAvailability: ...
    async def execute(self, args: BaseModel, ctx: ToolContext) -> ToolResult: ...
```

Four properties matter, and each closes an attack or honesty gap:

**Arguments are a validated Pydantic model.** An agent — or later an LLM — can only express what the
schema permits. There is no free-form command line anywhere in the platform. This is the structural
answer to §12's "never allow arbitrary shell commands from LLM output": the LLM does not emit a
command, it fills in a typed form, and the form is validated before anything executes.

**Adapters never accept a path.** File access happens through `ToolContext.artifact_path`, which the
`ToolRunner` resolves and containment-checks. An adapter cannot be induced to read
`/etc/shadow` because it has no parameter through which a path could arrive.

**Results are drafts, not persisted rows.** `ToolResult` carries `EvidenceDraft` objects plus metrics
and warnings. The store assigns provenance and identity. An adapter cannot forge a `tool_run_id`.

**An adapter that cannot do its job says so.** It reports through `warnings` or raises `ToolError`.
It never invents output — §31.

## 2. Availability probing

`probe()` returns `ToolAvailability{name, version, tier, available, reason}`. In-process adapters are
always available; adapters that shell out to an external binary override `probe()` to check for it.
The public capability response exposes only coarse availability; version and reason are administrator
diagnostics so an unavailable dependency or sandbox detail cannot become reconnaissance data.

This is surfaced through `GET /capabilities` so the UI never implies a capability the deployment does
not have. A missing Zeek installation is reported at startup, not discovered halfway through an
investigation and silently swallowed. §31: no fake functionality.

## 3. Sandbox tiers

Isolation is a property of the adapter, declared in code and recorded on every `tool_runs` row.

| Tier | Execution | Use | Phase |
|---|---|---|---|
| `T0_IN_PROCESS` | Pure Python in the API process | Parsing and extraction over text | 1–3 |
| `T1_SUBPROCESS` | Separate process, no network, dropped privileges, rlimits, timeout | Trusted binaries: TShark, Zeek, YARA | 4 |
| `T2_CONTAINER` | Ephemeral container, read-only rootfs, no network, non-root, tmpfs | Untrusted samples, Suricata, Volatility | 4 |
| `T3_NETWORK` | Egress-permitted, allow-listed destinations, rate-limited, audited | Threat intel APIs, DNS, RDAP | 4 |

Tiers are not merely descriptive. The runner will refuse to execute an adapter whose declared tier
exceeds what the deployment is configured to provide, so a container-only tool cannot silently fall
back to running in-process on a developer laptop.

T3 is called out separately from T0–T2 because its risk is *outbound*, not inbound: submitting an
indicator to VirusTotal discloses it to a third party. That has real operational consequences during
a live incident, so T3 tools require explicit configuration and are logged as disclosure events. See
[threat-model.md](threat-model.md).

**Currently implemented: T0 only.** `auth_log_parser` and `ioc_extractor`, both pure Python.

### Security execution profile (required before any tier above T0)

A tool registration is incomplete until it declares and tests: the sandbox tier; immutable container
or VM image identity; CPU, memory, process, disk, and wall-clock limits; network policy (disabled by
default); a read-only artifact mount; a write-only, size-limited output directory; non-root identity;
timeout/cancellation semantics; and persisted executable or image digest. T0 remains restricted to
bounded text parsing. A parser for a hostile binary, archive, PCAP, EVTX, or memory image is not a
T0 extension.

## 4. Auditing

Every invocation writes a `tool_runs` row **before** execution and updates it after, so a crash
leaves a durable record of what was attempted rather than no record at all. Recorded: tool, version,
sandbox tier, validated arguments, status, exit status, evidence count, warnings, timing, error.
This satisfies §12 and supplies the tool-latency and tool-selection-accuracy metrics in
[experiments.md](experiments.md).

## 5. Roster

### Implemented (T0)

| Tool | Produces | Notes |
|---|---|---|
| `auth_log_parser` | `auth_event`, `privilege_event`, `session_event` | Linux auth logs; BSD syslog and ISO-8601 forms |
| `ioc_extractor` | `ioc` | IPs, domains, URLs, hashes, users, hosts, ports, paths, emails |

### Planned

| Tool | Tier | Phase | Notes |
|---|---|---|---|
| TShark | T1 | 4 | PCAP → packet/flow metadata |
| Zeek | T1 | 4 | PCAP → conn/dns/http/ssl logs |
| Suricata | T2 | 4 | PCAP → rule alerts |
| YARA | T2 | 4 | File → rule matches; never executes the sample |
| Sigma | T1 | 4 | Log → rule matches; compiled to the internal event schema |
| Windows EVTX parser | T1 | 4 | Event Log → normalized events |
| DNS / RDAP / WHOIS | T3 | 4 | Passive infrastructure lookup |
| Certificate fetch | T3 | 4 | TLS metadata; SSRF-guarded |
| VirusTotal / AbuseIPDB / OTX / Shodan | T3 | 4 | Reputation; **supporting** evidence only |
| MITRE ATT&CK catalog | T0 | 4 | Local catalog; mappings validated against it |
| Volatility | T2 | 6 | Memory artifacts |

Threat-intelligence results are evidence *that a source said something*, not evidence that the thing
is true. The adapter records source, query, timestamp, result, reputation, and confidence (§5.6), and
findings derived from reputation are `INFERENCE`, never `FACT` about maliciousness.

## 6. Adding a tool

1. Define an args model. Every field typed and constrained; no free-form strings that reach a shell.
2. Subclass `ToolAdapter`; set `name`, `version`, `tier`, `args_model`, `requires_artifact`.
3. Implement `probe()` if an external dependency exists.
4. Implement `execute()`, returning `EvidenceDraft`s with normalized entities and honest
   `time_confidence`.
5. Register in `tools/registry.py::build_default_registry()`.
6. Tests: unit tests on parsing with fixture data, a malformed-input test proving it degrades rather
   than crashes, and a security test for the tier's threat (path containment, argument injection,
   egress allow-listing).
7. Add it to the table above and, if it closes a gap, remove the corresponding line from
   `core/limitations.py`.

A tool is not done until `probe()` tells the truth on a machine where the dependency is absent.
