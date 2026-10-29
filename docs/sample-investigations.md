# Sample Investigations

AACIP includes a local-only sample catalog for demonstrations and evaluation. It
contains one high-risk and one low-risk investigation for every supported target
type, for **16 investigations total**:

| Target type | High-risk sample | Low-risk sample |
|---|---|---|
| Domain | Malicious domain reputation (`evil-attacker.example.com`) | Benign domain reputation (`safe.example.com`) |
| URL | Suspicious login URL (`https://evil-attacker.example.com/login`) | Routine health URL (`https://safe.example.com/status`) |
| IP | Malicious source IP (`198.51.100.23`) | Documentation source IP (`192.0.2.1`) |
| Hash | Known malicious test hash (EICAR test MD5) | Empty-file test SHA-256 |
| File | Quarantined synthetic text artifact containing the known test hash | Routine text report with no indicators |
| Log | SSH password guessing followed by root-level `sudo` | Routine public-key logins and cron activity |
| PCAP | DNS query for the synthetic suspicious domain | Routine DNS query and network flow |
| Description | Incident description containing the suspicious domain | Routine maintenance description |

The high-risk indicators use the project's offline synthetic threat-intelligence
feed and RFC 5737 documentation addresses. No third-party lookup is made. The
file and PCAP artifacts are generated in memory and stored using the same
content-addressed quarantine path as uploaded artifacts; they are never
executed.

## Seed and evaluate

After copying `.env.example` to `.env`, run:

```bash
.venv/Scripts/python.exe -m acip.cli seed-samples
```

On POSIX systems, use `.venv/bin/python` instead. The command migrates the
configured database, ensures the development administrator exists, creates the
sample entries, runs each one through the normal orchestrator, and prints the
computed severity and risk score. It is idempotent by sample title.

To create the entries and artifacts without running the pipeline:

```bash
.venv/Scripts/python.exe -m acip.cli seed-samples --no-run
```

The command is disabled when `ACIP_ENVIRONMENT=prod`. Low-risk examples are
expected to finish with `INFO` or `LOW` severity and a score of 10 or less. The
current deterministic scorer commonly uses `INFO` for clean samples because it
does not turn the absence of an attack into a positive claim. High-risk examples
are expected to finish with `HIGH` or `CRITICAL` severity and a score of at
least 20.

After seeding, start the server and log in with the configured development
administrator to view all entries in the workspace:

```bash
.venv/Scripts/python.exe -m acip.cli serve
```
