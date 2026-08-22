# Deployment and Operations

Covers §30. **Current supported deployment: one developer machine, bound to localhost.** Anything
beyond that requires the controls in [security.md](security.md) §1 rows 11–13 and 16, which do not
exist yet. This document describes what runs today and what production would require, kept separate so
the two are not confused.

## 1. Environments

`ACIP_ENVIRONMENT` is a `Literal["dev", "test", "prod"]` — those exact three values.

| | `dev` | `test` | `prod` |
|---|---|---|---|
| Database | SQLite file | SQLite file per test, temp dir | PostgreSQL (Phase 5) |
| `secret_key` | ephemeral, generated per process | fixture-supplied | **required, ≥32 chars, or startup fails** |
| Admin seeding | yes, warns | yes, via fixture | **refused** |
| Logs | console | `WARNING` console | JSON |
| Debug detail in errors | `ACIP_DEBUG=true` | off | off |
| Schema creation | `create_all()` | `create_all()` | Alembic (Phase 1′) |

Two of those rows are fail-closed behaviours rather than preferences, and both are verified in code:
`Settings._validate_secret()` raises `ConfigurationError` when `prod` has a weak secret, and
`seed_admin()` returns `None` without creating anything when `is_prod`. The consequence is deliberate —
**there is no default credential in production** — so the first account must be created out of band:

```bash
acip create-user alice --role admin
```

That prompts twice via `getpass`, enforces `MIN_PASSWORD_LENGTH`, and never takes the password as an
argument, because shell history is a credential store nobody audits.

## 2. Configuration reference

All settings come from the environment or `.env`, prefixed `ACIP_`. Nothing is hard-coded at a call
site.

| Variable | Default | Notes |
|---|---|---|
| `ACIP_ENVIRONMENT` | `dev` | `dev` \| `test` \| `prod` |
| `ACIP_DEBUG` | `false` | Echoes internal error messages. **Never in prod** |
| `ACIP_LOG_LEVEL` | `INFO` | Validated against the standard levels |
| `ACIP_LOG_FORMAT` | `json` | `json` \| `console` |
| `ACIP_SECRET_KEY` | *(empty)* | Required in `prod`, ≥32 chars |
| `ACIP_ACCESS_TOKEN_TTL_MINUTES` | `60` | 1–1440 |
| `ACIP_DATABASE_URL` | `sqlite+aiosqlite:///./data/acip.db` | `postgresql+asyncpg://…` from Phase 5 |
| `ACIP_DB_ECHO` | `false` | SQL logging; leaks data at `INFO` |
| `ACIP_ARTIFACT_DIR` | `./data/artifacts` | Content-addressed store |
| `ACIP_MAX_ARTIFACT_BYTES` | `26214400` (25 MiB) | Enforced mid-stream |
| `ACIP_MAX_INVESTIGATION_SECONDS` | `300` | Wall-clock budget |
| `ACIP_MAX_TASKS_PER_INVESTIGATION` | `25` | Loop bound (§29) |
| `ACIP_BRUTEFORCE_MIN_FAILURES` | `5` | Detection threshold — **tunable, so it must never be tuned on the evaluation set** |
| `ACIP_BRUTEFORCE_WINDOW_SECONDS` | `300` | As above |
| `ACIP_API_PREFIX` | `/api/v1` | |
| `ACIP_CORS_ORIGINS` | `["http://localhost:5173"]` | JSON list. Never `*` |
| `ACIP_BOOTSTRAP_ADMIN_USERNAME` | `admin` | Ignored in `prod` |
| `ACIP_BOOTSTRAP_ADMIN_PASSWORD` | `changeme-dev-only` | Ignored in `prod` |

The two detection thresholds are configuration on purpose — deterministic rules need tunable
thresholds — and that creates an evaluation hazard worth flagging here rather than only in
[experiments.md](experiments.md): tuning them against the evaluation set silently inflates every recall
number. Threshold values used for a run are recorded in the experiment config.

`ACIP_DB_ECHO` is the other footgun: it writes SQL, including parameter values, to the log. Evidence
content therefore reaches the log file. Development only.

## 3. Local setup

```bash
python -m venv .venv && .venv/Scripts/activate
pip install -e ".[dev]"
cp .env.example .env
acip init
acip serve --reload
```

`acip serve` binds `127.0.0.1:8000` by default — deliberately not `0.0.0.0`, since with no rate
limiting and no TLS the loopback bind is currently a load-bearing security control, not a convenience.

Useful commands:

```bash
acip capabilities
```

That prints what the deployment can actually do: registered agents, registered tools with live
`probe()` results, and the declared limitations from `core/limitations.py`. It is the honest answer to
"what does this build do", available without starting the server, and it is the first thing to run when
something appears to be missing.

## 4. Runtime layout

```text
data/
├── acip.db          SQLite database (gitignored)
└── artifacts/       content-addressed store, sha256-named, 0o600 on POSIX
```

`data/` is gitignored except `.gitkeep` (§34: never commit artifacts or datasets).
`Settings.ensure_directories()` creates both at startup, including the SQLite parent directory.

**`0o600` is a no-op on Windows**, which is the current development platform. Stored artifacts are
readable by any process running as the same user. Stated here as an operational fact, not buried as a
caveat — see [threat-model.md](threat-model.md) §3.5.

## 5. Operations

**Health.** `GET /health` reports liveness and database reachability. Distinguishing "process is up"
from "database is reachable" matters, because the API can serve `/capabilities` while the database is
gone and look healthy to a naive probe.

**Logging.** Structured JSON in production, human-readable console in development. The database URL is
redacted before it reaches the log (`_redact()` strips credentials). Requirements that hold everywhere:
never log secrets, tokens, passwords, or artifact content; log an artifact's `sha256`, never its bytes.

**Audit.** `audit_log` is append-only and is the record of platform activity, distinct from application
logs. Application logs are for debugging and may be rotated away; audit rows are not.

**Backup.** Two things must be backed up together, and the ordering matters: the database and
`artifacts/`. A database referencing a missing artifact breaks the provenance chain — the evidence row
survives while the bytes it was derived from do not, which is the one failure this system's central
claim cannot tolerate. Restore is verified by checking that every `artifacts.sha256` resolves to a file
whose digest matches. That check should be a script, not a habit.

**Migrations.** `create_all()` today, which is acceptable only because no data is worth keeping.
Alembic arrives in Phase 1′ before that stops being true.

## 6. What production would require

None of this exists. Listed so "deploy it" is never mistaken for a small task:

| Requirement | Why |
|---|---|
| TLS termination via reverse proxy (nginx/Caddy) | Bearer tokens over plaintext are stolen tokens |
| Rate limiting | No login throttling today ([security.md](security.md) §9) |
| PostgreSQL with restricted grants | `UPDATE`/`DELETE` revoked on `evidence` and `audit_log` |
| Object-level authorization | Any `viewer` currently reads every investigation |
| Token revocation | A stolen token is valid until expiry |
| Secret management | Env vars only; no rotation, no keyring |
| Container isolation for tools | Everything runs in-process as the API user |
| Egress allow-list | Required before any T3 tool ships |
| Artifact encryption at rest | Retained samples are hostile code |
| Backup verification | See above |
| Uvicorn behind a supervisor, multiple workers | Single process today |

**A note on workers:** the current design runs investigations as asyncio tasks inside the API process
(`InvestigationRunner`). Multiple uvicorn workers would each get an independent runner with an
independent semaphore, so `max_concurrent` would stop meaning what it says and two workers could
schedule the same investigation. Scaling out therefore requires the external queue that
`InvestigationRunner.submit()` was designed as the seam for — it is not a configuration change. This is
recorded in [architecture.md](architecture.md)'s orchestration decision and is the main thing that
decision defers.

## 7. Lab topology for Phase 4+

When container-isolated and network tools arrive, the lab environment becomes part of the security
architecture rather than a detail:

- Analysis host on an **isolated segment**, no route to the campus or home network.
- Tool containers with `--network=none` by default; egress only for T3 tools, through an explicit
  allow-list.
- Sample-handling VM snapshotted before use and reverted after, if dynamic analysis is ever in scope.
- **All offensive activity confined to the authorized lab (§19)**, against hosts the team owns.
  Atomic Red Team executions for ATT&CK ground truth ([experiments.md](experiments.md) §3) happen here
  and nowhere else.

Until that segment exists, the operating rules in [threat-model.md](threat-model.md) §5 are the
deployment security model: localhost, synthetic data, no live malware.
