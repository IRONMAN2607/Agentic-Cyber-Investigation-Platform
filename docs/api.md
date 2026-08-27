# API Design

FastAPI application, versioned under `ACIP_API_PREFIX` (default `/api/v1`). Interactive docs at
`/docs`; schema at `/openapi.json`. The OpenAPI document is the contract the frontend generates its
client from — no hand-written API types on the frontend side.

## 2. Error envelope

Every error, from every layer, returns the same shape:

```json
{ "code": "not_found", "message": "investigation … not found", "detail": {} }
```

Domain modules raise typed `ACIPError` subclasses carrying an HTTP status and a stable machine-readable
`code`; the API layer translates them. `HTTPException` is not scattered through the domain, so the
same errors are usable from the CLI and from background workers that have no request context.

| Code | Status | Meaning |
|---|---|---|
| `validation_error` | 422 | Request or artifact failed validation |
| `authentication_failed` | 401 | Missing/invalid/expired token |
| `not_authorized` | 403 | Authenticated but insufficient role |
| `not_found` | 404 | Absent, or not visible to this caller |
| `conflict` | 409 | Illegal state transition (e.g. starting a running investigation) |
| `payload_too_large` | 413 | Artifact exceeded `max_artifact_bytes` |
| `tool_unavailable` | 503 | A required tool is not installed |
| `grounding_violation` | 500 | An agent tried to assert what the evidence does not support |
| `internal_error` | 500 | Unhandled |

`grounding_violation` returning **500** is deliberate: it is an agent bug, not a client error. It must
be loud, and its rate is a research metric — see [evidence-model.md](evidence-model.md).

Internal error messages are echoed only when `ACIP_DEBUG` is on, because an exception string can carry
file paths, SQL fragments, or artifact content.

## 3. Authentication and authorization

`POST /auth/login` exchanges credentials for a JWT (HS256, TTL `access_token_ttl_minutes`, default 60).
Bearer token on subsequent requests. Passwords are argon2id.

Roles are ordered — `viewer` < `investigator` < `admin` — so an admin can do anything an investigator
can. Checks live in `core/security/authz.py`, outside the API layer, so background workers can apply
the same rule.

| Capability | Minimum role |
|---|---|
| Read investigations, evidence, findings, reports | `viewer` |
| Create investigation, upload artifact, start investigation | `investigator` |
| Create users, administrative actions | `admin` |

Known gaps, tracked in [risks-and-assumptions.md](risks-and-assumptions.md): no refresh tokens, no
token revocation list (a stolen token is valid until expiry), no per-investigation ownership ACL — any
authenticated `viewer` can read every investigation. Acceptable for a lab deployment, **not** for
shared multi-tenant use, and stated as such rather than left implicit.

## 4. Endpoints

### System

| Method | Path | Role | Notes |
|---|---|---|---|
| `GET` | `/health` | none | Liveness + database reachability |
| `GET` | `/capabilities` | none | Coarse local capability report |
| `GET` | `/admin/capabilities` | admin | Detailed diagnostic report |

`/capabilities` reports only coarse feature flags and declared limitations, sufficient for a local UI
to avoid implying unavailable functionality. It exposes no investigation data, tool versions, sandbox
details, probe reasons, paths, or configuration. The authenticated administrator-only
`/admin/capabilities` endpoint contains registered agents and tools with live `probe()` diagnostics.
This preserves honest local diagnostics without providing reconnaissance detail if the deployment
boundary later changes.

### Auth

| Method | Path | Role |
|---|---|---|
| `POST` | `/auth/login` | none |
| `GET` | `/auth/me` | authenticated |

### Investigations

| Method | Path | Role | Notes |
|---|---|---|---|
| `POST` | `/investigations` | investigator | Create investigation in `created` status |
| `GET` | `/investigations` | viewer | List investigations with optional `status` & `target_type` filters |
| `GET` | `/investigations/{id}` | viewer | Detail: workspace state, artifacts, runs, findings, counts |
| `PATCH` | `/investigations/{id}` | investigator | Update investigation metadata (`title`, `target_value`, `retention_state`) |
| `GET` | `/investigations/{id}/progress` | viewer | Real-time progress metric, completion percentage, task counts |
| `GET` | `/investigations/{id}/tasks` | viewer | List planned and executed `TaskRun` rows with status & duration |
| `POST` | `/investigations/{id}/tasks` | investigator | Manually append or schedule dynamic task |
| `POST` | `/investigations/{id}/artifacts` | investigator | Multipart upload into quarantine storage (before start) |
| `POST` | `/investigations/{id}/start` | investigator | Queue investigation; returns immediately |
| `POST` | `/investigations/{id}/cancel` | investigator | Cancel in-flight run and transition to `halted` status |
| `POST` | `/investigations/{id}/retry` | investigator | Re-queue failed, halted, or partial investigation |
| `GET` | `/investigations/{id}/evidence` | viewer | Paged evidence query, filterable by `kind` |
| `GET` | `/investigations/{id}/evidence/{evidence_id}/provenance` | viewer | Resolve full provenance chain (tool run, artifact, agent run, gaps) |
| `GET` | `/investigations/{id}/report` | viewer | Generated report (audited on read) |
| `DELETE` | `/investigations/{id}` | investigator | Delete investigation; requires `?purge=true` if append-only records exist |

`start` returns `202`-style semantics with a `StartResponse` rather than blocking: it commits the
status transition **before** scheduling, so the background task cannot race the request transaction for
the row. Progress is observed by polling `/investigations/{id}/progress` or `/investigations/{id}`.

Re-starting a non-`created` investigation is a `409`, not an idempotent no-op — silently ignoring it
would hide a client bug and could double-run tools. For re-running failed or halted work, use
`POST /investigations/{id}/retry`.

### Planned

| Phase | Endpoints |
|---|---|
| 5 | `/investigations/{id}/graph`, `/entities`, `/timeline`, `/findings/{id}/subgraph` |
| 6 | `/investigations/{id}/hypotheses` |
| 8 | `/investigations/{id}/chat`, `/investigations/{id}/events` (SSE), `/report/export` |
| 8 | `/investigations/{id}/attack` (ATT&CK matrix view) |

## 5. Progress reporting

Polling `GET /investigations/{id}` is the M1 mechanism. Phase 8 adds **server-sent events** for live
agent activity.

SSE rather than WebSockets: the stream is one-directional (server → UI), SSE reconnects automatically,
and it needs no protocol upgrade path through a proxy. There is no bidirectional requirement —
investigator chat is request/response.

The events endpoint will emit only **real** state transitions read from `agent_runs` and `tool_runs`.
§15 is explicit: never animate agent activity that is not happening. The UI's animation state is driven
by persisted rows, so a stalled agent looks stalled.

## 6. Conventions

- **Pagination** — use stable cursor pagination for investigation records, evidence, entities,
  timeline, audit, and run history. Each endpoint specifies a bounded `limit` (≤500) and an opaque
  cursor derived from a deterministic sort key; offset pagination is not part of the public contract.
- **Timestamps** — ISO 8601 UTC with offset, always.
- **Ids** — UUIDs in payloads; `INV-`/`EVD-`/`FND-` display forms are additional fields, never
  substitutes.
- **Enums** — lowercase snake_case strings matching `types.py`.
- **Versioning** — breaking changes go to `/api/v2`; `v1` is additive-only once the frontend exists.
- **CORS** — explicit origin allow-list from `ACIP_CORS_ORIGINS`, never `*` with credentials.

## 7. Rate limiting

**Not implemented.** Required before any non-localhost deployment: login attempts (credential
stuffing), artifact upload (disk exhaustion), and investigation start (compute exhaustion) all need
limits. Planned for Phase 4 alongside T3 network tools, which additionally need outbound rate limiting
to third-party APIs. Tracked in [security.md](security.md).
