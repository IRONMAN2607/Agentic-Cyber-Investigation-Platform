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
| `GET` | `/capabilities` | none | **Honest** capability report |

`/capabilities` reports registered agents, registered tools with live `probe()` results, and the
declared limitations from `core/limitations.py`. It is the mechanism that stops the UI from implying a
capability the deployment lacks (§31). It is unauthenticated so a deployment can be inspected before
credentials exist; it exposes no investigation data.

### Auth

| Method | Path | Role |
|---|---|---|
| `POST` | `/auth/login` | none |
| `GET` | `/auth/me` | authenticated |

### Investigations

| Method | Path | Role | Notes |
|---|---|---|---|
| `POST` | `/investigations` | investigator | Create |
| `GET` | `/investigations` | viewer | List |
| `GET` | `/investigations/{id}` | viewer | Detail: status, plan, runs, findings |
| `POST` | `/investigations/{id}/artifacts` | investigator | Multipart upload |
| `POST` | `/investigations/{id}/start` | investigator | Queue; returns immediately |
| `GET` | `/investigations/{id}/evidence` | viewer | Paged, filterable by `kind` |
| `GET` | `/investigations/{id}/report` | viewer | Generated report |

`start` returns `202`-style semantics with a `StartResponse` rather than blocking: it commits the
status transition **before** scheduling, so the background task cannot race the request transaction for
the row. Progress is observed by polling the detail endpoint.

Re-starting a non-`created` investigation is a `409`, not an idempotent no-op — silently ignoring it
would hide a client bug and could double-run tools.

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

- **Pagination** — `limit` (≤500) / `offset`, with `total`. Cursor pagination if evidence volumes
  demand it.
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
