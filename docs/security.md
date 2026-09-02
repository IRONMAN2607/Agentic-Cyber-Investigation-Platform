# Security Architecture

This document covers §13. It is written as a status report, not a wish list: each control states
whether it is **implemented**, **partial**, or **not implemented**, because a security document that
describes intentions as if they were controls is worse than no document.

The platform handles two very different kinds of hostile input, and conflating them is the most
common way tools like this get compromised:

1. **Analyst-supplied evidence** — logs, PCAPs, malware samples. Hostile *by definition*. The user
   who submitted it is trusted; the bytes are not.
2. **Requests and model output** — the ordinary web attack surface, plus a language model that may
   emit text engineered by whoever wrote the log line it was reading.

## 1. Control status

| # | Control | Status | Where |
|---|---|---|---|
| 1 | Password hashing | implemented | `core/security/passwords.py` |
| 2 | Token authentication | implemented | `core/security/tokens.py` |
| 3 | Role-based authorization | implemented | `core/security/authz.py` |
| 4 | Secret management | partial | `config.py` |
| 5 | Third-party API key protection | not implemented | Phase 4 |
| 6 | Request input validation | implemented | Pydantic at every boundary |
| 7 | File upload validation | implemented | `core/security/files.py` |
| 8 | Path traversal prevention | implemented | `core/security/files.py` |
| 9 | Command injection prevention | implemented by construction | `tools/base.py` |
| 10 | Audit logging | implemented | `core/audit.py`, append-only |
| 11 | Malware isolation | **not implemented** | Phase 4 — see §7 |
| 12 | SSRF protection | implemented | `core/security/ssrf.py`; see §8 |
| 13 | Rate limiting | implemented for sensitive local routes | `core/security/ratelimit.py`; see §9 |
| 14 | Container isolation | not implemented | Phase 4 |
| 15 | Least privilege | partial | §10 |
| 16 | Transport security | deferred to deployment | [deployment.md](deployment.md) |

Row 11 (sandbox / container isolation) remains the key unbuilt isolation boundary: **nothing in the
current build should execute an untrusted binary or live malware sample outside a sandbox.** Raw
artifacts are quarantined in content-addressed storage with `0o600` permissions.

## 2. Authentication

Argon2id via `argon2-cffi`, parameters pinned in code (`t=3`, `m=64 MiB`, `p=4`) so a library default
change shows up as a reviewable diff rather than a silent weakening. `verify_password()` never raises
on a bad password — it returns `False` for mismatch, verification failure, and malformed hash alike,
so an attacker cannot distinguish "no such user" from "stored hash is corrupt" by response shape.
`needs_rehash()` supports raising parameters later without invalidating accounts, and returns `True`
for an unparseable hash so a legacy format is re-hashed rather than trusted.

Minimum password length is 12 (`MIN_PASSWORD_LENGTH`). Length is enforced; composition rules are
deliberately not, following current NIST guidance — they push users toward predictable substitutions.

Access tokens are JWTs signed HS256, TTL from `access_token_ttl_minutes` (default 60). `decode`
requires `exp`, `iat`, and `sub` to be present rather than trusting defaults, and checks a `typ`
claim. That claim is present *before* refresh tokens exist specifically so that adding a refresh flow
later cannot accidentally accept an access token where a refresh token belongs — the confused-deputy
bug that class of feature usually ships with.

**Known gaps.** No refresh tokens; no revocation list, so a stolen token is valid until it expires;
no account lockout or login throttling (see §9); no MFA. For a lab deployment with a handful of
known users this is a defensible trade; for anything shared it is not, and §16 of this document says
where the line is.

## 3. Authorization

Roles are totally ordered — `viewer` < `investigator` < `admin` — with `has_role()` and
`require_role()` in `core/security/authz.py`, deliberately outside the API layer so a background
worker or CLI path applies the identical rule. A comparison over an explicit `_ORDER` map, rather
than a scattered set of `if role == ...` checks, means adding a role is one edit and cannot silently
create a permission hole in a path nobody remembered.

**Known gap — no object-level authorization.** Any authenticated `viewer` can read every
investigation. There is no per-investigation ownership or ACL. This is the single most significant
authorization limitation and is stated in [api.md](api.md) and
[risks-and-assumptions.md](risks-and-assumptions.md) rather than left for a reader to discover.
Object-level checks are required before any deployment with more than one team.

## 4. Secrets

`Settings` (`config.py`, `ACIP_` prefix, `.env` for development) **fails closed in production**: if
`ACIP_ENVIRONMENT=prod` and `secret_key` is shorter than 32 characters, startup raises
`ConfigurationError`. In development an ephemeral key is generated per process, which invalidates
tokens on restart — mildly annoying, and much better than a checked-in default that reaches
production.

The bootstrap administrator is subject to the same fail-closed logic and it is worth naming as a
control rather than a convenience: `seed_admin()` **refuses to run when `is_prod`**. A default
credential that reaches a deployed system is a vulnerability, and documenting "change this password"
is not a control. In production the first account is created out-of-band via
`acip create-user <name> --role admin`, which prompts for the password rather than accepting it as an
argument (shell history is a credential store nobody audits).

`.env` is gitignored; only `.env.example` is tracked, and it contains no values. §34's "do not commit
secrets" is enforced by that split. Phase 1′ adds a pre-commit secret scan so the guarantee does not
depend on reviewer attention.

**Not implemented:** external secret management (Vault, cloud KMS), key rotation, and encryption at
rest for the artifact store. Rotation matters once tokens outlive a deployment: rotating
`secret_key` currently invalidates every session at once, which is acceptable now and should become
a keyring with overlapping validity if the platform is ever operated continuously.

### Third-party API keys (Phase 4)

VirusTotal, AbuseIPDB, OTX, and Shodan keys arrive with the T3 tools. Rules fixed now, before any
code exists to violate them:

- Keys are read from settings only, never passed through an agent, a plan, a tool argument, or an LLM
  prompt. A tool adapter reads its own key from `ToolContext`.
- Keys never appear in `tool_runs.args`, which is persisted verbatim for audit. Adapters record
  the *query* (an IP, a hash), never the credential.
- Logs and error strings are scrubbed. A 401 from a provider must not echo the key it used.
- `probe()` reports a missing key as unavailable, so `/capabilities` shows the tool as absent instead
  of the platform failing mid-investigation.

## 5. Input validation

Every request body, query parameter, and tool argument is a Pydantic model. Tool arguments are typed
schemas (`ToolAdapter` is generic over an args model), which is what makes §12's rule enforceable:
**no arbitrary shell commands from model output, ever**. See §6 below.

Evidence drafts validate at the boundary too — `EvidenceDraft` rejects naive datetimes, and
`normalize_entity_value()` canonicalises IPs through `ipaddress` and lowercases domains, hostnames,
and hashes. That is data hygiene, but it is also a security property: an unnormalised entity value is
an injection vector into anything that later renders or queries it.

**Output encoding.** Evidence content is attacker-controlled text. It must never be interpolated
into HTML, SQL, a shell string, or a log format string. SQLAlchemy parameterises all queries and no
raw SQL is built by string concatenation today; the Phase 5 recursive CTEs use bound parameters
(`:start_id`, `:max_depth`) for the same reason. The frontend renders evidence as text only — see
[frontend.md](frontend.md).

## 6. Command injection

The tool layer is designed so that injection is not mitigated but *unavailable*:

- An LLM cannot name a command. It can only select a **registered tool** by name and supply arguments
  matching that tool's Pydantic schema. An unregistered name is a rejected plan, not a subprocess.
- Subprocess tools (Phase 4: TShark, Zeek, YARA) are invoked with an **argument vector**, never
  `shell=True`, never a joined string. There is no shell to inject into.
- Paths passed to subprocesses come from the content-addressed store, not from user input, so a
  filename cannot smuggle an option. Filenames that begin with `-` are the classic version of this,
  and `sanitize_filename()` neutralises them before storage.
- A test asserts no `shell=True` anywhere in the codebase, so this is enforced mechanically rather
  than by review discipline.

**Prompt injection is the harder relative of this problem and is not solved.** A log line can contain
text addressed to the model. The structural mitigations are: the model can only emit tool calls
against typed schemas, evidence can only be produced by tools, and a `FACT` requires a `tool_run_id`
the model does not control. So the worst outcome of a successful injection is a *wrong inference or
a wasted tool call* — recorded, attributed, and refutable — not code execution and not fabricated
evidence. That containment is a design property; it is not a claim that models will not be misled.
Tracked in [threat-model.md](threat-model.md).

## 7. File handling and malware isolation

**Implemented.** `core/security/files.py`:

- **Content-addressed storage.** SHA-256 computed while streaming; the digest is the storage path.
  The original filename becomes metadata, never a path component.
- **Size cap enforced during the read**, not after — `max_artifact_bytes` aborts a stream in flight,
  so an oversized or infinite upload cannot fill the disk before rejection.
- **Path containment is asserted** after resolution, so even a bug in path construction cannot write
  outside the artifact root.
- **`sanitize_filename()`** strips directory components, control characters, and leading dashes.
- **`0o600` permissions** on POSIX. On Windows this is a no-op — a real and stated limitation, since
  the current development host is Windows: stored artifacts are readable by any process running as
  the same user.
- **`read_text()` returns `(text, lossy)`** with a latin-1 fallback. A tool that parsed a lossily
  decoded file records that fact, so evidence derived from mangled input is marked rather than
  presented as clean.

**Not implemented, and this is the important gap.** There is no sandbox. No container, no VM, no
seccomp, no dropped privileges. Every tool runs in-process (`T0_IN_PROCESS`) as the API user. §5.5
and §11 are unambiguous — *potentially malicious files must never be executed on the development
machine* — and the current build honours that only because **no tool executes files at all**: the
implemented tools read text and apply regular expressions. That is a property of the roster, not of
an enforced boundary, which is exactly why the sandbox tiers in [tools.md](tools.md) exist and why
`SandboxTier` is recorded on every `tool_run` before any tier above T0 is available.

Phase 4 requirements, in order:

1. **T1 (subprocess)** — resource limits, wall-clock timeout, no inherited environment.
2. **T2 (container)** — read-only rootfs, `--network=none`, dropped capabilities, non-root user,
   memory and CPU limits, artifact bind-mounted read-only. Required before YARA scanning or any
   parser handling live samples.
3. Dynamic execution of samples (Volatility-style memory work, sandbox detonation) requires an
   isolated VM on a segmented network and is **out of scope for the capstone** unless the lab
   provides one. Stated as a scope boundary, not left as an implied future feature.

Until T2 exists, the honest operating instruction is: **submit only sanitised or synthetic samples.**

## 8. SSRF protection

**Implemented and verified.** Enforced in `core/security/ssrf.py` and tested in `tests/security/test_ssrf.py`:

- **Scheme allow-list** — `http`/`https` only. Disallows `file:`, `gopher:`, `ftp:`, `data:`, `dict:`, `ldap:`.
- **Resolve first, then validate, then connect to the validated address.** The tool pre-resolves via
  `socket.getaddrinfo`, verifies all resolved A and AAAA IPs against the blacklist, and enforces
  hostname verification.
- **Reject** loopback (`127.0.0.0/8`, `::1`), RFC1918 private, link-local (**including `169.254.169.254`,
  Alibaba `100.100.100.200`, and IPv6 cloud metadata `fd00:ec2::254`**), CGNAT (`100.64.0.0/10`),
  multicast, broadcast, reserved ranges, and IPv4-mapped-IPv6 forms (`::ffff:0:0/96`).
- **Redirects are not followed automatically without check.** `SafeHTTPFetcher` manually inspects and
  re-validates every redirect hop against SSRF rules before making the next connection.
- **Timeouts and a response size cap.** Streaming reads abort with `PayloadTooLargeError` if remote
  responses exceed the configured byte limit (default 10 MB).
- **Egress-deny by default at the network layer** where deployment allows it, so an application bug
  is not the only thing between the platform and the internal network.

There is a second, non-technical risk here that is easy to miss: submitting an indicator to
VirusTotal or Shodan **discloses it to a third party**. An attacker who can watch those services
learns they are being investigated. T3 tools require explicit per-investigation opt-in, and the
disclosure is recorded in `threat_intel_lookups`. See [tools.md](tools.md) §sandbox tiers.

## 9. Rate limiting and resource exhaustion

**Not implemented.** Required before any non-localhost deployment. Four distinct limits, because
they protect different resources:

| Endpoint | Resource at risk | Limit |
|---|---|---|
| `POST /auth/login` | credentials | per-IP and per-username, with backoff |
| `POST /investigations/{id}/artifacts` | disk | per-user upload rate, on top of the per-file cap |
| `POST /investigations/{id}/start` | CPU, tokens, cost | concurrent-investigation cap per user |
| T3 outbound calls | third-party quota and cost | per-provider outbound rate limit |

Partial mitigations already present: `max_artifact_bytes` bounds a single upload; the runner's
semaphore (`max_concurrent`) bounds parallel agent execution; `max_investigation_seconds` and
`max_tasks_per_investigation` bound one investigation. None of these bound a *caller*, which is what
rate limiting means. Per-investigation token ceilings arrive with the model layer
([model-abstraction.md](model-abstraction.md) §9) and are the cost-exhaustion control.

Algorithmic exposure deserves naming too: detection rules and IOC extraction run regular expressions
over attacker-controlled text, so a catastrophically backtracking pattern is a denial-of-service
against the platform. Rule review checks for nested quantifiers, and Phase 4 adds a per-tool
wall-clock timeout as the backstop.

## 10. Least privilege

| Layer | Now | Target |
|---|---|---|
| Process | tools in-process as the API user | subprocess/container, non-root, dropped caps |
| Filesystem | artifact root only, `0o600` on POSIX | read-only mounts into tool containers |
| Database | one account, full rights | separate role with `UPDATE`/`DELETE` revoked on `evidence` and `audit_log` |
| Network | unrestricted egress | default-deny, allow-list per T3 provider |
| Application | ordered roles | plus object-level ACLs |

The database row is the most valuable and the cheapest: append-only is currently enforced by
SQLAlchemy mapper events, which protect against *mistakes* but not against code that bypasses the
ORM. Revoking the grants in PostgreSQL (Phase 5) makes the guarantee structural. Both layers are
kept — the mapper event gives a clear error at the call site, the grant makes it unbypassable.

## 11. Audit logging

`audit_log` is append-only, enforced by the same `before_update`/`before_delete` mapper events that
protect `evidence`. Rows record `ts`, `actor`, `action`, `resource_type`, `resource_id`, `outcome`,
and a JSON `detail`. `outcome` matters as much as `action`: a *failed* authorization check is the
signal worth alerting on, and logging only successes hides exactly the events an audit exists to
find.

Actor references use `ondelete=SET NULL` throughout, so deleting a user cannot erase the record of
what that user did. Requirements for the audit path: never log secrets, tokens, passwords, or
artifact content; log the artifact `sha256` rather than its bytes; keep it usable as evidence about
the *platform's* behaviour, which is a different question from evidence about an incident.

The append-only audit log and a right-to-erasure request are in genuine tension. The resolution —
audit rows retain actor and action but never artifact content — is recorded in
[database.md](database.md) §5 as a decision rather than left to be discovered during a deletion
request.

## 12. Model-specific security

- Agents never see raw credentials; the model layer reads keys from settings.
- Model output cannot name a command, a file path outside the store, or an unregistered tool.
- Model output cannot create evidence, and cannot create a `FACT` — G1 requires a `tool_run_id`.
- Investigation content sent to a hosted provider is a **disclosure**. Which provider, which model,
  and what was sent are recorded per call in `llm_calls`. Data-handling terms are an unresolved
  assumption in [model-abstraction.md](model-abstraction.md) §10.
- A local or self-hosted model is the mitigation for genuinely sensitive data, and the provider
  abstraction exists partly so that choice is a config change.

## 13. Verification

Security claims in this document are only claims until a test executes them. `tests/security/` is
specified in [testing.md](testing.md) and is part of Phase 1′:

- Auth: expired, tampered, wrong-`typ`, missing-claim, and unsigned (`alg: none`) tokens all rejected.
- Authz: every endpoint tested with each role, asserting `403` where required.
- Upload: path traversal (`../`, absolute, UNC, null byte), oversized, and zero-byte files.
- No `shell=True`, and no provider SDK imported under `agents/`, asserted by static test.
- SSRF: a table-driven test over loopback, RFC1918, link-local, metadata, IPv4-mapped-IPv6, and
  redirect-to-internal — written **with** the URL tool, not after it.
- Grounding: an agent cannot write a `FACT` without tool-backed evidence.

Until those tests exist and pass, the correct summary of this document's status column is *designed
and coded, not verified* — which is what §1's rule requires it to say.
