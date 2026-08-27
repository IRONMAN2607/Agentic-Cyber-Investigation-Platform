# Testing Architecture

**Current state: 97 tests passing.** The full test suite covers `unit/`, `integration/`, `api/`, `security/`, and `scenarios/`, verifying grounding invariants G0–G4, append-only immutability, provenance integrity, recovery semantics, Alembic upgrades, and the complete M1 vertical slice.

That is stated first because §1 is the project's governing rule: never claim something works without
having verified it. That cuts both ways: the suite below is real and was run, and the gaps in
[roadmap.md](roadmap.md) §3.1 are real too. Four Phase 1′ criteria remain open — an atomic start
claim, a backup/restore integrity check, retention disclosure in the report, and the operating
boundary in the capability output — and no document here should be read as covering them.

## 1. What the fixtures already commit us to

The fixtures encode two decisions worth keeping:

**File-backed SQLite, not `:memory:`.** The orchestrator deliberately opens several short-lived
sessions per task (three transactions per task — see [agents.md](agents.md) §3). An in-memory
database pinned to one connection via `StaticPool` would make cross-transaction visibility bugs
invisible, which is precisely the class of bug the three-transaction design can introduce. The
`Database` class supports `:memory:` correctly, and tests decline to use it on purpose.

**In-process ASGI, not a live server.** `httpx.ASGITransport` drives the app directly, so API tests
share the test's database and need no port, no subprocess, and no sleep-until-ready. `auth_client`
performs a real login and attaches a real token, so authentication is exercised by every API test
rather than stubbed.

Both choices trade a little realism for determinism, and both are the right trade at this scale.
`PRAGMA foreign_keys=ON` is set per connection, so foreign-key and cascade behaviour is genuinely
tested rather than silently ignored as SQLite defaults to.

## 2. Layers

```text
tests/
├── conftest.py        shared fixtures (exists)
├── unit/              pure logic, no I/O beyond a temp dir
├── integration/       real database, real orchestrator
├── api/               ASGI client, real auth
├── security/          the controls in security.md §13
├── scenarios/         labelled end-to-end investigations
└── evaluation/        experiment harness correctness
```

### unit/

Deterministic, fast, no database where avoidable.

- `types.py` — `Severity.rank` ordering, `InvestigationStatus.terminal` membership.
- `contracts.py` — `normalize_entity_value()` per entity type: IPv4/IPv6 canonicalisation through
  `ipaddress`, IPv4-mapped-IPv6 forms, trailing-dot domains, mixed-case hashes, and inputs that are
  *not* valid instances of their declared type.
- `content_hash()` — the property that matters: **two evidence rows with identical intrinsic content
  but different `collected_at` and different run ids must hash equal**, and any change to intrinsic
  content must change the hash. Deduplication correctness is a database-level guarantee resting on
  this function.
- `files.py` — `sanitize_filename()` against `../`, absolute paths, UNC paths, null bytes, control
  characters, leading dashes, reserved Windows device names, and empty results after stripping.
- `passwords.py` — round-trip, mismatch returns `False` rather than raising, malformed hash returns
  `False`, `needs_rehash` on a weaker-parameter hash.
- `tokens.py` — see security/ below; the negative cases matter more than the positive one.
- `planner.py` — every branch, asserting the same inputs always yield the same plan and that each
  `Task` carries a non-empty `rationale`.
- Detection rules — each rule against a positive and a *near-miss* negative fixture. A rule that
  fires on everything is worse than no rule, and only the negative case catches it.

### integration/

Real database, real transactions.

- **Grounding invariants, one test per invariant.** G0–G4 each get a test asserting `GroundingError`
  is raised — not that the value is downgraded. This is the most important test file in the
  repository: it is the executable form of the project's central claim.
- **Append-only enforcement.** `UPDATE` and `DELETE` on `evidence` and `audit_log` both raise. Then
  the same test at the PostgreSQL level once grants are revoked in Phase 5, because the mapper event
  and the grant are different guarantees.
- **Deduplication.** The same tool run twice produces one evidence row; the unique constraint holds
  under concurrent inserts.
- **Orchestrator transaction shape.** An agent that raises must leave its `AgentRun` recorded as
  failed *and* leave no partial evidence behind. This is the one test that justifies the
  three-transaction design, and it can only be written against a file-backed database.
- **Status derivation.** All-succeed → `completed`; mixed → `partial`; all-fail → `failed`; budget
  exceeded → `halted`. Plus the report grace window: a halted investigation still produces a report.
- **Planner degradation.** An unregistered agent in a plan is dropped, recorded in `Plan.notes`, and
  surfaced — not a hard failure and not a silent skip.
- **Cascade and `SET NULL`.** Deleting an investigation removes its owned rows; deleting a user does
  **not** erase what that user did.

### api/

- Every endpoint: success, `404`, `422`, and the wrong-role case.
- `/capabilities` reports registered agents and tools and the live `probe()` results, and its
  `limitations` list matches `core/limitations.py`. A test asserting that the honesty endpoint is
  honest is not a joke — it is what stops the list going stale as features land.
- `start` on a non-`created` investigation returns `409`.
- The error envelope is identical in shape across every failure path, and internal messages are
  absent unless `ACIP_DEBUG` is set.
- Pagination bounds: `limit` above the maximum is rejected, not silently clamped.

### security/

The list in [security.md](security.md) §13, verbatim, because a security control that is only
described is not a control:

- Tokens: expired, tampered signature, wrong `typ`, missing `exp`/`iat`/`sub`, `alg: none`, and a
  token signed with a different secret — each rejected with `401`.
- Authorization: a role matrix over every endpoint, asserting `403` where required. Table-driven, so
  a new endpoint absent from the table is a visible omission.
- Upload: traversal, oversized (aborted mid-stream, not after), zero-byte, and a filename that
  sanitises to nothing.
- Static assertions: no `shell=True` anywhere; no provider SDK imported under `agents/`; no
  hard-coded model name outside config. These enforce §7 and §12 mechanically rather than by review.
- SSRF: table-driven over loopback, RFC1918, link-local including `169.254.169.254`, IPv6 metadata,
  CGNAT, IPv4-mapped-IPv6, and redirect-to-internal. **Written alongside the URL tool, not after it** —
  a URL tool merged without this table is the single most likely way this project ships a real
  vulnerability.
- Grounding-as-security: an agent cannot write a `FACT` without tool-backed evidence.

### scenarios/

End-to-end, labelled, and the bridge between testing and evaluation. Each scenario is a fixture with
a **ground-truth label file**: which findings should appear, which entities, which ATT&CK techniques,
and — critically — what should **not** be found.

`AUTH_LOG_SAMPLE` in `conftest.py` is the seed of the first one: a brute-force burst from
`203.0.113.55`, a successful login for `deploy`, and a `sudo` to root, using RFC 5737 documentation
addresses. It exercises all four `R-AUTH` rules, and the expected output is therefore knowable in
advance.

Scenarios assert on **structure, not prose**: which findings, which assertion classes, which evidence
citations, which severity. Asserting on generated narrative text would make every wording change a
test failure, and would test the template rather than the investigation.

The false-positive assertion is as important as the true-positive one. A scenario with a clean log
must produce zero findings. Without that, every rule can be made to pass by lowering its threshold.

### evaluation/

The harness is code, and code that computes research numbers needs tests more than most: precision,
recall, and F1 against hand-computed values on a tiny fixture; grounding-violation counting; the
`replay.py` provider returning identical output for identical input. A bug here produces plausible
numbers, publishes them, and is never noticed. See [experiments.md](experiments.md).

## 3. Property-based testing

Hypothesis for the three functions where the input space is genuinely adversarial and the property is
crisper than any example set:

- `sanitize_filename()` — the output never contains a path separator, never starts with `-`, and is
  never empty.
- `normalize_entity_value()` — idempotent: `f(f(x)) == f(x)`. A non-idempotent normaliser silently
  breaks deduplication and entity resolution at once.
- `content_hash()` — equal intrinsic content implies equal hash, across generated payloads.

Not used elsewhere. Property tests on business logic tend to restate the implementation.

## 4. What is deliberately not tested

- **Live third-party APIs.** Contract tests run against recorded fixtures. A test suite that fails
  because VirusTotal is rate-limited teaches the team to ignore red builds.
- **Live LLM providers.** `replay.py` is the test double. It is registered only in test and experiment
  configurations, never in a production one, so §31's ban on fake functionality is not violated —
  a test double in a test is not a fake feature in a product.
- **Generated report wording.** Structure is asserted; prose is not.
- **Sandbox escape.** Verifying a container boundary properly needs a lab and an offensive test
  harness. Phase 4 asserts container *configuration* (read-only rootfs, `--network=none`, non-root,
  dropped capabilities) and states plainly that configuration assertions are not escape testing.

## 5. Coverage

Line coverage is a reporting metric, not a gate. The gate is a list of properties, each with a named
test:

| Property | Test |
|---|---|
| A `FACT` cannot exist without a `tool_run_id` | `integration/test_grounding.py` |
| A `HYPOTHESIS` cannot exist without a refutation condition | `integration/test_grounding.py` |
| Evidence cannot be updated or deleted | `integration/test_append_only.py` |
| Bulk DML cannot bypass append-only guards | `integration/test_append_only.py` |
| Provenance cannot be ungrounded via CASCADE or SET NULL | `integration/test_provenance_integrity.py` |
| The audit log cannot be updated or deleted | `integration/test_append_only.py` |
| A failed agent leaves no partial evidence | `integration/test_orchestrator.py` |
| Interrupted work recovers on startup | `integration/test_recovery.py` |
| Identical evidence deduplicates | `integration/test_dedupe.py` |
| No endpoint is reachable by an insufficient role | `security/test_authz_matrix.py` |
| No shell is ever invoked; no reserved keys in log extra | `security/test_static_invariants.py` |
| `/capabilities` matches reality | `api/test_capabilities.py` |

Target coverage: ≥85% on `core/`, ≥70% overall — as a signal that the tests were actually written,
not as evidence that they are good.

## 6. Running

```bash
pytest
```

`asyncio_mode = "auto"` is set, so `async def` tests need no decorator. Markers: `unit`,
`integration`, `api`, `security`, `scenario`, `slow`. Everything except `slow` runs on every commit.

CI (Phase 1′, GitHub Actions): `ruff check`, `ruff format --check`, `mypy src`, `pytest`, and
`pip-audit`. All four gate a merge. The 18 ruff and 11 mypy findings currently outstanding must be
cleared before CI is switched on, otherwise the first red build teaches the team to bypass it.

## 7. Definition of done (§38)

A unit of work is done when **all** of the following hold. Not most.

1. The code is written and reviewed by a second team member.
2. Tests exist at the appropriate layer and **have been executed and pass**.
3. `ruff check` and `mypy src` are clean.
4. Nothing is faked: no hard-coded results, no simulated tool or agent execution, no invented threat
   intelligence, no invented ATT&CK ids, no claim that an API was called when it was not (§31).
5. Any new limitation is added to `core/limitations.py`; any removed limitation is deleted from it.
6. `/capabilities` reflects reality.
7. Documentation in `docs/` is updated in the same change, not afterwards.
8. Evidence produced by the change is traceable to a tool run, and any new assertion class is covered
   by a grounding test.
9. The claim "this works" is backed by an execution the author actually observed.

Item 9 is the one that fails most often. It is also the one §1 cares about most: **the phrase "should
work" is not a status report.**
