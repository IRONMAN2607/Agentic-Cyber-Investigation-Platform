# Frontend Architecture

Phase 8. **Nothing is implemented** — the `web/` directory does not exist. This is the design.

The UI has one job that matters more than any feature: **make provenance the primary interaction.**
A platform whose contribution is that every claim traces to evidence, presented through an interface
where that trace is three clicks deep and easy to skip, has not delivered the contribution. Everything
below follows from that.

## 1. Stack

| Concern | Choice | Rationale |
|---|---|---|
| Framework | React 18 + TypeScript (strict) | Team familiarity; the ecosystem for graph and data views |
| Build | Vite | Fast dev server; CORS already expects `localhost:5173` |
| API client | **generated from `/openapi.json`** | No hand-written request types |
| Server state | TanStack Query | Caching, polling, and request state are the whole problem here |
| Client state | React state + context | There is very little; a store would be ceremony (§16) |
| Routing | React Router | Deep-linkable investigation URLs |
| Styling | Tailwind + Radix primitives | Radix for accessible dialogs/menus rather than reimplementing focus traps |
| Graph | Cytoscape.js | Mature layouts, handles 10³–10⁴ nodes, stable node identity for click-through |
| Timeline | virtualised list, ordered by `observed_at` | A dense forensic timeline is read as a table, not a gantt |
| Tests | Vitest + React Testing Library + MSW; Playwright for e2e | |

**Generated client, not hand-written types.** FastAPI already emits the schema, and the failure mode
being avoided is specific: a hand-maintained TypeScript type that has silently drifted from the API
will render a stale field as `undefined` and show an investigator a blank where a finding should be.
Regenerating on schema change turns that into a compile error.

**Cytoscape.js over a force-directed d3 wrapper**: node identity must be stable across renders so an
edge click reliably resolves to one `evidence_id`. Revisit if the graph exceeds ~10⁴ nodes, at which
point rendering moves to canvas/WebGL and the interaction model changes anyway.

**No global store.** Almost all state is server state, which TanStack Query owns. The rest is the
auth token and UI preferences. Adding Redux here would be infrastructure for its own sake.

## 2. Non-negotiable design rules

These are architecture, not styling, and each maps to a rule in the specification.

**1. Assertion class is always visible and never decorative.** FACT, INFERENCE, HYPOTHESIS, and
UNKNOWN are rendered with distinct labels, distinct iconography, **and distinct text** — never colour
alone, both for accessibility and because colour is the first thing lost in a screenshot pasted into
an incident ticket. An inference styled like a fact would undo the entire evidence model in the last
layer of the stack.

**2. Every claim is clickable to its evidence.** A finding opens its supporting evidence rows; an
evidence row shows its `tool_run`, its artifact, and its `sha256`; a graph edge opens the observation
that produced it. One hop, always available. The UI test suite asserts this for every claim type.

**3. No fake activity (§15).** Progress animation is driven by persisted `agent_runs` and `tool_runs`
rows. A stalled agent looks stalled. No spinner that implies work when no run is `running`, no
synthetic "analysing…" step, no progress bar interpolating toward a guess. This is stated as a UI rule
because a plausible fake is far easier to build in a frontend than anywhere else in the system.

**4. Capability honesty.** The shell fetches `/capabilities` on load and hides — not disables with a
tooltip, hides — features the deployment does not have. The declared limitations from
`core/limitations.py` render in an **About / Limitations** panel that is always reachable, so
"no language model is involved in this build" is visible to a user, not just to a code reader.

**5. The client computes nothing authoritative.** Severity, confidence, and risk score are displayed
as returned. No client-side re-derivation, no rounding that changes a number, no re-sorting that
implies a ranking the server did not produce. Two sources of truth for a risk score is a defect
waiting to be argued about in a demo.

**6. Evidence is rendered as text.** Evidence content is attacker-authored
([threat-model.md](threat-model.md) §3.2). No `dangerouslySetInnerHTML`, no markdown rendering of
evidence fields, no interpolation into anchors or `src` attributes. Long values are truncated with an
explicit expand, and monospace formatting makes homoglyph and whitespace tricks visible rather than
smoothing them away. Report *narrative* is server-generated and may be rendered as markdown; evidence
*content* never is.

**7. Uncertainty is shown, not smoothed.** `time_confidence` of `APPROXIMATE` renders differently from
`EXACT`; a lossily decoded artifact is marked; an investigation with status `partial` says which tasks
failed on the same screen as the findings. A UI that presents partial results as complete is the same
failure as an agent claiming a FACT without evidence.

## 3. Views

| View | Content |
|---|---|
| Investigations | List with status, severity, risk, created-at; filter and search |
| New investigation | Target type/value, artifact upload with client-side size pre-check |
| Investigation detail | Status, plan with each task's `rationale`, agent runs, tool runs, failures |
| Evidence browser | Paged, filterable by kind and entity; each row expandable to full provenance |
| Finding detail | Assertion class, confidence, reasoning, supporting **and contradicting** evidence |
| Graph | Cytoscape view, depth control, entity-type filter, every edge click-through to evidence |
| Timeline | Ordered events with `time_confidence`, correlated across sources |
| ATT&CK matrix | Techniques with `catalog_version`, each linked to the finding that mapped it |
| Report | Rendered report, export, and the limitations block |
| Chat | Investigator Q&A over structured investigation data only (first to be cut, per roadmap §6) |
| About / Limitations | `/capabilities` output verbatim |

The **plan with rationale** view is unusual and worth keeping: showing *why each step was taken* makes
the orchestrator's decisions auditable by the analyst rather than only by a developer reading
`agent_runs`.

The **failures on the same screen as the findings** rule matters for the same reason. "Three agents
succeeded, one crashed" changes how a reader should weigh the findings, and putting it on a separate
tab means nobody sees it.

## 4. Progress and streaming

M1 semantics: poll `GET /investigations/{id}`, via TanStack Query with an interval while the status is
non-terminal, stopping on a terminal status. Simple, and correct.

Phase 8 replaces the poll with **SSE** on `/investigations/{id}/events`. One-directional, reconnects
natively, no proxy upgrade path needed ([api.md](api.md) §5). Chat stays request/response, so there is
no bidirectional requirement to justify WebSockets. The event stream carries only real state
transitions read from persisted rows — rule 3 above.

Polling remains the fallback when SSE fails, rather than the UI silently going quiet.

## 5. Authentication in the browser

Bearer token from `POST /auth/login`. Where to keep it is a real trade-off with no clean answer, and
the decision is stated rather than defaulted:

- **`localStorage`** — survives reload; readable by any XSS. Rejected.
- **In-memory only** — not XSS-persistable, but a page refresh logs the user out. Chosen for Phase 8,
  because a lab tool can afford re-login and because there is no refresh-token flow to make silent
  renewal work anyway.
- **httpOnly cookie + CSRF tokens** — the right answer for a real deployment, and it changes the API's
  auth model. Revisit together with refresh tokens and revocation ([security.md](security.md) §2).

With a 60-minute access token and no revocation list, in-memory storage is also the only option that
meaningfully limits a stolen token's blast radius.

## 6. Accessibility and presentation

Dark-first, because the tool is used in operations centres and alongside terminals — but a light theme
is required, not optional: reports get printed and screenshotted into tickets. Radix primitives supply
keyboard navigation and focus management. Every state distinction that uses colour also uses text or
shape (rule 1). Target WCAG AA contrast. Full keyboard navigation for the evidence browser
specifically, since that is where an analyst spends their time.

## 7. Testing

- **Unit** (Vitest + RTL): assertion-class rendering, provenance link presence, capability gating.
- **API mocking** (MSW) against schemas generated from the real OpenAPI document, so a mock cannot
  drift from the server.
- **e2e** (Playwright): the full slice — create, upload, start, watch real progress, read the report,
  click a finding through to its evidence.
- **Two rules-as-tests**, mirroring the backend's static assertions: no `dangerouslySetInnerHTML`
  anywhere in the tree, and no progress indicator rendered when no run is `running`. Both are
  greppable invariants, and both are the kind of thing that gets reintroduced during a demo crunch.
