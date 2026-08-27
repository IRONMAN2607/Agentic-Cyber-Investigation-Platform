# Evidence Graph Design

§10 requires an evidence graph and explicitly requires evaluating **Neo4j versus a PostgreSQL-based
representation** before implementation. This document records that evaluation and the design that
follows from it. Implementation lands in Phase 5.

## 1. Decision — relational graph in PostgreSQL; do not adopt Neo4j

**Chosen:** represent the graph as `entities` + `entity_edges` tables in PostgreSQL, traversed with
recursive CTEs. See [database.md](database.md) for the schema.

### Why

**Scale does not justify it.** A single investigation yields on the order of 10²–10⁴ entities. Neo4j's
advantage appears on deep traversals across large, densely connected graphs. At this size a
well-indexed relational table with a recursive CTE is not the bottleneck, and the project has no
cross-investigation global graph requirement.

**The queries the platform actually needs are shallow.** The chain §5.8 specifies —
`USER → AUTHENTICATED_TO → HOST → EXECUTED → PROCESS → DOWNLOADED → FILE → CONTACTED → DOMAIN →
RESOLVES_TO → IP` — is a path enumeration of bounded depth. The real query set is: *what connects
these two entities*, *what is within N hops of this entity*, *what evidence supports this finding*,
and *what is the ordered timeline*. All are expressible in SQL, and the last two are not graph
queries at all.

**Transactional integrity is the whole point of the system.** Evidence rows and their edges must be
written atomically with provenance. Two datastores means dual-write, which means a reconciliation
story and a window where the graph disagrees with the evidence. For a platform whose central claim is
provenance integrity, that is the wrong risk to take on.

**`entity_edges.evidence_id` is a foreign key.** Every edge is backed by an evidence row, enforced by
the database. Expressing that constraint across a Postgres/Neo4j boundary is not possible — it
becomes application-level hope.

**Operational and academic cost.** A second datastore adds a deployment dependency, a backup story,
and a second query language for a four-person team, in exchange for performance headroom this
workload does not need. §16 is explicit: do not add infrastructure to make the project appear complex.

**It is reversible.** Edges are *derived* from evidence, so the graph can be rebuilt from scratch at
any time. Migrating later is a projection, not a schema rewrite — which is precisely why deferring is
cheap and adopting early is not.

### What was rejected, and honestly

Neo4j would give a more natural query language for path finding (Cypher's variable-length patterns are
genuinely nicer than recursive CTEs), a mature graph visualisation story, and better asymptotics if the
graph ever became large and traversals deep. Recursive CTEs are harder to read and easier to get
subtly wrong. That is a real cost, mitigated by keeping traversal in one reviewed, tested module
(`core/graph/traversal.py`) rather than spreading CTEs through the codebase.

### Revisit when any of these becomes true

- Traversals routinely need >4 hops, or variable-length path queries dominate.
- A cross-investigation graph is required (correlating campaigns across cases).
- Recursive CTE p95 exceeds ~500 ms on realistic data.
- Graph algorithms beyond traversal are needed (community detection, centrality).

**Migration path if so:** keep PostgreSQL authoritative and add Neo4j as a **read-side projection**
rebuilt from evidence. This preserves atomic writes and the evidence-backed-edge constraint while
gaining Cypher for analysis. Never dual-write.

## 2. Node types

From `EntityType` in `types.py` — already recorded on evidence in M1, so Phase 5 builds the graph from
data already collected without re-running investigations:

`USER` · `HOST` · `IP` · `DOMAIN` · `URL` · `FILE` · `HASH` · `PROCESS` · `PORT` · `EMAIL`

Added in Phase 4+ as their sources arrive: `TECHNIQUE`, `MALWARE`, `THREAT_ACTOR`, `ALERT`,
`REGISTRY_KEY`.

`EVENT` from §10 is deliberately **not** a node type. Events are evidence rows; promoting them to
nodes would duplicate the evidence table and create two places where an observation lives. Evidence
attaches to edges instead, via `entity_edges.evidence_id`.

## 3. Relationships

| Relation | From → To | Source |
|---|---|---|
| `AUTHENTICATED_TO` | USER → HOST | auth logs |
| `FAILED_AUTH_TO` | USER → HOST | auth logs |
| `CONNECTED_FROM` | IP → HOST | auth/network |
| `EXECUTED` | HOST/USER → PROCESS | endpoint telemetry |
| `SPAWNED` | PROCESS → PROCESS | endpoint telemetry |
| `CREATED` / `ACCESSED` | PROCESS → FILE | endpoint telemetry |
| `DOWNLOADED` | PROCESS → FILE | endpoint/network |
| `HAS_HASH` | FILE → HASH | hashing |
| `CONTACTED` | PROCESS/HOST → DOMAIN/IP | network |
| `RESOLVES_TO` | DOMAIN → IP | DNS |
| `LISTENS_ON` / `CONNECTED_TO_PORT` | HOST → PORT | network |
| `ASSOCIATED_WITH` | any → any | intel; inferred/weak relation, always carries source, basis, and confidence |
| `MAPPED_TO` | FINDING → TECHNIQUE | ATT&CK agent |

`entity_edges` stores **edge instances**: each row is one relationship asserted by one evidence row.
The `evidence_id` uniqueness component therefore preserves multiple independent observations of the
same logical relationship; consumers may group them only by an explicit, reproducible query. Direct
observations and inferred relations (including `ASSOCIATED_WITH`) are separately filterable and the
UI defaults to direct observations. Confidence is derived from declared source/basis rules and is
never overwritten by an LLM.

## 4. Entity resolution

Resolution is deliberately conservative — a false merge fabricates a connection that was never
observed, which is worse than a missed one.

**Tier 1 — canonical form (automatic).** `normalize_entity_value()` already applies at draft time:
IPs through `ipaddress`, domains lowercased and de-dotted, hashes lowercased, usernames and hostnames
lowercased. Two entities with the same `(type, value_normalized)` in an investigation are the same
entity. This is the only merge performed automatically.

**Tier 2 — proposed links (never silent merges).** `web01` and `web01.corp.example` are probably the
same host; `HAS_HASH` relates a file to its digest. These become explicit `ASSOCIATED_WITH` edges
with stated basis and confidence, leaving both nodes intact.

**Not attempted:** cross-investigation identity, and any LLM-driven merge. A model may *propose* an
association, recorded as an `INFERENCE` finding with an edge — it never rewrites entity identity.

Scope is per-investigation: `UNIQUE(investigation_id, type, value_normalized)`. Cross-investigation
correlation is out of scope for the capstone and is listed in [research.md](research.md) as future
work.

## 5. Traversal

Confined to `core/graph/traversal.py`. Every traversal is depth-bounded and result-capped — an
unbounded recursive CTE on a dense graph is a denial-of-service against the platform itself.

```sql
WITH RECURSIVE reachable(entity_id, depth, path) AS (
    SELECT :start_id, 0, ARRAY[:start_id]
  UNION ALL
    SELECT e.dst_entity_id, r.depth + 1, r.path || e.dst_entity_id
    FROM entity_edges e
    JOIN reachable r ON e.src_entity_id = r.entity_id
    WHERE r.depth < :max_depth
      AND e.investigation_id = :inv
      AND NOT e.dst_entity_id = ANY(r.path)     -- cycle guard
)
SELECT * FROM reachable LIMIT :cap;
```

Planned operations: `neighbours(entity, depth)`, `paths_between(a, b, max_depth)`,
`subgraph_for_finding(finding_id)`, `timeline(investigation)`.

The cycle guard is not optional: `RESOLVES_TO` and `ASSOCIATED_WITH` produce cycles routinely
(a domain resolving to an IP that hosts the domain).

## 6. API and UI

```text
GET /investigations/{id}/graph?entity=&depth=2      nodes + edges, evidence-cited
GET /investigations/{id}/entities?type=&q=          entity list
GET /investigations/{id}/timeline                   ordered events with time_confidence
GET /findings/{id}/subgraph                         what supports and contradicts this finding
```

Every edge in a graph response carries its `evidence_id`, so the UI can make any relationship
clickable through to the observation that produced it. Graph responses enforce a bounded depth, result
cap, execution timeout, cancellation, and the same investigation authorization check as other
investigation data. A graph edge the user cannot trace to evidence would undermine the platform's
central claim.

## 7. Research relevance

The graph is one of the four independent variables in the ablation study (§22): the "without evidence
graph" condition disables correlation and graph-derived findings while leaving detection, hypotheses,
and validation intact. Because edges are derived from evidence rather than collected separately, that
condition is a genuine ablation on identical inputs rather than a different data collection — which is
what makes the comparison valid. See [experiments.md](experiments.md).
