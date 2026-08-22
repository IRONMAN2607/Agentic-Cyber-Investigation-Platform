# Evaluation Methodology

Covers §21–§23. The research questions are in [research.md](research.md); this document specifies how
each is measured, what the comparison conditions are, and which parts of the design are not yet
settled.

Nothing here has been run. No dataset has been obtained, no baseline exists, and no metric harness has
been written. This is the plan.

## 1. Design

Four **comparison conditions** answer "is this architecture better than the alternatives", and four
**ablations** answer "which part of it is doing the work". Every condition consumes byte-identical
inputs from the same committed scenario fixtures, and every configuration is a file in
`experiments/configs/` so a result can be regenerated from a commit hash plus a config path.

### Comparison conditions

| Condition | Description | Answers |
|---|---|---|
| **A — Rule-based** | Deterministic detection rules only. No model anywhere. | Does the reasoning layer add anything over rules? |
| **B — Single LLM** | One model, same tool access, same token ceiling. No agents, no graph, no grounding invariants. Prompted to cite evidence. | Does the architecture beat one capable model? |
| **C — Multi-agent, no graph** | Full agent decomposition and grounding, correlation and graph disabled. | Does the graph earn its cost? |
| **D — Proposed** | Everything. | — |

Baseline B is the one that matters and the one easiest to rig. Rules that make it fair:

- **Same tools.** B can invoke every tool D can, through the same registry.
- **Same token ceiling.** RQ3 is meaningless if D simply spends more. Total tokens are capped equally
  and reported per condition.
- **Prompted to cite.** B's prompt explicitly instructs it to cite evidence and to distinguish fact
  from inference. B is the *prompted* grounding condition; D is the *enforced* one. That is the whole
  comparison, and giving B a weak prompt would invalidate the paper's central claim.
- **Written first.** B's prompt is frozen before D's results on that dataset are seen, and the version
  is recorded.

Baseline A is not a strawman either: the same detection rules D uses, running alone. It will likely
win on precision and lose badly on multi-step reasoning, and saying so is more useful than a
comparison against something artificially weak.

### Ablations

| # | Removed | Isolates | Expected direction |
|---|---|---|---|
| 1 | Grounding invariants (log violations, allow the write) | Enforcement vs prompting | ↑ unsupported assertions; recall ↑ or flat — **RQ2's crux** |
| 2 | Evidence graph | Correlation value | ↓ chain reconstruction; per-source findings unchanged |
| 3 | Multi-agent decomposition | Decomposition vs a long prompt | uncertain — this is a genuine question |
| 4 | Adaptive planner → `StaticPlanner` | Planning value | ↓ recall on unusual inputs; ↑ reproducibility |

Ablation 1 is the important one and the design is deliberately careful: the invariants are **not**
removed from the code path. They run, detect, and log the violation, then permit the write. Both
conditions therefore share one code path and one detection mechanism, so the difference measured is
enforcement, not two different implementations. A separately built "ungrounded" variant would
confound the result.

Ablation 4 is why `Planner` is a Protocol with two implementations rather than one class with a flag
([agents.md](agents.md) §4) — the seam exists for this measurement.

## 2. Metrics

### Detection accuracy

Precision, recall, and F1 on findings against ground-truth labels, plus:

- **IOC extraction** — precision/recall on IPs, domains, hashes, users, hosts.
- **ATT&CK mapping accuracy** — exact technique match, and parent-technique match scored separately,
  because a sub-technique confusion is a different error from a wrong tactic.
- **False-positive rate on benign input.** A clean-log scenario must produce zero findings. Without
  this, every recall number is gameable by lowering thresholds, and it is the first number a reviewer
  will ask for.

**Matching rule** (specified now, because it is where evaluations quietly go wrong): a predicted
finding matches a ground-truth finding when it names the same primary entity set and the same
behaviour class. Matching is **one-to-one** via maximum bipartite matching per scenario — otherwise
one vague finding matching three labels inflates recall. Near-misses are recorded in a separate
`partial_match` count and reported, never folded into recall. Matching is performed by the harness,
not by a model, and the rule is fixed before results are seen.

### Grounding and hallucination — the primary contribution

| Metric | Definition |
|---|---|
| **Unsupported assertion rate** | Claims lacking valid provenance ÷ total claims |
| **Grounding violation rate** | `GroundingError`s ÷ persisted-claim attempts, per model and prompt version |
| **Assertion class accuracy** | Was a claim labelled FACT genuinely tool-backed; was an INFERENCE genuinely inferential? |
| **Provenance completeness** | Fraction of report statements traceable to evidence in one hop |
| **Fabrication count** | Entities, CVEs, or ATT&CK ids appearing in output but absent from all evidence |

Fabrication count is the strongest single number available, because it needs no judgement: an entity
in a report that appears in no evidence row is fabricated, and both sides of that comparison are
queryable. It is computed by set difference over the database, not by review.

The other four require care. Baselines A–C have no `GroundingError` mechanism, so for them the
harness applies the **same invariant checks offline**, post hoc, over their output. That is what makes
the comparison apples-to-apples: one checker, four conditions.

**Construct limitation, restated because it constrains the paper's wording:** grounding violation rate
counts *attempts the invariants rejected*. It cannot see a fabrication the model never tried to
persist, and it weights an honest over-claim the same as a confident invention. It is a proxy for
hallucination, not a measurement of it.

### Reasoning quality

- **Attack-chain reconstruction** — F1 over the ordered set of chain steps, plus a strict
  exact-order score. This is ablation 2's target metric.
- **Hypothesis quality** — are competing hypotheses generated, and does each carry a refutation
  condition that is actually testable against available evidence? Requires human scoring on a fixed
  rubric with two independent raters and a reported agreement statistic (Cohen's κ). Without κ, "we
  rated them good" is not a result.
- **Temporal accuracy** — is the timeline ordering correct, and are `time_confidence` labels honest?

### Efficiency

Wall-clock per investigation; tokens in/out; cost estimate; tool invocations; tool-selection accuracy
(was the chosen tool appropriate for the artifact); and agent success rate. All are already recorded
by the platform in `agent_runs`, `tool_runs`, and `llm_calls` — **the audit trail is the measurement
instrument**, so no separate instrumentation is written and no measurement code can disagree with what
actually ran.

### Robustness

- **Determinism** — repeat the same scenario N times; report finding-set variance per condition.
  Baseline A should be exactly deterministic; if it is not, there is a bug.
- **Degradation** — behaviour on truncated, corrupted, and lossily decoded input. The `read_text()`
  `lossy` flag should propagate to a marked finding rather than a clean-looking one.
- **Adversarial input** — a log containing text addressed to the model
  ([threat-model.md](threat-model.md) §3.2). Measures whether D's containment holds where B's
  prompting does not. If enforced grounding has a decisive advantage anywhere, it is here, and this
  is the experiment most likely to produce the paper's headline figure.

## 3. Datasets — the binding constraint

**Ground truth is the bottleneck, not tooling.** A dataset without reliable labels cannot produce a
precision number, and labelling by hand is slow and disputable.

Three tiers:

**Tier 1 — synthetic, generated with known ground truth.** A generator emits logs from a scripted
attack narrative, so labels are exact by construction and negative (benign) cases are free.
Necessary, and weak on its own: synthetic data flatters the system by containing exactly the patterns
the rules look for. Used for regression scenarios and for the false-positive baseline.

**Tier 2 — public datasets.** Candidates below. **Every one requires verification of current
availability, licence, and whether usable labels exist** before the experimental design is frozen —
they are listed as leads, not as a confirmed corpus:

| Candidate | For | Must verify |
|---|---|---|
| LANL authentication / unified host-and-network events | auth-log analysis at scale | label granularity; whether red-team labels suit finding-level scoring |
| CIC-IDS2017 / UNSW-NB15 | network detection | flow-level labels are coarser than finding-level; mapping needed |
| CTU-13 | botnet traffic | label format and PCAP availability |
| Security Datasets / EVTX attack samples | Windows telemetry, ATT&CK-tagged | tagging quality; whether tags are technique-level |
| Atomic Red Team executions in the team's own lab | controlled, ATT&CK-labelled by construction | lab availability; §19 authorization |
| LogHub | log parsing robustness | mostly non-security; useful for degradation tests only |

The last row of the table is the most promising for ATT&CK-mapping accuracy: running Atomic Red Team
tests in an authorized lab produces telemetry whose technique labels are known *because the team chose
which technique to execute*. It also keeps §19 satisfied — all offensive activity inside the lab.

**Tier 3 — hand-labelled realistic cases.** A small number (5–10) of realistic multi-source scenarios
labelled by two team members independently, with disagreements resolved by discussion and the
pre-resolution agreement rate reported. Expensive, and the only tier that resembles real
investigation.

Rule: **no dataset is used for tuning and evaluation both.** A held-out split is fixed before any rule
threshold or prompt is tuned. Tuning on the evaluation set is the single most common way capstone
evaluations become meaningless, and it is invisible in the results.

`datasets/` tracks manifests, checksums, licences, and generator scripts. Raw data is gitignored (§34).

## 4. Statistical treatment

- **N ≥ 5 runs** per condition per scenario for any condition involving a model. Single-shot numbers
  from a stochastic system are not results.
- **Paired tests**, since conditions run on identical inputs. Wilcoxon signed-rank rather than a
  *t*-test, given small N and no normality assumption.
- **Bootstrap confidence intervals** on aggregate metrics.
- **Per-scenario results reported alongside aggregates**, always. With 10–20 scenarios, an aggregate
  hides which scenario carried the effect.
- **Multiple-comparison correction** (Holm) across the ablation family.
- **Effect sizes**, not just *p*-values. With small N, a significant *p* on a trivial effect is a
  reporting artefact.
- **Temperature 0.0 and a fixed seed where the provider supports it.** Neither guarantees
  determinism across provider-side updates, so `provider`, `model`, and `model_snapshot` are recorded
  per run ([model-abstraction.md](model-abstraction.md) §8).

## 5. Harness

```text
experiments/
├── configs/       one file per condition × dataset
├── runners/       execution + metric computation
├── datasets/      manifests, checksums, licences, generators
└── results/       raw output, gitignored; summaries committed
```

A run records the git commit, the config, resolved model identifiers, dataset checksums, and the full
`agent_runs` / `tool_runs` / `llm_calls` rows. Metrics are computed from that persisted state, never
from in-memory values — so a metric can be recomputed later with a corrected formula without
re-running anything, which will happen at least once.

The harness is tested ([testing.md](testing.md) §2 `evaluation/`). Precision, recall, F1, and the
bipartite matcher are verified against hand-computed values on a fixture small enough to check by
hand. A silent bug here produces plausible numbers that nobody catches — the worst failure mode
available to this project.

`replay.py` provides deterministic model responses for harness tests and for exact reproduction of a
recorded run. It is a test double and is never registered in a production configuration (§31).

## 6. Open decisions

1. **Two providers or one.** The single-vs-multi-model comparison in §8/§22 requires two working
   providers. If only one is available, that ablation is dropped and the paper says so.
   [model-abstraction.md](model-abstraction.md) §10 — highest-impact open question in the project.
2. **RQ5 analyst study** — retain scoped or drop with a structural argument. Decide by week 4
   ([research.md](research.md) §8).
3. **Dataset set** — cannot be frozen until availability and labels are verified.
4. **Human-scored metrics** — hypothesis quality needs a rubric and two raters. If rater time is
   unavailable, the metric is dropped rather than scored by one person and reported as if it were
   reliable.

## 7. Reporting commitments

Fixed now, so they are not negotiated once the numbers exist:

- Every table states N and variance.
- Negative and null results are reported with the same prominence as positive ones.
- Ablation 1 is reported even if enforcement costs recall — especially then, since that is RQ2.
- Cost and latency are reported; an architecture that wins on accuracy at 20× the cost has stated that
  trade-off.
- Any metric changed after seeing results is disclosed as such.
- No number appears in the paper that the harness cannot regenerate from a commit and a config.
