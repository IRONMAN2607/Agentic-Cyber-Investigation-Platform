# Research Question and Contribution

This document covers §20. It states what is being claimed, what would disprove it, and what is
*not* being claimed. [experiments.md](experiments.md) specifies how the claims are measured.

**No literature review has been performed yet, and no citations have been gathered.** The positioning
in §4 below is therefore stated as a hypothesis about the gap, not as an established finding. Filling
that in is the first research task of the semester (§7 below). Nothing in this document should be
cited as if the survey had been done.

## 1. The problem

Applying language models to security investigation runs into a specific failure that generic
"LLM hallucination" framing understates. In an investigation, a fabricated detail is not merely
wrong — it is **indistinguishable from a finding**. A model that reports "the attacker escalated via
`CVE-2021-4034`" when no such evidence exists produces output with the same syntax, the same
confidence, and the same authority as a correct conclusion. The analyst has no local signal to
separate them, and the cost of being wrong is an incident response aimed at the wrong thing.

The usual mitigations are behavioural: better prompts, self-critique, chain-of-thought, RAG,
"say I don't know". All of them ask the model to be more honest. They reduce error rates without
changing what is *possible* to assert, so residual fabrication remains unbounded and undetectable
from the output alone.

## 2. Research question

> **Does architecturally enforcing evidence grounding — rather than prompting for it — measurably
> reduce unsupported assertions in multi-agent LLM security investigation, and at what cost to
> recall and to the analyst?**

"Architecturally enforcing" has a precise meaning here, and it is the substance of the contribution:
a claim about the world can only be persisted if its provenance satisfies a machine-checked
invariant. In this system a `FACT` requires a `tool_run_id`, which only the deterministic tool runner
sets. A model cannot produce one. It is not that the model is asked to cite evidence; it is that
**an uncited factual claim cannot be written to the database at all** — the write raises
`GroundingError`. See [evidence-model.md](evidence-model.md) for G0–G4.

### Sub-questions

- **RQ1 (grounding).** What fraction of model-generated claims are rejected by the invariants, and how
  does that fraction vary by model, by task class, and by prompt version?
- **RQ2 (cost of enforcement).** Does enforcement reduce recall? A model prevented from asserting an
  unsupported `FACT` might report nothing rather than reporting an `INFERENCE`. This is the honest
  risk of the whole approach and must be measured, not assumed away.
- **RQ3 (decomposition).** Does multi-agent decomposition outperform a single model with the same
  tools and the same context budget — or is the gain merely more tokens spent?
- **RQ4 (graph).** Does an evidence graph improve multi-step attack-chain reconstruction over
  independent per-source analysis?
- **RQ5 (explainability).** Does complete provenance change analyst *verification time* and
  *error-detection rate*, not just perceived trust?

RQ2 and RQ3 are the ones that could embarrass the project, which is why they are in the plan rather
than discovered by a reviewer.

## 3. Claimed contributions

1. **A grounding invariant system for LLM-produced security claims**, with a typed assertion
   taxonomy (FACT / INFERENCE / HYPOTHESIS / UNKNOWN) enforced at the persistence boundary, where the
   write fails rather than the value being silently downgraded.
2. **A mechanically measurable hallucination metric.** `grounding_violations` per `llm_calls` row ties
   a specific model and prompt version to the rate at which its reasoning over-claimed — computed
   from the system's own audit trail, with no human annotation in the loop. Most reported
   hallucination rates in this domain depend on manual review, which does not scale and is not
   reproducible.
3. **An architecture in which adding a language model cannot weaken evidence guarantees**, because the
   model layer sits structurally downstream of the invariants and beside the agents, never between
   the tools and the store ([model-abstraction.md](model-abstraction.md) §2).
4. **An evidence graph in which every edge carries a non-null foreign key to the evidence row that
   produced it**, making "why do you believe these two things are connected?" answerable by
   construction rather than by explanation.
5. **An empirical comparison** of rule-based, single-model, multi-agent-without-graph, and full
   configurations on identical inputs, with ablations isolating grounding enforcement, the graph,
   multi-agent decomposition, and static-versus-adaptive planning.

Contribution 2 is the strongest candidate for the paper's central claim: it converts a qualitative
concern into a number that falls out of normal operation.

## 4. Positioning — stated as hypothesis, not finding

The literature is expected to cluster into four areas. Each entry names what must be checked, since
none of it has been checked yet:

| Area | What to verify |
|---|---|
| LLM agents for security operations | Whether existing systems enforce provenance or prompt for it; what they report as accuracy and on what data |
| Hallucination detection and mitigation | Whether any work makes unsupported assertion *structurally impossible* rather than less likely; how grounding is measured |
| Provenance in digital forensics | Chain-of-custody models predate LLMs and are mature. Whether any work applies them to model-generated claims |
| Multi-agent LLM frameworks | Whether reported gains from decomposition control for total token budget |

**Hypothesised gap:** forensic provenance is well developed for *artifacts* and largely absent for
*machine reasoning*; LLM security agents optimise capability and report accuracy but rarely enforce
that a claim be backed by a recorded tool execution. If that holds, the contribution is joining the
two. **If a system already does this, the contribution narrows to the measurement methodology and the
ablation study** — which is still publishable, and is a much better position than discovering the
overlap at review time. The survey must therefore be run before the experimental design is frozen,
not after.

## 5. Falsifiability

The claims fail if any of the following is observed. Each is a real possible outcome of the planned
experiments:

- **Grounding enforcement does not reduce unsupported assertions** relative to a prompted-to-cite
  baseline — the invariants would then be ceremony.
- **Enforcement costs more recall than it saves precision.** If the full system misses substantially
  more true findings than Baseline B, the architecture is a poor trade and the paper must say so.
- **Multi-agent shows no advantage** over a single model at equal token budget — decomposition would
  be complexity without benefit (§16's warning, realised).
- **The graph does not improve chain reconstruction** — it would be an expensive visualisation.
- **Provenance does not change analyst behaviour.** If verification time and error detection are
  unchanged, the explainability claim is unsupported regardless of how principled the mechanism is.

Negative results are reportable and will be reported. A paper that finds enforced grounding costs 15%
recall for a 60% reduction in unsupported assertions is a more useful contribution than one that
reports only wins — and pre-committing to that here is what makes the number credible later.

## 6. Explicit non-claims

To keep the framing defensible:

- Not claiming the system replaces an analyst, or performs autonomous incident response.
- Not claiming immunity to prompt injection. Containment is claimed and bounded in
  [threat-model.md](threat-model.md) §3.2; prevention is not.
- Not claiming detection-capability novelty. The detection rules are conventional on purpose — the
  contribution is the reasoning and provenance layer, not new detections.
- Not claiming production readiness. The gaps in [security.md](security.md) are stated, not hidden.
- Not claiming generality beyond the evaluated data. Results hold for the datasets in
  [experiments.md](experiments.md) and no further.
- Not claiming the assertion taxonomy is novel in itself. FACT/INFERENCE/HYPOTHESIS distinctions are
  old; enforcing them at a database write boundary for model output is the part being claimed.

## 7. Research tasks, in dependency order

1. **Literature survey** (weeks 1–4). Venues: USENIX Security, ACM CCS, IEEE S&P, NDSS, DFRWS,
   ACL/EMNLP for the grounding side, arXiv for currency. Deliverable: a positioning table and a
   confirmed or corrected gap statement. **Blocks freezing the experimental design.**
2. **Dataset selection and labelling** (weeks 3–8). Ground truth is the hard constraint — see
   [experiments.md](experiments.md) §3.
3. **Baseline implementation** (weeks 8–14). Baselines are code the team writes and must be
   *charitable*; a strawman baseline invalidates everything downstream.
4. **Metric harness and its tests** (weeks 10–14). Tested code, per [testing.md](testing.md) §2.
5. **Experiments and ablations** (semester 2, weeks 1–8). N runs with variance, not single shots.
6. **Analyst study**, if RQ5 is retained — see the scoping decision below.
7. **Writing** (semester 2, weeks 6–12), overlapping analysis.

## 8. The RQ5 scoping decision

RQ5 needs human participants, which means recruitment, a protocol, and — at most institutions —
ethics review. With four members and two semesters, attempting it badly is worse than declining it.

Two options, and the choice must be made by the end of week 4 rather than drifting:

- **Retain**, scoped to a small within-subjects study (6–10 participants, security-course students or
  lab members) measuring verification time and injected-error detection rate on identical reports
  with and without provenance links. Requires an ethics application filed early.
- **Drop**, and replace with a structural argument plus a *quantitative provenance-completeness*
  metric: the fraction of report statements traceable to evidence in one click. Measurable without
  participants, and honestly weaker as an explainability claim.

Recommendation: **decide by the literature survey's completion.** If the survey shows explainability
claims in this area are routinely made without user studies, the second option is defensible and the
saved effort goes into RQ1–RQ4, which are the stronger contributions. Tracked in
[risks-and-assumptions.md](risks-and-assumptions.md).

## 9. Threats to validity

**Internal.** The team implements both the system and its baselines — an unavoidable conflict.
Mitigations: baselines get the same tools, same context budget, and same token ceiling; baseline
prompts are written before the system's results are seen; every configuration runs from the same
committed harness on the same inputs.

**Construct.** "Hallucination rate" as measured is *the rate at which the invariants rejected a
claim*. That is a proxy. It cannot count fabrications the model never attempted to persist, and it
counts a rejected-but-honest over-claim the same as a confident fabrication. The paper must define
the metric precisely and not let it be read as a general hallucination rate.

**External.** Datasets are public or synthetic; performance on a real enterprise incident is
unmeasured. Model behaviour drifts under provider-side updates, so every result records
`provider`, `model`, and a `model_snapshot` label.

**Statistical.** With few scenarios, per-scenario variance will be large. Report per-scenario results
alongside aggregates, use paired tests on identical inputs, and state N and variance everywhere.
Aggregate-only reporting over a handful of scenarios would be the easiest way to overclaim.

## 10. Output

Target: an IEEE-format conference or workshop paper. Realistic scope for a capstone is a workshop or
a student track; framing it that way from the start keeps the claims proportionate to the evidence.

The artifact is the second output and is the one the numbers depend on: the repository, the datasets
or their manifests, the experiment configurations, and the raw `agent_runs` / `tool_runs` /
`llm_calls` tables. Reproducibility is not a courtesy here — the central metric is derived from those
tables, so a reader who cannot inspect them cannot check the main claim.
