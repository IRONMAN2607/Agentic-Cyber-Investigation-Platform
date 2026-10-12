# ACIP Empirical Evaluation Results

Comparative evaluation across experimental conditions and ablations.

| Condition / Baseline | Precision | Recall | F1 Score | Benign FPR | Provenance Completeness | Fabrications |
|---|---|---|---|---|---|---|
| Baseline A (Rules Only) | 0.406 | 0.875 | **0.489** | 0.000 | 1.000 | 0 |
| Baseline B (Single LLM) | 0.250 | 0.250 | **0.250** | 0.000 | 1.000 | 0 |
| Baseline C (No Graph) | 0.406 | 0.875 | **0.489** | 0.000 | 1.000 | 0 |
| **Condition D (Proposed)** | 0.383 | 0.875 | **0.462** | 0.000 | 1.000 | 0 |

### Metric Definitions
- **Precision / Recall / F1**: Computed via strict one-to-one maximum bipartite matching between predicted and ground-truth findings.
- **Benign FPR**: False-positive rate on verified clean operational baselines.
- **Provenance Completeness**: Proportion of claims with valid non-null deterministic tool run and evidence records.
- **Fabrications**: Output entities absent from all immutable evidence rows.