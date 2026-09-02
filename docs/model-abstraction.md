# Model Abstraction and Routing

Implemented in `src/acip/core/llm/` with tests in `tests/unit/test_llm_*.py`.
Provides provider-agnostic model routing, candidate fallback chains, NVIDIA NIM
integration (supporting Nemotron and DeepSeek R1), error handling, and structured outputs.

## 1. Why this layer exists

Three requirements drive it:

1. **No provider lock-in** (§7). Agents must never import a provider SDK or reference a model name.
2. **Continuity under quota exhaustion** (§8). If the primary provider's quota is exhausted, the
   platform must continue on a secondary **without code changes**.
3. **Experimental comparability** (§8, §23). The research must compare models on accuracy, grounding,
   hallucination, latency, tokens, cost, and tool-selection accuracy. That requires every call to be
   recorded in a uniform shape.

## 2. Placement — downstream of the grounding invariants

This is the most important structural point, and it is what keeps the platform from becoming an LLM
wrapper:

```text
ModelRouter ──▶ reasoning output ──▶ agent ──▶ EvidenceStore.add_finding()
                                                      │
                                                 G1 rejects any FACT
                                                 not backed by a tool
```

The model layer sits **beside** agents, never between tools and the store. It can produce an
`INFERENCE` or a `HYPOTHESIS`. It can never produce evidence, and it can never produce a `FACT`,
because only the tool runner sets `tool_run_id` and G1 tests for it. Adding LLMs therefore cannot
weaken the evidence guarantees — see [evidence-model.md](evidence-model.md).

## 3. Module layout

```text
core/llm/
├── contracts.py    Message, LLMRequest, LLMResponse, Usage, FinishReason, ToolSpec
├── provider.py     LLMProvider protocol + error taxonomy
├── providers/
│   ├── openai.py       OpenAI-compatible
│   ├── nvidia.py       NVIDIA NIM (OpenAI-compatible surface)
│   └── replay.py       deterministic test double (test/experiment only)
├── router.py       ModelRouter — the only entry point agents use
├── policy.py       routing table + fallback chains, loaded from config
├── budget.py       token/cost accounting, quota state, circuit breaking
├── prompts/        versioned prompt templates
└── trace.py        persists every call to llm_calls
```

## 4. Provider contract

```python
class LLMProvider(Protocol):
    name: str

    async def complete(self, request: LLMRequest) -> LLMResponse: ...
    async def probe(self) -> ProviderAvailability: ...
```

`probe()` mirrors the tool layer: report availability honestly at startup rather than discovering a
missing API key mid-investigation.

### Error taxonomy

The distinction that makes automatic fallback safe:

| Error | Fallback? | Why |
|---|---|---|
| `ProviderQuotaExceeded` | **yes** | Another provider can do this work |
| `ProviderRateLimited` | retry, then yes | Transient |
| `ProviderUnavailable` (5xx, network) | **yes** | Transient or provider-side |
| `ProviderTimeout` | retry once, then yes | Transient |
| `ProviderRefused` | **no** | A second model will likely refuse too; record it |
| `SchemaValidationFailed` | **no** | Retry same model with repair prompt, then fail the task |
| `ProviderAuthError` | **no** | Misconfiguration; fail loudly |

Falling back on `ProviderRefused` or `SchemaValidationFailed` would silently shop for a compliant
model and destroy the hallucination/grounding measurements. Both are recorded as outcomes instead.

## 5. Task classes and routing

Agents request a **task class**, never a model:

```python
class TaskClass(StrEnum):
    PLANNING  # which agents to run, and why
    EXTRACTION  # structured pull from text
    CLASSIFICATION  # bounded label assignment
    CORRELATION  # entity/event linking proposals
    HYPOTHESIS  # competing explanations
    VALIDATION  # adversarial review of a conclusion
    NARRATIVE  # report prose from stored records
    CHAT  # investigator Q&A
```

The routing table lives in configuration, not code:

```toml
[routing.HYPOTHESIS]
candidates = [
  { provider = "openai", model = "${ACIP_MODEL_REASONING}", temperature = 0.0 },
  { provider = "nvidia", model = "${ACIP_MODEL_LONGCTX}",   temperature = 0.0 },
]
max_output_tokens = 2048
schema_retries = 2

[routing.EXTRACTION]
candidates = [
  { provider = "nvidia", model = "${ACIP_MODEL_SMALL}", temperature = 0.0 },
]
```

`ModelRouter.complete(task_class, request, *, schema=None)` walks the candidate list in order,
applying the fallback rules above. Changing which model serves a task class is a config edit —
satisfying §8's requirement that quota exhaustion needs no code change.

## 6. Structured output

Reasoning that feeds the database must be structured. The router accepts a Pydantic model and
guarantees the return value validates against it:

1. Dynamic schema template generation: converts Pydantic models into concrete, descriptive JSON
   templates with explicit enum choices, avoiding raw `$defs` clutter.
2. Request provider-native constrained/JSON output (`response_format={"type": "json_object"}`).
3. Validate against the Pydantic schema using `model_validate_json()`.
4. On failure, retry the **same** model up to `schema_retries` with the validation error appended.
5. On final failure, raise `SchemaValidationFailed`. The agent's task fails and is recorded.

There is no "best-effort parse" path and no regex salvage of malformed output. A model that cannot
produce the required shape is a measurable result, not something to paper over.

Default configuration pairs `meta/llama-3.2-11b-vision-instruct` (primary) and `openai/gpt-oss-20b`
(secondary) across task classes for low-latency, strictly grounded JSON generation.

## 7. Observability

Every call writes an `llm_calls` row (§28). This table is the primary research dataset:

| Column | Purpose |
|---|---|
| `investigation_id`, `agent_run_id` | Ties reasoning to the investigation it shaped |
| `task_class` | Routing analysis |
| `provider`, `model` | Model comparison |
| `prompt_name`, `prompt_version` | Prompt-change attribution |
| `tokens_in`, `tokens_out` | Cost and context-pressure analysis |
| `latency_ms` | Performance metrics |
| `cost_estimate_usd` | Budget tracking (estimate; provider pricing is config) |
| `finish_reason` | Truncation detection |
| `retries`, `schema_valid` | Reliability per model |
| `fallback_from` | How often the primary failed |
| `temperature`, `seed` | Reproducibility metadata |
| `grounding_violations` | `GroundingError`s raised by findings from this call |

`grounding_violations` is the key research linkage: it connects a specific model and prompt version
to the rate at which its reasoning over-claimed. That is the hallucination metric, measured
mechanically rather than by manual review.

Prompts are **versioned files**, never inline strings. A prompt change without a version bump makes
prior results unattributable.

## 8. Determinism for experiments

Temperature defaults to `0.0`; a seed is sent where the provider supports it. Neither guarantees
determinism across provider-side model updates, so each call records `provider`, `model`, and a
`nondeterminism_risk` flag, and experiment runs pin a `model_snapshot` label in their config.
Experiments report N runs with variance rather than single-shot numbers — see
[experiments.md](experiments.md).

## 9. Budget and failure handling

- **Per-investigation token ceiling.** Exceeding it halts the investigation with status `halted` and a
  stated reason — never a silent truncation of reasoning.
- **Circuit breaker.** Repeated failures from a provider open a breaker so every subsequent task does
  not pay the timeout.
- **Quota state is persisted**, so a restart does not re-hammer an exhausted provider.
- **Cost estimates come from config**, not hard-coded prices, and are labelled estimates.

## 10. Open assumptions — require confirmation before Phase 6

The spec names **"GPT-5.6 Tera"** and **"NVIDIA Nemotron 3 Ultra 550B"** as candidate models (§7).

**I cannot verify that either identifier exists, what its API name is, its context window, its pricing,
or whether it supports constrained structured output or tool calling.** Nothing in this design depends
on those answers: models are configuration values (`ACIP_MODEL_REASONING`, `ACIP_MODEL_LONGCTX`,
`ACIP_MODEL_SMALL`) resolved at runtime, and the code will name no model.

Before Phase 6 the team must confirm, per provider:

1. Exact model identifiers available under the accounts held.
2. Whether structured/JSON-schema-constrained output is supported natively — §6's typed-message
   requirement depends on it, and the fallback (retry-with-repair) is measurably worse.
3. Context window, for the long-context routing tier to be meaningful.
4. Rate limits and quota units, for the breaker and budget thresholds.
5. Current pricing, for cost estimates.
6. Data-handling terms. **Investigation content may contain real security data**; sending it to a
   third-party API is a disclosure decision, not just a technical one. See
   [threat-model.md](threat-model.md).

Also unconfirmed: whether the team has API credit for both providers. If only one is available, the
multi-model comparison in §8 and the single-vs-multi-model ablation in §22 cannot be run as specified,
and the evaluation plan must be scoped down. This is the highest-impact open question in the project —
tracked in [risks-and-assumptions.md](risks-and-assumptions.md).

## 11. Testing

- `replay.py` provides a deterministic provider for tests. It is a **test double, not a mock in
  production** — it is never registered outside test and experiment configurations, so §31's ban on
  fake functionality is not violated.
- Contract tests run against every provider implementation.
- Fallback tests inject each error type and assert the correct fallback/no-fallback decision.
- A test asserts that no module under `agents/` imports a provider SDK, keeping §7 enforced
  mechanically rather than by review.
