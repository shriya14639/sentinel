# Part 4: Incident Explanation

Explains an event that Parts 2 and 3 already processed. It is **advisory only**: it never
runs any action, never changes the severity, and never decides that an attack is confirmed.

## Works without an API key
By default it writes the summary and recommendations from templates. Those summaries start with
`[FALLBACK - template-based, not LLM-generated]`, and the result says `source: "fallback"`.
Only a real LLM answer has `source: "llm"` and `llm_used: true`.

## Use it
```python
from pipeline.orchestrator import process_event          # Parts 2 + 3
from genai_explanation.explain import explain_incident   # Part 4

processed = process_event(raw_event, detector, tracker)
explanation = explain_incident(processed)
```
Run from the repository root. No new packages are needed (standard library only).

## Input
The dict returned by `process_event`. Required: `metrics` (dict of numbers).
Optional and used if present: `event_id`, `system_id`, `timestamp`, `severity`, `is_anomaly`,
`anomaly_score`, `deviated_metrics` (or `flagged_metrics`), `metric_scores`,
`correlation_detected`, `memory_trend_detected`.
Ground-truth labels (`injected_anomaly`, `anomaly_type`) and all other fields are ignored
and never sent to an LLM.

## Output (the same keys every time)
| key | meaning |
|---|---|
| `event_id`, `system_id`, `timestamp` | copied from the input, or `null` |
| `status` | `ok` (LLM text), `fallback` (template text), `error` (input unusable) |
| `source` | `llm`, `fallback` or `none` |
| `llm_used` | `true` only for real LLM text |
| `provider` | provider name, or `null` |
| `incident_type` | one of the allowed types, or `unknown` on error |
| `severity` | copied from Part 3 (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`), or `UNKNOWN` |
| `summary` | short, cautious explanation |
| `evidence` | lines built by code from the input only |
| `recommended_actions` | advice for humans, never executed |
| `warnings` | list of notes (for example why the fallback was used) |
| `error` | `null`, or a message when `status` is `error` |
| `advisory_only` | always `true` |

Part 5 and Part 6 should check `status` and `source` first.

Allowed incident types: `possible_brute_force_activity`, `unusual_resource_and_network_activity`,
`possible_memory_leak`, `unusual_network_activity`, `unusual_resource_usage`,
`possible_service_degradation`, `no_clear_anomaly`, `unknown_anomaly`.

## Add a real LLM later (optional)
1. Copy `.env.example` to `.env` (same folder) and fill in your own values. Never commit `.env`.
2. Set `SENTINEL_LLM_PROVIDER=openai_compatible` (works with OpenAI-style APIs).
3. For another service (for example IBM watsonx.ai), add one function in `providers.py`
   and register it in `PROVIDERS`.
If the LLM fails or answers badly, the fallback is used and `warnings` says why.
The LLM path has been tested only with mocks until someone runs one real call.

## Safety
- Evidence is built by code. An LLM never writes it.
- LLM output must be valid JSON, use an allowed incident type that the event data supports,
  have sensible lengths, avoid over-confident words and avoid IP addresses.
- Event text is cleaned, shortened and sent only inside a data block marked as untrusted.
- Only the fields in `PROMPT_FIELDS` (prompts.py) can ever be sent to an LLM.

## Run the tests (no key or network needed)
```
python -m unittest tests.test_explain -v
```

## Limits
- The fallback is rule-based and cannot tell causes apart beyond the metric patterns it knows.
- When a memory trend is detected, Part 3's pipeline may raise the memory score to a fixed
  minimum, so that score is not shown as evidence.
- The over-confidence and IP-address checks on LLM text are simple filters, not guarantees.