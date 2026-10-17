# Part 4: GenAI Incident Explanation

Explains an event that the Part 2 detector already flagged. It is **advisory only**:
it never runs any action, and it never decides whether something is an attack.

## Install (Windows PowerShell, from the repo root)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r genai_explanation\requirements.txt
```

## Configure (optional)
Without a key the module still works, using a rule-based fallback.
To use a real LLM:
```powershell
copy genai_explanation\.env.example genai_explanation\.env
```
Open `genai_explanation\.env` and fill in the 3 values. Never commit it.

## Run the demo
```powershell
python -m genai_explanation.explain
```

## Run the tests (no key or network needed)
```powershell
python -m unittest genai_explanation.test_explain -v
```

## Use it from other code
```python
from pipeline.orchestrator import process_event
from genai_explanation.explain import explain_incident

processed = process_event(raw_event)          # Part 2 + Part 3
if processed["is_anomaly"]:                   # only explain flagged events
    explanation = explain_incident(processed)
```

## Input
A dict with `metrics` (dict of numbers). Optional: `system_id`, `timestamp`,
`severity` (LOW/MEDIUM/HIGH/CRITICAL), `anomaly_score`, `is_anomaly`,
`metric_scores`, `description`. All other fields (including ground-truth labels) are ignored
and never sent to the LLM.

## Output (always these keys)
| key | meaning |
|---|---|
| `event_id` | copied from the input event (for example `evt_000001`), or `null` |
| `status` | `ok` (LLM used), `fallback` (template used), `error` (bad input) |
| `llm_used` | `true` only if a real LLM answer was used |
| `source` | `llm`, `rule_based_fallback` or `none` |
| `incident_type` | one of the allowed types, or `unknown` on error |
| `severity` | copied from the input (LOW/MEDIUM/HIGH/CRITICAL), or `UNKNOWN` |
| `summary` | short cautious explanation |
| `evidence` | lines built by code from the input only |
| `recommended_actions` | advice for humans, never executed |
| `warnings` | list of notes (for example, why fallback was used) |
| `error` | `null`, or a message when `status` is `error` |
| `advisory_only` | always `true` |

Part 5 should check `status` first.

## Safety
- Evidence is built by code, not by the LLM.
- LLM output is validated (JSON, allowed incident types, lengths, no over-confident words).
- Event text is treated as data. Text fields are cleaned and shortened.
- Only listed fields are sent to the LLM.

## Troubleshooting
- `status` is `fallback` and the warning names a variable: set it in `.env`.
- `HTTP 401/403`: the key is wrong or lacks access.
- `HTTP 404`: check `SENTINEL_LLM_BASE_URL` and the model name.
- Timeout: raise `SENTINEL_LLM_TIMEOUT` or check your network.
- `ModuleNotFoundError: genai_explanation`: run commands from the repo root.
- Script blocked when activating the venv: run
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again.