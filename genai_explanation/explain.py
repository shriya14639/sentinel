"""Part 4: GenAI incident explanation for Sentinel (advisory only).

    from genai_explanation.explain import explain_incident
    result = explain_incident(score_event(event))

Input : an event dict, normally the output of anomaly_detection.score.score_event
        (it must contain event["metrics"], a dict of numbers).
Output: a dict that always has the same keys (see _build_result).

This module only EXPLAINS an event the ML detector already flagged. It never executes
any recommended action and never sends ground-truth labels to the LLM.
"""
import json
import math
import os
import re
import socket
import urllib.error
import urllib.request

try:                                   # optional: read settings from a .env file
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from .prompts import (ALLOWED_INCIDENT_TYPES, FALLBACK_ACTIONS, SYSTEM_PROMPT,
                      TYPE_DESCRIPTIONS, build_user_prompt)

ALLOWED_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
METRIC_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
DEVIATION_LIMIT = 1.0          # same meaning as THRESHOLD in score.py: 1.0 = edge of normal
MAX_ID_LEN = 64
MAX_DESCRIPTION_LEN = 300
MAX_SUMMARY_LEN = 600
MAX_ACTION_LEN = 400
DEFAULT_TIMEOUT = 20.0
# Crude guard against over-confident wording in LLM text.
OVERCONFIDENT_WORDS = ("definitely", "certainly", "undoubtedly", "without doubt")


class InvalidEventError(ValueError):
    """The event cannot be explained (wrong type, no usable metrics)."""


class LLMError(Exception):
    """The LLM call failed or its answer was unusable. Safe to show to users."""


# ---------------------------------------------------------------- input checking
def _is_number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _clean_text(value, max_len):
    """Keep printable characters only and cut to max_len (limits injection and size)."""
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text.strip()[:max_len]


def validate_event(event):
    """Return (clean_event, warnings). Raise InvalidEventError if unusable."""
    warnings = []
    if not isinstance(event, dict):
        raise InvalidEventError("event must be a dict")
    raw_metrics = event.get("metrics")
    if not isinstance(raw_metrics, dict) or not raw_metrics:
        raise InvalidEventError("event['metrics'] must be a non-empty dict")

    metrics = {}
    for name, value in raw_metrics.items():
        if not isinstance(name, str) or not METRIC_NAME_PATTERN.match(name):
            warnings.append("Ignored a metric with an invalid name.")
        elif not _is_number(value):
            warnings.append(f"Ignored metric '{name}': value is not a finite number.")
        else:
            metrics[name] = float(value)
    if not metrics:
        raise InvalidEventError("no valid numeric metrics found in event['metrics']")

    metric_scores = {}
    raw_scores = event.get("metric_scores")
    if isinstance(raw_scores, dict):
        for name in metrics:
            if _is_number(raw_scores.get(name)):
                metric_scores[name] = float(raw_scores[name])
    elif raw_scores is not None:
        warnings.append("Ignored metric_scores: it is not a dict.")

    anomaly_score = None
    if event.get("anomaly_score") is not None:
        if _is_number(event["anomaly_score"]):
            anomaly_score = float(event["anomaly_score"])
        else:
            warnings.append("Ignored anomaly_score: not a finite number.")

    is_anomaly = event.get("is_anomaly")
    if is_anomaly is not None and not isinstance(is_anomaly, bool):
        warnings.append("Ignored is_anomaly: not a boolean.")
        is_anomaly = None

    severity = "UNKNOWN"
    if event.get("severity") is not None:
        candidate = str(event["severity"]).strip().upper()
        if candidate in ALLOWED_SEVERITIES:
            severity = candidate
        else:
            warnings.append("Ignored severity: not one of LOW/MEDIUM/HIGH/CRITICAL.")

    def optional_text(key, max_len):
        value = event.get(key)
        return (_clean_text(value, max_len) or None) if value is not None else None

    clean = {
        "system_id": optional_text("system_id", MAX_ID_LEN),
        "event_id": optional_text("event_id", MAX_ID_LEN),
        "timestamp": optional_text("timestamp", MAX_ID_LEN),
        "description": optional_text("description", MAX_DESCRIPTION_LEN),
        "severity": severity,
        "anomaly_score": anomaly_score,
        "is_anomaly": is_anomaly,
        "metrics": metrics,
        "metric_scores": metric_scores,
    }
    return clean, warnings


# ------------------------------------------------- evidence and rule-based fallback
def find_deviated_metrics(clean):
    """Metrics whose deviation ratio is at/above 1.0, biggest first: [(name, ratio)]."""
    pairs = [(n, s) for n, s in clean["metric_scores"].items() if s >= DEVIATION_LIMIT]
    return sorted(pairs, key=lambda p: p[1], reverse=True)


def build_evidence(clean, deviated):
    """Evidence lines built by CODE from the supplied data only (the LLM never writes these)."""
    lines = [f"System: {clean['system_id']}" if clean["system_id"] else "System: not specified"]
    lines.append(f"Timestamp: {clean['timestamp']}" if clean["timestamp"]
                 else "Timestamp: not specified")
    lines.append(f"Severity (from the previous module): {clean['severity']}"
                 if clean["severity"] != "UNKNOWN" else "Severity: not specified")
    if clean["anomaly_score"] is not None:
        lines.append(f"Anomaly score: {clean['anomaly_score']:.2f} (1.0 = edge of normal range)")
    else:
        lines.append("Anomaly score: not specified")
    if clean["metric_scores"]:
        if deviated:
            for name, score in deviated[:6]:
                lines.append(f"{name} = {clean['metrics'][name]:g}, "
                             f"deviation {score:.2f}x its normal limit")
        else:
            lines.append("No metric is outside its normal range.")
    else:
        lines.append("Per-metric deviation scores: not specified")
    if clean["description"]:
        lines.append(f"Description supplied with the event: {clean['description']}")
    return lines


def classify_incident(clean, deviated):
    """Simple cautious rules used only by the fallback."""
    if not clean["metric_scores"]:
        return "unknown_anomaly"
    names = {n for n, _ in deviated}
    if not names:
        return "no_clear_anomaly"
    if "failed_logins" in names:
        return "possible_brute_force_activity"
    if "cpu_pct" in names and "network_in_mbps" in names:
        return "unusual_resource_and_network_activity"
    if names & {"network_in_mbps", "network_out_mbps"}:
        return "unusual_network_activity"
    if names & {"cpu_pct", "memory_pct"}:
        return "unusual_resource_usage"
    if "error_rate" in names:
        return "possible_service_degradation"
    return "unknown_anomaly"


def _fallback_summary(clean, incident_type, deviated):
    system = clean["system_id"] or "an unnamed system"
    note = "This is an automatic template explanation, not an LLM analysis."
    if incident_type == "unknown_anomaly" and not clean["metric_scores"]:
        return (f"An event was reported for {system}, but per-metric deviation scores were "
                f"not provided, so the cause cannot be identified. {note}")
    if incident_type == "no_clear_anomaly":
        return f"No metric for {system} is outside its normal range in the data supplied. {note}"
    names = ", ".join(n for n, _ in deviated[:3])
    return (f"{system}: metrics outside their normal range ({names}). This is consistent with "
            f"{TYPE_DESCRIPTIONS[incident_type]}, but the data alone cannot confirm the cause. {note}")


# ------------------------------------------------------------------ LLM access
def _load_config():
    """Read settings from environment variables. Returns (config_or_None, warning_or_None)."""
    key = os.environ.get("SENTINEL_LLM_API_KEY", "").strip()
    if not key:
        return None, "SENTINEL_LLM_API_KEY is not set; using the rule-based fallback."
    base_url = os.environ.get("SENTINEL_LLM_BASE_URL", "").strip()
    model = os.environ.get("SENTINEL_LLM_MODEL", "").strip()
    missing = [n for n, v in (("SENTINEL_LLM_BASE_URL", base_url),
                              ("SENTINEL_LLM_MODEL", model)) if not v]
    if missing:
        return None, "Missing environment variable(s): " + ", ".join(missing) + "; using fallback."
    local = base_url.startswith(("http://localhost", "http://127.0.0.1"))
    if not (base_url.startswith("https://") or local):
        return None, "SENTINEL_LLM_BASE_URL must start with https://; using fallback."
    try:
        timeout = float(os.environ.get("SENTINEL_LLM_TIMEOUT", DEFAULT_TIMEOUT))
        if timeout <= 0:
            raise ValueError
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    return {"api_key": key, "base_url": base_url, "model": model, "timeout": timeout}, None


def _call_llm(config, system_prompt, user_prompt):
    """Send one chat request to an OpenAI-compatible API. Returns the reply text.

    Raises LLMError (with a safe message, never containing the API key) on any failure.
    """
    body = {
        "model": config["model"],
        "temperature": 0.2,
        "messages": [{"role": "system", "content": system_prompt},
                     {"role": "user", "content": user_prompt}],
    }
    request = urllib.request.Request(
        config["base_url"].rstrip("/") + "/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + config["api_key"]},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config["timeout"]) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as err:        # must come before URLError
        raise LLMError(f"The LLM API returned HTTP {err.code}.") from None
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
        raise LLMError("Could not reach the LLM API (network problem or timeout).") from None
    try:
        content = json.loads(raw)["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise LLMError("The LLM API response had an unexpected format.") from None
    if not isinstance(content, str):
        raise LLMError("The LLM API response had no text content.")
    return content


def _parse_llm_json(text):
    """Pull one JSON object out of the reply (tolerates ```json fences)."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("The LLM output did not contain a JSON object.")
    try:
        return json.loads(text[start:end + 1])
    except ValueError:
        raise LLMError("The LLM output was not valid JSON.") from None


def _validate_llm_output(parsed):
    """Check keys, types, lengths and wording. Returns (incident_type, summary, actions)."""
    if not isinstance(parsed, dict):
        raise LLMError("The LLM output was not a JSON object.")
    incident_type = parsed.get("incident_type")
    if not isinstance(incident_type, str) or incident_type not in ALLOWED_INCIDENT_TYPES:
        raise LLMError("The LLM gave an unknown incident_type.")
    summary = parsed.get("summary")
    if not isinstance(summary, str) or not (1 <= len(summary.strip()) <= MAX_SUMMARY_LEN):
        raise LLMError("The LLM summary is missing or has an invalid length.")
    actions = parsed.get("recommended_actions")
    if not isinstance(actions, list) or not (1 <= len(actions) <= 6):
        raise LLMError("The LLM recommended_actions must be a list of 1-6 items.")
    cleaned = []
    for action in actions:
        if not isinstance(action, str) or not (1 <= len(action.strip()) <= MAX_ACTION_LEN):
            raise LLMError("An LLM recommended action is not a valid string.")
        cleaned.append(action.strip())
    everything = (summary + " " + " ".join(cleaned)).lower()
    if any(word in everything for word in OVERCONFIDENT_WORDS):
        raise LLMError("The LLM used over-confident wording.")
    return incident_type, summary.strip(), cleaned


# ---------------------------------------------------------------- public function
def _build_result(status, llm_used, source, incident_type, severity, summary,
                  evidence, actions, warnings, error, event_id=None):
    """Every result has exactly these keys, so Part 5 can rely on them."""
    return {
        "event_id": event_id,                # copied from the input, or None
        "status": status,                    # "ok" | "fallback" | "error"
        "llm_used": llm_used,                # True only if a real LLM answer was used
        "source": source,                    # "llm" | "rule_based_fallback" | "none"
        "incident_type": incident_type,      # one of ALLOWED_INCIDENT_TYPES, or "unknown"
        "severity": severity,                # copied from the event, or "unknown"
        "summary": summary,
        "evidence": evidence,                # list of strings built from the input only
        "recommended_actions": actions,      # advice for humans; never executed
        "warnings": warnings,                # list of strings
        "error": error,                      # None, or a message when status == "error"
        "advisory_only": True,
    }


def _error_result(message):
    return _build_result(
        "error", False, "none", "unknown", "UNKNOWN",
        "No explanation was generated because the input event could not be used.", [],
        ["Check the event produced by the previous module and send it again."], [], message)


def explain_incident(event):
    """Explain one detector-flagged event. Never raises for bad input; see status field."""
    try:
        clean, warnings = validate_event(event)
    except InvalidEventError as err:
        return _error_result(str(err))
    except Exception as err:                       # safety net: report, do not crash
        return _error_result(f"Unexpected error while checking the event: {type(err).__name__}")

    deviated = find_deviated_metrics(clean)
    evidence = build_evidence(clean, deviated)

    config, config_warning = _load_config()
    if config_warning:
        warnings.append(config_warning)
    if config is not None:
        try:
            reply = _call_llm(config, SYSTEM_PROMPT, build_user_prompt(clean))
            incident_type, summary, actions = _validate_llm_output(_parse_llm_json(reply))
            return _build_result("ok", True, "llm", incident_type, clean["severity"],
                                 summary, evidence, actions, warnings, None,
                                 event_id=clean["event_id"])
        except LLMError as err:
            warnings.append(f"LLM explanation failed: {err} Using the rule-based fallback.")

    incident_type = classify_incident(clean, deviated)
    return _build_result("fallback", False, "rule_based_fallback", incident_type,
                         clean["severity"], _fallback_summary(clean, incident_type, deviated),
                         evidence, list(FALLBACK_ACTIONS[incident_type]), warnings, None,
                         event_id=clean["event_id"])

if __name__ == "__main__":
    # Demo with a MADE-UP event (not from your repo data). Works with no API key.
    demo = {
        "system_id": "demo-server-1", "timestamp": "2026-10-09T10:00:00Z",
        "severity": "critical", "anomaly_score": 7.5, "is_anomaly": True,
        "metrics": {"cpu_pct": 35, "memory_pct": 52, "network_in_mbps": 20,
                    "network_out_mbps": 15, "failed_logins": 85, "error_rate": 0.01},
        "metric_scores": {"cpu_pct": 0.2, "memory_pct": 0.1, "network_in_mbps": 0.3,
                          "network_out_mbps": 0.2, "failed_logins": 7.5, "error_rate": 0.1},
    }
    print(json.dumps(explain_incident(demo), indent=2))