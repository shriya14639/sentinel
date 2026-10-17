"""Part 4: incident explanation for Sentinel (advisory only).

    from genai_explanation.explain import explain_incident
    explanation = explain_incident(processed_event)

INPUT : the dict returned by pipeline.orchestrator.process_event (Parts 2 + 3).
        Required: "metrics" (dict of numbers). Everything else is optional.
OUTPUT: always a dict with the same keys (see _result). Check result["status"]:
          "ok"       a real LLM wrote the summary and recommendations
          "fallback" a template wrote them (no LLM configured, or the LLM failed)
          "error"    the input event could not be used (see result["error"])
        result["source"] says who wrote the text: "llm", "fallback" or "none".

Rules this module follows:
  * It never changes the severity chosen by Part 3. It only copies it.
  * "evidence" is built by this code from the event. An LLM never writes it.
  * Ground-truth labels (injected_anomaly, anomaly_type) are never used or sent.
  * Event text is treated as untrusted data. It is cleaned and shortened.
  * Recommended actions are advice for humans. Nothing is ever executed.
"""
import json
import math
import re

from . import providers
from .prompts import (ALLOWED_INCIDENT_TYPES, FALLBACK_ACTIONS, FALLBACK_LABEL,
                      SYSTEM_PROMPT, TYPE_DESCRIPTIONS, build_user_prompt)
from .providers import LLMError

ALLOWED_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
METRIC_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
IPV4_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
MAX_TEXT_LEN = 64
MAX_SUMMARY_LEN = 600
MAX_ACTION_LEN = 400
# Crude guard against over-confident wording in LLM text.
OVERCONFIDENT_WORDS = ("definitely", "certainly", "undoubtedly", "without doubt")


class InvalidEventError(ValueError):
    """The event cannot be explained (wrong type or no usable metrics)."""


# ------------------------------------------------------------ input checking
def _is_number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _clean_text(value):
    """Keep printable characters only and cut to MAX_TEXT_LEN (limits injection and size)."""
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text.strip()[:MAX_TEXT_LEN]


def _optional_text(event, key):
    value = event.get(key)
    return (_clean_text(value) or None) if value is not None else None


def validate_event(event):
    """Return (clean_event, warnings). Raise InvalidEventError if the event is unusable."""
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

    # Part 3 writes "deviated_metrics" (a copy of Part 2's "flagged_metrics").
    raw_deviated = event.get("deviated_metrics")
    if raw_deviated is None:
        raw_deviated = event.get("flagged_metrics")
    has_deviation_info = isinstance(raw_deviated, (list, tuple))
    deviated = []
    if has_deviation_info:
        for name in raw_deviated:
            if isinstance(name, str) and name in metrics:
                if name not in deviated:
                    deviated.append(name)
            else:
                warnings.append("Ignored a deviated-metric name that is not a metric in this event.")
        deviated.sort(key=lambda n: metric_scores.get(n, 0.0), reverse=True)
    elif raw_deviated is not None:
        warnings.append("Ignored deviated_metrics: it is not a list.")

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

    # Severity belongs to Part 3. We only copy it (accepting any letter case).
    severity = "UNKNOWN"
    if event.get("severity") is not None:
        candidate = str(event["severity"]).strip().upper()
        if candidate in ALLOWED_SEVERITIES:
            severity = candidate
        else:
            warnings.append("Ignored severity: not LOW, MEDIUM, HIGH or CRITICAL.")

    clean = {
        "event_id": _optional_text(event, "event_id"),
        "system_id": _optional_text(event, "system_id"),
        "timestamp": _optional_text(event, "timestamp"),
        "severity": severity,
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score,
        "deviated_metrics": deviated,
        "has_deviation_info": has_deviation_info,
        "correlation_detected": event.get("correlation_detected") is True,
        "memory_trend_detected": event.get("memory_trend_detected") is True,
        "metrics": metrics,
        "metric_scores": metric_scores,
    }
    return clean, warnings


# ------------------------------------------------ evidence and classification
def build_evidence(clean):
    """Evidence lines built by CODE from the supplied event only."""
    lines = [f"System: {clean['system_id']}" if clean["system_id"] else "System: not specified"]
    lines.append(f"Timestamp: {clean['timestamp']}" if clean["timestamp"]
                 else "Timestamp: not specified")
    lines.append(f"Severity assigned by the pipeline: {clean['severity']}"
                 if clean["severity"] != "UNKNOWN" else "Severity: not specified")
    if clean["is_anomaly"] is True:
        lines.append("The detector flagged this event as anomalous.")
    elif clean["is_anomaly"] is False:
        lines.append("The detector did not flag this event as anomalous.")
    else:
        lines.append("Detector anomaly flag: not specified")
    if clean["anomaly_score"] is not None:
        lines.append(f"Detector anomaly score: {clean['anomaly_score']:.2f} (higher = more unusual)")
    else:
        lines.append("Detector anomaly score: not specified")

    if not clean["has_deviation_info"]:
        lines.append("Deviated metrics: not specified")
    elif not clean["deviated_metrics"]:
        lines.append("No individual metric was reported as deviated.")
    for name in clean["deviated_metrics"]:
        value = f"{name} = {clean['metrics'][name]:g}"
        if name == "memory_pct" and clean["memory_trend_detected"]:
            # The pipeline may raise this score to a fixed minimum when a trend is found,
            # so we do not present it as a measured score.
            lines.append(value + " (deviated; part of a sustained increase)")
        elif name in clean["metric_scores"]:
            lines.append(f"{value} (detector score {clean['metric_scores'][name]:.2f})")
        else:
            lines.append(value + " (deviated)")
    if clean["correlation_detected"]:
        lines.append("Several metrics deviated together (correlation reported by the pipeline).")
    if clean["memory_trend_detected"]:
        lines.append("A sustained memory increase over recent readings was detected.")
    return lines


def classify_incident(clean):
    """Cautious rule-based incident type, used by the fallback."""
    names = set(clean["deviated_metrics"])
    trend = clean["memory_trend_detected"]
    if not names and not trend:
        if clean["has_deviation_info"] and not clean["is_anomaly"]:
            return "no_clear_anomaly"
        return "unknown_anomaly"
    if "failed_logins" in names:
        return "possible_brute_force_activity"
    if trend or names == {"memory_pct"}:
        return "possible_memory_leak"
    if "cpu_pct" in names and "network_in_mbps" in names:
        return "unusual_resource_and_network_activity"
    if names & {"network_in_mbps", "network_out_mbps"}:
        return "unusual_network_activity"
    if names & {"cpu_pct", "memory_pct"}:
        return "unusual_resource_usage"
    if "error_rate" in names:
        return "possible_service_degradation"
    return "unknown_anomaly"


def _supported_by_evidence(incident_type, clean):
    """True if the event data backs this incident type (used to check LLM answers)."""
    names = set(clean["deviated_metrics"])
    trend = clean["memory_trend_detected"]
    checks = {
        "possible_brute_force_activity": "failed_logins" in names,
        "unusual_resource_and_network_activity": {"cpu_pct", "network_in_mbps"} <= names,
        "possible_memory_leak": trend or "memory_pct" in names,
        "unusual_network_activity": bool(names & {"network_in_mbps", "network_out_mbps"}),
        "unusual_resource_usage": bool(names & {"cpu_pct", "memory_pct"}),
        "possible_service_degradation": "error_rate" in names,
        "no_clear_anomaly": not names and not trend,
        "unknown_anomaly": True,
    }
    return checks.get(incident_type, False)


def _fallback_summary(clean, incident_type):
    system = clean["system_id"] or "an unnamed system"
    severity = (f" (pipeline severity: {clean['severity']})"
                if clean["severity"] != "UNKNOWN" else "")
    if incident_type == "no_clear_anomaly":
        body = f"The detector reported no deviated metric for {system}{severity}."
    elif incident_type == "unknown_anomaly":
        body = (f"An event was reported for {system}{severity}, but the data does not say "
                "which metrics deviated, so the cause cannot be identified.")
    else:
        parts = list(clean["deviated_metrics"])
        if clean["memory_trend_detected"] and "memory_pct" not in parts:
            parts.append("memory_pct")
        body = (f"On {system}{severity} these metrics deviated: {', '.join(parts)}. "
                f"This is consistent with {TYPE_DESCRIPTIONS[incident_type]}, but the "
                "available data cannot confirm the cause.")
    return FALLBACK_LABEL + " " + body


# ------------------------------------------------------------- LLM output
def _parse_llm_json(text):
    """Pull one JSON object out of the LLM reply (tolerates ```json fences)."""
    if not isinstance(text, str):
        raise LLMError("The LLM reply was not text.")
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("The LLM output did not contain a JSON object.")
    try:
        return json.loads(text[start:end + 1])
    except ValueError:
        raise LLMError("The LLM output was not valid JSON.") from None


def _validate_llm_output(parsed, clean):
    """Check keys, types, lengths, wording and consistency. Returns (type, summary, actions)."""
    if not isinstance(parsed, dict):
        raise LLMError("The LLM output was not a JSON object.")
    incident_type = parsed.get("incident_type")
    if not isinstance(incident_type, str) or incident_type not in ALLOWED_INCIDENT_TYPES:
        raise LLMError("The LLM gave an unknown incident_type.")
    if not _supported_by_evidence(incident_type, clean):
        raise LLMError("The LLM incident_type is not supported by the event data.")
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
    text = summary + " " + " ".join(cleaned)
    if any(word in text.lower() for word in OVERCONFIDENT_WORDS):
        raise LLMError("The LLM used over-confident wording.")
    if IPV4_PATTERN.search(text):
        raise LLMError("The LLM mentioned an IP address, which was not in the event data.")
    return incident_type, summary.strip(), cleaned


# ---------------------------------------------------------- public function
def _result(status, source, provider=None, event_id=None, system_id=None, timestamp=None,
            incident_type="unknown", severity="UNKNOWN", summary="", evidence=None,
            actions=None, warnings=None, error=None):
    """Every result has exactly these keys, so Parts 5 and 6 can rely on them."""
    return {
        "event_id": event_id,                  # copied from the input, or None
        "system_id": system_id,                # copied from the input, or None
        "timestamp": timestamp,                # copied from the input, or None
        "status": status,                      # "ok" | "fallback" | "error"
        "source": source,                      # "llm" | "fallback" | "none"
        "llm_used": source == "llm",           # True only for real LLM text
        "provider": provider,                  # provider name, or None
        "incident_type": incident_type,        # one of ALLOWED_INCIDENT_TYPES, or "unknown"
        "severity": severity,                  # copied from Part 3, or "UNKNOWN"
        "summary": summary,
        "evidence": evidence if evidence is not None else [],
        "recommended_actions": actions if actions is not None else [],
        "warnings": warnings if warnings is not None else [],
        "error": error,                        # None, or a message when status is "error"
        "advisory_only": True,                 # nothing here is ever executed automatically
    }


def _error_result(message, event):
    event_id = None
    if isinstance(event, dict) and isinstance(event.get("event_id"), str):
        event_id = _clean_text(event["event_id"]) or None
    return _result(
        "error", "none", event_id=event_id,
        summary="No explanation was generated because the input event could not be used.",
        actions=["Check the event produced by the earlier pipeline stages and send it again."],
        error=message)


def explain_incident(event, llm=None):
    """Explain one event from the pipeline. Never raises for bad input.

    event: dict returned by pipeline.orchestrator.process_event.
    llm:   optional function (system_prompt, user_prompt) -> reply text. Used for tests
           or custom providers. If None, a provider is chosen from the environment;
           if none is configured, the template-based fallback is used.
    """
    try:
        clean, warnings = validate_event(event)
    except InvalidEventError as err:
        return _error_result(str(err), event)
    except Exception as err:                       # safety net: report it, do not crash
        return _error_result(f"Unexpected error while checking the event: {type(err).__name__}",
                             event)

    evidence = build_evidence(clean)
    ids = {"event_id": clean["event_id"], "system_id": clean["system_id"],
           "timestamp": clean["timestamp"], "severity": clean["severity"],
           "evidence": evidence}

    provider_name = "custom" if llm is not None else None
    if llm is None:
        llm, provider_name, provider_warning = providers.load_provider()
        if provider_warning:
            warnings.append(provider_warning)

    if llm is not None:
        try:
            reply = llm(SYSTEM_PROMPT, build_user_prompt(clean))
            incident_type, summary, actions = _validate_llm_output(_parse_llm_json(reply), clean)
            return _result("ok", "llm", provider=provider_name, incident_type=incident_type,
                           summary=summary, actions=actions, warnings=warnings, **ids)
        except Exception as err:
            reason = str(err) if isinstance(err, LLMError) else type(err).__name__
            warnings.append(f"LLM explanation failed ({reason}). "
                            "The template-based fallback was used.")

    incident_type = classify_incident(clean)
    return _result("fallback", "fallback", incident_type=incident_type,
                   summary=_fallback_summary(clean, incident_type),
                   actions=list(FALLBACK_ACTIONS[incident_type]), warnings=warnings, **ids)


if __name__ == "__main__":
    # Demo with a MADE-UP event (not from your data). Works with no API key.
    demo = {
        "event_id": "demo-1", "system_id": "demo-server", "timestamp": "2026-10-17T10:00:00Z",
        "severity": "CRITICAL", "is_anomaly": True, "anomaly_score": 40.0,
        "deviated_metrics": ["failed_logins", "cpu_pct"], "correlation_detected": True,
        "memory_trend_detected": False,
        "metrics": {"cpu_pct": 95, "memory_pct": 52, "network_in_mbps": 20,
                    "network_out_mbps": 15, "failed_logins": 40, "error_rate": 0.01},
        "metric_scores": {"cpu_pct": 30.0, "memory_pct": 0.3, "network_in_mbps": 0.2,
                          "network_out_mbps": 0.2, "failed_logins": 40.0, "error_rate": 0.1},
    }
    print(json.dumps(explain_incident(demo), indent=2))