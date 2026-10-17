// Sentinel IBM Z Incident & Telemetry Service
// Demo data mirrors data2/sample_events.json telemetry and schema

export const DEMO_INCIDENTS = [
  {
    event_id: "evt_000104",
    timestamp: "2026-10-17T18:42:10Z",
    system_id: "s390x-lpar-prod-01",
    status: "OPEN",
    severity: "CRITICAL",
    summary: "Sustained CPU saturation & anomalous memory consumption detected on primary LPAR",
    anomaly_type: "Resource Exhaustion Spike",
    metrics: {
      cpu_pct: 98.4,
      memory_pct: 92.1,
      network_in_mbps: 840.5,
      network_out_mbps: 712.3,
      failed_logins: 14,
      error_rate: 12.8
    },
    evidence: "Statistical anomaly z-score > 4.2 across consecutive 30s evaluation windows. Kernel scheduler latency spike correlates with heavy batch execution.",
    recommended_actions: [
      "Throttle or reroute non-critical batch processing to secondary sysplex node.",
      "Check top running tasks via RMF / z/OS monitoring facilities.",
      "Inspect auth logs for potential brute-force activity given elevated failed logins."
    ],
    warnings: [
      "LPAR page space approaching 85% threshold.",
      "CICS transaction throughput degraded by 34%."
    ]
  },
  {
    event_id: "evt_000098",
    timestamp: "2026-10-17T18:25:00Z",
    system_id: "linuxone-app-02",
    status: "INVESTIGATING",
    severity: "HIGH",
    summary: "Elevated transaction error rate spike accompanied by high outbound network egress",
    anomaly_type: "Network Egress Exfiltration Pattern",
    metrics: {
      cpu_pct: 64.2,
      memory_pct: 58.7,
      network_in_mbps: 110.2,
      network_out_mbps: 945.8,
      failed_logins: 3,
      error_rate: 8.4
    },
    evidence: "Outbound transfer volume is 8.5x the rolling 24-hour baseline. HTTP 502/504 error response rate increased to 8.4%.",
    recommended_actions: [
      "Isolate network interface eth1 on linuxone-app-02.",
      "Audit active socket connections and review reverse proxy logs."
    ],
    warnings: [
      "Exceeds bandwidth alert boundary for tier-2 microservices."
    ]
  },
  {
    event_id: "evt_000085",
    timestamp: "2026-10-17T17:58:32Z",
    system_id: "s390x-db2-subsystem",
    status: "OPEN",
    severity: "MEDIUM",
    summary: "Abnormal surge in authentication failures on administrative ports",
    anomaly_type: "Credential Spray / Auth Anomaly",
    metrics: {
      cpu_pct: 42.1,
      memory_pct: 61.0,
      network_in_mbps: 45.6,
      network_out_mbps: 38.2,
      failed_logins: 47,
      error_rate: 2.1
    },
    evidence: "Failed login count (47) exceeds dynamic threshold of 5/min across RACF security audit logs.",
    recommended_actions: [
      "Temporarily lock targeted service accounts pending verification.",
      "Verify source IP origin against whitelist."
    ],
    warnings: []
  },
  {
    event_id: "evt_000072",
    timestamp: "2026-10-17T16:15:18Z",
    system_id: "linuxone-api-gateway",
    status: "RESOLVED",
    severity: "LOW",
    summary: "Minor latency jitter detected during scheduled batch checkpointing",
    anomaly_type: "Checkpoint Jitter",
    metrics: {
      cpu_pct: 48.3,
      memory_pct: 51.2,
      network_in_mbps: 88.4,
      network_out_mbps: 76.1,
      failed_logins: 0,
      error_rate: 0.4
    },
    evidence: "Latency delta settled back inside nominal bounds after synchronization completed.",
    recommended_actions: [
      "No remediation required; log marked as normal scheduled behavior."
    ],
    warnings: []
  }
];

export async function fetchIncidents(apiBaseUrl = "") {
  if (apiBaseUrl) {
    try {
<<<<<<< HEAD
      const response = await fetch(`${apiBaseUrl}/incidents`, {
        headers: { "Content-Type": "application/json" }
      });

      if (!response.ok) {
        throw new Error(
          `HTTP Error ${response.status}: ${response.statusText}`
        );
      }

      const data = await response.json();

      const apiIncidents = Array.isArray(data)
        ? data
        : (data.items || data.incidents || []);

      const mappedIncidents = apiIncidents.map((item) => ({
        event_id: String(item.event_id ?? item.record_id ?? "Unknown"),
        timestamp: item.timestamp ?? "",
        system_id: String(item.system_id ?? "Unknown"),
        status: item.is_anomaly ? "OPEN" : "RESOLVED",
        severity: String(item.severity ?? "LOW").toUpperCase(),
summary: (() => {
  const value = item.explanation ?? item.summary;
  if (typeof value === "string") return value;
  if (value && typeof value === "object") {
    return String(
      value.message ??
      value.description ??
      value.summary ??
      value.reason ??
      JSON.stringify(value)
    );
  }
  return "Anomaly monitoring event";
})(),
           
        anomaly_type: String(item.anomaly_type ?? "Telemetry anomaly"),
        metrics:
          item.metrics && typeof item.metrics === "object"
            ? item.metrics
            : {},
        evidence: Array.isArray(item.deviated_metrics)
          ? item.deviated_metrics.map(String)
          : [],
        warnings: [],
        recommended_actions: []
      }));

      return {
        data: mappedIncidents,
=======
      const response = await fetch(`${apiBaseUrl}/api/incidents`, {
        headers: { "Content-Type": "application/json" }
      });
      if (!response.ok) {
        throw new Error(`HTTP Error ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();
      return {
        data: Array.isArray(data) ? data : data.incidents || [],
>>>>>>> origin/main
        isDemo: false,
        error: null
      };
    } catch (err) {
      console.warn("Backend unavailable, falling back to verified demo data:", err.message);
      return {
        data: DEMO_INCIDENTS,
        isDemo: true,
        error: `Could not reach backend (${err.message}). Displaying local datathon demo events.`
      };
      
    }
  }

  return {
    data: DEMO_INCIDENTS,
    isDemo: true,
    error: null
  };
<<<<<<< HEAD
}


  
=======
}
>>>>>>> origin/main
