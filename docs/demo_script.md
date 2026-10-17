# Sentinel IBM Z — 3-Minute Video Demo Script & Presentation Guide

## 0:00 - 0:35 | Problem & Community Context
- Small to mid-sized organizations—such as municipal offices, regional healthcare facilities, and university IT teams—rely on critical infrastructure but cannot afford enterprise monitoring tools running tens of thousands of dollars annually.
- When an LPAR runs out of memory or an application suffers a brute-force spike, these teams suffer outages because they don't have dedicated SOC analysts watching raw metrics 24/7.
- Sentinel bridges this gap by combining real-time anomaly detection with automated, explainable incident triage on IBM LinuxONE.

## 0:35 - 1:15 | Architecture & Technical Design
- Our pipeline ingests multi-system telemetry (CPU %, Memory %, Network I/O, Error Rates, and Failed Logins).
- An unsupervised Isolation Forest scores multi-variate deviations in real time, catching subtle correlated anomalies that simple thresholds miss.
- Flagged events pass to a severity triage layer and our GenAI incident analysis engine, which produces plain-English explanations and actionable remediation steps.
- The entire stack is containerized on LinuxONE Community Cloud, demonstrating high concurrent throughput and data encryption at rest.

## 1:15 - 2:20 | Live Command-Center Dashboard Demo
- Walk through the Sentinel Command Center built with React and Vite.
- Highlight the total events, open incidents, and the severity breakdown across CRITICAL, HIGH, MEDIUM, and LOW tiers.
- Show live telemetry continuously monitoring systems like s390x-lpar-prod-01 and linuxone-api-gateway.
- Click a CRITICAL incident: highlight detector evidence, telemetry metrics, and active warnings.
- Demonstrate plain-English remediation actions generated to guide on-call staff.
- Show the API settings toggle switching between verified benchmark replay and live REST endpoints.

## 2:20 - 3:00 | Impact & Conclusion
- By coupling lightweight predictive anomaly detection with clear generative guidance on secure LinuxONE infrastructure, Sentinel delivers enterprise-grade resilience and rapid Mean Time to Resolution at a fraction of the cost.