const http = require('http');
const fs = require('fs');

const PORT = 5000;

const server = http.createServer((req, res) => {
  // Enable CORS so the React dashboard can call this API
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  if (req.url === '/api/incidents') {
    try {
      const rawData = fs.readFileSync('data2/sample_events.json', 'utf8');
      const events = JSON.parse(rawData);

      // Transform sample telemetry events to dashboard incident format
      const incidents = events.slice(0, 10).map((e) => {
        const isAnom = Boolean(e.injected_anomaly);
        return {
          event_id: e.event_id,
          timestamp: e.timestamp,
          system_id: e.system_id,
          status: isAnom ? 'OPEN' : 'RESOLVED',
          severity: isAnom ? 'CRITICAL' : 'LOW',
          summary: isAnom
            ? `Telemetry anomaly detected on ${e.system_id}: abnormal deviation in system counters`
            : `Nominal operational telemetry on ${e.system_id}`,
          anomaly_type: e.anomaly_type || 'Standard Baseline',
          metrics: e.metrics,
          evidence: isAnom
            ? 'Multivariate Isolation Forest detected abnormal correlation between CPU utilization and error rate.'
            : 'Metrics within standard nominal operating bounds.',
          recommended_actions: isAnom
            ? [
                'Inspect active batch jobs on designated LPAR.',
                'Audit security event log for repeated auth failures.',
                'Verify network ingress boundaries on LinuxONE VM.'
              ]
            : ['No remediation required.'],
          warnings: isAnom ? ['Threshold alert triggered on host interface'] : []
        };
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(incidents));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: err.message }));
    }
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`Sentinel Mock Telemetry Server running on http://127.0.0.1:${PORT}`);
});