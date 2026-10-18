import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Server, 
  AlertTriangle, 
  CheckCircle, 
  Search, 
  RefreshCw, 
  Database,
  ExternalLink,
  ChevronRight,
  Info
} from 'lucide-react';
import { fetchIncidents } from './services/dataService';

export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState(null);
  const [isDemo, setIsDemo] = useState(true);
  const [selectedIncident, setSelectedIncident] = useState(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Backend connection toggle
  const [backendUrl, setBackendUrl] = useState('http://127.0.0.1:8001');
  const [showConfig, setShowConfig] = useState(false);

  const loadData = async (url = backendUrl) => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetchIncidents(url);
      setIncidents(res.data);
      setIsDemo(res.isDemo);
      setErrorMsg(res.error);
      if (res.data.length > 0 && !selectedIncident) {
        setSelectedIncident(res.data[0]);
      }
    } catch (err) {
      setErrorMsg(err.message || 'Failed to retrieve telemetry.');
    } finally {
      setLoading(false);
    }
  };

 useEffect(() => {
  loadData();
  const interval = setInterval(() => {
    loadData(backendUrl);
  }, 3000);
  return () => clearInterval(interval);
}, [backendUrl]);

  // Filtered dataset
  const filteredIncidents = useMemo(() => {
    return incidents.filter((item) => {
      const matchesSearch = 
        item.event_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.system_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.summary.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesSev = severityFilter === 'ALL' || item.severity === severityFilter;
      const matchesStatus = statusFilter === 'ALL' || item.status === statusFilter;

      return matchesSearch && matchesSev && matchesStatus;
    });
  }, [incidents, searchQuery, severityFilter, statusFilter]);

  // Aggregate stats
  const stats = useMemo(() => {
    const total = incidents.length;
    const critical = incidents.filter(i => i.severity === 'CRITICAL').length;
    const high = incidents.filter(i => i.severity === 'HIGH').length;
    const medium = incidents.filter(i => i.severity === 'MEDIUM').length;
    const low = incidents.filter(i => i.severity === 'LOW').length;
    const open = incidents.filter(i => i.status === 'OPEN').length;
    return { total, critical, high, medium, low, open };
  }, [incidents]);

  return (
    <div className="dashboard-container">
      {/* Top Navigation Bar */}
      <header className="header-bar">
        <div className="brand-title">
          <ShieldAlert size={28} color="#0f62fe" />
          <span>IBM Z // Sentinel Anomaly Monitor</span>
          {isDemo ? (
            <span className="badge-tag badge-demo">Demo Data Mode</span>
          ) : (
            <span className="badge-tag badge-live">Live Telemetry API</span>
          )}
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button 
            onClick={() => setShowConfig(!showConfig)}
            className="filter-select"
            style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
          >
            <Server size={14} />
            <span>API Settings</span>
          </button>
          <button 
            onClick={() => loadData()}
            className="filter-select"
            style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </header>

      {/* Backend API Configuration Drawer */}
      {showConfig && (
        <div className="card" style={{ marginBottom: '1.5rem', background: '#162036' }}>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <label style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Backend API Base URL:
            </label>
            <input 
              type="text" 
              placeholder="e.g. http://localhost:5000 or http://10.x.x.x:5000"
              value={backendUrl}
              onChange={(e) => setBackendUrl(e.target.value)}
              className="search-input"
              style={{ flex: 1, minWidth: '280px' }}
            />
            <button 
              onClick={() => loadData(backendUrl)}
              className="filter-select"
              style={{ background: 'var(--ibm-blue)', color: '#fff', border: 'none', cursor: 'pointer', fontWeight: 600 }}
            >
              Connect to API
            </button>
            <button 
              onClick={() => { setBackendUrl(''); loadData(''); }}
              className="filter-select"
              style={{ cursor: 'pointer' }}
            >
              Reset to Demo Mode
            </button>
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
            * Note: Keep blank to run verified offline Datathon simulation data.
          </p>
        </div>
      )}

      {/* Warning Notice if Backend unreachable */}
      {errorMsg && (
        <div className="card" style={{ borderLeft: '4px solid #da1e28', marginBottom: '1.5rem', background: '#25151b' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#ff8389', fontSize: '0.85rem' }}>
            <AlertTriangle size={16} />
            <span>{errorMsg}</span>
          </div>
        </div>
      )}

      {/* Metric Cards Overview */}
      <section className="kpi-grid">
        <div className="card">
          <div className="kpi-label">
            <span>Total Events</span>
            <Activity size={16} color="var(--ibm-blue)" />
          </div>
          <div className="kpi-value">{stats.total}</div>
        </div>

        <div className="card">
          <div className="kpi-label">
            <span>Critical Anomalies</span>
            <span className="sev-pill sev-CRITICAL">CRITICAL</span>
          </div>
          <div className="kpi-value" style={{ color: '#ff8389' }}>{stats.critical}</div>
        </div>

        <div className="card">
          <div className="kpi-label">
            <span>High Severity</span>
            <span className="sev-pill sev-HIGH">HIGH</span>
          </div>
          <div className="kpi-value" style={{ color: '#ffb784' }}>{stats.high}</div>
        </div>

        <div className="card">
          <div className="kpi-label">
            <span>Medium / Low</span>
            <span className="sev-pill sev-MEDIUM">MED/LOW</span>
          </div>
          <div className="kpi-value" style={{ color: '#fddc69' }}>{stats.medium + stats.low}</div>
        </div>

        <div className="card">
          <div className="kpi-label">
            <span>Open Status</span>
            <Database size={16} color="var(--text-muted)" />
          </div>
          <div className="kpi-value">{stats.open}</div>
        </div>
      </section>

      {/* Controls & Filter Bar */}
      <section className="controls-bar">
        <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
          <Search size={16} style={{ position: 'absolute', top: '50%', left: '12px', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            className="search-input"
            style={{ paddingLeft: '2.4rem', width: '100%' }}
            placeholder="Search by event ID, system LPAR, or summary..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <select 
          className="filter-select"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select 
          className="filter-select"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="ALL">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="RESOLVED">Resolved</option>
        </select>
      </section>

      {/* Main Split Layout: Table and Detail Panel */}
      <main className={`layout-split ${selectedIncident ? 'has-detail' : ''}`}>
        {/* Incidents Table */}
        <div className="card table-wrapper" style={{ padding: 0 }}>
          {loading ? (
            <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading telemetry feed...
            </div>
          ) : filteredIncidents.length === 0 ? (
            <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              No incidents match the active filter criteria.
            </div>
          ) : (
            <table className="incident-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>System</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Anomaly Type / Summary</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredIncidents.map((item) => (
                  <tr 
                    key={item.event_id}
                    onClick={() => setSelectedIncident(item)}
                    className={selectedIncident?.event_id === item.event_id ? 'selected' : ''}
                  >
                    <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{item.event_id}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{item.system_id}</td>
                    <td>
                      <span className={`sev-pill sev-${item.severity}`}>{item.severity}</span>
                    </td>
                    <td>
                      <span style={{ 
                        fontSize: '0.75rem', 
                        fontWeight: 600, 
                        color: item.status === 'RESOLVED' ? '#42be65' : '#ffb784' 
                      }}>
                        {item.status}
                      </span>
                    </td>
                    <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {item.summary}
                    </td>
                    <td>
                      <ChevronRight size={16} color="var(--text-muted)" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Selected Incident Drawer */}
        {selectedIncident && (
          <aside className="detail-panel">
            <div className="detail-header">
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                  {selectedIncident.event_id} â€¢ {new Date(selectedIncident.timestamp).toLocaleTimeString()}
                </span>
                <h3 style={{ fontSize: '1.15rem', marginTop: '0.2rem' }}>
                  {selectedIncident.system_id}
                </h3>
              </div>
              <span className={`sev-pill sev-${selectedIncident.severity}`}>
                {selectedIncident.severity}
              </span>
            </div>

            <div>
              <span className="kpi-label" style={{ marginBottom: '0.35rem' }}>Anomaly Pattern</span>
              <p style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-main)' }}>
                {selectedIncident.anomaly_type}
              </p>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                {selectedIncident.summary}
              </p>
            </div>

            {/* Metrics Strip */}
            {selectedIncident.metrics && (
              <div>
                <span className="kpi-label" style={{ marginBottom: '0.5rem' }}>System Telemetry</span>
                <div className="metric-strip">
                  <div className="metric-strip-item">
                    <span>CPU Util</span>
                    <strong>{selectedIncident.metrics.cpu_pct}%</strong>
                  </div>
                  <div className="metric-strip-item">
                    <span>Memory</span>
                    <strong>{selectedIncident.metrics.memory_pct}%</strong>
                  </div>
                  <div className="metric-strip-item">
                    <span>Error Rate</span>
                    <strong>{selectedIncident.metrics.error_rate}%</strong>
                  </div>
                  <div className="metric-strip-item">
                    <span>Net In</span>
                    <strong>{selectedIncident.metrics.network_in_mbps} Mb/s</strong>
                  </div>
                  <div className="metric-strip-item">
                    <span>Net Out</span>
                    <strong>{selectedIncident.metrics.network_out_mbps} Mb/s</strong>
                  </div>
                  <div className="metric-strip-item">
                    <span>Failed Auth</span>
                    <strong>{selectedIncident.metrics.failed_logins}</strong>
                  </div>
                </div>
              </div>
            )}

            {/* Evidence Section */}
            <div>
              <span className="kpi-label" style={{ marginBottom: '0.4rem' }}>Detector Evidence</span>
              <div className="evidence-box">
                {selectedIncident.evidence}
              </div>
            </div>

            {/* Warnings Section */}
            {selectedIncident.warnings && selectedIncident.warnings.length > 0 && (
              <div className="warning-box">
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#ffb784', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <AlertTriangle size={14} /> ACTIVE WARNINGS
                </span>
                <ul className="warning-list">
                  {selectedIncident.warnings.map((warn, idx) => (
                    <li key={idx}>{warn}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Recommended Remediation Actions */}
            <div>
              <span className="kpi-label" style={{ marginBottom: '0.3rem' }}>Recommended Remediation</span>
              <ol className="action-list">
                {selectedIncident.recommended_actions.map((action, idx) => (
                  <li key={idx}>{action}</li>
                ))}
              </ol>
            </div>
          </aside>
        )}
      </main>
    </div>
  );
}
