import { useState, useEffect } from "react";
import "./styles/dashboard.css";

const navItems = [
  { icon: "▦", label: "Overview" },
  { icon: "⌁", label: "Phishing Analysis" },
  { icon: "◇", label: "Compliance" },
];

function Panel({ title, extra, children, id }) {
  return (
    <section className="panel" id={id}>
      <div className="panel-heading">
        <h2>{title}</h2>
        {extra}
      </div>
      {children}
    </section>
  );
}

export default function App() {
  const [active, setActive] = useState("Overview");
  const [search, setSearch] = useState("");
  const [compliance, setCompliance] = useState(null);
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [menuOpen, setMenuOpen] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState(null);

  const loadReports = () => {
    fetch("/reports")
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => {
        if (!Array.isArray(data)) return;
        const formatted = data.map((r) => {
          const dateStr = r.created_at
            ? new Date(r.created_at).toLocaleString("en-US", {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })
            : "Recent";
          return {
            id: r.id,
            date: dateStr,
            type: r.subject || "Reported Phish",
            sender: r.sender_actual || r.sender_claimed || "Unknown sender",
            claimedSender: r.sender_claimed || "None",
            source: r.link || "No embedded URL",
            body: r.body || "No raw body captured",
            severity: (r.severity || "Low").charAt(0).toUpperCase() + (r.severity || "Low").slice(1),
            status: (r.status || "new").toLowerCase(),
            score: r.risk_score ?? 0,
            indicators: r.indicators || [],
          };
        });
        setThreats(formatted);
      })
      .catch((err) => console.error("Reports fetch error:", err))
      .finally(() => setLoading(false));
  };

  const loadCompliance = () => {
    fetch("/compliance-status")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!data) return;
        const total = data.statuses ? data.statuses.length : (data.obligations ? data.obligations.length : 0);
        const met = data.statuses
          ? data.statuses.filter((s) => s.status === "met").length
          : (data.obligations ? data.obligations.filter((o) => o.status === "Met").length : 0);
        const score = total > 0 ? Math.round((met / total) * 100) : 0;
        const items = (data.obligations || []).map((ob) => {
          const st = (data.statuses || []).find((s) => s.obligation_id === ob.id);
          const isMet = st ? st.status === "met" : ob.status === "Met";
          return {
            title: ob.title,
            isMet,
            detail: ob.description || "Standard cybersecurity baseline requirement.",
          };
        });
        setCompliance({ score, items, total, met });
      })
      .catch((err) => console.error("Compliance fetch error:", err));
  };

  const handleStatusChange = async (reportId, newStatus) => {
    setThreats((prev) =>
      prev.map((t) => (t.id === reportId ? { ...t, status: newStatus } : t))
    );

    try {
      const res = await fetch(`/reports/${reportId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) {
        console.error("Status update failed on server.");
        loadReports();
      }
    } catch (err) {
      console.error("PATCH error:", err);
      loadReports();
    }
  };

  useEffect(() => {
    loadReports();
    loadCompliance();
  }, []);

  const visibleThreats = threats.filter((threat) =>
    `${threat.type} ${threat.sender} ${threat.source} ${threat.severity} ${threat.status}`
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  const totalReports = threats.length || 1;
  const highRiskCount = threats.filter((t) => t.severity.toLowerCase() === "high").length;
  const medRiskCount = threats.filter((t) => t.severity.toLowerCase() === "medium").length;
  const lowRiskCount = threats.filter((t) => t.severity.toLowerCase() === "low").length;

  const highPct = Math.round((highRiskCount / totalReports) * 100);
  const medPct = Math.round((medRiskCount / totalReports) * 100);
  const lowPct = Math.round((lowRiskCount / totalReports) * 100);

  const statusNew = threats.filter((t) => t.status === "new").length;
  const statusReview = threats.filter((t) => t.status === "under review").length;
  const statusMitigated = threats.filter((t) => t.status === "blocked" || t.status === "resolved").length;

  return (
    <div className={`dashboard ${menuOpen ? "nav-open" : ""}`}>
      {menuOpen && <div className="backdrop" onClick={() => setMenuOpen(false)} />}

      <aside className="sidebar">
        <a className="brand" href="#overview" onClick={() => { setActive("Overview"); setMenuOpen(false); }}>
          <span className="brand-symbol">E</span>
          <span className="brand-copy">
            <strong>EthioSecure</strong>
            <small>PHISH WATCH</small>
          </span>
        </a>

        <div className="nav-caption">WORKSPACE</div>
        <nav className="navigation" aria-label="Main navigation">
          {navItems.map((item) => (
            <button
              key={item.label}
              className={`nav-link ${active === item.label ? "selected" : ""}`}
              onClick={() => { setActive(item.label); setMenuOpen(false); }}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
              {item.label === "Phishing Analysis" && (
                <span className="nav-count">{threats.length}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="status-indicator"><span /> SOC CONNECTED</div>
          <p className="sidebar-note">Active threat monitoring & audit engine.</p>
          <div className="sidebar-version">PHISH WATCH · ANALYST PORTAL</div>
        </div>
      </aside>

      <main className="main-area" id="overview">
        <header className="topbar">
          <div className="topbar-left">
            <button className="mobile-toggle" onClick={() => setMenuOpen(!menuOpen)} aria-label="Toggle Navigation">
              ☰
            </button>
            <div className="breadcrumbs">EthioSecure <span>/</span> {active}</div>
          </div>
          <div className="topbar-right">
            <span className="demo-pill">● Live Database</span>
            <div className="user-avatar">SA</div>
            <div className="user-label"><strong>Security Analyst</strong><small>SOC Operator</small></div>
          </div>
        </header>

        <div className="content">
          <section className="page-intro">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS</div>
              <h1>
                {active === "Overview" && "Executive Security Overview"}
                {active === "Phishing Analysis" && "Phishing Incident Triage & Analysis"}
                {active === "Compliance" && "Regulatory Compliance & Standards Audit"}
              </h1>
              <p>
                {active === "Overview" && "High-level posture, telemetry analytics, and operational metrics."}
                {active === "Phishing Analysis" && "Inspect raw headers, payloads, link forensics, and update remediation state."}
                {active === "Compliance" && "National Cybersecurity & Data Protection readiness tracking."}
              </p>
            </div>
            <button className="outline-button" onClick={() => { setSearch(""); loadReports(); loadCompliance(); }}>
              ↻ Refresh Data
            </button>
          </section>

          {/* ========================================================
              TAB 1: OVERVIEW VIEW
             ======================================================== */}
          {active === "Overview" && (
            <>
              <section className="metric-grid" aria-label="Security metrics">
                <article className="metric-card">
                  <div className="metric-icon blue">⌕</div>
                  <div className="metric-label">Total Submissions</div>
                  <div className="metric-value">{threats.length}</div>
                  <div className="metric-note">Stored in Neon PostgreSQL</div>
                </article>

                <article className="metric-card">
                  <div className="metric-icon red">⚠</div>
                  <div className="metric-label">High Severity</div>
                  <div className="metric-value">{highRiskCount}</div>
                  <div className="metric-note">Immediate remediation</div>
                </article>

                <article className="metric-card">
                  <div className="metric-icon purple">⏳</div>
                  <div className="metric-label">Triage Queue</div>
                  <div className="metric-value">{statusNew + statusReview}</div>
                  <div className="metric-note">Awaiting analyst action</div>
                </article>

                <article className="metric-card">
                  <div className="metric-icon green">◇</div>
                  <div className="metric-label">Compliance Readiness</div>
                  <div className="metric-value">{compliance ? `${compliance.score}%` : "--"}</div>
                  <div className="metric-note">{compliance ? `${compliance.met}/${compliance.total} obligations met` : "Auditing..."}</div>
                </article>
              </section>

              <Panel title="Threat Telemetry & Risk Posture" extra={<span className="table-count">{threats.length} logged incidents</span>}>
                <div className="telemetry-grid">
                  <div className="telemetry-box">
                    <div className="telemetry-header">
                      <strong>Severity Distribution</strong>
                      <span>Ratio of incoming risk</span>
                    </div>
                    <div className="exposure-bar-track">
                      <div style={{ width: `${threats.length ? highPct : 0}%` }} className="seg-high" title={`High: ${highPct}%`} />
                      <div style={{ width: `${threats.length ? medPct : 0}%` }} className="seg-med" title={`Medium: ${medPct}%`} />
                      <div style={{ width: `${threats.length ? lowPct : 100}%` }} className="seg-low" title={`Low: ${lowPct}%`} />
                    </div>
                    <div className="telemetry-stats">
                      <div className="stat-item"><span className="dot red" /> High: <strong>{highRiskCount}</strong> <small>({threats.length ? highPct : 0}%)</small></div>
                      <div className="stat-item"><span className="dot amber" /> Medium: <strong>{medRiskCount}</strong> <small>({threats.length ? medPct : 0}%)</small></div>
                      <div className="stat-item"><span className="dot green" /> Low: <strong>{lowRiskCount}</strong> <small>({threats.length ? lowPct : 0}%)</small></div>
                    </div>
                  </div>

                  <div className="telemetry-box">
                    <div className="telemetry-header">
                      <strong>Incident Triage Pipeline</strong>
                      <span>Response lifecycle</span>
                    </div>
                    <div className="pipeline-steps">
                      <div className="step-card">
                        <span className="step-label">Unreviewed</span>
                        <strong className="step-num text-amber">{statusNew}</strong>
                        <span className="step-tag">New</span>
                      </div>
                      <div className="pipeline-arrow">→</div>
                      <div className="step-card">
                        <span className="step-label">In Progress</span>
                        <strong className="step-num text-blue">{statusReview}</strong>
                        <span className="step-tag">Under Review</span>
                      </div>
                      <div className="pipeline-arrow">→</div>
                      <div className="step-card">
                        <span className="step-label">Remediated</span>
                        <strong className="step-num text-green">{statusMitigated}</strong>
                        <span className="step-tag">Mitigated</span>
                      </div>
                    </div>
                  </div>
                </div>
              </Panel>

              <div className="main-grid">
                <Panel title="Recent Threat Stream" extra={<button className="text-button" onClick={() => setActive("Phishing Analysis")}>Open Full Triage Console →</button>}>
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>THREAT / SENDER</th>
                          <th>SEVERITY</th>
                          <th>STATUS</th>
                        </tr>
                      </thead>
                      <tbody>
                        {threats.slice(0, 5).map((threat) => (
                          <tr key={threat.id} style={{ cursor: "pointer" }} onClick={() => { setSelectedThreat(threat); setActive("Phishing Analysis"); }}>
                            <td>
                              <strong className="threat-name">{threat.type}</strong>
                              <small className="threat-source">{threat.sender}</small>
                            </td>
                            <td><span className={`severity ${threat.severity.toLowerCase()}`}>{threat.severity}</span></td>
                            <td><span className="status-pill">{threat.status}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Panel>

                <Panel title="System Diagnostics">
                  <div className="diagnostics-box">
                    <p><strong>API Gateway:</strong> Render Web Service</p>
                    <p><strong>Database:</strong> Neon PostgreSQL (Active)</p>
                    <p><strong>Audit Pipeline:</strong> Live Automated Scan</p>
                    <p><strong>Active Session:</strong> SOC Analyst Level 2</p>
                  </div>
                </Panel>
              </div>
            </>
          )}

          {/* ========================================================
              TAB 2: PHISHING ANALYSIS VIEW
             ======================================================== */}
          {active === "Phishing Analysis" && (
            <div className="analysis-workspace">
              <Panel
                title="Phishing Investigation & Triage Feed"
                extra={<span className="table-count">{visibleThreats.length} total alerts</span>}
              >
                <div className="table-toolbar">
                  <label className="search-box">
                    <span>⌕</span>
                    <input
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="Filter by subject, sender, link, severity..."
                      aria-label="Filter threat records"
                    />
                  </label>
                  {search && <button className="text-button" onClick={() => setSearch("")}>Clear</button>}
                </div>

                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>THREAT DETAILS</th>
                        <th>EMBEDDED URL / LINK</th>
                        <th>SEVERITY</th>
                        <th>RISK SCORE</th>
                        <th>TRIAGE ACTION</th>
                        <th>INSPECT</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visibleThreats.map((threat) => (
                        <tr key={threat.id}>
                          <td>
                            <strong className="threat-name">{threat.type}</strong>
                            <small className="threat-source">From: {threat.sender}</small>
                            <small className="threat-date">{threat.date}</small>
                          </td>
                          <td style={{ maxWidth: "200px", wordBreak: "break-all" }}>
                            <code className="code-pill">{threat.source}</code>
                          </td>
                          <td>
                            <span className={`severity ${threat.severity.toLowerCase()}`}>
                              {threat.severity}
                            </span>
                          </td>
                          <td>
                            <strong>{threat.score} / 100</strong>
                          </td>
                          <td>
                            <select
                              className="status-select"
                              value={threat.status}
                              onChange={(e) => handleStatusChange(threat.id, e.target.value)}
                            >
                              <option value="new">New</option>
                              <option value="under review">Under Review</option>
                              <option value="blocked">Blocked</option>
                              <option value="resolved">Resolved</option>
                            </select>
                          </td>
                          <td>
                            <button className="text-button" onClick={() => setSelectedThreat(threat)}>
                              View Details
                            </button>
                          </td>
                        </tr>
                      ))}
                      {visibleThreats.length === 0 && !loading && (
                        <tr>
                          <td colSpan="6" className="empty-row">
                            No records matching query.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </Panel>

              {/* Threat Detail Modal / Drawer */}
              {selectedThreat && (
                <div className="modal-backdrop" onClick={() => setSelectedThreat(null)}>
                  <div className="modal-window" onClick={(e) => e.stopPropagation()}>
                    <div className="modal-header">
                      <h3>Incident #{selectedThreat.id} — Forensics</h3>
                      <button className="close-btn" onClick={() => setSelectedThreat(null)}>✕</button>
                    </div>
                    <div className="modal-body">
                      <div className="modal-field">
                        <label>Subject / Type:</label>
                        <p><strong>{selectedThreat.type}</strong></p>
                      </div>
                      <div className="modal-field">
                        <label>Claimed vs Actual Sender:</label>
                        <p>{selectedThreat.claimedSender} &rarr; <code>{selectedThreat.sender}</code></p>
                      </div>
                      <div className="modal-field">
                        <label>Suspicious Link:</label>
                        <p><code className="code-pill">{selectedThreat.source}</code></p>
                      </div>
                      <div className="modal-field">
                        <label>Risk Score & Severity:</label>
                        <p><span className={`severity ${selectedThreat.severity.toLowerCase()}`}>{selectedThreat.severity}</span> ({selectedThreat.score} / 100)</p>
                      </div>
                      <div className="modal-field">
                        <label>Raw Payload Content:</label>
                        <pre className="raw-box">{selectedThreat.body}</pre>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ========================================================
              TAB 3: COMPLIANCE VIEW
             ======================================================== */}
          {active === "Compliance" && (
            <div className="compliance-workspace">
              <Panel
                title="National Cybersecurity Framework Readiness"
                extra={<span className="readiness-tag">REGULATORY AUDIT</span>}
              >
                <div className="readiness-header-card">
                  <div className="readiness-score">
                    <strong>{compliance ? compliance.score : 0}<span>%</span></strong>
                    <span>{compliance ? `${compliance.met}/${compliance.total} obligations satisfied` : "Auditing..."}</span>
                  </div>
                  <div className="progress-track" style={{ height: "14px", flex: 1 }}>
                    <div style={{ width: `${compliance ? compliance.score : 0}%` }} />
                  </div>
                </div>

                <div className="compliance-grid-cards">
                  {compliance && compliance.items.length > 0 ? (
                    compliance.items.map((item, idx) => (
                      <div key={idx} className={`compliance-card ${item.isMet ? "border-green" : "border-amber"}`}>
                        <div className="card-top">
                          <span className={item.isMet ? "check-badge" : "pending-badge"}>
                            {item.isMet ? "COMPLIANT" : "ACTION REQUIRED"}
                          </span>
                          <span className="obligation-id">REQ-0{idx + 1}</span>
                        </div>
                        <h4>{item.title}</h4>
                        <p>{item.detail}</p>
                      </div>
                    ))
                  ) : (
                    <div>Auditing compliance obligations...</div>
                  )}
                </div>
              </Panel>
            </div>
          )}
        </div>

        <footer className="footer">
          <span>EthioSecure – Phish Watch</span>
          <span>Analyst Dashboard · Production Connected</span>
        </footer>
      </main>
    </div>
  );
}
