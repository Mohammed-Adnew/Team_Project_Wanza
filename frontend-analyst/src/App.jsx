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
            source: r.sender_actual || r.sender_claimed || (r.link ? r.link : "Unknown source"),
            severity: (r.severity || "Low").charAt(0).toUpperCase() + (r.severity || "Low").slice(1),
            status: r.status || "new",
            score: r.risk_score ?? 0,
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
            detail: ob.description || "",
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
    `${threat.type} ${threat.source} ${threat.severity} ${threat.status}`
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  const pendingCount = threats.filter(
    (t) => t.status.toLowerCase() === "new" || t.status.toLowerCase() === "under review"
  ).length;
  const highRiskCount = threats.filter((t) => t.severity.toLowerCase() === "high").length;
  const medRiskCount = threats.filter((t) => t.severity.toLowerCase() === "medium").length;
  const lowRiskCount = threats.filter((t) => t.severity.toLowerCase() === "low").length;

  return (
    <div className={`dashboard ${menuOpen ? "nav-open" : ""}`}>
      {/* Mobile Backdrop */}
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
            <div className="breadcrumbs">EthioSecure <span>/</span> Analyst Portal</div>
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
              <h1>{active === "Overview" ? "Security Overview" : active}</h1>
              <p>Real-time threat feed and regulatory cybersecurity readiness audit.</p>
            </div>
            <button className="outline-button" onClick={() => { setSearch(""); loadReports(); loadCompliance(); }}>
              ↻ Refresh Data
            </button>
          </section>

          {/* Metric Grid */}
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
              <div className="metric-note">Actionable threats</div>
            </article>

            <article className="metric-card">
              <div className="metric-icon purple">⏳</div>
              <div className="metric-label">Triage Queue</div>
              <div className="metric-value">{pendingCount}</div>
              <div className="metric-note">Awaiting analyst action</div>
            </article>

            <article className="metric-card">
              <div className="metric-icon green">◇</div>
              <div className="metric-label">Compliance Readiness</div>
              <div className="metric-value">{compliance ? `${compliance.score}%` : "--"}</div>
              <div className="metric-note">{compliance ? `${compliance.met}/${compliance.total} obligations met` : "Auditing..."}</div>
            </article>
          </section>

          {/* Dynamic Visual Activity Chart */}
          {(active === "Overview" || active === "Phishing Analysis") && (
            <Panel
              title="Threat Telemetry & Severity Distribution"
              extra={<span className="table-count">{threats.length} total events</span>}
            >
              <div className="chart-container">
                <div className="chart-legend">
                  <span><i className="legend-red" /> High ({highRiskCount})</span>
                  <span><i className="legend-amber" /> Medium ({medRiskCount})</span>
                  <span><i className="legend-green" /> Low ({lowRiskCount})</span>
                </div>
                
                {/* Visual SVG Wave graph reflecting the active threat levels */}
                <div className="chart-wrapper">
                  <svg viewBox="0 0 700 140" preserveAspectRatio="none" className="telemetry-svg">
                    <defs>
                      <linearGradient id="cyberGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#2563eb" stopOpacity="0.4" />
                        <stop offset="100%" stopColor="#2563eb" stopOpacity="0.0" />
                      </linearGradient>
                    </defs>
                    <polygon
                      points={`0,120 100,${110 - lowRiskCount * 12} 250,${100 - medRiskCount * 15} 420,${90 - highRiskCount * 22} 550,${95 - threats.length * 8} 700,105 700,140 0,140`}
                      fill="url(#cyberGradient)"
                    />
                    <polyline
                      points={`0,120 100,${110 - lowRiskCount * 12} 250,${100 - medRiskCount * 15} 420,${90 - highRiskCount * 22} 550,${95 - threats.length * 8} 700,105`}
                      fill="none"
                      stroke="#2563eb"
                      strokeWidth="3"
                    />
                  </svg>
                  <div className="chart-x-labels">
                    <span>Baseline</span>
                    <span>Low Risk</span>
                    <span>Medium Risk</span>
                    <span>High Risk</span>
                    <span>Active Queue</span>
                    <span>Normalized</span>
                  </div>
                </div>
              </div>
            </Panel>
          )}

          <div className="main-grid">
            <div className="column">
              {(active === "Overview" || active === "Phishing Analysis") && (
                <Panel
                  title="Live Phishing Feed"
                  id="feed"
                  extra={<span className="table-count">{visibleThreats.length} records</span>}
                >
                  <div className="table-toolbar">
                    <label className="search-box">
                      <span>⌕</span>
                      <input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Filter by subject, sender, severity..."
                        aria-label="Filter threat records"
                      />
                    </label>
                    {search && <button className="text-button" onClick={() => setSearch("")}>Clear</button>}
                  </div>

                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>THREAT / SOURCE</th>
                          <th>SEVERITY</th>
                          <th>STATUS (TRIAGE)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleThreats.map((threat) => (
                          <tr key={threat.id}>
                            <td>
                              <strong className="threat-name">{threat.type}</strong>
                              <small className="threat-source">{threat.source}</small>
                              <small className="threat-date">{threat.date}</small>
                            </td>
                            <td>
                              <span className={`severity ${threat.severity.toLowerCase()}`}>
                                {threat.severity}
                              </span>
                            </td>
                            <td>
                              <select
                                className="status-select"
                                value={threat.status.toLowerCase()}
                                onChange={(e) => handleStatusChange(threat.id, e.target.value)}
                              >
                                <option value="new">New</option>
                                <option value="under review">Under Review</option>
                                <option value="blocked">Blocked</option>
                                <option value="resolved">Resolved</option>
                              </select>
                            </td>
                          </tr>
                        ))}
                        {visibleThreats.length === 0 && !loading && (
                          <tr>
                            <td colSpan="3" className="empty-row">
                              No reports match your filter criteria.
                            </td>
                          </tr>
                        )}
                        {loading && (
                          <tr>
                            <td colSpan="3" className="empty-row">
                              Loading live reports from database...
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  <div className="table-footnote">
                    ● Real-time sync with PostgreSQL via Render API
                  </div>
                </Panel>
              )}
            </div>

            <div className="column">
              {(active === "Overview" || active === "Compliance") && (
                <Panel
                  title="Compliance Obligations"
                  id="compliance"
                  extra={<span className="readiness-tag">LIVE AUDIT</span>}
                >
                  <div className="readiness-score">
                    <strong>{compliance ? compliance.score : 0}<span>%</span></strong>
                    <span>{compliance ? `${compliance.met}/${compliance.total} obligations met` : "Auditing..."}</span>
                  </div>
                  <div className="progress-track">
                    <div style={{ width: `${compliance ? compliance.score : 0}%` }} />
                  </div>
                  <div className="compliance-list">
                    {compliance && compliance.items.length > 0 ? (
                      compliance.items.map((item, idx) => (
                        <div key={idx} title={item.detail}>
                          <span className={item.isMet ? "check" : "pending-dot"}>
                            {item.isMet ? "✓" : "•"}
                          </span>
                          <span>{item.title}</span>
                          <span className={item.isMet ? "complete" : "in-progress"}>
                            {item.isMet ? "Met" : "Unmet"}
                          </span>
                        </div>
                      ))
                    ) : (
                      <div><span>Auditing compliance records...</span></div>
                    )}
                  </div>
                </Panel>
              )}

              <Panel title="System Diagnostics">
                <div className="diagnostics-box">
                  <p><strong>API Gateway:</strong> Render Web Service</p>
                  <p><strong>Database:</strong> Neon PostgreSQL (Active)</p>
                  <p><strong>Pipeline:</strong> Direct Heuristic + Risk Model</p>
                </div>
              </Panel>
            </div>
          </div>
        </div>

        <footer className="footer">
          <span>EthioSecure – Phish Watch</span>
          <span>Analyst Dashboard · Production Connected</span>
        </footer>
      </main>
    </div>
  );
}
