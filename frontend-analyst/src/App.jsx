
import { useState, useEffect } from "react";
import "./styles/dashboard.css";

const initialThreats = [
  { id: 1, date: "Oct 14, 2026 · 08:32", type: "Phishing link", source: "suspicious-link.example", severity: "High", status: "Blocked" },
  { id: 2, date: "Oct 14, 2026 · 07:15", type: "Fake login page", source: "account-check.example", severity: "High", status: "Under review" },
  { id: 3, date: "Oct 13, 2026 · 16:42", type: "Suspicious attachment", source: "invoice-demo.exe", severity: "Medium", status: "Quarantined" },
  { id: 4, date: "Oct 13, 2026 · 11:20", type: "Phishing link", source: "verify-user.example", severity: "Medium", status: "Blocked" },
  { id: 5, date: "Oct 12, 2026 · 09:03", type: "Fake login page", source: "secure-access.example", severity: "Low", status: "Resolved" },
];

const navItems = [
  { icon: "▦", label: "Overview" },
  { icon: "⌁", label: "Phishing Analysis" },
  { icon: "◇", label: "Compliance" },
  { icon: "▤", label: "Reports" },
  { icon: "◈", label: "Assets & Risk" },
];

const metrics = [
  { label: "Scan requests", value: "248", note: "Illustrative total", icon: "⌕", color: "blue" },
  { label: "Threats detected", value: "17", note: "Illustrative total", icon: "⚠", color: "red" },
  { label: "Compliance readiness", value: "86%", note: "Demo assessment", icon: "◇", color: "green" },
  { label: "Monitored assets", value: "12", note: "Sample inventory", icon: "▣", color: "purple" },
];

function Panel({ title, extra, children }) {
  return (
    <section className="panel">
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
  const [period, setPeriod] = useState("7 days");
  const [notice, setNotice] = useState("");
  const [compliance, setCompliance] = useState(null);
  const [threats, setThreats] = useState([]);

  const loadReports = () => {
    fetch("/reports")
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => {
        if (!Array.isArray(data) || data.length === 0) return;
        const formatted = data.map((r) => {
          const dateStr = r.created_at ? new Date(r.created_at).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "Recent";
          return {
            id: r.id,
            date: dateStr,
            type: r.subject || "Reported Email",
            source: r.sender_actual || r.sender_claimed || (r.link ? r.link : "Unknown source"),
            severity: (r.severity || "Low").charAt(0).toUpperCase() + (r.severity || "Low").slice(1),
            status: (r.status || "new").charAt(0).toUpperCase() + (r.status || "new").slice(1),
          };
        });
        setThreats(formatted);
      })
      .catch((err) => console.error("Reports fetch error:", err));
  };

  useEffect(() => {
    loadReports();
    fetch("/compliance-status")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!data) return;
        const total = data.statuses ? data.statuses.length : 0;
        const met = data.statuses ? data.statuses.filter((s) => s.status === "met").length : 0;
        const score = total > 0 ? Math.round((met / total) * 100) : 0;
        const items = (data.obligations || []).map((ob) => {
          const st = (data.statuses || []).find((s) => s.obligation_id === ob.id);
          return {
            title: ob.title,
            isMet: st ? st.status === "met" : false,
            detail: st ? st.detail : "",
          };
        });
        setCompliance({ score, items, total, met });
      })
      .catch((err) => console.error("Compliance fetch error:", err));
  }, []);

  const currentThreatsList = threats.length > 0 ? threats : initialThreats;
  const visibleThreats = currentThreatsList.filter((threat) =>
    `${threat.type} ${threat.source} ${threat.severity} ${threat.status}`
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  function chooseSection(label) {
    setActive(label);
    setNotice(
      label === "Overview"
        ? ""
        : `${label} selected. This section is a visual prototype and is not connected to the backend yet.`
    );
  }

  return (
    <div className="dashboard">
      <aside className="sidebar">
        <a className="brand" href="#overview" onClick={() => chooseSection("Overview")}>
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
              onClick={() => chooseSection(item.label)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
              {item.label === "Phishing Analysis" && <span className="nav-count">5</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="status-indicator"><span /> DEMO ENVIRONMENT</div>
          <p>Building a safer digital Ethiopia.</p>
          <div className="sidebar-version">PHISH WATCH · ANALYST PORTAL</div>
        </div>
      </aside>

      <main className="main-area" id="overview">
        <header className="topbar">
          <div className="breadcrumbs">EthioSecure <span>/</span> Analyst Portal</div>
          <div className="topbar-right">
            <span className="demo-pill"><span /> Sample data</span>
            <div className="user-avatar">SA</div>
            <div className="user-label"><strong>Security Analyst</strong><small>Analyst workspace</small></div>
          </div>
        </header>

        <div className="content">
          <section className="page-intro">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS</div>
              <h1>{active === "Overview" ? "Security Overview" : active}</h1>
              <p>Monitor phishing activity and review cybersecurity readiness.</p>
            </div>
            <button className="outline-button" onClick={() => { setSearch(""); setPeriod("7 days"); setNotice("Dashboard filters have been reset."); }}>
              ↻ Reset view
            </button>
          </section>

          {notice && (
            <div className="notice" role="status">
              <span>{notice}</span>
              <button onClick={() => setNotice("")} aria-label="Dismiss message">×</button>
            </div>
          )}

          <div className="demo-banner">
            <span className="banner-icon">i</span>
            <p><strong>Prototype mode.</strong> All numbers, alerts, and dates below are illustrative sample data. Live backend integration has not been configured.</p>
          </div>

          <section className="metric-grid" aria-label="Security metrics">
            {metrics.map((metric) => {
              const isComp = metric.label === "Compliance readiness";
              const isThreat = metric.label === "Threats detected";
              let displayVal = metric.value;
              let displayNote = metric.note;

              if (isComp && compliance) {
                displayVal = `${compliance.score}%`;
                displayNote = `${compliance.met}/${compliance.total} obligations met`;
              } else if (isThreat && threats.length > 0) {
                displayVal = `${threats.length}`;
                displayNote = "Live database total";
              }
              return (
                <article className="metric-card" key={metric.label}>
                  <div className={`metric-icon ${metric.color}`}>{metric.icon}</div>
                  <div className="metric-label">{metric.label}</div>
                  <div className="metric-value">{displayVal}</div>
                  <div className="metric-note">{displayNote}</div>
                </article>
              );
            })}
          </section>

          <div className="main-grid">
            <div className="column">
              <Panel
                title="Threat activity"
                extra={
                  <select className="period-select" value={period} onChange={(event) => setPeriod(event.target.value)} aria-label="Chart period">
                    <option value="7 days">Last 7 days</option>
                    <option value="30 days">Last 30 days</option>
                  </select>
                }
              >
                <div className="chart-legend">
                  <span><i className="legend-blue" /> Detected</span>
                  <span><i className="legend-green" /> Blocked</span>
                  <span className="chart-demo-label">Illustrative trend</span>
                </div>
                <div className="chart-area">
                  <div className="chart-y-axis"><span>50</span><span>40</span><span>30</span><span>20</span><span>10</span><span>0</span></div>
                  <div className="chart-plot">
                    {[0, 1, 2, 3, 4, 5].map((line) => <div className="chart-grid-line" key={line} />)}
                    <svg viewBox="0 0 600 200" preserveAspectRatio="none" role="img" aria-label={`Illustrative threat activity over ${period}`}>
                      <defs>
                        <linearGradient id="areaBlue" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#4389f5" stopOpacity=".22" /><stop offset="100%" stopColor="#4389f5" stopOpacity="0" /></linearGradient>
                        <linearGradient id="areaGreen" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#12b981" stopOpacity=".16" /><stop offset="100%" stopColor="#12b981" stopOpacity="0" /></linearGradient>
                      </defs>
                      <polygon points="0,150 100,122 200,135 300,62 400,94 500,80 600,42 600,200 0,200" fill="url(#areaBlue)" />
                      <polyline points="0,150 100,122 200,135 300,62 400,94 500,80 600,42" fill="none" stroke="#4389f5" strokeWidth="3" vectorEffect="non-scaling-stroke" />
                      <polygon points="0,174 100,156 200,165 300,132 400,158 500,141 600,115 600,200 0,200" fill="url(#areaGreen)" />
                      <polyline points="0,174 100,156 200,165 300,132 400,158 500,141 600,115" fill="none" stroke="#12b981" strokeWidth="3" vectorEffect="non-scaling-stroke" />
                    </svg>
                    <div className="chart-x-axis">
                      {(period === "7 days" ? ["Oct 8", "Oct 9", "Oct 10", "Oct 11", "Oct 12", "Oct 13", "Oct 14"] : ["Week 1", "Week 2", "Week 3", "Week 4", "Week 5", "Week 6", "Week 7"]).map((day) => <span key={day}>{day}</span>)}
                    </div>
                  </div>
                </div>
              </Panel>

              <Panel title="Recent phishing alerts" extra={<span className="table-count">{visibleThreats.length} records</span>}>
                <div className="table-toolbar">
                  <label className="search-box">
                    <span>⌕</span>
                    <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search threats, source, status..." aria-label="Search threat records" />
                  </label>
                  <button className="text-button" onClick={() => setSearch("")}>Clear</button>
                </div>
                <div className="table-scroll">
                  <table>
                    <thead><tr><th>THREAT / SOURCE</th><th>SEVERITY</th><th>STATUS</th></tr></thead>
                    <tbody>
                      {visibleThreats.map((threat) => (
                        <tr key={threat.id}>
                          <td><strong className="threat-name">{threat.type}</strong><small className="threat-source">{threat.source}</small><small className="threat-date">{threat.date}</small></td>
                          <td><span className={`severity ${threat.severity.toLowerCase()}`}>{threat.severity}</span></td>
                          <td><span className={`status status-${threat.status.toLowerCase().replace(" ", "-")}`}>{threat.status}</span></td>
                        </tr>
                      ))}
                      {visibleThreats.length === 0 && <tr><td colSpan="3" className="empty-row">No matching records. Try another search.</td></tr>}
                    </tbody>
                  </table>
                </div>
                <div className="table-footnote">{threats.length > 0 ? "Live reports synchronized with PostgreSQL" : "Sample records only · No live security events"}</div>
              </Panel>
            </div>

            <div className="column">
              <Panel title="Threat categories" extra={<span className="muted-tag">DEMO</span>}>
                <div className="donut-layout">
                  <div className="donut-chart"><div><strong>17</strong><small>Threats</small></div></div>
                  <div className="donut-legend">
                    <div><i className="dot dot-blue" /><span>Phishing links</span><strong>9</strong></div>
                    <div><i className="dot dot-orange" /><span>Fake login pages</span><strong>4</strong></div>
                    <div><i className="dot dot-purple" /><span>Attachments</span><strong>2</strong></div>
                    <div><i className="dot dot-gray" /><span>Other</span><strong>2</strong></div>
                  </div>
                </div>
              </Panel>

              <Panel title="Compliance readiness" extra={<span className="readiness-tag">{compliance ? "LIVE AUDIT" : "DEMO SCORE"}</span>}>
                <div className="readiness-score">
                  <strong>{compliance ? compliance.score : 86}<span>%</span></strong>
                  <span>{compliance ? `${compliance.met}/${compliance.total} obligations met` : "Illustrative score"}</span>
                </div>
                <div className="progress-track">
                  <div style={{ width: `${compliance ? compliance.score : 86}%` }} />
                </div>
                <div className="compliance-list">
                  {compliance && compliance.items.length > 0 ? (
                    compliance.items.map((item, idx) => (
                      <div key={idx} title={item.detail}>
                        <span className={item.isMet ? "check" : "pending-dot"}>{item.isMet ? "✓" : "•"}</span>
                        <span>{item.title}</span>
                        <span className={item.isMet ? "complete" : "in-progress"}>{item.isMet ? "Met" : "Unmet"}</span>
                      </div>
                    ))
                  ) : (
                    <>
                      <div><span className="check">✓</span><span>Data protection</span><span className="complete">Sample</span></div>
                      <div><span className="check">✓</span><span>Access controls</span><span className="complete">Sample</span></div>
                      <div><span className="pending-dot" /><span>Incident response</span><span className="in-progress">Sample</span></div>
                      <div><span className="check">✓</span><span>User awareness</span><span className="complete">Sample</span></div>
                    </>
                  )}
                </div>
              </Panel>

              <Panel title="Quick actions">
                <div className="quick-actions">
                  <button onClick={() => chooseSection("Phishing Analysis")}><span>⌕</span><span><strong>Review phishing</strong><small>Inspect reported threats</small></span><b>↗</b></button>
                  <button onClick={() => chooseSection("Compliance")}><span>◇</span><span><strong>View compliance</strong><small>Review readiness items</small></span><b>↗</b></button>
                  <button onClick={() => chooseSection("Reports")}><span>▤</span><span><strong>Open reports</strong><small>Explore activity summaries</small></span><b>↗</b></button>
                </div>
              </Panel>
              <div className="help-card"><span>✳</span><div><strong>Stay security-aware</strong><p>Review suspicious reports carefully. Sample records do not represent real threats.</p></div></div>
            </div>
          </div>
        </div>

        <footer className="footer">
          <span>EthioSecure – Phish Watch</span>
          <span>Analyst dashboard prototype · Sample data only</span>
        </footer>
      </main>
    </div>
  );
}

