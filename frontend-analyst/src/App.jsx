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
  const [complianceLoading, setComplianceLoading] = useState(false);
  const [complianceError, setComplianceError] = useState("");
  const [assessments, setAssessments] = useState([]);
  const [assessmentDraft, setAssessmentDraft] = useState({ duty_id: "", status: "not_fulfilled", evidence_note: "", responsible: "", target_date: "" });
  const [assessmentSaving, setAssessmentSaving] = useState(false);
  const [assessmentMessage, setAssessmentMessage] = useState("");
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
            source: r.link || r.attachment_filename || "No embedded URL or attachment",
            link: r.link || "",
            body: r.message_body || "No message body captured",
            severity: (r.severity || "Low").charAt(0).toUpperCase() + (r.severity || "Low").slice(1),
            status: (r.status || "new").toLowerCase(),
            score: r.risk_score ?? 0,
            reasons: Array.isArray(r.reasons) ? r.reasons : [],
            attachmentFilename: r.attachment_filename || "",
            reportSource: r.source || "unknown",
          };
        });
        setThreats(formatted);
      })
      .catch((err) => console.error("Reports fetch error:", err))
      .finally(() => setLoading(false));
  };

  const loadCompliance = async () => {
    setComplianceLoading(true);
    setComplianceError("");
    try {
      const response = await fetch("/compliance-status");
      if (!response.ok) throw new Error(`Compliance service returned ${response.status}.`);
      const data = await response.json();
      const obligations = Array.isArray(data.obligations) ? data.obligations : [];
      const statuses = Array.isArray(data.statuses) ? data.statuses : [];
      const items = obligations.map((obligation) => {
        const result = statuses.find((status) => status.obligation_id === obligation.id);
        const normalizedStatus = String(result?.status || "unavailable").toLowerCase();
        return {
          id: obligation.id,
          title: obligation.title || "Unnamed obligation",
          status: normalizedStatus,
          detail: result?.detail || obligation.description || "No assessment detail was provided.",
        };
      });
      const total = items.length;
      const met = items.filter((item) => item.status === "met").length;
      const atRisk = items.filter((item) => item.status === "at risk").length;
      const unmet = items.filter((item) => item.status === "unmet").length;
      setCompliance({
        score: total ? Math.round((met / total) * 100) : 0,
        items,
        total,
        met,
        atRisk,
        unmet,
      });
    } catch (err) {
      setComplianceError(err.message || "Could not load compliance readiness.");
      console.error("Compliance fetch error:", err);
    } finally {
      setComplianceLoading(false);
    }
  };

  const loadAssessments = async () => {
    try {
      const response = await fetch("/compliance-assessments");
      if (!response.ok) throw new Error(`Manual assessment service returned ${response.status}.`);
      const rows = await response.json();
      if (!Array.isArray(rows)) throw new Error("Manual assessment response was not a list.");
      setAssessments(rows);
    } catch (err) {
      setAssessmentMessage(err.message || "Could not load manual assessments.");
    }
  };

  const saveAssessment = async (assessment) => {
    setAssessmentSaving(true);
    setAssessmentMessage("");
    try {
      const response = await fetch("/compliance-assessments", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...assessment,
          target_date: assessment.target_date || null,
          evidence_note: assessment.evidence_note || null,
          responsible: assessment.responsible || null,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || `Save failed (${response.status}).`);
      setAssessmentMessage(`Saved assessment ${result.duty_id}.`);
      await loadAssessments();
      return true;
    } catch (err) {
      setAssessmentMessage(err.message || "Could not save the assessment.");
      return false;
    } finally {
      setAssessmentSaving(false);
    }
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
    loadAssessments();
  }, []);

  const visibleThreats = threats.filter((threat) =>
    `${threat.type} ${threat.sender} ${threat.source} ${threat.severity} ${threat.status} ${threat.reasons.join(" ")}`
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
  const statusReview = threats.filter((t) => t.status === "investigating").length;
  const statusMitigated = threats.filter((t) => t.status === "resolved").length;

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
            <button className="outline-button" onClick={() => { setSearch(""); loadReports(); loadCompliance(); loadAssessments(); }}>
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
                        <span className="step-tag">Investigating</span>
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
                        <th>LINK / ATTACHMENT</th>
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
                              <option value="investigating">Investigating</option>
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
                        <label>Report source:</label>
                        <p>{selectedThreat.reportSource}</p>
                      </div>
                      <div className="modal-field">
                        <label>Suspicious Link:</label>
                        <p><code className="code-pill">{selectedThreat.link || "No separate link field recorded; check the message body and detection reasons."}</code></p>
                      </div>
                      {selectedThreat.attachmentFilename && (
                        <div className="modal-field">
                          <label>Attachment:</label>
                          <p>{selectedThreat.attachmentFilename}</p>
                        </div>
                      )}
                      <div className="modal-field">
                        <label>Risk Score & Severity:</label>
                        <p><span className={`severity ${selectedThreat.severity.toLowerCase()}`}>{selectedThreat.severity}</span> ({selectedThreat.score} / 100)</p>
                      </div>
                      <div className="modal-field">
                        <label>Raw Payload Content:</label>
                        <pre className="raw-box">{selectedThreat.body}</pre>
                      </div>
                      <div className="modal-field">
                        <label>Detection reasons and coverage:</label>
                        {selectedThreat.reasons.length > 0 ? (
                          <ul className="reason-list">
                            {selectedThreat.reasons.map((reason, index) => (
                              <li key={`${index}-${reason}`}>{reason}</li>
                            ))}
                          </ul>
                        ) : (
                          <p>No detection reasons were returned for this report.</p>
                        )}
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
                title="Compliance Readiness"
                extra={<span className="readiness-tag">REPORT-BASED CHECKS</span>}
              >
                <p className="readiness-scope-note">
                  Report based checks and analyst entered INSA assessments are shown separately. Enter the duty ID used by your INSA policy checklist.
                </p>
                {complianceError && (
                  <div className="readiness-error" role="alert">
                    {complianceError} Use “Refresh Data” to try again.
                  </div>
                )}
                <div className="readiness-header-card">
                  <div className="readiness-score">
                    <strong>{compliance ? compliance.score : "—"}<span>{compliance ? "%" : ""}</span></strong>
                    <span>{complianceLoading ? "Refreshing checks…" : compliance ? `${compliance.met}/${compliance.total} checks met` : "Waiting for compliance data"}</span>
                  </div>
                  <div
                    className="progress-track"
                    role="progressbar"
                    aria-label="Report-based compliance checks met"
                    aria-valuemin="0"
                    aria-valuemax="100"
                    aria-valuenow={compliance?.score ?? 0}
                    style={{ height: "14px", flex: 1 }}
                  >
                    <div style={{ width: `${compliance?.score ?? 0}%` }} />
                  </div>
                </div>

                {compliance && (
                  <div className="readiness-status-summary" aria-label="Compliance check totals">
                    <span className="readiness-count met">Met: {compliance.met}</span>
                    <span className="readiness-count at-risk">At risk: {compliance.atRisk}</span>
                    <span className="readiness-count unmet">Unmet: {compliance.unmet}</span>
                  </div>
                )}

                <div className="compliance-grid-cards">
                  {complianceLoading && !compliance ? (
                    <div>Loading compliance checks…</div>
                  ) : compliance && compliance.items.length > 0 ? (
                    compliance.items.map((item, idx) => (
                      <div key={item.id || idx} className={`compliance-card ${item.status === "met" ? "border-green" : item.status === "at risk" ? "border-risk" : "border-amber"}`}>
                        <div className="card-top">
                          <span className={`compliance-status-badge ${item.status === "met" ? "is-met" : item.status === "at risk" ? "is-at-risk" : "is-unmet"}`}>
                            {item.status === "met" ? "MET" : item.status === "at risk" ? "AT RISK" : item.status === "unmet" ? "UNMET" : "UNAVAILABLE"}
                          </span>
                          <span className="obligation-id">{item.id || `REQ-0${idx + 1}`}</span>
                        </div>
                        <h4>{item.title}</h4>
                        <p>{item.detail}</p>
                      </div>
                    ))
                  ) : (
                    <div>{complianceError ? "Compliance checks could not be loaded." : "No report-based compliance checks were returned."}</div>
                  )}
                </div>
              </Panel>
              <Panel title="Manual INSA Assessments" extra={<span className="readiness-tag">SAVED TO DATABASE</span>}>
                {assessmentMessage && <div className={assessmentMessage.startsWith("Saved ") ? "assessment-message success" : "assessment-message"} role="status">{assessmentMessage}</div>}
                <form className="assessment-form" onSubmit={async (event) => {
                  event.preventDefault();
                  if (await saveAssessment(assessmentDraft)) setAssessmentDraft({ duty_id: "", status: "not_fulfilled", evidence_note: "", responsible: "", target_date: "" });
                }}>
                  <label>INSA duty ID<input required maxLength="255" value={assessmentDraft.duty_id} onChange={(event) => setAssessmentDraft({ ...assessmentDraft, duty_id: event.target.value })} placeholder="For example, use the ID from your policy checklist" /></label>
                  <label>Status<select value={assessmentDraft.status} onChange={(event) => setAssessmentDraft({ ...assessmentDraft, status: event.target.value })}><option value="fulfilled">Fulfilled</option><option value="in_progress">In progress</option><option value="not_fulfilled">Not fulfilled</option></select></label>
                  <label>Responsible<input maxLength="255" value={assessmentDraft.responsible} onChange={(event) => setAssessmentDraft({ ...assessmentDraft, responsible: event.target.value })} /></label>
                  <label>Target date<input type="date" value={assessmentDraft.target_date} onChange={(event) => setAssessmentDraft({ ...assessmentDraft, target_date: event.target.value })} /></label>
                  <label className="assessment-evidence">Evidence note<textarea rows="3" value={assessmentDraft.evidence_note} onChange={(event) => setAssessmentDraft({ ...assessmentDraft, evidence_note: event.target.value })} /></label>
                  <button className="assessment-save" type="submit" disabled={assessmentSaving}>{assessmentSaving ? "Saving…" : "Save assessment"}</button>
                </form>
                <div className="assessment-list">
                  {assessments.length === 0 ? <p>No manual assessments have been saved yet.</p> : assessments.map((item) => (
                    <form className="assessment-row" key={item.duty_id} onSubmit={(event) => { event.preventDefault(); saveAssessment(item); }}>
                      <strong>{item.duty_id}</strong>
                      <select aria-label={`Status for ${item.duty_id}`} value={item.status || "not_fulfilled"} onChange={(event) => setAssessments((previous) => previous.map((row) => row.duty_id === item.duty_id ? { ...row, status: event.target.value } : row))}><option value="fulfilled">Fulfilled</option><option value="in_progress">In progress</option><option value="not_fulfilled">Not fulfilled</option></select>
                      <input aria-label={`Responsible for ${item.duty_id}`} placeholder="Responsible" maxLength="255" value={item.responsible || ""} onChange={(event) => setAssessments((previous) => previous.map((row) => row.duty_id === item.duty_id ? { ...row, responsible: event.target.value } : row))} />
                      <input aria-label={`Target date for ${item.duty_id}`} type="date" value={item.target_date || ""} onChange={(event) => setAssessments((previous) => previous.map((row) => row.duty_id === item.duty_id ? { ...row, target_date: event.target.value } : row))} />
                      <textarea aria-label={`Evidence note for ${item.duty_id}`} rows="2" placeholder="Evidence note" value={item.evidence_note || ""} onChange={(event) => setAssessments((previous) => previous.map((row) => row.duty_id === item.duty_id ? { ...row, evidence_note: event.target.value } : row))} />
                      <button className="assessment-save" type="submit" disabled={assessmentSaving}>Save changes</button>
                    </form>
                  ))}
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
