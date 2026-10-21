"""
Compliance readiness: checks saved reports against a small set of obligations.

This module is pure logic. It receives a list of report dictionaries (the same
shape GET /reports returns) and never touches the database.
Obligations 1-3 were written by the Database role; 4-5 were added by Backend.
"""

from datetime import datetime, timedelta, timezone

RESPONSE_WINDOW_HOURS = 48
MONITORING_WINDOW_DAYS = 30
VALID_SEVERITIES = {"high", "medium", "low"}

# Article 7 of Ethiopia's Critical Infrastructure Cybersecurity Proclamation
# No. 1426/2026 lists 18 duties for owners of designated critical infrastructure.
# This catalog is an evidence-tracking aid, not a legal applicability decision.
INSA_DUTIES = [
    ("insa_01", "Develop a cybersecurity program", "Develop the institution's cybersecurity program using national cybersecurity frameworks.", "Approved program, owner, scope, and review date."),
    ("insa_02", "Implement mandatory cybersecurity frameworks", "Implement the mandatory cybersecurity frameworks issued or recognized by INSA.", "Framework mapping, implementation records, and gaps."),
    ("insa_03", "Maintain an institutional cybersecurity framework", "Develop and implement an institutional framework consistent with applicable laws, policies, and INSA technical policies.", "Approved framework, control mapping, and version history."),
    ("insa_04", "Classify and protect critical assets", "Classify and protect assets according to applicable INSA standards.", "Asset inventory, classification criteria, and safeguards."),
    ("insa_05", "Conduct regular cyber risk and impact assessments", "Assess cybersecurity risks and impacts regularly under the system established by INSA.", "Dated risk register, impact analysis, treatment owners, and review cycle."),
    ("insa_06", "Participate in the national cyber risk survey", "Participate in INSA's annual national cybersecurity risk survey and provide relevant information.", "Submission records and correspondence."),
    ("insa_07", "Maintain cyber audit and evaluation certification", "Obtain, maintain, and renew the required cyber audit and cybersecurity inspection/evaluation certificate.", "Certificate, scope, issue/expiry dates, and audit report."),
    ("insa_08", "Remediate audit and assessment findings", "Complete corrective actions for audit and inspection findings within the prescribed time.", "Findings register, remediation evidence, and closure approvals."),
    ("insa_09", "Establish cybersecurity governance", "Create the cybersecurity organizational structure required by the national framework.", "Organization chart, mandates, escalation path, and meeting records."),
    ("insa_10", "Employ qualified cybersecurity professionals", "Employ cybersecurity professionals with INSA-issued or recognized certifications, and arrange certification for existing staff as required.", "Role assignments, certification evidence, and staffing plan."),
    ("insa_11", "Secure the technology supply chain", "Ensure the security of the supply chain for technology products in use.", "Supplier inventory, due diligence, security clauses, and risk reviews."),
    ("insa_12", "Obtain security clearance before integration", "Obtain required security clearance for new or upgraded ICT systems before integrating them.", "System change records and applicable clearance approvals."),
    ("insa_13", "Operate incident monitoring and response capability", "Establish and manage a center responsible for monitoring, reporting, and responding to cyber attacks under the applicable framework.", "SOC/center mandate, coverage, operating procedures, and response records."),
    ("insa_14", "Notify and respond to incidents within 48 hours", "Notify the National Computer Emergency Response Center of cyber incidents within 48 hours and implement its applicable directions.", "Incident timeline, notification receipt, and corrective-action evidence."),
    ("insa_15", "Exchange information with INSA", "Periodically exchange required information using the information exchange system established by INSA.", "Exchange schedule, submissions, and acknowledgements."),
    ("insa_16", "Run cybersecurity exercises and training", "Develop and implement cybersecurity exercises and training, and participate in those facilitated by INSA.", "Training/exercise plan, attendance, results, and follow-up actions."),
    ("insa_17", "Obtain required personnel security clearances", "Ensure staff or officials with access to critical infrastructure assets obtain security clearance from the relevant government body.", "Access-role list and clearance records, handled with appropriate confidentiality."),
    ("insa_18", "Enforce cybersecurity professional ethics", "Ensure compliance with the professional ethics required for cybersecurity work.", "Applicable code of ethics, acknowledgement records, and enforcement process."),
]


def build_insa_assessments(saved_rows):
    """Join the fixed Article 7 catalog to saved evidence/status records."""
    saved = {row.get("duty_id"): row for row in (saved_rows or [])}
    results = []
    for duty_id, title, description, evidence_guidance in INSA_DUTIES:
        row = saved.get(duty_id, {})
        status = row.get("status")
        status_map = {"fulfilled": "met", "in_progress": "at risk", "not_fulfilled": "unmet"}
        results.append({
            "id": duty_id,
            "title": title,
            "description": description,
            "evidence_guidance": evidence_guidance,
            "status": status_map.get(status, "not assessed"),
            "assessment_status": status or "not_assessed",
            "evidence_note": row.get("evidence_note") or "",
            "responsible": row.get("responsible") or "",
            "target_date": row.get("target_date"),
            "updated_at": row.get("updated_at"),
        })
    return results

COMPLIANCE_OBLIGATIONS = [
    {
        "id": "obl_1",
        "title": "Timely Incident Logging",
        "description": "All reported phishing incidents must be logged with valid timestamps.",
    },
    {
        "id": "obl_2",
        "title": "Severity Classification",
        "description": "Every security report must have a defined severity level (High, Medium, Low).",
    },
    {
        "id": "obl_3",
        "title": "Automated and Manual Source Tracking",
        "description": "Reports must clearly indicate whether they originated from automated scans or manual employee reports.",
    },
    {
        "id": "obl_4",
        "title": "Incident Response Within 48 Hours",
        "description": "High-severity incidents must be resolved within 48 hours of being reported.",
    },
    {
        "id": "obl_5",
        "title": "Active Monitoring",
        "description": "Automated scanning must have produced reports within the last 30 days.",
    },
]


def _to_naive_utc(value):
    """Turns an ISO timestamp string or a datetime into a naive UTC datetime. None if missing or invalid."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _check_logging(reports):
    """Obligation 1: every report has a valid timestamp."""
    missing = [r for r in reports if _to_naive_utc(r.get("created_at") or r.get("timestamp")) is None]
    if missing:
        return "unmet", f"{len(missing)} of {len(reports)} report(s) have no valid timestamp."
    return "met", f"All {len(reports)} report(s) have a valid timestamp." if reports else "No reports yet."


def _check_severity(reports):
    """Obligation 2: every report has a severity of high, medium or low."""
    missing = [r for r in reports if str(r.get("severity") or "").lower() not in VALID_SEVERITIES]
    if missing:
        return "at risk", f"{len(missing)} of {len(reports)} report(s) have no valid severity."
    return "met", f"All {len(reports)} report(s) have a severity." if reports else "No reports yet."


def _check_source(reports):
    """Obligation 3: every report says whether it was automatic or reported by an employee."""
    missing = [r for r in reports if not r.get("source")]
    if missing:
        return "unmet", f"{len(missing)} of {len(reports)} report(s) have no source."
    return "met", f"All {len(reports)} report(s) have a source." if reports else "No reports yet."


def _check_response_time(reports, now):
    """Obligation 4: high-severity reports are resolved within 48 hours."""
    limit = timedelta(hours=RESPONSE_WINDOW_HOURS)
    high = 0
    overdue = 0
    for r in reports:
        if str(r.get("severity") or "").lower() != "high":
            continue
        high += 1
        created = _to_naive_utc(r.get("created_at"))
        if created is None:
            continue  # obligation 1 reports missing timestamps
        resolved = _to_naive_utc(r.get("resolved_at"))
        if resolved is None and str(r.get("status") or "").lower() == "resolved":
            continue  # closed, but the closing time was never recorded, so it can't be judged
        if (resolved or now) - created > limit:
            overdue += 1
    if overdue:
        return "at risk", f"{overdue} of {high} high-severity report(s) were not resolved within 48 hours."
    if high:
        return "met", f"All {high} high-severity report(s) are within the 48-hour window."
    return "met", "No high-severity reports yet."


def _check_monitoring(reports, now):
    """Obligation 5: automatic scanning produced reports in the last 30 days."""
    cutoff = now - timedelta(days=MONITORING_WINDOW_DAYS)
    recent = [
        r for r in reports
        if str(r.get("source") or "").lower() == "automatic"
        and (_to_naive_utc(r.get("created_at")) or datetime.min) >= cutoff
    ]
    if recent:
        return "met", f"{len(recent)} automatic report(s) in the last {MONITORING_WINDOW_DAYS} days."
    return "unmet", f"No automatic scan results in the last {MONITORING_WINDOW_DAYS} days."


def evaluate_compliance_status(reports, now=None):
    """
    Returns one status per obligation:
        [{"obligation_id": "obl_1", "status": "met" | "unmet" | "at risk", "detail": "..."}, ...]
    `now` is only for testing; it defaults to the current time (UTC).
    """
    reports = reports or []
    now = _to_naive_utc(now) if now else datetime.now(timezone.utc).replace(tzinfo=None)

    checks = [
        ("obl_1", _check_logging(reports)),
        ("obl_2", _check_severity(reports)),
        ("obl_3", _check_source(reports)),
        ("obl_4", _check_response_time(reports, now)),
        ("obl_5", _check_monitoring(reports, now)),
    ]
    return [
        {"obligation_id": obligation_id, "status": status, "detail": detail}
        for obligation_id, (status, detail) in checks
    ]
