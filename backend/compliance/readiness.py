"""
Compliance readiness against the Critical Infrastructure Cybersecurity Proclamation No. 1426/2026.

Art. 7 lists 18 duties of a critical infrastructure owner. This module tracks how many of them the
organization fulfills. Two kinds of evidence are kept apart:
  - "automatic" duties are computed from PhishWatch data (Art. 7(13) and 7(14));
  - "manual" duties are the organization's own status, recorded by a person. They are self-reported,
    because phishing data cannot prove things like audits, certified staff or asset classification.

Pure logic: it receives report dictionaries (the shape GET /reports returns) and a dictionary of
manual assessments, and never touches the database.
"""

from datetime import datetime, timedelta, timezone

from compliance.obligations import COMPLIANCE_OBLIGATIONS, evaluate_compliance_status, _to_naive_utc

LAW_NAME = "Critical Infrastructure Cybersecurity Proclamation No. 1426/2026"
LAW_NOTE = (
    "Published on 21 July 2026. It applies one year after publication (Art. 28), and only to critical "
    "infrastructure designated by the Administration (Arts. 3 and 5). Duties marked manual are self-reported "
    "by the organization; the Administration verifies compliance through its audits (Art. 9(3))."
)

NOTIFICATION_WINDOW_HOURS = 48
ATTESTABLE = {"fulfilled", "in_progress", "not_fulfilled"}


def _duty(n, title, kind="manual", penalty=None):
    return {"id": f"art7_{n}", "article": f"Art. 7({n})", "title": title, "kind": kind, "penalty": penalty}


DUTIES = [
    _duty(1, "Formulate its own cybersecurity programs based on the national cybersecurity frameworks"),
    _duty(2, "Implement the mandatory cybersecurity frameworks issued or recognized by the Administration",
          penalty="Fine of 500,000 to 1,000,000 Birr if not implemented on time (Art. 22(1)(a))"),
    _duty(3, "Develop and implement its own cybersecurity framework based on national policies and laws"),
    _duty(4, "Classify and protect critical assets to the Administration's standard"),
    _duty(5, "Conduct regular cybersecurity risk assessments and impact analyses"),
    _duty(6, "Take part in the annual National Cybersecurity Risk Survey and provide the information requested"),
    _duty(7, "Maintain and renew the cyber audit and cyber inspection and evaluation certificate"),
    _duty(8, "Take corrective action on audit and inspection findings within the time given",
          penalty="Fine of 800,000 to 1,000,000 Birr if not done on time (Art. 22(1)(e))"),
    _duty(9, "Create the cybersecurity organizational structure required by the national framework"),
    _duty(10, "Employ certified cybersecurity professionals and help existing staff get certified"),
    _duty(11, "Ensure the supply-chain security of the technology products it uses"),
    _duty(12, "Obtain security clearance for new or upgraded ICT systems before using them",
          penalty="Related fine of 800,000 to 1,000,000 Birr for using systems that were not inspected and evaluated (Art. 22(1)(f))"),
    _duty(13, "Establish and run a center that monitors, reports and responds to cyber attacks", kind="automatic"),
    _duty(14, "Notify cyber incidents to the National Computer Emergency Response Center within 48 hours and follow its directions",
          kind="automatic",
          penalty="Fine of 1,500,000 to 2,000,000 Birr (Art. 22(1)(b)); intentional failure can also be a crime (Art. 25)"),
    _duty(15, "Exchange important information periodically through the Administration's information exchange system"),
    _duty(16, "Develop and run cybersecurity exercises and training, and take part in the Administration's drills"),
    _duty(17, "Make sure staff with access to critical resources have security clearance"),
    _duty(18, "Make sure the professional ethics required by cybersecurity are followed"),
]

MANUAL_DUTY_IDS = {d["id"] for d in DUTIES if d["kind"] == "manual"}


def _duty_13(reports, now):
    """Monitoring, reporting and response center: built from the five record and response checks."""
    checks = evaluate_compliance_status(reports, now=now)
    titles = {o["id"]: o["title"] for o in COMPLIANCE_OBLIGATIONS}
    evidence = [{"name": titles[c["obligation_id"]], "status": c["status"], "detail": c["detail"]} for c in checks]
    by_id = {c["obligation_id"]: c["status"] for c in checks}
    if by_id["obl_5"] == "unmet":
        return "not_fulfilled", "No automatic scanning activity in the last 30 days.", evidence
    needing_attention = sum(1 for c in checks if c["status"] != "met")
    if needing_attention == 0:
        return "fulfilled", "Monitoring is active and every record and response check passes.", evidence
    return "in_progress", f"Monitoring is active, but {needing_attention} of {len(checks)} checks need attention.", evidence


def _duty_14(reports, now):
    """Notification to the National CERT within 48 hours. Needs a notified_at value on each report."""
    if not any("notified_at" in r for r in reports):
        return ("not_assessed",
                "Notification to the National CERT is not tracked yet (the reports table needs a notified_at column).",
                [])
    limit = timedelta(hours=NOTIFICATION_WINDOW_HOURS)
    incidents = [r for r in reports if str(r.get("verdict") or "").lower() == "risky"]
    on_time = pending = late = 0
    for r in incidents:
        created = _to_naive_utc(r.get("created_at"))
        if created is None:
            continue
        notified = _to_naive_utc(r.get("notified_at"))
        if notified is not None:
            if notified - created <= limit:
                on_time += 1
            else:
                late += 1
        elif now - created > limit:
            late += 1
        else:
            pending += 1
    detail = (f"{len(incidents)} incident(s) (reports with a risky verdict): {on_time} notified within 48 hours, "
              f"{pending} still inside the 48-hour window, {late} late or never notified.")
    evidence = [{"name": "Notification within 48 hours", "status": "at risk" if late else "met", "detail": detail}]
    if late:
        return "not_fulfilled", detail, evidence
    if pending:
        return "in_progress", detail, evidence
    return "fulfilled", detail if incidents else "No incidents to notify so far.", evidence


_MANUAL_DETAIL = {
    "fulfilled": "Recorded as fulfilled by the organization.",
    "in_progress": "Recorded as in progress by the organization.",
    "not_fulfilled": "Recorded as not fulfilled by the organization.",
}


def evaluate_readiness(reports, assessments=None, now=None):
    """
    Returns {"law", "note", "summary", "duties"}.
    Each duty has: id, article, title, kind, status, detail, evidence, penalty, assessment.
    status is one of: fulfilled, in_progress, not_fulfilled, not_assessed.
    """
    reports = reports or []
    assessments = assessments or {}
    now = _to_naive_utc(now) if now else datetime.now(timezone.utc).replace(tzinfo=None)

    duties = []
    for duty in DUTIES:
        item = dict(duty, evidence=[], assessment=None)
        if duty["id"] == "art7_13":
            item["status"], item["detail"], item["evidence"] = _duty_13(reports, now)
        elif duty["id"] == "art7_14":
            item["status"], item["detail"], item["evidence"] = _duty_14(reports, now)
        else:
            assessment = assessments.get(duty["id"])
            status = (assessment or {}).get("status")
            if status in ATTESTABLE:
                item["status"], item["detail"], item["assessment"] = status, _MANUAL_DETAIL[status], assessment
            else:
                item["status"] = "not_assessed"
                item["detail"] = "Not assessed yet. A compliance officer needs to record the current status and the evidence."
        duties.append(item)

    total = len(duties)
    counts = {s: sum(1 for d in duties if d["status"] == s) for s in ("fulfilled", "in_progress", "not_fulfilled", "not_assessed")}
    summary = dict(
        counts,
        total=total,
        percent_fulfilled=round(100 * counts["fulfilled"] / total),
        percent_assessed=round(100 * (total - counts["not_assessed"]) / total),
    )
    return {"law": LAW_NAME, "note": LAW_NOTE, "summary": summary, "duties": duties}
