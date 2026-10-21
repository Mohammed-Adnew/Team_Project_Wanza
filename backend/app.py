import json
from datetime import date, datetime

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from sqlalchemy import MetaData, Table, create_engine, inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from config import Config
from models import Report
from detection.combiner import combine_results
from detection.text_check import extract_domain_from_email, split_sender
from compliance.obligations import COMPLIANCE_OBLIGATIONS, evaluate_compliance_status, build_insa_assessments
from detection.sender_auth import authentication_statuses_from_reasons
from routes.inbound_email_routes import register_inbound_email_routes

engine = create_engine(Config.DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)

ALLOWED_STATUSES = {"new", "investigating", "resolved"}
ASSESSMENT_STATUSES = {"fulfilled", "in_progress", "not_fulfilled"}

_inbox_table = None


def get_inbox_table():
    """
    The simulated_inbox table belongs to the Database role and has no model in
    models.py, so it is read exactly as it exists in the database (read-only).
    """
    global _inbox_table
    if _inbox_table is None:
        _inbox_table = Table("simulated_inbox", MetaData(), autoload_with=engine)
    return _inbox_table


def make_report(*, sender_claimed, sender_actual, subject, body, link,
                attachment_filename, result, source):
    """Builds a Report row from a combine_results() result."""
    return Report(
        sender_claimed=sender_claimed,
        sender_actual=sender_actual,
        subject=subject,
        message_body=body,
        link=link,
        attachment_filename=attachment_filename,
        risk_score=result["score"],
        verdict=result["verdict"],
        severity=result["severity"],
        reasons=json.dumps(result["reasons"]),
        source=source,
        status="new",
    )


def report_to_dict(report):
    """Turns a Report row into a JSON-friendly dict (reasons is stored as JSON text)."""
    reasons = json.loads(report.reasons) if report.reasons else []
    return {
        "id": report.id,
        "sender_claimed": report.sender_claimed,
        "sender_actual": report.sender_actual,
        "subject": report.subject,
        "message_body": report.message_body,
        "link": report.link,
        "attachment_filename": report.attachment_filename,
        "risk_score": report.risk_score,
        "verdict": report.verdict,
        "severity": report.severity,
        "reasons": reasons,
        "sender_authentication": authentication_statuses_from_reasons(reasons),
        "source": report.source,
        "status": report.status,
        "notes": report.notes,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "resolved_at": report.resolved_at.isoformat() if report.resolved_at else None,
    }


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_ATTACHMENT_BYTES + (1024 * 1024)
    CORS(app)  # lets the frontend (running on a different port) call this API

    # This app NEVER creates or changes tables - the Database role owns the schema.
    # It only checks that the table exists and warns clearly if it doesn't.
    try:
        if not inspect(engine).has_table("reports"):
            print("WARNING: the 'reports' table does not exist in the database yet. "
                  "Ask the Database owner to create it. /reports endpoints will fail until then.")
    except SQLAlchemyError as exc:
        print(f"WARNING: could not check the database: {exc.__class__.__name__}")

    @app.errorhandler(SQLAlchemyError)
    def handle_db_error(exc):
        app.logger.error("Database error: %s", exc)
        return jsonify({"error": "database error - check that the tables exist and match models.py"}), 500

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_request(_exc):
        return jsonify({"error": "request is too large; attachments are limited to 10 MB"}), 413

    @app.route("/")
    def home():
        return jsonify({"message": "Phish Watch backend is running!"})

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/reports", methods=["POST"])
    def submit_report():
        data = request.form.to_dict() if request.mimetype == "multipart/form-data" else (request.get_json(silent=True) or {})
        if not isinstance(data, dict):
            return jsonify({"error": "request body must be a JSON object or multipart form"}), 400
        uploaded_file = request.files.get("attachment")

        subject = data.get("subject", "")
        body = data.get("message_body") or data.get("body") or ""
        if not isinstance(subject, str) or not isinstance(body, str):
            return jsonify({"error": "subject and message_body must be text"}), 400
        if not (subject.strip() or body.strip() or uploaded_file):
            return jsonify({"error": "subject, message_body, or attachment is required"}), 400

        sender_claimed = data.get("sender_claimed") or data.get("claimed_org") or ""
        sender_actual = data.get("sender_actual") or data.get("sender") or ""
        link = data.get("link") or None
        attachment_filename = data.get("attachment_filename")
        if attachment_filename is not None and not isinstance(attachment_filename, str):
            return jsonify({"error": "attachment_filename must be text"}), 400
        if not isinstance(data.get("sender_claimed", data.get("claimed_org", "")), str):
            return jsonify({"error": "sender_claimed must be text"}), 400
        if not isinstance(data.get("sender_actual", data.get("sender", "")), str):
            return jsonify({"error": "sender_actual must be text"}), 400
        if link is not None and not isinstance(link, str):
            return jsonify({"error": "link must be text"}), 400
        attachment_bytes = b""
        if uploaded_file is not None:
            attachment_filename = secure_filename(uploaded_file.filename or "")[:255]
            if not attachment_filename:
                return jsonify({"error": "uploaded attachment must have a valid filename"}), 400
            attachment_bytes = uploaded_file.read(Config.MAX_ATTACHMENT_BYTES + 1)
            if len(attachment_bytes) > Config.MAX_ATTACHMENT_BYTES:
                return jsonify({"error": "attachment exceeds the 10 MB upload limit"}), 413
            if not attachment_bytes:
                return jsonify({"error": "uploaded attachment is empty"}), 400
        consent_value = data.get("share_with_virustotal", False)
        share_with_virustotal = consent_value is True or (
            isinstance(consent_value, str) and consent_value.strip().lower() in {"true", "1", "yes", "on"}
        )
        authentication_results = data.get("authentication_results", "")
        if not isinstance(authentication_results, str):
            return jsonify({"error": "authentication_results must be text"}), 400

        # The sending domain comes from the real address, the claimed organization
        # from the "claims to be from" field.
        sender_domain = extract_domain_from_email(sender_actual)
        claimed_org = data.get("claimed_org") or sender_claimed
        if not isinstance(claimed_org, str):
            return jsonify({"error": "claimed_org must be text"}), 400

        # The link has its own field, so add it to the text the link check scans.
        scan_text = f"{body}\n{link}" if link else body

        result = combine_results(
            subject=subject,
            body=scan_text,
            sender_domain=sender_domain,
            claimed_org=claimed_org,
            attachment_filename=attachment_filename,
            attachment_bytes=attachment_bytes,
            authentication_results=authentication_results,
            allow_virustotal_upload=bool(attachment_bytes and share_with_virustotal and Config.VT_FILE_UPLOAD_ENABLED),
        )
        if attachment_bytes and share_with_virustotal:
            result["reasons"].append("Submitter consent to VirusTotal file sharing was recorded for this report.")
        elif attachment_bytes:
            result["reasons"].append("VirusTotal file upload was not authorized; file bytes were not sent to VirusTotal.")

        with SessionLocal() as session:
            report = make_report(
                sender_claimed=sender_claimed,
                sender_actual=sender_actual,
                subject=subject,
                body=body,
                link=link,
                attachment_filename=attachment_filename,
                result=result,
                source=data.get("source", "employee"),
            )
            session.add(report)
            session.commit()
            session.refresh(report)
            return jsonify(report_to_dict(report)), 201

    @app.route("/inbox/scan", methods=["POST"])
    def scan_inbox():
        """
        Scans emails from the simulated inbox and saves each result as a report
        with source "automatic". Emails already scanned are skipped, so it is safe
        to call repeatedly. ?limit=N (default 10, max 50) caps emails per call -
        useful because VirusTotal's free tier only allows 4 requests a minute.
        """
        if not inspect(engine).has_table("simulated_inbox"):
            return jsonify({"error": "the simulated_inbox table does not exist in the database"}), 503

        limit = min(max(request.args.get("limit", default=10, type=int), 1), 50)
        inbox = get_inbox_table()
        results = []
        skipped = 0

        with SessionLocal() as session:
            rows = session.execute(select(inbox).order_by(inbox.c.id)).mappings().all()

            for row in rows:
                if len(results) >= limit:
                    break

                sender = row["sender"] or ""
                subject = row["subject"] or ""
                body = row["body"] or ""

                # The sender may look like 'Name <address>'. The address is the real sender.
                sender_name, sender_addr = split_sender(sender)
                actual = sender_addr or sender
                # Who the email claims to be from: the inbox's sender_claimed column if the
                # Database role has added one, otherwise nothing (the display name is used below).
                claimed = row.get("sender_claimed") or ""

                already_scanned = session.query(Report.id).filter(
                    Report.source == "automatic",
                    Report.sender_actual == actual,
                    Report.subject == subject,
                    Report.message_body == body,
                ).first()
                if already_scanned:
                    skipped += 1
                    continue

                result = combine_results(
                    subject=subject,
                    body=body,
                    sender_domain=extract_domain_from_email(actual),
                    claimed_org=claimed,
                    # Use the display name only when there is no explicit claim, so the same
                    # mismatch is never counted twice.
                    sender_display_name="" if claimed else sender_name,
                    sender_email=actual,
                )
                report = make_report(
                    sender_claimed=claimed or sender_name or None,
                    sender_actual=actual,
                    subject=subject,
                    body=body,
                    link=None,
                    attachment_filename=None,
                    result=result,
                    source="automatic",
                )
                session.add(report)
                session.flush()  # assigns report.id

                labeled_phishing = row["is_phishing"]
                matches_label = (
                    None if labeled_phishing is None
                    else (result["verdict"] == "risky") == labeled_phishing
                )
                results.append({
                    "inbox_id": row["id"],
                    "report_id": report.id,
                    "subject": subject,
                    "verdict": result["verdict"],
                    "risk_score": result["score"],
                    "severity": result["severity"],
                    "labeled_phishing": labeled_phishing,
                    "matches_label": matches_label,
                })

            session.commit()

        labeled = [r for r in results if r["matches_label"] is not None]
        matched = sum(1 for r in labeled if r["matches_label"])
        return jsonify({
            "scanned": len(results),
            "skipped_already_scanned": skipped,
            "limit_reached": len(results) >= limit,
            "matches_label": f"{matched}/{len(labeled)}",
            "results": results,
        })

    @app.route("/reports", methods=["GET"])
    def get_reports():
        with SessionLocal() as session:
            reports = session.query(Report).order_by(Report.created_at.desc()).all()
            return jsonify([report_to_dict(r) for r in reports])

    @app.route("/inbound-emails", methods=["GET"])
    def get_inbound_emails():
        """Return only messages received through the configured inbound provider."""
        limit = min(max(request.args.get("limit", default=50, type=int), 1), 100)
        with SessionLocal() as session:
            reports = (session.query(Report)
                       .filter(Report.source == "inbound")
                       .order_by(Report.created_at.desc())
                       .limit(limit).all())
            return jsonify([report_to_dict(report) for report in reports])

    @app.route("/reports/<int:report_id>", methods=["GET"])
    def get_report(report_id):
        with SessionLocal() as session:
            report = session.get(Report, report_id)
            if report is None:
                return jsonify({"error": "report not found"}), 404
            return jsonify(report_to_dict(report))

    @app.route("/reports/<int:report_id>", methods=["PATCH"])
    def update_report(report_id):
        data = request.get_json(silent=True) or {}

        with SessionLocal() as session:
            report = session.get(Report, report_id)
            if report is None:
                return jsonify({"error": "report not found"}), 404

            if "status" in data:
                if data["status"] not in ALLOWED_STATUSES:
                    return jsonify({"error": "status must be new, investigating, or resolved"}), 400
                report.status = data["status"]
                # Compliance (48-hour notification) needs to know when a report was closed
                if data["status"] == "resolved" and report.resolved_at is None:
                    report.resolved_at = datetime.utcnow()

            if "notes" in data:
                report.notes = data["notes"]

            session.commit()
            session.refresh(report)
            return jsonify(report_to_dict(report))

    @app.route("/compliance-status", methods=["GET"])
    def get_compliance_status():
        with SessionLocal() as session:
            reports = [report_to_dict(r) for r in session.query(Report).all()]

        return jsonify({
            "obligations": COMPLIANCE_OBLIGATIONS,
            "statuses": evaluate_compliance_status(reports),
        })

    @app.route("/compliance-assessments", methods=["GET"])
    def get_compliance_assessments():
        """Read analyst-entered INSA assessments from the Database-owned table."""
        if not inspect(engine).has_table("compliance_assessments"):
            return jsonify({"error": "the compliance_assessments table does not exist"}), 503
        with engine.connect() as connection:
            rows = connection.execute(text("""
                SELECT duty_id, status, evidence_note, responsible, target_date, updated_at
                FROM compliance_assessments ORDER BY duty_id
            """)).mappings().all()
        return jsonify([{
            **dict(row),
            "target_date": row["target_date"].isoformat() if row["target_date"] else None,
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        } for row in rows])

    @app.route("/compliance-assessments", methods=["PUT"])
    def save_compliance_assessment():
        """Create or update a manual assessment without changing the table schema."""
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400
        duty_id = data.get("duty_id")
        status = data.get("status")
        if not isinstance(duty_id, str) or not duty_id.strip() or len(duty_id.strip()) > 255:
            return jsonify({"error": "duty_id must be text between 1 and 255 characters"}), 400
        if not isinstance(status, str) or status not in ASSESSMENT_STATUSES:
            return jsonify({"error": "status must be fulfilled, in_progress, or not_fulfilled"}), 400
        for field, limit in (("evidence_note", None), ("responsible", 255)):
            value = data.get(field)
            if value is not None and not isinstance(value, str):
                return jsonify({"error": f"{field} must be text"}), 400
            if value is not None and limit is not None and len(value) > limit:
                return jsonify({"error": f"{field} must be at most {limit} characters"}), 400
        if status == "fulfilled" and not (data.get("evidence_note") or "").strip():
            return jsonify({"error": "evidence_note is required when an assessment is marked fulfilled"}), 400
        target_date = data.get("target_date") or None
        if target_date is not None:
            if not isinstance(target_date, str):
                return jsonify({"error": "target_date must be a YYYY-MM-DD date or empty"}), 400
            try:
                target_date = date.fromisoformat(target_date)
            except ValueError:
                return jsonify({"error": "target_date must be a valid YYYY-MM-DD date"}), 400
        if not inspect(engine).has_table("compliance_assessments"):
            return jsonify({"error": "the compliance_assessments table does not exist"}), 503

        with engine.begin() as connection:
            row = connection.execute(text("""
                INSERT INTO compliance_assessments
                    (duty_id, status, evidence_note, responsible, target_date, updated_at)
                VALUES
                    (:duty_id, :status, :evidence_note, :responsible, :target_date, CURRENT_TIMESTAMP)
                ON CONFLICT (duty_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    evidence_note = EXCLUDED.evidence_note,
                    responsible = EXCLUDED.responsible,
                    target_date = EXCLUDED.target_date,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING duty_id, status, evidence_note, responsible, target_date, updated_at
            """), {
                "duty_id": duty_id.strip(),
                "status": status,
                "evidence_note": data.get("evidence_note"),
                "responsible": data.get("responsible"),
                "target_date": target_date,
            }).mappings().one()
        return jsonify({
            **dict(row),
            "target_date": row["target_date"].isoformat() if row["target_date"] else None,
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        }), 200

    @app.route("/insa-obligations", methods=["GET"])
    def get_insa_obligations():
        """Return the Article 7 catalog joined with saved manual assessments."""
        if not inspect(engine).has_table("compliance_assessments"):
            return jsonify({"error": "the compliance_assessments table does not exist"}), 503
        with engine.connect() as connection:
            rows = connection.execute(text("""
                SELECT duty_id, status, evidence_note, responsible, target_date, updated_at
                FROM compliance_assessments
            """)).mappings().all()
        saved_rows = [{
            **dict(row),
            "target_date": row["target_date"].isoformat() if row["target_date"] else None,
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        } for row in rows]
        duties = build_insa_assessments(saved_rows)
        counts = {
            "met": sum(item["status"] == "met" for item in duties),
            "at_risk": sum(item["status"] == "at risk" for item in duties),
            "unmet": sum(item["status"] == "unmet" for item in duties),
            "not_assessed": sum(item["status"] == "not assessed" for item in duties),
            "total": len(duties),
        }
        progress = round((counts["met"] + counts["at_risk"] * 0.5) / counts["total"] * 100) if counts["total"] else 0
        return jsonify({
            "framework": "Ethiopia Critical Infrastructure Cybersecurity Proclamation No. 1426/2026, Article 7",
            "scope_note": "Applies to owners of designated critical infrastructure. This evidence tracker is a self-assessment aid, not a legal applicability decision or certification.",
            "progress_percent": progress,
            "counts": counts,
            "obligations": duties,
        })

    register_inbound_email_routes(app, SessionLocal, engine, Report, make_report)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0",debug=False, port=5000)
