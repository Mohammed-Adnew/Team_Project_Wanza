import json
from datetime import datetime

from flask import Flask, jsonify, request
from flask_cors import CORS
from sqlalchemy import MetaData, Table, create_engine, inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from werkzeug.exceptions import HTTPException

from config import Config
from models import Report
from detection.combiner import combine_results
from detection.text_check import extract_domain_from_email, split_sender
from compliance.obligations import COMPLIANCE_OBLIGATIONS, evaluate_compliance_status
from compliance.readiness_routes import register_readiness_routes

if not Config.DATABASE_URL.strip():
    raise RuntimeError("DATABASE_URL is required; configure it in the backend environment before starting the API")

engine = create_engine(Config.DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)

ALLOWED_STATUSES = {"new", "investigating", "resolved"}

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
    try:
        reasons = json.loads(report.reasons) if report.reasons else []
    except (TypeError, ValueError):
        # Keep a malformed legacy value visible instead of failing every report read.
        reasons = [report.reasons] if report.reasons else []
    if not isinstance(reasons, list):
        reasons = [reasons]

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
        "source": report.source,
        "status": report.status,
        "notes": report.notes,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "resolved_at": report.resolved_at.isoformat() if report.resolved_at else None,
    }


def create_app():
    app = Flask(__name__)
    CORS(app)  # lets the frontend (running on a different port) call this API
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

    # This app NEVER creates or changes tables - the Database role owns the schema.
    # It only checks that the table exists and warns clearly if it doesn't.
    try:
        if not inspect(engine).has_table("reports"):
            app.logger.warning(
                "The 'reports' table is missing; /reports endpoints will be unavailable until it is created."
            )
    except SQLAlchemyError as exc:
        app.logger.warning("Could not check database tables (%s)", exc.__class__.__name__)

    @app.errorhandler(SQLAlchemyError)
    def handle_db_error(exc):
        app.logger.error("Database operation failed (%s)", exc.__class__.__name__)
        return jsonify({"error": "database operation failed; check the database connection and schema"}), 500

    @app.errorhandler(HTTPException)
    def handle_http_error(exc):
        return jsonify({"error": exc.description}), exc.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc):
        app.logger.exception("Unhandled API error")
        return jsonify({"error": "internal server error"}), 500

    @app.route("/")
    def home():
        return jsonify({"message": "Phish Watch backend is running!"})

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/reports", methods=["POST"])
    def submit_report():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "a JSON object is required"}), 400

        subject = data.get("subject", "")
        body = data.get("message_body") or data.get("body") or ""
        if not isinstance(subject, str) or not isinstance(body, str):
            return jsonify({"error": "subject and message_body must be text"}), 400
        if not (subject.strip() or body.strip()):
            return jsonify({"error": "subject or message_body is required"}), 400
        if len(subject) > 255:
            return jsonify({"error": "subject must be 255 characters or fewer"}), 400

        text_limits = {
            "sender_claimed": 255,
            "sender_actual": 255,
            "sender_domain": 255,
            "claimed_org": 255,
            "attachment_filename": 255,
            "source": 100,
        }
        for field, max_length in text_limits.items():
            value = data.get(field)
            if value is not None and not isinstance(value, str):
                return jsonify({"error": f"{field} must be text"}), 400
            if isinstance(value, str) and len(value) > max_length:
                return jsonify({"error": f"{field} must be {max_length} characters or fewer"}), 400
        if data.get("link") is not None and not isinstance(data["link"], str):
            return jsonify({"error": "link must be text"}), 400

        sender_claimed = data.get("sender_claimed") or data.get("claimed_org") or ""
        sender_actual = data.get("sender_actual") or data.get("sender") or ""
        link = data.get("link") or None
        attachment_filename = data.get("attachment_filename")

        # The sending domain comes from the real address, the claimed organization
        # from the "claims to be from" field.
        sender_domain = data.get("sender_domain") or extract_domain_from_email(sender_actual)
        claimed_org = data.get("claimed_org") or sender_claimed

        # The link has its own field, so add it to the text the link check scans.
        scan_text = f"{body}\n{link}" if link else body

        result = combine_results(
            subject=subject,
            body=scan_text,
            sender_domain=sender_domain,
            claimed_org=claimed_org,
            attachment_filename=attachment_filename,
        )

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

    @app.route("/reports/<int:report_id>", methods=["GET"])
    def get_report(report_id):
        with SessionLocal() as session:
            report = session.get(Report, report_id)
            if report is None:
                return jsonify({"error": "report not found"}), 404
            return jsonify(report_to_dict(report))

    @app.route("/reports/<int:report_id>", methods=["PATCH"])
    def update_report(report_id):
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "a JSON object is required"}), 400
        if not data:
            return jsonify({"error": "at least one field is required"}), 400
        unknown_fields = set(data) - {"status", "notes"}
        if unknown_fields:
            return jsonify({"error": f"unsupported field(s): {', '.join(sorted(unknown_fields))}"}), 400
        if "status" in data and (
            not isinstance(data["status"], str) or data["status"] not in ALLOWED_STATUSES
        ):
            return jsonify({"error": "status must be new, investigating, or resolved"}), 400
        if "notes" in data and data["notes"] is not None and not isinstance(data["notes"], str):
            return jsonify({"error": "notes must be text or null"}), 400
        if isinstance(data.get("notes"), str) and len(data["notes"]) > 10000:
            return jsonify({"error": "notes must be 10000 characters or fewer"}), 400

        with SessionLocal() as session:
            report = session.get(Report, report_id)
            if report is None:
                return jsonify({"error": "report not found"}), 404

            if "status" in data:
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

    register_readiness_routes(app, SessionLocal, engine, Report, report_to_dict)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", debug=False, port=5000)
