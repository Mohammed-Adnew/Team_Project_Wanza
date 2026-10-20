"""Receive and analyze inbound emails delivered by Resend webhooks."""

import json
from html.parser import HTMLParser
from urllib.parse import quote

import requests
from flask import current_app, jsonify, request
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from svix.webhooks import Webhook, WebhookVerificationError

from config import Config
from detection.combiner import combine_results
from detection.text_check import extract_domain_from_email, split_sender


class _EmailHTMLText(HTMLParser):
    """Extract readable text and hrefs without rendering untrusted email HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden_depth += 1
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.parts.append(f" {href} ")

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth and data.strip():
            self.parts.append(data.strip())


def _message_body(email):
    text = email.get("text")
    parts = [text.strip()] if isinstance(text, str) and text.strip() else []

    # Include HTML anchor hrefs and readable text even when a plain-text alternative exists.
    html = email.get("html")
    if isinstance(html, str) and html.strip():
        parser = _EmailHTMLText()
        parser.feed(html)
        parser.close()
        parts.extend(parser.parts)
    return "\n".join(dict.fromkeys(parts))


def _authentication_results(headers):
    """Extract Authentication-Results values from provider-returned header shapes."""
    if isinstance(headers, dict):
        return [value[:10000] for name, value in headers.items()
                if isinstance(name, str) and name.lower() == "authentication-results"
                and isinstance(value, str)]
    if isinstance(headers, list):
        values = []
        for item in headers:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("key")
            value = item.get("value")
            if isinstance(name, str) and name.lower() == "authentication-results" and isinstance(value, str):
                values.append(value[:10000])
        return values
    return []


def register_inbound_email_routes(app, SessionLocal, engine, Report, make_report):
    @app.route("/webhooks/resend", methods=["POST"])
    def receive_resend_email():
        """Verify Resend's signed event, fetch its email, and save an analysis report."""
        webhook_secret = Config.RESEND_WEBHOOK_SECRET.strip()
        api_key = Config.RESEND_API_KEY.strip()
        if not webhook_secret or not api_key:
            current_app.logger.error("Resend inbound email is not configured")
            return jsonify({"error": "inbound email integration is not configured"}), 503

        raw_body = request.get_data(cache=True, as_text=True)
        try:
            Webhook(webhook_secret).verify(raw_body, request.headers)
            event = json.loads(raw_body)
        except (WebhookVerificationError, ValueError, TypeError):
            return jsonify({"error": "invalid webhook signature or payload"}), 400

        if not isinstance(event, dict):
            return jsonify({"error": "invalid webhook payload"}), 400
        if event.get("type") != "email.received":
            return jsonify({"status": "ignored", "reason": "unsupported event type"}), 200

        event_data = event.get("data")
        email_id = event_data.get("email_id") if isinstance(event_data, dict) else None
        if not isinstance(email_id, str) or not email_id.strip():
            return jsonify({"error": "email.received event is missing data.email_id"}), 400

        email_url = f"https://api.resend.com/emails/receiving/{quote(email_id, safe='')}"
        try:
            response = requests.get(
                email_url,
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=10,
            )
            response.raise_for_status()
            email = response.json()
        except (requests.RequestException, ValueError):
            current_app.logger.exception("Could not retrieve received Resend email %s", email_id)
            return jsonify({"error": "could not retrieve received email from provider"}), 502

        if not isinstance(email, dict):
            return jsonify({"error": "provider returned an invalid email record"}), 502

        sender = email.get("from") or ""
        subject = email.get("subject") or ""
        body = _message_body(email)
        email_attachments = email.get("attachments") if isinstance(email.get("attachments"), list) else []
        if not isinstance(sender, str) or not isinstance(subject, str):
            return jsonify({"error": "received email has invalid sender or subject"}), 422
        if not isinstance(body, str) or not (subject.strip() or body.strip() or email_attachments):
            return jsonify({"error": "received email has no analyzable subject, body, or attachment"}), 422
        if len(subject) > 255:
            return jsonify({"error": "received email subject exceeds the 255 character database limit"}), 422
        if len(body) > 1_000_000:
            return jsonify({"error": "received email body exceeds the 1 MB analysis limit"}), 422

        sender_name, sender_address = split_sender(sender)
        actual_sender = sender_address or sender
        if len(actual_sender) > 255:
            return jsonify({"error": "received email sender exceeds the 255 character database limit"}), 422
        attachment_names = [
            item.get("filename") for item in email_attachments
            if isinstance(item, dict) and isinstance(item.get("filename"), str) and item.get("filename").strip()
        ]
        if email_attachments and not attachment_names:
            attachment_names = ["(unnamed inbound attachment)"]
        attachment_filename = ", ".join(attachment_names)[:255] or None
        auth_results = _authentication_results(email.get("headers"))
        result = combine_results(
            subject=subject,
            body=body,
            sender_domain=extract_domain_from_email(actual_sender),
            sender_display_name=sender_name,
            sender_email=actual_sender,
            authentication_results=auth_results,
            attachment_filename=attachment_names or None,
        )

        try:
            has_provider_id_column = any(
                column["name"] == "provider_email_id"
                for column in inspect(engine).get_columns("reports")
            )
            with SessionLocal() as session:
                if has_provider_id_column:
                    existing = session.execute(
                        text("SELECT id FROM reports WHERE provider_email_id = :email_id"),
                        {"email_id": email_id},
                    ).first()
                else:
                    # Fallback until the database owner adds the provider ID column.
                    existing = session.query(Report.id).filter(
                        Report.source == "inbound",
                        Report.sender_actual == actual_sender,
                        Report.subject == subject,
                        Report.message_body == body,
                    ).first()
                if existing:
                    return jsonify({"status": "already_processed", "report_id": existing[0]}), 200

                report = make_report(
                    sender_claimed=sender_name[:255] or None,
                    sender_actual=actual_sender,
                    subject=subject,
                    body=body,
                    link=None,
                    attachment_filename=attachment_filename,
                    result=result,
                    source="inbound",
                )
                session.add(report)
                if has_provider_id_column:
                    session.flush()
                    session.execute(
                        text("UPDATE reports SET provider_email_id = :email_id WHERE id = :report_id"),
                        {"email_id": email_id, "report_id": report.id},
                    )
                session.commit()
                session.refresh(report)
                report_id = report.id
        except SQLAlchemyError:
            current_app.logger.exception("Could not save inbound email report %s", email_id)
            return jsonify({"error": "could not save inbound email report"}), 500

        return jsonify({"status": "processed", "report_id": report_id}), 201
