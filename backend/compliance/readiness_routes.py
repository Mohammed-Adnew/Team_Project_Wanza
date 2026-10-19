"""
Routes for the compliance readiness view:
  GET /compliance/readiness     progress against the duties in Art. 7 of the Proclamation
  PUT /compliance/duties/<id>   record the organization's own status for a manual duty

The compliance_assessments table belongs to the Database role. It is read and written as it exists
(reflection). Without it the endpoints still work: manual duties show as "not assessed" and saving returns 503.
"""

from datetime import date, datetime

from flask import jsonify, request
from sqlalchemy import MetaData, Table, inspect, select

from compliance.readiness import ATTESTABLE, MANUAL_DUTY_IDS, evaluate_readiness

TABLE = "compliance_assessments"


def _plain(value):
    return value.isoformat() if isinstance(value, (date, datetime)) else value


def register_readiness_routes(app, SessionLocal, engine, Report, report_to_dict):
    def assessments_table():
        if not inspect(engine).has_table(TABLE):
            return None
        return Table(TABLE, MetaData(), autoload_with=engine)

    @app.route("/compliance/readiness", methods=["GET"])
    def get_readiness():
        table = assessments_table()
        assessments = {}
        if table is not None:
            with engine.connect() as conn:
                for row in conn.execute(select(table)).mappings():
                    assessments[row["duty_id"]] = {k: _plain(v) for k, v in row.items() if k != "duty_id"}
        with SessionLocal() as session:
            reports = [report_to_dict(r) for r in session.query(Report).all()]
        data = evaluate_readiness(reports, assessments)
        data["assessments_available"] = table is not None
        return jsonify(data)

    @app.route("/compliance/duties/<duty_id>", methods=["PUT"])
    def save_duty(duty_id):
        if duty_id not in MANUAL_DUTY_IDS:
            return jsonify({"error": "unknown duty, or a duty that is computed automatically"}), 404
        data = request.get_json(silent=True) or {}
        status = data.get("status")
        if status not in ATTESTABLE:
            return jsonify({"error": "status must be fulfilled, in_progress or not_fulfilled"}), 400
        table = assessments_table()
        if table is None:
            return jsonify({"error": "the compliance_assessments table does not exist yet"}), 503

        values = {"status": status}
        for key in ("evidence_note", "responsible"):
            if key in data and key in table.c:
                values[key] = data[key]
        if "target_date" in data and "target_date" in table.c:
            try:
                values["target_date"] = date.fromisoformat(data["target_date"]) if data["target_date"] else None
            except (TypeError, ValueError):
                return jsonify({"error": "target_date must look like 2027-01-31"}), 400
        if "updated_at" in table.c:
            values["updated_at"] = datetime.utcnow()

        with engine.begin() as conn:
            exists = conn.execute(select(table.c.duty_id).where(table.c.duty_id == duty_id)).first()
            if exists:
                conn.execute(table.update().where(table.c.duty_id == duty_id).values(**values))
            else:
                conn.execute(table.insert().values(duty_id=duty_id, **values))
        return jsonify({"duty_id": duty_id, **{k: _plain(v) for k, v in values.items()}})
