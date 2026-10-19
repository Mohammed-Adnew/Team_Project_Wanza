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
from sqlalchemy.dialects.postgresql import insert as pg_insert

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
            missing_columns = {"duty_id", "status"} - set(table.c.keys())
            if missing_columns:
                return jsonify({
                    "error": "the compliance_assessments table is missing required columns",
                    "missing_columns": sorted(missing_columns),
                }), 503
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
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "a JSON object is required"}), 400
        allowed_fields = {"status", "evidence_note", "responsible", "target_date"}
        unknown_fields = set(data) - allowed_fields
        if unknown_fields:
            return jsonify({"error": f"unsupported field(s): {', '.join(sorted(unknown_fields))}"}), 400

        status = data.get("status")
        if not isinstance(status, str) or status not in ATTESTABLE:
            return jsonify({"error": "status must be fulfilled, in_progress or not_fulfilled"}), 400
        table = assessments_table()
        if table is None:
            return jsonify({"error": "the compliance_assessments table does not exist yet"}), 503
        required_columns = {"duty_id", "status"}
        missing_columns = required_columns - set(table.c.keys())
        if missing_columns:
            return jsonify({
                "error": "the compliance_assessments table is missing required columns",
                "missing_columns": sorted(missing_columns),
            }), 503

        values = {"status": status}
        for key, max_length in (("evidence_note", 10000), ("responsible", 255)):
            if key not in data:
                continue
            if key not in table.c:
                return jsonify({"error": f"the database table does not support {key}"}), 503
            value = data[key]
            if value is not None and not isinstance(value, str):
                return jsonify({"error": f"{key} must be text or null"}), 400
            if isinstance(value, str) and len(value) > max_length:
                return jsonify({"error": f"{key} must be {max_length} characters or fewer"}), 400
            values[key] = value

        if "target_date" in data:
            if "target_date" not in table.c:
                return jsonify({"error": "the database table does not support target_date"}), 503
            try:
                target_date = data["target_date"]
                if target_date is not None and not isinstance(target_date, str):
                    return jsonify({"error": "target_date must look like 2027-01-31"}), 400
                values["target_date"] = date.fromisoformat(target_date) if target_date else None
            except (TypeError, ValueError):
                return jsonify({"error": "target_date must look like 2027-01-31"}), 400
        if "updated_at" in table.c:
            values["updated_at"] = datetime.utcnow()

        with engine.begin() as conn:
            statement = pg_insert(table).values(duty_id=duty_id, **values)
            statement = statement.on_conflict_do_update(
                index_elements=[table.c.duty_id],
                set_=values,
            )
            conn.execute(statement)
        return jsonify({"duty_id": duty_id, **{k: _plain(v) for k, v in values.items()}})
