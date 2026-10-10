import os
from flask import Flask, jsonify
import psycopg2

app = Flask(__name__)

def check_db_connection():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        return False, "DATABASE_URL environment variable is missing"
    try:
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        cur.close()
        conn.close()
        return True, "Database connection successful!"
    except Exception as e:
        return False, str(e)

@app.route("/")
def home():
    return jsonify({"message": "Phish Watch backend is running!"})

@app.route("/health")
def health():
    db_ok, db_msg = check_db_connection()
    status_code = 200 if db_ok else 500
    return jsonify({"backend": "healthy", "database": db_msg}), status_code

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
