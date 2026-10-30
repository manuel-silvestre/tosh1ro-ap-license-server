"""
NYPD AP License Server
----------------------
Simple Flask server for one-time, computer-bound activation.

Install:
    py -m pip install flask

Run:
    py license_server.py

For real deployment, put this behind HTTPS and use a production
WSGI server/database. This sample uses SQLite for simplicity.
"""

import hashlib
import secrets
import sqlite3
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB = str(BASE_DIR / "licenses.db")

APP_ID = "nypd_ap_v1"


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_hash TEXT UNIQUE NOT NULL,
            machine_id TEXT,
            token_hash TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            activated_at DATETIME
        )
    """)
    con.commit()
    con.close()


def hash_value(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

@app.get("/")
def home():
    return jsonify(
        ok=True,
        message="NYPD AP License Server is running."
    )

@app.post("/activate")
def activate():
    data = request.get_json(silent=True) or {}

    if data.get("app_id") != APP_ID:
        return jsonify(ok=False, error="Invalid application."), 400

    code = str(data.get("license_code", "")).strip()
    machine_id = str(data.get("machine_id", "")).strip()

    if not code or not machine_id:
        return jsonify(ok=False, error="Missing activation information."), 400

    con = db()
    row = con.execute(
        "SELECT * FROM licenses WHERE code_hash=?",
        (hash_value(code),)
    ).fetchone()

    if not row:
        con.close()
        return jsonify(ok=False, error="Invalid activation code."), 403

    if not row["active"]:
        con.close()
        return jsonify(ok=False, error="This license has been disabled."), 403

    if row["machine_id"]:
        con.close()
        if row["machine_id"] == machine_id:
            return jsonify(ok=False, error="This code was already activated on this computer.")
        return jsonify(ok=False, error="This activation code is already bound to another computer."), 403

    token = secrets.token_urlsafe(32)

    con.execute(
        """UPDATE licenses
           SET machine_id=?, token_hash=?, activated_at=CURRENT_TIMESTAMP
           WHERE id=?""",
        (machine_id, hash_value(token), row["id"])
    )
    con.commit()
    con.close()

    return jsonify(ok=True, license_token=token)


@app.post("/verify")
def verify():
    data = request.get_json(silent=True) or {}

    if data.get("app_id") != APP_ID:
        return jsonify(ok=False), 400

    token = str(data.get("license_token", "")).strip()
    machine_id = str(data.get("machine_id", "")).strip()

    if not token or not machine_id:
        return jsonify(ok=False), 403

    con = db()
    row = con.execute(
        """SELECT active FROM licenses
           WHERE token_hash=? AND machine_id=?""",
        (hash_value(token), machine_id)
    ).fetchone()
    con.close()

    return jsonify(ok=bool(row and row["active"]))

@app.get("/debug/licenses")
def debug_licenses():
    con = db()
    rows = con.execute(
        "SELECT id, machine_id, active, created_at, activated_at FROM licenses"
    ).fetchall()
    con.close()

    return jsonify(
        count=len(rows),
        licenses=[dict(row) for row in rows]
    )


# Initialize database when the application starts
init_db()

if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
