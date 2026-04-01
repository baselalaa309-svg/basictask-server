"""
Basic Task — License Server
Deploy to Railway, Render, or any Python host (free tier works fine).

Install:  pip install flask requests
Run:      python license_server.py
Deploy:   push to Railway/Render, set env vars below.

Environment variables to set on your host:
  GUMROAD_ACCESS_TOKEN   — from gumroad.com/settings/advanced → Application Token
  PRODUCT_PERMALINK      — your Gumroad product slug, e.g. "basictask"
  APP_SECRET             — must match APP_SECRET in basic_task.py
  MAX_MACHINES           — how many machines per license key (default: 2)
"""

import os, json, hashlib, hmac, sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# ── Config (set as env vars on your host) ─────────────────────────────────────
GUMROAD_TOKEN  = os.environ.get("GUMROAD_ACCESS_TOKEN", "YOUR_GUMROAD_TOKEN")
PRODUCT_PLINK  = os.environ.get("PRODUCT_PERMALINK",    "basictask")
APP_SECRET     = os.environ.get("APP_SECRET",           "bt-2024-secret-do-not-share")
MAX_MACHINES   = int(os.environ.get("MAX_MACHINES",     "2"))
DB_PATH        = os.environ.get("DB_PATH",              "licenses.db")

# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS activations (
            key       TEXT NOT NULL,
            machine   TEXT NOT NULL,
            activated TEXT NOT NULL,
            PRIMARY KEY (key, machine)
        );
        CREATE TABLE IF NOT EXISTS revoked (
            key       TEXT PRIMARY KEY,
            reason    TEXT,
            revoked   TEXT NOT NULL
        );
    """)
    db.commit()
    db.close()

init_db()

# ── Helpers ───────────────────────────────────────────────────────────────────

def verify_with_gumroad(license_key: str) -> tuple[bool, dict]:
    """Ask Gumroad if this key is valid for our product."""
    try:
        resp = requests.post(
            "https://api.gumroad.com/v2/licenses/verify",
            data={
                "product_permalink": PRODUCT_PLINK,
                "license_key":       license_key,
                "increment_uses_count": "false",
            },
            timeout=10)
        data = resp.json()
        return data.get("success", False), data
    except Exception as e:
        return False, {"error": str(e)}

def is_revoked(key: str) -> bool:
    db = get_db()
    row = db.execute("SELECT 1 FROM revoked WHERE key=?", (key,)).fetchone()
    db.close()
    return row is not None

def get_machines(key: str) -> list[str]:
    db = get_db()
    rows = db.execute(
        "SELECT machine FROM activations WHERE key=?", (key,)).fetchall()
    db.close()
    return [r["machine"] for r in rows]

def add_machine(key: str, machine: str):
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO activations (key, machine, activated) VALUES (?,?,?)",
        (key, machine, datetime.utcnow().isoformat()))
    db.commit()
    db.close()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/validate", methods=["POST"])
def validate():
    try:
        body    = request.get_json(force=True)
        key     = str(body.get("key",     "")).strip().upper()
        machine = str(body.get("machine", "")).strip()
    except Exception:
        return jsonify({"valid": False, "message": "Bad request"}), 400

    if not key or not machine:
        return jsonify({"valid": False, "message": "Missing key or machine ID"}), 400

    # 1. Check revoked list first
    if is_revoked(key):
        return jsonify({"valid": False,
                        "message": "This license has been revoked. Contact support."}), 403

    # 2. Check Gumroad
    ok, gum = verify_with_gumroad(key)
    if not ok:
        return jsonify({"valid": False,
                        "message": "Invalid license key. "
                                   "Purchase at basictask.gumroad.com"}), 403

    # 3. Check if this machine is already registered, or slot is available
    machines = get_machines(key)
    if machine not in machines:
        if len(machines) >= MAX_MACHINES:
            return jsonify({
                "valid": False,
                "message": f"This key is already activated on {MAX_MACHINES} "
                           f"machine(s). Contact support to transfer your license."}), 403
        add_machine(key, machine)

    return jsonify({"valid": True,
                    "message": "License valid. Welcome to Basic Task!"}), 200


@app.route("/revoke", methods=["POST"])
def revoke():
    """Admin endpoint — protect this with a secret header in production."""
    auth = request.headers.get("X-Admin-Secret", "")
    if auth != APP_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    body   = request.get_json(force=True)
    key    = str(body.get("key", "")).strip().upper()
    reason = str(body.get("reason", ""))
    if not key:
        return jsonify({"error": "Missing key"}), 400
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO revoked (key, reason, revoked) VALUES (?,?,?)",
        (key, reason, datetime.utcnow().isoformat()))
    db.commit()
    db.close()
    return jsonify({"revoked": key}), 200


@app.route("/activations", methods=["GET"])
def activations():
    """Admin — list all activations."""
    auth = request.headers.get("X-Admin-Secret", "")
    if auth != APP_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    db   = get_db()
    rows = db.execute(
        "SELECT key, machine, activated FROM activations ORDER BY activated DESC"
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows]), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
