import hashlib
import json
from datetime import datetime, timezone

from flask import request

from db import get_db


def log_action(action: str, user_id: int | None = None, username: str | None = None,
                filename: str | None = None, details: str | None = None):
    """Write one row to audit_log. Called on every login attempt, upload,
    download, and logout so there's a full who/when/what trail."""
    db = get_db()
    timestamp = datetime.now(timezone.utc).isoformat()
    previous = db.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous["entry_hash"] if previous else None
    payload = {
        "user_id": user_id, "username": username, "action": action, "filename": filename,
        "ip_address": request.remote_addr, "timestamp": timestamp, "details": details,
        "previous_hash": previous_hash,
    }
    entry_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    db.execute(
        """
        INSERT INTO audit_log (user_id, username, action, filename, ip_address, timestamp, details, previous_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, username, action, filename, request.remote_addr, timestamp, details, previous_hash, entry_hash),
    )
    db.commit()


def verify_chain(db):
    rows = db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    previous_hash = None
    for row in rows:
        payload = {"user_id": row["user_id"], "username": row["username"], "action": row["action"], "filename": row["filename"], "ip_address": row["ip_address"], "timestamp": row["timestamp"], "details": row["details"], "previous_hash": previous_hash}
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if row["previous_hash"] != previous_hash or row["entry_hash"] != expected:
            return False, row["id"]
        previous_hash = row["entry_hash"]
    return True, None
