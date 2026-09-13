import os
import sqlite3
import base64
import hashlib
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app, g


def get_db():
    """Return a request-scoped SQLite connection (opened once per request)."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """Create tables if they don't exist yet, and register cleanup."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with app.app_context():
        db = get_db()
        with open(schema_path) as f:
            db.executescript(f.read())
        columns = {row["name"] for row in db.execute("PRAGMA table_info(files)")}
        if "sha256" not in columns:
            db.execute("ALTER TABLE files ADD COLUMN sha256 TEXT")
        for column, definition in {
            "encryption_version": "INTEGER NOT NULL DEFAULT 1",
            "key_id": "TEXT NOT NULL DEFAULT 'master-v1'",
            "wrapped_key": "TEXT",
            "wrap_nonce": "TEXT",
        }.items():
            if column not in columns:
                db.execute(f"ALTER TABLE files ADD COLUMN {column} {definition}")
        audit_columns = {row["name"] for row in db.execute("PRAGMA table_info(audit_log)")}
        if "previous_hash" not in audit_columns:
            db.execute("ALTER TABLE audit_log ADD COLUMN previous_hash TEXT")
        if "entry_hash" not in audit_columns:
            db.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")
        _backfill_audit_chain(db)
        _backfill_file_fingerprints(db)
        db.commit()
    app.teardown_appcontext(close_db)


def _backfill_file_fingerprints(db):
    """Hash legacy plaintext after authenticated decryption for metadata migration."""
    key = base64.b64decode(current_app.config["MASTER_KEY"])
    rows = db.execute(
        "SELECT id, stored_filename, nonce FROM files WHERE sha256 IS NULL"
    ).fetchall()
    for row in rows:
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], row["stored_filename"])
        if not os.path.exists(path):
            continue
        with open(path, "rb") as encrypted_file:
            plaintext = AESGCM(key).decrypt(
                base64.b64decode(row["nonce"]), encrypted_file.read(), None
            )
        db.execute(
            "UPDATE files SET sha256 = ? WHERE id = ?",
            (hashlib.sha256(plaintext).hexdigest(), row["id"]),
        )


def _backfill_audit_chain(db):
    """Build a verifiable chain for legacy audit rows in insertion order."""
    rows = db.execute(
        "SELECT id, user_id, username, action, filename, ip_address, timestamp, details, entry_hash "
        "FROM audit_log ORDER BY id"
    ).fetchall()
    previous_hash = None
    for row in rows:
        payload = {
            "user_id": row["user_id"], "username": row["username"],
            "action": row["action"], "filename": row["filename"], "ip_address": row["ip_address"],
            "timestamp": row["timestamp"], "details": row["details"], "previous_hash": previous_hash,
        }
        entry_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        db.execute("UPDATE audit_log SET previous_hash = ?, entry_hash = ? WHERE id = ?", (previous_hash, entry_hash, row["id"]))
        previous_hash = entry_hash
