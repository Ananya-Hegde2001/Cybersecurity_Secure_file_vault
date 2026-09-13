import io
import hashlib
import os
import secrets
import uuid
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidTag
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    jsonify,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from audit import log_action
from audit import verify_chain
from crypto_utils import decrypt_bytes, decrypt_envelope, encrypt_envelope
from db import get_db
from decorators import login_required
from risk import calculate_risk
from threat_scan import scan_upload

vault_bp = Blueprint("vault", __name__)


def _decrypt_file_row(file_row, ciphertext):
    content_nonce = b64decode(file_row["nonce"])
    if file_row["encryption_version"] == 2:
        return decrypt_envelope(
            ciphertext,
            content_nonce,
            b64decode(file_row["wrapped_key"]),
            b64decode(file_row["wrap_nonce"]),
            file_row["key_id"],
        )
    return decrypt_bytes(ciphertext, content_nonce)


@vault_bp.route("/")
@login_required
def dashboard():
    db = get_db()
    search = request.args.get("q", "").strip()
    search_filter = f"%{search}%"
    files = db.execute(
        "SELECT id, original_filename, sha256, encryption_version, key_id, size_bytes, uploaded_at "
        "FROM files WHERE user_id = ? AND original_filename LIKE ? ORDER BY uploaded_at DESC",
        (session["user_id"], search_filter),
    ).fetchall()
    audit_entries = db.execute(
        "SELECT action, filename, ip_address, timestamp, details "
        "FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 8",
        (session["user_id"],),
    ).fetchall()
    risk = calculate_risk(audit_entries)
    total_bytes = sum(file_row["size_bytes"] for file_row in files)
    failed_events = db.execute(
        "SELECT COUNT(*) AS count FROM audit_log "
        "WHERE user_id = ? AND action IN ('login_failed', 'login_blocked_lockout', 'download_failed_integrity')",
        (session["user_id"],),
    ).fetchone()["count"]
    event_count = db.execute(
        "SELECT COUNT(*) AS count FROM audit_log WHERE user_id = ?",
        (session["user_id"],),
    ).fetchone()["count"]
    latest_event = audit_entries[0]["timestamp"] if audit_entries else "No events yet"

    # The score reflects observable account events, not a claim that the host
    # itself has been fully audited.
    security_score = max(0, 100 - risk["score"])
    stats = {
        "file_count": len(files),
        "total_bytes": total_bytes,
        "event_count": event_count,
        "failed_events": failed_events,
        "security_score": security_score,
        "latest_event": latest_event,
        "session_started": datetime.now(timezone.utc).strftime("%H:%M UTC"),
        "risk": risk,
    }
    return render_template("dashboard.html", files=files, audit_entries=audit_entries, stats=stats, search=search)


@vault_bp.route("/profile")
@login_required
def profile():
    db = get_db()
    user = db.execute(
        "SELECT username, created_at, failed_attempts, lockout_until FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    file_stats = db.execute(
        "SELECT COUNT(*) AS count, COALESCE(SUM(size_bytes), 0) AS bytes FROM files WHERE user_id = ?",
        (session["user_id"],),
    ).fetchone()
    share_stats = db.execute(
        "SELECT COUNT(*) AS count, COALESCE(SUM(download_count), 0) AS downloads "
        "FROM share_links WHERE user_id = ? AND expires_at > ? AND download_count < max_downloads",
        (session["user_id"], datetime.now(timezone.utc).isoformat()),
    ).fetchone()
    entries = db.execute(
        "SELECT action, timestamp, ip_address, details FROM audit_log WHERE user_id = ? "
        "ORDER BY timestamp DESC LIMIT 100",
        (session["user_id"],),
    ).fetchall()
    risk = calculate_risk(entries)
    unique_ips = len({entry["ip_address"] for entry in entries if entry["ip_address"]})
    return render_template(
        "profile.html",
        user=user,
        risk=risk,
        file_stats=file_stats,
        share_stats=share_stats,
        unique_ips=unique_ips,
        config_key_id=current_app.config["KEY_ID"],
        recent_entries=entries[:6],
    )


@vault_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.get("file")
    if not uploaded or uploaded.filename == "":
        flash("Choose a file first.", "warning")
        return redirect(url_for("vault.dashboard"))

    original_name = secure_filename(uploaded.filename)
    plaintext = uploaded.read()
    threat_report = scan_upload(original_name, plaintext)
    if threat_report["risk"] == "BLOCK":
        log_action("upload_blocked_threat", user_id=session["user_id"], username=session["username"], filename=original_name, details=threat_report["findings"][0]["message"])
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": "THREAT GATE BLOCKED", "report": threat_report}), 422
        flash("Upload blocked by the Threat Gate: " + threat_report["findings"][0]["message"], "danger")
        return redirect(url_for("vault.dashboard"))
    if threat_report["risk"] == "REVIEW":
        log_action("upload_flagged_review", user_id=session["user_id"], username=session["username"], filename=original_name, details=threat_report["findings"][0]["message"])
    digest = hashlib.sha256(plaintext).hexdigest()

    ciphertext, nonce, wrapped_key, wrap_nonce = encrypt_envelope(plaintext, current_app.config["KEY_ID"])

    # The name on disk is a random UUID, never the user-supplied filename —
    # that avoids any path-traversal or collision issues.
    stored_name = f"{uuid.uuid4().hex}.enc"
    stored_path = os.path.join(current_app.config["UPLOAD_FOLDER"], stored_name)
    with open(stored_path, "wb") as f:
        f.write(ciphertext)

    db = get_db()
    db.execute(
        """
        INSERT INTO files (user_id, original_filename, stored_filename, nonce, encryption_version, key_id, wrapped_key, wrap_nonce, sha256, size_bytes)
        VALUES (?, ?, ?, ?, 2, ?, ?, ?, ?, ?)
        """,
        (session["user_id"], original_name, stored_name, b64encode(nonce).decode(), current_app.config["KEY_ID"], b64encode(wrapped_key).decode(), b64encode(wrap_nonce).decode(), digest, len(plaintext)),
    )
    db.commit()
    log_action("upload", user_id=session["user_id"], username=session["username"], filename=original_name)

    flash(f'"{original_name}" was encrypted and stored.', "success")
    return redirect(url_for("vault.dashboard"))


@vault_bp.route("/download/<int:file_id>")
@login_required
def download(file_id):
    db = get_db()
    file_row = db.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()

    # Owner check: a logged-in user can only ever reach their own rows,
    # so there's no way to guess another user's file id and download it.
    if file_row is None:
        abort(404)

    stored_path = os.path.join(current_app.config["UPLOAD_FOLDER"], file_row["stored_filename"])
    with open(stored_path, "rb") as f:
        ciphertext = f.read()
    nonce = b64decode(file_row["nonce"])

    try:
        plaintext = _decrypt_file_row(file_row, ciphertext)
    except InvalidTag:
        log_action(
            "download_failed_integrity",
            user_id=session["user_id"],
            username=session["username"],
            filename=file_row["original_filename"],
        )
        flash("This file failed integrity verification and could not be decrypted.", "danger")
        return redirect(url_for("vault.dashboard"))

    log_action(
        "download",
        user_id=session["user_id"],
        username=session["username"],
        filename=file_row["original_filename"],
    )

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=file_row["original_filename"],
    )


@vault_bp.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    db = get_db()
    file_row = db.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()
    if file_row is None:
        abort(404)

    stored_path = os.path.join(current_app.config["UPLOAD_FOLDER"], file_row["stored_filename"])
    if os.path.exists(stored_path):
        os.remove(stored_path)
    db.execute("DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, session["user_id"]))
    db.commit()
    log_action("delete", user_id=session["user_id"], username=session["username"], filename=file_row["original_filename"], details="encrypted blob removed")
    flash(f'"{file_row["original_filename"]}" was securely removed.', "success")
    return redirect(url_for("vault.dashboard"))


@vault_bp.route("/share/<int:file_id>", methods=["POST"])
@login_required
def create_share(file_id):
    db = get_db()
    file_row = db.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()
    if file_row is None:
        abort(404)
    hours = request.form.get("expires_hours", "24")
    if hours not in {"1", "24", "168"}:
        hours = "24"
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=int(hours))
    db.execute(
        "INSERT INTO share_links (file_id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
        (file_id, session["user_id"], hashlib.sha256(token.encode()).hexdigest(), expires_at.isoformat()),
    )
    db.commit()
    link = url_for("vault.shared_download", token=token, _external=True)
    log_action("share_created", user_id=session["user_id"], username=session["username"], filename=file_row["original_filename"], details=f"expires {expires_at.isoformat()}")
    flash(f"Secure share created for {hours} hour(s): {link}", "success")
    return redirect(url_for("vault.dashboard"))


@vault_bp.route("/shared/<token>")
def shared_download(token):
    db = get_db()
    row = db.execute(
        "SELECT share_links.*, files.original_filename, files.stored_filename, files.nonce, "
        "files.encryption_version, files.key_id, files.wrapped_key, files.wrap_nonce, "
        "users.username FROM share_links JOIN files ON files.id = share_links.file_id "
        "JOIN users ON users.id = share_links.user_id WHERE share_links.token_hash = ?",
        (hashlib.sha256(token.encode()).hexdigest(),),
    ).fetchone()
    now = datetime.now(timezone.utc)
    if row is None or row["download_count"] >= row["max_downloads"] or now >= datetime.fromisoformat(row["expires_at"]):
        return render_template("share_expired.html"), 410
    updated = db.execute(
        "UPDATE share_links SET download_count = download_count + 1 WHERE id = ? AND download_count < max_downloads",
        (row["id"],),
    )
    if updated.rowcount != 1:
        return render_template("share_expired.html"), 410
    db.commit()
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], row["stored_filename"])
    try:
        with open(path, "rb") as encrypted_file:
            plaintext = _decrypt_file_row(row, encrypted_file.read())
    except (OSError, InvalidTag, ValueError):
        return render_template("share_expired.html", message="This share failed integrity verification."), 410
    log_action("shared_download", user_id=row["user_id"], username=row["username"], filename=row["original_filename"], details="one-time share redeemed")
    return send_file(io.BytesIO(plaintext), as_attachment=True, download_name=row["original_filename"])


@vault_bp.route("/api/integrity-scan", methods=["POST"])
@login_required
def integrity_scan():
    """Verify every owned encrypted blob without returning plaintext."""
    db = get_db()
    rows = db.execute(
        "SELECT id, original_filename, stored_filename, nonce, encryption_version, key_id, wrapped_key, wrap_nonce, sha256 "
        "FROM files WHERE user_id = ? ORDER BY id",
        (session["user_id"],),
    ).fetchall()
    results = []
    for row in rows:
        status = "VERIFIED"
        detail = "Authenticated decryption and SHA-256 match"
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], row["stored_filename"])
        try:
            if not os.path.exists(path):
                raise FileNotFoundError
            with open(path, "rb") as encrypted_file:
                plaintext = _decrypt_file_row(row, encrypted_file.read())
            if row["sha256"] and hashlib.sha256(plaintext).hexdigest() != row["sha256"]:
                status = "FINGERPRINT MISMATCH"
                detail = "Payload decrypts but its fingerprint changed"
        except (InvalidTag, FileNotFoundError, OSError, ValueError):
            status = "INTEGRITY FAILURE"
            detail = "Ciphertext missing, malformed, or authentication failed"
        results.append({"id": row["id"], "filename": row["original_filename"], "status": status, "detail": detail})

    failures = sum(result["status"] != "VERIFIED" for result in results)
    log_action(
        "integrity_scan",
        user_id=session["user_id"],
        username=session["username"],
        details=f"{len(results)} assets scanned; {failures} failure(s)",
    )
    return jsonify({"scanned": len(results), "failures": failures, "results": results})


@vault_bp.route("/api/audit-integrity", methods=["POST"])
@login_required
def audit_integrity():
    valid, broken_id = verify_chain(get_db())
    log_action("audit_chain_check", user_id=session["user_id"], username=session["username"], details="valid" if valid else f"broken at entry {broken_id}")
    return jsonify({"valid": valid, "broken_entry": broken_id})


@vault_bp.route("/audit-log")
@login_required
def audit_log():
    db = get_db()
    entries = db.execute(
        "SELECT action, filename, ip_address, timestamp, details, entry_hash, previous_hash "
        "FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 200",
        (session["user_id"],),
    ).fetchall()
    chain_valid, broken_entry = verify_chain(db)
    critical_actions = {"login_failed", "login_blocked_lockout", "download_failed_integrity"}
    warning_actions = {"delete", "share_created", "shared_download"}
    summary = {
        "total": len(entries),
        "critical": sum(entry["action"] in critical_actions for entry in entries),
        "warnings": sum(entry["action"] in warning_actions for entry in entries),
        "chain_valid": chain_valid,
        "broken_entry": broken_entry,
    }
    return render_template("audit_log.html", entries=entries, summary=summary)


@vault_bp.route("/audit-log.csv")
@login_required
def audit_log_csv():
    db = get_db()
    entries = db.execute(
        "SELECT timestamp, action, filename, ip_address, details FROM audit_log "
        "WHERE user_id = ? ORDER BY timestamp DESC LIMIT 2000",
        (session["user_id"],),
    ).fetchall()
    output = io.StringIO()
    writer = __import__("csv").writer(output)
    writer.writerow(["timestamp", "action", "filename", "ip_address", "details"])
    writer.writerows([tuple(entry) for entry in entries])
    response = current_app.make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=secure-vault-audit.csv"
    return response
