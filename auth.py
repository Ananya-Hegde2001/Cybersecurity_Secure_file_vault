from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from audit import log_action
from db import get_db

auth_bp = Blueprint("auth", __name__)

USERNAME_MIN_LEN = 3
PASSWORD_MIN_LEN = 8


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = None
        if len(username) < USERNAME_MIN_LEN:
            error = f"Username must be at least {USERNAME_MIN_LEN} characters."
        elif len(password) < PASSWORD_MIN_LEN:
            error = f"Password must be at least {PASSWORD_MIN_LEN} characters."
        elif password != confirm:
            error = "Passwords do not match."

        db = get_db()
        if error is None:
            existing = db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing is not None:
                error = "That username is already taken."

        if error:
            flash(error, "danger")
            return render_template("register.html", username=username)

        # werkzeug's default hashing method (scrypt) is a slow, salted KDF —
        # appropriate for password storage, unlike a fast hash like SHA-256.
        password_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
        log_action("register", username=username)
        flash("Account created. You can log in now.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", username="")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Check account lockout first, before touching the password at all.
        if user and user["lockout_until"]:
            lockout_until = datetime.fromisoformat(user["lockout_until"])
            if datetime.now(timezone.utc) < lockout_until:
                remaining = int((lockout_until - datetime.now(timezone.utc)).total_seconds() // 60) + 1
                flash(f"Account locked. Try again in about {remaining} minute(s).", "danger")
                log_action("login_blocked_lockout", user_id=user["id"], username=username)
                return render_template("login.html", username=username)

        # Deliberately use the same generic error whether the username
        # doesn't exist or the password is wrong, so an attacker can't use
        # this form to enumerate valid usernames.
        valid = user is not None and check_password_hash(user["password_hash"], password)

        if valid:
            db.execute(
                "UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?",
                (user["id"],),
            )
            db.commit()
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            log_action("login_success", user_id=user["id"], username=username)
            return redirect(url_for("vault.dashboard"))

        just_locked = False
        if user:
            attempts = user["failed_attempts"] + 1
            lockout_until = None
            if attempts >= current_app.config["MAX_FAILED_ATTEMPTS"]:
                lockout_until = (
                    datetime.now(timezone.utc) + current_app.config["LOCKOUT_DURATION"]
                ).isoformat()
                attempts = 0  # reset counter; lockout window now governs access
                just_locked = True
            db.execute(
                "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?",
                (attempts, lockout_until, user["id"]),
            )
            db.commit()

        if just_locked:
            minutes = int(current_app.config["LOCKOUT_DURATION"].total_seconds() // 60)
            log_action("login_blocked_lockout", user_id=user["id"], username=username)
            flash(f"Too many failed attempts. Account locked for {minutes} minutes.", "danger")
        else:
            log_action("login_failed", user_id=user["id"] if user else None, username=username)
            flash("Invalid username or password.", "danger")
        return render_template("login.html", username=username)

    return render_template("login.html", username="")


@auth_bp.route("/logout")
def logout():
    username = session.get("username")
    user_id = session.get("user_id")
    session.clear()
    if user_id:
        log_action("logout", user_id=user_id, username=username)
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
