from datetime import datetime, timezone
from functools import wraps

from flask import current_app, flash, redirect, session, url_for


def login_required(view):
    """Require a logged-in user, and enforce the idle-session timeout on
    every request (not just at login time)."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))

        last_active_raw = session.get("last_active")
        if last_active_raw:
            last_active = datetime.fromisoformat(last_active_raw)
            idle_for = datetime.now(timezone.utc) - last_active
            if idle_for > current_app.config["SESSION_IDLE_TIMEOUT"]:
                session.clear()
                flash("Your session expired due to inactivity. Please log in again.", "warning")
                return redirect(url_for("auth.login"))

        # Any authenticated request resets the idle clock.
        session["last_active"] = datetime.now(timezone.utc).isoformat()
        return view(*args, **kwargs)

    return wrapped_view
