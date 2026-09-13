from datetime import datetime, timezone


EVENT_WEIGHTS = {
    "login_failed": 18,
    "login_blocked_lockout": 35,
    "download_failed_integrity": 50,
    "shared_download": 4,
    "delete": 3,
}


def calculate_risk(entries):
    """Return a bounded, explainable score from recent security events."""
    now = datetime.now(timezone.utc)
    total = 0.0
    factors = []
    for entry in entries:
        weight = EVENT_WEIGHTS.get(entry["action"], 0)
        if not weight:
            continue
        try:
            age_hours = max(0.0, (now - datetime.fromisoformat(entry["timestamp"])).total_seconds() / 3600)
        except (TypeError, ValueError):
            age_hours = 0
        contribution = weight * (0.5 ** (age_hours / 24))
        total += contribution
        factors.append({"action": entry["action"], "impact": round(contribution)})
    risk = min(100, round(total))
    level = "CRITICAL" if risk >= 70 else "ELEVATED" if risk >= 35 else "GUARDED" if risk else "LOW"
    return {"score": risk, "level": level, "factors": factors[:5]}