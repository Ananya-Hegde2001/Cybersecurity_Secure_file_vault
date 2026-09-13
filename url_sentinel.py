from flask import Blueprint, render_template, request, session

from audit import log_action
from decorators import login_required
from url_scanner import analyze_url

url_sentinel_bp = Blueprint("url_sentinel", __name__)


@url_sentinel_bp.route("/url-sentinel", methods=["GET", "POST"])
@login_required
def url_sentinel():
    result = None
    if request.method == "POST":
        raw_url = request.form.get("url", "")
        result = analyze_url(raw_url)
        log_action(
            "url_analysis",
            user_id=session["user_id"],
            username=session["username"],
            details=f"{result['verdict']} / score {result['risk_score']} / host {result['hostname']}",
        )
    return render_template("url_sentinel.html", result=result)
