from flask import Blueprint, render_template
from flask_login import login_required, current_user

from app.models.project import Project
from app.models.website import Website
from app.models.scan import Scan
from app.services.risk_scoring import calculate_risk_score, score_to_color

main_bp = Blueprint("main", __name__)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    websites = (
        Website.query.join(Project)
        .filter(Project.owner_id == current_user.id)
        .order_by(Website.created_at.desc())
        .all()
    )

    website_rows = []
    for website in websites:
        latest_scan = (
            Scan.query.filter_by(website_id=website.id)
            .order_by(Scan.started_at.desc())
            .first()
        )
        score = None
        score_color = None
        if latest_scan is not None:
            score = calculate_risk_score(latest_scan.findings)
            score_color = score_to_color(score)

        website_rows.append(
            {
                "website": website,
                "latest_scan": latest_scan,
                "score": score,
                "score_color": score_color,
            }
        )

    return render_template("dashboard.html", website_rows=website_rows)

@main_bp.route("/chartjs-test")
@login_required
def chartjs_test():
    return render_template("chartjs_test.html")
