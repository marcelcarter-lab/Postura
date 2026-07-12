from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user

from app.models.project import Project
from app.models.website import Website
from app.models.scan import Scan
from app.services.risk_scoring import calculate_risk_score, score_to_color
from app.services.checks.schema import Severity

scan_view_bp = Blueprint("scan_view", __name__)

# Order findings should be grouped/displayed in, most severe first.
SEVERITY_DISPLAY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


@scan_view_bp.route("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    scan = (
        Scan.query.join(Website)
        .join(Project)
        .filter(Scan.id == scan_id, Project.owner_id == current_user.id)
        .first()
    )
    if scan is None:
        abort(404, description="Scan not found")

    findings_by_severity = {severity: [] for severity in SEVERITY_DISPLAY_ORDER}
    for finding in scan.findings:
        severity = Severity(finding.severity)
        findings_by_severity[severity].append(finding)

    score = calculate_risk_score(scan.findings)
    score_color = score_to_color(score)

    return render_template(
        "scan/detail.html",
        scan=scan,
        website=scan.website,
        score=score,
        score_color=score_color,
        findings_by_severity=findings_by_severity,
        severity_order=SEVERITY_DISPLAY_ORDER,
    )
