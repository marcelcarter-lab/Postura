from flask import Blueprint, render_template, abort, send_file
from flask_login import login_required, current_user
from datetime import datetime, timezone

from app.models.project import Project
from app.models.website import Website
from app.models.scan import Scan
from app.services.risk_scoring import calculate_risk_score, score_to_color
from app.services.checks.schema import Severity
from app.services.reporting.report_data import build_report_data
from app.services.reporting.executive_summary import generate_executive_summary
from app.services.reporting.pdf_generator import render_report_html, generate_pdf

from io import BytesIO


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

@scan_view_bp.route("/scans/<int:scan_id>/report-preview")
@login_required
def report_preview(scan_id):
    scan = (
        Scan.query.join(Website)
        .join(Project)
        .filter(Scan.id == scan_id, Project.owner_id == current_user.id)
        .first()
    )
    if scan is None:
        abort(404, description="Scan not found")

    report = build_report_data(scan)
    executive_summary = generate_executive_summary(report)

    return render_template(
        "reports/report.html",
        report=report,
        executive_summary=executive_summary,
        generated_at=datetime.now(timezone.utc),
    )

@scan_view_bp.route("/scans/<int:scan_id>/report.pdf")
@login_required
def download_report(scan_id):
    scan = (
        Scan.query.join(Website)
        .join(Project)
        .filter(Scan.id == scan_id, Project.owner_id == current_user.id)
        .first()
    )
    if scan is None:
        abort(404, description="Scan not found")

    report = build_report_data(scan)
    executive_summary = generate_executive_summary(report)
    html = render_report_html(report, executive_summary, datetime.now(timezone.utc))
    pdf_bytes = generate_pdf(html)

    filename = f"postura-report-{report.website_name.replace(' ', '-').lower()}-{scan.id}.pdf"

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
