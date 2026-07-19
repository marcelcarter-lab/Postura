from flask import Blueprint, render_template, abort, send_file, redirect, url_for, flash, request, jsonify
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
from app.services.scan_diff import diff_scans_by_id, ScanDiffError, find_previous_scan
from app.services.reporting.report_data import build_report_data, report_data_to_dict
from app.services.compliance.compliance_scoring import calculate_compliance_by_category

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
    previous_scan = find_previous_scan(scan)
    compliance_breakdown = calculate_compliance_by_category(scan.findings)

    return render_template(
        "scan/detail.html",
        scan=scan,
        website=scan.website,
        score=score,
        score_color=score_color,
        findings_by_severity=findings_by_severity,
        severity_order=SEVERITY_DISPLAY_ORDER,
        previous_scan=previous_scan,
        compliance_breakdown=compliance_breakdown,
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

@scan_view_bp.route("/scans/compare")
@login_required
def compare_scans():
    scan_ids = request.args.getlist("scan_id", type=int)

    if len(scan_ids) != 2:
        flash("Please select exactly two scans to compare.", "danger")
        return redirect(request.referrer or url_for("main.dashboard"))

    scan_id_a, scan_id_b = scan_ids

    owned_scans = (
        Scan.query.join(Website)
        .join(Project)
        .filter(
            Scan.id.in_([scan_id_a, scan_id_b]),
            Project.owner_id == current_user.id,
        )
        .all()
    )
    owned_scan_ids = {s.id for s in owned_scans}
    if scan_id_a not in owned_scan_ids or scan_id_b not in owned_scan_ids:
        abort(404, description="One or both scans not found")

    try:
        diff = diff_scans_by_id(scan_id_a, scan_id_b)
    except ScanDiffError as exc:
        flash(str(exc), "danger")
        return redirect(request.referrer or url_for("main.dashboard"))

    # Determine which loaded scan is older/newer for display purposes
    # (diff_scans_by_id already did this internally, but the route
    # needs the actual Scan objects too, for showing dates/website
    # info in the template header).
    scan_a = next(s for s in owned_scans if s.id == scan_id_a)
    scan_b = next(s for s in owned_scans if s.id == scan_id_b)
    older_scan, newer_scan = (
        (scan_a, scan_b) if scan_a.started_at <= scan_b.started_at else (scan_b, scan_a)
    )

    older_score = calculate_risk_score(older_scan.findings)
    newer_score = calculate_risk_score(newer_scan.findings)
    score_delta = newer_score - older_score

    return render_template(
        "scan/compare.html",
        website=newer_scan.website,
        older_scan=older_scan,
        newer_scan=newer_scan,
        older_score=older_score,
        newer_score=newer_score,
        score_delta=score_delta,
        diff=diff,
    )

@scan_view_bp.route("/scans/<int:scan_id>/export.json")
@login_required
def export_scan_json(scan_id):
    scan = (
        Scan.query.join(Website)
        .join(Project)
        .filter(Scan.id == scan_id, Project.owner_id == current_user.id)
        .first()
    )
    if scan is None:
        abort(404, description="Scan not found")

    report = build_report_data(scan)
    data = report_data_to_dict(report)

    filename = f"postura-export-{report.website_name.replace(' ', '-').lower()}-{scan.id}.json"

    response = jsonify(data)
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response
