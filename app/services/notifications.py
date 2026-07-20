from flask import render_template, current_app
from flask_mail import Message

from app.extensions import mail
from app.services.checks.schema import Severity
from app.services.scan_diff import find_previous_scan, diff_scans


def find_new_critical_findings(scan):
    """..."""  # unchanged from last task
    critical_findings = [f for f in scan.findings if Severity(f.severity) == Severity.CRITICAL]

    if not critical_findings:
        return []

    previous_scan = find_previous_scan(scan)
    if previous_scan is None:
        return critical_findings

    diff = diff_scans(previous_scan, scan)
    new_check_type_titles = {(f.check_type, f.title) for f in diff.new}

    return [f for f in critical_findings if (f.check_type, f.title) in new_check_type_titles]


def send_new_critical_finding_email(scan, new_critical_findings):
    """Sends an email notification for newly-detected critical
    findings on a completed scan. Caller is responsible for deciding
    WHETHER to send and for calling find_new_critical_findings() first
    to determine WHAT to send; this function only composes and
    dispatches the email itself.
    """
    website = scan.website
    recipient = website.project.owner.email

    subject = f"[Postura] {len(new_critical_findings)} new critical finding(s) — {website.display_name}"

    report_url = f"{current_app.config['APP_BASE_URL']}/scans/{scan.id}"

    body = render_template(
        "email/new_critical_findings.txt",
        website=website,
        scan=scan,
        findings=new_critical_findings,
        report_url=report_url,
    )

    message = Message(subject=subject, recipients=[recipient], body=body)
    mail.send(message)
