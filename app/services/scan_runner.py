from datetime import datetime, timezone

from app.extensions import db
from app.models.scan import Scan
from app.services.scan_orchestrator import run_scan
from app.services.finding_persistence import save_findings
from app.services.ssrf_guard import assert_safe_scan_target, SSRFBlockedError
from app.services.notifications import find_new_critical_findings, send_new_critical_finding_email


def execute_scan(website) -> Scan:
    """Runs a full scan against `website` and persists the results.
    ... (existing docstring content unchanged) ...

    After a successful scan, checks for newly-detected critical
    findings (relative to the website's previous scan, or all
    critical findings if this is the first scan) and sends an email
    notification if any are found. Email-sending failures are caught
    and logged, not allowed to fail the scan itself — a notification
    delivery problem (SMTP misconfiguration, network issue) shouldn't
    cause a genuinely completed scan to be reported as failed.
    """
    scan = Scan(website_id=website.id, status="running")
    db.session.add(scan)
    db.session.commit()

    try:
        assert_safe_scan_target(website.url)
    except SSRFBlockedError as exc:
        scan.status = "blocked"
        scan.completed_at = datetime.now(timezone.utc)
        db.session.commit()

        from app.models.finding import Finding

        blocked_finding = Finding(
            scan_id=scan.id,
            check_type="ssrf_guard",
            severity="critical",
            title="Scan blocked: target resolves to a private/internal address",
            description=str(exc),
            evidence=f"target_url={website.url}",
            recommendation="Only scan publicly reachable websites.",
            passed=False,
        )
        db.session.add(blocked_finding)
        db.session.commit()

        return scan

    check_results = run_scan(website.url)
    save_findings(scan.id, check_results)

    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)
    db.session.commit()

    _notify_if_new_critical_findings(scan)

    return scan


def _notify_if_new_critical_findings(scan):
    try:
        owner = scan.website.project.owner
        if not owner.notify_on_critical_findings:
            return

        new_critical = find_new_critical_findings(scan)
        if new_critical:
            send_new_critical_finding_email(scan, new_critical)
    except Exception:
        import logging

        logging.getLogger(__name__).exception(
            "Failed to send new-critical-finding notification for scan %s", scan.id
        )
