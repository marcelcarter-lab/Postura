from datetime import datetime, timezone

from app.extensions import db
from app.models.scan import Scan
from app.services.scan_orchestrator import run_scan
from app.services.finding_persistence import save_findings
from app.services.ssrf_guard import assert_safe_scan_target, SSRFBlockedError


def execute_scan(website) -> Scan:
    """Runs a full scan against `website` and persists the results.
    Creates the Scan row, runs all enabled checks, saves findings, and
    marks the scan completed. Before running any checks, verifies the
    target does not resolve to a private/internal IP address (SSRF
    guard) — a scan against a blocked target is recorded as a failed
    scan with an explanatory finding, rather than silently refusing or
    raising an unhandled exception up to the caller.
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

    return scan
