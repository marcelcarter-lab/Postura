from datetime import datetime, timezone

from app.extensions import db
from app.models.scan import Scan
from app.services.scan_orchestrator import run_scan
from app.services.finding_persistence import save_findings


def execute_scan(website) -> Scan:
    """Runs a full scan against `website` and persists the results.
    Creates the Scan row, runs all enabled checks, saves findings, and
    marks the scan completed — the single source of truth for "what
    happens when a scan is triggered," shared by both the JSON API
    endpoint (app/routes/scan.py) and the browser-facing trigger route
    (app/routes/website.py), so there's one place this logic lives
    rather than two copies that could drift apart.
    """
    scan = Scan(website_id=website.id, status="running")
    db.session.add(scan)
    db.session.commit()

    check_results = run_scan(website.url)
    save_findings(scan.id, check_results)

    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)
    db.session.commit()

    return scan
