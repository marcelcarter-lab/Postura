from flask import Blueprint, jsonify, abort
from flask_login import login_required
from datetime import datetime, timezone

from app.extensions import db
from app.models.website import Website
from app.models.scan import Scan
from app.services.scan_orchestrator import run_scan
from app.services.finding_persistence import save_findings

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/scan/<int:website_id>", methods=["POST"])
@login_required
def trigger_scan(website_id):
    website = Website.query.get(website_id)
    if website is None:
        abort(404, description="Website not found")

    scan = Scan(website_id=website.id, status="running")
    db.session.add(scan)
    db.session.commit()

    check_results = run_scan(website.url)
    findings_count = save_findings(scan.id, check_results)

    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)
    db.session.commit()

    return (
        jsonify(
            {
                "scan_id": scan.id,
                "website_id": website.id,
                "status": scan.status,
                "findings_count": findings_count,
            }
        ),
        201,
    )
