from flask import Blueprint, jsonify, abort
from flask_login import login_required, current_user

from app.models.project import Project
from app.models.website import Website
from app.services.scan_runner import execute_scan

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/scan/<int:website_id>", methods=["POST"])
@login_required
def trigger_scan(website_id):
    website = Website.query.join(Project).filter(
        Website.id == website_id, Project.owner_id == current_user.id
    ).first()
    if website is None:
        abort(404, description="Website not found")

    scan = execute_scan(website)

    return (
        jsonify(
            {
                "scan_id": scan.id,
                "website_id": website.id,
                "status": scan.status,
                "findings_count": len(scan.findings),
            }
        ),
        201,
    )
