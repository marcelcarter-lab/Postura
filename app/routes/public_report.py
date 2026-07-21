from datetime import datetime, timezone

from flask import Blueprint, render_template, abort

from app.models.scan import Scan
from app.services.reporting.report_data import build_report_data
from app.services.reporting.executive_summary import generate_executive_summary

public_report_bp = Blueprint("public_report", __name__)


@public_report_bp.route("/shared/<token>")
def public_report_view(token):
    """Public, no-authentication view of a scan's report, gated by
    possession of a valid share token rather than a logged-in
    session. Deliberately a separate blueprint/route from the
    authenticated scan_detail/download_report routes (scan_view.py) —
    keeping "requires login" and "requires a valid token" as
    completely distinct access paths, rather than threading token
    logic into the same routes that also handle session-based auth,
    which would risk accidentally weakening the authenticated routes'
    access control while adding this feature.
    """
    scan = Scan.query.filter_by(share_token=token).first()

    if scan is None or not scan.share_link_is_active:
        # Deliberately the same 404 for "token doesn't exist" and
        # "token exists but expired" — not distinguishing them in the
        # response avoids leaking information about whether a given
        # token string was ever valid at all, a minor but real
        # information-disclosure consideration for a public,
        # unauthenticated endpoint.
        abort(404, description="This shared report link is invalid or has expired.")

    report = build_report_data(scan)
    executive_summary = generate_executive_summary(report)

    return render_template(
        "reports/report.html",
        report=report,
        executive_summary=executive_summary,
        generated_at=datetime.now(timezone.utc),
    )
