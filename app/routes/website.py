from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from datetime import datetime, timezone

from app.extensions import db
from app.models.project import Project
from app.models.website import Website

from app.models.scan import Scan
from app.services.risk_scoring import calculate_risk_score, score_to_color
from app.services.scan_runner import execute_scan
from app.services.url_validation import validate_website_url
from app.services.scheduling import FREQUENCY_INTERVALS
from app.services.scan_diff import find_previous_scan

website_bp = Blueprint("website", __name__)


def _get_or_create_default_project():
    """Returns the current user's first project, creating a default
    one if they have none yet. Avoids blocking the add-website flow
    on a project-management UI that doesn't exist yet (not part of
    this sprint's scope)."""
    project = Project.query.filter_by(owner_id=current_user.id).first()
    if project is None:
        project = Project(name="My Projects", owner_id=current_user.id)
        db.session.add(project)
        db.session.commit()
    return project


@website_bp.route("/websites/add", methods=["GET", "POST"])
@login_required
def add_website():
    projects = Project.query.filter_by(owner_id=current_user.id).all()

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        project_id = request.form.get("project_id", "").strip()

        error = validate_website_url(url)

        if not error:
            project = Project.query.filter_by(
                id=project_id, owner_id=current_user.id
            ).first()
            if project is None:
                error = "Invalid project selected."

        if error:
            flash(error, "danger")
            return render_template("website/add.html", projects=projects, url=url)

        website = Website(project_id=project.id, url=url)
        db.session.add(website)
        db.session.commit()

        flash("Website added successfully.", "success")
        return redirect(url_for("main.dashboard"))

    if not projects:
        _get_or_create_default_project()
        projects = Project.query.filter_by(owner_id=current_user.id).all()

    return render_template("website/add.html", projects=projects, url="")

@website_bp.route("/websites/<int:website_id>/edit", methods=["GET", "POST"])
@login_required
def edit_website(website_id):
    website = Website.query.join(Project).filter(
        Website.id == website_id, Project.owner_id == current_user.id
    ).first()
    if website is None:
        abort(404, description="Website not found")

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        name = request.form.get("name", "").strip()

        error = validate_website_url(url)

        if error:
            flash(error, "danger")
            return render_template(
                "website/edit.html", website=website, url=url, name=name
            )

        website.url = url
        website.name = name or None

        schedule_enabled = request.form.get("schedule_enabled") == "on"
        selected_frequency = request.form.get("frequency", "daily")

        if schedule_enabled:
            if selected_frequency not in FREQUENCY_INTERVALS:
                selected_frequency = "daily"

            if website.frequency != selected_frequency:
                # Frequency is newly enabled, or was changed to a
                # different cadence — (re)set next_run_at from now,
                # using the newly selected interval.
                website.frequency = selected_frequency
                website.next_run_at = datetime.now(timezone.utc) + FREQUENCY_INTERVALS[selected_frequency]
        else:
            website.frequency = None
            website.next_run_at = None

        db.session.commit()

        flash("Website updated successfully.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template(
        "website/edit.html", website=website, url=website.url, name=website.name or ""
    )

@website_bp.route("/websites/<int:website_id>/delete", methods=["POST"])
@login_required
def delete_website(website_id):
    website = Website.query.join(Project).filter(
        Website.id == website_id, Project.owner_id == current_user.id
    ).first()
    if website is None:
        abort(404, description="Website not found")

    db.session.delete(website)
    db.session.commit()

    flash("Website and all associated scan history deleted.", "info")
    return redirect(url_for("main.dashboard"))


@website_bp.route("/websites/<int:website_id>/history")
@login_required
def scan_history(website_id):
    website = Website.query.join(Project).filter(
        Website.id == website_id, Project.owner_id == current_user.id
    ).first()
    if website is None:
        abort(404, description="Website not found")

    scans = (
        Scan.query.filter_by(website_id=website.id)
        .order_by(Scan.started_at.desc())
        .all()
    )

    scan_rows = []
    for scan in scans:
        score = None
        score_color = None
        trend = None
        if scan.status == "completed":
            score = calculate_risk_score(scan.findings)
            score_color = score_to_color(score)

            previous_scan = find_previous_scan(scan)
            if previous_scan is not None:
                previous_score = calculate_risk_score(previous_scan.findings)
                if score > previous_score:
                    trend = "up"
                elif score < previous_score:
                    trend = "down"
                else:
                    trend = "flat"
            # If there's no previous scan, trend stays None — the
            # website's first scan has nothing to compare against, so
            # no trend indicator should show for it.

        scan_rows.append(
            {"scan": scan, "score": score, "score_color": score_color, "trend": trend}
        )

    return render_template("website/history.html", website=website, scan_rows=scan_rows)

@website_bp.route("/websites/<int:website_id>/scan", methods=["POST"])
@login_required
def trigger_scan_ui(website_id):
    website = Website.query.join(Project).filter(
        Website.id == website_id, Project.owner_id == current_user.id
    ).first()
    if website is None:
        abort(404, description="Website not found")

    scan = execute_scan(website)

    flash("Scan completed.", "success")
    return redirect(url_for("scan_view.scan_detail", scan_id=scan.id))
