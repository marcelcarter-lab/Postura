from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user

from app.extensions import db

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
def user_settings():
    if request.method == "POST":
        current_user.notify_on_critical_findings = request.form.get("notify_on_critical_findings") == "on"
        db.session.commit()
        flash("Settings updated.", "success")
        return redirect(url_for("settings.user_settings"))

    return render_template("settings/index.html")
