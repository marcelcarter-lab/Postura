from flask import Blueprint
from flask_login import login_required, current_user

main_bp = Blueprint("main", __name__)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    return f"<h1>Welcome, {current_user.email}</h1><p>Dashboard coming soon.</p>"
