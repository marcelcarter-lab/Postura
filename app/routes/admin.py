from flask import Blueprint, render_template
from flask_login import login_required

from app.models.user import User
from app.services.auth_guards import admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/users")
@login_required
@admin_required
def user_list():
    users = User.query.order_by(User.created_at.asc()).all()
    return render_template("admin/users.html", users=users)
