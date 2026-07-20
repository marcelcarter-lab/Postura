from datetime import datetime, timezone
from app.extensions import db, login_manager
from flask_login import UserMixin

ROLE_ADMIN = "admin"
ROLE_STANDARD = "standard"
VALID_ROLES = {ROLE_ADMIN, ROLE_STANDARD}


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default=ROLE_STANDARD)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Sprint 10: whether this user receives automatic email
    # notifications for newly-detected critical findings. Defaults to
    # True — an opt-out model rather than opt-in, since a security
    # tool's users likely want to know about new critical issues by
    # default, and can turn it off if they find it too noisy (see
    # "Build notification preferences UI" later in this sprint).
    notify_on_critical_findings = db.Column(db.Boolean, nullable=False, default=True)

    def __repr__(self):
        return f"<User {self.email}>"

    @property
    def is_admin(self):
        return self.role == ROLE_ADMIN


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
