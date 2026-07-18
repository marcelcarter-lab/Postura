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

    def __repr__(self):
        return f"<User {self.email}>"

    @property
    def is_admin(self):
        """Convenience property for checking admin status in routes/
        templates, e.g. `if current_user.is_admin:` — reads more
        clearly than comparing current_user.role == ROLE_ADMIN
        everywhere it's needed."""
        return self.role == ROLE_ADMIN


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
