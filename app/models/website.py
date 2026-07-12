from datetime import datetime, timezone
from app.extensions import db


class Website(db.Model):
    __tablename__ = "websites"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    url = db.Column(db.String(2048), nullable=False)
    name = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    project = db.relationship("Project", backref=db.backref("websites", lazy=True))

    def __repr__(self):
        return f"<Website {self.url}>"

    @property
    def display_name(self):
        """Returns the user-provided name if set, otherwise falls back
        to the URL — used anywhere a website needs a human-readable
        label (dashboard, scan history, etc.)."""
        return self.name or self.url
