from datetime import datetime, timezone
from app.extensions import db


class Website(db.Model):
    __tablename__ = "websites"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    url = db.Column(db.String(2048), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    project = db.relationship("Project", backref=db.backref("websites", lazy=True))

    def __repr__(self):
        return f"<Website {self.url}>"
