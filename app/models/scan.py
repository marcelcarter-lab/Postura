from datetime import datetime, timezone
from app.extensions import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(
        db.Integer, db.ForeignKey("websites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status = db.Column(db.String(20), nullable=False, default="pending")
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)

    website = db.relationship(
        "Website", backref=db.backref("scans", lazy=True, cascade="all, delete-orphan")
    )

    def __repr__(self):
        return f"<Scan {self.id} website={self.website_id} status={self.status}>"
