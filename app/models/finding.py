from datetime import datetime, timezone
from app.extensions import db


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    check_type = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    evidence = db.Column(db.Text, nullable=False, default="")
    recommendation = db.Column(db.Text, nullable=False, default="")
    passed = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    scan = db.relationship("Scan", backref=db.backref("findings", lazy=True))

    def __repr__(self):
        return f"<Finding {self.check_type} severity={self.severity} passed={self.passed}>"
