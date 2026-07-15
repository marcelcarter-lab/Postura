from datetime import datetime, timezone
from app.extensions import db


class Website(db.Model):
    __tablename__ = "websites"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    url = db.Column(db.String(2048), nullable=False)
    name = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Scheduling fields (Sprint 6): frequency is one of "daily",
    # "weekly", "monthly", or NULL if scheduled scanning is disabled
    # for this website. next_run_at is the next UTC timestamp this
    # website is due for an automatic scan, or NULL if scheduling is
    # disabled. These two fields should always be in sync — both set,
    # or both NULL — enforced at the application layer (not a DB
    # constraint), since SQLAlchemy/Postgres don't easily express
    # "both or neither" nullability constraints declaratively.
    frequency = db.Column(db.String(20), nullable=True)
    next_run_at = db.Column(db.DateTime, nullable=True, index=True)

    project = db.relationship("Project", backref=db.backref("websites", lazy=True))

    def __repr__(self):
        return f"<Website {self.url}>"

    @property
    def display_name(self):
        """Returns the user-provided name if set, otherwise falls back
        to the URL — used anywhere a website needs a human-readable
        label (dashboard, scan history, etc.)."""
        return self.name or self.url
