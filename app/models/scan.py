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

    # Sprint 10: shareable public link support. share_token is NULL
    # until a user explicitly generates a share link for this scan
    # (see "Add share-report button and link copy" task) — most scans
    # will never have one. share_token_expires_at is optional; NULL
    # means the link never expires. The report itself is still
    # generated on-demand from this scan's findings when the public
    # link is visited (see "Build public report view route") — no
    # rendered report content is persisted, consistent with this
    # project's existing "reports generated on-demand" architecture
    # decision (see architecture.md).
    share_token = db.Column(db.String(64), nullable=True, unique=True, index=True)
    share_token_expires_at = db.Column(db.DateTime, nullable=True)

    website = db.relationship(
        "Website", backref=db.backref("scans", lazy=True, cascade="all, delete-orphan")
    )

    def __repr__(self):
        return f"<Scan {self.id} website={self.website_id} status={self.status}>"

    @property
    def share_link_is_active(self):
        """Whether this scan currently has a valid, non-expired share
        token. False if no token was ever generated, or if one was
        generated but has since expired.

        Note: share_token_expires_at is stored as a naive datetime
        (this project's DateTime columns are not timezone-aware,
        consistent with every other timestamp column throughout the
        codebase — see Scan.started_at, Finding.created_at, etc.).
        Comparing it against datetime.now(timezone.utc) directly would
        raise TypeError (Python refuses to compare aware and naive
        datetimes) — so we strip tzinfo from the "now" value before
        comparing, treating both sides as naive UTC, which is what
        they represent regardless of whether tzinfo is attached.
        """
        if self.share_token is None:
            return False
        if self.share_token_expires_at is None:
            return True
        now_naive_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        return now_naive_utc < self.share_token_expires_at
