from datetime import datetime, timezone, timedelta

from app.extensions import db
from app.models.user import User
from app.models.project import Project
from app.models.website import Website
from app.services.scheduling import (
    find_due_websites,
    _reschedule_next_run,
    FREQUENCY_INTERVALS,
)


def _make_website(app):
    """Creates a throwaway User/Project/Website chain for testing,
    inside the given app's context."""
    user = User(email="scheduling-test@postura.local", password_hash="x", role="staff")
    db.session.add(user)
    db.session.commit()

    project = Project(name="Test Project", owner_id=user.id)
    db.session.add(project)
    db.session.commit()

    website = Website(project_id=project.id, url="https://example.com")
    db.session.add(website)
    db.session.commit()
    return website


def test_find_due_websites_excludes_unscheduled(app):
    with app.app_context():
        website = _make_website(app)
        website.frequency = None
        website.next_run_at = None
        db.session.commit()

        due = find_due_websites()
        assert website.id not in [w.id for w in due]


def test_find_due_websites_excludes_future_next_run(app):
    with app.app_context():
        website = _make_website(app)
        website.frequency = "daily"
        website.next_run_at = datetime.now(timezone.utc) + timedelta(hours=1)
        db.session.commit()

        due = find_due_websites()
        assert website.id not in [w.id for w in due]


def test_find_due_websites_includes_overdue(app):
    with app.app_context():
        website = _make_website(app)
        website.frequency = "daily"
        website.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.session.commit()

        due = find_due_websites()
        assert website.id in [w.id for w in due]


def test_find_due_websites_orders_most_overdue_first(app):
    with app.app_context():
        website_a = _make_website(app)
        website_a.frequency = "daily"
        website_a.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=5)

        website_b = Website(project_id=website_a.project_id, url="https://example2.com")
        db.session.add(website_b)
        db.session.commit()
        website_b.frequency = "daily"
        website_b.next_run_at = datetime.now(timezone.utc) - timedelta(hours=2)

        db.session.commit()

        due = find_due_websites()
        due_ids_in_order = [w.id for w in due if w.id in (website_a.id, website_b.id)]
        assert due_ids_in_order == [website_b.id, website_a.id]


def test_reschedule_advances_next_run_at_by_frequency(app):
    with app.app_context():
        website = _make_website(app)
        website.frequency = "weekly"
        website.next_run_at = datetime.now(timezone.utc)
        db.session.commit()

        before = datetime.now(timezone.utc)
        _reschedule_next_run(website)
        after = datetime.now(timezone.utc)

        expected_min = before + FREQUENCY_INTERVALS["weekly"]
        expected_max = after + FREQUENCY_INTERVALS["weekly"]
        assert expected_min <= website.next_run_at <= expected_max


def test_reschedule_clears_next_run_at_when_frequency_is_none(app):
    with app.app_context():
        website = _make_website(app)
        website.frequency = None
        website.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.session.commit()

        _reschedule_next_run(website)

        assert website.next_run_at is None


def test_all_frequency_intervals_are_positive_timedeltas():
    for frequency, interval in FREQUENCY_INTERVALS.items():
        assert isinstance(interval, timedelta)
        assert interval.total_seconds() > 0
