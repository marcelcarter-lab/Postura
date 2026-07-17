from datetime import datetime, timezone, timedelta

from app.extensions import db
from app.models.user import User
from app.models.project import Project
from app.models.website import Website
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.scan_diff import (
    diff_scans,
    diff_scans_by_id,
    find_previous_scan,
    ScanDiffError,
)


def _make_website(app):
    user = User(email="diff-test@postura.local", password_hash="x", role="staff")
    db.session.add(user)
    db.session.commit()

    project = Project(name="Test Project", owner_id=user.id)
    db.session.add(project)
    db.session.commit()

    website = Website(project_id=project.id, url="https://example.com")
    db.session.add(website)
    db.session.commit()
    return website


def _make_scan(website, started_at, findings_specs):
    scan = Scan(
        website_id=website.id,
        status="completed",
        started_at=started_at,
        completed_at=started_at + timedelta(seconds=30),
    )
    db.session.add(scan)
    db.session.commit()

    for spec in findings_specs:
        finding = Finding(
            scan_id=scan.id,
            check_type=spec["check_type"],
            severity=spec.get("severity", "medium"),
            title=spec["title"],
            description=spec.get("description", ""),
            evidence=spec.get("evidence", ""),
            recommendation=spec.get("recommendation", ""),
            passed=spec.get("passed", False),
        )
        db.session.add(finding)
    db.session.commit()
    return scan


def test_diff_scans_classifies_new_resolved_unchanged(app):
    with app.app_context():
        website = _make_website(app)
        now = datetime.now(timezone.utc)

        older_scan = _make_scan(
            website,
            now - timedelta(days=1),
            [
                {"check_type": "csp_header", "title": "Missing CSP header", "passed": False},
                {"check_type": "hsts_header", "title": "Missing HSTS header", "passed": False},
                {"check_type": "ssl_cert_validity", "title": "SSL certificate is valid", "passed": True},
            ],
        )
        newer_scan = _make_scan(
            website,
            now,
            [
                {"check_type": "csp_header", "title": "CSP configured correctly", "passed": True},
                {"check_type": "hsts_header", "title": "Missing HSTS header", "passed": False},
                {"check_type": "exposure_detection", "title": "Exposed .git directory", "passed": False},
                {"check_type": "ssl_cert_validity", "title": "SSL certificate is valid", "passed": True},
            ],
        )

        diff = diff_scans(older_scan, newer_scan)

        assert len(diff.new) == 1
        assert diff.new[0].check_type == "exposure_detection"

        assert len(diff.resolved) == 1
        assert diff.resolved[0].check_type == "csp_header"
        assert diff.resolved[0].title == "Missing CSP header"

        assert len(diff.unchanged) == 2
        unchanged_check_types = {f.check_type for f in diff.unchanged}
        assert unchanged_check_types == {"hsts_header", "ssl_cert_validity"}


def test_diff_scans_no_findings_at_all():
    pass  # placeholder to be replaced below


def test_diff_scans_empty_scans(app):
    with app.app_context():
        website = _make_website(app)
        now = datetime.now(timezone.utc)

        older_scan = _make_scan(website, now - timedelta(days=1), [])
        newer_scan = _make_scan(website, now, [])

        diff = diff_scans(older_scan, newer_scan)

        assert diff.new == []
        assert diff.resolved == []
        assert diff.unchanged == []


def test_diff_scans_by_id_auto_orders_regardless_of_argument_order(app):
    with app.app_context():
        website = _make_website(app)
        now = datetime.now(timezone.utc)

        older_scan = _make_scan(
            website,
            now - timedelta(days=1),
            [{"check_type": "csp_header", "title": "Missing CSP header", "passed": False}],
        )
        newer_scan = _make_scan(website, now, [])

        # Pass newer scan ID first, older second — deliberately reversed
        diff_forward = diff_scans_by_id(newer_scan.id, older_scan.id)
        diff_reversed = diff_scans_by_id(older_scan.id, newer_scan.id)

        # Both should produce the identical classification regardless
        # of argument order, since the function determines
        # chronological order internally.
        assert len(diff_forward.resolved) == 1
        assert len(diff_reversed.resolved) == 1
        assert diff_forward.resolved[0].id == diff_reversed.resolved[0].id


def test_diff_scans_by_id_rejects_nonexistent_scan(app):
    with app.app_context():
        website = _make_website(app)
        scan = _make_scan(website, datetime.now(timezone.utc), [])

        try:
            diff_scans_by_id(999999, scan.id)
            assert False, "Expected ScanDiffError"
        except ScanDiffError:
            pass


def test_diff_scans_by_id_rejects_different_websites(app):
    with app.app_context():
        website_a = _make_website(app)
        user_b = User(email="other@postura.local", password_hash="x", role="staff")
        db.session.add(user_b)
        db.session.commit()
        project_b = Project(name="Other Project", owner_id=user_b.id)
        db.session.add(project_b)
        db.session.commit()
        website_b = Website(project_id=project_b.id, url="https://different-site.com")
        db.session.add(website_b)
        db.session.commit()

        scan_a = _make_scan(website_a, datetime.now(timezone.utc), [])
        scan_b = _make_scan(website_b, datetime.now(timezone.utc), [])

        try:
            diff_scans_by_id(scan_a.id, scan_b.id)
            assert False, "Expected ScanDiffError"
        except ScanDiffError:
            pass


def test_diff_scans_by_id_rejects_comparing_scan_with_itself(app):
    with app.app_context():
        website = _make_website(app)
        scan = _make_scan(website, datetime.now(timezone.utc), [])

        try:
            diff_scans_by_id(scan.id, scan.id)
            assert False, "Expected ScanDiffError"
        except ScanDiffError:
            pass


def test_find_previous_scan_returns_none_for_first_scan(app):
    with app.app_context():
        website = _make_website(app)
        scan = _make_scan(website, datetime.now(timezone.utc), [])

        assert find_previous_scan(scan) is None


def test_find_previous_scan_returns_immediately_prior_scan(app):
    with app.app_context():
        website = _make_website(app)
        now = datetime.now(timezone.utc)

        scan_1 = _make_scan(website, now - timedelta(days=2), [])
        scan_2 = _make_scan(website, now - timedelta(days=1), [])
        scan_3 = _make_scan(website, now, [])

        assert find_previous_scan(scan_3).id == scan_2.id
        assert find_previous_scan(scan_2).id == scan_1.id
        assert find_previous_scan(scan_1) is None
