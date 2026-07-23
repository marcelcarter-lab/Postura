from datetime import datetime, timezone, timedelta

from app.extensions import db
from app.models.user import User
from app.models.project import Project
from app.models.website import Website
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.share_tokens import generate_share_token


def _make_scan_with_finding(share_token=None, share_token_expires_at=None):
    """Creates a User -> Project -> Website -> Scan -> Finding chain
    and returns the Scan, so each test can independently configure
    the scan's share token state without depending on other tests."""
    user = User(email="owner@example.com", password_hash="not-a-real-hash")
    db.session.add(user)
    db.session.commit()

    project = Project(name="Test Project", owner_id=user.id)
    db.session.add(project)
    db.session.commit()

    website = Website(project_id=project.id, url="http://test-target:5001")
    db.session.add(website)
    db.session.commit()

    scan = Scan(
        website_id=website.id,
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        share_token=share_token,
        share_token_expires_at=share_token_expires_at,
    )
    db.session.add(scan)
    db.session.commit()

    finding = Finding(
        scan_id=scan.id,
        check_type="header_csp",
        severity="medium",
        title="Content-Security-Policy header missing",
        description="No CSP header was found.",
        evidence="",
        recommendation="Add a Content-Security-Policy header.",
        passed=False,
    )
    db.session.add(finding)
    db.session.commit()

    return scan


def test_valid_active_token_returns_report(client, app):
    token = generate_share_token()
    _make_scan_with_finding(share_token=token)

    response = client.get(f"/shared/{token}")

    assert response.status_code == 200


def test_nonexistent_token_returns_404(client, app):
    response = client.get("/shared/this-token-was-never-generated")

    assert response.status_code == 404


def test_expired_token_returns_404(client, app):
    token = generate_share_token()
    expired_at = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None)
    _make_scan_with_finding(share_token=token, share_token_expires_at=expired_at)

    response = client.get(f"/shared/{token}")

    assert response.status_code == 404


def test_revoked_token_returns_404(client, app):
    # Simulates the state right after a user hits "revoke" — token
    # fields cleared back to None. The old token string should no
    # longer resolve to anything.
    token = generate_share_token()
    scan = _make_scan_with_finding(share_token=token)

    scan.share_token = None
    scan.share_token_expires_at = None
    db.session.commit()

    response = client.get(f"/shared/{token}")

    assert response.status_code == 404


def test_token_with_no_expiry_never_expires(client, app):
    token = generate_share_token()
    _make_scan_with_finding(share_token=token, share_token_expires_at=None)

    response = client.get(f"/shared/{token}")

    assert response.status_code == 200


def test_no_authentication_required_for_valid_token(client, app):
    # Deliberately does NOT log in or establish a session — the whole
    # point of the share-link feature is unauthenticated access.
    token = generate_share_token()
    _make_scan_with_finding(share_token=token)

    response = client.get(f"/shared/{token}")

    assert response.status_code == 200
