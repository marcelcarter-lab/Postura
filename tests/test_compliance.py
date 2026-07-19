from datetime import datetime, timezone, timedelta

from app.extensions import db
from app.models.user import User
from app.models.project import Project
from app.models.website import Website
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.compliance.owasp_mapping import get_owasp_category
from app.services.compliance.compliance_scoring import calculate_compliance_by_category
from app.services.compliance.trend_data import get_score_trend_data


def _make_finding(check_type, passed):
    """A lightweight stand-in object with just the attributes
    calculate_compliance_by_category() actually reads, avoiding the
    need for a real DB-backed Finding row for these pure-logic tests."""

    class FakeFinding:
        def __init__(self, check_type, passed):
            self.check_type = check_type
            self.passed = passed

    return FakeFinding(check_type, passed)


def test_get_owasp_category_known_check_type():
    category = get_owasp_category("csp_header")
    assert category == "A05:2021 - Security Misconfiguration"


def test_get_owasp_category_unmapped_check_type_returns_uncategorized():
    category = get_owasp_category("some_future_check_not_yet_mapped")
    assert category == "Uncategorized"


def test_all_enabled_checks_have_a_real_owasp_mapping():
    """Guards against the exact gap flagged in
    docs/owasp-mapping-rationale.md's maintenance note: every check in
    ENABLED_CHECKS should have a real (non-"Uncategorized") mapping.
    This test would fail the moment a new check is added to the
    orchestrator without a corresponding mapping table entry —
    converting that documented manual convention into an enforced one.
    """
    from app.services.scan_orchestrator import ENABLED_CHECKS

    unmapped = [
        check_class.check_type
        for check_class in ENABLED_CHECKS
        if get_owasp_category(check_class.check_type) == "Uncategorized"
    ]
    assert unmapped == [], f"These checks have no OWASP mapping: {unmapped}"


def test_calculate_compliance_by_category_computes_correct_percentages():
    findings = [
        _make_finding("csp_header", True),
        _make_finding("hsts_header", False),
        _make_finding("x_frame_options", True),
        _make_finding("ssl_cert_validity", True),
        _make_finding("tls_protocol_strength", True),
        _make_finding("server_header_disclosure", False),
        _make_finding("wordpress_version", False),
    ]

    results = calculate_compliance_by_category(findings)
    by_category = {r.category: r for r in results}

    misconfig = by_category["A05:2021 - Security Misconfiguration"]
    assert misconfig.passed_count == 2
    assert misconfig.total_count == 3
    assert misconfig.percentage == 67

    crypto = by_category["A02:2021 - Cryptographic Failures"]
    assert crypto.passed_count == 2
    assert crypto.total_count == 2
    assert crypto.percentage == 100

    components = by_category["A06:2021 - Vulnerable and Outdated Components"]
    assert components.passed_count == 0
    assert components.total_count == 2
    assert components.percentage == 0


def test_calculate_compliance_excludes_unmapped_check_types():
    findings = [
        _make_finding("csp_header", True),
        _make_finding("some_future_check_not_yet_mapped", True),
    ]

    results = calculate_compliance_by_category(findings)
    categories = [r.category for r in results]

    assert len(results) == 1
    assert "Uncategorized" not in categories


def test_calculate_compliance_empty_findings_list_returns_empty():
    results = calculate_compliance_by_category([])
    assert results == []


def test_calculate_compliance_results_sorted_by_category_name():
    findings = [
        _make_finding("wordpress_version", True),  # A06
        _make_finding("csp_header", True),  # A05
        _make_finding("ssl_cert_validity", True),  # A02
    ]

    results = calculate_compliance_by_category(findings)
    categories_in_order = [r.category for r in results]

    assert categories_in_order == sorted(categories_in_order)


def _make_website_with_scans(app, scores_and_days_ago):
    user = User(email="compliance-test@postura.local", password_hash="x", role="staff")
    db.session.add(user)
    db.session.commit()

    project = Project(name="Test Project", owner_id=user.id)
    db.session.add(project)
    db.session.commit()

    website = Website(project_id=project.id, url="https://example.com")
    db.session.add(website)
    db.session.commit()

    for score, days_ago in scores_and_days_ago:
        scan = Scan(
            website_id=website.id,
            status="completed",
            started_at=datetime.now(timezone.utc) - timedelta(days=days_ago),
            completed_at=datetime.now(timezone.utc) - timedelta(days=days_ago) + timedelta(seconds=30),
        )
        db.session.add(scan)
        db.session.commit()

        # A single passed INFO finding gives a scan a clean 100 score;
        # to get an arbitrary target score, add enough failed MEDIUM
        # findings to deduct down to it (100 - 7*n, capped at 28) —
        # simpler for this test: just add exactly the finding(s)
        # needed for a couple of known, easy-to-reason-about scores.
        if score < 100:
            deduction_needed = 100 - score
            # MEDIUM findings deduct 7 each, capped at 28 total
            num_medium = min(deduction_needed // 7, 4)
            for i in range(num_medium):
                db.session.add(
                    Finding(
                        scan_id=scan.id,
                        check_type=f"filler_check_{i}",
                        severity="medium",
                        title="filler",
                        description="",
                        evidence="",
                        recommendation="",
                        passed=False,
                    )
                )
        db.session.commit()

    return website


def test_get_score_trend_data_returns_chronological_order(app):
    with app.app_context():
        website = _make_website_with_scans(app, [(100, 2), (72, 1), (100, 0)])

        trend = get_score_trend_data(website.id)

        assert len(trend["labels"]) == 3
        assert len(trend["scores"]) == 3
        # Oldest (2 days ago) first, most recent (today) last
        assert trend["scores"][0] == 100
        assert trend["scores"][-1] == 100


def test_get_score_trend_data_empty_for_website_with_no_scans(app):
    with app.app_context():
        website = _make_website_with_scans(app, [])
        trend = get_score_trend_data(website.id)

        assert trend["labels"] == []
        assert trend["scores"] == []


def test_get_score_trend_data_nonexistent_website_returns_empty(app):
    with app.app_context():
        trend = get_score_trend_data(999999)
        assert trend["labels"] == []
        assert trend["scores"] == []
