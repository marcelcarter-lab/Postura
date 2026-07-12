from app.services.risk_scoring import calculate_risk_score
from app.services.checks.base import CheckResult
from app.services.checks.schema import Severity


def _make_findings(severity, count=1, passed=False):
    """Builds `count` CheckResult objects with the given severity."""
    return [
        CheckResult(
            check_type="test_check",
            severity=severity,
            title="t",
            description="",
            passed=passed,
        )
        for _ in range(count)
    ]


def test_empty_findings_list_scores_100():
    assert calculate_risk_score([]) == 100


def test_all_passed_findings_score_100():
    # Findings that passed=True should never count as deductions,
    # regardless of their severity value.
    findings = (
        _make_findings(Severity.INFO, count=5, passed=True)
        + _make_findings(Severity.CRITICAL, count=1, passed=True)
    )
    assert calculate_risk_score(findings) == 100


def test_worked_example_from_design_task():
    # 1 CRITICAL + 2 HIGH + 3 MEDIUM + 4 LOW -> expected score 12
    # (25) + (15*2=30) + (7*3=21) + (3*4=12) = 88 deducted -> 100-88=12
    findings = (
        _make_findings(Severity.CRITICAL, count=1)
        + _make_findings(Severity.HIGH, count=2)
        + _make_findings(Severity.MEDIUM, count=3)
        + _make_findings(Severity.LOW, count=4)
    )
    assert calculate_risk_score(findings) == 12


def test_single_critical_finding():
    findings = _make_findings(Severity.CRITICAL, count=1)
    assert calculate_risk_score(findings) == 75  # 100 - 25


def test_single_high_finding():
    findings = _make_findings(Severity.HIGH, count=1)
    assert calculate_risk_score(findings) == 85  # 100 - 15


def test_single_medium_finding():
    findings = _make_findings(Severity.MEDIUM, count=1)
    assert calculate_risk_score(findings) == 93  # 100 - 7


def test_single_low_finding():
    findings = _make_findings(Severity.LOW, count=1)
    assert calculate_risk_score(findings) == 97  # 100 - 3


def test_info_findings_never_deduct_even_if_failed():
    # INFO severity has a weight of 0 by design (e.g. "could not
    # evaluate" results) — even if passed=False, they shouldn't
    # reduce the score.
    findings = _make_findings(Severity.INFO, count=10, passed=False)
    assert calculate_risk_score(findings) == 100


def test_severity_tier_cap_applies():
    # 10 LOW findings: raw deduction would be 3*10=30, but capped at
    # 15 -> expected score 100-15=85, NOT 100-30=70.
    findings = _make_findings(Severity.LOW, count=10)
    assert calculate_risk_score(findings) == 85


def test_severity_tier_cap_applies_to_medium():
    # 10 MEDIUM findings: raw deduction would be 7*10=70, capped at
    # 28 -> expected score 100-28=72.
    findings = _make_findings(Severity.MEDIUM, count=10)
    assert calculate_risk_score(findings) == 72


def test_score_floors_at_zero():
    # 10 CRITICAL findings: raw deduction would be 25*10=250, capped
    # at 60 -> 100-60=40. Add 10 HIGH too (capped at 45) -> still
    # nowhere near enough to go negative on its own, so combine with
    # enough tiers maxed out to floor at exactly 0.
    findings = (
        _make_findings(Severity.CRITICAL, count=10)  # capped at 60
        + _make_findings(Severity.HIGH, count=10)  # capped at 45
        + _make_findings(Severity.MEDIUM, count=10)  # capped at 28
    )
    # 60+45+28 = 133 deduction, far exceeding 100 -> floors at 0
    assert calculate_risk_score(findings) == 0


def test_accepts_string_severity_from_db_style_objects():
    # Finding DB rows store severity as a plain string, not a Severity
    # enum — calculate_risk_score() must handle both transparently.
    class FakeFindingRow:
        def __init__(self, severity, passed):
            self.severity = severity
            self.passed = passed

    findings = [
        FakeFindingRow(severity="critical", passed=False),
        FakeFindingRow(severity="high", passed=False),
    ]
    assert calculate_risk_score(findings) == 60  # 100 - 25 - 15
