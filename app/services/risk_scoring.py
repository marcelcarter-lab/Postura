from app.services.checks.schema import Severity

# Points deducted per finding, and the maximum total deduction any
# single severity tier can contribute — prevents many low-severity
# findings from dominating the score the way one severe finding does.
# See "Design risk scoring formula" task for full reasoning.
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

SEVERITY_CAPS = {
    Severity.CRITICAL: 60,
    Severity.HIGH: 45,
    Severity.MEDIUM: 28,
    Severity.LOW: 15,
    Severity.INFO: 0,
}

MAX_SCORE = 100
MIN_SCORE = 0


def calculate_risk_score(findings: list) -> int:
    """Computes a 0-100 risk score from a list of findings, starting
    at a perfect 100 and deducting points per failed finding, weighted
    by severity, with a per-severity-tier cap so many findings of the
    same severity have diminishing marginal impact rather than
    stacking linearly forever.

    `findings` can be a list of CheckResult objects (severity as a
    Severity enum) or Finding DB model rows (severity as a plain
    string) — both are normalized internally, since this function may
    be called either right after a scan (on in-memory CheckResults,
    before persistence) or later when recomputing a score from stored
    Finding rows.

    Only findings with passed=False count toward deductions — a
    passing/INFO result contributes nothing, whether or not it's
    included in the list.
    """
    counts_by_severity = {severity: 0 for severity in Severity}

    for finding in findings:
        if getattr(finding, "passed", True):
            continue

        severity = _normalize_severity(finding.severity)
        counts_by_severity[severity] += 1

    total_deduction = 0
    for severity, count in counts_by_severity.items():
        weight = SEVERITY_WEIGHTS[severity]
        cap = SEVERITY_CAPS[severity]
        total_deduction += min(weight * count, cap)

    score = MAX_SCORE - total_deduction
    return max(MIN_SCORE, min(MAX_SCORE, score))


def _normalize_severity(severity) -> Severity:
    """Accepts either a Severity enum member or a plain string (e.g.
    from a Finding DB row where severity is stored as String(20)) and
    returns a Severity enum member."""
    if isinstance(severity, Severity):
        return severity
    return Severity(severity)

SCORE_COLOR_THRESHOLDS = {
    "danger": (0, 49),
    "warning": (50, 79),
    "success": (80, 100),
}


def score_to_color(score: int) -> str:
    """Maps a 0-100 risk score to a Bootstrap color class name
    (danger/warning/success), used for badge color-coding in the
    dashboard. Thresholds are a judgment call — see Sprint 3's "Add
    score color-coding to dashboard" task notes for reasoning."""
    for color, (low, high) in SCORE_COLOR_THRESHOLDS.items():
        if low <= score <= high:
            return color
    return "secondary"  # fallback, should be unreachable for valid 0-100 scores
