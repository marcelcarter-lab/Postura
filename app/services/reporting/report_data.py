from dataclasses import dataclass, field
from datetime import datetime

from app.services.checks.schema import Severity


@dataclass
class ReportFinding:
    """A single finding as it will appear in the report — a flattened,
    report-ready view of a Finding DB row (avoids passing raw
    SQLAlchemy model instances into templates/PDF rendering code)."""

    check_type: str
    severity: Severity
    title: str
    description: str
    evidence: str
    recommendation: str
    passed: bool


@dataclass
class RecommendationItem:
    """One entry in the prioritized recommendations list. Groups one
    or more findings that share identical recommendation text under a
    single action item, so duplicate advice (e.g. multiple headers all
    suggesting "add a security header") doesn't appear as repeated,
    near-identical bullet points."""

    text: str
    severity: Severity
    related_titles: list = field(default_factory=list)


@dataclass
class ReportData:
    """The complete, structured data needed to render a report for one
    scan. This is the single source of truth every later Sprint 4 task
    (executive summary, findings table, HTML template, PDF generation)
    should consume — built once here, not re-derived independently in
    each of those places.
    """

    website_url: str
    website_name: str
    scan_id: int
    scan_date: datetime
    risk_score: int
    score_color: str
    findings: list = field(default_factory=list)
    findings_by_severity: dict = field(default_factory=dict)
    total_findings: int = 0
    failed_findings: int = 0
    recommendations: list = field(default_factory=list)


def build_report_data(scan) -> ReportData:
    """Builds a ReportData object from a Scan DB model instance
    (expects scan.website and scan.findings relationships to be
    accessible, as set up in Sprints 0-1).
    """
    from app.services.risk_scoring import calculate_risk_score, score_to_color

    report_findings = [
        ReportFinding(
            check_type=f.check_type,
            severity=Severity(f.severity),
            title=f.title,
            description=f.description,
            evidence=f.evidence,
            recommendation=f.recommendation,
            passed=f.passed,
        )
        for f in scan.findings
    ]

    findings_by_severity = {severity: [] for severity in Severity}
    for finding in report_findings:
        findings_by_severity[finding.severity].append(finding)

    score = calculate_risk_score(scan.findings)

    return ReportData(
        website_url=scan.website.url,
        website_name=scan.website.display_name,
        scan_id=scan.id,
        scan_date=scan.started_at,
        risk_score=score,
        score_color=score_to_color(score),
        findings=report_findings,
        findings_by_severity=findings_by_severity,
        total_findings=len(report_findings),
        failed_findings=sum(1 for f in report_findings if not f.passed),
        recommendations=build_recommendations(report_findings),
    )


# Findings are ordered by severity, most urgent first, when building
# the prioritized recommendations list. INFO is excluded entirely —
# those are passed/no-issue findings with nothing actionable to
# recommend.
_RECOMMENDATION_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
]


def build_recommendations(findings: list) -> list:
    """Builds a prioritized, deduplicated list of RecommendationItem
    from a list of ReportFinding. Findings that share identical
    recommendation text are grouped into a single item (listing which
    findings it applies to), rather than repeated as separate,
    near-identical entries. Ordered by severity, most urgent first.
    """
    grouped = {}  # recommendation text -> RecommendationItem

    for severity in _RECOMMENDATION_SEVERITY_ORDER:
        for finding in findings:
            if finding.severity != severity or finding.passed or not finding.recommendation:
                continue

            key = finding.recommendation.strip()
            if key not in grouped:
                grouped[key] = RecommendationItem(
                    text=key,
                    severity=severity,
                    related_titles=[],
                )
            grouped[key].related_titles.append(finding.title)

    return list(grouped.values())
