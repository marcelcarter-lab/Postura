from app.services.reporting.report_data import ReportData
from app.services.checks.schema import Severity

# Plain-language descriptors for the overall score, used to open the
# summary with an immediately understandable headline before any
# specifics. Thresholds intentionally match score_to_color()'s ranges
# (danger/warning/success) for consistency between the visual badge
# and the written narrative.
SCORE_DESCRIPTORS = {
    "success": "in a strong security position",
    "warning": "in a reasonable security position, with some notable gaps",
    "danger": "in a weak security position, with significant issues that need attention",
}


def generate_executive_summary(report: ReportData) -> str:
    """Generates a short, plain-language paragraph summarizing the
    scan's overall security posture — written for a non-technical
    reader (e.g. an agency's client), avoiding jargon like specific
    header/protocol names. Template-based (not free-form generated
    text) so output is deterministic and testable.
    """
    critical_count = len(report.findings_by_severity.get(Severity.CRITICAL, []))
    high_count = len(report.findings_by_severity.get(Severity.HIGH, []))
    medium_count = len(report.findings_by_severity.get(Severity.MEDIUM, []))
    low_count = len(report.findings_by_severity.get(Severity.LOW, []))

    descriptor = SCORE_DESCRIPTORS.get(report.score_color, "in an undetermined security position")

    sentences = [
        f"{report.website_name} is currently {descriptor}, with an overall "
        f"security score of {report.risk_score} out of 100."
    ]

    if report.failed_findings == 0:
        sentences.append(
            "No security issues were identified during this scan. "
            "We recommend periodic re-scanning to maintain this posture "
            "as the site evolves."
        )
    else:
        issue_summary_parts = []
        if critical_count:
            issue_summary_parts.append(
                f"{critical_count} critical issue{'s' if critical_count != 1 else ''} "
                "requiring immediate attention"
            )
        if high_count:
            issue_summary_parts.append(
                f"{high_count} high-priority issue{'s' if high_count != 1 else ''}"
            )
        if medium_count:
            issue_summary_parts.append(
                f"{medium_count} moderate issue{'s' if medium_count != 1 else ''}"
            )
        if low_count:
            issue_summary_parts.append(
                f"{low_count} minor issue{'s' if low_count != 1 else ''}"
            )

        if issue_summary_parts:
            joined = _join_with_commas_and_and(issue_summary_parts)
            sentences.append(f"This scan identified {joined}.")

        if critical_count or high_count:
            sentences.append(
                "We strongly recommend addressing the critical and "
                "high-priority items as soon as possible, as these "
                "represent the most significant risk to the site and "
                "its users."
            )
        else:
            sentences.append(
                "While no urgent issues were found, addressing the "
                "remaining items will further strengthen the site's "
                "security posture."
            )

    return " ".join(sentences)


def _join_with_commas_and_and(parts: list) -> str:
    """Joins a list of strings into a natural-language list, e.g.
    ['a', 'b', 'c'] -> 'a, b, and c'; ['a', 'b'] -> 'a and b';
    ['a'] -> 'a'."""
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    return ", ".join(parts[:-1]) + f", and {parts[-1]}"
