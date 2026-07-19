from dataclasses import dataclass

from app.services.compliance.owasp_mapping import get_owasp_category


@dataclass
class CategoryCompliance:
    """Compliance breakdown for a single OWASP category within a scan."""

    category: str
    passed_count: int
    total_count: int
    percentage: int


def calculate_compliance_by_category(findings: list) -> list:
    """Groups a scan's findings by OWASP category and computes a
    pass percentage for each: (checks that passed / total checks in
    that category) * 100, rounded to the nearest whole number.

    Only findings with a real (non-"Uncategorized") OWASP mapping are
    included — an unmapped check_type (see owasp_mapping.py's
    get_owasp_category docstring) doesn't have a meaningful category
    to report compliance against, so it's silently excluded from this
    breakdown rather than lumped into a confusing catch-all bucket.

    Returns a list of CategoryCompliance, sorted by category name for
    stable, predictable ordering in reports/UI.
    """
    counts_by_category = {}

    for finding in findings:
        category = get_owasp_category(finding.check_type)
        if category == "Uncategorized":
            continue

        if category not in counts_by_category:
            counts_by_category[category] = {"passed": 0, "total": 0}

        counts_by_category[category]["total"] += 1
        if finding.passed:
            counts_by_category[category]["passed"] += 1

    results = []
    for category, counts in counts_by_category.items():
        percentage = round((counts["passed"] / counts["total"]) * 100) if counts["total"] > 0 else 0
        results.append(
            CategoryCompliance(
                category=category,
                passed_count=counts["passed"],
                total_count=counts["total"],
                percentage=percentage,
            )
        )

    return sorted(results, key=lambda c: c.category)
