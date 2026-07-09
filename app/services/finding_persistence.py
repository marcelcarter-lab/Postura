from app.extensions import db
from app.models.finding import Finding


def save_findings(scan_id: int, check_results: list) -> int:
    """Bulk-persists a list of CheckResult objects as Finding rows tied
    to scan_id. Returns the number of findings saved.

    Uses SQLAlchemy's bulk_insert_mappings for efficiency — this issues
    a single batched INSERT rather than N individual
    session.add()/autoflush cycles, which matters once a scan grows to
    dozens of checks (and later, Phase 2's expanded fingerprinting).
    """
    if not check_results:
        return 0

    mappings = [
        {
            "scan_id": scan_id,
            "check_type": result.check_type,
            "severity": result.severity.value,
            "title": result.title,
            "description": result.description,
            "evidence": result.evidence,
            "recommendation": result.recommendation,
            "passed": result.passed,
        }
        for result in check_results
    ]

    db.session.bulk_insert_mappings(Finding, mappings)
    db.session.commit()

    return len(mappings)
