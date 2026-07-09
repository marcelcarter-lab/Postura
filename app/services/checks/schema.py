from enum import Enum


class Severity(str, Enum):
    """Standardized severity levels for findings, ordered low to high.
    Using str + Enum lets these serialize cleanly to JSON and store
    directly as strings in the DB without extra conversion."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Defines the canonical finding schema. Every check's CheckResult and
# every Finding DB row must populate these fields. This is documentation
# +  a single source of truth, not an enforced runtime contract by itself
# (SQLAlchemy model + dataclass typing handle enforcement separately).
FINDING_SCHEMA = {
    "scan_id": "int — FK to the Scan this finding belongs to",
    "check_type": "str — machine-readable check identifier, e.g. 'hsts_header'",
    "severity": "Severity — one of info/low/medium/high/critical",
    "title": "str — short human-readable summary, e.g. 'Missing HSTS header'",
    "description": "str — explains what was checked and what was found",
    "evidence": "str — raw data supporting the finding (e.g. actual header value, or absence)",
    "recommendation": "str — actionable guidance on how to fix the issue",
    "passed": "bool — True if the check passed (no issue), False if it failed (issue found)",
    "created_at": "datetime — when the finding was recorded (UTC)",
}
