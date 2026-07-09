from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.services.checks.schema import Severity


@dataclass
class CheckResult:
    """Represents the outcome of a single check run. Matches the
    finding schema that will be persisted to the DB (Finding model)."""

    check_type: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    passed: bool = True
    run_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseCheck(ABC):
    """Abstract base class every security check must implement.

    Subclasses represent a single, atomic check (e.g. HSTS header
    presence, SSL certificate validity) and must implement `run()`,
    returning a CheckResult describing the outcome.
    """

    #: Short machine-readable identifier for this check, e.g. "hsts_header".
    #: Subclasses must override this.
    check_type: str = "base_check"

    def __init__(self, target_url: str):
        self.target_url = target_url

    @abstractmethod
    def run(self) -> CheckResult:
        """Execute the check against self.target_url and return a
        CheckResult. Must be implemented by every subclass."""
        raise NotImplementedError

    def __repr__(self):
        return f"<{self.__class__.__name__} target={self.target_url!r}>"
