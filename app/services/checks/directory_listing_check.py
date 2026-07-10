import re

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

# Common directory-listing signatures across different web servers.
# Apache's "Index of /" is the classic one; nginx's autoindex module
# produces a similar but distinctly-formatted page; IIS has its own
# variant. Matched case-insensitively against the response body.
DIRECTORY_LISTING_PATTERNS = [
    re.compile(r"Index of /", re.IGNORECASE),
    re.compile(r"<title>Index of ", re.IGNORECASE),
    re.compile(r"Directory Listing For", re.IGNORECASE),  # some IIS configs
    re.compile(r"\[To Parent Directory\]", re.IGNORECASE),  # classic IIS
]


class DirectoryListingCheck(BaseCheck):
    """Checks whether the target's root (or a given path) returns a
    raw directory listing instead of a proper page — a common
    misconfiguration that can expose file/folder structure."""

    check_type = "directory_listing"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate directory listing",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        body = response.text or ""
        matched_pattern = self._find_matching_pattern(body)

        if matched_pattern:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.MEDIUM,
                title="Directory listing is enabled",
                description=(
                    "The server returned a raw directory listing instead "
                    "of a proper page or error, potentially exposing file "
                    "and folder structure to visitors."
                ),
                evidence=f"matched pattern: {matched_pattern!r} in response body",
                recommendation=(
                    "Disable directory listing/autoindex on the web "
                    "server, or add an index file to every directory that "
                    "should not be browsable."
                ),
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="No directory listing detected",
            description="No directory-listing signature was found in the response body.",
            evidence="",
            recommendation="",
            passed=True,
        )

    @staticmethod
    def _find_matching_pattern(body: str):
        for pattern in DIRECTORY_LISTING_PATTERNS:
            if pattern.search(body):
                return pattern.pattern
        return None
