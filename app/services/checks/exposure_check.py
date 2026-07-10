from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.exposure_wordlist import EXPOSURE_WORDLIST
from app.services.checks.path_checker import check_paths_concurrent


class ExposureCheck(BaseCheck):
    """Checks for exposed sensitive files/paths (VCS metadata, .env
    files, backups, etc.) using the curated exposure wordlist. Unlike
    the other checks, a single run of this check can produce evidence
    of MULTIPLE distinct exposures, all rolled into one CheckResult
    (rather than one CheckResult per path) — since the exposure
    wordlist is one conceptual check ("does this site leak sensitive
    files"), not many independent ones.
    """

    check_type = "exposure_detection"

    def run(self) -> CheckResult:
        results = check_paths_concurrent(self.target_url, EXPOSURE_WORDLIST)
        exposed = [r for r in results if r.exists]

        if not exposed:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No exposed sensitive files detected",
                description="None of the checked sensitive paths were found on the target.",
                evidence="",
                recommendation="",
                passed=True,
            )

        evidence_lines = [f"{r.path} (status={r.status_code})" for r in exposed]

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.CRITICAL,
            title=f"Exposed sensitive file(s) detected: {len(exposed)} path(s)",
            description=(
                "One or more sensitive files/paths (version control "
                "metadata, environment files, backups, etc.) were found "
                "publicly accessible, which can leak source code, "
                "credentials, or other sensitive data."
            ),
            evidence="; ".join(evidence_lines),
            recommendation=(
                "Remove these files from the publicly served directory, "
                "or configure the web server to block access to them."
            ),
            passed=False,
        )
