from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.cms_signatures import CMS_SIGNATURE_PATHS
from app.services.checks.path_checker import check_paths_concurrent


class CMSFingerprintCheck(BaseCheck):
    """Checks for known CMS-specific static file/folder paths (e.g.
    /wp-content/ for WordPress, /sites/default/ for Drupal) to
    fingerprint which CMS platform, if any, the target is running.
    Informational check: identifying the CMS itself isn't a
    vulnerability, but it narrows the attack surface an attacker would
    target (e.g. known WordPress plugin vulnerabilities).
    """

    check_type = "cms_fingerprint"

    def run(self) -> CheckResult:
        paths = list(CMS_SIGNATURE_PATHS.keys())
        results = check_paths_concurrent(self.target_url, paths)

        matched_cms = set()
        matched_paths = []
        for result in results:
            if result.exists:
                cms = CMS_SIGNATURE_PATHS[result.path]
                matched_cms.add(cms)
                matched_paths.append(f"{result.path} ({cms}, status={result.status_code})")

        if not matched_paths:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No CMS fingerprint detected",
                description="No known CMS-specific paths were found on the target.",
                evidence="",
                recommendation="",
                passed=True,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title=f"CMS fingerprint detected: {', '.join(sorted(matched_cms))}",
            description=(
                "One or more known CMS-specific paths were found, "
                "identifying the platform the site is running. This is "
                "informational — it narrows the attack surface an "
                "attacker would target, but is not itself a "
                "vulnerability."
            ),
            evidence="; ".join(matched_paths),
            recommendation="",
            passed=True,
        )
