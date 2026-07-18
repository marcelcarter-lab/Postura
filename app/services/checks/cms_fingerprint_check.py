from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.cms_signatures import CMS_SIGNATURE_PATHS
from app.services.checks.path_checker import check_paths_concurrent


class CMSFingerprintCheck(BaseCheck):
    """Checks for known CMS-specific static file/folder paths (e.g.
    /wp-content/ for WordPress, /sites/default/ for Drupal) to
    fingerprint which CMS platform, if any, the target is running.
    Each matched path carries a confidence level (high/possible),
    surfaced in the result so a report reader can distinguish a
    near-certain identification from a weaker, corroborating-only
    signal. Informational check: identifying the CMS itself isn't a
    vulnerability, but narrows the attack surface an attacker would
    target (e.g. known WordPress plugin vulnerabilities).
    """

    check_type = "cms_fingerprint"

    def run(self) -> CheckResult:
        paths = list(CMS_SIGNATURE_PATHS.keys())
        results = check_paths_concurrent(self.target_url, paths)

        matched_cms = set()
        matched_paths = []
        highest_confidence_by_cms = {}

        for result in results:
            if not result.exists:
                continue
            cms, confidence = CMS_SIGNATURE_PATHS[result.path]
            matched_cms.add(cms)
            matched_paths.append(f"{result.path} ({cms}, {confidence}, status={result.status_code})")

            # Track the strongest confidence level seen for each CMS,
            # so if e.g. both a "possible" and a "high" path matched
            # for WordPress, the overall summary reflects "high" (the
            # more informative, corroborated conclusion), not the
            # weaker one.
            if cms not in highest_confidence_by_cms or (
                confidence == "high" and highest_confidence_by_cms[cms] == "possible"
            ):
                highest_confidence_by_cms[cms] = confidence

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

        summary_parts = [f"{cms} ({confidence})" for cms, confidence in highest_confidence_by_cms.items()]

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title=f"CMS fingerprint detected: {', '.join(sorted(summary_parts))}",
            description=(
                "One or more known CMS-specific paths were found, "
                "identifying the platform the site is running. Each "
                "match is labeled with a confidence level: 'high' "
                "means the specific file/path is unlikely to exist "
                "for any other reason, while 'possible' means the "
                "signal is weaker and could theoretically coincide "
                "with an unrelated setup. This is informational — it "
                "narrows the attack surface an attacker would target, "
                "but is not itself a vulnerability."
            ),
            evidence="; ".join(matched_paths),
            recommendation="",
            passed=True,
        )
