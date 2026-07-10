from bs4 import BeautifulSoup

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get


class MetaGeneratorCheck(BaseCheck):
    """Checks for a <meta name="generator" content="..."> tag in the
    target's HTML, which many CMS platforms (WordPress, Drupal, Joomla,
    etc.) include by default, often revealing the exact CMS version.
    Informational/fingerprinting check, same framing as
    ServerHeaderCheck and XPoweredByCheck: presence with version info
    is a disclosure risk, not a binary pass/fail configuration issue.
    """

    check_type = "meta_generator_disclosure"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate meta generator tag",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        generator_content = self._extract_generator_tag(response.text or "")

        if not generator_content:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No meta generator tag found",
                description="No <meta name=\"generator\"> tag was found in the page HTML.",
                evidence="",
                recommendation="",
                passed=True,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.LOW,
            title="Meta generator tag discloses platform information",
            description=(
                "The page includes a meta generator tag revealing the "
                "underlying CMS/platform, which can help an attacker "
                "target known vulnerabilities for that specific platform "
                "or version."
            ),
            evidence=f'<meta name="generator" content="{generator_content}">',
            recommendation=(
                "Remove or suppress the meta generator tag (most CMS "
                "platforms provide a plugin, setting, or code snippet to "
                "disable it)."
            ),
            passed=False,
        )

    @staticmethod
    def _extract_generator_tag(html: str):
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("meta", attrs={"name": "generator"})
        if tag and tag.get("content"):
            return tag["content"].strip()
        return None
