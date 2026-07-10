import re

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

# Matches a version number pattern like "8.1.2", "5.6" anywhere in the
# X-Powered-By header value — distinguishes a generic technology name
# from one that discloses specific version information.
VERSION_PATTERN = re.compile(r"\d+\.\d+(\.\d+)?")


class XPoweredByCheck(BaseCheck):
    """Fingerprints the target's X-Powered-By response header. Like
    ServerHeaderCheck, this is an informational check: the concern is
    whether the header discloses specific version information (useful
    to an attacker targeting known vulnerabilities), not whether any
    particular value is "correct"."""

    check_type = "x_powered_by_disclosure"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate X-Powered-By header",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        header_value = response.headers.get("X-Powered-By")

        if not header_value:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No X-Powered-By header disclosed",
                description="The response did not include an X-Powered-By header, revealing no backend technology information.",
                evidence="X-Powered-By header not present.",
                recommendation="",
                passed=True,
            )

        if VERSION_PATTERN.search(header_value):
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="X-Powered-By header discloses version information",
                description=(
                    "The X-Powered-By header includes specific version "
                    "information, which can help an attacker identify "
                    "known vulnerabilities for that exact version."
                ),
                evidence=f"X-Powered-By: {header_value}",
                recommendation=(
                    "Configure the backend framework/language to suppress "
                    "the X-Powered-By header (e.g. expose_php=Off in PHP, "
                    "app.disable('x-powered-by') in Express)."
                ),
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="X-Powered-By header present but generic",
            description=(
                f"The X-Powered-By header ({header_value}) does not "
                "appear to disclose specific version information."
            ),
            evidence=f"X-Powered-By: {header_value}",
            recommendation="",
            passed=True,
        )
