import re

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

# Matches a version number pattern like "2.4.41", "1.18.0", "10.0"
# anywhere in the Server header value — used to distinguish a generic
# server name from one that discloses specific version information.
VERSION_PATTERN = re.compile(r"\d+\.\d+(\.\d+)?")


class ServerHeaderCheck(BaseCheck):
    """Fingerprints the target's Server response header. This is an
    informational check, not a pass/fail hardening check: the goal is
    to flag when the header discloses specific version information
    (useful to an attacker targeting known vulnerabilities), not to
    judge whether any particular Server value is "correct" — there
    isn't one."""

    check_type = "server_header_disclosure"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate Server header",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        server_header = response.headers.get("Server")

        if not server_header:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No Server header disclosed",
                description="The response did not include a Server header, revealing no backend software information.",
                evidence="Server header not present.",
                recommendation="",
                passed=True,
            )

        if VERSION_PATTERN.search(server_header):
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="Server header discloses version information",
                description=(
                    "The Server header includes specific version "
                    "information, which can help an attacker identify "
                    "known vulnerabilities for that exact version."
                ),
                evidence=f"Server: {server_header}",
                recommendation=(
                    "Configure the web server to suppress or generalize "
                    "the Server header (e.g. ServerTokens Prod on Apache, "
                    "server_tokens off on nginx)."
                ),
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="Server header present but generic",
            description=(
                f"The Server header ({server_header}) does not appear to "
                "disclose specific version information."
            ),
            evidence=f"Server: {server_header}",
            recommendation="",
            passed=True,
        )
