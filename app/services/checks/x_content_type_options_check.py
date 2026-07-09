from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get


class XContentTypeOptionsCheck(BaseCheck):
    """Checks whether the target sends an X-Content-Type-Options:
    nosniff header, preventing browsers from MIME-sniffing responses
    away from their declared Content-Type."""

    check_type = "x_content_type_options"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate X-Content-Type-Options",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        xcto_header = response.headers.get("X-Content-Type-Options")

        if not xcto_header:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="Missing X-Content-Type-Options header",
                description=(
                    "The response did not include an X-Content-Type-Options "
                    "header, so browsers may MIME-sniff the response body "
                    "and interpret it as a different content type than "
                    "declared, which can enable certain content-injection "
                    "attacks in specific scenarios (e.g. user-uploaded "
                    "content served from the same origin)."
                ),
                evidence="X-Content-Type-Options header not present.",
                recommendation="Add an X-Content-Type-Options header set to nosniff.",
                passed=False,
            )

        if xcto_header.strip().lower() != "nosniff":
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="X-Content-Type-Options has an invalid value",
                description=(
                    "The X-Content-Type-Options header is present but its "
                    "value is not 'nosniff', the only value this header "
                    "meaningfully supports."
                ),
                evidence=f"X-Content-Type-Options: {xcto_header}",
                recommendation="Set X-Content-Type-Options to nosniff.",
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="X-Content-Type-Options configured correctly",
            description="X-Content-Type-Options is set to nosniff.",
            evidence=f"X-Content-Type-Options: {xcto_header}",
            recommendation="",
            passed=True,
        )
