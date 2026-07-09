from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get


class PermissionsPolicyCheck(BaseCheck):
    """Checks whether the target sends a non-trivial Permissions-Policy
    header, restricting access to sensitive browser features/APIs.

    This is a lighter-touch presence check rather than deep per-
    directive validation: the "correct" set of allowed features is
    genuinely site-specific (e.g. a video-chat app legitimately needs
    camera/microphone access), so this check cannot judge whether
    individual directive values are appropriate for a given site. It
    verifies the header exists and isn't empty/trivial.
    """

    check_type = "permissions_policy"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate Permissions-Policy",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        header_value = response.headers.get("Permissions-Policy")

        if not header_value or not header_value.strip():
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="Missing Permissions-Policy header",
                description=(
                    "The response did not include a Permissions-Policy "
                    "header, so no restrictions are placed on powerful "
                    "browser features (camera, microphone, geolocation, "
                    "payment, etc.) that injected or third-party scripts "
                    "could otherwise attempt to access."
                ),
                evidence="Permissions-Policy header not present.",
                recommendation=(
                    "Add a Permissions-Policy header restricting features "
                    "not required by the site, e.g. "
                    "camera=(), microphone=(), geolocation=()."
                ),
                passed=False,
            )

        directive_count = len([d for d in header_value.split(",") if d.strip()])

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="Permissions-Policy present",
            description=(
                f"A Permissions-Policy header is present with "
                f"{directive_count} directive(s). This check verifies "
                "presence only — review the specific directives to "
                "confirm they match the site's actual feature needs."
            ),
            evidence=f"Permissions-Policy: {header_value}",
            recommendation="",
            passed=True,
        )
