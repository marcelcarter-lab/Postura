from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

SAFE_VALUES = {
    "no-referrer",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
}

MIDDLE_GROUND_VALUES = {
    "origin",
    "origin-when-cross-origin",
    "no-referrer-when-downgrade",
}

UNSAFE_VALUES = {"unsafe-url"}


class ReferrerPolicyCheck(BaseCheck):
    """Checks whether the target sends a Referrer-Policy header that
    limits how much URL information leaks to third parties via the
    Referer header."""

    check_type = "referrer_policy"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate Referrer-Policy",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        header_value = response.headers.get("Referrer-Policy")

        if not header_value:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="Missing Referrer-Policy header",
                description=(
                    "The response did not include a Referrer-Policy header. "
                    "Modern browsers default to a reasonably safe policy "
                    "(strict-origin-when-cross-origin), but explicitly "
                    "setting this header ensures consistent, intentional "
                    "behavior across all browsers and versions."
                ),
                evidence="Referrer-Policy header not present.",
                recommendation=(
                    "Add a Referrer-Policy header set to "
                    "strict-origin-when-cross-origin or no-referrer."
                ),
                passed=False,
            )

        # A header can list multiple comma-separated policies (fallback
        # chain); browsers use the last valid one, so we evaluate that.
        values = [v.strip().lower() for v in header_value.split(",") if v.strip()]
        effective_value = values[-1] if values else ""

        if effective_value in UNSAFE_VALUES:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.MEDIUM,
                title="Referrer-Policy set to unsafe-url",
                description=(
                    "The Referrer-Policy is set to unsafe-url, which "
                    "always sends the full URL (including path and query "
                    "string) as the referrer, even across origins and "
                    "even when downgrading from HTTPS to HTTP."
                ),
                evidence=f"Referrer-Policy: {header_value}",
                recommendation=(
                    "Change to strict-origin-when-cross-origin or "
                    "no-referrer to avoid leaking full URLs to third "
                    "parties."
                ),
                passed=False,
            )

        if effective_value in MIDDLE_GROUND_VALUES:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="Referrer-Policy could be tightened",
                description=(
                    f"The Referrer-Policy is set to '{effective_value}', "
                    "which leaks more referrer information than "
                    "necessary for most use cases."
                ),
                evidence=f"Referrer-Policy: {header_value}",
                recommendation=(
                    "Consider strict-origin-when-cross-origin or "
                    "no-referrer for tighter control over referrer "
                    "information leakage."
                ),
                passed=False,
            )

        if effective_value not in SAFE_VALUES:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="Referrer-Policy has an unrecognized value",
                description=(
                    "The Referrer-Policy header is present but its value "
                    "is not a recognized policy directive."
                ),
                evidence=f"Referrer-Policy: {header_value}",
                recommendation=(
                    "Set Referrer-Policy to a valid, safe value such as "
                    "strict-origin-when-cross-origin or no-referrer."
                ),
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="Referrer-Policy configured safely",
            description=f"Referrer-Policy is set to a safe value ({effective_value}).",
            evidence=f"Referrer-Policy: {header_value}",
            recommendation="",
            passed=True,
        )
