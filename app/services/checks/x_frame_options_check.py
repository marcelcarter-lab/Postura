from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

# DENY and SAMEORIGIN are the two modern, browser-supported safe values.
# ALLOW-FROM is deprecated/non-standard and ignored by most modern
# browsers (superseded by CSP's frame-ancestors directive), so it's
# treated as effectively unsafe here despite technically being a
# documented value.
SAFE_VALUES = ["deny", "sameorigin"]


class XFrameOptionsCheck(BaseCheck):
    """Checks whether the target sends an X-Frame-Options header with
    a safe value, protecting against clickjacking via iframe embedding."""

    check_type = "x_frame_options"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate X-Frame-Options",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        xfo_header = response.headers.get("X-Frame-Options")

        if not xfo_header:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.MEDIUM,
                title="Missing X-Frame-Options header",
                description=(
                    "The response did not include an X-Frame-Options "
                    "header, so the site can potentially be embedded in "
                    "an iframe on a malicious page and used for "
                    "clickjacking attacks."
                ),
                evidence="X-Frame-Options header not present.",
                recommendation=(
                    "Add an X-Frame-Options header set to DENY or "
                    "SAMEORIGIN, and/or a Content-Security-Policy with a "
                    "frame-ancestors directive."
                ),
                passed=False,
            )

        value = xfo_header.strip().lower()

        if value.startswith("allow-from"):
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="X-Frame-Options uses deprecated ALLOW-FROM value",
                description=(
                    "The X-Frame-Options header uses the deprecated "
                    "ALLOW-FROM directive, which is ignored by most "
                    "modern browsers, leaving the protection effectively "
                    "absent in practice."
                ),
                evidence=f"X-Frame-Options: {xfo_header}",
                recommendation=(
                    "Replace ALLOW-FROM with SAMEORIGIN or DENY, or use "
                    "a Content-Security-Policy frame-ancestors directive "
                    "for fine-grained control over allowed embedders."
                ),
                passed=False,
            )

        if value not in SAFE_VALUES:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.MEDIUM,
                title="X-Frame-Options has an invalid value",
                description=(
                    "The X-Frame-Options header is present but its value "
                    "is not one of the recognized safe values."
                ),
                evidence=f"X-Frame-Options: {xfo_header}",
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="X-Frame-Options configured correctly",
            description=f"X-Frame-Options is set to a safe value ({xfo_header}).",
            evidence=f"X-Frame-Options: {xfo_header}",
            recommendation="",
            passed=True,
        )
