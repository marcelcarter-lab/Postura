import re
from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

# A widely recommended minimum max-age for HSTS is 6 months (in
# seconds). Anything below this is considered weak; 1 year+ is
# considered strong (and required for HSTS preload list submission).
MIN_RECOMMENDED_MAX_AGE = 15768000  # ~6 months
STRONG_MAX_AGE = 31536000  # 1 year


class HSTSCheck(BaseCheck):
    """Checks whether the target sends a Strict-Transport-Security
    header and evaluates its max-age, includeSubDomains, and preload
    directives."""

    check_type = "hsts_header"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate Strict-Transport-Security",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        hsts_header = response.headers.get("Strict-Transport-Security")

        if not hsts_header:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.MEDIUM,
                title="Missing Strict-Transport-Security header",
                description=(
                    "The response did not include an HSTS header, so "
                    "browsers will not be instructed to only connect over "
                    "HTTPS, leaving users exposed to protocol-downgrade "
                    "and man-in-the-middle attacks."
                ),
                evidence="Strict-Transport-Security header not present.",
                recommendation=(
                    "Add a Strict-Transport-Security header with a max-age "
                    "of at least 1 year, and consider includeSubDomains "
                    "and preload."
                ),
                passed=False,
            )

        max_age = self._parse_max_age(hsts_header)
        include_subdomains = "includesubdomains" in hsts_header.lower()
        preload = "preload" in hsts_header.lower()

        if max_age is None:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.MEDIUM,
                title="Strict-Transport-Security present but malformed",
                description="The HSTS header is present but no valid max-age directive was found.",
                evidence=f"HSTS: {hsts_header}",
                recommendation="Set a valid max-age directive, e.g. max-age=31536000.",
                passed=False,
            )

        if max_age < MIN_RECOMMENDED_MAX_AGE:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="Strict-Transport-Security max-age too low",
                description=(
                    f"HSTS max-age is set to {max_age} seconds, below the "
                    f"recommended minimum of {MIN_RECOMMENDED_MAX_AGE} "
                    "seconds (~6 months)."
                ),
                evidence=f"HSTS: {hsts_header}",
                recommendation=(
                    "Increase max-age to at least 31536000 (1 year) for "
                    "stronger protection."
                ),
                passed=False,
            )

        evidence_parts = [f"max-age={max_age}"]
        if include_subdomains:
            evidence_parts.append("includeSubDomains")
        if preload:
            evidence_parts.append("preload")

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="Strict-Transport-Security configured adequately",
            description=(
                "HSTS is present with a max-age meeting or exceeding the "
                "recommended minimum."
                + (" includeSubDomains is not set." if not include_subdomains else "")
            ),
            evidence=f"HSTS: {hsts_header} | Parsed: {', '.join(evidence_parts)}",
            recommendation=(
                ""
                if include_subdomains and max_age >= STRONG_MAX_AGE
                else "Consider adding includeSubDomains and preload, and "
                "using a max-age of at least 1 year for maximum protection."
            ),
            passed=True,
        )

    @staticmethod
    def _parse_max_age(hsts_header: str):
        """Extracts the integer max-age value from an HSTS header
        string, or None if not present/parseable."""
        match = re.search(r"max-age\s*=\s*(\d+)", hsts_header, re.IGNORECASE)
        if not match:
            return None
        return int(match.group(1))
