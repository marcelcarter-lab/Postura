from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

# Directives considered important for a baseline-safe CSP. Not
# exhaustive — this is a lightweight heuristic check, not a full CSP
# validator/parser.
IMPORTANT_DIRECTIVES = ["default-src", "script-src", "object-src"]

# Values that effectively defeat the purpose of a CSP if present
# unrestricted on script-related directives.
UNSAFE_VALUES = ["*", "unsafe-inline", "unsafe-eval"]


class CSPCheck(BaseCheck):
    """Checks whether the target sends a Content-Security-Policy header
    and does a lightweight evaluation of its directives, flagging
    absence or clearly unsafe configurations."""

    check_type = "csp_header"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate Content-Security-Policy",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        csp_header = response.headers.get("Content-Security-Policy")

        if not csp_header:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.MEDIUM,
                title="Missing Content-Security-Policy header",
                description=(
                    "The response did not include a Content-Security-Policy "
                    "header, leaving the site more exposed to XSS and data "
                    "injection attacks."
                ),
                evidence="Content-Security-Policy header not present.",
                recommendation=(
                    "Add a Content-Security-Policy header that restricts "
                    "script, style, and object sources to trusted origins."
                ),
                passed=False,
            )

        directives = self._parse_directives(csp_header)
        issues = self._evaluate_directives(directives)

        if issues:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.LOW,
                title="Content-Security-Policy present but weak",
                description=(
                    "A Content-Security-Policy header is present, but "
                    "contains directives that reduce its effectiveness."
                ),
                evidence=f"CSP: {csp_header} | Issues: {'; '.join(issues)}",
                recommendation=(
                    "Avoid 'unsafe-inline', 'unsafe-eval', and wildcard "
                    "sources on script-src/object-src; scope directives to "
                    "specific trusted origins instead."
                ),
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="Content-Security-Policy present and reasonably configured",
            description="A Content-Security-Policy header was found with no obviously unsafe directives.",
            evidence=f"CSP: {csp_header}",
            recommendation="",
            passed=True,
        )

    @staticmethod
    def _parse_directives(csp_header: str) -> dict:
        """Parses a CSP header string into a dict of {directive: [values]}."""
        directives = {}
        for part in csp_header.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if not tokens:
                continue
            name = tokens[0].lower()
            values = [v.strip("'\"") for v in tokens[1:]]
            directives[name] = values
        return directives

    @staticmethod
    def _evaluate_directives(directives: dict) -> list:
        """Returns a list of human-readable issue strings for any
        unsafe values found on important directives."""
        issues = []
        for directive_name in IMPORTANT_DIRECTIVES:
            values = directives.get(directive_name, [])
            for unsafe_value in UNSAFE_VALUES:
                if unsafe_value in values:
                    issues.append(f"{directive_name} allows '{unsafe_value}'")
        return issues
