from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.js_framework_signatures import FRAMEWORK_SIGNATURES
from app.services.http_client import build_session, safe_get


class JSFrameworkCheck(BaseCheck):
    """Checks the target's HTML for JS framework detection signatures
    (React, Vue, Angular, and their meta-frameworks Next.js/Nuxt.js).
    Informational/fingerprinting check, same framing as
    CMSFingerprintCheck: identifying the framework isn't itself a
    vulnerability, but narrows the attack surface an attacker would
    target (e.g. known framework-specific vulnerabilities), and helps
    build a fuller technology profile for the report.
    """

    check_type = "js_framework_fingerprint"

    def run(self) -> CheckResult:
        session = build_session()
        response, error = safe_get(session, self.target_url)

        if error:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate JS framework fingerprint",
                description="The check could not complete because the request failed.",
                evidence=f"error={error}",
                recommendation="Ensure the target is reachable and retry the scan.",
                passed=False,
            )

        body = response.text or ""
        matches = self._find_matches(body)

        if not matches:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No JS framework fingerprint detected",
                description=(
                    "No known JS framework signatures were found in the page "
                    "HTML. This does not guarantee no framework is in use — "
                    "client-side-rendered apps with minimal build output can "
                    "evade static HTML detection."
                ),
                evidence="",
                recommendation="",
                passed=True,
            )

        evidence_lines = [f"{label} ({confidence})" for label, confidence in matches]

        # Lead the title with the highest-confidence match, if any —
        # gives the most useful summary at a glance rather than an
        # arbitrary first match.
        high_confidence_labels = [label for label, confidence in matches if confidence == "high"]
        if high_confidence_labels:
            headline = f"{high_confidence_labels[0]} (high confidence)"
        else:
            headline = f"{matches[0][0]} (possible)"

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title=f"JS framework fingerprint detected: {headline}",
            description=(
                "One or more JS framework signatures were found, "
                "identifying the frontend technology in use. Each "
                "match is labeled with a confidence level: 'high' "
                "means the signal is specific and unlikely to occur "
                "by coincidence, while 'possible' means the signal is "
                "weaker (e.g. a generic root element ID) and should "
                "be treated as corroborating evidence rather than a "
                "standalone conclusion. This is informational — it "
                "narrows the attack surface an attacker would target, "
                "but is not itself a vulnerability."
            ),
            evidence="; ".join(evidence_lines),
            recommendation="",
            passed=True,
        )

    @staticmethod
    def _find_matches(body: str):
        """Returns a deduplicated list of (label, confidence) tuples
        for every signature pattern that matched, preserving the
        order signatures are checked in (more specific/informative
        matches first, per FRAMEWORK_SIGNATURES' ordering)."""
        matches = []
        seen_labels = set()
        for pattern, label, confidence in FRAMEWORK_SIGNATURES:
            if pattern.search(body) and label not in seen_labels:
                matches.append((label, confidence))
                seen_labels.add(label)
        return matches
