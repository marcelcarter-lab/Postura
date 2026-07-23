from urllib.parse import urljoin, urlparse

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

UNTRUSTED_ORIGIN = "https://evil-attacker-domain-postura-test.com"


class PermissiveCORSCheck(BaseCheck):
    """Inspects Cross-Origin Resource Sharing (CORS) response headers returned
    by the target site to detect overly permissive configurations.

    Key risks checked:
    1. Wildcard origin (`*`) with credentials allowed (`Access-Control-Allow-Credentials: true`).
    2. Arbitrary/reflective origin reflection: echoing an untrusted `Origin` back in
       `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`.
    3. Wildcard origin (`*`) on resource responses without credentials.
    4. Trusting the `null` origin (`Access-Control-Allow-Origin: null`).
    """

    check_type = "permissive_cors"

    def run(self) -> CheckResult:
        session = build_session(max_retries=0, status_forcelist=[])
        base = self.target_url if self.target_url.endswith("/") else self.target_url + "/"

        # Probe paths to inspect for CORS policy
        probe_urls = [
            self.target_url,
            urljoin(base, "api/"),
        ]

        findings = []
        errors = []

        for url in probe_urls:
            # Probe 1: Send request with an untrusted arbitrary origin header
            resp_untrusted, err1 = safe_get(
                session, url, headers={"Origin": UNTRUSTED_ORIGIN}
            )
            if err1 or resp_untrusted is None:
                errors.append(f"GET {url} with untrusted origin failed ({err1})")
            else:
                self._evaluate_cors_response(
                    resp_untrusted.headers,
                    request_origin=UNTRUSTED_ORIGIN,
                    url=url,
                    method="GET",
                    findings=findings,
                )

            # Probe 2: Send request with Origin: null
            resp_null, err2 = safe_get(session, url, headers={"Origin": "null"})
            if err2 or resp_null is None:
                errors.append(f"GET {url} with null origin failed ({err2})")
            else:
                self._evaluate_cors_response(
                    resp_null.headers,
                    request_origin="null",
                    url=url,
                    method="GET",
                    findings=findings,
                )

        if not findings:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No permissive CORS misconfiguration detected",
                description=(
                    "CORS response headers were either absent (restricting access to same-origin) "
                    "or properly restricted to trusted origins without wildcard or arbitrary origin reflection."
                ),
                evidence="; ".join(errors) if errors else "",
                recommendation="",
                passed=True,
            )

        # Determine highest severity among findings
        has_high_severity = any(f["severity"] == Severity.HIGH for f in findings)
        overall_severity = Severity.HIGH if has_high_severity else Severity.MEDIUM

        evidence_lines = [
            f"{f['url']} [{f['method']} with Origin: '{f['origin']}']: {f['detail']}"
            for f in findings
        ]

        return CheckResult(
            check_type=self.check_type,
            severity=overall_severity,
            title=(
                "Overly permissive CORS configuration with credentials allowed"
                if has_high_severity
                else "Permissive CORS policy detected"
            ),
            description=(
                "The target application returned Cross-Origin Resource Sharing (CORS) headers "
                "that allow unauthorized third-party domains to read response data. "
                "Allowing arbitrary origins or wildcard origins—especially when combined with "
                "Access-Control-Allow-Credentials: true—enables cross-site data theft."
            ),
            evidence="; ".join(evidence_lines),
            recommendation=(
                "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted domains. "
                "Never dynamically reflect untrusted request Origin headers into Access-Control-Allow-Origin "
                "when Access-Control-Allow-Credentials is set to true. Avoid using Access-Control-Allow-Origin: * "
                "on authenticated endpoints or sensitive APIs."
            ),
            passed=False,
        )

    def _evaluate_cors_response(
        self,
        headers,
        request_origin: str,
        url: str,
        method: str,
        findings: list,
    ):
        allow_origin = headers.get("Access-Control-Allow-Origin", "").strip()
        allow_credentials = (
            headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        )

        if not allow_origin:
            return

        # Case 1: Reflective untrusted origin + credentials (HIGH severity)
        if allow_origin == UNTRUSTED_ORIGIN and allow_credentials:
            findings.append({
                "severity": Severity.HIGH,
                "url": url,
                "method": method,
                "origin": request_origin,
                "detail": (
                    f"Reflected untrusted origin '{allow_origin}' with Access-Control-Allow-Credentials: true"
                ),
            })
            return

        # Case 2: Wildcard origin + credentials (HIGH severity misconfig)
        if allow_origin == "*" and allow_credentials:
            findings.append({
                "severity": Severity.HIGH,
                "url": url,
                "method": method,
                "origin": request_origin,
                "detail": "Wildcard '*' origin with Access-Control-Allow-Credentials: true",
            })
            return

        # Case 3: Reflective untrusted origin without credentials (MEDIUM severity)
        if allow_origin == UNTRUSTED_ORIGIN:
            findings.append({
                "severity": Severity.MEDIUM,
                "url": url,
                "method": method,
                "origin": request_origin,
                "detail": f"Reflected untrusted origin '{allow_origin}'",
            })
            return

        # Case 4: Null origin allowed (MEDIUM severity)
        if allow_origin == "null" and request_origin == "null":
            findings.append({
                "severity": Severity.MEDIUM,
                "url": url,
                "method": method,
                "origin": request_origin,
                "detail": "Access-Control-Allow-Origin set to 'null'",
            })
            return

        # Case 5: Wildcard origin '*' (MEDIUM severity)
        if allow_origin == "*":
            findings.append({
                "severity": Severity.MEDIUM,
                "url": url,
                "method": method,
                "origin": request_origin,
                "detail": "Wildcard '*' Access-Control-Allow-Origin header returned",
            })
            return
