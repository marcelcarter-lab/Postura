from urllib.parse import urlparse

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.sslscan_utils import run_sslscan, SSLScanError

DEFAULT_PORT = 443
INSECURE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
ACCEPTABLE_PROTOCOLS = {"TLSv1.2"}
IDEAL_PROTOCOLS = {"TLSv1.3"}


class TLSVersionCheck(BaseCheck):
    """Checks which TLS protocol versions the target server actually
    accepts, using sslscan (which negotiates with its own legacy-
    capable OpenSSL build) rather than Python's ssl module, which is
    bound by the host's security policy and confirmed unable to
    negotiate deprecated protocols even when deliberately relaxed.
    """

    check_type = "tls_protocol_strength"

    def run(self) -> CheckResult:
        hostname, port = self._extract_host_port(self.target_url)

        if not hostname:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate TLS protocol version",
                description="Could not extract a hostname from the target URL.",
                evidence=f"target_url={self.target_url}",
                recommendation="Ensure the target URL is well-formed.",
                passed=False,
            )

        try:
            scan = run_sslscan(hostname, port)
        except SSLScanError as exc:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate TLS protocol version",
                description="sslscan could not complete against the target.",
                evidence=f"error={exc}",
                recommendation="Ensure the target is reachable and retry.",
                passed=False,
            )

        if not scan.supported_protocols:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No TLS protocols detected",
                description="sslscan did not report any accepted protocol versions.",
                evidence="supported_protocols=[]",
                recommendation="Manually inspect the server's TLS configuration.",
                passed=False,
            )

        insecure_found = sorted(p for p in scan.supported_protocols if p in INSECURE_PROTOCOLS)
        evidence = f"supported_protocols={', '.join(scan.supported_protocols)}"

        if insecure_found:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.HIGH,
                title=f"Server accepts insecure TLS protocol version(s): {', '.join(insecure_found)}",
                description=(
                    "The server accepts one or more deprecated, "
                    "cryptographically weak protocol versions, confirmed "
                    "by direct negotiation via sslscan (not just inferred "
                    "from a refused client connection)."
                ),
                evidence=evidence,
                recommendation=(
                    "Disable TLS 1.0/1.1 and SSLv2/v3 on the server, and "
                    "require TLS 1.2 or higher."
                ),
                passed=False,
            )

        best = self._best_protocol(scan.supported_protocols)

        if best in IDEAL_PROTOCOLS:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Strong TLS protocol version(s) only",
                description=f"The server only accepts secure protocol versions: {', '.join(scan.supported_protocols)}.",
                evidence=evidence,
                recommendation="",
                passed=True,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="Acceptable TLS protocol version(s) only",
            description=f"The server only accepts secure protocol versions: {', '.join(scan.supported_protocols)}.",
            evidence=evidence,
            recommendation="Consider enabling TLS 1.3 for improved performance and security.",
            passed=True,
        )

    @staticmethod
    def _best_protocol(protocols):
        for p in ("TLSv1.3", "TLSv1.2"):
            if p in protocols:
                return p
        return protocols[0] if protocols else None

    @staticmethod
    def _extract_host_port(target_url: str):
        parsed = urlparse(target_url)
        return parsed.hostname, (parsed.port or DEFAULT_PORT)