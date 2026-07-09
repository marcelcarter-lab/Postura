import socket
import ssl
from urllib.parse import urlparse

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.tls_utils import open_tls_connection

INSECURE_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
ACCEPTABLE_VERSIONS = {"TLSv1.2"}
IDEAL_VERSIONS = {"TLSv1.3"}


class TLSVersionCheck(BaseCheck):
    """Checks which TLS protocol version was negotiated with the
    target, flagging deprecated/insecure versions (TLS 1.0/1.1 and
    below). Operates at the TLS layer directly, not via the HTTP fetch
    wrapper used by header checks.
    """

    check_type = "tls_protocol_strength"

    def run(self) -> CheckResult:
        hostname = self._extract_hostname(self.target_url)

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
            with open_tls_connection(hostname) as ssock:
                negotiated_version = ssock.version()
        except (ssl.SSLError, socket.error, socket.timeout, ConnectionError) as exc:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate TLS protocol version",
                description="Could not complete a TLS handshake with the target.",
                evidence=f"error={exc}",
                recommendation="Ensure the target supports HTTPS on port 443 and retry.",
                passed=False,
            )

        evidence = f"negotiated_version={negotiated_version}"

        if negotiated_version in INSECURE_VERSIONS:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.HIGH,
                title=f"Insecure TLS protocol version negotiated ({negotiated_version})",
                description=(
                    f"The server negotiated {negotiated_version}, a deprecated "
                    "and cryptographically weak protocol version that modern "
                    "browsers have blocked since 2020. This exposes "
                    "connections to known protocol-level attacks."
                ),
                evidence=evidence,
                recommendation=(
                    "Disable TLS 1.0/1.1 and SSLv2/v3 on the server, and "
                    "require TLS 1.2 or higher."
                ),
                passed=False,
            )

        if negotiated_version in IDEAL_VERSIONS:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Strong TLS protocol version negotiated",
                description=f"The server negotiated {negotiated_version}, the current best-practice protocol version.",
                evidence=evidence,
                recommendation="",
                passed=True,
            )

        if negotiated_version in ACCEPTABLE_VERSIONS:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Acceptable TLS protocol version negotiated",
                description=f"The server negotiated {negotiated_version}, which is still secure and widely supported.",
                evidence=evidence,
                recommendation="Consider enabling TLS 1.3 if not already supported, for improved performance and security.",
                passed=True,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="Unrecognized TLS protocol version",
            description=f"The server negotiated an unrecognized version string: {negotiated_version}.",
            evidence=evidence,
            recommendation="Manually verify the server's TLS configuration.",
            passed=False,
        )

    @staticmethod
    def _extract_hostname(target_url: str):
        parsed = urlparse(target_url)
        return parsed.hostname
