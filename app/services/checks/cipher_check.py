import socket
import ssl
from urllib.parse import urlparse

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.tls_utils import open_tls_connection

# Substrings commonly found in weak/deprecated cipher names. Not an
# exhaustive cryptographic classification — a lightweight heuristic
# matching well-known deprecated algorithms.
WEAK_CIPHER_MARKERS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
MIN_ACCEPTABLE_BITS = 128


class CipherStrengthCheck(BaseCheck):
    """Checks the strength of the cipher suite negotiated with the
    target, flagging known-weak ciphers by name pattern and low key
    strength. Operates at the TLS layer directly via
    tls_utils.open_tls_connection, not via the HTTP fetch wrapper.

    Note: because the underlying connection uses the client's default
    (secure) SSL context, this check primarily confirms that a *strong*
    cipher was negotiated. It has limited ability to detect servers
    that are willing to offer weak ciphers to a less strict client,
    since the client itself will typically refuse to negotiate down to
    them. See tls_version_check.py for the same limitation.
    """

    check_type = "cipher_suite_strength"

    def run(self) -> CheckResult:
        hostname = self._extract_hostname(self.target_url)

        if not hostname:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate cipher suite",
                description="Could not extract a hostname from the target URL.",
                evidence=f"target_url={self.target_url}",
                recommendation="Ensure the target URL is well-formed.",
                passed=False,
            )

        try:
            with open_tls_connection(hostname) as ssock:
                cipher_info = ssock.cipher()
        except (ssl.SSLError, socket.error, socket.timeout, ConnectionError) as exc:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate cipher suite",
                description="Could not complete a TLS handshake with the target.",
                evidence=f"error={exc}",
                recommendation="Ensure the target supports HTTPS on port 443 and retry.",
                passed=False,
            )

        if cipher_info is None:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate cipher suite",
                description="No cipher information was returned by the TLS connection.",
                evidence="cipher()=None",
                recommendation="Manually inspect the server's TLS configuration.",
                passed=False,
            )

        cipher_name, tls_version, secret_bits = cipher_info
        evidence = f"cipher={cipher_name} | tls_version={tls_version} | secret_bits={secret_bits}"

        weak_markers_found = [m for m in WEAK_CIPHER_MARKERS if m in cipher_name.upper()]
        is_low_bits = secret_bits is not None and secret_bits < MIN_ACCEPTABLE_BITS

        if weak_markers_found or is_low_bits:
            reasons = []
            if weak_markers_found:
                reasons.append(f"contains deprecated marker(s): {', '.join(weak_markers_found)}")
            if is_low_bits:
                reasons.append(f"key strength ({secret_bits} bits) below {MIN_ACCEPTABLE_BITS}")

            return CheckResult(
                check_type=self.check_type,
                severity=Severity.HIGH,
                title=f"Weak cipher suite negotiated ({cipher_name})",
                description=(
                    f"The negotiated cipher suite appears weak: "
                    f"{'; '.join(reasons)}."
                ),
                evidence=evidence,
                recommendation=(
                    "Disable weak/deprecated cipher suites on the server "
                    "and restrict to modern, strong ciphers (e.g. AES-GCM, "
                    "ChaCha20-Poly1305)."
                ),
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="Strong cipher suite negotiated",
            description=f"The negotiated cipher suite ({cipher_name}) appears strong.",
            evidence=evidence,
            recommendation="",
            passed=True,
        )

    @staticmethod
    def _extract_hostname(target_url: str):
        parsed = urlparse(target_url)
        return parsed.hostname
