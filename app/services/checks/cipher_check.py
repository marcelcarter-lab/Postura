from urllib.parse import urlparse

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.sslscan_utils import run_sslscan, SSLScanError

DEFAULT_PORT = 443
WEAK_CIPHER_MARKERS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
MIN_ACCEPTABLE_BITS = 128


class CipherStrengthCheck(BaseCheck):
    """Checks the strength of cipher suites the target server actually
    accepts, using sslscan (legacy-capable OpenSSL) rather than
    Python's ssl module, which cannot negotiate down to weak ciphers
    like RC4/3DES regardless of context settings — confirmed via live
    testing against badssl.com's rc4/3des subdomains.
    """

    check_type = "cipher_suite_strength"

    def run(self) -> CheckResult:
        hostname, port = self._extract_host_port(self.target_url)

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
            scan = run_sslscan(hostname, port)
        except SSLScanError as exc:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate cipher suite",
                description="sslscan could not complete against the target.",
                evidence=f"error={exc}",
                recommendation="Ensure the target is reachable and retry.",
                passed=False,
            )

        if not scan.ciphers:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No cipher information detected",
                description="sslscan did not report any accepted ciphers.",
                evidence="ciphers=[]",
                recommendation="Manually inspect the server's TLS configuration.",
                passed=False,
            )

        weak = []
        for c in scan.ciphers:
            name = c["name"].upper()
            markers = [m for m in WEAK_CIPHER_MARKERS if m in name]
            low_bits = c["bits"] is not None and c["bits"] < MIN_ACCEPTABLE_BITS
            if markers or low_bits:
                weak.append(c["name"])

        evidence = f"total_ciphers_offered={len(scan.ciphers)} | weak_ciphers={weak}"

        if weak:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.HIGH,
                title=f"Server accepts weak cipher suite(s): {', '.join(weak[:5])}",
                description=(
                    "The server accepts one or more weak/deprecated "
                    "cipher suites, confirmed by direct negotiation via "
                    "sslscan."
                ),
                evidence=evidence,
                recommendation=(
                    "Disable weak/deprecated cipher suites on the server "
                    "and restrict to modern, strong ciphers (e.g. "
                    "AES-GCM, ChaCha20-Poly1305)."
                ),
                passed=False,
            )

        strongest = max(scan.ciphers, key=lambda c: c["bits"] or 0)
        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="No weak cipher suites detected",
            description=(
                f"Strongest offered cipher: {strongest['name']} "
                f"({strongest['bits']} bits). No weak ciphers accepted."
            ),
            evidence=evidence,
            recommendation="",
            passed=True,
        )

    @staticmethod
    def _extract_host_port(target_url: str):
        parsed = urlparse(target_url)
        return parsed.hostname, (parsed.port or DEFAULT_PORT)