import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.tls_utils import open_tls_connection

EXPIRY_WARNING_DAYS = 30

# Certificate dates from the ssl module are returned in this format,
# e.g. "Jan 15 12:00:00 2027 GMT"
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


class SSLCertCheck(BaseCheck):
    """Checks the target's TLS certificate validity: whether it has
    expired, is expiring soon, and basic issuer information. Operates
    at the TLS layer directly via tls_utils.open_tls_connection, not
    via the HTTP fetch wrapper used by header checks.
    """

    check_type = "ssl_cert_validity"

    def run(self) -> CheckResult:
        hostname = self._extract_hostname(self.target_url)

        if not hostname:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate SSL certificate",
                description="Could not extract a hostname from the target URL.",
                evidence=f"target_url={self.target_url}",
                recommendation="Ensure the target URL is well-formed.",
                passed=False,
            )

        try:
            with open_tls_connection(hostname) as ssock:
                cert = ssock.getpeercert()
        except (ssl.SSLError, socket.error, socket.timeout, ConnectionError) as exc:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate SSL certificate",
                description="Could not complete a TLS handshake with the target.",
                evidence=f"error={exc}",
                recommendation="Ensure the target supports HTTPS on port 443 and retry.",
                passed=False,
            )

        not_after = self._parse_cert_date(cert.get("notAfter"))
        not_before = self._parse_cert_date(cert.get("notBefore"))
        issuer = self._format_name(cert.get("issuer"))

        if not_after is None:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="Could not evaluate SSL certificate",
                description="The certificate's expiration date could not be parsed.",
                evidence=f"raw_notAfter={cert.get('notAfter')}",
                recommendation="Manually inspect the certificate.",
                passed=False,
            )

        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days

        evidence = (
            f"issuer={issuer} | notBefore={not_before} | notAfter={not_after} | "
            f"days_remaining={days_remaining}"
        )

        if days_remaining < 0:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.CRITICAL,
                title="SSL certificate has expired",
                description=(
                    f"The SSL certificate expired {abs(days_remaining)} day(s) "
                    "ago. Browsers will show security warnings or block access "
                    "entirely."
                ),
                evidence=evidence,
                recommendation="Renew the SSL certificate immediately.",
                passed=False,
            )

        if days_remaining <= EXPIRY_WARNING_DAYS:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.MEDIUM,
                title="SSL certificate expiring soon",
                description=(
                    f"The SSL certificate expires in {days_remaining} day(s), "
                    f"within the {EXPIRY_WARNING_DAYS}-day warning window."
                ),
                evidence=evidence,
                recommendation="Renew the SSL certificate before it expires.",
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="SSL certificate is valid",
            description=f"The SSL certificate is valid for {days_remaining} more day(s).",
            evidence=evidence,
            recommendation="",
            passed=True,
        )

    @staticmethod
    def _extract_hostname(target_url: str):
        parsed = urlparse(target_url)
        return parsed.hostname

    @staticmethod
    def _parse_cert_date(date_str):
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @staticmethod
    def _format_name(name_tuples):
        """Certificate issuer/subject fields come as a nested tuple
        structure like ((('countryName', 'US'),), (('organizationName',
        'Example CA'),), ...). Flattens to a readable string."""
        if not name_tuples:
            return "unknown"
        parts = []
        for rdn in name_tuples:
            for key, value in rdn:
                parts.append(f"{key}={value}")
        return ", ".join(parts)
