import ipaddress
import socket
from urllib.parse import urlparse

# Hostnames explicitly permitted to bypass the private-IP block, for
# legitimate internal testing purposes only (e.g. our own local
# vulnerable test target, run within the same Docker Compose network).
# This is a narrow, explicit allowlist — NOT a general escape hatch.
ALLOWED_INTERNAL_HOSTNAMES = {"test-target"}


class SSRFBlockedError(Exception):
    """Raised when a scan target resolves to a private/internal IP
    address and is not on the explicit internal-testing allowlist."""


def assert_safe_scan_target(url: str) -> None:
    """Raises SSRFBlockedError if `url`'s hostname resolves to a
    private, loopback, link-local, or otherwise non-public IP address
    — preventing the scanner from being used to probe internal
    network resources (classic SSRF risk). Does nothing (returns
    normally) if the target is safe to scan.

    This performs actual DNS resolution (not just inspecting the
    hostname string), since an attacker-controlled DNS name could
    resolve to a private IP even if the hostname itself looks
    innocuous (DNS rebinding-style risk) — checking the string alone
    would not be sufficient.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        raise SSRFBlockedError("Could not determine hostname from target URL.")

    if hostname in ALLOWED_INTERNAL_HOSTNAMES:
        return

    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"Could not resolve hostname: {hostname}") from exc

    ip_obj = ipaddress.ip_address(resolved_ip)

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    ):
        raise SSRFBlockedError(
            f"Scan target '{hostname}' resolves to a private/internal "
            f"IP address ({resolved_ip}) and cannot be scanned."
        )
