import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

SSLSCAN_TIMEOUT = 120  # seconds


class SSLScanError(Exception):
    """Raised when sslscan cannot be run, times out, or its output
    cannot be parsed."""


@dataclass
class SSLScanResult:
    supported_protocols: list = field(default_factory=list)
    ciphers: list = field(default_factory=list)  # [{"name", "protocol", "bits"}, ...]


def run_sslscan(hostname: str, port: int = 443, timeout: int = SSLSCAN_TIMEOUT) -> SSLScanResult:
    """..."""
    target = f"{hostname}:{port}"
    try:
        proc = subprocess.run(
            ["sslscan", "--no-colour", "--xml=-", target],
            capture_output=True,
            timeout=timeout,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SSLScanError("sslscan is not installed in this environment") from exc
    except subprocess.TimeoutExpired as exc:
        raise SSLScanError(f"sslscan timed out after {timeout}s") from exc

    if not proc.stdout.strip():
        raise SSLScanError(f"sslscan produced no output (stderr={proc.stderr.strip()})")

    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError as exc:
        raise SSLScanError(f"could not parse sslscan XML output: {exc}") from exc

    ssltest = root.find(".//ssltest")
    if ssltest is None:
        raise SSLScanError("sslscan output missing <ssltest> element (target may be unreachable)")

    # Read enabled protocol versions directly from <protocol> elements,
    # independent of cipher results — this is the authoritative source
    # for "does this server support this protocol at all".
    supported_protocols = set()
    for protocol_el in ssltest.findall("protocol"):
        if protocol_el.get("enabled") == "1":
            proto_type = protocol_el.get("type")
            version = protocol_el.get("version")
            supported_protocols.add(_format_protocol_name(proto_type, version))

    # A cipher can be reported as "preferred" (the server's top choice
    # for that protocol) or "accepted" (also usable but not preferred).
    # Both indicate the server genuinely offers that cipher — only
    # "rejected"/other statuses should be excluded.
    ciphers = []
    for cipher_el in ssltest.findall("cipher"):
        if cipher_el.get("status") not in ("accepted", "preferred"):
            continue
        protocol = cipher_el.get("sslversion", "")
        name = cipher_el.get("cipher", "")
        bits = cipher_el.get("bits")
        ciphers.append(
            {
                "name": name,
                "protocol": protocol,
                "bits": int(bits) if bits and bits.isdigit() else None,
            }
        )

    return SSLScanResult(supported_protocols=sorted(supported_protocols), ciphers=ciphers)


def _format_protocol_name(proto_type: str, version: str) -> str:
    """Converts sslscan's <protocol type="tls" version="1.2"> into the
    "TLSv1.2" style string used elsewhere (matching what Python's ssl
    module and the rest of this codebase use for protocol names)."""
    if proto_type == "ssl":
        return f"SSLv{version}"
    return f"TLSv{version}"