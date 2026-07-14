import shutil
import subprocess
import defusedxml.ElementTree as ET
from dataclasses import dataclass, field

SSLSCAN_TIMEOUT = 120  # seconds — sslscan opens a fresh connection per
# protocol/cipher combination tested; a full scan against a server with
# many enabled protocols/ciphers can take 60-90+ seconds. Confirmed via
# live testing: a scan against badssl.com took ~59s.

# Resolved once at import time rather than relying on subprocess.run()
# to search $PATH at call time (addresses bandit B607: starting a
# process with a partial executable path).
SSLSCAN_PATH = shutil.which("sslscan")


class SSLScanError(Exception):
    """Raised when sslscan cannot be run, times out, or its output
    cannot be parsed."""


@dataclass
class SSLScanResult:
    supported_protocols: list = field(default_factory=list)
    ciphers: list = field(default_factory=list)  # [{"name", "protocol", "bits"}, ...]


def run_sslscan(hostname: str, port: int = 443, timeout: int = SSLSCAN_TIMEOUT) -> SSLScanResult:
    """Runs the external sslscan tool against hostname:port and parses
    its XML output.

    Unlike Python's ssl module (bound by the host's OpenSSL security
    policy — confirmed unable to negotiate RC4/3DES even with
    SECLEVEL=0), sslscan ships its own statically-linked OpenSSL build
    with legacy protocols/ciphers intact, so it can reliably report
    what a server actually offers, not just what our client is willing
    to accept.
    """
    if SSLSCAN_PATH is None:
        raise SSLScanError("sslscan is not installed in this environment")

    target = f"{hostname}:{port}"
    try:
        proc = subprocess.run(  # nosec B603 B607 - shell=False, list-form args, resolved absolute path, no shell interpretation of `target`
            [SSLSCAN_PATH, "--no-colour", "--xml=-", target],
            capture_output=True,
            timeout=timeout,
            text=True,
        )
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

    supported_protocols = set()
    for protocol_el in ssltest.findall("protocol"):
        if protocol_el.get("enabled") == "1":
            proto_type = protocol_el.get("type")
            version = protocol_el.get("version")
            supported_protocols.add(_format_protocol_name(proto_type, version))

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
