import socket
import ssl

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10  # seconds


def open_tls_connection(hostname: str, port: int = DEFAULT_PORT, timeout: int = DEFAULT_TIMEOUT):
    """Opens a TLS connection using strict, secure validation (the
    client's default trust policy). Raises ssl.SSLError if the
    certificate is expired, untrusted, or has a hostname mismatch —
    the handshake fails before any certificate details are available.

    Used by SSLCertCheck. TLSVersionCheck and CipherStrengthCheck no
    longer use this module at all — they use sslscan_utils.py instead,
    since Python's ssl module (bound by the host's OpenSSL security
    policy) cannot reliably negotiate down to weak/legacy protocols
    and ciphers even when deliberately relaxed. This was confirmed via
    live testing against badssl.com's rc4/3des/legacy-TLS subdomains.
    """
    context = ssl.create_default_context()
    sock = socket.create_connection((hostname, port), timeout=timeout)
    return context.wrap_socket(sock, server_hostname=hostname)


def open_tls_connection_insecure(
    hostname: str, port: int = DEFAULT_PORT, timeout: int = DEFAULT_TIMEOUT
):
    """Opens a TLS connection with certificate TRUST validation
    disabled, so the handshake completes even for expired/self-signed/
    mismatched certs, allowing the caller to inspect the certificate
    manually. Protocol/cipher negotiation still uses normal secure
    defaults here — only trust checking is relaxed.

    SECURITY NOTE: provides no trust guarantees. Never use to fetch or
    trust actual content. Used by SSLCertCheck to report *why* a
    certificate is invalid (expired vs. untrusted vs. other) instead
    of a generic handshake failure.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((hostname, port), timeout=timeout)
    return context.wrap_socket(sock, server_hostname=hostname)
