import socket
import ssl

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10  # seconds


def open_tls_connection(hostname: str, port: int = DEFAULT_PORT, timeout: int = DEFAULT_TIMEOUT):
    """Opens a TLS connection to hostname:port and returns the wrapped
    ssl.SSLSocket, still open, positioned right after the handshake.
    Caller is responsible for closing it (use as a context manager).

    Raises ssl.SSLError, socket.error, socket.timeout, or
    ConnectionError on failure — callers should catch these broadly,
    since a raw handshake can fail in many ways (untrusted cert,
    hostname mismatch, connection refused, timeout, etc.) and this
    helper does not attempt to distinguish between them.
    """
    context = ssl.create_default_context()
    sock = socket.create_connection((hostname, port), timeout=timeout)
    return context.wrap_socket(sock, server_hostname=hostname)
