import pytest
from app.services.checks.ssl_cert_check import SSLCertCheck
from app.services.checks.tls_version_check import TLSVersionCheck
from app.services.checks.cipher_check import CipherStrengthCheck

# These are LIVE tests against badssl.com — no mocking. They require
# network access, and the TLS-version/cipher tests specifically call
# sslscan as a subprocess, so they take noticeably longer than the
# rest of the suite (each sslscan invocation can take 30-90+ seconds,
# since it opens a fresh connection per protocol/cipher combination
# tested).
pytestmark = pytest.mark.live


# --- SSLCertCheck: uses Python's ssl module directly (fast) ---


def test_expired_cert_detected():
    result = SSLCertCheck("https://expired.badssl.com").run()
    assert result.severity.value == "high"
    assert result.title == "SSL certificate is not trusted"
    assert "expired" in result.evidence.lower()
    assert result.passed is False


def test_self_signed_cert_untrusted():
    result = SSLCertCheck("https://self-signed.badssl.com").run()
    assert result.severity.value == "high"
    assert result.title == "SSL certificate is not trusted"
    assert result.passed is False


def test_good_cert_passes():
    result = SSLCertCheck("https://badssl.com").run()
    assert result.severity.value == "info"
    assert result.title == "SSL certificate is valid"
    assert result.passed is True


# --- TLSVersionCheck / CipherStrengthCheck: use sslscan (slower) ---
#
# NOTE: badssl.com itself (the "control" target) intentionally still
# offers TLS 1.0/1.1 and 3DES ciphers alongside modern options, as
# confirmed by direct sslscan inspection — so it correctly triggers a
# HIGH finding here too, same as the dedicated weak-protocol/cipher
# subdomains. This is accurate, not a bug: it reflects the site's
# actual (imperfect) configuration.


def test_rc4_subdomain_detects_weak_protocol():
    result = TLSVersionCheck("https://rc4.badssl.com").run()
    assert result.severity.value == "high"
    assert "TLSv1.0" in result.evidence
    assert "TLSv1.1" in result.evidence
    assert result.passed is False


def test_rc4_subdomain_detects_weak_cipher():
    result = CipherStrengthCheck("https://rc4.badssl.com").run()
    assert result.severity.value == "high"
    assert "RC4" in result.evidence
    assert result.passed is False


def test_3des_subdomain_detects_weak_cipher():
    result = CipherStrengthCheck("https://3des.badssl.com").run()
    assert result.severity.value == "high"
    assert "3DES" in result.evidence
    assert result.passed is False


def test_good_target_tls_version_reflects_actual_config():
    """badssl.com genuinely offers TLS 1.0/1.1 alongside 1.2, so this
    is correctly flagged HIGH — an accurate finding, not a false
    positive."""
    result = TLSVersionCheck("https://badssl.com").run()
    assert result.severity.value == "high"
    assert result.passed is False


def test_good_target_cipher_reflects_actual_config():
    """badssl.com genuinely offers 3DES alongside strong ciphers, so
    this is correctly flagged HIGH — an accurate finding, not a false
    positive."""
    result = CipherStrengthCheck("https://badssl.com").run()
    assert result.severity.value == "high"
    assert "3DES" in result.evidence
    assert result.passed is False