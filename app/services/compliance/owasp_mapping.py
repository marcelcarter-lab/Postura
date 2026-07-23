"""Maps each Postura check_type to an OWASP Top 10 (2021) category.

This mapping is inherently approximate: the OWASP Top 10 describes
general web application vulnerability classes (broken access control,
injection, etc.), while Postura is a configuration/exposure posture
scanner — most of our checks map reasonably well onto "Security
Misconfiguration" or "Cryptographic Failures," but a few are looser
fits assigned based on the closest reasonable category rather than a
precise, unambiguous match. See docs/owasp-mapping-rationale.md (added
in a later Sprint 9 task) for the full reasoning behind each
assignment, including the looser fits.
"""

OWASP_A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
OWASP_A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
OWASP_A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
OWASP_A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"

CHECK_TYPE_TO_OWASP_CATEGORY = {
    # --- Security headers: primarily misconfiguration (a missing/
    # weak header is a server config gap, not a code-level flaw) ---
    "csp_header": OWASP_A05_SECURITY_MISCONFIGURATION,
    "hsts_header": OWASP_A05_SECURITY_MISCONFIGURATION,
    "x_frame_options": OWASP_A05_SECURITY_MISCONFIGURATION,
    "x_content_type_options": OWASP_A05_SECURITY_MISCONFIGURATION,
    "referrer_policy": OWASP_A05_SECURITY_MISCONFIGURATION,
    "permissions_policy": OWASP_A05_SECURITY_MISCONFIGURATION,
    # --- SSL/TLS: cryptographic configuration issues ---
    "ssl_cert_validity": OWASP_A02_CRYPTOGRAPHIC_FAILURES,
    "tls_protocol_strength": OWASP_A02_CRYPTOGRAPHIC_FAILURES,
    "cipher_suite_strength": OWASP_A02_CRYPTOGRAPHIC_FAILURES,
    # --- Exposure detection: an exposed .git/.env/backup file is a
    # server serving files it shouldn't — a misconfiguration, but one
    # with a direct access-control dimension too (unintended public
    # access to files that should be restricted). Assigned to
    # misconfiguration as the primary/closest category. ---
    "exposure_detection": OWASP_A05_SECURITY_MISCONFIGURATION,
    "directory_listing": OWASP_A05_SECURITY_MISCONFIGURATION,
    # --- Fingerprinting / version disclosure: these reveal
    # information about server/technology versions, which relates most
    # closely to "Vulnerable and Outdated Components" when a specific
    # version is disclosed (the point of caring about the version at
    # all is usually "is this version known-vulnerable") ---
    "server_header_disclosure": OWASP_A06_VULNERABLE_COMPONENTS,
    "x_powered_by_disclosure": OWASP_A06_VULNERABLE_COMPONENTS,
    "meta_generator_disclosure": OWASP_A06_VULNERABLE_COMPONENTS,
    "cms_fingerprint": OWASP_A06_VULNERABLE_COMPONENTS,
    "js_framework_fingerprint": OWASP_A06_VULNERABLE_COMPONENTS,
    "wordpress_version": OWASP_A06_VULNERABLE_COMPONENTS,
    # --- Sprint 11: API security checks & error leakage ---
    "missing_auth_rest_paths": OWASP_A01_BROKEN_ACCESS_CONTROL,
    "verbose_error_leakage": OWASP_A05_SECURITY_MISCONFIGURATION,
    "permissive_cors": OWASP_A05_SECURITY_MISCONFIGURATION,
}


def get_owasp_category(check_type: str) -> str:
    """Returns the OWASP Top 10 category for a given check_type, or
    'Uncategorized' if no mapping exists (e.g. a future check added
    without updating this table — fails gracefully rather than
    raising, so an unmapped check doesn't crash compliance scoring)."""
    return CHECK_TYPE_TO_OWASP_CATEGORY.get(check_type, "Uncategorized")
