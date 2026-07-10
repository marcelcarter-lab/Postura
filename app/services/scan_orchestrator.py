import logging

from app.services.checks.base import CheckResult
from app.services.checks.schema import Severity
from app.services.checks.csp_check import CSPCheck
from app.services.checks.hsts_check import HSTSCheck
from app.services.checks.x_frame_options_check import XFrameOptionsCheck
from app.services.checks.x_content_type_options_check import XContentTypeOptionsCheck
from app.services.checks.referrer_policy_check import ReferrerPolicyCheck
from app.services.checks.permissions_policy_check import PermissionsPolicyCheck
from app.services.checks.ssl_cert_check import SSLCertCheck
from app.services.checks.tls_version_check import TLSVersionCheck
from app.services.checks.cipher_check import CipherStrengthCheck
from app.services.checks.exposure_check import ExposureCheck
from app.services.checks.directory_listing_check import DirectoryListingCheck
from app.services.checks.server_header_check import ServerHeaderCheck
from app.services.checks.x_powered_by_check import XPoweredByCheck
from app.services.checks.meta_generator_check import MetaGeneratorCheck
from app.services.checks.cms_fingerprint_check import CMSFingerprintCheck

logger = logging.getLogger(__name__)

ENABLED_CHECKS = [
    # Sprint 1: HTTP security headers
    CSPCheck,
    HSTSCheck,
    XFrameOptionsCheck,
    XContentTypeOptionsCheck,
    ReferrerPolicyCheck,
    PermissionsPolicyCheck,
    # Sprint 1: SSL/TLS
    SSLCertCheck,
    TLSVersionCheck,
    CipherStrengthCheck,
    # Sprint 2: exposure detection + fingerprinting
    ExposureCheck,
    DirectoryListingCheck,
    ServerHeaderCheck,
    XPoweredByCheck,
    MetaGeneratorCheck,
    CMSFingerprintCheck,
]


def run_scan(target_url: str) -> list:
    """Runs all enabled checks sequentially against target_url and
    returns a list of CheckResult objects, one per check.

    Each check's own internal error handling covers expected failures
    (network errors, handshake failures, etc.) by returning an INFO
    "could not evaluate" CheckResult. This function adds an additional
    safety net: if a check raises an unexpected exception (a bug, not
    a handled failure mode), it's caught here and converted into a
    synthetic CheckResult instead of aborting the entire scan, so one
    broken check can't take down results from every other check.
    """
    results = []

    for check_class in ENABLED_CHECKS:
        check = check_class(target_url)
        try:
            result = check.run()
        except Exception as exc:  # noqa: BLE001 — intentionally broad, see docstring
            logger.exception("Check %s raised an unexpected exception", check_class.__name__)
            result = CheckResult(
                check_type=getattr(check_class, "check_type", check_class.__name__),
                severity=Severity.INFO,
                title=f"{check_class.__name__} failed unexpectedly",
                description="This check raised an unexpected error and could not complete.",
                evidence=f"error={exc!r}",
                recommendation="Report this to the development team; this indicates a bug in the check itself.",
                passed=False,
            )
        results.append(result)

    return results
