import pytest
from app.services.scan_orchestrator import run_scan

# These tests require the `test-target` Docker Compose service to be
# running (docker compose up -d test-target) and are run FROM INSIDE
# the `web` container, where "test-target" resolves via Docker's
# internal DNS. They will fail with connection errors if run from the
# host or if the test-target service isn't up.
pytestmark = pytest.mark.integration

TEST_TARGET_URL = "http://test-target:5001"


def _find_result(results, check_type):
    for r in results:
        if r.check_type == check_type:
            return r
    raise AssertionError(f"No result found for check_type={check_type!r}")


@pytest.fixture(scope="module")
def scan_results():
    return run_scan(TEST_TARGET_URL)


def test_scan_produces_a_result_for_every_enabled_check(scan_results):
    from app.services.scan_orchestrator import ENABLED_CHECKS

    assert len(scan_results) == len(ENABLED_CHECKS)


def test_missing_security_headers_detected(scan_results):
    for check_type in ("csp_header", "hsts_header", "x_frame_options"):
        result = _find_result(scan_results, check_type)
        assert result.passed is False
        assert result.severity.value == "medium"


def test_exposed_git_files_detected(scan_results):
    result = _find_result(scan_results, "exposure_detection")
    assert result.passed is False
    assert result.severity.value == "critical"
    assert ".git/HEAD" in result.evidence
    assert ".git/config" in result.evidence


def test_directory_listing_detected(scan_results):
    result = _find_result(scan_results, "directory_listing")
    assert result.passed is False
    assert result.severity.value == "medium"


def test_cms_fingerprint_detects_wordpress_signature(scan_results):
    result = _find_result(scan_results, "cms_fingerprint")
    assert result.passed is True  # informational, not a failure — see task 10's design note
    assert "WordPress" in result.title


def test_ssl_checks_report_could_not_evaluate_for_plain_http_target(scan_results):
    # The test target serves plain HTTP, no TLS at all — SSL/TLS
    # checks should gracefully report "could not evaluate", not crash.
    for check_type in ("ssl_cert_validity", "tls_protocol_strength", "cipher_suite_strength"):
        result = _find_result(scan_results, check_type)
        assert result.severity.value == "info"
        assert result.passed is False
