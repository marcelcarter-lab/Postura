import responses

from tests.conftest import load_html_fixture
from app.services.checks.js_framework_check import JSFrameworkCheck
from app.services.checks.cms_fingerprint_check import CMSFingerprintCheck
from app.services.checks.cms_signatures import CMS_SIGNATURE_PATHS
from app.services.checks.wordpress_version_check import WordPressVersionCheck

TARGET_URL = "https://example.com"


@responses.activate
def test_react_fixture_detected():
    responses.add(responses.GET, TARGET_URL, body=load_html_fixture("react_app.html"), status=200)
    result = JSFrameworkCheck(TARGET_URL).run()
    assert "React" in result.title
    assert result.passed is True


@responses.activate
def test_nextjs_fixture_detected_as_high_confidence():
    responses.add(responses.GET, TARGET_URL, body=load_html_fixture("nextjs_app.html"), status=200)
    result = JSFrameworkCheck(TARGET_URL).run()
    assert "Next.js" in result.title
    assert "high confidence" in result.title


@responses.activate
def test_vue_fixture_detected():
    responses.add(responses.GET, TARGET_URL, body=load_html_fixture("vue_app.html"), status=200)
    result = JSFrameworkCheck(TARGET_URL).run()
    assert "Vue" in result.title


@responses.activate
def test_angular_fixture_detected_with_version_evidence():
    responses.add(responses.GET, TARGET_URL, body=load_html_fixture("angular_app.html"), status=200)
    result = JSFrameworkCheck(TARGET_URL).run()
    assert "Angular" in result.title
    assert "ng-version" in result.evidence.lower() or "Angular" in result.evidence


@responses.activate
def test_plain_html_fixture_detects_nothing():
    responses.add(responses.GET, TARGET_URL, body=load_html_fixture("plain_html.html"), status=200)
    result = JSFrameworkCheck(TARGET_URL).run()
    assert result.title == "No JS framework fingerprint detected"
    assert result.passed is True


@responses.activate
def test_wordpress_generator_fixture_detects_vulnerable_version():
    responses.add(responses.GET, TARGET_URL, body=load_html_fixture("wordpress_generator.html"), status=200)
    result = WordPressVersionCheck(TARGET_URL).run()
    assert "4.7.1" in result.title
    assert result.passed is False
    assert result.severity.value == "critical"


@responses.activate
def test_cms_fingerprint_high_confidence_path():
    for path in CMS_SIGNATURE_PATHS:
        status = 200 if path == "wp-login.php" else 404
        responses.add(responses.GET, f"{TARGET_URL}/{path}", status=status)
    result = CMSFingerprintCheck(TARGET_URL).run()
    assert "WordPress" in result.title
    assert "high" in result.title.lower()


@responses.activate
def test_cms_fingerprint_possible_confidence_path():
    for path in CMS_SIGNATURE_PATHS:
        status = 200 if path == "administrator/" else 404
        responses.add(responses.GET, f"{TARGET_URL}/{path}", status=status)
    result = CMSFingerprintCheck(TARGET_URL).run()
    assert "Joomla" in result.title
    assert "possible" in result.title.lower()
