import responses
from app.services.checks.csp_check import CSPCheck

TARGET_URL = "https://example.com"


@responses.activate
def test_missing_csp_header():
    responses.add(responses.GET, TARGET_URL, headers={}, status=200)
    result = CSPCheck(TARGET_URL).run()
    assert result.severity.value == "medium"
    assert result.title == "Missing Content-Security-Policy header"
    assert result.passed is False


@responses.activate
def test_weak_csp_header():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"},
        status=200,
    )
    result = CSPCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "Content-Security-Policy present but weak"
    assert result.passed is False


@responses.activate
def test_good_csp_header():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'"
        },
        status=200,
    )
    result = CSPCheck(TARGET_URL).run()
    assert result.severity.value == "info"
    assert result.title == "Content-Security-Policy present and reasonably configured"
    assert result.passed is True
