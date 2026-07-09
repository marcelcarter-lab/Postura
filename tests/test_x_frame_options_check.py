import responses
from app.services.checks.x_frame_options_check import XFrameOptionsCheck

TARGET_URL = "https://example.com"


@responses.activate
def test_missing_xfo():
    responses.add(responses.GET, TARGET_URL, headers={}, status=200)
    result = XFrameOptionsCheck(TARGET_URL).run()
    assert result.severity.value == "medium"
    assert result.title == "Missing X-Frame-Options header"
    assert result.passed is False


@responses.activate
def test_allow_from_deprecated():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"X-Frame-Options": "ALLOW-FROM https://example.com"},
        status=200,
    )
    result = XFrameOptionsCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "X-Frame-Options uses deprecated ALLOW-FROM value"
    assert result.passed is False


@responses.activate
def test_invalid_value():
    responses.add(
        responses.GET, TARGET_URL, headers={"X-Frame-Options": "MAYBE"}, status=200
    )
    result = XFrameOptionsCheck(TARGET_URL).run()
    assert result.severity.value == "medium"
    assert result.title == "X-Frame-Options has an invalid value"
    assert result.passed is False


@responses.activate
def test_sameorigin():
    responses.add(
        responses.GET, TARGET_URL, headers={"X-Frame-Options": "SAMEORIGIN"}, status=200
    )
    result = XFrameOptionsCheck(TARGET_URL).run()
    assert result.severity.value == "info"
    assert result.title == "X-Frame-Options configured correctly"
    assert result.passed is True


@responses.activate
def test_deny():
    responses.add(
        responses.GET, TARGET_URL, headers={"X-Frame-Options": "DENY"}, status=200
    )
    result = XFrameOptionsCheck(TARGET_URL).run()
    assert result.severity.value == "info"
    assert result.title == "X-Frame-Options configured correctly"
    assert result.passed is True
