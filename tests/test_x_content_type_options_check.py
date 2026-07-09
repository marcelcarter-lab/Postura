import responses
from app.services.checks.x_content_type_options_check import XContentTypeOptionsCheck

TARGET_URL = "https://example.com"


@responses.activate
def test_missing_xcto():
    responses.add(responses.GET, TARGET_URL, headers={}, status=200)
    result = XContentTypeOptionsCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "Missing X-Content-Type-Options header"
    assert result.passed is False


@responses.activate
def test_wrong_value():
    responses.add(
        responses.GET, TARGET_URL, headers={"X-Content-Type-Options": "sniff"}, status=200
    )
    result = XContentTypeOptionsCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "X-Content-Type-Options has an invalid value"
    assert result.passed is False


@responses.activate
def test_nosniff():
    responses.add(
        responses.GET, TARGET_URL, headers={"X-Content-Type-Options": "nosniff"}, status=200
    )
    result = XContentTypeOptionsCheck(TARGET_URL).run()
    assert result.severity.value == "info"
    assert result.title == "X-Content-Type-Options configured correctly"
    assert result.passed is True
