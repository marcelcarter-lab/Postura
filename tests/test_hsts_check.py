import responses
from app.services.checks.hsts_check import HSTSCheck

TARGET_URL = "https://example.com"


@responses.activate
def test_missing_hsts_header():
    responses.add(responses.GET, TARGET_URL, headers={}, status=200)
    result = HSTSCheck(TARGET_URL).run()
    assert result.severity.value == "medium"
    assert result.title == "Missing Strict-Transport-Security header"
    assert result.passed is False


@responses.activate
def test_weak_max_age():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Strict-Transport-Security": "max-age=3600"},
        status=200,
    )
    result = HSTSCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "Strict-Transport-Security max-age too low"
    assert result.passed is False


@responses.activate
def test_strong_hsts():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"},
        status=200,
    )
    result = HSTSCheck(TARGET_URL).run()
    assert result.severity.value == "info"
    assert result.title == "Strict-Transport-Security configured adequately"
    assert result.passed is True


@responses.activate
def test_malformed_hsts():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Strict-Transport-Security": "includeSubDomains"},
        status=200,
    )
    result = HSTSCheck(TARGET_URL).run()
    assert result.severity.value == "medium"
    assert result.title == "Strict-Transport-Security present but malformed"
    assert result.passed is False
