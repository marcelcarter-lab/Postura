import responses
from app.services.checks.referrer_policy_check import ReferrerPolicyCheck

TARGET_URL = "https://example.com"


@responses.activate
def test_missing_referrer_policy():
    responses.add(responses.GET, TARGET_URL, headers={}, status=200)
    result = ReferrerPolicyCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "Missing Referrer-Policy header"
    assert result.passed is False


@responses.activate
def test_unsafe_url():
    responses.add(
        responses.GET, TARGET_URL, headers={"Referrer-Policy": "unsafe-url"}, status=200
    )
    result = ReferrerPolicyCheck(TARGET_URL).run()
    assert result.severity.value == "medium"
    assert result.title == "Referrer-Policy set to unsafe-url"
    assert result.passed is False


@responses.activate
def test_middle_ground_value():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Referrer-Policy": "origin-when-cross-origin"},
        status=200,
    )
    result = ReferrerPolicyCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "Referrer-Policy could be tightened"
    assert result.passed is False


@responses.activate
def test_unrecognized_value():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Referrer-Policy": "not-a-real-value"},
        status=200,
    )
    result = ReferrerPolicyCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "Referrer-Policy has an unrecognized value"
    assert result.passed is False


@responses.activate
def test_safe_value():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Referrer-Policy": "strict-origin-when-cross-origin"},
        status=200,
    )
    result = ReferrerPolicyCheck(TARGET_URL).run()
    assert result.severity.value == "info"
    assert result.title == "Referrer-Policy configured safely"
    assert result.passed is True


@responses.activate
def test_fallback_chain_evaluates_last_value():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Referrer-Policy": "no-referrer, strict-origin-when-cross-origin"},
        status=200,
    )
    result = ReferrerPolicyCheck(TARGET_URL).run()
    assert result.severity.value == "info"
    assert result.passed is True
