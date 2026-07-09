import responses
from app.services.checks.permissions_policy_check import PermissionsPolicyCheck

TARGET_URL = "https://example.com"


@responses.activate
def test_missing_permissions_policy():
    responses.add(responses.GET, TARGET_URL, headers={}, status=200)
    result = PermissionsPolicyCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "Missing Permissions-Policy header"
    assert result.passed is False


@responses.activate
def test_whitespace_only_value():
    responses.add(
        responses.GET, TARGET_URL, headers={"Permissions-Policy": "   "}, status=200
    )
    result = PermissionsPolicyCheck(TARGET_URL).run()
    assert result.severity.value == "low"
    assert result.title == "Missing Permissions-Policy header"
    assert result.passed is False


@responses.activate
def test_present_with_directives():
    responses.add(
        responses.GET,
        TARGET_URL,
        headers={"Permissions-Policy": "camera=(), microphone=(), geolocation=(self)"},
        status=200,
    )
    result = PermissionsPolicyCheck(TARGET_URL).run()
    assert result.severity.value == "info"
    assert result.title == "Permissions-Policy present"
    assert result.passed is True
