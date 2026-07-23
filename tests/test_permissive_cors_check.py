import responses
from app.services.checks.permissive_cors_check import PermissiveCORSCheck, UNTRUSTED_ORIGIN
from app.services.checks.schema import Severity


@responses.activate
def test_strict_cors_or_absent_passes():
    responses.add(
        responses.GET,
        "https://example.com/",
        headers={"Content-Type": "text/html"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/",
        headers={"Access-Control-Allow-Origin": "https://trusted-domain.com"},
        status=200,
    )

    check = PermissiveCORSCheck("https://example.com")
    result = check.run()

    assert result.passed is True
    assert result.severity == Severity.INFO
    assert result.title == "No permissive CORS misconfiguration detected"


@responses.activate
def test_wildcard_cors_without_credentials_detected():
    responses.add(
        responses.GET,
        "https://example.com/",
        headers={"Access-Control-Allow-Origin": "*"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/",
        headers={"Access-Control-Allow-Origin": "*"},
        status=200,
    )

    check = PermissiveCORSCheck("https://example.com")
    result = check.run()

    assert result.passed is False
    assert result.severity == Severity.MEDIUM
    assert result.title == "Permissive CORS policy detected"
    assert "Wildcard '*'" in result.evidence


@responses.activate
def test_reflective_origin_with_credentials_detected():
    responses.add(
        responses.GET,
        "https://example.com/",
        headers={
            "Access-Control-Allow-Origin": UNTRUSTED_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/",
        headers={},
        status=200,
    )

    check = PermissiveCORSCheck("https://example.com")
    result = check.run()

    assert result.passed is False
    assert result.severity == Severity.HIGH
    assert "Overly permissive CORS configuration with credentials allowed" in result.title
    assert UNTRUSTED_ORIGIN in result.evidence


@responses.activate
def test_wildcard_with_credentials_detected():
    responses.add(
        responses.GET,
        "https://example.com/",
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/",
        headers={},
        status=200,
    )

    check = PermissiveCORSCheck("https://example.com")
    result = check.run()

    assert result.passed is False
    assert result.severity == Severity.HIGH
    assert "Overly permissive CORS configuration with credentials allowed" in result.title


@responses.activate
def test_null_origin_allowed_detected():
    responses.add(
        responses.GET,
        "https://example.com/",
        headers={},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/",
        headers={"Access-Control-Allow-Origin": "null"},
        status=200,
    )

    check = PermissiveCORSCheck("https://example.com")
    result = check.run()

    assert result.passed is False
    assert result.severity == Severity.MEDIUM
    assert "null" in result.evidence
