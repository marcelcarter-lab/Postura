import responses
from app.services.checks.schema import Severity
from app.services.checks.verbose_error_leakage_check import VerboseErrorLeakageCheck


@responses.activate
def test_clean_error_response_passes():
    responses.add(
        responses.GET,
        "https://example.com/nonexistent-postura-test-404",
        body="<html><body><h1>404 Not Found</h1><p>Page does not exist.</p></body></html>",
        status=404,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/nonexistent-postura-test-404",
        body='{"error": "Not Found", "message": "Resource unavailable"}',
        status=404,
    )
    responses.add(
        responses.GET,
        "https://example.com/?postura_test_err=%27%22%3Cscript%3E",
        body="<html><body><h1>Welcome</h1></body></html>",
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/",
        body="<html><body><h1>Welcome</h1></body></html>",
        status=200,
    )

    check = VerboseErrorLeakageCheck("https://example.com")
    result = check.run()

    assert result.passed is True
    assert result.severity == Severity.INFO
    assert result.title == "No verbose error leakage detected"


@responses.activate
def test_python_traceback_detected():
    responses.add(
        responses.GET,
        "https://example.com/nonexistent-postura-test-404",
        body="""
        <html>
        <head><title>500 Internal Server Error</title></head>
        <body>
        <h1>500 Error</h1>
        <pre>
Traceback (most recent call last):
  File "/app/routes.py", line 42, in get_user
    user = users[user_id]
KeyError: 'invalid'
        </pre>
        </body>
        </html>
        """,
        status=500,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/nonexistent-postura-test-404",
        body='{"error": "Not Found"}',
        status=404,
    )
    responses.add(
        responses.GET,
        "https://example.com/?postura_test_err=%27%22%3Cscript%3E",
        body="OK",
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/",
        body="OK",
        status=200,
    )

    check = VerboseErrorLeakageCheck("https://example.com")
    result = check.run()

    assert result.passed is False
    assert result.severity == Severity.HIGH
    assert "Verbose error leakage detected" in result.title
    assert "Python Traceback" in result.evidence


@responses.activate
def test_node_stack_trace_detected():
    responses.add(
        responses.GET,
        "https://example.com/nonexistent-postura-test-404",
        body="404",
        status=404,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/nonexistent-postura-test-404",
        body="""
        TypeError: Cannot read property 'id' of undefined
            at /app/dist/controllers/userController.js:84:12
            at processTicksAndRejections (internal/process/task_queues.js:95:5)
        """,
        status=500,
    )
    responses.add(
        responses.GET,
        "https://example.com/?postura_test_err=%27%22%3Cscript%3E",
        body="OK",
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/",
        body="OK",
        status=200,
    )

    check = VerboseErrorLeakageCheck("https://example.com")
    result = check.run()

    assert result.passed is False
    assert result.severity == Severity.HIGH
    assert "Verbose error leakage detected" in result.title


@responses.activate
def test_java_stack_trace_detected():
    responses.add(
        responses.GET,
        "https://example.com/nonexistent-postura-test-404",
        body="""
        <html><body>
        <h2>HTTP Status 500 – Internal Server Error</h2>
        <p><b>Exception</b></p>
        <pre>java.lang.NullPointerException
            at com.example.service.UserService.getUserDetails(UserService.java:54)
            at com.example.controller.UserController.get(UserController.java:23)
        </pre>
        </body></html>
        """,
        status=500,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/nonexistent-postura-test-404",
        body="404",
        status=404,
    )
    responses.add(
        responses.GET,
        "https://example.com/?postura_test_err=%27%22%3Cscript%3E",
        body="OK",
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/",
        body="OK",
        status=200,
    )

    check = VerboseErrorLeakageCheck("https://example.com")
    result = check.run()

    assert result.passed is False
    assert result.severity == Severity.HIGH
    assert "Java Exception" in result.evidence or "Java Stack Trace" in result.evidence


@responses.activate
def test_aspnet_server_error_detected():
    responses.add(
        responses.GET,
        "https://example.com/nonexistent-postura-test-404",
        body="""
        <html>
        <head><title>Server Error in '/' Application.</title></head>
        <body>
        <h1>Server Error in '/' Application.</h1>
        <hr width=100% size=1 color=silver>
        <h2> <i>Runtime Error</i> </h2>
        </body>
        </html>
        """,
        status=500,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/nonexistent-postura-test-404",
        body="404",
        status=404,
    )
    responses.add(
        responses.GET,
        "https://example.com/?postura_test_err=%27%22%3Cscript%3E",
        body="OK",
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/",
        body="OK",
        status=200,
    )

    check = VerboseErrorLeakageCheck("https://example.com")
    result = check.run()

    assert result.passed is False
    assert result.severity == Severity.HIGH
    assert "ASP.NET Server Error Page" in result.evidence


@responses.activate
def test_php_laravel_whoops_detected():
    responses.add(
        responses.GET,
        "https://example.com/nonexistent-postura-test-404",
        body="<html><body>Whoops! There was an error.</body></html>",
        status=500,
    )
    responses.add(
        responses.GET,
        "https://example.com/api/nonexistent-postura-test-404",
        body="404",
        status=404,
    )
    responses.add(
        responses.GET,
        "https://example.com/?postura_test_err=%27%22%3Cscript%3E",
        body="OK",
        status=200,
    )
    responses.add(
        responses.GET,
        "https://example.com/",
        body="OK",
        status=200,
    )

    check = VerboseErrorLeakageCheck("https://example.com")
    result = check.run()

    assert result.passed is False
    assert result.severity == Severity.HIGH
    assert "Laravel Whoops Debugger" in result.evidence
