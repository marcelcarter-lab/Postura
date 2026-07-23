from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from urllib.parse import urljoin

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

# Paths and query payloads to probe for error response leakage
PROBE_TARGETS = [
    {"path": "nonexistent-postura-test-404", "desc": "non-existent page"},
    {"path": "api/nonexistent-postura-test-404", "desc": "non-existent API endpoint"},
    {"path": "?postura_test_err=%27%22%3Cscript%3E", "desc": "malformed query parameter"},
]

# Patterns representing verbose error messages, framework debug pages, or stack traces
STACK_TRACE_PATTERNS = [
    # Python / Flask / Werkzeug / Django
    (re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE), "Python Traceback"),
    (re.compile(r"Werkzeug Debugger", re.IGNORECASE), "Werkzeug Debugger"),
    (re.compile(r"django\.core\.exceptions\.", re.IGNORECASE), "Django Exception"),
    (re.compile(r"File \".+?\", line \d+, in ", re.IGNORECASE), "Python Stack Frame"),
    # Node.js / Express / JavaScript
    (
        re.compile(
            r"(?:TypeError|ReferenceError|SyntaxError|RangeError|URIError):\s+.+?\n\s+at\s+",
            re.IGNORECASE,
        ),
        "Node.js Exception Stack",
    ),
    (re.compile(r"\bError:\s+.+?\n\s+at\s+[^\n]+:\d+:\d+", re.IGNORECASE), "JavaScript Stack Trace"),
    (
        re.compile(
            r"\s+at\s+(?:Module\._compile|processTicksAndRejections|asyncGeneratorStep)",
            re.IGNORECASE,
        ),
        "Node.js Internal Stack Frame",
    ),
    # Java / Spring / Tomcat
    (re.compile(r"java\.lang\.[A-Za-z0-9_]+Exception", re.IGNORECASE), "Java Exception"),
    (
        re.compile(r"\s+at\s+[a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.]+\.java:\d+\)", re.IGNORECASE),
        "Java Stack Trace",
    ),
    (re.compile(r"org\.springframework\.[a-zA-Z0-9_\.]+", re.IGNORECASE), "Spring Stack Trace"),
    # ASP.NET / C#
    (re.compile(r"\[NullReferenceException:", re.IGNORECASE), "ASP.NET Exception"),
    (re.compile(r"System\.Web\.HttpUnhandledException", re.IGNORECASE), "ASP.NET Unhandled Exception"),
    (re.compile(r"Server Error in '[^']+' Application", re.IGNORECASE), "ASP.NET Server Error Page"),
    (re.compile(r"Stack Trace:\s*<pre>", re.IGNORECASE), "ASP.NET Stack Trace"),
    # PHP / Laravel / Symfony / Rails
    (re.compile(r"Fatal error:\s*Uncaught", re.IGNORECASE), "PHP Fatal Error"),
    (re.compile(r"Stack trace:\s*#0", re.IGNORECASE), "PHP Stack Trace"),
    (re.compile(r"Whoops!\s*There was an error\.", re.IGNORECASE), "Laravel Whoops Debugger"),
    (re.compile(r"Symfony\\Component\\Debug", re.IGNORECASE), "Symfony Debugger"),
    (re.compile(r"ActionView::Template::Error", re.IGNORECASE), "Ruby on Rails Template Error"),
    # Generic stack trace markers
    (re.compile(r"<b>Stack Trace:</b>", re.IGNORECASE), "Generic Stack Trace Header"),
    (re.compile(r"<b>Exception Details:</b>", re.IGNORECASE), "Generic Exception Details Header"),
]

MAX_CONCURRENT_REQUESTS = 5


class VerboseErrorLeakageCheck(BaseCheck):
    """Probes the target site with non-existent paths and malformed input to
    trigger error responses, then inspects response bodies for verbose
    stack traces, debug screens, or raw exception details.

    Exposing stack traces or framework debug pages in production leaks
    internal application structure, source code paths, database schema
    information, and dependency versions to unauthorized users.
    """

    check_type = "verbose_error_leakage"

    def run(self) -> CheckResult:
        session = build_session(max_retries=0, status_forcelist=[])
        base = self.target_url if self.target_url.endswith("/") else self.target_url + "/"

        leaking_findings = []
        errors = []

        # Target probe URLs
        probe_urls = [(urljoin(base, target["path"]), target["desc"]) for target in PROBE_TARGETS]
        # Include base URL probe if root page itself returns an error
        probe_urls.append((self.target_url, "root URL"))

        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
            future_to_probe = {
                executor.submit(safe_get, session, url): (url, desc) for url, desc in probe_urls
            }
            for future in as_completed(future_to_probe):
                url, desc = future_to_probe[future]
                response, error = future.result()

                if error is not None:
                    errors.append(f"{desc} ({url}) error={error}")
                    continue

                body = response.text or ""
                match_label = self._inspect_body_for_stack_trace(body)
                if match_label:
                    leaking_findings.append(
                        f"{desc} ({url}) status={response.status_code} matched '{match_label}'"
                    )

        if leaking_findings:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.HIGH,
                title=f"Verbose error leakage detected on {len(leaking_findings)} path(s)",
                description=(
                    "One or more error responses returned detailed stack traces, framework debug "
                    "screens, or unhandled exception details. Exposing stack traces in production "
                    "reveals internal application code structure, directory paths, line numbers, "
                    "and dependency information to potential attackers."
                ),
                evidence="; ".join(leaking_findings),
                recommendation=(
                    "Disable framework debug mode in production environments (e.g., set FLASK_DEBUG=0, "
                    "DEBUG=False, NODE_ENV=production). Configure generic 4xx and 5xx custom error "
                    "pages and ensure detailed stack traces are logged internally rather than exposed "
                    "in HTTP responses."
                ),
                passed=False,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.INFO,
            title="No verbose error leakage detected",
            description=(
                "Probed error responses did not contain stack traces, framework debug pages, or raw "
                "unhandled exception details."
            ),
            evidence="; ".join(errors) if errors else "",
            recommendation="",
            passed=True,
        )

    @staticmethod
    def _inspect_body_for_stack_trace(body: str) -> str | None:
        """Inspect response body text for known stack trace or debug page signatures.
        Returns the label of the first matching pattern, or None if clean.
        """
        if not body:
            return None
        for pattern, label in STACK_TRACE_PATTERNS:
            if pattern.search(body):
                return label
        return None
