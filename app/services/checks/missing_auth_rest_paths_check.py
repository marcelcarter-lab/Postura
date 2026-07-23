from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.http_client import build_session, safe_get

# Common REST/API endpoint paths worth probing for missing
# authentication. Deliberately a small, curated list of frequently
# real, high-value targets (not an exhaustive path-guessing wordlist
# like ExposureCheck's) — this check targets a single well-known
# class of misconfiguration (an API endpoint left reachable without
# an auth check), not broad content discovery.
COMMON_API_PATHS = [
    "/api/users",
    "/api/user",
    "/api/admin",
    "/api/config",
    "/api/settings",
    "/api/v1/users",
    "/api/v1/admin",
    "/api/v1/config",
    "/api/accounts",
    "/api/internal",
]

# Status codes indicating the endpoint exists AND is enforcing some
# form of access control — not a finding.
AUTH_ENFORCED_STATUS_CODES = {401, 403}

# Status codes indicating the path simply doesn't exist here — not a
# finding either way, just absence of the endpoint.
NOT_FOUND_STATUS_CODES = {404, 410}

MAX_CONCURRENT_REQUESTS = 10


class MissingAuthOnRestPathsCheck(BaseCheck):
    """Probes a curated list of common REST/API endpoint paths and
    flags any that respond with a 2xx status instead of an
    auth-enforcing 401/403 — a strong signal the endpoint is
    reachable without authentication. Paths that 404 are treated as
    "doesn't exist here" and are not findings either way; only a
    reachable-and-apparently-unprotected endpoint counts as an issue.

    Like ExposureCheck, a single run can surface multiple distinct
    unprotected paths, rolled into one CheckResult rather than one
    per path — this is one conceptual check ("are API endpoints
    missing auth"), not many independent ones.

    This is a heuristic, not a guarantee: a 2xx response only means
    "no auth challenge was observed for this specific path", not that
    the endpoint is real, sensitive, or actually vulnerable. Framed
    explicitly as such in the finding's description, consistent with
    how WordPressVersionCheck documents its own known limitations
    rather than overstating confidence.
    """

    check_type = "missing_auth_rest_paths"

    def run(self) -> CheckResult:
        session = build_session()
        base = self.target_url if self.target_url.endswith("/") else self.target_url + "/"

        unprotected = []
        errors = []

        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
            future_to_path = {
                executor.submit(safe_get, session, urljoin(base, path.lstrip("/"))): path
                for path in COMMON_API_PATHS
            }
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                response, error = future.result()

                if error is not None:
                    errors.append(f"{path} (error={error})")
                    continue

                if response.status_code in NOT_FOUND_STATUS_CODES:
                    continue

                if response.status_code in AUTH_ENFORCED_STATUS_CODES:
                    continue

                if 200 <= response.status_code < 300:
                    unprotected.append(f"{path} (status={response.status_code})")

        if not unprotected:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No unprotected API endpoints detected",
                description=(
                    "None of the checked common API paths responded "
                    "successfully without an apparent authentication "
                    "challenge."
                ),
                evidence="; ".join(errors) if errors else "",
                recommendation="",
                passed=True,
            )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity.HIGH,
            title=f"Possible missing authentication on {len(unprotected)} API path(s)",
            description=(
                "One or more common API endpoint paths responded with "
                "a successful status code instead of an authentication "
                "challenge (401/403), suggesting these endpoints may "
                "be reachable without authentication. This is a "
                "heuristic based on a curated list of common paths, "
                "not a confirmation these are real, sensitive "
                "endpoints — manual verification is recommended "
                "before treating this as a confirmed vulnerability."
            ),
            evidence="; ".join(unprotected),
            recommendation=(
                "Verify whether each flagged endpoint should require "
                "authentication. If so, add an auth check before it "
                "returns data. Endpoints that are intentionally public "
                "should be reviewed to confirm they don't leak "
                "sensitive information."
            ),
            passed=False,
        )
