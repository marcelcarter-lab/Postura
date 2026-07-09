import time
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import (
    TooManyRedirects,
    RequestException,
)
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.5
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_USER_AGENT = "Postura-Scanner/1.0 (+https://postura.example.com/about)"
DEFAULT_MIN_REQUEST_INTERVAL = 0.5  # seconds between requests to the same session


def build_session(
    timeout: int = DEFAULT_TIMEOUT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    user_agent: str = DEFAULT_USER_AGENT,
    min_request_interval: float = DEFAULT_MIN_REQUEST_INTERVAL,
) -> requests.Session:
    """Builds a requests.Session configured with automatic retries
    (using exponential backoff) for transient failures, a default
    timeout applied via a thin wrapper (requests doesn't support
    session-level timeouts natively, see TimeoutSession below), a
    custom User-Agent identifying Postura's scanner traffic, a capped
    number of redirects to follow, and basic rate limiting between
    consecutive requests.
    """
    session = TimeoutSession(
        default_timeout=timeout,
        min_request_interval=min_request_interval,
    )

    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    session.headers.update({"User-Agent": user_agent})
    session.max_redirects = max_redirects

    return session


class TimeoutSession(requests.Session):
    """A requests.Session subclass that applies a default timeout to
    every request unless one is explicitly passed (requests has no
    built-in session-wide timeout), and enforces a minimum delay
    between consecutive requests as a simple, self-throttling rate
    limiter — no external dependency needed for this scale of use.
    """

    def __init__(
        self,
        default_timeout: int = DEFAULT_TIMEOUT,
        min_request_interval: float = DEFAULT_MIN_REQUEST_INTERVAL,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.default_timeout = default_timeout
        self.min_request_interval = min_request_interval
        self._last_request_time = 0.0

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.default_timeout)
        self._throttle()
        try:
            return super().request(method, url, **kwargs)
        finally:
            self._last_request_time = time.monotonic()

    def _throttle(self):
        elapsed = time.monotonic() - self._last_request_time
        wait_time = self.min_request_interval - elapsed
        if wait_time > 0:
            time.sleep(wait_time)


def safe_get(session: requests.Session, url: str, **kwargs):
    """Wraps session.get() so that any request-level failure (redirect
    loops, timeouts, connection errors, retries exhausted, etc.) is
    converted into a clean (response, error) tuple instead of an
    uncaught exception. Checks that call this should treat a None
    response as "could not complete check" and record the error string
    as evidence, rather than as a Python-level crash.

    Returns:
        (response, None) on success
        (None, error_code) on failure, where error_code is one of:
          - "too_many_redirects"
          - "request_failed" (covers timeouts, connection errors,
            retries exhausted, and any other requests-level failure)
    """
    try:
        response = session.get(url, **kwargs)
        return response, None
    except TooManyRedirects:
        return None, "too_many_redirects"
    except RequestException:
        return None, "request_failed"
