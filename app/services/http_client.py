import threading
import time
from urllib.parse import urlparse

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
DEFAULT_MIN_REQUEST_INTERVAL = 0.5  # seconds between requests to the same host


def build_session(
    timeout: int = DEFAULT_TIMEOUT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    user_agent: str = DEFAULT_USER_AGENT,
    min_request_interval: float = DEFAULT_MIN_REQUEST_INTERVAL,
    status_forcelist: list[int] | None = None,
) -> requests.Session:
    """Builds a requests.Session configured with automatic retries
    (using exponential backoff) for transient failures, a default
    timeout applied via a thin wrapper (requests doesn't support
    session-level timeouts natively, see TimeoutSession below), a
    custom User-Agent identifying Postura's scanner traffic, a capped
    number of redirects to follow, and per-host rate limiting that is
    safe to use across multiple concurrent threads (e.g. from
    path_checker.check_paths_concurrent()).
    """
    session = TimeoutSession(
        default_timeout=timeout,
        min_request_interval=min_request_interval,
    )

    if status_forcelist is None:
        status_forcelist = [500, 502, 503, 504]

    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False if not status_forcelist else True,
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
    between consecutive requests to the SAME HOST — tracked
    independently per hostname so different hosts don't block each
    other's pacing, and protected by a lock so it behaves correctly
    even when this session is shared across multiple threads (e.g.
    path_checker.check_paths_concurrent() running several requests to
    the same host in parallel).
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
        self._last_request_time_by_host = {}
        self._throttle_lock = threading.Lock()

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.default_timeout)
        self._throttle(url)
        try:
            return super().request(method, url, **kwargs)
        finally:
            self._record_request_time(url)

    def _throttle(self, url: str):
        host = urlparse(url).hostname or url
        with self._throttle_lock:
            last_time = self._last_request_time_by_host.get(host, 0.0)
            elapsed = time.monotonic() - last_time
            wait_time = self.min_request_interval - elapsed
        # Sleep OUTSIDE the lock — holding it during sleep would
        # serialize all requests to ALL hosts, not just this one,
        # defeating the point of allowing different hosts (and
        # multiple threads hitting the same host) to be paced
        # independently and concurrently up to their own limits.
        if wait_time > 0:
            time.sleep(wait_time)

    def _record_request_time(self, url: str):
        host = urlparse(url).hostname or url
        with self._throttle_lock:
            self._last_request_time_by_host[host] = time.monotonic()


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
