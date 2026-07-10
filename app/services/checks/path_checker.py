from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin

from app.services.http_client import build_session, safe_get

DEFAULT_MAX_CONCURRENCY = 5


@dataclass
class PathCheckResult:
    """Result of requesting a single candidate path against a target."""

    path: str
    url: str
    status_code: int | None
    content_length: int | None
    error: str | None = None

    @property
    def exists(self) -> bool:
        """Whether the path appears to actually exist and be
        accessible. A 200 is the clearest signal; some servers return
        403 for a path that exists but is blocked (still worth
        flagging — it confirms the file is there), so that's treated
        as "exists" too. 404 and errors are not."""
        return self.status_code in (200, 403) if self.status_code else False


def _check_single_path(session, base_url: str, path: str) -> PathCheckResult:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    response, error = safe_get(session, url)

    if error:
        return PathCheckResult(path=path, url=url, status_code=None, content_length=None, error=error)

    return PathCheckResult(
        path=path,
        url=url,
        status_code=response.status_code,
        content_length=len(response.content) if response.content else 0,
    )


def check_paths(base_url: str, paths: list) -> list:
    """Requests each path in `paths` against `base_url` sequentially
    and returns a list of PathCheckResult, one per path.

    Kept for cases where strict sequential behavior is wanted (e.g.
    tests, or environments where concurrency isn't appropriate).
    check_paths_concurrent() is the version actually used by the
    exposure scanner going forward.
    """
    session = build_session()
    return [_check_single_path(session, base_url, path) for path in paths]


def check_paths_concurrent(
    base_url: str, paths: list, max_concurrency: int = DEFAULT_MAX_CONCURRENCY
) -> list:
    """Requests each path in `paths` against `base_url` concurrently,
    capped at `max_concurrency` simultaneous requests, and returns a
    list of PathCheckResult in the same order as `paths` was given
    (order is preserved even though completion order may differ,
    since callers/tests may reasonably expect deterministic ordering).

    Note: build_session() returns a requests.Session, which IS
    thread-safe for concurrent use per requests' own documentation
    (each request gets its own connection from the pool), so sharing
    one session across worker threads here is safe and avoids the
    overhead of building a new session per thread.
    """
    session = build_session()
    results = [None] * len(paths)

    with ThreadPoolExecutor(max_workers=max_concurrency) as executor:
        future_to_index = {
            executor.submit(_check_single_path, session, base_url, path): i
            for i, path in enumerate(paths)
        }
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            results[index] = future.result()

    return results
