from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
DOTLESS_HOSTNAME_ALLOWLIST = {"localhost", "test-target"}


def validate_website_url(url: str) -> str | None:
    """Validates that `url` is a well-formed http(s) URL with a real
    hostname. Returns None if valid, or an error message string if
    invalid — this is purely syntactic validation (is this a
    well-formed URL), not a reachability check (does this site
    actually respond), which is the scan's job, not form validation's.
    """
    url = url.strip()

    if not url:
        return "URL is required."

    try:
        parsed = urlparse(url)
    except ValueError:
        return "URL is not well-formed."

    if parsed.scheme not in ALLOWED_SCHEMES:
        return "URL must start with http:// or https://."

    if not parsed.hostname:
        return "URL must include a valid hostname (e.g. https://example.com)."

    if "." not in parsed.hostname and parsed.hostname not in DOTLESS_HOSTNAME_ALLOWLIST:
        return "URL must include a valid domain (e.g. https://example.com)."

    if len(url) > 2048:
        return "URL is too long (maximum 2048 characters)."

    return None
