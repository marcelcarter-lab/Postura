"""Known WordPress core version ranges with publicly documented
vulnerabilities.

IMPORTANT MAINTENANCE NOTE: this list is necessarily a point-in-time
snapshot and WILL become stale. WordPress core vulnerabilities are
disclosed continuously; this file was seeded with a small number of
well-documented historical examples during initial development and is
NOT a substitute for a real, actively-maintained vulnerability feed.
Before relying on this for real security decisions, this should be
replaced with (or supplemented by) a live-updated source such as the
WPScan Vulnerability Database (https://wpscan.com/wordpress) or the
WordPress core security advisories
(https://wordpress.org/support/wordpress-version/). This is flagged
explicitly here and in docs/security-considerations.md rather than
presented as a complete or current list.

Each entry: (min_version_inclusive, max_version_inclusive, CVE or
advisory reference, short description, severity).
"""

from dataclasses import dataclass


@dataclass
class WordPressVulnerability:
    min_version: str
    max_version: str
    reference: str
    description: str
    severity: str


# Seeded with a small number of well-documented, widely-cited
# historical examples. NOT exhaustive — see module docstring.
KNOWN_VULNERABLE_RANGES = [
    WordPressVulnerability(
        min_version="4.7.0",
        max_version="4.7.1",
        reference="CVE-2017-5487 (WordPress REST API)",
        description=(
            "An unauthenticated privilege escalation vulnerability in "
            "the WordPress REST API allowed remote attackers to modify "
            "the content of any post or page."
        ),
        severity="critical",
    ),
    WordPressVulnerability(
        min_version="5.7.0",
        max_version="5.7.1",
        reference="Multiple CVEs (WordPress 5.7.2 security release)",
        description=(
            "WordPress 5.7.2 was released as a security release "
            "addressing multiple vulnerabilities in prior 5.7.x "
            "releases."
        ),
        severity="high",
    ),
]


def _version_tuple(version_str: str):
    """Converts a version string like '5.7.1' into a comparable tuple
    of integers (5, 7, 1), so version range comparisons work
    correctly (string comparison alone would incorrectly sort '5.9'
    after '5.10', for example)."""
    return tuple(int(part) for part in version_str.split("."))


def find_vulnerabilities_for_version(detected_version: str) -> list:
    """Returns all known vulnerabilities whose range includes
    detected_version. Returns an empty list if the version string
    can't be parsed, or no known vulnerability matches."""
    try:
        detected = _version_tuple(detected_version)
    except (ValueError, AttributeError):
        return []

    matches = []
    for vuln in KNOWN_VULNERABLE_RANGES:
        try:
            min_v = _version_tuple(vuln.min_version)
            max_v = _version_tuple(vuln.max_version)
        except ValueError:
            continue
        if min_v <= detected <= max_v:
            matches.append(vuln)
    return matches
