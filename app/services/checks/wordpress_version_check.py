import re

from bs4 import BeautifulSoup

from app.services.checks.base import BaseCheck, CheckResult
from app.services.checks.schema import Severity
from app.services.checks.wordpress_vulnerabilities import find_vulnerabilities_for_version
from app.services.http_client import build_session, safe_get

GENERATOR_VERSION_PATTERN = re.compile(r"WordPress\s+([\d.]+)", re.IGNORECASE)
README_VERSION_PATTERN = re.compile(r"Version\s+([\d.]+)", re.IGNORECASE)


class WordPressVersionCheck(BaseCheck):
    """Detects the specific WordPress core version a target is
    running (via the meta generator tag or the default readme.html
    file), then cross-references it against a curated list of known
    vulnerable version ranges (see wordpress_vulnerabilities.py — NOTE:
    that list is a small, non-exhaustive seed, not a complete
    vulnerability feed, documented in security-considerations.md).
    """

    check_type = "wordpress_version"

    def run(self) -> CheckResult:
        session = build_session()

        version, source = self._detect_version_from_generator_tag(session)
        if version is None:
            version, source = self._detect_version_from_readme(session)

        if version is None:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title="No WordPress version detected",
                description=(
                    "Could not determine a specific WordPress version from "
                    "the meta generator tag or readme.html. This does not "
                    "confirm the site isn't running WordPress — the version "
                    "may simply be hidden/removed."
                ),
                evidence="",
                recommendation="",
                passed=True,
            )

        vulnerabilities = find_vulnerabilities_for_version(version)

        if not vulnerabilities:
            return CheckResult(
                check_type=self.check_type,
                severity=Severity.INFO,
                title=f"WordPress {version} detected — no known issues in local database",
                description=(
                    f"Detected WordPress version {version} via {source}. No "
                    "matching entries were found in this tool's curated "
                    "vulnerability list. This list is a small, "
                    "non-exhaustive seed, NOT a complete or up-to-date "
                    "vulnerability database — absence of a match here does "
                    "not mean this version has no known vulnerabilities."
                ),
                evidence=f"detected_version={version} | source={source}",
                recommendation=(
                    "Ensure WordPress core is kept up to date regardless of "
                    "this check's result, and consult a maintained "
                    "vulnerability database (e.g. WPScan) for a complete "
                    "assessment."
                ),
                passed=True,
            )

        vuln_descriptions = [f"{v.reference}: {v.description}" for v in vulnerabilities]
        highest_severity = max(
            (v.severity for v in vulnerabilities),
            key=lambda s: {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0),
        )

        return CheckResult(
            check_type=self.check_type,
            severity=Severity(highest_severity),
            title=f"WordPress {version} has known vulnerabilities ({len(vulnerabilities)})",
            description=(
                f"Detected WordPress version {version} via {source}, which "
                f"matches {len(vulnerabilities)} known vulnerability "
                "range(s) in this tool's curated (non-exhaustive) list."
            ),
            evidence=(
                f"detected_version={version} | source={source} | "
                + "; ".join(vuln_descriptions)
            ),
            recommendation="Update WordPress core to the latest version immediately.",
            passed=False,
        )

    def _detect_version_from_generator_tag(self, session):
        response, error = safe_get(session, self.target_url)
        if error:
            return None, None

        soup = BeautifulSoup(response.text or "", "html.parser")
        tag = soup.find("meta", attrs={"name": "generator"})
        if not tag or not tag.get("content"):
            return None, None

        match = GENERATOR_VERSION_PATTERN.search(tag["content"])
        if match:
            return match.group(1), "meta generator tag"
        return None, None

    def _detect_version_from_readme(self, session):
        readme_url = self.target_url.rstrip("/") + "/readme.html"
        response, error = safe_get(session, readme_url)
        if error or response.status_code != 200:
            return None, None

        match = README_VERSION_PATTERN.search(response.text or "")
        if match:
            return match.group(1), "readme.html"
        return None, None
