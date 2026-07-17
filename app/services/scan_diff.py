from dataclasses import dataclass


@dataclass
class ScanDiff:
    """The result of comparing two scans' findings. Each list contains
    Finding DB rows (not a custom wrapper type), classified by
    presence in the older vs. newer scan, matched by the
    (check_type, title) key documented in diff-design-notes.md.
    """

    new: list
    resolved: list
    unchanged: list


def _finding_key(finding):
    """The matching key used to determine whether two findings from
    different scans represent "the same" finding. See
    docs/diff-design-notes.md for the full reasoning behind this
    choice, including a known limitation for ExposureCheck's
    dynamically-worded titles.
    """
    return (finding.check_type, finding.title)


def diff_scans(older_scan, newer_scan) -> ScanDiff:
    """Compares older_scan's findings against newer_scan's findings
    and classifies each into new, resolved, or unchanged.

    Only FAILED findings (passed=False) are considered for "new" and
    "resolved" classification — a passing/INFO finding appearing or
    disappearing between scans isn't a meaningful security change to
    highlight the same way an actual issue appearing/resolving is.
    "Unchanged" includes any finding (failed or passed) present in
    both scans under the same key, so a user can still see confirmation
    that, e.g., a previously-passing check is still passing.
    """
    older_by_key = {_finding_key(f): f for f in older_scan.findings}
    newer_by_key = {_finding_key(f): f for f in newer_scan.findings}

    older_keys = set(older_by_key.keys())
    newer_keys = set(newer_by_key.keys())

    new_keys = newer_keys - older_keys
    resolved_keys = older_keys - newer_keys
    unchanged_keys = older_keys & newer_keys

    new = [newer_by_key[k] for k in new_keys if newer_by_key[k].passed is False]
    resolved = [older_by_key[k] for k in resolved_keys if older_by_key[k].passed is False]
    unchanged = [newer_by_key[k] for k in unchanged_keys]

    return ScanDiff(new=new, resolved=resolved, unchanged=unchanged)


class ScanDiffError(Exception):
    """Raised when two scans cannot be meaningfully compared (missing,
    belong to different websites, etc.)."""


def diff_scans_by_id(scan_id_a: int, scan_id_b: int) -> ScanDiff:
    """Loads two scans by ID and returns their diff, regardless of
    which ID was passed first — automatically determines chronological
    order based on started_at, so callers (e.g. a form where a user
    picks two scans from a dropdown in no particular order) don't need
    to know or care which one is "older."

    Raises ScanDiffError if either scan doesn't exist, or if the two
    scans belong to different websites (comparing scans of unrelated
    websites is not a meaningful operation).
    """
    from app.models.scan import Scan

    scan_a = Scan.query.get(scan_id_a)
    scan_b = Scan.query.get(scan_id_b)

    if scan_a is None or scan_b is None:
        raise ScanDiffError("One or both scans could not be found.")

    if scan_a.website_id != scan_b.website_id:
        raise ScanDiffError("Cannot compare scans belonging to different websites.")

    if scan_a.id == scan_b.id:
        raise ScanDiffError("Cannot compare a scan with itself.")

    older_scan, newer_scan = (
        (scan_a, scan_b) if scan_a.started_at <= scan_b.started_at else (scan_b, scan_a)
    )

    return diff_scans(older_scan, newer_scan)

def find_previous_scan(scan):
    """Returns the completed scan for the same website that ran
    immediately before `scan`, or None if there isn't one (e.g. this
    is the website's first scan). Used for the "vs previous scan"
    quick-compare shortcut on the scan detail page.
    """
    from app.models.scan import Scan

    return (
        Scan.query.filter(
            Scan.website_id == scan.website_id,
            Scan.status == "completed",
            Scan.started_at < scan.started_at,
        )
        .order_by(Scan.started_at.desc())
        .first()
    )
