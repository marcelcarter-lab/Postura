# Historical Comparison: Diff Matching Key Design (Sprint 7)

## The matching key

Two findings (from two different scans of the same website) are
considered "the same finding" for diffing purposes if they share an
identical `(check_type, title)` pair.

## Why this pair, not just check_type

`check_type` alone is stable and unique per check (e.g.
`"x_frame_options"`), but a single check can produce multiple
distinct titles depending on its outcome (e.g. "Missing
X-Frame-Options header" vs. "X-Frame-Options uses deprecated
ALLOW-FROM value" vs. "X-Frame-Options configured correctly").
Matching on `check_type` alone would treat all of these as "the same
finding, unchanged" even when the underlying issue meaningfully
changed in nature — which defeats the purpose of a diff. Including
`title` in the key means a change in outcome category correctly shows
up as one finding resolving and a different one appearing, which is
the more useful signal for a user reviewing what changed between
scans.

## Known limitation: ExposureCheck's dynamic count in title

`ExposureCheck`'s title includes a dynamic count of exposed paths
(e.g. "Exposed sensitive file(s) detected: 2 path(s)"). Because this
count is embedded in the title text itself, a change in the *number*
of exposed files between two scans (e.g. 2 paths -> 3 paths) will be
classified as the 2-path finding "resolving" and a new 3-path finding
"appearing," rather than as one finding whose severity/scope
increased. This is a known, accepted limitation of the
(check_type, title) matching key for this specific check — a more
precise fix would require either stripping dynamic content from
titles before matching, or matching on check_type alone for this
specific check as a special case. Neither is implemented in this MVP;
documented here as a known edge case rather than silently glossed
over.

## What counts as "new," "resolved," or "unchanged"

(To be finalized in the next task, "Build diff algorithm" — noted
here as the natural next design question this key's definition leads
into.)
- A finding present in the newer scan but not the older scan (by this
  key) = **new**.
- A finding present in the older scan but not the newer scan = **resolved**.
- A finding present in both = **unchanged** — even if `passed`,
  `severity`, `evidence`, etc. differ slightly between the two
  occurrences, since (per the reasoning above) a genuine change in
  outcome category is already captured by the title differing, which
  would make it a different key entirely, not an "unchanged" match
  with different details.

## Known limitation: same-key pass/fail transitions

If a finding's `passed` status changes between two scans (e.g.
failing → passing) WITHOUT its title also changing, the diff
algorithm currently classifies it as "unchanged" (since the
(check_type, title) key still matches) — even though the underlying
pass/fail result genuinely changed. Most of this project's checks
already encode their outcome into the title text itself (e.g.
X-Frame-Options's three distinct titles for missing/deprecated/
correct), which mostly avoids this in practice, but it is not
guaranteed for every check, and is not currently detected/surfaced
separately from a true "nothing changed" result. Noted here as a
known simplification, not silently glossed over.
