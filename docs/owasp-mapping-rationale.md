# OWASP Top 10 (2021) Mapping Rationale

This document explains the reasoning behind each check's OWASP Top 10
category assignment in `app/services/compliance/owasp_mapping.py`.

## Why OWASP Top 10 (2021), not ASVS or another framework

The OWASP Top 10 is the most widely recognized security reference
framework, making it the most useful choice for a compliance summary
aimed at a non-specialist audience (an agency's client). ASVS
(Application Security Verification Standard) is more granular and
arguably a better technical fit for some of Postura's checks, but its
audience and use case (a detailed verification checklist for security
engineers) is a worse match for this project's report-facing
compliance summary. This is a reasonable, defensible choice, not the
only correct one.

## A fundamental limitation worth stating plainly

The OWASP Top 10 describes **web application vulnerability classes**
(broken access control, injection, insecure design, etc.) — it was
written to categorize *application-level code and logic flaws*.
Postura is a **configuration and exposure posture scanner** — it
inspects HTTP responses, TLS handshakes, and publicly accessible
files/paths. It does not test application logic, authentication flows,
input handling, or business logic at all. This means several of
Postura's checks are mapped to the *closest reasonable* OWASP category
rather than a category the check precisely, unambiguously belongs to.
This mapping should be understood as "which OWASP category does this
configuration issue relate most closely to," not "Postura tests for
this OWASP category comprehensively."

## Category-by-category reasoning

### A05:2021 - Security Misconfiguration

The most natural fit for the largest group of Postura's checks: all
six HTTP security header checks (CSP, HSTS, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy), plus
exposure detection and directory listing detection. All of these are,
definitionally, server/application misconfigurations — a missing
header or an accidentally-public `.git` directory is exactly what
"Security Misconfiguration" describes. This is the strongest,
least-debatable set of mappings in the table.

### A02:2021 - Cryptographic Failures

SSL certificate validity, TLS protocol strength, and cipher suite
strength all map here — these directly concern the strength/validity
of cryptographic configuration (an expired certificate, a weak TLS
version, a deprecated cipher). Also a strong, direct fit.

### A06:2021 - Vulnerable and Outdated Components

Assigned to every fingerprinting/version-disclosure check: Server
header disclosure, X-Powered-By disclosure, meta generator tag
disclosure, CMS fingerprinting, JS framework fingerprinting, and
WordPress version detection. This is the **loosest** mapping in the
table, worth being explicit about: these checks don't directly test
*whether* a component is vulnerable or outdated — most of them
(Server header, X-Powered-By, meta generator, generic CMS/JS
fingerprinting) only detect *what technology is present*, not whether
that specific version has a known vulnerability. The one exception is
WordPress version detection, which genuinely does cross-reference
against a (small, non-exhaustive — see
security-considerations.md#wordpress-vulnerability-database-sprint-8)
known-vulnerability list, making it the only check in this category
with a truly direct A06 fit. The rest are mapped here because
disclosing a specific version number is the precondition an attacker
would need to *check* for known vulnerabilities in that version — a
reasonable, if indirect, connection.

## Known gap: A01:2021 - Broken Access Control

No current check maps to this category. Broken Access Control (in the
OWASP Top 10's sense) concerns application-level authorization flaws —
e.g. a user accessing another user's data by manipulating a URL
parameter, missing permission checks on an action, etc. Postura does
not test the *scanned website's* access control at all (only its own
application's, which is a separate, internal concern documented in
security-considerations.md). This is a genuine coverage gap relative
to the full OWASP Top 10, not an oversight in the mapping table —
there is currently no check that could reasonably map here, since
nothing in Postura's check suite tests this vulnerability class.
Closing this gap would require a fundamentally different kind of
check (e.g. testing whether admin-only paths are reachable
unauthenticated) — out of scope for the current MVP+Phase 2/3 feature
set.

## Maintenance note

Every new check added to `ENABLED_CHECKS` (`app/services/
scan_orchestrator.py`) should have a corresponding entry added to
`CHECK_TYPE_TO_OWASP_CATEGORY` in the same commit — nothing currently
enforces this automatically (see `get_owasp_category()`'s graceful
"Uncategorized" fallback, which prevents a crash but silently excludes
an unmapped check from compliance percentage calculations rather than
raising an error). A future improvement could add a test asserting
every `ENABLED_CHECKS` entry has a non-"Uncategorized" mapping,
turning this from a manual convention into an enforced one.
