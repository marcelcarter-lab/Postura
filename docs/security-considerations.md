# Security Considerations

This document describes the security-relevant design decisions made
throughout Postura's development, along with known limitations. It's
intended for anyone evaluating, deploying, or extending this project.

## Authentication & session management

- Passwords are hashed using Werkzeug's `generate_password_hash`
  (PBKDF2 by default) — never stored or logged in plaintext.
- Sessions are managed by Flask-Login, signed using `SECRET_KEY`.
- **No rate limiting on login/register endpoints.** Brute-force
  password guessing is not currently mitigated. A production
  deployment handling untrusted signups should add rate limiting
  (e.g. Flask-Limiter) before relying on this.
- **No email verification, no password reset flow.** Both are
  reasonable additions outside this MVP's scope.

## CSRF protection

All state-changing HTML forms use Flask-WTF's CSRF protection
(hidden token field, validated server-side). The one JSON API endpoint
(`POST /scan/<website_id>`) is explicitly exempted from CSRF, since
that protection mechanism assumes a browser session with a rendered
form — a deliberate tradeoff appropriate for its current use (called
only by our own UI, not exposed as a general public API). If this
endpoint is ever opened up to third-party API consumers, it should
move to token/API-key-based authentication instead of relying on
session cookies at all.

## SECRET_KEY enforcement

`config.py` refuses to start with the insecure default `SECRET_KEY`
value (`"changeme"`) unless `FLASK_ENV=development`. In any other
environment, a missing or empty `SECRET_KEY` causes the process to
exit immediately at startup with a clear error, rather than silently
running with a forgeable session-signing key. See
[deployment.md](deployment.md#3-configure-environment-variables) for
how to generate a real one.

## SQL injection

All database queries go through SQLAlchemy's ORM
(`Model.query.filter_by()`, `db.session.add()`, etc.), which
parameterizes all values automatically. No raw/string-interpolated SQL
exists anywhere in the codebase — confirmed via a targeted audit (see
commit history, Sprint 5).

## Shell/command injection

The `sslscan` integration (`app/services/checks/sslscan_utils.py`)
shells out to an external binary. It uses `subprocess.run()` with a
list of arguments and `shell=False` (the safe pattern), never string
concatenation into a shell command — this means even a maliciously
crafted target hostname cannot inject shell commands, since each
argument is passed to the process directly, never interpreted by a
shell.

## XML parsing

`sslscan`'s XML output is parsed using `defusedxml` rather than the
standard library's `xml.etree.ElementTree`, closing the theoretical
risk of XML entity-expansion attacks, identified via static analysis
(bandit) during Sprint 5's audit.

## SSRF (Server-Side Request Forgery) protection

Because Postura's core function is making outbound HTTP/TLS
connections to user-supplied URLs, it is inherently exposed to SSRF
risk: without protection, a user could point a "website to scan" at
internal infrastructure (e.g. a cloud metadata endpoint like
`169.254.169.254`, or an internal admin panel) and use the scanner as
a proxy to probe resources it shouldn't be able to reach.

`app/services/ssrf_guard.py` blocks this by **resolving the target's
DNS and checking the resulting IP address** against private, loopback,
link-local, reserved, and multicast ranges — not by pattern-matching
the hostname string, since a malicious/attacker-controlled DNS name
could resolve to a private IP despite looking like a normal public
domain (a DNS rebinding-style risk that string matching alone would
miss). A single hostname (`test-target`) is explicitly allowlisted for
local development/testing purposes.

**Known limitation:** this check resolves DNS once, at scan-start
time. A sufficiently sophisticated attacker performing DNS rebinding
(where a domain resolves to a public IP at check-time but a private IP
at actual connection-time, exploiting the gap between the two) could
theoretically bypass this. Fully closing this gap would require
binding the resolved IP at connection time throughout the entire
scanning pipeline (every check, every request), which is a
significant architectural change beyond this MVP's scope.

## TLS/SSL check limitations

Python's built-in `ssl` module is bound by the host system's OpenSSL
security policy, which — by design — refuses to negotiate deprecated
TLS versions (1.0/1.1) or weak ciphers (RC4, 3DES) even when a
`SSLContext` is deliberately configured to attempt it. This was
discovered and confirmed via live testing against badssl.com during
Sprint 1: a target that *only* supports weak protocols/ciphers would
appear as a generic connection failure rather than producing an
actionable "insecure configuration" finding.

This was resolved by shelling out to the external `sslscan` tool,
which ships its own statically-linked, legacy-capable OpenSSL build
specifically for this kind of security testing, and can therefore
accurately report what a target server is willing to negotiate,
independent of the host's own TLS policy.

**Certificate validation:** `SSLCertCheck` first attempts a connection
with strict certificate validation (the client's default trust
policy). If that fails, it retries with validation disabled purely to
retrieve certificate details (expiration date, issuer) for reporting
purposes — this retry connection is never used to send or trust actual
data, only to inspect the certificate that caused the original
validation failure.

## Scan execution model

Scans run **synchronously**, within the same HTTP request that
triggers them. There is no background job queue (e.g. Celery, RQ) in
this MVP. Practical implications:

- A slow scan (particularly SSL/TLS checks, which can take 30-90+
  seconds due to `sslscan`'s per-protocol/cipher connection testing)
  holds the triggering request open for that entire duration.
- There is no built-in protection against a user triggering many
  concurrent scans and exhausting server resources — worth adding
  rate limiting or a job queue before this matters at scale.
- Recurring/scheduled scanning (a documented Phase 2 feature) will
  require revisiting this synchronous model, likely via APScheduler
  running scans as background jobs rather than within request/response
  cycles.

## Data exposure in reports

Generated PDF reports contain sensitive information by design (exposed
file paths, header disclosure details, certificate information) —
that's the entire point of the tool. Reports are generated on-demand
and streamed directly to the requesting user; they are not persisted
to disk or any storage service, so there's no additional data-at-rest
exposure surface from stored report files. However, this also means:

- There is currently no access control on report *contents* beyond
  the existing scan-ownership check (a user can only generate a report
  for scans belonging to their own tracked websites) — there's no
  separate "sharing" or "read-only link" feature (mentioned as a
  possible Phase 3 feature) that would need its own access-control
  review if implemented.

## Dependency and infrastructure notes

- Flask's built-in development server (`flask run`) is used directly
  in the Docker image, rather than a production WSGI server (e.g.
  gunicorn). See [deployment.md](deployment.md#known-limitations-for-production-use)
  for the recommended mitigation (reverse proxy in front).
- A static analysis pass (`bandit`) was run against the full
  application codebase during Sprint 5; all findings were either fixed
  (XML parsing, subprocess path resolution) or reviewed and confirmed
  as non-issues given actual usage (subprocess call pattern). See
  commit history for the full before/after comparison.

## Summary

This project takes security seriously as both its subject matter and
its own implementation — but it remains an MVP built within a fixed
internship timeline, not a fully hardened production system. The gaps
documented above (rate limiting, background job execution, DNS
rebinding edge case) are known and intentional scope boundaries, not
oversights, and are reasonable next steps for continued development
beyond this initial phase.
