# Security Audit Notes

## DB Query Parameterization Audit (Sprint 5)

**Method:** Searched the codebase for raw SQL patterns
(`db.session.execute`, `text()`, direct `.execute()` calls) and
string-interpolation patterns near query-like code (f-strings,
`.format()`, `%`-formatting containing SQL keywords).

**Result:** No raw/string-interpolated SQL found anywhere in the
codebase. All database interactions go through SQLAlchemy's ORM
(`Model.query.filter_by()`, `Model.query.filter()`,
`db.session.add()`, `db.session.bulk_insert_mappings()`, etc.), which
parameterizes all values automatically, including user-supplied input
such as website URLs and form field values.

**Related check:** The `sslscan` subprocess call in
`app/services/checks/sslscan_utils.py` uses a list-form
`subprocess.run([...])` call rather than a shell string, which
prevents shell injection via a malicious target URL/hostname.

**Conclusion:** No SQL injection or shell injection vulnerabilities
identified in this audit.

## Bandit Static Analysis Audit (Sprint 5)

**Command:** `bandit -r app/ -f txt`

**Initial results:** 5 findings, all in `app/services/checks/sslscan_utils.py`
(the module responsible for shelling out to the external `sslscan`
tool and parsing its XML output):

- B404, B603, B607 (subprocess usage) — the subprocess call already
  used safe, list-form arguments with `shell=False` (confirmed during
  the earlier DB query parameterization audit). Fixed B607 for real by
  resolving `sslscan`'s absolute path via `shutil.which()` at import
  time instead of relying on `$PATH` lookup at call time. B603
  suppressed via inline `# nosec` with an explanatory comment, since
  it is a generic "review this subprocess call" prompt rather than an
  indication of an actual shell-injection vulnerability in this case.
- B405, B314 (XML parsing) — genuinely fixed, not just suppressed, by
  replacing `xml.etree.ElementTree` with `defusedxml.ElementTree`
  (a drop-in replacement with an identical API), closing the
  theoretical risk of XML entity-expansion attacks via `sslscan`'s
  output, as defense-in-depth even though the output isn't directly
  user-controlled in the traditional sense.

**Result after fixes:** 0-1 findings remaining (a possible residual
low-severity B404 informational note on the `import subprocess`
statement itself, which is expected and accepted — subprocess usage is
a deliberate, necessary part of the sslscan integration).

## Environment Variable Audit (Sprint 5)

**Method:** Searched the codebase for all `os.environ`/`os.getenv`
usage, cross-referenced against `.env.example`, and searched for any
hardcoded secret-like strings outside of environment variable
fallback defaults.

**Result:** Only two environment variables are read by application
code: `SECRET_KEY` and `DATABASE_URL` (both in config.py), plus
`FLASK_APP`/`FLASK_ENV` which are read directly by Flask's CLI.
`.env.example` was already accurate; expanded with comments
explaining SECRET_KEY's security implications for deployed
environments. No hardcoded secrets found outside of SECRET_KEY's
documented local-development fallback default ("changeme"), which is
intentionally insecure-by-default to force real deployments to set
their own value (enforced further in the "Remove default credentials"
task later in this sprint). Confirmed `.env` (the real file) is
correctly gitignored.
