# Postura

**Postura** is a self-hosted security posture scanner for websites and web
applications. It automates the kind of pre-handoff security checks a web
agency would otherwise do manually: HTTP security header analysis, SSL/TLS
configuration checks, detection of accidentally exposed files (`.git`,
`.env`, backups), and tech/CMS fingerprinting. Results are scored and
compiled into a PDF report, so agencies can catch and fix issues before
handing a site off to a client.

Built with Flask, PostgreSQL, and server-rendered Jinja2 templates,
containerized with Docker Compose.
