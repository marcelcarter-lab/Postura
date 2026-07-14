# Postura

Postura is a self-hosted web application that automates security
posture audits for websites — the kind of pre-handoff checks a web
design/digital agency would otherwise run manually before delivering
a client's site. It checks HTTP security headers, SSL/TLS
configuration, common exposure risks (accidentally public `.git`
directories, `.env` files, backups), and basic CMS/technology
fingerprinting — then scores the results and generates a downloadable
PDF report.

## Features

- **Header checks** — Content-Security-Policy, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **SSL/TLS checks** — certificate validity/trust, protocol version
  strength, cipher suite strength (via `sslscan`, which can detect
  weak configurations that a standard TLS client cannot)
- **Exposure detection** — checks for publicly accessible sensitive
  files (`.git`, `.env`, backups) and directory listings
- **Fingerprinting** — Server/X-Powered-By header disclosure, meta
  generator tags, CMS-specific static file signatures
- **Risk scoring** — a weighted, capped 0–100 score computed from a
  scan's findings
- **PDF reporting** — a full report (executive summary, prioritized
  recommendations, detailed findings) generated via WeasyPrint

## Tech stack

- **Backend:** Python, Flask, SQLAlchemy, Flask-Login, Flask-WTF
- **Database:** PostgreSQL
- **Frontend:** Server-rendered Jinja2 templates, Bootstrap 5
- **PDF generation:** WeasyPrint
- **Deployment:** Docker Compose
- **Testing:** pytest, `responses` (HTTP mocking)

## Quick start

Requires Docker and Docker Compose.

1. Clone the repository:
```bash
   git clone <repo-url>
   cd Postura
```

2. Copy the example environment file and (optionally) adjust it:
```bash
   cp .env.example .env
```
   The default values work out of the box for local development. See
   [Deployment](docs/deployment.md) for what to change before deploying
   anywhere beyond your own machine.

3. Start everything with one command:
```bash
   docker compose up --build
```
   This builds the app image, starts PostgreSQL, waits for it to be
   healthy, and automatically runs database migrations before the
   Flask app starts — no manual setup steps required.

4. Visit **http://localhost:5000** and register an account.

### Optional: local vulnerable test target

A deliberately-misconfigured Flask app is included for testing scans
against a known target (exposed `.git` directory, missing headers,
etc.) without needing to scan a real external site:

```bash
docker compose up -d --wait test-target
```

Then add `http://test-target:5001` as a website to scan from within
the app (only reachable from inside the Docker network, i.e. by the
`web` container — not from your host browser directly).

## Running tests

```bash
docker compose run --rm web pytest -v -m "not live"
```

The `not live` marker excludes tests that make real network calls to
external services (e.g. badssl.com for SSL/TLS edge cases), which are
slower and require internet access. Run the full suite including those
with:

```bash
docker compose run --rm web pytest -v
```

## Project structure

app/
├── models/          # SQLAlchemy models (User, Project, Website, Scan, Finding)
├── routes/          # Flask blueprints (auth, website, scan, main, scan_view)
├── services/
│   ├── checks/      # Individual security checks (BaseCheck subclasses)
│   ├── reporting/   # PDF report generation pipeline
│   └── ...          # HTTP client, scan orchestration, risk scoring, etc.
├── templates/        # Jinja2 templates
test_target/          # Local vulnerable test fixture
tests/                 # pytest test suite
docs/                  # Architecture, deployment, and security docs

## Documentation

- [Architecture](docs/architecture.md) — system diagram and component overview
- [Deployment](docs/deployment.md) — step-by-step deployment guide
- [Security considerations](docs/security-considerations.md) — design
  decisions and known limitations
