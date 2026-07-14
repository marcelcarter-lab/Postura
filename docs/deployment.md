# Deployment Guide

This guide covers deploying Postura on any server running Docker and
Docker Compose. It assumes a Linux server (a small VPS or cloud VM is
sufficient) with Docker installed.

## 1. Prerequisites

- A server with Docker Engine and the Docker Compose plugin installed.
- A domain name pointed at the server (recommended — see HTTPS below).
- Outbound network access from the server (the scanning engine needs
  to reach whatever websites it scans).

## 2. Clone the repository

```bash
git clone <repo-url>
cd Postura
```

## 3. Configure environment variables

Copy the example file:

```bash
cp .env.example .env
```

Then edit `.env` and set the following for a real deployment:

- **`SECRET_KEY`** — **required**. Generate a real random value:
```bash
  python3 -c "import secrets; print(secrets.token_hex(32))"
```
  Paste the output as `SECRET_KEY` in `.env`. The app will refuse to
  start with the insecure default (`changeme`) unless `FLASK_ENV` is
  `development` — see [security-considerations.md](security-considerations.md#secret_key-enforcement).

- **`FLASK_ENV`** — set to `production`.

- **`DATABASE_URL`** — the default value works if you're using the
  bundled `db` Docker Compose service as-is. If you're pointing at an
  external/managed PostgreSQL instance instead, update this to that
  database's connection string, and consider removing the `db` service
  from `docker-compose.yml` entirely in that case.

## 4. Build and start

```bash
docker compose up --build -d
```

This builds the app image, starts PostgreSQL, waits for it to report
healthy, then starts the Flask app — which automatically runs any
pending database migrations before serving requests. No manual
migration step is needed, including on first deploy.

Check that everything started correctly:

```bash
docker compose ps
docker compose logs web --tail=50
```

## 5. Put a reverse proxy in front of it (HTTPS)

Flask's built-in development server (`flask run`), which this project
currently uses, is **not intended to directly face the public
internet** — it lacks the hardening, concurrency handling, and TLS
termination a production deployment needs. Before exposing Postura
publicly, put a reverse proxy in front of it that:

- Terminates HTTPS (e.g. via [Caddy](https://caddyserver.com/) with
  automatic Let's Encrypt certificates, or Nginx + certbot)
- Forwards requests to `localhost:5000` (or the `web` container,
  depending on your proxy's own deployment)

A minimal example using Caddy (add a `Caddyfile` alongside
`docker-compose.yml`, and add Caddy as an additional service):

your-domain.com {
reverse_proxy web:5000
}
This is not currently wired into `docker-compose.yml` as a default
service, since the appropriate reverse-proxy setup varies by hosting
environment — this section describes the general shape rather than a
copy-paste-ready service definition.

## 6. Verify

Visit your domain (or the server's IP on port 5000 if testing without
a reverse proxy yet). Register an account and confirm the full flow —
add a website, run a scan, download a PDF report — works end to end.

## 7. Ongoing operations

**Applying updates:**
```bash
git pull
docker compose up --build -d
```
Migrations run automatically on every `web` container start, so
schema changes in an update are applied without a separate manual
step.

**Backing up the database:**
```bash
docker compose exec db pg_dump -U postura_user postura_db > backup.sql
```

**Viewing logs:**
```bash
docker compose logs web -f
```

## Known limitations for production use

This project was built as an MVP within a fixed internship timeline.
Before relying on this in a real production setting beyond
internal/trusted use, be aware of the following (also covered in more
depth in [security-considerations.md](security-considerations.md)):

- Scans run synchronously within the request cycle — a slow scan (SSL/
  TLS checks in particular) will hold that request open for the
  duration. There is no background job queue.
- Flask's built-in dev server is used directly, not a production WSGI
  server (e.g. gunicorn) — addressed by putting a reverse proxy in
  front, but worth being aware the underlying app server itself is
  still Flask's development server.
- No rate limiting on authentication endpoints (login/register) —
  brute-force protection is not currently implemented.
