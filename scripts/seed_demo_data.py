"""Seeds the database with realistic demo data: a demo user account,
a few tracked websites, and completed scans with genuine findings —
so a demo/presentation doesn't depend on live scanning or manual UI
setup. Idempotent: safe to run multiple times, will not create
duplicate demo data on repeat runs.

Usage (from the web container):
    python scripts/seed_demo_data.py
"""

from datetime import datetime, timezone, timedelta

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.project import Project
from app.models.website import Website
from app.models.scan import Scan
from app.models.finding import Finding
from werkzeug.security import generate_password_hash

DEMO_EMAIL = "demo@postura.local"
DEMO_PASSWORD = "DemoPassword123"


def get_or_create_demo_user():
    user = User.query.filter_by(email=DEMO_EMAIL).first()
    if user is None:
        user = User(
            email=DEMO_EMAIL,
            password_hash=generate_password_hash(DEMO_PASSWORD),
            role="staff",
        )
        db.session.add(user)
        db.session.commit()
        print(f"Created demo user: {DEMO_EMAIL} / {DEMO_PASSWORD}")
    else:
        print(f"Demo user already exists: {DEMO_EMAIL}")
    return user


def get_or_create_demo_project(user):
    project = Project.query.filter_by(owner_id=user.id, name="Demo Agency Clients").first()
    if project is None:
        project = Project(name="Demo Agency Clients", owner_id=user.id)
        db.session.add(project)
        db.session.commit()
    return project


def get_or_create_website(project, url, name):
    website = Website.query.filter_by(project_id=project.id, url=url).first()
    if website is None:
        website = Website(project_id=project.id, url=url, name=name)
        db.session.add(website)
        db.session.commit()
        print(f"Created website: {name} ({url})")
    else:
        print(f"Website already exists: {name} ({url})")
    return website


def create_demo_scan(website, findings_spec, days_ago):
    """Creates a completed scan with the given findings, backdated by
    `days_ago` so demo data shows a believable scan history timeline
    rather than everything timestamped "just now"."""
    scan_time = datetime.now(timezone.utc) - timedelta(days=days_ago)
    scan = Scan(
        website_id=website.id,
        status="completed",
        started_at=scan_time,
        completed_at=scan_time + timedelta(seconds=45),
    )
    db.session.add(scan)
    db.session.commit()

    findings = [
        Finding(
            scan_id=scan.id,
            check_type=spec["check_type"],
            severity=spec["severity"],
            title=spec["title"],
            description=spec["description"],
            evidence=spec["evidence"],
            recommendation=spec["recommendation"],
            passed=spec["passed"],
        )
        for spec in findings_spec
    ]
    db.session.add_all(findings)
    db.session.commit()
    return scan


# Findings sets representing three realistic scenarios: a well-secured
# site, a moderately-configured site, and a poorly-secured legacy site
# — giving the demo a range of scores/colors to show off the dashboard
# and reporting features meaningfully, rather than every demo site
# looking identical.

WELL_SECURED_FINDINGS = [
    {"check_type": "csp_header", "severity": "info", "title": "Content-Security-Policy present and reasonably configured", "description": "A CSP header was found with no obviously unsafe directives.", "evidence": "CSP: default-src 'self'", "recommendation": "", "passed": True},
    {"check_type": "hsts_header", "severity": "info", "title": "Strict-Transport-Security configured adequately", "description": "HSTS is present with a max-age meeting the recommended minimum.", "evidence": "HSTS: max-age=31536000; includeSubDomains; preload", "recommendation": "", "passed": True},
    {"check_type": "ssl_cert_validity", "severity": "info", "title": "SSL certificate is valid", "description": "The SSL certificate is valid for 84 more days.", "evidence": "issuer=Let's Encrypt", "recommendation": "", "passed": True},
    {"check_type": "exposure_detection", "severity": "info", "title": "No exposed sensitive files detected", "description": "None of the checked sensitive paths were found on the target.", "evidence": "", "recommendation": "", "passed": True},
]

MODERATE_FINDINGS = [
    {"check_type": "csp_header", "severity": "medium", "title": "Missing Content-Security-Policy header", "description": "The response did not include a Content-Security-Policy header.", "evidence": "Content-Security-Policy header not present.", "recommendation": "Add a Content-Security-Policy header restricting script, style, and object sources to trusted origins.", "passed": False},
    {"check_type": "x_frame_options", "severity": "medium", "title": "Missing X-Frame-Options header", "description": "The response did not include an X-Frame-Options header.", "evidence": "X-Frame-Options header not present.", "recommendation": "Add an X-Frame-Options header set to DENY or SAMEORIGIN.", "passed": False},
    {"check_type": "server_header_disclosure", "severity": "low", "title": "Server header discloses version information", "description": "The Server header includes specific version information.", "evidence": "Server: nginx/1.18.0", "recommendation": "Configure the web server to suppress version-specific headers.", "passed": False},
    {"check_type": "ssl_cert_validity", "severity": "info", "title": "SSL certificate is valid", "description": "The SSL certificate is valid for 40 more days.", "evidence": "issuer=DigiCert", "recommendation": "", "passed": True},
]

POORLY_SECURED_FINDINGS = [
    {"check_type": "exposure_detection", "severity": "critical", "title": "Exposed sensitive file(s) detected: 2 path(s)", "description": "One or more sensitive files/paths were found publicly accessible.", "evidence": ".git/HEAD (status=200); .git/config (status=200)", "recommendation": "Remove these files from the publicly served directory, or configure the web server to block access to them.", "passed": False},
    {"check_type": "tls_protocol_strength", "severity": "high", "title": "Server accepts insecure TLS protocol version(s): TLSv1.0, TLSv1.1", "description": "The server accepts deprecated, cryptographically weak protocol versions.", "evidence": "supported_protocols=TLSv1.0, TLSv1.1, TLSv1.2", "recommendation": "Disable TLS 1.0/1.1 on the server, and require TLS 1.2 or higher.", "passed": False},
    {"check_type": "csp_header", "severity": "medium", "title": "Missing Content-Security-Policy header", "description": "The response did not include a Content-Security-Policy header.", "evidence": "Content-Security-Policy header not present.", "recommendation": "Add a Content-Security-Policy header restricting script, style, and object sources to trusted origins.", "passed": False},
    {"check_type": "hsts_header", "severity": "medium", "title": "Missing Strict-Transport-Security header", "description": "The response did not include an HSTS header.", "evidence": "Strict-Transport-Security header not present.", "recommendation": "Add a Strict-Transport-Security header with a max-age of at least 1 year.", "passed": False},
    {"check_type": "ssl_cert_validity", "severity": "critical", "title": "SSL certificate has expired", "description": "The SSL certificate expired 12 day(s) ago.", "evidence": "issuer=Sectigo | days_remaining=-12", "recommendation": "Renew the SSL certificate immediately.", "passed": False},
]


def main():
    app = create_app()
    with app.app_context():
        user = get_or_create_demo_user()
        project = get_or_create_demo_project(user)

        secure_site = get_or_create_website(project, "https://secure-client-example.com", "Alpine Consulting")
        moderate_site = get_or_create_website(project, "https://moderate-client-example.com", "Riverside Bakery")
        legacy_site = get_or_create_website(project, "https://legacy-client-example.com", "Old Town Hardware")

        # Only create scans if these websites don't already have any —
        # keeps the script idempotent (re-running won't pile up
        # duplicate scan history on top of existing demo data).
        if not secure_site.scans:
            create_demo_scan(secure_site, WELL_SECURED_FINDINGS, days_ago=1)
            print(f"Created scan history for {secure_site.name}")

        if not moderate_site.scans:
            create_demo_scan(moderate_site, MODERATE_FINDINGS, days_ago=5)
            create_demo_scan(moderate_site, MODERATE_FINDINGS, days_ago=1)
            print(f"Created scan history for {moderate_site.name}")

        if not legacy_site.scans:
            create_demo_scan(legacy_site, POORLY_SECURED_FINDINGS, days_ago=1)
            print(f"Created scan history for {legacy_site.name}")

        print()
        print("Demo data ready. Log in with:")
        print(f"  Email:    {DEMO_EMAIL}")
        print(f"  Password: {DEMO_PASSWORD}")


if __name__ == "__main__":
    main()
