import os

from flask import Flask, app
from config import Config
from app.extensions import db, migrate, login_manager, csrf, scheduler, mail


def _start_scheduler_if_appropriate(app):
    """Starts the background scheduler exactly once, guarded by three
    independent checks:
    1. Not already running (idempotency, e.g. across repeated
       create_app() calls in tests).
    2. Not the Flask reloader's parent watcher process (dev-server-
       specific double-start prevention).
    3. SCHEDULER_ENABLED env flag AND a Postgres advisory lock — both
       must allow it, ensuring only one process across a potential
       multi-worker deployment actually runs scheduled jobs, even if
       the env flag is misconfigured (the advisory lock is an
       automatic fallback, not just a redundant check).

    Once started, registers run_scheduled_scans() to run on a
    repeating interval (SCHEDULER_INTERVAL_SECONDS, default 300s/5min
    — set lower, e.g. 60, for quick dev-mode verification that
    scheduled scans actually fire).
    """
    if scheduler.running:
        return

    if app.config.get("TESTING"):
        # Never start the real background scheduler during tests —
        # it would try to run against whatever test database is
        # configured (e.g. SQLite in-memory, which doesn't support
        # Postgres-specific functions like pg_try_advisory_lock), and
        # more fundamentally, tests should never have a real recurring
        # background job running during test execution regardless of
        # database backend.
        return

    is_reloader_parent = os.environ.get("WERKZEUG_RUN_MAIN") != "true"
    reloader_enabled = app.config.get("DEBUG", False) or os.environ.get("FLASK_DEBUG") == "1"

    if reloader_enabled and is_reloader_parent:
        return

    scheduler_enabled_flag = os.environ.get("SCHEDULER_ENABLED", "true").lower() == "true"
    if not scheduler_enabled_flag:
        app.logger.warning("Scheduler disabled via SCHEDULER_ENABLED env flag.")
        return

    from app.services.scheduling import try_acquire_scheduler_lock

    with app.app_context():
        lock_acquired = try_acquire_scheduler_lock(db.session)

    if not lock_acquired:
        app.logger.warning(
            "Scheduler NOT started: another process already holds the "
            "scheduler advisory lock (likely a multi-worker deployment "
            "where a different process is running the scheduler)."
        )
        return

    interval_seconds = int(os.environ.get("SCHEDULER_INTERVAL_SECONDS", "300"))

    def _run_scheduled_scans_with_context():
        # The scheduler calls this on its own background thread, with
        # no Flask app/request context — must push one explicitly so
        # run_scheduled_scans() (and everything it calls, like
        # db.session) works correctly.
        with app.app_context():
            from app.services.scheduling import run_scheduled_scans

            run_scheduled_scans()

    scheduler.add_job(
        _run_scheduled_scans_with_context,
        "interval",
        seconds=interval_seconds,
        id="run_scheduled_scans",
        replace_existing=True,
    )

    scheduler.start()
    app.logger.warning(
        "Background scheduler started (advisory lock acquired), "
        "checking for due scans every %s seconds.",
        interval_seconds,
    )


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"
    csrf.init_app(app)
    mail.init_app(app)

    with app.app_context():
        from app import models  # noqa: F401 — ensures models are registered

    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")

    from app.routes.main import main_bp
    app.register_blueprint(main_bp)

    from app.routes.scan import scan_bp
    app.register_blueprint(scan_bp)

    from app.routes.website import website_bp
    app.register_blueprint(website_bp)

    from app.routes.scan_view import scan_view_bp
    app.register_blueprint(scan_view_bp)

    from app.routes.admin import admin_bp
    app.register_blueprint(admin_bp)

    from app.services.risk_scoring import score_to_color
    app.jinja_env.globals["score_to_color"] = score_to_color

    from app.routes.settings import settings_bp
    app.register_blueprint(settings_bp)

    from app.routes.public_report import public_report_bp
    app.register_blueprint(public_report_bp)

    _start_scheduler_if_appropriate(app)

    return app

