from datetime import datetime, timezone, timedelta
from sqlalchemy import text

from app.models.website import Website

FREQUENCY_INTERVALS = {
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}

SCHEDULER_LOCK_KEY = 918273645

def try_acquire_scheduler_lock(db_session) -> bool:
    """Attempts to acquire a Postgres session-level advisory lock,
    used to ensure only one process's scheduler actually runs even if
    multiple app instances/workers are started. pg_try_advisory_lock
    is non-blocking: it returns True immediately if the lock was
    acquired, or False immediately if another session already holds
    it — never waits.

    The lock is held for the lifetime of the underlying DB connection/
    session, which for a long-running app process is effectively "for
    as long as this process is alive" — appropriate here, since we
    want exactly one process's scheduler to hold this lock for its
    entire runtime, not release and reacquire it repeatedly.
    """
    result = db_session.execute(
        text("SELECT pg_try_advisory_lock(:key)"), {"key": SCHEDULER_LOCK_KEY}
    )
    return result.scalar()


def find_due_websites() -> list:
    """Returns all Website rows whose scheduled scan is currently due:
    scheduling is enabled (frequency is set) and next_run_at has
    passed (or is exactly now). Ordered by next_run_at ascending, so
    the most overdue websites are processed first if there are more
    due than can be scanned in one tick.
    """
    now = datetime.now(timezone.utc)
    return (
        Website.query.filter(
            Website.frequency.isnot(None),
            Website.next_run_at.isnot(None),
            Website.next_run_at <= now,
        )
        .order_by(Website.next_run_at.asc())
        .all()
    )


def run_scheduled_scans():
    """The function APScheduler calls on each tick. Finds every
    website currently due for an automatic scan and runs one for each,
    via the same execute_scan() entry point used by the browser UI and
    JSON API (Sprint 3) — so scheduled scans behave identically to a
    manually-triggered one (same checks, same persistence, same
    exception safety net inside the orchestrator).

    Must be called within an active Flask app context, since it (and
    everything it calls) uses db.session — this function does NOT push
    its own app context, since doing so here would tie this module to
    a specific Flask app instance. The caller (the actual APScheduler
    job registration, in the next task) is responsible for wrapping
    this call in `with app.app_context():`.

    Each website's scan is wrapped in its own try/except, so one
    website failing to scan (e.g. a genuinely broken/unreachable site)
    does not prevent the rest of the due websites from being
    processed in the same tick — the same "one failure shouldn't take
    down the whole batch" principle already applied inside the scan
    orchestrator itself (Sprint 1), now applied one level up.
    """
    from app.services.scan_runner import execute_scan
    from app.extensions import db

    due_websites = find_due_websites()

    if not due_websites:
        return

    for website in due_websites:
        try:
            execute_scan(website)
        except Exception:
            # Intentionally broad: a genuinely unexpected exception in
            # one website's scan (not the expected/handled failure
            # modes already covered inside execute_scan/the check
            # orchestrator) should not abort the rest of this batch.
            import logging

            logging.getLogger(__name__).exception(
                "Scheduled scan failed unexpectedly for website %s (%s)",
                website.id,
                website.url,
            )
            continue
        finally:
            _reschedule_next_run(website)
            db.session.commit()


def _reschedule_next_run(website):
    """Advances website.next_run_at based on its frequency, so the
    next scheduled scan is queued regardless of whether this one
    succeeded, failed, or was SSRF-blocked — scheduling should keep
    advancing rather than getting stuck retrying the same failing
    website every tick indefinitely.

    Reschedules relative to the CURRENT time (when this scan actually
    ran), not relative to the website's previous next_run_at. This is
    a deliberate choice: if the scheduler was down for an extended
    period and a website's scheduled scan is significantly overdue by
    the time it's finally processed, this avoids a "catch-up" pile-up
    where the next run is immediately due again — the cadence instead
    smoothly resumes from whenever the scan actually happened, at the
    cost of the schedule drifting later after any outage. This is
    considered the more practically useful behavior for this use case
    (agencies checking client sites periodically) over strict
    adherence to the original schedule.
    """
    interval = FREQUENCY_INTERVALS.get(website.frequency)
    if interval is None:
        # Frequency was cleared (scheduling disabled) between when
        # this website was picked up as due and now — respect that
        # and leave next_run_at as None rather than rescheduling a
        # website whose scheduling was turned off mid-flight.
        website.next_run_at = None
        return
    website.next_run_at = datetime.now(timezone.utc) + interval
