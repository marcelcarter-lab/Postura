from functools import wraps

from flask import abort
from flask_login import current_user


def admin_required(view_func):
    """Decorator restricting a route to admin users only. Must be used
    ALONGSIDE @login_required (not as a replacement for it) — this
    decorator assumes current_user is already authenticated and only
    checks the role; an unauthenticated request should still be
    redirected to login by @login_required first, not handled here.

    Usage:
        @app.route("/admin/something")
        @login_required
        @admin_required
        def admin_only_view():
            ...

    Returns 403 Forbidden for an authenticated but non-admin user,
    distinct from the 401/redirect-to-login behavior @login_required
    provides for a genuinely unauthenticated request.
    """

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403, description="This page requires administrator access.")
        return view_func(*args, **kwargs)

    return wrapped
