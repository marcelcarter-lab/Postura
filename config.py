import os
import sys
import warnings

INSECURE_DEFAULT_SECRET_KEY = "changeme"


def _resolve_secret_key():
    raw_value = os.environ.get("SECRET_KEY", "")
    secret_key = raw_value.strip() or INSECURE_DEFAULT_SECRET_KEY
    flask_env = os.environ.get("FLASK_ENV", "development")

    is_insecure = secret_key == INSECURE_DEFAULT_SECRET_KEY

    if is_insecure:
        if flask_env == "development":
            warnings.warn(
                "SECRET_KEY is not set (or is empty) — using an insecure "
                "default value. This is only acceptable for local "
                "development. Set a real SECRET_KEY before deploying.",
                RuntimeWarning,
                stacklevel=2,
            )
        else:
            sys.exit(
                "FATAL: SECRET_KEY must be explicitly set to a secure random "
                "value when FLASK_ENV is not 'development'. Refusing to start "
                "with a missing, empty, or insecure default value. Generate "
                "one with:\n"
                '  python -c "import secrets; print(secrets.token_hex(32))"'
            )

    return secret_key


class Config:
    SECRET_KEY = _resolve_secret_key()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://postura_user:postura_pass@db:5432/postura_db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email (Sprint 10). Defaults point at a local Mailhog instance
    # (added in the "Test email delivery locally" task) for
    # development — no real SMTP credentials needed to develop/test
    # email-sending code locally. A real deployment must override
    # these via environment variables.
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "localhost")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "1025"))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "false").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME") or None
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD") or None
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@postura.local")
    # The public base URL this app is reachable at, used to build
    # absolute links in emails (which are composed outside of any
    # browser request context, so Flask's normal url_for() can't infer
    # the host automatically the way it does for in-app links).
    APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000")
