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
