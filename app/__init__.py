from flask import Flask
from config import Config
from app.extensions import db, migrate, login_manager


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"

    with app.app_context():
        from app import models  # noqa: F401 — ensures models are registered

    from app.routes.auth import auth_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")

    return app
