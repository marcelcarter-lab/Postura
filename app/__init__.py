from flask import Flask
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Extensions will be initialized here as they're added
    # (e.g. db.init_app(app), login_manager.init_app(app))

    # Blueprints will be registered here as routes are created
    # (e.g. app.register_blueprint(main_bp))

    return app
