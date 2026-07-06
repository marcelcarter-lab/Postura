import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "changeme")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://postura_user:postura_pass@db:5432/postura_db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False