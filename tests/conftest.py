import pytest
from app import create_app
from app.extensions import db as _db
import os

class TestConfig:
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TESTING = True
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    app = create_app(config_class=TestConfig)

    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "html")


def load_html_fixture(filename):
    """Loads an HTML fixture file's contents as a string, for use in
    signature-detection tests. Fixtures live in tests/fixtures/html/,
    one file per technology scenario, so each can be inspected/opened
    independently of the test code that uses it."""
    with open(os.path.join(FIXTURES_DIR, filename)) as f:
        return f.read()
