from app.extensions import db
from app.models.user import User, ROLE_ADMIN, ROLE_STANDARD


def _make_user(email, role):
    user = User(email=email, password_hash="x", role=role)
    db.session.add(user)
    db.session.commit()
    return user


def _login_as(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def test_admin_route_redirects_unauthenticated_user(app, client):
    with app.app_context():
        response = client.get("/admin/users")
        # @login_required's default behavior for an unauthenticated
        # request is a redirect to the login page, not a 403 — this
        # should take precedence over the role check entirely, since
        # admin_required assumes an already-authenticated user.
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]


def test_admin_route_returns_403_for_standard_user(app, client):
    with app.app_context():
        user = _make_user("standard-user@postura.local", ROLE_STANDARD)
        _login_as(client, user)

        response = client.get("/admin/users")
        assert response.status_code == 403


def test_admin_route_returns_200_for_admin_user(app, client):
    with app.app_context():
        admin = _make_user("admin-user@postura.local", ROLE_ADMIN)
        _login_as(client, admin)

        response = client.get("/admin/users")
        assert response.status_code == 200


def test_admin_route_lists_all_users_for_admin(app, client):
    with app.app_context():
        admin = _make_user("admin-user2@postura.local", ROLE_ADMIN)
        _make_user("another-user@postura.local", ROLE_STANDARD)
        _login_as(client, admin)

        response = client.get("/admin/users")
        assert response.status_code == 200
        assert b"admin-user2@postura.local" in response.data
        assert b"another-user@postura.local" in response.data


def test_is_admin_property_reflects_role_correctly():
    admin = User(email="x@x.com", password_hash="x", role=ROLE_ADMIN)
    standard = User(email="y@y.com", password_hash="x", role=ROLE_STANDARD)

    assert admin.is_admin is True
    assert standard.is_admin is False
