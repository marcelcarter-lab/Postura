def test_app_exists(app):
    assert app is not None


def test_app_is_testing(app):
    assert app.config["TESTING"] is True


def test_register_page_loads(client):
    response = client.get("/auth/register")
    assert response.status_code == 200


def test_login_page_loads(client):
    response = client.get("/auth/login")
    assert response.status_code == 200
