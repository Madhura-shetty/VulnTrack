"""Flask-level tests that do not need a database: auth gate, CSRF, headers, templates."""
import re, pytest
from app import create_app


@pytest.fixture()
def client():
    app = create_app(); app.testing = False
    return app.test_client()


def token(client):
    html = client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def test_login_page_is_separate_and_has_headers(client):
    r = client.get("/login"); assert r.status_code == 200 and b"Sign in" in r.data and b'id="sidebar"' not in r.data
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"] and r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert "HttpOnly" in r.headers["Set-Cookie"] and "SameSite=Lax" in r.headers["Set-Cookie"]


@pytest.mark.parametrize("path", ["/", "/assets", "/vulnerabilities", "/risks", "/api-integration", "/audit"])
def test_pages_redirect_when_anonymous(client, path):
    r = client.get(path); assert r.status_code == 302 and "/login" in r.headers["Location"]


@pytest.mark.parametrize("path", ["/api/assets", "/api/vulnerabilities", "/api/risks", "/api/dashboard", "/api/audit-logs", "/api/me", "/api/reports/assets.csv"])
def test_api_requires_auth(client, path):
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("method,path", [("post", "/api/login"), ("post", "/api/assets"), ("put", "/api/assets/1"), ("delete", "/api/assets/1"), ("post", "/api/sync")])
def test_csrf_required_on_state_changes(client, method, path):
    assert getattr(client, method)(path, json={}).status_code == 403
    assert getattr(client, method)(path, json={}, headers={"X-CSRF-Token": "wrong"}).status_code == 403


def test_with_csrf_but_unauthenticated_is_401(client):
    h = {"X-CSRF-Token": token(client)}
    assert client.post("/api/assets", json={}, headers=h).status_code == 401
    assert client.delete("/api/assets/1", headers=h).status_code == 401


def test_login_validation_before_db(client):
    r = client.post("/api/login", json={"username": "", "password": ""}, headers={"X-CSRF-Token": token(client)})
    assert r.status_code == 400


def test_role_enforcement_viewer_cannot_write(client):
    with client.session_transaction() as s:
        s.update(uid=2, username="viewer", role="viewer", csrf="t")
    h = {"X-CSRF-Token": "t"}
    for method, path in (("post", "/api/assets"), ("put", "/api/risks/1"), ("delete", "/api/vulnerabilities/1"), ("post", "/api/sync"), ("post", "/api/sync/sample")):
        assert getattr(client, method)(path, json={}, headers=h).status_code == 403, path


def test_unknown_route_json_404(client):
    assert client.get("/api/nope").status_code == 404
