"""End-to-end tests against a REAL PostgreSQL database. Skipped unless DB_PASSWORD is set and the DB is reachable.
Run after: init_db.py and seed_db.py.   Uses the seeded admin/viewer accounts."""
import os, re, pytest

psycopg2 = pytest.importorskip("psycopg2")
from dotenv import load_dotenv
load_dotenv()
try:
    from app.database.db import connect
    connect().close(); HAVE_DB = hasattr(psycopg2, "__version__")
except Exception:
    HAVE_DB = False
pytestmark = pytest.mark.skipif(not HAVE_DB, reason="PostgreSQL not available")


def login(app, user, pw):
    c = app.test_client()
    t = re.search(r'content="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
    r = c.post("/api/login", json={"username": user, "password": pw}, headers={"X-CSRF-Token": t})
    return c, t, r


@pytest.fixture()
def app():
    from app import create_app
    return create_app()


def test_login_failure_is_generic(app):
    _, _, r = login(app, "admin", "wrong-password"); assert r.status_code == 401 and r.get_json()["error"] == "Invalid username or password"
    _, _, r = login(app, "nobody", "x"); assert r.get_json()["error"] == "Invalid username or password"


def test_admin_crud_cycle_and_viewer_blocked(app):
    c, t, r = login(app, "admin", os.environ["SEED_ADMIN_PASSWORD"]); assert r.status_code == 200
    h = {"X-CSRF-Token": t}
    a = {"asset_code": "TST-1", "name": "Test", "asset_type": "Server", "owner": "QA", "host": "10.9.9.9", "environment": "Test", "criticality": "Low", "status": "Active"}
    c.delete("/api/assets/0", headers=h)
    new = c.post("/api/assets", json=a, headers=h); assert new.status_code in (201, 409)
    items = c.get("/api/assets?q=TST-1").get_json()["items"]; aid = items[0]["id"]
    assert c.put(f"/api/assets/{aid}", json={**a, "name": "Renamed"}, headers=h).status_code == 200
    assert c.get("/api/assets?q=' OR 1=1 --").get_json()["items"] == []  # injection is treated as data
    assert c.delete(f"/api/assets/{aid}", headers=h).status_code == 200
    assert any(x["module"] == "assets" for x in c.get("/api/audit-logs").get_json()["items"])
    v, vt, _ = login(app, "viewer", os.environ["SEED_VIEWER_PASSWORD"])
    assert v.post("/api/assets", json=a, headers={"X-CSRF-Token": vt}).status_code == 403
