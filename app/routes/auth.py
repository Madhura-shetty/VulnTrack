from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash

from ..database.db import get_cursor
from ..security import audit, clear_failures, login_required, rate_limited, record_failure

bp = Blueprint("auth", __name__, url_prefix="/api")
# Pre-computed hash so unknown usernames cost the same time as wrong passwords.
DUMMY = "scrypt:32768:8:1$dummy$" + "0" * 128


@bp.post("/login")
def login():
    d = request.get_json(silent=True) or {}
    username, password = str(d.get("username", "")).strip(), str(d.get("password", ""))
    if not username or not password or len(username) > 50 or len(password) > 200:
        return jsonify(error="Username and password are required"), 400
    key = f"{request.remote_addr}|{username.lower()}"
    if rate_limited(key):
        return jsonify(error="Too many failed attempts. Try again in a few minutes."), 429
    with get_cursor() as cur:
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
        u = cur.fetchone()
        ok = bool(u) and check_password_hash(u["password_hash"], password)
        if not ok:
            record_failure(key)
            return jsonify(error="Invalid username or password"), 401  # generic on purpose
        clear_failures(key)
        csrf = session.get("csrf")
        session.clear()  # new session on login (prevents session fixation)
        session.update(uid=u["id"], username=u["username"], role=u["role"], csrf=csrf)
        audit(cur, "LOGIN", "auth", u["username"])
    return jsonify(username=u["username"], role=u["role"])


@bp.post("/logout")
@login_required
def logout():
    with get_cursor() as cur:
        audit(cur, "LOGOUT", "auth", session["username"])
    session.clear()
    return jsonify(ok=True)


@bp.get("/me")
@login_required
def me():
    return jsonify(username=session["username"], role=session["role"])
