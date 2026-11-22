import time
from functools import wraps

from flask import jsonify, redirect, session, url_for

_failures = {}  # {key: [timestamps]}  in-memory login rate limiter (demo-grade; use Redis for multi-process)
MAX_FAILS, WINDOW = 5, 300


def rate_limited(key):
    now = time.time()
    _failures[key] = [t for t in _failures.get(key, []) if now - t < WINDOW]
    return len(_failures[key]) >= MAX_FAILS


def record_failure(key):
    _failures.setdefault(key, []).append(time.time())


def clear_failures(key):
    _failures.pop(key, None)


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            return jsonify(error="Authentication required"), 401
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if session.get("role") != "admin":
            return jsonify(error="Admin role required"), 403
        return f(*a, **k)
    return w


def page_login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            return redirect(url_for("pages.login_page"))
        return f(*a, **k)
    return w


def audit(cur, action, module, record_id=None, user=None):
    cur.execute(
        "INSERT INTO audit_logs (user_id, username, action, module, record_id) VALUES (%s,%s,%s,%s,%s)",
        (user[0] if user else session.get("uid"), user[1] if user else session.get("username", "system"),
         action, module, None if record_id is None else str(record_id)))
