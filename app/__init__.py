import os
import secrets
from datetime import date, datetime, timedelta

from dotenv import load_dotenv
from flask import Flask, jsonify, request, session
from flask.json.provider import DefaultJSONProvider


class IsoJSON(DefaultJSONProvider):
    def default(self, o):
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        return super().default(o)


def create_app():
    load_dotenv()
    app = Flask(__name__)
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY is not set. Copy .env.example to .env and set it.")
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.environ.get("SESSION_MINUTES", "30"))),
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    app.json = IsoJSON(app)

    from .routes import auth, assets, vulns, risks, misc, pages
    for m in (auth, assets, vulns, risks, misc, pages):
        app.register_blueprint(m.bp)

    @app.before_request
    def protect():
        session.permanent = True  # sliding expiration: timer resets on each request
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.headers.get("X-CSRF-Token", "")
            if not secrets.compare_digest(sent, session["csrf"]):
                return jsonify(error="Invalid or missing CSRF token"), 403

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(404)
    def nf(e):
        return jsonify(error="Not found"), 404

    @app.errorhandler(405)
    def na(e):
        return jsonify(error="Method not allowed"), 405

    @app.errorhandler(413)
    def big(e):
        return jsonify(error="Request too large"), 413

    @app.errorhandler(Exception)
    def boom(e):
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return jsonify(error=e.description), e.code
        app.logger.exception("Unhandled error")  # details stay in the server log only
        return jsonify(error="Internal server error"), 500

    return app
