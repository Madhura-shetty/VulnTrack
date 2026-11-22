from flask import Blueprint, redirect, render_template, session, url_for

from ..security import page_login_required

bp = Blueprint("pages", __name__)


def _page(template, title):
    return render_template(template, title=title, csrf=session["csrf"], username=session.get("username"), role=session.get("role"))


@bp.get("/login")
def login_page():
    if "uid" in session:
        return redirect(url_for("pages.dashboard"))
    return render_template("login.html", csrf=session["csrf"])


@bp.get("/")
@page_login_required
def dashboard():
    return _page("dashboard.html", "Dashboard")


@bp.get("/assets")
@page_login_required
def assets():
    return _page("assets.html", "Assets")


@bp.get("/vulnerabilities")
@page_login_required
def vulnerabilities():
    return _page("vulnerabilities.html", "Vulnerabilities")


@bp.get("/risks")
@page_login_required
def risks():
    return _page("risks.html", "Risk Assessment")


@bp.get("/api-integration")
@page_login_required
def api_integration():
    return _page("api_integration.html", "API Integration")


@bp.get("/audit")
@page_login_required
def audit_page():
    return _page("audit.html", "Audit Logs")
