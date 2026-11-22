import psycopg2.errors
from flask import Blueprint, jsonify, request

from ..database.db import get_cursor
from ..security import admin_required, audit, login_required
from ..services.validators import validate_vuln_manual

bp = Blueprint("vulns", __name__, url_prefix="/api/vulnerabilities")
SORTABLE = {"cve_id", "cvss_score", "severity", "affected_products", "published_at", "is_kev", "source"}
COLS = "id, cve_id, description, cvss_score::float AS cvss_score, severity, affected_products, published_at, is_kev, source, analyst_notes, refs->>0 AS reference"


@bp.get("")
@login_required
def list_vulns():
    sort = request.args.get("sort", "published_at")
    sort = sort if sort in SORTABLE else "published_at"
    direction = "ASC" if request.args.get("dir") == "asc" else "DESC"
    sql, args = f"SELECT {COLS} FROM vulnerabilities WHERE TRUE", []
    q = request.args.get("q", "").strip()
    if q:
        sql += " AND (cve_id ILIKE %s OR description ILIKE %s OR affected_products ILIKE %s)"
        args += [f"%{q}%"] * 3
    if request.args.get("severity"):
        sql += " AND severity = %s"
        args.append(request.args["severity"].upper())
    if request.args.get("is_kev") in ("true", "false"):
        sql += " AND is_kev = %s"
        args.append(request.args["is_kev"] == "true")
    if request.args.get("source"):
        sql += " AND source = %s"
        args.append(request.args["source"])
    sql += f" ORDER BY {sort} {direction} NULLS LAST, id LIMIT 500"
    with get_cursor() as cur:
        cur.execute(sql, args)
        return jsonify(items=cur.fetchall())


@bp.get("/options")
@login_required
def options():
    with get_cursor() as cur:
        cur.execute("SELECT id AS value, cve_id || ' (' || severity || ')' AS label FROM vulnerabilities ORDER BY cvss_score DESC NULLS LAST, cve_id LIMIT 500")
        return jsonify(items=cur.fetchall())


@bp.get("/<int:vid>")
@login_required
def detail(vid):
    with get_cursor() as cur:
        cur.execute("""SELECT id, cve_id, description, cvss_score::float AS cvss_score, severity, affected_products, published_at,
                       last_modified_at, refs, source, is_kev, kev_data, analyst_notes, synced_at FROM vulnerabilities WHERE id=%s""", (vid,))
        row = cur.fetchone()
    return (jsonify(row) if row else (jsonify(error="Vulnerability not found"), 404))


@bp.post("")
@admin_required
def create_manual():
    try:
        d = validate_vuln_manual(request.get_json(silent=True) or {})
    except ValueError as e:
        return jsonify(error=str(e)), 400
    try:
        with get_cursor() as cur:
            cur.execute("""INSERT INTO vulnerabilities (cve_id,description,cvss_score,severity,affected_products,analyst_notes,source)
                           VALUES (%(cve_id)s,%(description)s,%(cvss_score)s,%(severity)s,%(affected_products)s,%(analyst_notes)s,'manual')
                           RETURNING id""", d)
            new_id = cur.fetchone()["id"]
            audit(cur, "CREATE", "vulnerabilities", d["cve_id"])
    except psycopg2.errors.UniqueViolation:
        return jsonify(error="This CVE ID already exists"), 409
    return jsonify(id=new_id), 201


@bp.put("/<int:vid>")
@admin_required
def update(vid):
    """API-sourced (nvd) records: only analyst_notes may change. Manual/sample records: all editable fields."""
    body = request.get_json(silent=True) or {}
    with get_cursor() as cur:
        cur.execute("SELECT source, cve_id FROM vulnerabilities WHERE id=%s", (vid,))
        row = cur.fetchone()
        if not row:
            return jsonify(error="Vulnerability not found"), 404
        if row["source"] == "nvd":
            notes = str(body.get("analyst_notes", "")).strip()
            if len(notes) > 2000:
                return jsonify(error="analyst_notes must be at most 2000 characters"), 400
            cur.execute("UPDATE vulnerabilities SET analyst_notes=%s, updated_at=now() WHERE id=%s", (notes, vid))
        else:
            try:
                d = validate_vuln_manual({**body, "cve_id": row["cve_id"]})  # CVE ID is immutable
            except ValueError as e:
                return jsonify(error=str(e)), 400
            cur.execute("""UPDATE vulnerabilities SET description=%(description)s,cvss_score=%(cvss_score)s,severity=%(severity)s,
                           affected_products=%(affected_products)s,analyst_notes=%(analyst_notes)s,updated_at=now() WHERE id=%(id)s""", {**d, "id": vid})
        audit(cur, "UPDATE", "vulnerabilities", row["cve_id"])
    return jsonify(ok=True)


@bp.delete("/<int:vid>")
@admin_required
def delete(vid):
    try:
        with get_cursor() as cur:
            cur.execute("SELECT source, cve_id FROM vulnerabilities WHERE id=%s", (vid,))
            row = cur.fetchone()
            if not row:
                return jsonify(error="Vulnerability not found"), 404
            if row["source"] == "nvd":
                return jsonify(error="API-sourced records cannot be deleted; they are managed by synchronization"), 403
            cur.execute("DELETE FROM vulnerabilities WHERE id=%s", (vid,))
            audit(cur, "DELETE", "vulnerabilities", row["cve_id"])
    except psycopg2.errors.ForeignKeyViolation:
        return jsonify(error="Cannot delete: risk assessments reference this vulnerability"), 409
    return jsonify(ok=True)
