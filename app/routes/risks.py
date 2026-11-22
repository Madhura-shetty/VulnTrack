import psycopg2.errors
from flask import Blueprint, jsonify, request

from ..database.db import get_cursor
from ..security import admin_required, audit, login_required
from ..services.validators import validate_risk

bp = Blueprint("risks", __name__, url_prefix="/api/risks")
SORTABLE = {"id": "r.id", "asset": "a.name", "cve_id": "v.cve_id", "likelihood": "r.likelihood", "impact": "r.impact",
            "risk_score": "r.risk_score", "risk_level": "r.risk_score", "status": "r.status"}
BASE = """SELECT r.id, r.risk_code, r.asset_id, a.asset_code || ' - ' || a.name AS asset, r.vulnerability_id, v.cve_id,
          r.likelihood, r.impact, r.risk_score, r.risk_level, r.mitigation, r.status
          FROM risk_assessments r JOIN assets a ON a.id=r.asset_id JOIN vulnerabilities v ON v.id=r.vulnerability_id WHERE TRUE"""


@bp.get("")
@login_required
def list_risks():
    sort = SORTABLE.get(request.args.get("sort", "risk_score"), "r.risk_score")
    direction = "ASC" if request.args.get("dir") == "asc" else "DESC"
    sql, args = BASE, []
    q = request.args.get("q", "").strip()
    if q:
        sql += " AND (a.name ILIKE %s OR v.cve_id ILIKE %s OR r.mitigation ILIKE %s OR r.risk_code ILIKE %s)"
        args += [f"%{q}%"] * 4
    for f, col in (("risk_level", "r.risk_level"), ("status", "r.status")):
        if request.args.get(f):
            sql += f" AND {col} = %s"
            args.append(request.args[f])
    sql += f" ORDER BY {sort} {direction}, r.id LIMIT 500"
    with get_cursor() as cur:
        cur.execute(sql, args)
        return jsonify(items=cur.fetchall())


def _write(sql_fn):
    try:
        d = validate_risk(request.get_json(silent=True) or {})
    except ValueError as e:
        return jsonify(error=str(e)), 400
    try:
        with get_cursor() as cur:
            return sql_fn(cur, d)
    except psycopg2.errors.UniqueViolation:
        return jsonify(error="A risk assessment for this asset and vulnerability already exists"), 409
    except psycopg2.errors.ForeignKeyViolation:
        return jsonify(error="Selected asset or vulnerability does not exist"), 400


@bp.post("")
@admin_required
def create():
    def go(cur, d):
        cur.execute("""INSERT INTO risk_assessments (asset_id,vulnerability_id,likelihood,impact,risk_score,risk_level,mitigation,status)
                       VALUES (%(asset_id)s,%(vulnerability_id)s,%(likelihood)s,%(impact)s,%(risk_score)s,%(risk_level)s,%(mitigation)s,%(status)s)
                       RETURNING id, risk_code""", d)
        row = cur.fetchone()
        audit(cur, "CREATE", "risks", row["risk_code"])
        return jsonify(id=row["id"]), 201
    return _write(go)


@bp.put("/<int:rid>")
@admin_required
def update(rid):
    def go(cur, d):
        cur.execute("""UPDATE risk_assessments SET asset_id=%(asset_id)s,vulnerability_id=%(vulnerability_id)s,likelihood=%(likelihood)s,
                       impact=%(impact)s,risk_score=%(risk_score)s,risk_level=%(risk_level)s,mitigation=%(mitigation)s,
                       status=%(status)s,updated_at=now() WHERE id=%(id)s RETURNING risk_code""", {**d, "id": rid})
        row = cur.fetchone()
        if not row:
            return jsonify(error="Risk assessment not found"), 404
        audit(cur, "UPDATE", "risks", row["risk_code"])
        return jsonify(ok=True)
    return _write(go)


@bp.delete("/<int:rid>")
@admin_required
def delete(rid):
    with get_cursor() as cur:
        cur.execute("DELETE FROM risk_assessments WHERE id=%s RETURNING risk_code", (rid,))
        row = cur.fetchone()
        if not row:
            return jsonify(error="Risk assessment not found"), 404
        audit(cur, "DELETE", "risks", row["risk_code"])
    return jsonify(ok=True)
