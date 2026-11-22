import psycopg2.errors
from flask import Blueprint, jsonify, request

from ..database.db import get_cursor
from ..security import admin_required, audit, login_required
from ..services.validators import validate_asset

bp = Blueprint("assets", __name__, url_prefix="/api/assets")
SORTABLE = {"asset_code", "name", "asset_type", "owner", "host", "environment", "criticality", "status"}
COLS = "id, asset_code, name, asset_type, owner, host, environment, criticality, status"


@bp.get("")
@login_required
def list_assets():
    q = request.args.get("q", "").strip()
    sort = request.args.get("sort", "asset_code")
    sort = sort if sort in SORTABLE else "asset_code"  # whitelist: identifiers cannot be parameterised
    direction = "DESC" if request.args.get("dir") == "desc" else "ASC"
    sql, args = f"SELECT {COLS} FROM assets WHERE TRUE", []
    if q:
        sql += " AND (asset_code ILIKE %s OR name ILIKE %s OR owner ILIKE %s OR host ILIKE %s)"
        args += [f"%{q}%"] * 4
    for f in ("environment", "criticality", "status"):
        if request.args.get(f):
            sql += f" AND {f} = %s"
            args.append(request.args[f])
    sql += f" ORDER BY {sort} {direction} LIMIT 500"
    with get_cursor() as cur:
        cur.execute(sql, args)
        return jsonify(items=cur.fetchall())


@bp.get("/options")
@login_required
def options():
    with get_cursor() as cur:
        cur.execute("SELECT id AS value, asset_code || ' - ' || name AS label FROM assets WHERE status <> 'Decommissioned' ORDER BY asset_code")
        return jsonify(items=cur.fetchall())


@bp.post("")
@admin_required
def create():
    try:
        d = validate_asset(request.get_json(silent=True) or {})
    except ValueError as e:
        return jsonify(error=str(e)), 400
    try:
        with get_cursor() as cur:
            cur.execute("""INSERT INTO assets (asset_code,name,asset_type,owner,host,environment,criticality,status)
                           VALUES (%(asset_code)s,%(name)s,%(asset_type)s,%(owner)s,%(host)s,%(environment)s,%(criticality)s,%(status)s)
                           RETURNING id""", d)
            new_id = cur.fetchone()["id"]
            audit(cur, "CREATE", "assets", d["asset_code"])
    except psycopg2.errors.UniqueViolation:
        return jsonify(error="An asset with this Asset ID already exists"), 409
    return jsonify(id=new_id), 201


@bp.put("/<int:aid>")
@admin_required
def update(aid):
    try:
        d = validate_asset(request.get_json(silent=True) or {})
    except ValueError as e:
        return jsonify(error=str(e)), 400
    try:
        with get_cursor() as cur:
            cur.execute("""UPDATE assets SET asset_code=%(asset_code)s,name=%(name)s,asset_type=%(asset_type)s,owner=%(owner)s,
                           host=%(host)s,environment=%(environment)s,criticality=%(criticality)s,status=%(status)s,updated_at=now()
                           WHERE id=%(id)s RETURNING id""", {**d, "id": aid})
            if not cur.fetchone():
                return jsonify(error="Asset not found"), 404
            audit(cur, "UPDATE", "assets", d["asset_code"])
    except psycopg2.errors.UniqueViolation:
        return jsonify(error="An asset with this Asset ID already exists"), 409
    return jsonify(ok=True)


@bp.delete("/<int:aid>")
@admin_required
def delete(aid):
    with get_cursor() as cur:
        cur.execute("DELETE FROM assets WHERE id=%s RETURNING asset_code", (aid,))
        row = cur.fetchone()
        if not row:
            return jsonify(error="Asset not found"), 404
        audit(cur, "DELETE", "assets", row["asset_code"])
    return jsonify(ok=True)
