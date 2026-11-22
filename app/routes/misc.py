from flask import Blueprint, Response, jsonify, request, session

from ..database.db import get_cursor
from ..security import admin_required, audit, login_required
from ..services import cisa, nvd, reports, sample_data, sync
from ..services.nvd import ApiError

bp = Blueprint("misc", __name__, url_prefix="/api")


@bp.get("/dashboard")
@login_required
def dashboard():
    with get_cursor() as cur:
        cur.execute("""SELECT (SELECT count(*) FROM assets) AS assets,
            (SELECT count(*) FROM vulnerabilities) AS vulnerabilities,
            (SELECT count(*) FROM vulnerabilities WHERE severity='CRITICAL') AS critical,
            (SELECT count(*) FROM vulnerabilities WHERE severity='HIGH') AS high,
            (SELECT count(*) FROM vulnerabilities WHERE is_kev) AS kev,
            (SELECT count(*) FROM risk_assessments) AS risks,
            (SELECT max(created_at) FROM api_sync_logs WHERE status IN ('success','partial')) AS last_sync""")
        stats = cur.fetchone()
        cur.execute("SELECT username, action, module, record_id, created_at FROM audit_logs ORDER BY id DESC LIMIT 8")
        stats["recent_audit"] = cur.fetchall()
    return jsonify(stats)


@bp.get("/audit-logs")
@login_required
def audit_logs():
    args, sql = [], "SELECT id, username, action, module, record_id, created_at FROM audit_logs WHERE TRUE"
    for f in ("module", "action"):
        if request.args.get(f):
            sql += f" AND {f} = %s"
            args.append(request.args[f])
    q = request.args.get("q", "").strip()
    if q:
        sql += " AND (username ILIKE %s OR record_id ILIKE %s)"
        args += [f"%{q}%"] * 2
    with get_cursor() as cur:
        cur.execute(sql + " ORDER BY id DESC LIMIT 300", args)
        return jsonify(items=cur.fetchall())


@bp.post("/sync")
@admin_required
def run_sync():
    d = request.get_json(silent=True) or {}
    mode = d.get("mode", "recent")
    if mode not in ("recent", "keyword", "cve", "kev"):
        return jsonify(error="mode must be recent, keyword, cve or kev"), 400
    try:
        limit = int(d.get("limit", 20))
    except (TypeError, ValueError):
        return jsonify(error="limit must be a number"), 400
    query = str(d.get("query", ""))[:100]
    stats = sync.run_sync(mode, query, limit, session["username"])
    with get_cursor() as cur:
        audit(cur, "API_SYNC", "api", f"{mode}:{stats['status']}")
    return jsonify(stats), (200 if stats["status"] != "failed" else 502)


@bp.post("/sync/check")
@admin_required
def check():
    result = {}
    for name, fn in (("nvd", lambda: nvd.fetch({"resultsPerPage": 1})), ("cisa", cisa.fetch_catalog)):
        try:
            fn()
            result[name] = {"ok": True, "message": "Connected"}
        except ApiError as e:
            result[name] = {"ok": False, "message": str(e)}
    return jsonify(result)


@bp.get("/sync/logs")
@login_required
def sync_logs():
    with get_cursor() as cur:
        cur.execute("SELECT id, source, query, fetched, inserted, updated, failed, status, message, username, created_at FROM api_sync_logs ORDER BY id DESC LIMIT 20")
        logs = cur.fetchall()
        cur.execute("SELECT max(created_at) AS t FROM api_sync_logs WHERE status IN ('success','partial')")
        last = cur.fetchone()["t"]
    return jsonify(items=logs, last_success=last)


@bp.post("/sync/sample")
@admin_required
def load_sample():
    with get_cursor() as cur:
        n = sample_data.load_sample(cur)
        audit(cur, "LOAD_SAMPLE", "api", n)
    return jsonify(inserted=n)


@bp.get("/reports/<name>.csv")
@login_required
def report(name):
    if name not in reports.REPORTS:
        return jsonify(error="Unknown report"), 404
    with get_cursor() as cur:
        body = reports.build_csv(cur, name)
        audit(cur, "EXPORT", "reports", name)
    return Response(body, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={name}_report.csv"})
