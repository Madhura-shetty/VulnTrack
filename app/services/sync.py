"""Orchestrates API -> Python -> PostgreSQL synchronisation with upserts and sync logging."""
import json

from ..database.db import get_cursor
from . import cisa, nvd, validators
from .nvd import ApiError

UPSERT = """
INSERT INTO vulnerabilities (cve_id, description, cvss_score, severity, affected_products,
                             published_at, last_modified_at, refs, source, synced_at)
VALUES (%(cve_id)s, %(description)s, %(cvss_score)s, %(severity)s, %(affected_products)s,
        %(published_at)s, %(last_modified_at)s, %(refs)s::jsonb, 'nvd', now())
ON CONFLICT (cve_id) DO UPDATE SET
    description = EXCLUDED.description, cvss_score = EXCLUDED.cvss_score, severity = EXCLUDED.severity,
    affected_products = EXCLUDED.affected_products, published_at = EXCLUDED.published_at,
    last_modified_at = EXCLUDED.last_modified_at, refs = EXCLUDED.refs,
    source = 'nvd', synced_at = now(), updated_at = now()
WHERE vulnerabilities.source IN ('nvd', 'sample')   -- never overwrite manual records
RETURNING (xmax = 0) AS inserted
"""


def _log(cur, source, query, stats, status, message, username):
    cur.execute(
        """INSERT INTO api_sync_logs (source, query, fetched, inserted, updated, failed, status, message, username)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (source, query, stats["fetched"], stats["inserted"], stats["updated"], stats["failed"], status, message[:1000], username))


def upsert_records(cur, records):
    """Returns (inserted, updated, skipped_manual)."""
    ins = upd = skipped = 0
    for r in records:
        cur.execute(UPSERT, {**r, "refs": json.dumps(r["refs"])})
        row = cur.fetchone()
        if row is None:
            skipped += 1
        elif row["inserted"]:
            ins += 1
        else:
            upd += 1
    return ins, upd, skipped


def apply_kev(cur, catalog):
    """Flag every stored vulnerability that appears in the CISA catalog (others are un-flagged)."""
    cur.execute("UPDATE vulnerabilities SET is_kev = FALSE, kev_data = NULL WHERE is_kev AND NOT (cve_id = ANY(%s))", (list(catalog),))
    n = 0
    cur.execute("SELECT cve_id FROM vulnerabilities")
    for row in cur.fetchall():
        k = catalog.get(row["cve_id"])
        if k:
            cur.execute("UPDATE vulnerabilities SET is_kev = TRUE, kev_data = %s::jsonb WHERE cve_id = %s", (json.dumps(k), row["cve_id"]))
            n += 1
    return n


def run_sync(mode, query, limit, username):
    stats = {"fetched": 0, "inserted": 0, "updated": 0, "failed": 0, "kev_matched": 0, "messages": []}
    status, source = "success", "NVD" if mode != "kev" else "CISA"
    try:
        if mode != "kev":
            if mode in ("cve", "keyword") and not query.strip():
                raise ValueError("A CVE ID or keyword is required for this search mode")
            if mode == "cve" and not validators.CVE_RE.match(query.strip().upper()):
                raise ValueError("Invalid CVE ID format (expected CVE-YYYY-NNNN)")
            records, errors, total = nvd.search(mode, query, limit)
            stats["fetched"], stats["failed"] = len(records), len(errors)
            stats["messages"] += [f"Skipped invalid record: {e}" for e in errors]
            stats["total_available"] = total
            with get_cursor() as cur:
                stats["inserted"], stats["updated"], skipped = upsert_records(cur, records)
            if skipped:
                stats["failed"] += skipped
                stats["messages"].append(f"{skipped} record(s) not updated because a manual record with that CVE ID exists")
        try:
            catalog = cisa.fetch_catalog()
            with get_cursor() as cur:
                stats["kev_matched"] = apply_kev(cur, catalog)
            stats["kev_catalog_size"] = len(catalog)
        except ApiError as e:
            if mode == "kev":
                raise
            status = "partial"
            stats["messages"].append(f"CISA KEV step failed: {e}")
        if stats["failed"] and status == "success":
            status = "partial"
    except (ApiError, ValueError) as e:
        status = "failed"
        stats["messages"].append(str(e))
    with get_cursor() as cur:
        _log(cur, source, query or mode, stats, status, "; ".join(stats["messages"]), username)
    stats["status"] = status
    return stats
