"""CSV report generation (shared by the web endpoint and scripts/generate_report.py)."""
import csv
import io

REPORTS = {
    "assets": ("SELECT asset_code, name, asset_type, owner, host, environment, criticality, status FROM assets ORDER BY asset_code",
               ["asset_code", "name", "asset_type", "owner", "host", "environment", "criticality", "status"]),
    "vulnerabilities": ("SELECT cve_id, severity, cvss_score, is_kev, source, published_at, affected_products, description FROM vulnerabilities ORDER BY cvss_score DESC NULLS LAST",
                        ["cve_id", "severity", "cvss_score", "is_kev", "source", "published_at", "affected_products", "description"]),
    "risks": ("""SELECT r.risk_code, a.asset_code, v.cve_id, r.likelihood, r.impact, r.risk_score, r.risk_level, r.status, r.mitigation
                 FROM risk_assessments r JOIN assets a ON a.id = r.asset_id JOIN vulnerabilities v ON v.id = r.vulnerability_id
                 ORDER BY r.risk_score DESC""",
              ["risk_code", "asset_code", "cve_id", "likelihood", "impact", "risk_score", "risk_level", "status", "mitigation"]),
}


def safe_cell(v):
    """Neutralise CSV/Excel formula injection (cells starting with = + - @)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def build_csv(cur, name):
    sql, cols = REPORTS[name]
    cur.execute(sql)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for row in cur.fetchall():
        w.writerow([safe_cell(row[c]) for c in cols])
    return buf.getvalue()
