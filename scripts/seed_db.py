"""Seed demo users, assets, labelled sample vulnerabilities and risk assessments."""
import os
import _boot  # noqa
from werkzeug.security import generate_password_hash
from app.database.db import get_cursor
from app.services.sample_data import load_sample
from app.services.validators import risk_level

assets = [
    ("AST-001", "Primary Web Server", "Server", "IT Operations", "10.0.1.10", "Production", "Critical", "Active"),
    ("AST-002", "Customer Database", "Database", "Data Team", "db01.corp.local", "Production", "Critical", "Active"),
    ("AST-003", "Edge Firewall", "Network Device", "Network Team", "10.0.0.1", "Production", "High", "Active"),
    ("AST-004", "Java Payments App", "Application", "Dev Team", "pay.corp.local", "Staging", "High", "Active"),
    ("AST-005", "Legacy File Server", "Server", "IT Operations", "10.0.2.25", "Production", "Medium", "Active"),
]
risks = [("AST-004", "CVE-2021-44228", 4, 5, "Upgrade Log4j to a patched release; block outbound LDAP.", "In Progress"),
         ("AST-004", "CVE-2022-22965", 3, 5, "Upgrade Spring Framework; verify JDK/Tomcat deployment.", "Open"),
         ("AST-005", "CVE-2017-0144", 4, 4, "Disable SMBv1; apply MS17-010 patches.", "Open"),
         ("AST-001", "CVE-2014-0160", 2, 4, "Confirm OpenSSL is patched; rotate certificates.", "Mitigated"),
         ("AST-002", "CVE-2023-4863", 2, 5, "Update libwebp in client tooling.", "Accepted")]

with get_cursor() as cur:
    for name, role, env in (("admin", "admin", "SEED_ADMIN_PASSWORD"), ("viewer", "viewer", "SEED_VIEWER_PASSWORD")):
        pw = os.environ.get(env)
        if not pw:
            raise SystemExit(f"{env} is not set in .env")
        cur.execute("""INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)
                       ON CONFLICT (username) DO UPDATE SET password_hash=EXCLUDED.password_hash, role=EXCLUDED.role""",
                    (name, generate_password_hash(pw), role))
    for a in assets:
        cur.execute("""INSERT INTO assets (asset_code,name,asset_type,owner,host,environment,criticality,status)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (asset_code) DO NOTHING""", a)
    n = load_sample(cur)
    for code, cve, l, i, mit, st in risks:
        cur.execute("""INSERT INTO risk_assessments (asset_id,vulnerability_id,likelihood,impact,risk_score,risk_level,mitigation,status)
                       SELECT a.id, v.id, %s,%s,%s,%s,%s,%s FROM assets a, vulnerabilities v WHERE a.asset_code=%s AND v.cve_id=%s
                       ON CONFLICT (asset_id, vulnerability_id) DO NOTHING""", (l, i, l * i, risk_level(l * i), mit, st, code, cve))
print(f"Seeded users, {len(assets)} assets, {n} SAMPLE vulnerabilities (labelled source=sample), risk assessments.")
