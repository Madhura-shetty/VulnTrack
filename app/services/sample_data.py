"""Small, clearly labelled SAMPLE dataset (source='sample'); NOT live API data.
Used only when the external APIs are unavailable. A real NVD sync replaces these rows."""
from .validators import severity_from_score

SAMPLE = [
    ("CVE-2021-44228", "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other endpoints (Log4Shell).", 10.0, "apache log4j"),
    ("CVE-2022-22965", "Spring Framework data binding allows remote code execution on JDK 9+ when deployed as a WAR on Tomcat (Spring4Shell).", 9.8, "vmware spring_framework"),
    ("CVE-2019-0708", "Remote Desktop Services remote code execution vulnerability (BlueKeep).", 9.8, "microsoft windows_7"),
    ("CVE-2017-0144", "SMBv1 server remote code execution vulnerability (EternalBlue).", 8.1, "microsoft windows_server_2008"),
    ("CVE-2014-0160", "OpenSSL TLS heartbeat extension out-of-bounds read discloses process memory (Heartbleed).", 7.5, "openssl openssl"),
    ("CVE-2023-4863", "Heap buffer overflow in libwebp allows a remote attacker to perform an out-of-bounds memory write via a crafted WebP image.", 8.8, "webmproject libwebp"),
]


def sample_rows():
    return [{"cve_id": c, "description": d, "cvss_score": s, "severity": severity_from_score(s), "affected_products": p} for c, d, s, p in SAMPLE]


def load_sample(cur):
    """Insert sample rows; never overwrite existing rows. Returns number inserted."""
    n = 0
    for r in sample_rows():
        cur.execute(
            """INSERT INTO vulnerabilities (cve_id, description, cvss_score, severity, affected_products, source, refs)
               VALUES (%(cve_id)s, %(description)s, %(cvss_score)s, %(severity)s, %(affected_products)s, 'sample',
                       jsonb_build_array('https://nvd.nist.gov/vuln/detail/' || %(cve_id)s))
               ON CONFLICT (cve_id) DO NOTHING""", r)
        n += cur.rowcount
    return n
