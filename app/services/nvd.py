"""NVD CVE API 2.0 client (https://services.nvd.nist.gov/rest/json/cves/2.0)."""
import os
import time
from datetime import datetime, timedelta, timezone

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 20


class ApiError(Exception):
    """Raised for any problem talking to an external API (message is safe to show)."""


def _headers():
    key = os.environ.get("NVD_API_KEY", "").strip()
    return {"apiKey": key} if key else {}


def fetch(params, retries=1):
    """GET the NVD API with timeout, HTTP-429 back-off and JSON validation."""
    for attempt in range(retries + 1):
        try:
            r = requests.get(NVD_URL, params=params, headers=_headers(), timeout=TIMEOUT)
        except requests.exceptions.Timeout:
            raise ApiError("NVD request timed out")
        except requests.exceptions.RequestException:
            raise ApiError("Could not reach the NVD API (network error)")
        if r.status_code == 429:
            if attempt < retries:
                time.sleep(6)  # public rate limit: 5 requests / 30 s without a key
                continue
            raise ApiError("NVD rate limit reached (HTTP 429). Wait ~30 seconds or configure NVD_API_KEY")
        if r.status_code != 200:
            raise ApiError(f"NVD returned HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            raise ApiError("NVD returned malformed JSON")
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise ApiError("NVD response is missing the 'vulnerabilities' list")
        return data
    raise ApiError("NVD request failed")


def _iso(ts):
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def parse_cve(item):
    """Extract our fields from one entry of response['vulnerabilities']. Raises ValueError if unusable."""
    cve = (item or {}).get("cve")
    if not isinstance(cve, dict) or not cve.get("id"):
        raise ValueError("entry has no cve.id")
    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, severity = None, "UNKNOWN"
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):  # newest first
        entries = metrics.get(key) or []
        if entries:
            m = entries[0]
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            severity = (data.get("baseSeverity") or m.get("baseSeverity") or "UNKNOWN").upper()
            break
    products = []
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 4 and match.get("vulnerable", True):
                    p = f"{parts[3]} {parts[4]}"
                    if p not in products:
                        products.append(p)
    refs = [r["url"] for r in cve.get("references", []) or [] if r.get("url")][:20]
    return {
        "cve_id": cve["id"].upper(),
        "description": desc or "No English description provided.",
        "cvss_score": score,
        "severity": severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE") else "UNKNOWN",
        "affected_products": ", ".join(products[:15]),
        "published_at": _iso(cve.get("published")),
        "last_modified_at": _iso(cve.get("lastModified")),
        "refs": refs,
    }


def search(mode, query="", limit=20):
    """mode: recent | keyword | cve. Returns (records, errors, total_results). One page, never the whole DB."""
    limit = max(1, min(int(limit), 100))
    params = {"resultsPerPage": limit, "startIndex": 0}
    if mode == "cve":
        params["cveId"] = query.strip().upper()
    elif mode == "keyword":
        params["keywordSearch"] = query.strip()
    else:
        end = datetime.now(timezone.utc)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        params["pubStartDate"] = (end - timedelta(days=7)).strftime(fmt)
        params["pubEndDate"] = end.strftime(fmt)
    data = fetch(params)
    records, errors = [], []
    for item in data["vulnerabilities"]:
        try:
            records.append(parse_cve(item))
        except (ValueError, AttributeError, TypeError) as e:
            errors.append(str(e))
    return records, errors, data.get("totalResults", len(records))
