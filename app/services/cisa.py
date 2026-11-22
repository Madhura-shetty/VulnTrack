"""CISA Known Exploited Vulnerabilities (KEV) catalog client."""
import requests

from .nvd import ApiError

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_catalog():
    try:
        r = requests.get(KEV_URL, timeout=30)
    except requests.exceptions.Timeout:
        raise ApiError("CISA KEV request timed out")
    except requests.exceptions.RequestException:
        raise ApiError("Could not reach the CISA KEV feed (network error)")
    if r.status_code != 200:
        raise ApiError(f"CISA KEV returned HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError:
        raise ApiError("CISA KEV returned malformed JSON")
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ApiError("CISA KEV response is missing the 'vulnerabilities' list")
    return parse_catalog(data)


def parse_catalog(data):
    """Return {CVE_ID: kev_details}. Skips malformed entries."""
    out = {}
    for v in data["vulnerabilities"]:
        cve = str((v or {}).get("cveID", "")).upper()
        if not cve:
            continue
        out[cve] = {
            "name": v.get("vulnerabilityName", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "date_added": v.get("dateAdded", ""),
            "required_action": v.get("requiredAction", ""),
            "due_date": v.get("dueDate", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
        }
    return out
