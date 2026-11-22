"""Server-side input validation and the explainable risk-scoring rule."""
import re

ASSET_TYPES = ["Server", "Workstation", "Network Device", "Database", "Application", "Cloud Service", "Other"]
ENVIRONMENTS = ["Production", "Staging", "Development", "Test"]
CRITICALITY = ["Low", "Medium", "High", "Critical"]
ASSET_STATUS = ["Active", "Inactive", "Decommissioned"]
RISK_STATUS = ["Open", "In Progress", "Mitigated", "Accepted"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CODE_RE = re.compile(r"^[A-Za-z0-9_-]{2,30}$")
HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")


def _s(data, key, maxlen, required=True):
    v = data.get(key)
    v = "" if v is None else str(v).strip()
    if required and not v:
        raise ValueError(f"{key} is required")
    if len(v) > maxlen:
        raise ValueError(f"{key} must be at most {maxlen} characters")
    return v


def _choice(data, key, options):
    v = _s(data, key, 40)
    if v not in options:
        raise ValueError(f"{key} must be one of: {', '.join(options)}")
    return v


def validate_asset(d):
    out = {
        "asset_code": _s(d, "asset_code", 30),
        "name": _s(d, "name", 100),
        "asset_type": _choice(d, "asset_type", ASSET_TYPES),
        "owner": _s(d, "owner", 100),
        "host": _s(d, "host", 255),
        "environment": _choice(d, "environment", ENVIRONMENTS),
        "criticality": _choice(d, "criticality", CRITICALITY),
        "status": _choice(d, "status", ASSET_STATUS),
    }
    if not CODE_RE.match(out["asset_code"]):
        raise ValueError("asset_code may contain letters, digits, - and _ (2-30 chars)")
    if not HOST_RE.match(out["host"]):
        raise ValueError("host must be an IP address or hostname")
    return out


def _int(data, key, lo, hi):
    try:
        v = int(data.get(key))
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a whole number")
    if not lo <= v <= hi:
        raise ValueError(f"{key} must be between {lo} and {hi}")
    return v


def risk_level(score):
    """Risk score = likelihood (1-5) x impact (1-5). 20-25 Critical, 12-19 High, 6-11 Medium, 1-5 Low."""
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def validate_risk(d):
    likelihood, impact = _int(d, "likelihood", 1, 5), _int(d, "impact", 1, 5)
    score = likelihood * impact
    return {
        "asset_id": _int(d, "asset_id", 1, 2**31 - 1),
        "vulnerability_id": _int(d, "vulnerability_id", 1, 2**31 - 1),
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": score,
        "risk_level": risk_level(score),
        "mitigation": _s(d, "mitigation", 1000, required=False),
        "status": _choice(d, "status", RISK_STATUS),
    }


def validate_vuln_manual(d):
    cve = _s(d, "cve_id", 20).upper()
    if not CVE_RE.match(cve):
        raise ValueError("cve_id must look like CVE-2024-12345")
    score = d.get("cvss_score")
    if score in (None, ""):
        score = None
    else:
        try:
            score = round(float(score), 1)
        except (TypeError, ValueError):
            raise ValueError("cvss_score must be a number")
        if not 0 <= score <= 10:
            raise ValueError("cvss_score must be between 0 and 10")
    return {
        "cve_id": cve,
        "description": _s(d, "description", 4000),
        "cvss_score": score,
        "severity": severity_from_score(score),
        "affected_products": _s(d, "affected_products", 1000, required=False),
        "analyst_notes": _s(d, "analyst_notes", 2000, required=False),
    }


def severity_from_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
