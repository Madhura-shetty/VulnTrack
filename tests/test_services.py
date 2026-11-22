"""Unit tests: parsing with payloads shaped like real NVD/CISA responses, validation, failure handling.
HTTP is mocked here ONLY to exercise parsing and error paths - these are not live-API tests."""
import pytest
import requests
from unittest.mock import patch, MagicMock
from app.services import nvd, cisa, validators as v, reports
from app.services.nvd import ApiError

NVD_ITEM = {"cve": {"id": "CVE-2021-44228", "published": "2021-12-10T10:15:09.143", "lastModified": "2023-04-03T20:15:08.000",
    "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Log4j JNDI issue"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]}]}],
    "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}]}}


def resp(status=200, payload=None, bad_json=False):
    r = MagicMock(); r.status_code = status
    if bad_json: r.json.side_effect = ValueError()
    else: r.json.return_value = payload
    return r


def test_parse_full_record():
    r = nvd.parse_cve(NVD_ITEM)
    assert r["cve_id"] == "CVE-2021-44228" and r["cvss_score"] == 10.0 and r["severity"] == "CRITICAL"
    assert r["description"] == "Log4j JNDI issue" and r["affected_products"] == "apache log4j" and len(r["refs"]) == 1
    assert r["published_at"].startswith("2021-12-10")


def test_parse_missing_optional_fields():
    r = nvd.parse_cve({"cve": {"id": "CVE-2024-0001"}})
    assert r["cvss_score"] is None and r["severity"] == "UNKNOWN" and r["refs"] == [] and r["published_at"] is None


def test_parse_v2_fallback_and_invalid():
    r = nvd.parse_cve({"cve": {"id": "CVE-2010-0001", "metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]}}})
    assert r["severity"] == "HIGH" and r["cvss_score"] == 7.5
    with pytest.raises(ValueError): nvd.parse_cve({"nothing": 1})


@patch("app.services.nvd.requests.get")
def test_search_skips_bad_entries(g):
    g.return_value = resp(payload={"totalResults": 2, "vulnerabilities": [NVD_ITEM, {"bad": 1}]})
    recs, errs, total = nvd.search("keyword", "log4j", 10)
    assert len(recs) == 1 and len(errs) == 1 and total == 2
    assert g.call_args.kwargs["params"]["keywordSearch"] == "log4j"


@patch("app.services.nvd.time.sleep")
@patch("app.services.nvd.requests.get")
def test_429_then_failure(g, _s):
    g.return_value = resp(429)
    with pytest.raises(ApiError, match="429"): nvd.fetch({})
    assert g.call_count == 2  # one retry


@pytest.mark.parametrize("exc,msg", [(requests.exceptions.Timeout(), "timed out"), (requests.exceptions.ConnectionError(), "network")])
@patch("app.services.nvd.requests.get")
def test_network_failures(g, exc, msg):
    g.side_effect = exc
    with pytest.raises(ApiError, match=msg): nvd.fetch({})


@patch("app.services.nvd.requests.get")
def test_malformed_and_http_error(g):
    g.return_value = resp(bad_json=True)
    with pytest.raises(ApiError, match="malformed"): nvd.fetch({})
    g.return_value = resp(payload={"foo": 1})
    with pytest.raises(ApiError, match="missing"): nvd.fetch({})
    g.return_value = resp(503)
    with pytest.raises(ApiError, match="503"): nvd.fetch({})


def test_api_key_header_from_env(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "abc"); assert nvd._headers() == {"apiKey": "abc"}
    monkeypatch.delenv("NVD_API_KEY"); assert nvd._headers() == {}


def test_cisa_parse_and_errors():
    cat = cisa.parse_catalog({"vulnerabilities": [{"cveID": "cve-2021-44228", "vulnerabilityName": "Log4j RCE", "vendorProject": "Apache", "product": "Log4j2",
        "dateAdded": "2021-12-10", "requiredAction": "Apply updates", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"}, {"x": 1}]})
    assert list(cat) == ["CVE-2021-44228"] and cat["CVE-2021-44228"]["ransomware"] == "Known"
    with patch("app.services.cisa.requests.get") as g:
        g.return_value = resp(payload={"nope": []})
        with pytest.raises(ApiError): cisa.fetch_catalog()


def test_validators():
    assert v.validate_asset({"asset_code": "AST-1", "name": "n", "asset_type": "Server", "owner": "o", "host": "10.0.0.1",
                             "environment": "Production", "criticality": "High", "status": "Active"})["host"] == "10.0.0.1"
    with pytest.raises(ValueError): v.validate_asset({"asset_code": "bad code!", "name": "n"})
    with pytest.raises(ValueError): v.validate_asset({"asset_code": "A1", "name": "n", "asset_type": "Server", "owner": "o", "host": "x; DROP TABLE",
                                                      "environment": "Production", "criticality": "High", "status": "Active"})


def test_risk_scoring_and_bounds():
    assert (v.risk_level(25), v.risk_level(12), v.risk_level(6), v.risk_level(5)) == ("Critical", "High", "Medium", "Low")
    r = v.validate_risk({"asset_id": 1, "vulnerability_id": 1, "likelihood": 4, "impact": 5, "status": "Open"})
    assert r["risk_score"] == 20 and r["risk_level"] == "Critical"
    for bad in (0, 6, "x"):
        with pytest.raises(ValueError): v.validate_risk({"asset_id": 1, "vulnerability_id": 1, "likelihood": bad, "impact": 1, "status": "Open"})


def test_manual_vuln_validation():
    assert v.validate_vuln_manual({"cve_id": "cve-2024-1234", "description": "d", "cvss_score": "9.1"})["severity"] == "CRITICAL"
    with pytest.raises(ValueError): v.validate_vuln_manual({"cve_id": "1234", "description": "d"})
    with pytest.raises(ValueError): v.validate_vuln_manual({"cve_id": "CVE-2024-1234", "description": "d", "cvss_score": 11})


def test_csv_formula_injection_neutralised():
    assert reports.safe_cell("=cmd|' /C calc'!A0").startswith("'") and reports.safe_cell("ok") == "ok" and reports.safe_cell(None) == ""
