"use strict";
const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const dlgDetail = document.getElementById("detailDialog");
document.getElementById("detailClose").addEventListener("click", () => dlgDetail.close());

async function showDetail(row) {
  try {
    const v = await api("/api/vulnerabilities/" + row.id);
    const dl = el("dl", { class: "detail-grid" });
    const add = (k, val) => dl.append(el("dt", { text: k }), el("dd", {}, val));
    add("CVE ID", v.cve_id); add("Source", badge(v.source)); add("Severity", [badge(v.severity), " ", v.cvss_score ?? "no CVSS score"]);
    add("Description", v.description); add("Affected products", v.affected_products || "Not available");
    add("Published", fmtDate(v.published_at)); add("Last modified", fmtDate(v.last_modified_at)); add("Last synchronized", fmtDate(v.synced_at));
    if (v.is_kev && v.kev_data) {
      const k = v.kev_data;
      add("CISA KEV", badge("Known exploited", "kev")); add("KEV name", k.name); add("Vendor / product", k.vendor + " / " + k.product);
      add("Date added", k.date_added); add("Required action", k.required_action); add("Due date", k.due_date); add("Ransomware use", k.ransomware);
    } else add("CISA KEV", "Not listed" + (v.source === "sample" ? " (sample record; run a sync to check KEV)" : ""));
    add("References", (v.refs || []).filter(safeUrl).map(u => el("div", {}, el("a", { href: u, target: "_blank", rel: "noopener noreferrer", text: u }))));
    add("Analyst notes", v.analyst_notes || "-");
    document.getElementById("detailBody").replaceChildren(el("h2", { text: v.cve_id }), dl);
    dlgDetail.showModal();
  } catch (e) { toast(e.message, true); }
}

crudPage({
  endpoint: "/api/vulnerabilities", noun: "Vulnerability", label: r => r.cve_id, defaultSort: ["published_at", "desc"], exportUrl: "/api/reports/vulnerabilities.csv",
  columns: [
    { key: "cve_id", label: "CVE ID", sortable: true, render: r => el("a", { href: "#", text: r.cve_id, onclick: e => { e.preventDefault(); showDetail(r); } }) },
    { key: "description", label: "Description", cls: "desc", render: r => r.description.length > 140 ? r.description.slice(0, 140) + "..." : r.description },
    { key: "cvss_score", label: "CVSS", sortable: true, render: r => r.cvss_score ?? "N/A" },
    { key: "severity", label: "Severity", render: r => badge(r.severity) },
    { key: "affected_products", label: "Affected product", cls: "desc", render: r => r.affected_products || "-" },
    { key: "published_at", label: "Published", sortable: true, render: r => fmtDay(r.published_at) },
    { key: "is_kev", label: "CISA KEV", sortable: true, render: r => r.is_kev ? badge("KEV", "kev") : "No" },
    { key: "source", label: "Source", sortable: true, render: r => badge(r.source) },
    { key: "reference", label: "Reference", render: r => safeUrl(r.reference) ? el("a", { href: r.reference, target: "_blank", rel: "noopener noreferrer", text: "Link" }) : "-" }],
  filters: [{ param: "severity", label: "All severities", options: SEV }, { param: "is_kev", label: "KEV: any", options: [["true", "Known exploited"], ["false", "Not in KEV"]] },
    { param: "source", label: "All sources", options: [["nvd", "NVD (API)"], ["sample", "Sample"], ["manual", "Manual"]] }],
  fields: [{ name: "cve_id", label: "CVE ID", required: true, maxlength: 20, pattern: /^CVE-\d{4}-\d{4,}$/i, patternMsg: "Format: CVE-2024-12345" },
    { name: "description", label: "Description", type: "textarea", required: true, maxlength: 4000 },
    { name: "cvss_score", label: "CVSS score (0-10)", type: "number", min: 0, max: 10, step: "0.1" },
    { name: "affected_products", label: "Affected products", maxlength: 1000 },
    { name: "analyst_notes", label: "Analyst notes", type: "textarea", maxlength: 2000, hint: "For NVD (API) records only notes can be edited; API data is never overwritten by manual edits." }],
  lockedFields: r => r.source === "nvd" ? ["cve_id", "description", "cvss_score", "affected_products"] : ["cve_id"],
  canDelete: r => r.source !== "nvd",
});
// edit form needs notes: fetch full row so analyst_notes is pre-filled
