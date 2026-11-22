"use strict";
const lvl = s => s >= 20 ? "Critical" : s >= 12 ? "High" : s >= 6 ? "Medium" : "Low";
crudPage({
  endpoint: "/api/risks", noun: "Risk assessment", label: r => r.risk_code, defaultSort: ["risk_score", "desc"], exportUrl: "/api/reports/risks.csv",
  columns: [{ key: "risk_code", label: "Risk ID", sortable: true, sortKey: "id" }, { key: "asset", label: "Asset", sortable: true }, { key: "cve_id", label: "Vulnerability", sortable: true },
    { key: "likelihood", label: "Likelihood", sortable: true }, { key: "impact", label: "Impact", sortable: true }, { key: "risk_score", label: "Score", sortable: true },
    { key: "risk_level", label: "Level", render: r => badge(r.risk_level) }, { key: "mitigation", label: "Mitigation", cls: "desc" }, { key: "status", label: "Status", sortable: true }],
  filters: [{ param: "risk_level", label: "All levels", options: ["Low", "Medium", "High", "Critical"] }, { param: "status", label: "All statuses", options: ["Open", "In Progress", "Mitigated", "Accepted"] }],
  fields: [{ name: "asset_id", label: "Related asset", required: true, optionsUrl: "/api/assets/options" },
    { name: "vulnerability_id", label: "Related vulnerability", required: true, optionsUrl: "/api/vulnerabilities/options" },
    { name: "likelihood", label: "Likelihood (1-5)", type: "number", min: 1, max: 5, required: true, default: 3 },
    { name: "impact", label: "Impact (1-5)", type: "number", min: 1, max: 5, required: true, default: 3, hint: "Risk score = likelihood x impact. 20+ Critical, 12-19 High, 6-11 Medium, below 6 Low. Calculated by the server." },
    { name: "mitigation", label: "Mitigation action", type: "textarea", maxlength: 1000 },
    { name: "status", label: "Status", required: true, options: ["Open", "In Progress", "Mitigated", "Accepted"], default: "Open" }],
});
