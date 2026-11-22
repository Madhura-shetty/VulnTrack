"use strict";
const L = { env: ["Production", "Staging", "Development", "Test"], crit: ["Low", "Medium", "High", "Critical"], st: ["Active", "Inactive", "Decommissioned"],
  type: ["Server", "Workstation", "Network Device", "Database", "Application", "Cloud Service", "Other"] };
crudPage({
  endpoint: "/api/assets", noun: "Asset", label: r => r.asset_code, defaultSort: ["asset_code", "asc"], exportUrl: "/api/reports/assets.csv",
  columns: [{ key: "asset_code", label: "Asset ID", sortable: true }, { key: "name", label: "Name", sortable: true }, { key: "asset_type", label: "Type", sortable: true },
    { key: "owner", label: "Owner", sortable: true }, { key: "host", label: "IP / Hostname", sortable: true }, { key: "environment", label: "Environment", sortable: true },
    { key: "criticality", label: "Criticality", sortable: true, render: r => badge(r.criticality) }, { key: "status", label: "Status", sortable: true }],
  filters: [{ param: "environment", label: "All environments", options: L.env }, { param: "criticality", label: "All criticality", options: L.crit }, { param: "status", label: "All statuses", options: L.st }],
  fields: [{ name: "asset_code", label: "Asset ID", required: true, maxlength: 30, pattern: /^[A-Za-z0-9_-]{2,30}$/, patternMsg: "Asset ID: letters, digits, - or _ (2-30 chars)" },
    { name: "name", label: "Asset name", required: true, maxlength: 100 }, { name: "asset_type", label: "Asset type", required: true, options: L.type },
    { name: "owner", label: "Owner", required: true, maxlength: 100 },
    { name: "host", label: "IP address or hostname", required: true, maxlength: 255, pattern: /^[A-Za-z0-9._:-]{1,255}$/, patternMsg: "Enter a valid IP address or hostname" },
    { name: "environment", label: "Environment", required: true, options: L.env }, { name: "criticality", label: "Criticality", required: true, options: L.crit },
    { name: "status", label: "Status", required: true, options: L.st, default: "Active" }],
});
