"use strict";
(async function () {
  try {
    const d = await api("/api/dashboard", {}, true);
    for (const k of ["assets", "vulnerabilities", "critical", "high", "kev", "risks"]) document.getElementById("s-" + k).textContent = d[k];
    document.getElementById("lastSync").textContent = d.last_sync ? fmtDate(d.last_sync) : "Never";
    document.getElementById("recentAudit").replaceChildren(...d.recent_audit.map(a =>
      el("tr", {}, el("td", { text: a.username }), el("td", { text: a.action }), el("td", { text: a.module }), el("td", { text: a.record_id || "-" }), el("td", { text: fmtDate(a.created_at) }))));
  } catch (e) { toast(e.message, true); }
})();
