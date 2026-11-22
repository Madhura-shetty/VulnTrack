"use strict";
const $ = id => document.getElementById(id);
const isAdmin = document.body.dataset.role === "admin";
function setStatus(id, r) { const s = $(id + "Status"); s.textContent = r.ok ? "Connected" : "Unavailable"; s.className = "badge b-" + (r.ok ? "ok" : "bad"); $(id + "Msg").textContent = r.ok ? "" : r.message; }

async function loadLogs() {
  try {
    const d = await api("/api/sync/logs", {}, true);
    $("lastSuccess").textContent = d.last_success ? fmtDate(d.last_success) : "Never";
    $("logBody").replaceChildren(...d.items.map(l => el("tr", {}, el("td", { text: fmtDate(l.created_at) }), el("td", { text: l.source }), el("td", { text: l.query }),
      el("td", { text: l.fetched }), el("td", { text: l.inserted }), el("td", { text: l.updated }), el("td", { text: l.failed }), el("td", {}, badge(l.status)), el("td", { class: "desc", text: l.message || "-" }))));
  } catch (e) { toast(e.message, true); }
}

$("checkBtn").addEventListener("click", async () => {
  try { const r = await api("/api/sync/check", { method: "POST" }); setStatus("nvd", r.nvd); setStatus("cisa", r.cisa); }
  catch (e) { toast(e.message, true); }
});

$("syncMode").addEventListener("change", () => { $("syncQuery").disabled = ["recent", "kev"].includes($("syncMode").value); });
$("syncMode").dispatchEvent(new Event("change"));

$("syncForm").addEventListener("submit", async e => {
  e.preventDefault(); const err = $("syncError"); err.hidden = true;
  const mode = $("syncMode").value, query = $("syncQuery").value.trim(), limit = parseInt($("syncLimit").value, 10);
  if ((mode === "keyword" || mode === "cve") && !query) { err.textContent = "Enter a keyword or CVE ID."; err.hidden = false; return; }
  if (mode === "cve" && !/^CVE-\d{4}-\d{4,}$/i.test(query)) { err.textContent = "CVE ID format: CVE-2021-44228"; err.hidden = false; return; }
  if (!(limit >= 1 && limit <= 100)) { err.textContent = "Max records must be 1-100."; err.hidden = false; return; }
  let r;
  try { r = await api("/api/sync", { method: "POST", body: { mode, query, limit } }); }
  catch (ex) { r = ex.data && ex.data.status ? ex.data : { status: "failed", fetched: 0, inserted: 0, updated: 0, failed: 0, messages: [ex.message] }; }
  $("resultCard").hidden = false;
  $("resultSummary").textContent = "Status: " + r.status + " | Fetched " + r.fetched + " | New " + r.inserted + " | Updated " + r.updated + " | Failed " + r.failed + " | KEV matches " + (r.kev_matched ?? 0);
  $("resultMessages").replaceChildren(...(r.messages || []).map(m => el("li", { text: m })));
  toast("Synchronization " + r.status, r.status === "failed"); loadLogs();
});

$("sampleBtn").addEventListener("click", async () => {
  try { const r = await api("/api/sync/sample", { method: "POST" }); toast(r.inserted + " sample record(s) added (labelled 'sample', not live data)"); loadLogs(); }
  catch (e) { toast(e.message, true); }
});
loadLogs();
