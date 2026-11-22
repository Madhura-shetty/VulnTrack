"use strict";
const q = document.getElementById("searchInput"), mod = document.getElementById("moduleFilter");
async function load() {
  const p = new URLSearchParams(); if (q.value.trim()) p.set("q", q.value.trim()); if (mod.value) p.set("module", mod.value);
  try {
    const items = (await api("/api/audit-logs?" + p, {}, true)).items;
    document.getElementById("emptyMsg").hidden = items.length > 0;
    document.getElementById("auditBody").replaceChildren(...items.map(a =>
      el("tr", {}, el("td", { text: a.username }), el("td", {}, badge(a.action, "nvd")), el("td", { text: a.module }), el("td", { text: a.record_id || "-" }), el("td", { text: fmtDate(a.created_at) }))));
  } catch (e) { toast(e.message, true); }
}
q.addEventListener("input", debounce(load, 250)); mod.addEventListener("change", load); load();
