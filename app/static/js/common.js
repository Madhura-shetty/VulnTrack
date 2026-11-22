"use strict";
const CSRF = document.querySelector('meta[name="csrf-token"]').content;

/** fetch wrapper: JSON in/out, CSRF header, loading spinner, throws Error(message) on failure */
async function api(url, opts = {}, quiet = false) {
  const loading = document.getElementById("loading");
  if (loading && !quiet) loading.hidden = false;
  try {
    const init = { method: opts.method || "GET", headers: { "X-CSRF-Token": CSRF }, credentials: "same-origin" };
    if (opts.body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
    const res = await fetch(url, init);
    let data = {};
    try { data = await res.json(); } catch (e) { /* non-JSON */ }
    if (res.status === 401 && !url.endsWith("/login")) { window.location.href = "/login"; throw new Error("Session expired"); }
    if (!res.ok) { const err = new Error(data.error || "Request failed (" + res.status + ")"); err.status = res.status; err.data = data; throw err; }
    return data;
  } finally { if (loading) loading.hidden = true; }
}

function toast(msg, isError) {
  const box = document.getElementById("toasts"); if (!box) return;
  const t = document.createElement("div"); t.className = "toast" + (isError ? " error" : ""); t.textContent = msg;
  box.appendChild(t); setTimeout(() => t.remove(), 4500);
}

function el(tag, props, ...kids) {  // safe DOM builder: text is always set via textContent (XSS-proof)
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") e.className = v; else if (k === "text") e.textContent = v; else if (k === "onclick") e.addEventListener("click", v); else e.setAttribute(k, v);
  }
  kids.flat().forEach(c => { if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c))); });
  return e;
}
const badge = (text, cls) => el("span", { class: "badge b-" + String(cls || text).toLowerCase(), text });
const fmtDate = v => v ? new Date(v).toLocaleString() : "-";
const fmtDay = v => v ? new Date(v).toLocaleDateString() : "-";
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function safeUrl(u) { return /^https?:\/\//i.test(u || "") ? u : null; }

function confirmDialog(text) {
  return new Promise(resolve => {
    const d = document.getElementById("confirmDialog");
    document.getElementById("confirmText").textContent = text;
    const ok = document.getElementById("confirmOk"), no = document.getElementById("confirmCancel");
    const done = v => { ok.onclick = no.onclick = null; d.close(); resolve(v); };
    ok.onclick = () => done(true); no.onclick = () => done(false); d.showModal();
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const out = document.getElementById("logoutBtn");
  if (out) out.addEventListener("click", async () => { try { await api("/api/logout", { method: "POST" }); } finally { window.location.href = "/login"; } });
  const menu = document.getElementById("menuBtn"), side = document.getElementById("sidebar");
  if (menu) menu.addEventListener("click", () => side.classList.toggle("open"));
});
