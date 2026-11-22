"use strict";
const CSRF = document.querySelector('meta[name="csrf-token"]').content;
const form = document.getElementById("loginForm"), errBox = document.getElementById("loginError");
function showErr(m) { errBox.textContent = m; errBox.hidden = false; }
form.addEventListener("submit", async e => {
  e.preventDefault(); errBox.hidden = true;
  const username = form.username.value.trim(), password = form.password.value;
  if (!username || !password) return showErr("Please enter both username and password.");
  document.getElementById("loginBtn").disabled = true;
  try {
    const res = await fetch("/api/login", { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF }, body: JSON.stringify({ username, password }) });
    const data = await res.json().catch(() => ({}));
    if (res.ok) { window.location.href = "/"; return; }
    showErr(data.error || "Sign-in failed.");
  } catch (err) { showErr("Cannot reach the server."); }
  document.getElementById("loginBtn").disabled = false;
});
