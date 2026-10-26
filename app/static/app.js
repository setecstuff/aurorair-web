/* Aurora IR Web - browser client.
 * Security notes: all user data is inserted with textContent / DOM properties only
 * (never innerHTML); the CSP forbids inline scripts and third-party origins. */
"use strict";

const POLL_MS = 4000;
const S = {
  me: null, csrf: "", schema: null, sections: {}, cases: [], caseId: null, caseInfo: null,
  options: { lookups: {}, refs: {} }, view: "timeline", records: [], revision: 0,
  sort: {}, filter: "", pollTimer: null, online: true, modal: null, counts: {},
};

/* ------------------------------------------------------------------ helpers */

function el(tag, props, ...children) {
  const e = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (k === "dataset") Object.assign(e.dataset, v);
      else if (k in e && k !== "list") e[k] = v;
      else e.setAttribute(k, v === true ? "" : String(v));
    }
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

function toast(msg, isErr) {
  const t = el("div", { class: "t" + (isErr ? " err" : ""), text: msg });
  document.getElementById("toast").append(t);
  setTimeout(() => t.remove(), isErr ? 7000 : 3500);
}

class ApiError extends Error {
  constructor(status, body) {
    super((body && typeof body.detail === "string") ? body.detail : `HTTP ${status}`);
    this.status = status; this.body = body || {};
  }
}

async function api(method, path, body, rawBody) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") opts.headers["X-CSRF-Token"] = S.csrf;
  if (rawBody !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = rawBody;
  } else if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try { res = await fetch(path, opts); } catch (e) { throw new ApiError(0, { detail: "Network error - server unreachable" }); }
  let data = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) data = await res.json().catch(() => null);
  if (res.status === 401 && !path.startsWith("/api/login") && path !== "/api/mfa/setup") {
    if (path === "/api/session") showLogin(); else showLogin("Your session expired. Please sign in again.");
    throw new ApiError(401, data);
  }
  if (!res.ok) {
    if (data && Array.isArray(data.detail)) data.detail = data.detail.map(d => d.msg).join("; ");
    throw new ApiError(res.status, data);
  }
  return data;
}

const pad = n => String(n).padStart(2, "0");
function fmtMs(v) {
  if (v === "" || v === null || v === undefined) return "";
  if (typeof v !== "number") return String(v);
  const d = new Date(v);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}
function fmtTs(sec) { return fmtMs(sec * 1000); }
function nowUtc() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
function display(f, v) {
  if (f.kind === "bool") return v === true ? "✓" : "";
  if (f.kind === "auto_ms") return fmtMs(v);
  if (v === null || v === undefined) return "";
  return String(v);
}
function same(f, a, b) {
  if (f.kind === "bool") return !!a === !!b;
  return String(a ?? "") === String(b ?? "");
}
/** Column/field label; time fields are marked UTC everywhere. */
const isTimeField = f => f.kind === "datetime" || f.kind === "auto_ms";
const fieldLabel = f => isTimeField(f) ? `${f.label} (UTC)` : f.label;
// Edit / manage rights are per-case now (resolved by the server and returned on the case). canEdit/canManage
// reflect the currently open case; a signed-in user may always create or join a case.
const canEdit = () => !!(S.caseInfo && S.caseInfo.can_edit);
const canManage = () => !!(S.caseInfo && S.caseInfo.can_manage);
const isAdmin = () => S.me && S.me.role === "admin";
const signedIn = () => !!S.me;
// Cases are shown with their unique number prefixed ("12: IR-608 — client"): a user may not see other cases,
// so two cases can share a Case ID; the number keeps them distinct. The number is display-only (not in exports).
const caseLabel = c => `${c.id}: ${c.case_id || "—"}${c.client ? " — " + c.client : ""}`;
const lsGet = k => { try { return localStorage.getItem(k); } catch { return null; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* ignore */ } };

/**
 * Turn a text input into a masked secret field that browsers do NOT treat as a login password.
 * (A real type="password" input makes Chrome autofill the saved site login into it and into the text
 * field before it.) Masking is visual only (CSS -webkit-text-security); returns the input plus a Show button.
 */
function maskSecret(input) {
  input.type = "text";
  input.classList.add("masked");
  input.autocomplete = "off";
  input.spellcheck = false;
  for (const [k, v] of Object.entries({ "data-lpignore": "true", "data-1p-ignore": "true", "data-bwignore": "true",
    "data-form-type": "other", autocapitalize: "off", autocorrect: "off" })) input.setAttribute(k, v);
  const btn = el("button", { class: "btn small", type: "button", text: "Show", onclick: () => {
    const hidden = input.classList.toggle("masked");
    btn.textContent = hidden ? "Show" : "Hide";
  } });
  return el("div", { class: "row" }, input, btn);
}

/* ------------------------------------------------------------------ auth */

function authScreen(...children) {
  stopPolling();
  closeModal();
  document.getElementById("app").replaceChildren(el("div", { class: "login-wrap" }, ...children));
}

function showLogin(message) {
  if (typeof forgetApiKey === "function") forgetApiKey();
  S.me = null;
  const err = el("div", { class: "err", text: message || "" });
  const u = el("input", { type: "text", name: "username", autocomplete: "username", required: true, maxLength: 64 });
  const p = el("input", { type: "password", name: "password", autocomplete: "current-password", required: true, maxLength: 256 });
  const btn = el("button", { class: "btn primary", type: "submit", text: "Sign in" });
  const form = el("form", { class: "login", onsubmit: async ev => {
    ev.preventDefault(); btn.disabled = true; err.textContent = "";
    try { await afterAuthStep(await api("POST", "/api/login", { username: u.value, password: p.value })); }
    catch (e) { err.textContent = e.message; btn.disabled = false; p.value = ""; p.focus(); }
  } },
    el("h1", { text: "Aurora IR Web" }),
    el("p", { text: "Collaborative incident response case editing" }),
    el("div", { class: "field" }, el("label", { class: "lbl", text: "Username" }), u),
    el("div", { class: "field" }, el("label", { class: "lbl", text: "Password" }), p),
    btn, el("div", { class: "fld" }, err));
  authScreen(form);
  u.focus();
}

/** Continue the staged sign-in: mfa -> password -> mfa_setup -> full. */
async function afterAuthStep(r) {
  S.csrf = r.csrf;
  S.mfaEnforced = !!r.mfa_enforced;
  if (r.stage === "full") { S.me = r.user; return startApp(); }
  S.me = null;
  if (r.stage === "mfa") return showMfaCode(r.user);
  if (r.stage === "password") return showNewPassword(r.user);
  if (r.stage === "mfa_setup") return showMfaSetup(r.user);
  showLogin("Unexpected sign-in state; please sign in again.");
}

function stageForm(title, intro, fields, submitText, onSubmit) {
  const err = el("div", { class: "err" });
  const btn = el("button", { class: "btn primary", type: "submit", text: submitText });
  const form = el("form", { class: "login", onsubmit: async ev => {
    ev.preventDefault(); btn.disabled = true; err.textContent = "";
    try { await onSubmit(); } catch (e) { err.textContent = e.message; btn.disabled = false; }
  } },
    el("h1", { text: title }), intro, ...fields, btn, el("div", { class: "fld" }, err),
    el("p", { class: "muted small" }, el("a", { href: "#", text: "Cancel and sign out", onclick: ev => { ev.preventDefault(); logout(); } })));
  return form;
}

function codeInput() {
  return el("input", { type: "text", inputMode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,7}",
    maxLength: 7, required: true, placeholder: "123456", class: "otp" });
}

function showMfaCode(user) {
  const code = codeInput();
  authScreen(stageForm("Two-factor authentication",
    el("p", { text: `Enter the 6-digit code from your authenticator app for ${user.username}.` }),
    [el("div", { class: "field" }, el("label", { class: "lbl", text: "Authentication code" }), code)], "Verify",
    async () => afterAuthStep(await api("POST", "/api/login/mfa", { code: code.value.replace(/\s/g, "") }))));
  code.focus();
}

function showNewPassword(user) {
  const p1 = el("input", { type: "password", autocomplete: "new-password", required: true, maxLength: 256 });
  const p2 = el("input", { type: "password", autocomplete: "new-password", required: true, maxLength: 256 });
  authScreen(stageForm("Choose a new password",
    el("p", { text: `An administrator requires ${user.username} to set a new password before continuing (at least 12 characters).` }),
    [el("div", { class: "field" }, el("label", { class: "lbl", text: "New password" }), p1),
     el("div", { class: "field" }, el("label", { class: "lbl", text: "Repeat" }), p2)], "Save password",
    async () => {
      if (p1.value !== p2.value) throw new Error("The passwords do not match");
      await afterAuthStep(await api("POST", "/api/login/password", { new: p1.value }));
    }));
  p1.focus();
}

async function showMfaSetup(user, inline) {
  const setup = await api("GET", "/api/mfa/setup");
  const code = codeInput();
  const secretText = el("code", { class: "mono", text: setup.secret.replace(/(.{4})/g, "$1 ").trim() });
  const body = [
    el("p", { text: inline ? "Scan the QR code with an authenticator app (Microsoft or Google Authenticator, FreeOTP, 1Password, …), then enter the code it shows."
      : "Two-factor authentication is required on this server. Scan the QR code with an authenticator app (Microsoft or Google Authenticator, FreeOTP, 1Password, …), then enter the code it shows." }),
    el("div", { class: "qr" }, el("img", { src: setup.qr_png, alt: "QR code for the authenticator app", width: 220, height: 220 })),
    el("p", { class: "muted small" }, "Can't scan? Enter this key manually (time-based, 6 digits, 30 s): ", secretText),
    el("div", { class: "field" }, el("label", { class: "lbl", text: "Code from the app" }), code)];
  if (inline) return { body, code };
  authScreen(stageForm("Set up two-factor authentication", el("p", { class: "muted", text: `Account: ${user.username}` }), body, "Activate",
    async () => afterAuthStep(await api("POST", "/api/mfa/setup", { code: code.value.replace(/\s/g, "") }))));
  code.focus();
}

async function boot() {
  try {
    await afterAuthStep(await api("GET", "/api/session"));
  } catch (e) {
    if (e.status !== 401) showLogin(e.message);
  }
}

async function logout() {
  try { await api("POST", "/api/logout", {}); } catch { /* ignore */ }
  showLogin("Signed out.");
}

/* ------------------------------------------------------------------ app shell */

// Views that do not need a selected case
const NO_CASE_VIEWS = ["admin_cases", "admin_users", "admin_keys", "admin_integrations", "admin_backups", "account", "about", "apiexplorer"];

async function startApp() {
  S.schema = await api("GET", "/api/schema");
  S.sections = {};
  for (const s of S.schema.sections) S.sections[s.key] = s;
  S.cases = await api("GET", "/api/cases");
  const saved = Number(lsGet("aurora.case"));
  S.caseId = S.cases.find(c => c.id === saved) ? saved : (S.cases[0] ? S.cases[0].id : null);
  S.view = lsGet("aurora.view") || "timeline";
  if (!S.caseId && !NO_CASE_VIEWS.includes(S.view)) S.view = isAdmin() ? "admin_cases" : "about";
  renderShell();
  await loadCase();
  startPolling();
}

function renderShell() {
  const caseSel = el("select", { title: "Case", onchange: async ev => {
    S.caseId = Number(ev.target.value); lsSet("aurora.case", S.caseId);
    if (!S.sections[S.view] && !REPORT_VIEWS[S.view] && !["case", "report", "activity", ...NO_CASE_VIEWS].includes(S.view)) S.view = "timeline";
    await loadCase();
  } });
  for (const c of S.cases) caseSel.append(el("option", { value: c.id, text: caseLabel(c), selected: c.id === S.caseId }));
  if (!S.cases.length) caseSel.append(el("option", { text: "No cases", disabled: true, selected: true }));

  const exportBtn = el("button", { class: "btn primary", text: "⬇ Export .fox", title: "Download the current case as an Aurora .fox file (opens in the Aurora desktop app)", disabled: !S.caseId, onclick: () => exportFox("export", "case.fox") });
  const xlsxBtn = el("button", { class: "btn primary", text: "⬇ Export Excel", title: "Download the spreadsheet of doom: cover, executive summary and one sheet per section (UTC times)", disabled: !S.caseId, onclick: () => exportFox("export.xlsx", "case.xlsx") });
  const pdfBtn = el("button", { class: "btn", text: "PDF", title: "Download the case report as PDF (cover, executive summary, charts, all sections)", disabled: !S.caseId, onclick: () => exportFox("export.pdf", "case.pdf") });
  const texBtn = el("button", { class: "btn", text: "LaTeX", title: "Download the case report as a LaTeX source file (compile with xelatex)", disabled: !S.caseId, onclick: () => exportFox("export.tex", "case.tex") });
  const live = el("div", { class: "live", id: "live" }, el("span", { class: "dot" }), el("span", { id: "live-text", text: "Live" }));

  const navBtn = el("button", { class: "btn small navtoggle", type: "button", text: "☰", title: "Show / hide the menu",
    "aria-label": "Toggle menu", onclick: () => {
      const open = document.querySelector(".layout").classList.toggle("nav-open");
      lsSet("aurora.nav", open ? "open" : "closed");
    } });
  const top = el("div", { class: "topbar" }, navBtn,
    el("div", { class: "brand" }, el("img", { src: "favicon.svg", alt: "" }), el("span", { class: "brand-text", text: "Aurora IR Web" })),
    caseSel,
    signedIn() ? el("button", { class: "btn small", text: "+ New case", title: "Create an empty case (you become its owner)", onclick: openNewCaseModal }) : null,
    signedIn() ? el("button", { class: "btn small", text: "Import .fox", title: "Import a .fox as a new case (you become its owner)", onclick: openImportModal }) : null,
    signedIn() ? el("button", { class: "btn small", text: "Join case", title: "Join a case with its id and an invite code", onclick: openJoinModal }) : null,
    exportBtn, xlsxBtn, el("div", { class: "btn-group" }, pdfBtn, texBtn), live, el("div", { class: "spacer" }),
    el("span", { class: "userbox", text: `${S.me.username} (${S.me.role})` }),
    el("button", { class: "btn small", text: "Account", title: "Password and two-factor authentication", onclick: () => navigate("account") }),
    el("button", { class: "btn small", text: "Sign out", onclick: logout }));

  const side = el("nav", { class: "sidebar", id: "sidebar" });
  const content = el("main", { class: "content", id: "content" });
  // Menu: open by default on wide screens, collapsed below 1366px (the user's choice is remembered)
  const pref = lsGet("aurora.nav");
  const open = pref ? pref === "open" : window.innerWidth >= 1366;
  document.getElementById("app").replaceChildren(el("div", { class: "layout" + (open ? " nav-open" : "") }, top, side, content));
  renderSidebar();
}

function renderSidebar() {
  const side = document.getElementById("sidebar");
  if (!side) return;
  const link = (key, label) => el("a", { class: S.view === key ? "active" : "", onclick: () => navigate(key) },
    el("span", { text: label }), S.counts[key] !== undefined ? el("span", { class: "count", text: S.counts[key] }) : null);
  const items = [];
  if (S.caseId) {
    let group = null;
    for (const s of S.schema.sections) {
      if (s.group !== group) {
        if (group === "Investigation") {   // Aurora's order: Investigation, Reporting, Case Management
          items.push(el("div", { class: "group", text: "Reporting" }));
          for (const [k, v] of Object.entries(REPORT_VIEWS)) items.push(link(k, v.label));
        }
        group = s.group; items.push(el("div", { class: "group", text: group }));
      }
      items.push(link(s.key, s.label));
    }
    items.push(el("div", { class: "group", text: "Case" }), link("case", "Case Details"), link("report", "Report"),
      link("activity", "Activity Log"));
  }
  if (isAdmin()) items.push(el("div", { class: "group", text: "Administration" }), link("admin_cases", "Cases"),
    link("admin_users", "Users"), link("admin_keys", "API Keys"), link("admin_integrations", "MISP & VirusTotal"),
    link("admin_backups", "Backups & Restore"));
  items.push(el("div", { class: "group", text: "Integrations" }), link("apiexplorer", "API Explorer"));
  items.push(el("div", { class: "group", text: "About" }), link("about", "About & Credits"));
  side.replaceChildren(...items);
}

async function navigate(view) {
  if (!REPORT_VIEWS[view]) destroyReport();
  S.view = view; lsSet("aurora.view", view); S.filter = "";
  renderSidebar();
  await renderView();
}

async function loadCase() {
  destroyReport();
  if (S.caseId) {
    S.caseInfo = await api("GET", `/api/cases/${S.caseId}`);
    S.revision = S.caseInfo.revision;
    S.counts = Object.assign({}, S.caseInfo.counts);   // menu badges for every section, up front
    S.options = await api("GET", `/api/cases/${S.caseId}/options`);
  } else S.counts = {};
  renderSidebar();
  await renderView();
}

async function renderView() {
  const content = document.getElementById("content");
  if (!content) return;
  try {
    if (S.sections[S.view] && S.caseId) return await renderSection();
    if (REPORT_VIEWS[S.view] && S.caseId) return await renderReport(S.view);
    if (S.view === "about") return renderAbout();
    if (S.view === "account") return await renderAccount();
    if (S.view === "apiexplorer") return await renderApiExplorer();
    if (S.view === "case" && S.caseId) return renderCaseDetails();
    if (S.view === "report" && S.caseId) return await renderExecSummary();
    if (S.view === "activity" && S.caseId) return await renderActivity();
    if (S.view === "admin_cases" && isAdmin()) return await renderAdminCases();
    if (S.view === "admin_users" && isAdmin()) return await renderAdminUsers();
    if (S.view === "admin_keys" && isAdmin()) return await renderAdminKeys();
    if (S.view === "admin_integrations" && isAdmin()) return await renderAdminIntegrations();
    if (S.view === "admin_backups" && isAdmin()) return await renderAdminBackups();
    content.replaceChildren(el("div", { class: "empty", text: S.caseId ? "Select a section." : "No cases yet. Create one with + New case, import a .fox, or join a case you were invited to with Join case." }));
  } catch (e) {
    if (e.status !== 401) content.replaceChildren(el("div", { class: "banner err", text: e.message }));
  }
}

/* ------------------------------------------------------------------ live updates */

function startPolling() {
  stopPolling();
  S.pollTimer = setInterval(poll, POLL_MS);
}
function stopPolling() { if (S.pollTimer) clearInterval(S.pollTimer); S.pollTimer = null; }

async function poll() {
  if (!S.caseId || document.hidden || !S.me) return;
  const liveEl = document.getElementById("live");
  try {
    const r = await api("GET", `/api/cases/${S.caseId}/revision`);
    if (liveEl) { liveEl.classList.remove("off"); document.getElementById("live-text").textContent = "Live"; }
    if (r.revision !== S.revision) {
      S.revision = r.revision;
      S.options = await api("GET", `/api/cases/${S.caseId}/options`);
      S.caseInfo = await api("GET", `/api/cases/${S.caseId}`);
      S.counts = Object.assign({}, S.caseInfo.counts);
      renderSidebar();
      if (S.sections[S.view]) await refreshSection(true);
      else if (REPORT_VIEWS[S.view]) await renderReport(S.view, true);
      else if (S.view === "activity") await renderActivity();
      else if (S.view === "case" && !(S.caseForm && S.caseForm.isDirty())) renderCaseDetails(true);
      else if (S.view === "report" && !(S.reportForm && S.reportForm.isDirty())) await renderExecSummary();
      if (S.modal && S.modal.onRemoteChange) S.modal.onRemoteChange();
    }
  } catch (e) {
    if (liveEl && e.status !== 401) { liveEl.classList.add("off"); document.getElementById("live-text").textContent = "Offline"; }
  }
}

/* ------------------------------------------------------------------ section grid */

async function fetchRecords(section) {
  const r = await api("GET", `/api/cases/${S.caseId}/sections/${section}`);
  return r.records;
}

async function renderSection() {
  const sec = S.sections[S.view];
  S.records = await fetchRecords(sec.key);
  S.counts[sec.key] = S.records.length;
  renderSidebar();
  const search = el("input", { type: "search", placeholder: "Filter…", value: S.filter, oninput: ev => { S.filter = ev.target.value; drawTable(); } });
  const tb = el("div", { class: "toolbar" },
    el("h2", { text: sec.label }), el("span", { class: "muted", id: "rowcount" }), search,
    canEdit() ? el("button", { class: "btn primary", text: "+ Add", onclick: () => openRecordModal(sec, null) }) : null,
    canEdit() ? el("button", { class: "btn small", text: "Import CSV", title: "Add records to this section from a CSV file (validated; all-or-nothing)", onclick: () => importSectionCsv(sec) }) : null,
    el("button", { class: "btn small", text: "Export CSV", title: "Download this section's records as a CSV file (UTF-8, RFC 4180)", onclick: () => downloadSectionCsv(sec) }));
  const wrap = el("div", { class: "table-wrap", id: "tablewrap" });
  document.getElementById("content").replaceChildren(tb, wrap);
  drawTable();
}

async function refreshSection(fromPoll) {
  const sec = S.sections[S.view];
  const old = new Map(S.records.map(r => [r.recid, r.version]));
  S.records = await fetchRecords(sec.key);
  S.counts[sec.key] = S.records.length;
  renderSidebar();
  const changed = fromPoll ? new Set(S.records.filter(r => old.get(r.recid) !== r.version).map(r => r.recid)) : new Set();
  drawTable(changed);
}

/** Sort key comparison shared by header sorting; mirrors the server's ordering (schema.sort_by_fields). */
function ipKey(v) {
  const s = String(v).trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return [4, s.split(".").map(n => n.padStart(3, "0")).join(".")];
  if (s.includes(":")) {                     // IPv6: expand "::" and zero-pad every group
    const [h, t] = s.toLowerCase().split("::");
    const hs = h ? h.split(":") : [], ts = t !== undefined && t ? t.split(":") : [];
    const groups = t === undefined ? hs : hs.concat(Array(Math.max(0, 8 - hs.length - ts.length)).fill("0"), ts);
    return [6, groups.map(g => g.padStart(4, "0")).join(":")];
  }
  return [9, s];
}
function compareValues(f, x, y) {
  const kind = f ? f.kind : "text";
  if (kind === "int" || kind === "port" || kind === "auto_ms") return Number(x) - Number(y);
  if (kind === "bool") return (x === true) - (y === true);
  if (kind === "ip") { const a = ipKey(x), b = ipKey(y); return a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0); }
  return String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: "base" });
}
const isEmptyVal = v => v === undefined || v === null || (typeof v === "string" && v.trim() === "");

function sortedFiltered(sec) {
  const st = S.sort[sec.key];
  let recs = S.records;               // the server returns the section's default order
  const q = S.filter.trim().toLowerCase();
  if (q) {
    recs = recs.filter(r => sec.fields.some(f => display(f, r.data[f.name]).toLowerCase().includes(q)));
  }
  if (st) {
    const f = sec.fields.find(x => x.name === st.field);
    recs = recs.map((r, i) => [r, i]).sort(([a, i], [b, j]) => {
      const x = a.data[st.field], y = b.data[st.field], ex = isEmptyVal(x), ey = isEmptyVal(y);
      if (ex || ey) return ex === ey ? i - j : ex ? 1 : -1;          // empty values always last
      return compareValues(f, x, y) * st.dir || i - j;               // ties keep the default order
    }).map(([r]) => r);
  }
  return recs;
}

/**
 * Fluid grid columns. Every column has a preferred width (from Aurora's column definition) and a smaller minimum
 * that still shows its typical content (a full UTC timestamp, a verdict, ...). The width actually available is
 * shared out: first everyone gets the minimum, then the rest goes to columns in proportion to how far they are
 * from their preferred width, and any surplus beyond that in proportion to the preferred width. Only when the
 * window is narrower than the sum of minimums does the table scroll sideways (the actions column stays pinned).
 */
const KIND_PREF = { datetime: 165, auto_ms: 140, date: 105, bool: 70, readonly: 100, hash: 170, ip: 125, port: 65,
  int: 75, enum: 105, ref: 160, email: 170, url: 220, text: 130, longtext: 260 };
const KIND_MIN = { datetime: 160, auto_ms: 134, date: 96, bool: 64, readonly: 96, hash: 80, ip: 108, port: 52,
  int: 56, enum: 76, ref: 90, email: 100, url: 110, text: 70, longtext: 120 };
const ACT_COL = 46;
function colPref(f) {
  const w = f.width || "";
  const base = w.endsWith("px") ? parseInt(w, 10) : w.endsWith("%") ? parseFloat(w) * 9 : 0;
  return Math.max(base, KIND_PREF[f.kind] || 120, colMin(f));
}
function colMin(f) { return KIND_MIN[f.kind] || 70; }

function fitColumns(wrap, colEls, prefs, mins, extra) {
  const avail = Math.max(0, wrap.clientWidth - extra - 2);     // 2px: collapsed table borders
  const sumMin = mins.reduce((a, b) => a + b, 0);
  const sumPref = prefs.reduce((a, b) => a + b, 0);
  let widths;
  if (avail <= sumMin) widths = mins.slice();
  else if (avail <= sumPref) {
    const k = (avail - sumMin) / (sumPref - sumMin || 1);
    widths = mins.map((m, i) => m + (prefs[i] - m) * k);
  } else widths = prefs.map(p => p * avail / sumPref);
  widths = widths.map(Math.floor);
  widths.forEach((w, i) => { colEls[i].style.width = w + "px"; });
  return widths.reduce((a, b) => a + b, 0) + extra;
}

function drawTable(flash) {
  const sec = S.sections[S.view];
  const wrap = document.getElementById("tablewrap");
  if (!wrap || !sec) return;
  const cols = sec.fields.filter(f => f.in_table);
  const st = S.sort[sec.key];
  const defOrder = sec.default_order || [];
  const defText = defOrder.map(o => `${fieldLabel(sec.fields.find(x => x.name === o.field) || { label: o.field })} ${o.order === "desc" ? "↓" : "↑"}`).join(", ");
  const head = el("tr", null, cols.map(f => {
    const th = el("th", { text: fieldLabel(f), title: `Sort by ${fieldLabel(f)} (click again to reverse, a third time for the default order: ${defText || "as stored"})`, onclick: () => {
      const cur = S.sort[sec.key];
      S.sort[sec.key] = cur && cur.field === f.name ? (cur.dir === 1 ? { field: f.name, dir: -1 } : null) : { field: f.name, dir: 1 };
      drawTable();
    } });
    if (st && st.field === f.name) th.classList.add("sorted", ...(st.dir < 0 ? ["desc"] : []));
    const d = defOrder.findIndex(o => o.field === f.name);
    if (!st && d >= 0) th.classList.add("sorted", "default", ...(defOrder[d].order === "desc" ? ["desc"] : []));
    return th;
  }));
  const withMenu = canEdit();
  if (withMenu) head.append(el("th", { class: "act", title: "Row actions" }));
  const recs = sortedFiltered(sec);
  const body = el("tbody");
  for (const r of recs) {
    const tr = el("tr", { onclick: () => openRecordModal(sec, r) });
    if (flash && flash.has(r.recid)) tr.classList.add("flash");
    for (const f of cols) {
      const txt = display(f, r.data[f.name]);
      const td = el("td", { text: txt, title: txt.length > 12 ? txt : "" });
      if (f.kind === "bool") td.className = "bool";
      if (f.kind === "hash" || f.kind === "ip") td.classList.add("mono");
      if (f.name === "vt" && sec.key === "malware" && txt) td.classList.add("vt", "vt-" + txt);
      tr.append(td);
    }
    if (withMenu) {
      tr.addEventListener("contextmenu", ev => { ev.preventDefault(); openRowMenu(sec, r, ev.clientX, ev.clientY); });
      const btn = el("button", { class: "btn small rowmenu", type: "button", text: "⋯", title: "Actions (or right-click the row)",
        "aria-label": `Actions for record #${r.recid}`, onclick: ev => {
          ev.stopPropagation();
          const b = ev.currentTarget.getBoundingClientRect();
          openRowMenu(sec, r, b.right, b.bottom);
        } });
      tr.append(el("td", { class: "act" }, btn));
    }
    body.append(tr);
  }
  const prefs = cols.map(colPref), mins = cols.map(colMin);
  const colEls = cols.map(() => el("col"));
  const colgroup = el("colgroup", null, colEls, withMenu ? el("col", { style: `width:${ACT_COL}px` }) : null);
  const table = el("table", { class: "grid" }, colgroup, el("thead", null, head), body);
  const extra = withMenu ? ACT_COL : 0;
  const fit = () => { table.style.width = fitColumns(wrap, colEls, prefs, mins, extra) + "px"; };
  wrap.replaceChildren(recs.length ? table : el("div", { class: "empty", text: S.records.length ? "No records match the filter." : "No records yet." }));
  if (S.gridObserver) S.gridObserver.disconnect();
  if (recs.length) {
    fit();
    S.gridObserver = new ResizeObserver(() => fit());       // window resize, sidebar change, zoom
    S.gridObserver.observe(wrap);
  }
  const rc = document.getElementById("rowcount");
  if (rc) rc.textContent = recs.length === S.records.length ? `${S.records.length} records` : `${recs.length} of ${S.records.length} records`;
}

/* ------------------------------------------------------------------ record editor */

function closeModal() {
  if (S.modal) { S.modal.root.remove(); S.modal = null; }
  document.removeEventListener("keydown", modalKeys);
}
function modalKeys(ev) { if (ev.key === "Escape") closeModal(); }

function openModal(root) {
  closeModal();
  document.body.append(root);
  document.addEventListener("keydown", modalKeys);
}

function buildInput(f, value, ro) {
  const id = "f_" + f.name;
  let input;
  if (f.kind === "multiline") {             // free text that may span lines (never a record field)
    input = el("textarea", { id, value: value ?? "", maxLength: f.max_len, disabled: ro, rows: 8, class: "multiline" });
  } else if (f.kind === "longtext") {
    input = singleLineArea(el("textarea", { id, value: value ?? "", maxLength: f.max_len, disabled: ro, rows: 4 }));
  } else if (f.kind === "bool") {
    input = el("input", { id, type: "checkbox", checked: value === true, disabled: ro });
  } else if (f.kind === "enum") {
    input = el("select", { id, disabled: ro });
    const opts = [""].concat(S.options.lookups[f.enum] || []);
    if (value && !opts.includes(value)) opts.push(value);
    for (const o of opts) input.append(el("option", { value: o, text: o || "—", selected: o === (value ?? "") }));
  } else {
    const ph = { datetime: "YYYY-MM-DD HH:MM:SS (UTC)", date: "YYYY-MM-DD", ip: "e.g. 10.0.0.1", port: "0-65535", hash: "MD5 / SHA1 / SHA256 hex", url: "https://…", email: "name@example.org" }[f.kind] || "";
    input = el("input", { id, type: "text", value: value ?? "", placeholder: ph, disabled: ro,
      title: f.kind === "datetime" ? "UTC. A value with an offset (e.g. 2020-02-21T15:20:37+01:00) is converted to UTC on save." : "", maxLength: f.kind === "text" ? f.max_len : 4096, autocomplete: "off", spellcheck: f.kind === "text" });
    if (f.kind === "ref") {
      const listId = "dl_" + f.name;
      input.setAttribute("list", listId);
      const dl = el("datalist", { id: listId });
      for (const v of S.options.refs[f.ref] || []) dl.append(el("option", { value: v }));
      input._datalist = dl;
    }
  }
  return input;
}

/** A wrapping text area that never holds line breaks (all values must stay single-line for the Aurora desktop
 *  app): Enter is ignored and pasted / dropped line breaks are joined with a space. */
const LINE_BREAKS = /[ \t]*(?:\r\n|[\r\n\u2028\u2029])+[ \t]*/g;
function joinLines(v) { return String(v ?? "").replace(LINE_BREAKS, " "); }
function singleLineArea(ta) {
  ta.value = joinLines(ta.value);
  ta.addEventListener("keydown", ev => { if (ev.key === "Enter") ev.preventDefault(); });
  ta.addEventListener("input", () => {
    if (!/[\r\n\u2028\u2029]/.test(ta.value)) return;
    const pos = ta.selectionStart, before = joinLines(ta.value.slice(0, pos));
    ta.value = joinLines(ta.value);
    ta.setSelectionRange(before.length, before.length);
  });
  ta.title = "Single line: line breaks are not allowed";
  return ta;
}

function readInput(f, input) {
  if (f.kind === "bool") return input.checked;
  return f.kind === "longtext" ? joinLines(input.value) : input.value;
}

/** Open the create/edit dialog. `prefill` is used by "Duplicate". */
function openRecordModal(sec, rec, prefill) {
  const ro = !canEdit();
  const isNew = !rec;
  let base = {};               // values the user's edits are based on (sent as `expected`)
  let version = rec ? rec.version : null;
  let updatedBy = rec ? rec.updated_by : "";
  const inputs = {};
  const fieldBoxes = {};
  const bannerBox = el("div", { class: "wide" });
  const body = el("div", { class: "body" }, bannerBox);

  // New records default to the signed-in user's investigator (analyst, provider, task/note owner), except the
  // owner of a timeline event, which the analyst always picks.
  const defaults = {};
  if (isNew && sec.key !== "timeline") {
    for (const f of sec.fields) {
      if (f.kind === "ref" && f.ref === "investigators" && S.me.investigator && (S.options.refs.investigators || []).includes(S.me.investigator)) defaults[f.name] = S.me.investigator;
    }
  }
  const values = isNew ? Object.assign({}, defaults, prefill || {}) : rec.data;

  for (const f of sec.fields) {
    const wide = f.kind === "longtext";
    const lbl = el("label", { class: "lbl", htmlFor: "f_" + f.name }, fieldLabel(f), f.required && f.editable ? el("span", { class: "req", text: " *" }) : null);
    let ctrl;
    if (!f.editable) {
      if (isNew) continue;
      ctrl = el("div", { class: "ro", text: display(f, values[f.name]) || "—" });
    } else {
      const v = values[f.name] ?? (f.kind === "bool" ? false : "");
      base[f.name] = isNew ? (f.kind === "bool" ? false : "") : v;
      const input = buildInput(f, v, ro);
      inputs[f.name] = input;
      const row = el("div", { class: "row" }, input, input._datalist || null);
      if (f.kind === "datetime" && !ro) row.append(el("button", { class: "btn small", type: "button", text: "now", title: "Current UTC time", onclick: () => { input.value = nowUtc(); } }));
      if (f.kind === "date" && !ro) row.append(el("button", { class: "btn small", type: "button", text: "today", onclick: () => { input.value = nowUtc().slice(0, 10); } }));
      ctrl = f.kind === "bool" ? el("label", { class: "check" }, input, "Yes") : row;
    }
    const box = el("div", { class: "fld" + (wide ? " wide" : "") }, lbl, ctrl);
    fieldBoxes[f.name] = box;
    body.append(box);
  }

  const title = el("h3", { text: (isNew ? "New " : ro ? "View " : "Edit ") + sec.label.replace(/s$/, "") + (rec ? ` #${rec.recid}` : "") });
  const metaLine = el("div", { class: "meta", text: rec ? `version ${rec.version} · last change by ${rec.updated_by || "?"} ${fmtTs(rec.updated_at)} UTC` : "" });
  const saveBtn = el("button", { class: "btn primary", text: isNew ? "Create" : "Save", onclick: () => save() });
  const footer = el("footer", null,
    !ro && !isNew ? el("button", { class: "btn danger", text: "Delete", onclick: () => del() }) : null,
    !ro && !isNew ? el("button", { class: "btn", text: "Duplicate", onclick: () => duplicate() }) : null,
    !ro && !isNew ? rowActions(sec, rec).map(a => el("button", { class: "btn" + (a.reason ? " unavailable" : ""), type: "button", text: a.label,
      "aria-disabled": a.reason ? "true" : null, title: a.reason || a.hint, onclick: () => {
        if (a.reason) return toast(a.reason, true);
        if (isDirty()) return toast("Save or cancel your changes first: actions use the saved record.", true);
        closeModal();
        a.run();
      } })) : null,
    el("div", { class: "spacer" }),
    el("button", { class: "btn", text: ro ? "Close" : "Cancel", onclick: closeModal }),
    ro ? null : saveBtn);
  const modal = el("div", { class: "modal", role: "dialog", "aria-modal": "true" }, el("header", null, el("div", null, title, metaLine), el("button", { class: "btn small", text: "✕", onclick: closeModal })), body, footer);
  const back = el("div", { class: "modal-back", onmousedown: ev => { if (ev.target === back && ro) closeModal(); } }, modal);
  openModal(back);
  S.modal = { root: back, onRemoteChange };
  const first = Object.values(inputs)[0];
  if (first && !ro) first.focus();

  function clearErrors() {
    for (const b of Object.values(fieldBoxes)) {
      b.classList.remove("has-err");
      b.querySelectorAll(".err, .theirs").forEach(n => n.remove());
    }
    bannerBox.replaceChildren();
  }

  function showFieldError(name, msg) {
    const b = fieldBoxes[name];
    if (b) { b.classList.add("has-err"); b.append(el("div", { class: "err", text: msg })); }
  }

  function collect() {
    const out = {};
    for (const f of sec.fields) if (inputs[f.name]) out[f.name] = readInput(f, inputs[f.name]);
    return out;
  }

  function isDirty() {
    const cur = collect();
    return sec.fields.some(f => inputs[f.name] && !same(f, cur[f.name], base[f.name]));
  }

  async function onRemoteChange() {
    if (isNew) {
      // refresh datalists / selects for references created by others
      for (const f of sec.fields) {
        const inp = inputs[f.name];
        if (inp && inp._datalist) inp._datalist.replaceChildren(...(S.options.refs[f.ref] || []).map(v => el("option", { value: v })));
      }
      return;
    }
    const fresh = S.records.find(r => r.recid === rec.recid);
    if (!S.sections[S.view] || S.view !== sec.key) return;
    if (!fresh) {
      bannerBox.replaceChildren(el("div", { class: "banner err", text: "This record was deleted by another user." }));
      saveBtn.disabled = true;
      return;
    }
    if (fresh.version !== version) {
      const mine = collect();
      const touched = sec.fields.filter(f => inputs[f.name] && !same(f, mine[f.name], base[f.name]));
      const clash = touched.filter(f => !same(f, fresh.data[f.name], base[f.name]) && !same(f, fresh.data[f.name], mine[f.name]));
      // silently take over remote changes in fields the user has not touched
      for (const f of sec.fields) {
        const inp = inputs[f.name];
        if (!inp || touched.includes(f)) continue;
        const v = fresh.data[f.name] ?? (f.kind === "bool" ? false : "");
        if (f.kind === "bool") inp.checked = v === true; else inp.value = v;
        base[f.name] = v;
      }
      version = fresh.version; updatedBy = fresh.updated_by;
      metaLine.textContent = `version ${fresh.version} · last change by ${fresh.updated_by || "?"} ${fmtTs(fresh.updated_at)} UTC`;
      rec = fresh;
      bannerBox.replaceChildren(el("div", { class: "banner warn", text: clash.length
        ? `${fresh.updated_by} changed this record, including fields you are editing (${clash.map(f => f.label).join(", ")}). Saving will ask you to resolve them.`
        : `${fresh.updated_by} updated this record; their changes have been merged into this form.` }));
    }
  }

  async function save() {
    clearErrors();
    const cur = collect();
    saveBtn.disabled = true;
    try {
      if (isNew) {
        const r = await api("POST", `/api/cases/${S.caseId}/sections/${sec.key}`, { data: cur });
        toast(`${sec.label}: record #${r.recid} created`);
      } else {
        const changes = {}, expected = {};
        for (const f of sec.fields) {
          if (!inputs[f.name]) continue;
          if (!same(f, cur[f.name], base[f.name])) { changes[f.name] = cur[f.name]; expected[f.name] = base[f.name]; }
        }
        if (!Object.keys(changes).length) { closeModal(); return; }
        await api("PATCH", `/api/cases/${S.caseId}/sections/${sec.key}/${rec.recid}`, { changes, expected });
        toast(`${sec.label}: record #${rec.recid} saved`);
      }
      closeModal();
      await afterWrite();
    } catch (e) {
      saveBtn.disabled = false;
      handleWriteError(e);
    }
  }

  function handleWriteError(e) {
    if (e.status === 422 && e.body.errors) {
      for (const er of e.body.errors) showFieldError(er.field, er.message);
      const missing = e.body.missing_refs || [];
      if (missing.length && canEdit()) {
        const box = el("div", { class: "banner warn" }, "Referenced entries must be declared first:");
        for (const m of missing) {
          const tsec = S.sections[m.section];
          box.append(el("button", { class: "btn small", text: `Declare "${m.value}" in ${tsec.label}`, onclick: async () => {
            try {
              await api("POST", `/api/cases/${S.caseId}/sections/${m.section}`, { data: { [tsec.key_field]: m.value } });
              toast(`"${m.value}" added to ${tsec.label} - complete its details there later`);
              S.options = await api("GET", `/api/cases/${S.caseId}/options`);
              await save();
            } catch (e2) { toast(e2.message, true); }
          } }));
        }
        bannerBox.replaceChildren(box);
      } else if (!e.body.errors.some(er => fieldBoxes[er.field])) {
        bannerBox.replaceChildren(el("div", { class: "banner err", text: e.body.errors.map(er => `${er.field}: ${er.message}`).join("; ") }));
      }
    } else if (e.status === 409 && e.body.conflicts) {
      const current = e.body.current;
      bannerBox.replaceChildren(el("div", { class: "banner warn", text: `${current.updated_by || "Someone"} changed the same field(s) while you were editing. Review the highlighted values: keep yours and Save again, or take theirs.` }));
      for (const c of e.body.conflicts) {
        const f = sec.fields.find(x => x.name === c.field);
        base[c.field] = c.current;   // re-base: saving again now deliberately overrides theirs
        const b = fieldBoxes[c.field];
        if (!b) continue;
        b.classList.add("has-err");
        b.append(el("div", { class: "theirs" }, `Their value: ${display(f, c.current) || "(empty)"}  `,
          el("button", { class: "btn small", type: "button", text: "Use theirs", onclick: () => {
            const inp = inputs[c.field];
            if (f.kind === "bool") inp.checked = c.current === true; else inp.value = c.current ?? "";
          } })));
      }
      version = current.version;
      rec = current;
      metaLine.textContent = `version ${current.version} · last change by ${current.updated_by || "?"} ${fmtTs(current.updated_at)} UTC`;
    } else if (e.status === 404) {
      bannerBox.replaceChildren(el("div", { class: "banner err", text: e.message }));
    } else {
      bannerBox.replaceChildren(el("div", { class: "banner err", text: e.message }));
    }
  }

  async function del() {
    if (!confirm(`Delete ${sec.label} record #${rec.recid}? This cannot be undone (it remains in the activity log).`)) return;
    clearErrors();
    try {
      await api("POST", `/api/cases/${S.caseId}/sections/${sec.key}/${rec.recid}/delete`, { version });
      toast(`${sec.label}: record #${rec.recid} deleted`);
      closeModal();
      await afterWrite();
    } catch (e) {
      if (e.status === 409 && e.body.references) {
        const list = el("ul");
        for (const r of e.body.references) list.append(el("li", { text: `${S.sections[r.section].label} #${r.recid} (${r.field})` }));
        bannerBox.replaceChildren(el("div", { class: "banner err" }, e.message, list));
      } else if (e.status === 409) {
        bannerBox.replaceChildren(el("div", { class: "banner err", text: e.message }));
        version = e.body.current ? e.body.current.version : version;
      } else bannerBox.replaceChildren(el("div", { class: "banner err", text: e.message }));
    }
  }

  function duplicate() {
    openRecordModal(sec, null, duplicateValues(sec, collect()));
  }
}

/** Values for a "Duplicate Line": every editable field; unique names (systems, investigators) are cleared. */
function duplicateValues(sec, data) {
  const vals = {};
  for (const f of sec.fields) if (f.editable && data[f.name] !== undefined) vals[f.name] = data[f.name];
  if (sec.unique_key || sec.key === "systems" || sec.key === "investigators") vals[sec.key_field] = "";
  return vals;
}

/* ------------------------------------------------------------------ row actions (as in Aurora) */

const ROW_ACTIONS = {
  investigated_systems: ["to_timeline"],
  malware: ["to_investigated_systems", "to_timeline", "send_to_misp", "check_virustotal"],
  network_indicators: ["send_to_misp"],
  exfiltration: ["to_timeline"],
};
const HASH_RE = /^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/;

/** Actions for a record, with the reason when one is not possible (shown as tooltip, button disabled). */
function rowActions(sec, rec) {
  const integ = (S.caseInfo && S.caseInfo.integrations) || { enabled: false, misp: {}, virustotal: {} };
  const d = rec.data;
  const path = `/api/cases/${S.caseId}/sections/${sec.key}/${rec.recid}`;
  const out = [];
  for (const action of ROW_ACTIONS[sec.key] || []) {
    if (action === "to_timeline") out.push({ label: "To Timeline", hint: "Add a timeline event (Followup ticked) from this record",
      reason: "", run: () => recordAction(`${path}/to-timeline`, r => `Added to Timeline as event #${r.recid}`) });
    if (action === "to_investigated_systems") out.push({ label: "To hosts", hint: "Add this host to Investigated Systems (verdict Infected)",
      reason: d.hostname ? "" : "Set the Host of this malware first",
      run: () => recordAction(`${path}/to-investigated-systems`, r => `${r.data.hostname} added to Investigated Systems (#${r.recid})`) });
    if (action === "send_to_misp") {
      const hasValue = sec.key === "malware" ? !!d.text : !!(d.ip || d.domainname);
      out.push({ label: "Send to MISP", hint: `Send indicators to MISP event ${integ.misp.event_id || ""}`.trim(),
        reason: !integ.enabled ? "Integrations are disabled on this server"
          : !integ.misp.configured ? (integ.misp.note || `Configure ${(integ.misp.missing || []).join(", ")} first`)
          : !hasValue ? "This record has no value that can be sent to MISP" : "",
        run: () => openMispModal(sec, rec) });
    }
    if (action === "check_virustotal") out.push({ label: "Check VT", hint: "Look up the hash on VirusTotal and fill the vt column",
      reason: !integ.enabled ? "Integrations are disabled on this server"
        : !integ.virustotal.configured ? (integ.virustotal.note || "Add a VirusTotal API key in Case Details first")
        : !d.md5 ? "Enter the file hash first"
        : !HASH_RE.test(d.md5) ? "The hash must be an MD5, SHA-1 or SHA-256" : "",
      run: () => checkVirusTotal(sec, rec) });
  }
  return out;
}

function closeRowMenu() {
  const m = document.getElementById("rowmenu");
  if (m) m.remove();
  document.removeEventListener("mousedown", rowMenuOutside, true);
  document.removeEventListener("keydown", rowMenuKeys, true);
  window.removeEventListener("resize", closeRowMenu);
}
function rowMenuOutside(ev) { if (!ev.target.closest("#rowmenu")) closeRowMenu(); }
function rowMenuKeys(ev) { if (ev.key === "Escape") { ev.stopPropagation(); closeRowMenu(); } }

/** Context menu of a row: Duplicate Line plus the section's actions (Aurora's right-click menu). */
function openRowMenu(sec, rec, x, y) {
  closeRowMenu();
  const items = [{ label: "Duplicate Line", hint: "Open a new record pre-filled with this one", reason: "",
    run: () => openRecordModal(sec, null, duplicateValues(sec, rec.data)) }].concat(rowActions(sec, rec));
  const menu = el("div", { id: "rowmenu", class: "ctxmenu", role: "menu" },
    el("div", { class: "ctxtitle", text: `${sec.label} #${rec.recid}` }),
    items.map(a => el("button", { type: "button", role: "menuitem", disabled: !!a.reason, title: a.reason || a.hint,
      onclick: () => { closeRowMenu(); a.run(); } }, a.label, a.reason ? el("small", { text: a.reason }) : null)));
  document.body.append(menu);
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.max(4, Math.min(x, window.innerWidth - r.width - 4)) + "px";
  menu.style.top = Math.max(4, Math.min(y, window.innerHeight - r.height - 4)) + "px";
  const first = menu.querySelector("button:not([disabled])");
  if (first) first.focus();
  document.addEventListener("mousedown", rowMenuOutside, true);
  document.addEventListener("keydown", rowMenuKeys, true);
  window.addEventListener("resize", closeRowMenu);
}

async function recordAction(path, message) {
  try {
    const r = await api("POST", path);
    toast(message(r));
    await afterWrite();
  } catch (e) { toast(e.message, true); }
}

async function checkVirusTotal(sec, rec) {
  toast(`Checking ${rec.data.md5} on VirusTotal…`);
  try {
    const r = await api("POST", `/api/cases/${S.caseId}/sections/${sec.key}/${rec.recid}/check-virustotal`);
    const label = { infected: "INFECTED", clean: "clean", noresult: "no result" }[r.verdict] || r.verdict;
    toast(`VirusTotal: ${label} (${r.details.message})`, r.verdict === "infected");
    await afterWrite();
  } catch (e) { toast(e.message, true); }
}

/** Aurora's "Add to MISP" popup: choose attributes, adjust type and comment, then send (server-side). */
async function openMispModal(sec, rec) {
  let info;
  try { info = await api("GET", `/api/cases/${S.caseId}/sections/${sec.key}/${rec.recid}/misp-attributes`); }
  catch (e) { return toast(e.message, true); }
  const rows = info.attributes.map(a => {
    const check = el("input", { type: "checkbox", checked: true, "aria-label": `Send ${a.aurora_field}` });
    const type = el("select", { class: "misp-type", "aria-label": "MISP type" }, info.misp_types.map(t => el("option", { value: t, text: t, selected: t === a.type })));
    const comment = el("input", { type: "text", value: a.comment, maxLength: 1500, autocomplete: "off", "aria-label": "Comment" });
    return { a, check, type, comment, tr: el("tr", null, el("td", null, check), el("td", { text: a.aurora_field }), el("td", null, type),
      el("td", { class: "mono wrap", text: a.value }), el("td", null, comment)) };
  });
  const msg = el("div");
  const send = el("button", { class: "btn primary", text: "Send to MISP", onclick: async () => {
    const attributes = rows.filter(r => r.check.checked).map(r => ({ type: r.type.value, value: r.a.value, comment: r.comment.value }));
    if (!attributes.length) return msg.replaceChildren(el("div", { class: "banner err", text: "You need to select at least one indicator." }));
    send.disabled = true;
    try {
      const r = await api("POST", `/api/cases/${S.caseId}/sections/${sec.key}/${rec.recid}/send-to-misp`, { attributes });
      closeModal();
      toast(r.message, !r.ok);
    } catch (e) {
      send.disabled = false;
      msg.replaceChildren(el("div", { class: "banner err", text: e.message }));
    }
  } });
  const modal = el("div", { class: "modal", role: "dialog", "aria-modal": "true" },
    el("header", null, el("div", null, el("h3", { text: "Add to MISP" }),
      el("div", { class: "meta", text: `${sec.label} #${rec.recid} → ${info.misp.server} · event ${info.misp.event_id}` })),
      el("button", { class: "btn small", text: "✕", onclick: closeModal })),
    el("div", { class: "body one" }, msg,
      el("p", { class: "muted", text: "The selected values are sent by the server to the MISP event configured in Case Details. The MISP API key never reaches your browser." }),
      el("div", { class: "table-wrap" }, el("table", { class: "plain" },
        el("thead", null, el("tr", null, ["", "Aurora field", "MISP type", "Value", "Comment"].map(h => el("th", { text: h })))),
        el("tbody", null, rows.map(r => r.tr))))),
    el("footer", null, el("div", { class: "spacer" }), el("button", { class: "btn", text: "Cancel", onclick: closeModal }), send));
  const back = el("div", { class: "modal-back" }, modal);
  openModal(back);
  S.modal = { root: back };
}

async function afterWrite() {
  S.caseInfo = await api("GET", `/api/cases/${S.caseId}`);   // also refreshes every menu count
  S.revision = S.caseInfo.revision;
  S.counts = Object.assign({}, S.caseInfo.counts);
  renderSidebar();
  S.options = await api("GET", `/api/cases/${S.caseId}/options`);
  if (S.sections[S.view]) await refreshSection(false);
}

/* ------------------------------------------------------------------ export */

const EXPORT_KINDS = { "export": ".fox file", "export.xlsx": "Excel workbook", "export.pdf": "PDF report",
                       "export.tex": "LaTeX report" };
let exportBusy = false;

// Blocking "generating" window: shown when an export takes longer than a moment, so a slow PDF or Excel is not
// clicked again. Escape does not close it (the export keeps running); Cancel aborts the download.
function exportWaitWindow(what, caseLabel, controller) {
  const secs = el("span", { text: "0 s" });
  const box = el("div", { class: "busy-back", role: "alertdialog", "aria-modal": "true", "aria-live": "polite" },
    el("div", { class: "busy" },
      el("div", { class: "spinner", "aria-hidden": "true" }),
      el("h3", { text: `Generating the ${what}…` }),
      el("p", { class: "muted", text: `Case ${caseLabel}. Large cases can take a while; the download starts by itself.` }),
      el("p", { class: "muted" }, "Elapsed: ", secs),
      el("button", { class: "btn", text: "Cancel", onclick: () => controller.abort() })));
  const started = Date.now();
  const tick = setInterval(() => { secs.textContent = `${Math.round((Date.now() - started) / 1000)} s`; }, 1000);
  let shown = false;
  const timer = setTimeout(() => { document.body.append(box); shown = true; box.querySelector("button").focus(); }, 250);
  return () => { clearTimeout(timer); clearInterval(tick); if (shown) box.remove(); };
}

async function exportFox(endpoint, fallbackName) {
  if (!S.caseId || exportBusy) return;          // one export at a time: repeated clicks are ignored
  exportBusy = true;
  const controller = new AbortController();
  const c = S.cases.find(x => x.id === S.caseId);
  const close = exportWaitWindow(EXPORT_KINDS[endpoint] || "export", c ? c.case_id : `#${S.caseId}`, controller);
  try {
    const res = await fetch(`/api/cases/${S.caseId}/${endpoint}`, { credentials: "same-origin", signal: controller.signal });
    if (!res.ok) {
      const b = await res.json().catch(() => ({}));
      throw new Error(b.detail || `Export failed (HTTP ${res.status})`);
    }
    const blob = await res.blob();
    const cd = res.headers.get("content-disposition") || "";
    const m = cd.match(/filename="([^"]+)"/);
    const a = el("a", { href: URL.createObjectURL(blob), download: m ? m[1] : fallbackName });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    toast(`Exported revision ${res.headers.get("x-case-revision") || ""}`);
  } catch (e) {
    toast(e.name === "AbortError" ? "Export cancelled" : e.message, e.name !== "AbortError");
  } finally {
    close();
    exportBusy = false;
  }
}

async function downloadSectionCsv(sec) {
  if (!S.caseId) return;
  try {
    const res = await fetch(`/api/cases/${S.caseId}/sections/${sec.key}/export.csv`, { credentials: "same-origin" });
    if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.detail || `Export failed (HTTP ${res.status})`); }
    const blob = await res.blob();
    const cd = res.headers.get("content-disposition") || "";
    const m = cd.match(/filename="([^"]+)"/);
    const a = el("a", { href: URL.createObjectURL(blob), download: m ? m[1] : `${sec.key}.csv` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    toast(`Exported ${sec.label} as CSV`);
  } catch (e) { toast(e.message, true); }
}

async function importSectionCsv(sec) {
  if (!S.caseId) return;
  const file = await pickFile(".csv");
  if (!file) return;
  const text = await file.text();
  try {
    const r = await api("POST", `/api/cases/${S.caseId}/sections/${sec.key}/import.csv`, undefined, text);
    toast(`Imported ${r.created} record${r.created === 1 ? "" : "s"} into ${sec.label}`);
    if (S.view === sec.key) await renderSection();
  } catch (e) {
    // Surface the first validation problem clearly (nothing was written - the import is all-or-nothing).
    const d = (e.body && e.body.errors && e.body.errors[0]) ? `${e.body.errors[0].field}: ${e.body.errors[0].message}` : e.message;
    toast(`CSV import rejected — ${d}`, true);
  }
}

/* ------------------------------------------------------------------ case details */

function renderCaseDetails(fromPoll) {
  const meta = S.caseInfo.meta;
  const ro = !canEdit();
  const base = Object.assign({}, meta);
  const secretsSet = meta.secrets_set || {};
  const secretFields = S.schema.secret_case_fields;
  const inputs = {};
  const removeKey = {};          // secret field -> true when the stored key should be deleted on save
  const errBox = el("div");
  const grid = el("div", { class: "form-grid" });
  const boxes = {};                // field name -> its form box (to grey out fields a switch controls)
  for (const f of S.schema.case_fields) {
    const secret = secretFields.includes(f.name);
    if (secret) { grid.append(boxes[f.name] = secretField(f)); continue; }
    const input = buildInput(f, meta[f.name], ro);
    inputs[f.name] = input;
    // URL/ID fields must not look like a username either: no autofill hints at all
    const wide = f.kind === "longtext" || f.kind === "multiline";
    if (!wide) { input.autocomplete = "off"; input.setAttribute("data-lpignore", "true"); input.setAttribute("data-1p-ignore", "true"); }
    grid.append(boxes[f.name] = el("div", { class: "fld" + (wide ? " wide" : "") },
      el("label", { class: "lbl", htmlFor: "f_" + f.name, text: f.label }), input,
      CASE_FIELD_HINTS[f.name] ? el("div", { class: "hint", text: CASE_FIELD_HINTS[f.name] }) : null));
  }

  // "Use the server-wide ..." switches: while on, the case's own values are kept but unused, and not editable.
  const SWITCHED = { use_server_misp: ["mispserver", "mispapikey"], use_server_vt: ["vtapikey"] };
  const locked = name => Object.entries(SWITCHED).some(([sw, names]) => names.includes(name) && inputs[sw] && inputs[sw].checked);
  function applyLocks() {
    for (const names of Object.values(SWITCHED)) for (const name of names) {
      const box = boxes[name], on = locked(name);
      if (!box || ro) continue;
      box.classList.toggle("locked", on);
      for (const c of box.querySelectorAll("input, button")) c.disabled = on || (c === inputs[name] && !!removeKey[name]);
    }
  }
  for (const sw of Object.keys(SWITCHED)) if (inputs[sw]) inputs[sw].addEventListener("change", applyLocks);

  /** API keys are write-only: the stored value is never sent to the browser, only whether one exists. */
  function secretField(f) {
    const stored = !!secretsSet[f.name];
    const state = el("span", { class: "pill " + (stored ? "ok" : ""), text: stored ? "stored" : "not set" });
    const box = el("div", { class: "fld" }, el("label", { class: "lbl", htmlFor: "f_" + f.name }, f.label, " ", state));
    if (ro) { box.append(el("div", { class: "ro", text: stored ? "•••••••• (hidden)" : "—" })); return box; }
    const input = buildInput(f, "", false);
    input.placeholder = stored ? "Hidden · type to replace" : "Paste the API key";
    inputs[f.name] = input;
    const row = maskSecret(input);
    if (stored) {
      const rm = el("button", { class: "btn small", type: "button", text: "Remove", title: "Delete the stored key when you save", onclick: () => {
        removeKey[f.name] = !removeKey[f.name];
        rm.textContent = removeKey[f.name] ? "Keep" : "Remove";
        state.textContent = removeKey[f.name] ? "will be removed on save" : "stored";
        state.classList.toggle("warn", !!removeKey[f.name]);
        input.disabled = !!removeKey[f.name];
        if (removeKey[f.name]) input.value = "";
      } });
      row.append(rm);
    }
    box.append(row, el("div", { class: "hint", text: (CASE_FIELD_HINTS[f.name] ? CASE_FIELD_HINTS[f.name] + " " : "") +
      "Stored encrypted; never shown again and never included in the .fox, Excel, PDF or LaTeX exports." }));
    return box;
  }

  function collectChanges() {
    const changes = {}, expected = {};
    for (const f of S.schema.case_fields) {
      if (!inputs[f.name] && !removeKey[f.name]) continue;
      if (locked(f.name)) continue;               // kept as stored while the server-wide switch is on
      if (secretFields.includes(f.name)) {
        if (removeKey[f.name]) changes[f.name] = "";
        else if (inputs[f.name].value.trim()) changes[f.name] = inputs[f.name].value.trim();
        continue;                                   // write-only: no base value to compare with
      }
      const v = inputs[f.name].type === "checkbox" ? inputs[f.name].checked : inputs[f.name].value;
      if (!same(f, v, base[f.name])) { changes[f.name] = v; expected[f.name] = base[f.name]; }
    }
    return { changes, expected };
  }

  const save = el("button", { class: "btn primary", text: "Save case details", onclick: async () => {
    errBox.replaceChildren();
    const { changes, expected } = collectChanges();
    if (!Object.keys(changes).length) return toast("Nothing changed");
    try {
      await api("PATCH", `/api/cases/${S.caseId}`, { changes, expected });
      toast("Case details saved");
      S.caseInfo = await api("GET", `/api/cases/${S.caseId}`);
      S.revision = S.caseInfo.revision;
      S.cases = await api("GET", "/api/cases");
      renderShell(); renderCaseDetails();
    } catch (e) {
      if (e.status === 409 && e.body.conflicts) {
        for (const c of e.body.conflicts) base[c.field] = c.current;
        errBox.replaceChildren(el("div", { class: "banner warn", text: "Changed by someone else meanwhile: " + e.body.conflicts.map(c => `${c.field} is now "${c.current}"`).join("; ") + ". Save again to override." }));
      } else if (e.body && e.body.errors) {
        errBox.replaceChildren(el("div", { class: "banner err", text: e.body.errors.map(x => `${x.field}: ${x.message}`).join("; ") }));
      } else errBox.replaceChildren(el("div", { class: "banner err", text: e.message }));
    }
  } });
  applyLocks();
  S.caseForm = { isDirty: () => document.body.contains(grid) && Object.keys(collectChanges().changes).length > 0 };

  // Connection tests (Aurora's "Test connection" buttons), run by the server with the *saved* settings
  const integ = S.caseInfo.integrations || { enabled: false, misp: {}, virustotal: {} };
  const testBtn = (label, path, ok, reason) => el("button", { class: "btn", type: "button", text: label, disabled: !ok, title: ok ? "Uses the saved settings" : reason,
    onclick: async ev => {
      const b = ev.currentTarget;
      if (S.caseForm.isDirty()) return toast("Save the case details first: the test uses the saved settings.", true);
      b.disabled = true;
      try { toast((await api("POST", `/api/cases/${S.caseId}/integrations/${path}/test`)).message); }
      catch (e) { toast(e.message, true); }
      finally { b.disabled = false; }
    } });
  const integPanel = ro ? null : el("div", { class: "actions-row" },
    testBtn("Test MISP connection", "misp", integ.enabled && integ.misp.configured,
      integ.enabled ? `Set ${(integ.misp.missing || []).join(", ")} and save first` : "Integrations are disabled on this server"),
    testBtn("Test VirusTotal key", "virustotal", integ.enabled && integ.virustotal.configured,
      integ.enabled ? `Add a VirusTotal API key and save first (${integ.virustotal.note || ""})` : "Integrations are disabled on this server"));
  const integState = el("div", { class: "integ-state" },
    el("div", null, el("b", { text: "MISP: " }), integrationText(integ, "misp")),
    el("div", null, el("b", { text: "VirusTotal: " }), integrationText(integ, "virustotal")));
  const info = el("p", { class: "muted", text: `Case #${S.caseInfo.id} · owner ${S.caseInfo.owner || "— (none)"} · your access: ${S.caseInfo.access || "—"} · revision ${S.caseInfo.revision} · last change by ${S.caseInfo.updated_by || "?"} at ${fmtTs(S.caseInfo.updated_at)} UTC` });
  const mgmt = el("div");                      // owner/admin: members + invites, loaded lazily
  document.getElementById("content").replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "Case Details" })),
    el("div", { class: "panel" }, info, errBox, grid, ro ? null : el("div", { class: "actions-row" }, save), integState, integPanel),
    mgmt);
  if (canManage()) loadCaseManagement(mgmt);
}

/** Owner / administrator panel on Case Details: members (permission, remove, transfer owner) and invite codes. */
async function loadCaseManagement(mount) {
  const caseId = S.caseId;
  let data;
  try {
    const [m, inv] = await Promise.all([
      api("GET", `/api/cases/${caseId}/members`),
      api("GET", `/api/cases/${caseId}/invites`),
    ]);
    data = { members: m.members, invites: inv.invites };
  } catch (e) { mount.replaceChildren(el("div", { class: "banner err", text: e.message })); return; }
  if (S.caseId !== caseId) return;             // navigated away while loading
  const msg = el("div");
  const err = e => msg.replaceChildren(el("div", { class: "banner err", text: e.message }));
  const reload = () => { if (S.caseId === caseId) loadCaseManagement(mount); };

  // --- Members table ---
  const mbody = el("tbody");
  for (const u of data.members) {
    const permSel = el("select", { disabled: u.is_owner });
    for (const r of ["editor", "viewer"]) permSel.append(el("option", { value: r, text: r, selected: r === u.permission }));
    mbody.append(el("tr", null,
      el("td", null, el("b", { text: u.username }), u.investigator ? el("span", { class: "muted", text: " (" + u.investigator + ")" }) : null,
        u.is_owner ? el("span", { class: "pill ok", text: "owner" }) : null),
      el("td", null, u.is_owner ? el("span", { class: "muted", text: "editor (owner)" }) : permSel),
      el("td", null, u.is_owner ? null : el("div", { class: "btn-group" },
        el("button", { class: "btn small", text: "Save", onclick: async () => {
          try { await api("PATCH", `/api/cases/${caseId}/members/${u.user_id}`, { permission: permSel.value }); toast("Permission updated"); reload(); } catch (e) { err(e); }
        } }),
        el("button", { class: "btn small", text: "Make owner", title: "Transfer ownership to this member", onclick: async () => {
          if (!confirm(`Transfer ownership of this case to ${u.username}? You stay on as an editor.`)) return;
          try { await api("PATCH", `/api/cases/${caseId}/owner`, { user_id: u.user_id }); toast("Ownership transferred"); S.caseInfo = await api("GET", `/api/cases/${caseId}`); renderCaseDetails(); } catch (e) { err(e); }
        } }),
        el("button", { class: "btn small danger", text: "Remove", onclick: async () => {
          if (!confirm(`Remove ${u.username} from this case?`)) return;
          try { await api("DELETE", `/api/cases/${caseId}/members/${u.user_id}`); toast("Member removed"); reload(); } catch (e) { err(e); }
        } })))));
  }

  // --- New invite ---
  const caseUuid = (S.caseInfo && S.caseInfo.uuid) || "";
  const invPerm = el("select"); for (const r of ["editor", "viewer"]) invPerm.append(el("option", { value: r, text: r }));
  const invMax = el("input", { type: "number", min: "0", max: "10000", value: "1", style: "width:6rem" });
  const invExp = el("input", { type: "datetime-local", step: "1", title: "Optional expiry (UTC)" });
  const makeInvite = el("button", { class: "btn primary", text: "Create invite code", onclick: async () => {
    let r;
    try {
      r = await api("POST", `/api/cases/${caseId}/invites`, { permission: invPerm.value, max_redeems: Number(invMax.value || 0), expires: invExp.value || null });
    } catch (e) { err(e); return; }
    // Refresh the panel FIRST (rebuilds an empty .new-invite), then render the one-time code into it so the
    // refresh does not wipe it (same pattern as the API-key "shown once" box).
    await loadCaseManagement(mount);
    if (S.caseId !== caseId) return;
    const box = mount.querySelector(".new-invite");
    if (box) box.replaceChildren(el("div", { class: "banner warn" },
      el("b", { text: "Invite code created. Copy it now: it is shown only once and cannot be retrieved later. Send it to the user together with the case id (uuid) above." }),
      el("div", null, "Invite code: ", codeBlock(r.code))));
  } });

  // --- Existing invites ---
  const ibody = el("tbody");
  for (const v of data.invites) {
    const state = !v.enabled ? "revoked" : v.expired ? "expired" : (v.max_redeems && v.redeems_used >= v.max_redeems ? "used up" : "active");
    ibody.append(el("tr", null,
      el("td", { class: "mono", text: v.prefix + "…" }),
      el("td", { text: v.permission }),
      el("td", { text: v.max_redeems ? `${v.redeems_used} / ${v.max_redeems}` : `${v.redeems_used} / ∞` }),
      el("td", { text: `${fmtTs(v.created_at)} UTC` }),
      el("td", { text: v.expires_at ? fmtTs(v.expires_at) + " UTC" : "never" }),
      el("td", null, el("span", { class: "pill " + (state === "active" ? "ok" : "warn"), text: state })),
      el("td", null, state === "active" ? el("button", { class: "btn small danger", text: "Revoke", onclick: async () => {
        try { await api("DELETE", `/api/cases/${caseId}/invites/${v.id}`); toast("Invite revoked"); reload(); } catch (e) { err(e); }
      } }) : null)));
  }

  mount.replaceChildren(
    el("div", { class: "panel" }, el("h3", { text: "Members" }), msg,
      el("table", { class: "plain" }, el("thead", null, el("tr", null, ["User", "Permission", ""].map(h => el("th", { text: h })))), mbody)),
    el("div", { class: "panel" }, el("h3", { text: "Invite users to this case" }),
      el("p", { class: "muted", text: "To bring someone onto this case, send them BOTH the case id (uuid) below and an invite code you generate here — out of band. They join with Join case. Only the owner or an administrator can create invites." }),
      el("div", { class: "fld" }, el("label", { class: "lbl", text: "Case id (uuid) — send this with the code" }), codeBlock(caseUuid)),
      el("div", { class: "form-grid" },
        el("div", { class: "fld" }, el("label", { class: "lbl", text: "Permission" }), invPerm),
        el("div", { class: "fld" }, el("label", { class: "lbl", text: "Max redeems" }), invMax,
          el("div", { class: "hint", text: "1 = single use (default) · 0 = unlimited" })),
        el("div", { class: "fld" }, el("label", { class: "lbl", text: "Expires (UTC date & time, optional)" }), invExp,
          el("div", { class: "hint", text: "Empty = never expires" }))),
      el("div", { class: "actions-row" }, makeInvite),
      el("div", { class: "new-invite" }),
      data.invites.length ? el("table", { class: "plain" }, el("thead", null, el("tr", null,
        ["Code", "Permission", "Redeems", "Created", "Expires", "State", ""].map(h => el("th", { text: h })))), ibody) : null));
}

const CASE_FIELD_HINTS = {
  end_date: "For the reports (Excel, PDF, LaTeX); not written to the .fox.",
  summary: "Also shown as Context on the Report page. Line breaks are allowed here; the .fox export writes it as one line.",
  mispeventid: "Always this case's own event, also with the server-wide MISP.",
  use_server_misp: "On: the MISP an administrator configured for the server. Off: this case's own MISP URL and API key below.",
  mispserver: "Only used when 'Use the server-wide MISP' is off; then this case's own API key is needed too.",
  mispapikey: "Only used with this case's own MISP URL.",
  use_server_vt: "On: the server's VirusTotal key. Off: this case's own key below.",
  vtapikey: "Only used when 'Use the server-wide VirusTotal key' is off.",
};

/** Where a case's MISP / VirusTotal settings come from (case, server-wide, or nowhere and why). */
function integrationText(integ, which) {
  if (!integ.enabled) return "integrations are disabled on this server";
  const st = integ[which] || {};
  const where = st.source === "server" ? "server-wide settings" : st.source === "case" ? "this case's own settings" : "";
  if (which === "misp") {
    if (st.configured) return `${where} (${st.server}), event ${st.event_id}`;
    return `not ready: set ${(st.missing || []).join(", ")}${st.note ? ` (${st.note})` : ""}`;
  }
  return st.configured ? where : `not configured${st.note ? ` (${st.note})` : ""}`;
}

/* ------------------------------------------------------------------ activity */

async function renderActivity() {
  const rows = await api("GET", `/api/cases/${S.caseId}/audit?limit=300`);
  const body = el("tbody");
  for (const r of rows) {
    const sec = r.section ? S.sections[r.section] : null;
    const fields = r.after && typeof r.after === "object" ? Object.keys(r.after).join(", ") : "";
    const detail = el("tr", { hidden: true }, el("td", { colSpan: 5 },
      r.before ? el("div", null, "Before:", el("pre", { class: "json", text: JSON.stringify(r.before, null, 2) })) : null,
      r.after ? el("div", null, "After:", el("pre", { class: "json", text: JSON.stringify(r.after, null, 2) })) : null));
    const tr = el("tr", { onclick: () => { detail.hidden = !detail.hidden; } },
      el("td", { text: fmtTs(r.ts) }), el("td", { text: r.username }), el("td", { text: r.action }),
      el("td", { text: sec ? `${sec.label}${r.recid ? " #" + r.recid : ""}` : "" }), el("td", { class: "wrap", text: fields }));
    tr.style.cursor = "pointer";
    body.append(tr, detail);
  }
  document.getElementById("content").replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "Activity Log" }), el("span", { class: "muted", text: "Latest 300 changes (UTC). Click a row for details." })),
    el("div", { class: "panel" }, el("table", { class: "plain" },
      el("thead", null, el("tr", null, ["Time (UTC)", "User", "Action", "Record", "Fields"].map(h => el("th", { text: h })))), body)));
}

/* ------------------------------------------------------------------ admin: cases */

function pickFile(accept = ".fox,application/json") {
  return new Promise(resolve => {
    const inp = el("input", { type: "file", accept });
    inp.addEventListener("change", () => resolve(inp.files[0] || null));
    inp.click();
  });
}

async function renderAdminCases() {
  S.cases = await api("GET", "/api/cases");
  const users = await api("GET", "/api/users");          // admins may change any case's owner
  const content = document.getElementById("content");
  const msg = el("div");
  const showResult = (text, warnings) => msg.replaceChildren(el("div", { class: "banner warn" }, text,
    warnings && warnings.length ? el("ul", null, warnings.map(w => el("li", { text: w }))) : null));
  const showErr = e => msg.replaceChildren(el("div", { class: "banner err" }, e.message,
    e.body && e.body.errors ? el("ul", null, e.body.errors.slice(0, 50).map(x => el("li", { text: `${x.field}: ${x.message}` }))) : null));
  const declare = el("input", { type: "checkbox" });

  async function upload(path) {
    const file = await pickFile();
    if (!file) return null;
    const text = await file.text();
    return api("POST", `${path}${declare.checked ? "?declare_missing=true" : ""}`, undefined, text);
  }

  const newId = el("input", { type: "text", placeholder: "Case ID, e.g. IR-609", maxLength: 100 });
  const newClient = el("input", { type: "text", placeholder: "Client", maxLength: 200 });

  const list = el("tbody");
  for (const c of S.cases) {
    const ownerSel = el("select", { style: "min-width:9rem" });
    if (!c.owner_id) ownerSel.append(el("option", { value: "", text: "— (owner-less)", selected: true }));
    for (const u of users) ownerSel.append(el("option", { value: u.id, text: u.username, selected: u.id === c.owner_id }));
    const setOwner = el("button", { class: "btn small", text: "Set owner", title: "Transfer this case to the selected user", onclick: async () => {
      if (!ownerSel.value) return;
      if (!confirm(`Make ${ownerSel.options[ownerSel.selectedIndex].text} the owner of case ${c.id}: ${c.case_id}?`)) return;
      try { await api("PATCH", `/api/cases/${c.id}/owner`, { user_id: Number(ownerSel.value) }); toast("Owner changed"); renderAdminCases(); } catch (e) { showErr(e); }
    } });
    list.append(el("tr", { dataset: { search: `${c.id}\n${c.case_id}\n${c.client}\n${c.owner || ""}`.toLowerCase() } },
      el("td", { text: c.id }), el("td", { text: c.case_id }), el("td", { text: c.client }),
      el("td", null, el("div", { class: "btn-group" }, ownerSel, setOwner)), el("td", { text: c.revision }),
      el("td", { text: `${fmtTs(c.updated_at)} UTC · ${c.updated_by}` }),
      el("td", null,
        el("button", { class: "btn small", text: "Open", onclick: async () => { S.caseId = c.id; lsSet("aurora.case", c.id); S.view = "timeline"; renderShell(); await loadCase(); } }),
        " ",
        el("button", { class: "btn small", text: "Replace from .fox", onclick: async () => {
          if (!confirm(`Replace ALL data of case ${c.case_id} with an uploaded .fox? A database snapshot is taken first.`)) return;
          try { const r = await upload(`/api/cases/${c.id}/replace`); if (r) { showResult(`Case ${c.case_id} replaced.`, r.warnings); await afterCaseListChange(c.id); } } catch (e) { showErr(e); }
        } }),
        " ",
        el("button", { class: "btn small danger", text: "Delete", onclick: async () => {
          const typed = prompt(`Type the Case ID "${c.case_id}" to permanently delete this case (a database snapshot is written first):`);
          if (typed === null) return;
          try { await api("POST", `/api/cases/${c.id}/delete`, { confirm: typed }); toast("Case deleted"); await afterCaseListChange(null); } catch (e) { showErr(e); }
        } }),
        )));
  }

  const caseCount = el("span", { class: "muted" });
  content.replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "Cases" }), caseCount,
      rowFilter(list, "Search Case ID or client…", caseCount)), msg,
    el("div", { class: "panel" }, el("h3", { text: "Existing cases" }),
      S.cases.length ? el("table", { class: "plain" }, el("thead", null, el("tr", null, ["#", "Case ID", "Client", "Owner", "Revision", "Last change", ""].map(h => el("th", { text: h })))), list)
        : el("p", { class: "muted", text: "No cases yet." })),
    el("div", { class: "panel" }, el("h3", { text: "Import an Aurora .fox file as a new case" }),
      el("label", { class: "check" }, declare, "Automatically declare systems / investigators / lookup values that are referenced but missing"),
      el("div", { class: "actions-row" }, el("button", { class: "btn primary", text: "Choose .fox file…", onclick: async () => {
        try { const r = await upload("/api/cases/import"); if (r) { showResult("Case imported.", r.warnings); await afterCaseListChange(r.id); } } catch (e) { showErr(e); }
      } }))),
    el("div", { class: "panel" }, el("h3", { text: "Create an empty case" }),
      el("div", { class: "form-grid" }, newId, newClient),
      el("div", { class: "actions-row" }, el("button", { class: "btn", text: "Create case", onclick: async () => {
        try { const r = await api("POST", "/api/cases", { case_id: newId.value, client: newClient.value }); toast("Case created"); await afterCaseListChange(r.id); } catch (e) { showErr(e); }
      } }))));
}

async function afterCaseListChange(selectId) {
  S.cases = await api("GET", "/api/cases");
  if (selectId) S.caseId = selectId;
  if (!S.cases.find(c => c.id === S.caseId)) S.caseId = S.cases[0] ? S.cases[0].id : null;
  lsSet("aurora.case", S.caseId || "");
  renderShell();
  await loadCase();
}

/* ------------------------------------------------------------------ admin: users */

/** IP allowlist editor: one IPv4/IPv6 address or CIDR range per line; empty = any address. */
function allowlistArea(list) {
  return el("textarea", { class: "mono allowlist", rows: Math.max(2, Math.min(6, (list || []).length + 1)),
    value: (list || []).join("\n"), placeholder: "any address\n(one IP or CIDR per line, IPv4 or IPv6)", spellcheck: false });
}
const readAllowlist = ta => ta.value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);

async function renderAdminUsers() {
  const users = await api("GET", "/api/users");
  const msg = el("div");
  const showErr = e => msg.replaceChildren(el("div", { class: "banner err", text: e.message }));
  const roleSel = v => { const s = el("select"); for (const r of ["user", "admin"]) s.append(el("option", { value: r, text: r, selected: r === v })); return s; };

  const body = el("tbody");
  for (const u of users) {
    const role = roleSel(u.role);
    const inv = el("input", { type: "text", value: u.investigator, maxLength: 20, placeholder: "e.g. cvp" });
    const active = el("input", { type: "checkbox", checked: u.active });
    const force = el("input", { type: "checkbox", checked: u.must_change_password, title: "Require a new password at next sign-in" });
    const allow = allowlistArea(u.ip_allowlist);
    const locked = u.is_env_admin;
    if (locked) { role.disabled = true; active.disabled = true; }
    const mfa = el("td", null, el("span", { class: "pill " + (u.mfa_enabled ? "ok" : ""), text: u.mfa_enabled ? "on" : "off" }),
      u.mfa_enabled ? el("button", { class: "btn small", text: "Reset MFA", title: "Remove the user's authenticator; they enrol again", onclick: async () => {
        if (!confirm(`Remove the two-factor authentication of ${u.username}? They are signed out and must enrol a new authenticator${S.mfaEnforced ? " at their next sign-in" : " (MFA is optional on this server)"}.`)) return;
        try { await api("POST", `/api/users/${u.id}/reset-mfa`, {}); toast("MFA reset"); renderAdminUsers(); } catch (e) { showErr(e); }
      } }) : null);
    body.append(el("tr", { dataset: { search: `${u.username}\n${u.investigator || ""}`.toLowerCase() } },
      el("td", { text: u.username + (locked ? " (env)" : "") }), el("td", null, role), el("td", null, active), el("td", null, inv),
      mfa, el("td", null, force), el("td", null, allow),
      el("td", null,
        el("button", { class: "btn small", text: "Save", onclick: async () => {
          try {
            const patch = { investigator: inv.value, must_change_password: force.checked, ip_allowlist: readAllowlist(allow) };
            if (!locked) { patch.role = role.value; patch.active = active.checked; }
            if (!locked && u.active && !active.checked && !confirm(`Deactivate ${u.username}? They are signed out everywhere.`)) return;
            await api("PATCH", `/api/users/${u.id}`, patch); toast("User updated"); renderAdminUsers();
          } catch (e) { showErr(e); }
        } }), " ",
        el("button", { class: "btn small", text: "Reset password", onclick: async () => {
          const pw = prompt(`New password for ${u.username} (min 12 characters).\nThis signs the user out everywhere.`);
          if (!pw) return;
          const must = u.id !== S.me.id && confirm("Require the user to choose their own password at next sign-in?");
          try { await api("PATCH", `/api/users/${u.id}`, { password: pw, must_change_password: must }); toast("Password reset; the user's sessions were ended"); renderAdminUsers(); } catch (e) { showErr(e); }
        } }), " ",
        locked || u.id === S.me.id ? null : el("button", { class: "btn small danger", text: "Delete", onclick: async () => {
          if (!confirm(`Delete user ${u.username}?`)) return;
          try { await api("DELETE", `/api/users/${u.id}`); toast("User deleted"); renderAdminUsers(); } catch (e) { showErr(e); }
        } }))));
  }

  const nu = el("input", { type: "text", placeholder: "username", maxLength: 32, autocomplete: "off" });
  const np = el("input", { type: "password", placeholder: "initial password (min 12)", maxLength: 256, autocomplete: "new-password" });
  const nr = roleSel("user");
  const ni = el("input", { type: "text", placeholder: "investigator short name (optional)", maxLength: 20 });
  const nf = el("input", { type: "checkbox", checked: true });
  const na = allowlistArea([]);

  const userCount = el("span", { class: "muted" });
  document.getElementById("content").replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "Users" }), userCount, rowFilter(body, "Search username…", userCount)),
    el("p", { class: "muted", text: `Users: create and own cases, and join cases they are invited to (per-case editor or viewer rights). Admins: manage users, API keys and backups, and have full access to every case. Two-factor authentication is ${S.mfaEnforced ? "mandatory (MFA_ENFORCED)" : "optional"} on this server. An empty IP allowlist allows any address.` }),
    msg,
    el("div", { class: "panel" }, el("table", { class: "plain" },
      el("thead", null, el("tr", null, ["Username", "Role", "Active", "Investigator", "MFA", "New password at next sign-in", "IP allowlist", ""].map(h => el("th", { text: h })))), body)),
    el("div", { class: "panel" }, el("h3", { text: "Add user" }),
      el("div", { class: "form-grid" }, nu, np, nr, ni,
        el("label", { class: "check" }, nf, "Must choose a new password at first sign-in"),
        el("div", { class: "fld" }, el("label", { class: "lbl", text: "IP allowlist (optional)" }), na)),
      el("div", { class: "actions-row" }, el("button", { class: "btn primary", text: "Create user", onclick: async () => {
        try { await api("POST", "/api/users", { username: nu.value, password: np.value, role: nr.value, investigator: ni.value, must_change_password: nf.checked, ip_allowlist: readAllowlist(na) }); toast("User created"); renderAdminUsers(); } catch (e) { showErr(e); }
      } }))));
}

/** Search box for the admin tables: hides rows whose `data-search` text does not contain the query. */
function rowFilter(tbody, placeholder, countEl) {
  const input = el("input", { type: "search", placeholder, oninput: () => {
    const q = input.value.trim().toLowerCase();
    let shown = 0;
    for (const tr of tbody.rows) { const hit = !q || tr.dataset.search.includes(q); tr.hidden = !hit; shown += hit; }
    if (countEl) countEl.textContent = q ? `${shown} of ${tbody.rows.length}` : `${tbody.rows.length}`;
  } });
  if (countEl) countEl.textContent = `${tbody.rows.length}`;
  return input;
}

/* ------------------------------------------------------------------ API access */

function codeBlock(text) {
  const pre = el("pre", { class: "json code", text });
  const btn = el("button", { class: "btn small copy", text: "Copy", onclick: async () => {
    try { await navigator.clipboard.writeText(text); toast("Copied"); }
    catch { const r = document.createRange(); r.selectNodeContents(pre); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); }
  } });
  return el("div", { class: "codewrap" }, btn, pre);
}

/* ------------------------------------------------------------------ new case (admins and editors) */

function openNewCaseModal() {
  const cid = el("input", { type: "text", placeholder: "e.g. IR-610", maxLength: 100, autocomplete: "off" });
  const client = el("input", { type: "text", placeholder: "Client", maxLength: 200, autocomplete: "off" });
  const err = el("div", { class: "wide" });
  const create = el("button", { class: "btn primary", text: "Create case", onclick: async () => {
    try {
      const r = await api("POST", "/api/cases", { case_id: cid.value.trim(), client: client.value.trim() });
      closeModal();
      toast(`Case ${cid.value.trim()} created`);
      S.cases = await api("GET", "/api/cases");
      S.caseId = r.id; lsSet("aurora.case", r.id); S.view = "case";
      renderShell(); await loadCase();
    } catch (e) { err.replaceChildren(el("div", { class: "banner err", text: e.message })); }
  } });
  const back = el("div", { class: "modal-back" }, el("div", { class: "modal" },
    el("header", null, el("h3", { text: "New case" })),
    el("div", { class: "body" }, err,
      el("div", { class: "fld" }, el("label", { class: "lbl", text: "Case ID *" }), cid),
      el("div", { class: "fld" }, el("label", { class: "lbl", text: "Client" }), client),
      el("p", { class: "muted wide", text: "An empty case with Aurora's default lookup lists; you become its owner. Fill in the rest under Case Details. To start from an Aurora .fox file, use Import .fox instead." })),
    el("footer", null, el("div", { class: "spacer" }), el("button", { class: "btn", text: "Cancel", onclick: closeModal }), create)));
  openModal(back);
  S.modal = { root: back };
  cid.focus();
}

function openImportModal() {
  const declare = el("input", { type: "checkbox" });
  const err = el("div", { class: "wide" });
  const choose = el("button", { class: "btn primary", text: "Choose .fox file…", onclick: async () => {
    try {
      const file = await pickFile();
      if (!file) return;
      const text = await file.text();
      const r = await api("POST", `/api/cases/import${declare.checked ? "?declare_missing=true" : ""}`, undefined, text);
      closeModal();
      toast("Case imported" + (r.warnings && r.warnings.length ? ` (${r.warnings.length} warning(s))` : ""));
      S.cases = await api("GET", "/api/cases");
      S.caseId = r.id; lsSet("aurora.case", r.id); S.view = "timeline";
      renderShell(); await loadCase();
    } catch (e) { err.replaceChildren(el("div", { class: "banner err", text: e.message })); }
  } });
  const back = el("div", { class: "modal-back" }, el("div", { class: "modal" },
    el("header", null, el("h3", { text: "Import a .fox as a new case" })),
    el("div", { class: "body" }, err,
      el("label", { class: "check wide" }, declare, "Automatically declare systems / investigators / lookup values that are referenced but missing"),
      el("p", { class: "muted wide", text: "Importing a .fox creates and populates a new case; you become its owner. Secrets (API keys) are never carried in a .fox." })),
    el("footer", null, el("div", { class: "spacer" }), el("button", { class: "btn", text: "Cancel", onclick: closeModal }), choose)));
  openModal(back);
  S.modal = { root: back };
}

function openJoinModal() {
  const uuid = el("input", { type: "text", placeholder: "case id (uuid), e.g. 3f9c…", maxLength: 36, autocomplete: "off" });
  const code = el("input", { type: "text", placeholder: "invite code", maxLength: 128, autocomplete: "off" });
  const err = el("div", { class: "wide" });
  const join = el("button", { class: "btn primary", text: "Join case", onclick: async () => {
    try {
      const r = await api("POST", "/api/cases/join", { uuid: uuid.value.trim(), code: code.value.trim() });
      closeModal();
      toast(`Joined the case as ${r.permission}`);
      S.cases = await api("GET", "/api/cases");
      S.caseId = r.id; lsSet("aurora.case", r.id); S.view = "timeline";
      renderShell(); await loadCase();
    } catch (e) { err.replaceChildren(el("div", { class: "banner err", text: e.message })); }
  } });
  const back = el("div", { class: "modal-back" }, el("div", { class: "modal" },
    el("header", null, el("h3", { text: "Join a case" })),
    el("div", { class: "body" }, err,
      el("div", { class: "fld" }, el("label", { class: "lbl", text: "Case id (uuid) *" }), uuid),
      el("div", { class: "fld" }, el("label", { class: "lbl", text: "Invite code *" }), code),
      el("p", { class: "muted wide", text: "The case owner shares both the case id and an invite code with you (offline). The code sets whether you join as an editor or a viewer." })),
    el("footer", null, el("div", { class: "spacer" }), el("button", { class: "btn", text: "Cancel", onclick: closeModal }), join)));
  openModal(back);
  S.modal = { root: back };
  uuid.focus();
}

/* ------------------------------------------------------------------ admin: API keys */

const fmtDay = sec => sec ? new Date(sec * 1000).toISOString().slice(0, 10) : "";
const fmtDTLocal = sec => sec ? new Date(sec * 1000).toISOString().slice(0, 19) : "";   // YYYY-MM-DDTHH:MM:SS (UTC)

/* ------------------------------------------------------------------ server-wide MISP / VirusTotal */

async function renderAdminIntegrations() {
  const cur = await api("GET", "/api/settings/integrations");
  const msg = el("div");
  const url = el("input", { type: "text", id: "srv_misp_url", value: cur.misp_url, placeholder: "https://misp.example.org", maxLength: 2000,
    autocomplete: "off", "data-lpignore": "true", "data-1p-ignore": "true" });
  const keyField = (name, label) => {
    const stored = !!cur.secrets_set[name];
    const state = el("span", { class: "pill " + (stored ? "ok" : ""), text: stored ? "stored" : "not set" });
    const input = el("input", { id: "srv_" + name, maxLength: 200, placeholder: stored ? "Hidden · type to replace" : "Paste the API key" });
    const row = maskSecret(input);
    let remove = false;
    if (stored) {
      const rm = el("button", { class: "btn small", type: "button", text: "Remove", onclick: () => {
        remove = !remove; rm.textContent = remove ? "Keep" : "Remove";
        state.textContent = remove ? "will be removed on save" : "stored"; state.classList.toggle("warn", remove);
        input.disabled = remove; if (remove) input.value = "";
      } });
      row.append(rm);
    }
    return { box: el("div", { class: "fld" }, el("label", { class: "lbl", htmlFor: input.id }, label, " ", state), row),
      change: () => remove ? "" : (input.value.trim() || null) };
  };
  const mispKey = keyField("misp_apikey", "MISP API key"), vtKey = keyField("vt_apikey", "VirusTotal API key");
  const save = el("button", { class: "btn primary", text: "Save", onclick: async () => {
    const changes = {};
    if (url.value.trim() !== cur.misp_url) changes.misp_url = url.value.trim();
    for (const [k, f] of [["misp_apikey", mispKey], ["vt_apikey", vtKey]]) { const v = f.change(); if (v !== null) changes[k] = v; }
    if (!Object.keys(changes).length) return toast("Nothing changed");
    try {
      await api("PATCH", "/api/settings/integrations", changes);
      toast("Server-wide integration settings saved");
      // Server-wide keys change integration availability without bumping any case revision, so the open
      // case's cached status would otherwise stay stale (e.g. "Check VT" greyed after adding the key here).
      if (S.caseId) { try { S.caseInfo = await api("GET", `/api/cases/${S.caseId}`); } catch (_) {} }
      renderAdminIntegrations();
    }
    catch (e) { msg.replaceChildren(el("div", { class: "banner err", text: e.body && e.body.errors ? e.body.errors.map(x => `${x.field}: ${x.message}`).join("; ") : e.message })); }
  } });
  const test = (label, path) => el("button", { class: "btn", type: "button", text: label, disabled: !cur.integrations_enabled,
    title: cur.integrations_enabled ? "Uses the saved settings" : "Integrations are disabled on this server (INTEGRATIONS_ENABLED)",
    onclick: async ev => {
      const b = ev.currentTarget; b.disabled = true;
      try { toast((await api("POST", `/api/settings/integrations/${path}/test`)).message); } catch (e) { toast(e.message, true); }
      finally { b.disabled = false; }
    } });
  document.getElementById("content").replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "MISP & VirusTotal" })),
    el("div", { class: "panel" },
      el("p", null, "Server-wide settings, used by every case whose 'Use the server-wide MISP' / 'Use the server-wide VirusTotal key' switch is on (the default). A case with a switch off uses its own MISP URL and API key (both) or its own VirusTotal key instead. ",
        el("b", { text: "The MISP event ID is always set per case." }), " The server-wide MISP key is only ever sent to the server-wide MISP URL."),
      el("p", { class: "muted", text: "API keys are stored encrypted, never shown again and never exported (.fox, Excel, PDF, LaTeX). Exported .fox files leave the MISP URL empty for cases that use the server-wide MISP." }),
      msg,
      el("div", { class: "form-grid" },
        el("div", { class: "fld" }, el("label", { class: "lbl", htmlFor: url.id, text: "MISP server URL" }), url),
        mispKey.box, vtKey.box),
      el("div", { class: "actions-row" }, save, test("Test MISP connection", "misp"), test("Test VirusTotal key", "virustotal")),
      cur.updated_at ? el("p", { class: "muted", text: `Last change by ${cur.updated_by} at ${fmtTs(cur.updated_at)} UTC` }) : null,
      cur.integrations_enabled ? null : el("div", { class: "banner warn", text: "Integrations are disabled on this server (INTEGRATIONS_ENABLED=false): nothing is sent to MISP or VirusTotal." })));
}

async function renderAdminKeys() {
  const origin = location.origin;
  const keys = await api("GET", "/api/keys");
  const msg = el("div");
  const showErr = e => msg.replaceChildren(el("div", { class: "banner err", text: e.message }));
  const profileSel = v => { const s = el("select"); for (const [k, t] of [["read", "read"], ["readwrite", "readwrite"]]) s.append(el("option", { value: k, text: t, selected: k === v })); return s; };
  const showSecret = (title, secret) => document.getElementById("new-secret").replaceChildren(el("div", { class: "banner warn" },
    el("b", { text: `${title} Copy it now: it is shown only once and cannot be retrieved later.` }), codeBlock(secret)));

  const body = el("tbody");
  for (const k of keys) {
    const prof = profileSel(k.profile);
    const enabled = el("input", { type: "checkbox", checked: k.enabled });
    const exp = el("input", { type: "datetime-local", step: "1", value: fmtDTLocal(k.expires_at), title: "Expiry (UTC date & time); empty = never expires" });
    const allow = allowlistArea(k.ip_allowlist);
    const state = !k.enabled ? "disabled" : k.expired ? "expired" : "active";
    const scopeTxt = k.kind === "admin" ? "admin (full access)"
      : (k.scope === "single" ? `case #${k.case_pk}` : "all cases");
    body.append(el("tr", { dataset: { search: k.name.toLowerCase() } },
      el("td", null, el("b", { text: k.name }), el("div", { class: "mono muted", text: k.prefix + "…" })),
      el("td", null, el("span", { class: "pill " + (k.kind === "admin" ? "warn" : ""), text: scopeTxt })),
      el("td", null, prof), el("td", null, enabled, " ", el("span", { class: "pill " + (state === "active" ? "ok" : "warn"), text: state })),
      el("td", null, exp), el("td", null, allow),
      el("td", { class: "small", text: `${fmtTs(k.created_at)} UTC by ${k.created_by}${k.rotated_at ? ` · rotated ${fmtTs(k.rotated_at)} UTC` : ""}` }),
      el("td", { class: "small", text: k.last_used_at ? `${fmtTs(k.last_used_at)} UTC · ${k.last_used_ip}` : "never" }),
      el("td", null,
        el("button", { class: "btn small", text: "Save", onclick: async () => {
          try { await api("PATCH", `/api/keys/${k.id}`, { profile: prof.value, enabled: enabled.checked, expires: exp.value || "", ip_allowlist: readAllowlist(allow) }); toast("API key updated"); renderAdminKeys(); }
          catch (e) { showErr(e); }
        } }), " ",
        el("button", { class: "btn small", text: "Rotate secret", onclick: async () => {
          if (!confirm(`Issue a new secret for "${k.name}"? The current secret stops working immediately.`)) return;
          try { const r = await api("POST", `/api/keys/${k.id}/rotate`, {}); await renderAdminKeys(); showSecret(`New secret for "${k.name}".`, r.secret); }
          catch (e) { showErr(e); }
        } }), " ",
        el("button", { class: "btn small danger", text: "Delete", onclick: async () => {
          if (!confirm(`Delete API key "${k.name}"? Programs using it stop working immediately.`)) return;
          try { await api("DELETE", `/api/keys/${k.id}`); toast("API key deleted"); renderAdminKeys(); } catch (e) { showErr(e); }
        } }))));
  }

  const name = el("input", { type: "text", placeholder: "Name = identity in the activity log, e.g. plaso-importer", maxLength: 64 });
  const prof = profileSel("read");
  const kind = el("select"); for (const [v, t] of [["case", "case — case data only"], ["admin", "admin — full admin API"]]) kind.append(el("option", { value: v, text: t }));
  const scope = el("select"); for (const [v, t] of [["all", "all cases"], ["single", "a single case"]]) scope.append(el("option", { value: v, text: t }));
  const caseSel2 = el("select");
  for (const c of (S.cases || [])) caseSel2.append(el("option", { value: c.id, text: caseLabel(c) }));
  if (!(S.cases || []).length) caseSel2.append(el("option", { text: "no cases", disabled: true }));
  const scopeFld = el("div", { class: "fld" }, el("label", { class: "lbl", text: "Scope" }), scope);
  const caseFld = el("div", { class: "fld" }, el("label", { class: "lbl", text: "Case" }), caseSel2);
  const relayout = () => {
    const isCase = kind.value === "case";
    scopeFld.style.display = isCase ? "" : "none";
    caseFld.style.display = isCase && scope.value === "single" ? "" : "none";
  };
  kind.addEventListener("change", relayout); scope.addEventListener("change", relayout); relayout();
  const exp = el("input", { type: "datetime-local", step: "1", title: "Expiry (UTC date & time); empty = never expires" });
  const allow = allowlistArea([]);
  const create = el("button", { class: "btn primary", text: "Create API key", onclick: async () => {
    try {
      const payload = { name: name.value.trim(), profile: prof.value, kind: kind.value,
        scope: kind.value === "case" ? scope.value : "all",
        case_pk: (kind.value === "case" && scope.value === "single") ? Number(caseSel2.value) : null,
        expires: exp.value || null, ip_allowlist: readAllowlist(allow) };
      const r = await api("POST", "/api/keys", payload);
      await renderAdminKeys();
      showSecret(`API key "${r.key.name}" created.`, r.secret);
    } catch (e) { showErr(e); }
  } });
  const count = el("span", { class: "muted" });
  document.getElementById("content").replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "API Keys" }), count, rowFilter(body, "Search name…", count)),
    el("p", { class: "muted", text: "API keys belong to the application, not to a user, and only admins create them. An admin key is a full administrator (manage users, keys, backups and every case) — treat it as a secret with total access. A case key reaches case data only: profile read = view/search/export, readwrite = also change case data / MISP / VirusTotal; scope all = every case, single = one case. Changes made with a key appear in the Activity Log as “api:<name>”. Keys are managed here only; a database restore replaces them with the keys in the snapshot." }),
    msg, el("div", { id: "new-secret" }),
    el("div", { class: "panel" }, keys.length ? el("table", { class: "plain" }, el("thead", null, el("tr", null,
      ["Name", "Scope", "Profile", "Enabled", "Expires (UTC)", "IP allowlist", "Created", "Last used", ""].map(h => el("th", { text: h })))), body)
      : el("p", { class: "muted", text: "No API keys yet." })),
    el("div", { class: "panel" }, el("h3", { text: "Create an API key" }),
      el("div", { class: "form-grid" }, el("div", { class: "fld wide" }, name),
        el("div", { class: "fld" }, el("label", { class: "lbl", text: "Kind" }), kind),
        scopeFld, caseFld,
        el("div", { class: "fld" }, el("label", { class: "lbl", text: "Profile (case keys)" }), prof),
        el("div", { class: "fld" }, el("label", { class: "lbl", text: "Expires (UTC date & time; empty = never)" }), exp),
        el("div", { class: "fld wide" }, el("label", { class: "lbl", text: "IP allowlist (one IPv4/IPv6 address or CIDR per line; empty = any address)" }), allow)),
      el("div", { class: "actions-row" }, create)),
    el("div", { class: "panel" }, el("h3", { text: "Using a key" }),
      el("p", null, "Base URL ", el("span", { class: "mono", text: `${origin}/api` }), ". Send the secret as a Bearer header. Try requests in the ",
        el("a", { href: "#", text: "API Explorer", onclick: ev => { ev.preventDefault(); navigate("apiexplorer"); } }), "."),
      codeBlock(`curl -H "Authorization: Bearer $AURORA_KEY" ${origin}/api/cases

curl -H "Authorization: Bearer $AURORA_KEY" -H "Content-Type: application/json" \\
  -d '{"data": {"date_time": "2020-02-21 14:20:37", "event_type": "EventLog", "event_data": "example", "visual": true}}' \\
  ${origin}/api/cases/${S.caseId || 1}/sections/timeline

curl -H "Authorization: Bearer $AURORA_KEY" -o case.xlsx ${origin}/api/cases/${S.caseId || 1}/export.xlsx`)));
}

/* ------------------------------------------------------------------ account: password and MFA */

async function renderAccount() {
  const me = (await api("GET", "/api/session")).user;
  const msg = el("div");
  const showErr = e => msg.replaceChildren(el("div", { class: "banner err", text: e.message }));
  const cur = el("input", { type: "password", autocomplete: "current-password", maxLength: 256 });
  const n1 = el("input", { type: "password", autocomplete: "new-password", maxLength: 256 });
  const n2 = el("input", { type: "password", autocomplete: "new-password", maxLength: 256 });
  const pwPanel = el("div", { class: "panel" }, el("h3", { text: "Password" }),
    el("div", { class: "form-grid" },
      el("div", { class: "fld" }, el("label", { class: "lbl", text: "Current password" }), cur),
      el("div", { class: "fld" }, el("label", { class: "lbl", text: "New password (min 12)" }), n1),
      el("div", { class: "fld" }, el("label", { class: "lbl", text: "Repeat new password" }), n2)),
    el("div", { class: "actions-row" }, el("button", { class: "btn primary", text: "Change password", onclick: async () => {
      if (n1.value !== n2.value) return showErr(new Error("The new passwords do not match"));
      try { await api("POST", "/api/me/password", { current: cur.value, new: n1.value }); toast("Password changed; your other sessions were signed out"); cur.value = n1.value = n2.value = ""; msg.replaceChildren(); }
      catch (e) { showErr(e); }
    } })));

  const mfaPanel = el("div", { class: "panel" }, el("h3", { text: "Two-factor authentication (TOTP)" }));
  if (me.mfa_enabled) {
    mfaPanel.append(el("p", null, el("span", { class: "pill ok", text: "enabled" }), " Sign-in asks for a code from your authenticator app."));
    if (S.mfaEnforced) mfaPanel.append(el("p", { class: "muted", text: "MFA is mandatory on this server. If you lose your authenticator, ask an administrator to reset it." }));
    else {
      const pw = el("input", { type: "password", autocomplete: "current-password", maxLength: 256 });
      const code = codeInput();
      mfaPanel.append(el("div", { class: "form-grid" },
        el("div", { class: "fld" }, el("label", { class: "lbl", text: "Password" }), pw),
        el("div", { class: "fld" }, el("label", { class: "lbl", text: "Current code" }), code)),
        el("div", { class: "actions-row" }, el("button", { class: "btn danger", text: "Turn off MFA", onclick: async () => {
          try { await api("POST", "/api/me/mfa/disable", { password: pw.value, code: code.value.replace(/\s/g, "") }); toast("MFA turned off"); renderAccount(); }
          catch (e) { showErr(e); }
        } })));
    }
  } else {
    const start = el("button", { class: "btn primary", text: "Set up an authenticator", onclick: async () => {
      try {
        const { body, code } = await showMfaSetup(me, true);
        const confirmBtn = el("button", { class: "btn primary", text: "Activate", onclick: async () => {
          try { const r = await api("POST", "/api/mfa/setup", { code: code.value.replace(/\s/g, "") }); S.csrf = r.csrf; toast("MFA enabled"); renderAccount(); }
          catch (e) { showErr(e); }
        } });
        mfaPanel.replaceChildren(el("h3", { text: "Two-factor authentication (TOTP)" }), ...body, el("div", { class: "actions-row" }, confirmBtn));
        code.focus();
      } catch (e) { showErr(e); }
    } });
    mfaPanel.append(el("p", null, el("span", { class: "pill", text: "off" }), " Protect your account with a code from an authenticator app."), el("div", { class: "actions-row" }, start));
  }
  document.getElementById("content").replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "Account" }), el("span", { class: "muted", text: `${me.username} · ${me.role}` })),
    msg, pwPanel, mfaPanel,
    // replaceChildren() would print a null argument as the text "null": add the panel only when there is one
    ...(me.ip_allowlist.length ? [el("div", { class: "panel" }, el("h3", { text: "Allowed sign-in addresses" }),
      el("p", { class: "mono", text: me.ip_allowlist.join(", ") }), el("p", { class: "muted", text: "Set by an administrator." }))] : []));
}

/* ------------------------------------------------------------------ executive summary */

async function renderExecSummary() {
  const rep = await api("GET", `/api/cases/${S.caseId}/report`);
  const ro = !canEdit();
  const fields = S.schema.report_fields;
  const base = {};
  const inputs = {};
  const errBox = el("div");
  const hints = {
    executive_summary: "What happened, in plain words, for management. Not written to the .fox.",
    context: "The case Summary from Case Details (exported to the .fox as one line).",
    conclusions: "Root cause, scope, impact and status. Not written to the .fox.",
    lessons_learned: "What to improve: detection, response, hardening. Not written to the .fox.",
  };
  const boxes = fields.map(f => {
    base[f.name] = rep[f.name] || "";
    const ta = el("textarea", { id: "r_" + f.name, value: rep[f.name] || "", maxLength: f.max_len, disabled: ro, rows: f.name === "context" ? 6 : 10, class: "multiline" });
    inputs[f.name] = ta;
    return el("div", { class: "fld wide" }, el("label", { class: "lbl", htmlFor: ta.id, text: f.label }), ta, el("div", { class: "hint", text: hints[f.name] || "" }));
  });
  const changed = () => Object.fromEntries(fields.filter(f => inputs[f.name].value.replace(/\r\n/g, "\n") !== base[f.name]).map(f => [f.name, inputs[f.name].value]));
  S.reportForm = { isDirty: () => document.body.contains(inputs[fields[0].name]) && Object.keys(changed()).length > 0 };
  const save = el("button", { class: "btn primary", text: "Save report", onclick: async () => {
    errBox.replaceChildren();
    const changes = changed();
    if (!Object.keys(changes).length) return toast("Nothing changed");
    const expected = Object.fromEntries(Object.keys(changes).map(k => [k, base[k]]));
    try {
      await api("PATCH", `/api/cases/${S.caseId}/report`, { changes, expected });
      toast("Report saved");
      S.caseInfo = await api("GET", `/api/cases/${S.caseId}`); S.revision = S.caseInfo.revision;
      await renderExecSummary();
    } catch (e) {
      if (e.status === 409 && e.body.conflicts) {
        for (const c of e.body.conflicts) base[c.field] = c.current;
        errBox.replaceChildren(el("div", { class: "banner warn", text: "Changed by someone else meanwhile: " + e.body.conflicts.map(c => S.schema.report_fields.find(f => f.name === c.field).label).join(", ") + ". Their text is kept as the new base; save again to replace it with yours." }));
      } else if (e.body && e.body.errors) errBox.replaceChildren(el("div", { class: "banner err", text: e.body.errors.map(x => `${x.field}: ${x.message}`).join("; ") }));
      else errBox.replaceChildren(el("div", { class: "banner err", text: e.message }));
    }
  } });
  const info = el("p", { class: "muted", text: rep.updated_by ? `Last change by ${rep.updated_by} at ${fmtTs(rep.updated_at)} UTC` : "Last change: none yet (nothing written on this page)" });
  document.getElementById("content").replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "Report" }), el("span", { class: "muted", text: "Included in the Excel, PDF and LaTeX exports; never in the .fox." })),
    el("div", { class: "panel" }, info, errBox, el("div", { class: "form-grid one" }, ...boxes), ro ? null : el("div", { class: "actions-row" }, save)));
}

/* ------------------------------------------------------------------ admin: backups and restore */

async function renderAdminBackups() {
  const data = await api("GET", "/api/backups");
  const st = data.settings;
  const msg = el("div");
  const showErr = e => msg.replaceChildren(el("div", { class: "banner err", text: e.message }));
  const body = el("tbody");
  for (const b of data.backups) {
    body.append(el("tr", null,
      el("td", { class: "mono", text: b.name }), el("td", { text: b.reason }),
      el("td", { text: b.encrypted ? "PGP" : "no" }), el("td", { text: b.size < 1048576 ? `${Math.max(1, Math.round(b.size / 1024))} KB` : `${(b.size / 1048576).toFixed(1)} MB` }),
      el("td", null, el("a", { href: `/api/backups/${encodeURIComponent(b.name)}`, download: b.name, text: "Download" }))));
  }
  const now = el("button", { class: "btn primary", text: "Back up now", onclick: async ev => {
    ev.currentTarget.disabled = true;
    try { const b = await api("POST", "/api/backups", {}); toast(`Snapshot ${b.name} written`); renderAdminBackups(); }
    catch (e) { showErr(e); ev.currentTarget.disabled = false; }
  } });
  const fileIn = el("input", { type: "file", accept: ".sql,.gz,application/sql,application/gzip" });
  const typed = el("input", { type: "text", placeholder: "type RESTORE", maxLength: 10, autocomplete: "off" });
  const restoreBtn = el("button", { class: "btn danger", text: "Restore database", onclick: async () => {
    const f = fileIn.files[0];
    if (!f) return showErr(new Error("Choose an unencrypted .sql or .sql.gz snapshot first"));
    if (typed.value !== "RESTORE") return showErr(new Error("Type RESTORE to confirm"));
    if (!confirm(`Replace the WHOLE database (all cases, users, API keys and activity logs) with ${f.name}? A snapshot of the current state is written first. Everyone, including you, must sign in again.`)) return;
    restoreBtn.disabled = true;
    msg.replaceChildren(el("div", { class: "banner warn", text: "Restoring… do not close this page." }));
    try {
      const res = await fetch("/api/backups/restore?confirm=RESTORE", { method: "POST", credentials: "same-origin",
        headers: { "X-CSRF-Token": S.csrf, "Content-Type": "application/octet-stream" }, body: f });
      const out = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(out.detail || `Restore failed (HTTP ${res.status})`);
      showLogin("The database was restored. Please sign in again.");
    } catch (e) { showErr(e); restoreBtn.disabled = false; }
  } });
  document.getElementById("content").replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "Backups & Restore" })),
    msg,
    el("div", { class: "panel" }, el("h3", { text: "Database snapshots" }),
      el("p", { class: "muted", text: `Full database dumps (mysqldump), gzip-compressed. ${st.daily ? `Daily at ${st.time_utc} UTC` : "Daily snapshots are off (BACKUP_ENABLED=false)"}, plus on demand and before every case delete / replace / restore. The newest ${st.keep} are kept. Encryption: ${st.encrypted ? "PGP (BACKUP_ENCRYPT=true)" : "off"}. Activity-log retention: ${st.audit_retention_weeks ? st.audit_retention_weeks + " weeks" : "forever"}.` }),
      el("div", { class: "actions-row" }, now),
      data.backups.length ? el("table", { class: "plain" }, el("thead", null, el("tr", null, ["File", "Reason", "Encrypted", "Size", ""].map(h => el("th", { text: h })))), body)
        : el("p", { class: "muted", text: "No snapshots yet." })),
    el("div", { class: "panel" }, el("h3", { text: "Restore" }),
      el("p", null, "Upload an ", el("b", { text: "unencrypted" }), " snapshot (.sql.gz or .sql) of this application. Every table is dropped and re-created from the file: cases, users, API keys and activity logs. Encrypted snapshots (.gpg) must be decrypted first, e.g. ",
        el("span", { class: "mono", text: "gpg --decrypt aurora-….sql.gz.gpg > aurora-….sql.gz" }), ". See docs/deployment.md (Backup & restore)."),
      el("div", { class: "form-grid" }, fileIn, typed), el("div", { class: "actions-row" }, restoreBtn)));
}

document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); });
document.addEventListener("DOMContentLoaded", boot);   // after reports.js (deferred) has loaded
