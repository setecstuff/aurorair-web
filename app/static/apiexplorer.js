/* Aurora IR Web - API Explorer ("try it out") and in-app documentation viewer.
 *
 * Safety model (the explorer must never endanger the case):
 *  - Requests use ONLY the API key typed by the user (Authorization: Bearer) and are sent with
 *    credentials: "omit", so the browser session cookie is never used. You test exactly what that
 *    key may do, and the server enforces roles, validation, locking and audit as for any API client.
 *  - Requests that modify data (POST/PATCH/DELETE) are disabled until the user ticks "Allow requests
 *    that modify data"; destructive calls (delete/replace) additionally require confirmation.
 *  - The key is kept in memory only (never stored); it is cleared on reload or sign-out.
 *  - Only this server can be called (relative URLs, enforced by CSP connect-src 'self').
 *  - Responses and documentation are rendered as text / DOM nodes only, never as HTML.
 */
"use strict";

(() => {

const X = { spec: null, schema: null, ops: [], selected: null, token: "", me: null, allowWrites: false, filter: "" };
// Browser-session (and administrator) operations: documented, but API keys may not call them
const SESSION_ONLY_TAGS = new Set(["session", "api-keys", "users", "backups"]);
const SESSION_ONLY_OPS = new Set(["POST /api/cases/import", "POST /api/cases/{case_pk}/replace", "POST /api/cases/{case_pk}/delete"]);
const MAX_SHOW = 300000;   // characters of a response shown inline

/* ------------------------------------------------------------------ spec helpers */

function resolve(schema) {
  if (!schema) return {};
  if (schema.$ref) return resolve(X.spec.components.schemas[schema.$ref.split("/").pop()]);
  if (schema.anyOf) return resolve(schema.anyOf.find(s => s.type !== "null") || schema.anyOf[0]);
  return schema;
}

function sampleFor(schema, depth = 0) {
  const s = resolve(schema);
  if ("default" in s && s.default !== null) return s.default;
  if (depth > 3) return null;
  switch (s.type) {
    case "object": {
      const o = {};
      for (const [k, v] of Object.entries(s.properties || {})) o[k] = sampleFor(v, depth + 1);
      return o;
    }
    case "array": return [];
    case "integer": case "number": return 0;
    case "boolean": return false;
    case "string": return s.enum ? s.enum[0] : "";
    default: return null;
  }
}

/** Example record data for a section, built from the live field schema and allowed values. */
function sectionExample(section) {
  const sec = (X.schema && X.schema.sections || []).find(s => s.key === section);
  if (!sec) return {};
  const out = {};
  for (const f of sec.fields) {
    if (!f.editable) continue;
    const look = (S.options.lookups || {})[f.enum] || [];
    const refs = (S.options.refs || {})[f.ref] || [];
    out[f.name] = {
      datetime: nowUtc(), date: nowUtc().slice(0, 10), bool: false, enum: look[0] || "", ref: refs[0] || "",
      longtext: f.required ? "Example created with the API Explorer" : "",
      text: f.required ? (f.name === "text" ? "example-" + Date.now().toString(36) : "example") : "",
    }[f.kind] ?? "";
  }
  return out;
}

function exampleBody(op, values) {
  const key = `${op.method} ${op.path}`;
  const section = values.section || "timeline";
  switch (key) {
    case "POST /api/cases/{case_pk}/sections/{section}": return { data: sectionExample(section) };
    case "POST /api/cases/{case_pk}/sections/{section}/bulk": return { records: [sectionExample(section), sectionExample(section)] };
    case "PATCH /api/cases/{case_pk}/sections/{section}/{recid}": return { changes: { notes: "updated with the API Explorer" }, version: 1 };
    case "POST /api/cases/{case_pk}/sections/{section}/{recid}/delete": return { version: 1 };
    case "PATCH /api/cases/{case_pk}": return { changes: { summary: "Updated with the API Explorer" } };
    case "PATCH /api/cases/{case_pk}/report": return { changes: { conclusions: "Written with the API Explorer.\nSecond line." } };
    case "POST /api/cases": return { case_id: "SANDBOX-" + new Date().toISOString().slice(0, 10), client: "API Explorer sandbox" };
    case "POST /api/cases/{case_pk}/delete": return { confirm: "<exact Case ID>" };
  }
  const rb = op.op.requestBody;
  const schema = rb && rb.content && rb.content["application/json"] && rb.content["application/json"].schema;
  return schema ? sampleFor(schema) : null;
}

function isWrite(op) {
  return op.method !== "GET";
}

function destructiveWarning(op) {
  if (op.method === "DELETE" || op.path.endsWith("/delete")) return "This permanently DELETES live data.";
  if (op.path.endsWith("/replace")) return "This REPLACES ALL DATA of the case (a backup is taken first).";
  if (op.path.endsWith("/import")) return "This creates a new case from the uploaded file.";
  return null;
}

function rawBodyOp(op) { return op.path.endsWith("/import") || op.path.endsWith("/replace"); }

/* ------------------------------------------------------------------ page */

async function renderApiExplorer() {
  const content = document.getElementById("content");
  if (!X.spec) {
    content.replaceChildren(el("div", { class: "empty", text: "Loading API description…" }));
    X.spec = await api("GET", "/api/openapi.json");
    X.schema = await api("GET", "/api/schema");
    X.ops = [];
    for (const [path, item] of Object.entries(X.spec.paths)) {
      for (const [method, op] of Object.entries(item)) {
        const tag = (op.tags || ["other"])[0];
        const sessionOnly = (SESSION_ONLY_TAGS.has(tag) && !(method === "get" && path === "/api/me"))
          || SESSION_ONLY_OPS.has(`${method.toUpperCase()} ${path}`);
        X.ops.push({ id: `${method} ${path}`, method: method.toUpperCase(), path, op, tag, sessionOnly });
      }
    }
  }
  const tagOrder = (X.spec.tags || []).map(t => t.name);
  const list = el("div", { class: "apx-list" });
  const drawList = () => {
    const q = X.filter.toLowerCase();
    list.replaceChildren();
    for (const tag of tagOrder) {
      const ops = X.ops.filter(o => o.tag === tag && (!q || `${o.method} ${o.path} ${o.op.summary || ""}`.toLowerCase().includes(q)));
      if (!ops.length) continue;
      list.append(el("div", { class: "apx-tag", text: tag }));
      for (const o of ops) {
        list.append(el("button", { class: "apx-op" + (X.selected === o.id ? " active" : ""), title: o.op.summary || "",
          onclick: () => { X.selected = o.id; drawList(); drawOp(); } },
          el("span", { class: `apx-m m-${o.method.toLowerCase()}`, text: o.method }),
          el("span", { class: "apx-path", text: o.path }),
          o.sessionOnly ? el("span", { class: "apx-note", text: "session" }) : null));
      }
    }
  };
  const detail = el("div", { class: "apx-detail", id: "apx-detail" });

  // --- authorization bar
  const keyInput = el("input", { type: "text", value: X.token, placeholder: "Paste an API key (aurora_…)",
    oninput: ev => { X.token = ev.target.value.trim(); X.me = null; whoami.textContent = ""; } });
  const keyField = maskSecret(keyInput);      // not type=password: keeps browser password managers out
  const whoami = el("span", { class: "muted" });
  const showMe = () => {
    if (!X.me) return;
    whoami.textContent = X.me.error ? `✗ ${X.me.error}`
      : X.me.api_key ? `✓ API key “${X.me.api_key.name}” · profile ${X.me.api_key.profile}${X.me.api_key.profile === "read" ? " · read-only" : ""}`
      : `✓ ${X.me.user.username} · role ${X.me.user.role}`;
  };
  const check = el("button", { class: "btn small", text: "Check key", onclick: async () => {
    const r = await send("GET", "/api/me");
    X.me = r.ok ? r.json : { error: (r.json && r.json.detail) || `HTTP ${r.status}` };
    showMe();
  } });
  const writes = el("input", { type: "checkbox", checked: X.allowWrites, onchange: ev => {
    X.allowWrites = ev.target.checked; drawOp();
  } });
  const authBar = el("div", { class: "panel apx-auth" },
    el("div", { class: "apx-authrow" }, el("b", { text: "API key" }), keyField, check, el("button", { class: "btn small", text: "Forget", onclick: () => { X.token = ""; X.me = null; keyInput.value = ""; whoami.textContent = ""; } })),
    whoami,
    el("div", { class: "apx-authrow" }, el("label", { class: "check" }, writes,
      "Allow requests that modify data (POST / PATCH / DELETE act on the live case)")),
    el("p", { class: "muted", text: "Requests use only this key (your browser session is not used), so you see exactly what the key may do. The key stays in memory and is forgotten on reload. Tip: use a read-only key to explore safely, or create a sandbox case to try writes. Every change is validated and recorded in the Activity Log as made by the key." }),
    el("p", { class: "muted" }, isAdmin() ? "No key yet? Create one under " : "No key yet? Ask an administrator (Administration → API Keys).",
      isAdmin() ? el("a", { href: "#", text: "Administration → API Keys", onclick: ev => { ev.preventDefault(); navigate("admin_keys"); } }) : null,
      isAdmin() ? "." : null));

  content.replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "API Explorer" }),
      el("span", { class: "muted", text: `${X.ops.length} operations · OpenAPI ${X.spec.openapi} · API ${X.spec.info.version}` })),
    authBar,
    el("div", { class: "apx" },
      el("div", { class: "apx-side" }, el("input", { type: "search", placeholder: "Filter operations…", value: X.filter,
        oninput: ev => { X.filter = ev.target.value; drawList(); } }), list),
      detail));
  showMe();
  if (!X.selected) X.selected = "get /api/cases";
  drawList();
  drawOp();
}

/* ------------------------------------------------------------------ one operation */

function drawOp() {
  const box = document.getElementById("apx-detail");
  if (!box) return;
  const op = X.ops.find(o => o.id === X.selected);
  if (!op) { box.replaceChildren(el("p", { class: "muted", text: "Select an operation." })); return; }
  const inputs = {};
  const params = (op.op.parameters || []).filter(p => p.in === "path" || p.in === "query");
  const values = { case_pk: String(S.caseId || ""), section: S.sections[S.view] ? S.view : "timeline" };

  const paramRows = params.map(p => {
    const sch = resolve(p.schema);
    let input;
    if (p.name === "section") {
      input = el("select");
      for (const s of X.schema.sections) input.append(el("option", { value: s.key, text: s.key, selected: s.key === values.section }));
      input.addEventListener("change", () => { if (!bodyTouched && bodyArea) bodyArea.value = pretty(exampleBody(op, { section: input.value })); });
    } else if (sch.type === "boolean") {
      input = el("select");
      for (const v of ["", "true", "false"]) input.append(el("option", { value: v, text: v || "(default)" }));
    } else if (sch.enum) {
      input = el("select");
      for (const v of [""].concat(sch.enum)) input.append(el("option", { value: v, text: v || "(default)" }));
    } else if (sch.type === "array") {
      input = el("textarea", { rows: 2, placeholder: "one value per line, e.g. event_type:C2" });
    } else {
      input = el("input", { type: "text", value: values[p.name] ?? "", placeholder: sch.default !== undefined && sch.default !== null ? `default: ${sch.default}` : "" });
    }
    inputs[p.name] = { input, p, sch };
    return el("tr", null,
      el("td", null, el("span", { class: "mono", text: p.name }), p.required ? el("span", { class: "req", text: " *" }) : null,
        el("div", { class: "muted", text: `${p.in} · ${sch.type || "string"}` })),
      el("td", null, input, p.description ? el("div", { class: "muted", text: p.description }) : null));
  });

  let bodyArea = null, fileInput = null, bodyTouched = false;
  const hasBody = op.method !== "GET" && op.method !== "DELETE" && (op.op.requestBody || rawBodyOp(op));
  if (hasBody && rawBodyOp(op)) {
    fileInput = el("input", { type: "file", accept: ".fox,application/json" });
  } else if (hasBody) {
    bodyArea = el("textarea", { class: "mono apx-body", rows: 12, spellcheck: false, value: pretty(exampleBody(op, values)),
      oninput: () => { bodyTouched = true; } });
  }

  const resp = el("div", { class: "apx-resp" });
  const curlBox = el("div");
  const sendBtn = el("button", { class: "btn primary", text: "Send request" });
  const gate = el("div", { class: "muted" });
  const refreshGate = () => {
    const w = isWrite(op);
    const blocked = op.sessionOnly || (w && !X.allowWrites);
    sendBtn.disabled = blocked;
    gate.textContent = op.sessionOnly ? "Browser-session operation: API keys are not accepted here (by design). Use the regular pages instead."
      : w && !X.allowWrites ? "This request modifies data. Tick “Allow requests that modify data” above to enable it." : "";
  };
  if (bodyArea) bodyArea.addEventListener("input", refreshGate);

  sendBtn.addEventListener("click", async () => {
    if (!X.token) { resp.replaceChildren(el("div", { class: "banner err", text: "Enter an API key first." })); return; }
    let url = op.path;
    for (const [name, { input, p }] of Object.entries(inputs)) {
      if (p.in === "path") {
        if (!input.value.trim()) { resp.replaceChildren(el("div", { class: "banner err", text: `Path parameter “${name}” is required.` })); return; }
        url = url.replace(`{${name}}`, encodeURIComponent(input.value.trim()));
      }
    }
    const qs = new URLSearchParams();
    for (const [name, { input, p, sch }] of Object.entries(inputs)) {
      if (p.in !== "query") continue;
      if (sch.type === "array") input.value.split("\n").map(v => v.trim()).filter(Boolean).forEach(v => qs.append(name, v));
      else if (input.value.trim() !== "") qs.append(name, input.value.trim());
    }
    if ([...qs].length) url += "?" + qs.toString();
    let body;
    if (fileInput) {
      if (!fileInput.files[0]) { resp.replaceChildren(el("div", { class: "banner err", text: "Choose a .fox file." })); return; }
      body = await fileInput.files[0].text();
    } else if (bodyArea) {
      try { JSON.parse(bodyArea.value); } catch (e) { resp.replaceChildren(el("div", { class: "banner err", text: `Body is not valid JSON: ${e.message}` })); return; }
      body = bodyArea.value;
    }
    const warn = destructiveWarning(op);
    if (warn && !confirm(`${op.method} ${url}\n\n${warn}\n\nSend this request with the API key?`)) return;
    sendBtn.disabled = true;
    resp.replaceChildren(el("p", { class: "muted", text: "Sending…" }));
    curlBox.replaceChildren(codeBlock(curlFor(op.method, url, body, !!fileInput)));
    const r = await send(op.method, url, body);
    showResponse(resp, r);
    refreshGate();
    if (r.ok && op.method !== "GET" && S.caseId) afterWrite().catch(() => {});   // keep the rest of the UI in sync
  });

  const desc = op.op.description ? el("div", { class: "md apx-desc" }, renderMarkdown(op.op.description.trim(), "api.md")) : null;
  const responses = Object.entries(op.op.responses || {}).map(([code, r]) => `${code} ${r.description || ""}`).join(" · ");
  box.replaceChildren(...[    // DOM replaceChildren() would print null as "null": drop absent parts
    el("div", { class: "apx-head" }, el("span", { class: `apx-m m-${op.method.toLowerCase()}`, text: op.method }),
      el("span", { class: "mono apx-title", text: op.path })),
    el("h3", { text: op.op.summary || "" }), desc,
    el("p", { class: "muted", text: `Tag: ${op.tag} · Responses: ${responses}` }),
    params.length ? el("div", null, el("h4", { text: "Parameters" }), el("table", { class: "plain apx-params" }, el("tbody", null, paramRows))) : null,
    hasBody ? el("div", null, el("h4", { text: fileInput ? "Request body (raw .fox file)" : "Request body (JSON)" }),
      fileInput || bodyArea,
      bodyArea ? el("div", { class: "actions-row" },
        el("button", { class: "btn small", text: "Reset example", onclick: () => { bodyArea.value = pretty(exampleBody(op, { section: inputs.section ? inputs.section.input.value : values.section })); bodyTouched = false; refreshGate(); } }),
        el("button", { class: "btn small", text: "Format", onclick: () => { try { bodyArea.value = pretty(JSON.parse(bodyArea.value)); } catch { toast("Body is not valid JSON", true); } } })) : null) : null,
    el("div", { class: "actions-row" }, sendBtn, gate),
    el("h4", { text: "Response" }), resp,
    el("h4", { text: "Equivalent curl" }), curlBox].filter(Boolean));
  refreshGate();
}

const pretty = v => (v === null || v === undefined ? "" : JSON.stringify(v, null, 2));

function curlFor(method, url, body, isFile) {
  const q = s => "'" + String(s).replace(/'/g, "'\\''") + "'";
  let c = `curl -X ${method} -H "Authorization: Bearer $AURORA_KEY"`;
  if (body !== undefined) c += ` -H 'Content-Type: application/json'`;
  if (body !== undefined) c += ` \\\n  --data-binary ${isFile ? "@case.fox" : q(JSON.stringify(JSON.parse(body)))}`;
  return c + ` \\\n  ${q(location.origin + url)}`;
}

/** Send with the API key only (credentials omitted: no session cookie, no CSRF). */
async function send(method, url, body) {
  const headers = { Authorization: `Bearer ${X.token}` };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const t0 = performance.now();
  try {
    const res = await fetch(url, { method, headers, body, credentials: "omit", cache: "no-store", redirect: "error" });
    const ms = Math.round(performance.now() - t0);
    const ct = res.headers.get("content-type") || "";
    const out = { ok: res.ok, status: res.status, statusText: res.statusText, ms, ct, headers: res.headers };
    if (ct.includes("application/json")) { out.text = await res.text(); try { out.json = JSON.parse(out.text); } catch { /* keep text */ } }
    else if (ct.startsWith("text/")) out.text = await res.text();
    else if (res.status !== 202) out.blob = await res.blob();
    return out;
  } catch (e) {
    return { ok: false, status: 0, statusText: "network error", ms: Math.round(performance.now() - t0), text: String(e) };
  }
}

function showResponse(box, r) {
  const cls = r.ok ? "ok" : "bad";
  const hdr = ["content-type", "content-disposition", "x-case-revision", "www-authenticate"]
    .map(h => r.headers && r.headers.get(h) ? `${h}: ${r.headers.get(h)}` : null).filter(Boolean).join("\n");
  const parts = [el("div", { class: `apx-status ${cls}`, text: `${r.status} ${r.statusText || ""} · ${r.ms} ms` })];
  if (hdr) parts.push(el("pre", { class: "json", text: hdr }));
  if (r.blob) {
    const cd = (r.headers && r.headers.get("content-disposition")) || "";
    const m = cd.match(/filename="([^"]+)"/);
    parts.push(el("p", null, `Binary response, ${r.blob.size} bytes `,
      el("button", { class: "btn small", text: "Download", onclick: () => {
        const a = el("a", { href: URL.createObjectURL(r.blob), download: m ? m[1] : "download.bin" });
        document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 10000);
      } })));
  } else {
    let text = r.json !== undefined ? JSON.stringify(r.json, null, 2) : (r.text || (r.status === 202 ? "(202 Accepted, no body)" : ""));
    if (text.length > MAX_SHOW) text = text.slice(0, MAX_SHOW) + `\n… truncated (${text.length} characters total)`;
    parts.push(el("pre", { class: "json apx-out", text }));
  }
  box.replaceChildren(...parts);
}

/** Safe Markdown subset -> DOM nodes (headings, paragraphs, lists, tables, code, quotes, links). No innerHTML. */
function renderMarkdown(src, docName) {
  const lines = src.replace(/\r/g, "").split("\n");
  const out = [];
  let i = 0;
  const isTableSep = l => /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/.test(l);
  const cells = l => l.trim().replace(/^\|/, "").replace(/\|$/, "").split(/(?<!\\)\|/).map(c => c.trim().replace(/\\\|/g, "|"));
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out.push(codeBlock(buf.join("\n")));
      continue;
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    if (h) { out.push(el(`h${Math.min(h[1].length + 1, 5)}`, null, inline(h[2], docName))); i++; continue; }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) { out.push(el("hr")); i++; continue; }
    if (/^\s*\|/.test(line) && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const head = cells(line);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) rows.push(cells(lines[i++]));
      out.push(el("div", { class: "md-table" }, el("table", { class: "plain" },
        el("thead", null, el("tr", null, head.map(c => el("th", null, inline(c, docName))))),
        el("tbody", null, rows.map(r => el("tr", null, r.map(c => el("td", null, inline(c, docName)))))))));
      continue;
    }
    if (/^\s*>/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) buf.push(lines[i++].replace(/^\s*>\s?/, ""));
      out.push(el("blockquote", null, inline(buf.join(" "), docName)));
      continue;
    }
    if (/^\s*([*-]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const list = el(ordered ? "ol" : "ul");
      while (i < lines.length && /^\s*([*-]|\d+\.)\s+/.test(lines[i])) {
        let item = lines[i++].replace(/^\s*([*-]|\d+\.)\s+/, "");
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([*-]|\d+\.)\s+/.test(lines[i])) item += " " + lines[i++].trim();
        list.append(el("li", null, inline(item, docName)));
      }
      out.push(list);
      continue;
    }
    if (!line.trim()) { i++; continue; }
    const buf = [line];
    i++;
    while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|```|\s*\||\s*>|\s*([*-]|\d+\.)\s)/.test(lines[i])) buf.push(lines[i++]);
    out.push(el("p", null, inline(buf.join(" "), docName)));
  }
  return out;
}

function inline(text, docName) {
  const nodes = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[([^\]]+)\]\(([^)\s]+)\))|(_[^_\s][^_]*_)|(\*[^*\s][^*]*\*)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    if (m[1]) nodes.push(el("code", { text: m[1].slice(1, -1) }));
    else if (m[2]) nodes.push(el("b", { text: m[2].slice(2, -2) }));
    else if (m[3]) nodes.push(docLink(m[4], m[5], docName));
    else if (m[6] || m[7]) nodes.push(el("i", { text: (m[6] || m[7]).slice(1, -1) }));
    last = re.lastIndex;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

// Files outside docs/ that the app serves itself (repository path -> app URL)
const APP_LINKS = {};

function docLink(rawLabel, href, docName) {
  const code = /^`.*`$/.test(rawLabel);
  const label = code ? rawLabel.slice(1, -1) : rawLabel;
  const a = (props) => { const n = el("a", props); n.append(code ? el("code", { text: label }) : label); return n; };
  if (/^https?:\/\//i.test(href)) return a({ href, target: "_blank", rel: "noopener noreferrer" });
  const target = href.split("#")[0];
  if (!target) return el("span", { text: label });                            // in-page anchor: plain text
  const base = docName.includes("/") ? docName.slice(0, docName.lastIndexOf("/") + 1) : "";
  const parts = [];
  for (const seg of (base + target).split("/")) { if (seg === "..") parts.pop(); else if (seg && seg !== ".") parts.push(seg); }
  const resolved = parts.join("/");
  if (APP_LINKS[resolved]) return a({ href: APP_LINKS[resolved], download: resolved.split("/").pop() });
  return el("span", { class: "mono", text: label });                           // other docs refs: show as text
}

/** Called on sign-out: drop the key from memory. */
function forgetApiKey() { X.token = ""; X.me = null; X.allowWrites = false; }

Object.assign(window, { renderApiExplorer, forgetApiKey });
})();
