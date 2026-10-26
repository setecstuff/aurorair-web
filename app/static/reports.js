/* Aurora IR Web - reporting views.
 *
 * The Visual Timeline, Lateral Movement and Activity Plot reproduce the reports of
 * Aurora Incident Response (https://github.com/cyb3rfox/Aurora-Incident-Response, Apache-2.0):
 * same inclusion rules (Visual? flag, both hosts, direction), same event-type and system-type
 * colours. The data is read from a read-only snapshot endpoint; nothing here writes
 * to the case or produces a .fox file.
 *
 * Security: all case text reaches the DOM via textContent / DOM nodes (vis items and tooltips
 * receive Elements, never HTML strings). */
"use strict";

// Private scope: only the names app.js needs are exported (see bottom), so nothing here can
// shadow an app.js function of the same name.
(() => {

const REPORT_VIEWS = {
  rep_overview: { label: "Incident Overview", render: renderOverview },
  rep_timeline: { label: "Visual Timeline", render: renderVisualTimeline },
  rep_lateral: { label: "Lateral Movement", render: renderLateral },
  rep_activity: { label: "Activity Plot", render: renderActivityPlot },
};

// Aurora's event-type colours (css/aurora.css + getLateralMovements); "C2" uses Aurora's grey.
const EVENT_COLORS = {
  "EventLog": ["limegreen", "darkseagreen"], "File": ["gold", "goldenrod"], "Human": ["palevioletred", "chocolate"],
  "Engagement": ["lightskyblue", "dimgrey"], "Lateral Movement": ["lightseagreen", "darkcyan"],
  "Exfil": ["plum", "mediumorchid"], "Tanium Trace": ["palevioletred", "darkred"], "Malware": ["firebrick", "darkred"],
  "eMail": ["dodgerblue", "darkslateblue"], "Misc": ["darksalmon", "indianred"], "C2": ["#9e9e9e", "#6d6d6d"],
};
const DEFAULT_EVENT_COLOR = ["#cccccc", "#999999"];
// Aurora's CSS class per event type (timeline2vis); styled in style.css
const EVENT_CLASS = {
  "EventLog": "log", "File": "file", "Human": "human", "Engagement": "engagement", "Lateral Movement": "lateral",
  "Exfil": "exfil", "Tanium Trace": "tanium", "Malware": "malware", "eMail": "email", "Misc": "misc", "C2": "c2",
};
// Aurora's lateral-movement node groups (FontAwesome icon colours), drawn here as inline SVG.
const SYSTEM_COLORS = {
  "Desktop": "cadetblue", "Server": "coral", "Phone": "crimson", "Tablet": "blueviolet", "TV": "darkgoldenrod",
  "Networking device": "darkblue", "IoT device": "darkorchid", "Other": "dimgray", "Attacker Infra": "ATTACKER",
};
const ICONS = {
  "Desktop": '<rect x="12" y="14" width="40" height="26" rx="3" fill="none" stroke="C" stroke-width="5"/><path d="M4 46h56l-4 6H8z" fill="C"/>',
  "Server": '<rect x="10" y="8" width="44" height="13" rx="2" fill="C"/><rect x="10" y="25" width="44" height="13" rx="2" fill="C"/><rect x="10" y="42" width="44" height="13" rx="2" fill="C"/><circle cx="46" cy="14.5" r="2.5" fill="#fff"/><circle cx="46" cy="31.5" r="2.5" fill="#fff"/><circle cx="46" cy="48.5" r="2.5" fill="#fff"/>',
  "Phone": '<rect x="20" y="6" width="24" height="52" rx="4" fill="none" stroke="C" stroke-width="5"/><circle cx="32" cy="50" r="3" fill="C"/>',
  "Tablet": '<rect x="12" y="6" width="40" height="52" rx="5" fill="none" stroke="C" stroke-width="5"/><circle cx="32" cy="50" r="3" fill="C"/>',
  "TV": '<rect x="6" y="10" width="52" height="34" rx="3" fill="none" stroke="C" stroke-width="5"/><path d="M24 54h16M32 44v10" stroke="C" stroke-width="5"/>',
  "Networking device": '<path d="M18 48a12 12 0 0 1 0-24 15 15 0 0 1 28-4 12 12 0 0 1 2 28z" fill="C"/>',
  "IoT device": '<rect x="16" y="16" width="32" height="32" rx="3" fill="C"/><path d="M22 8v8M32 8v8M42 8v8M22 48v8M32 48v8M42 48v8M8 22h8M8 32h8M8 42h8M48 22h8M48 32h8M48 42h8" stroke="C" stroke-width="4"/>',
  "Other": '<path d="M22 6v14M42 6v14" stroke="C" stroke-width="5"/><path d="M14 20h36v10a18 18 0 0 1-36 0z" fill="C"/><path d="M32 48v12" stroke="C" stroke-width="5"/>',
  "Attacker Infra": '<path d="M14 26h36l-6-16-12 4-12-4z" fill="C"/><path d="M8 28h48" stroke="C" stroke-width="4"/><circle cx="24" cy="36" r="5" fill="none" stroke="C" stroke-width="3"/><circle cx="40" cy="36" r="5" fill="none" stroke="C" stroke-width="3"/><path d="M29 36h6" stroke="C" stroke-width="3"/><path d="M12 60c2-10 10-14 20-14s18 4 20 14z" fill="C"/>',
};
const HOURS = Array.from({ length: 24 }, (_, h) => `${String(h).padStart(2, "0")}:00`);

const R = { data: null, revision: null, timeline: null, network: null, charts: [], vendorLoaded: null };

/* ------------------------------------------------------------------ plumbing */

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src; s.onload = resolve; s.onerror = () => reject(new Error("Failed to load " + src));
    document.head.append(s);
  });
}
function loadCss(href) {
  const l = document.createElement("link");
  l.rel = "stylesheet"; l.href = href;
  document.head.append(l);
}
function loadVendor() {
  if (!R.vendorLoaded) {
    loadCss("vendor/vis-timeline-graph2d.min.css");
    loadCss("vendor/vis-network.min.css");
    R.vendorLoaded = (async () => {
      await loadScript("vendor/moment.min.js");
      await loadScript("vendor/vis-data.min.js");
      await loadScript("vendor/vis-timeline-graph2d.min.js");
      await loadScript("vendor/vis-network.min.js");
      await loadScript("vendor/chart.umd.min.js");
    })();
  }
  return R.vendorLoaded;
}

function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

function destroyReport() {
  if (R.timeline) { R.timeline.destroy(); R.timeline = null; }
  if (R.network) { R.network.destroy(); R.network = null; }
  for (const c of R.charts) c.destroy();
  R.charts = [];
}

async function fetchReportData() {
  R.data = await api("GET", `/api/cases/${S.caseId}/report-data`);
  R.revision = R.data.revision;
  return R.data;
}

/** Called by app.js for every report view (initial render and live refresh). */
async function renderReport(view, fromPoll) {
  const def = REPORT_VIEWS[view];
  const content = document.getElementById("content");
  if (!fromPoll) {
    destroyReport();
    content.replaceChildren(el("div", { class: "empty", text: "Loading report…" }));
  }
  await loadVendor();
  await fetchReportData();
  if (S.view !== view) return;          // user navigated away while loading
  await def.render(content, fromPoll);
}

const parseUtc = s => (s ? moment.utc(s, "YYYY-MM-DD HH:mm:ss", true) : null);
const evColor = t => EVENT_COLORS[t] || DEFAULT_EVENT_COLOR;
const sysByName = () => new Map(R.data.sections.systems.map(s => [s.text, s]));

function reportHeader(title, subtitle, controls) {
  const m = R.data.meta;
  return el("div", { class: "rep-head" },
    el("div", null,
      el("h2", { text: title }),
      el("div", { class: "muted", text: `${m.case_id}${m.client ? " · " + m.client : ""} · revision ${R.data.revision} · live` }),
      subtitle ? el("p", { class: "rep-sub", text: subtitle }) : null),
    el("div", { class: "rep-controls" }, controls || [], el("button", { class: "btn small no-print", text: "Print", onclick: () => window.print() })));
}

function checkbox(label, checked, onchange) {
  const c = el("input", { type: "checkbox", checked, onchange: ev => onchange(ev.target.checked) });
  return el("label", { class: "check" }, c, label);
}

function eventLegend(types) {
  return el("div", { class: "legend" }, types.map(t => el("span", { class: "legend-item" },
    swatch(evColor(t)[0], evColor(t)[1]), t)));
}
function swatch(bg, border) {
  const s = el("span", { class: "swatch" });
  s.style.background = bg; s.style.borderColor = border;
  return s;
}

function detailPanel() {
  return el("div", { class: "panel rep-detail", id: "rep-detail" }, el("p", { class: "muted", text: "Click an event to see its details." }));
}
function showEventDetail(ev) {
  const box = document.getElementById("rep-detail");
  if (!box) return;
  const rows = [
    ["Date/Time (UTC)", ev.date_time], ["Type", ev.event_type], ["Event system", ev.event_host],
    ["Direction", ev.direction], ["Remote system", ev.event_source_host], ["Killchain", ev.killchain],
    ["Event", ev.event_data], ["Notes", ev.notes], ["Attribution", ev.attribution], ["Owner", ev.owner],
  ].filter(([, v]) => v !== undefined && v !== null && v !== "");
  box.replaceChildren(el("h3", { text: `Timeline event #${ev.recid}` }),
    el("table", { class: "plain" }, el("tbody", null, rows.map(([k, v]) => el("tr", null, el("th", { text: k }), el("td", { class: "wrap", text: String(v) }))))));
}

/* ------------------------------------------------------------------ visual timeline (Aurora: timeline2vis) */

const TL = { onlyVisual: true, hidden: new Set() };

function timelineItems() {
  const items = [];
  for (const ev of R.data.sections.timeline) {
    if (TL.onlyVisual && !ev.visual) continue;
    const start = parseUtc(ev.date_time);
    if (!start || !start.isValid()) continue;          // Aurora: no timestamp, no item
    if (TL.hidden.has(ev.event_type || "")) continue;
    const host = ev.event_host || "N/A", src = ev.event_source_host || "N/A";
    const arrow = ev.direction === "<-" ? " ← " : ev.direction === "->" ? " → " : " | ";
    const content = el("div", { class: "tl-item" },
      el("div", null, ev.event_type ? el("b", { text: `[${ev.event_type}] ` }) : null, host + arrow + src),
      el("small", { text: ev.event_data || "" }));
    items.push({ id: ev.recid, content, start: start.toDate(), className: "aurora " + (EVENT_CLASS[ev.event_type] || "other") });
  }
  return items;
}

async function renderVisualTimeline(content, fromPoll) {
  const items = timelineItems();
  if (fromPoll && R.timeline) {
    R.timeline.setItems(new vis.DataSet(items));
    return;
  }
  destroyReport();
  const types = [...new Set(R.data.sections.timeline.map(e => e.event_type || ""))].filter(Boolean).sort();
  const legend = el("div", { class: "legend" }, types.map(t => {
    const item = el("button", { class: "legend-item toggle" + (TL.hidden.has(t) ? " off" : ""), title: "Show / hide this event type",
      onclick: () => { TL.hidden.has(t) ? TL.hidden.delete(t) : TL.hidden.add(t); renderReport("rep_timeline"); } },
      swatch(...evColor(t)), t);
    return item;
  }));
  const graph = el("div", { class: "rep-graph", id: "graph" });
  content.replaceChildren(
    reportHeader("Visual Timeline", "Timeline events placed on a UTC time axis. Drag to pan, scroll to zoom, click an event for details.",
      [checkbox("Only events marked “Visual?”", TL.onlyVisual, v => { TL.onlyVisual = v; renderReport("rep_timeline"); }),
       el("button", { class: "btn small", text: "Fit", onclick: () => R.timeline && R.timeline.fit() })]),
    legend, graph, detailPanel());
  if (!items.length) {
    graph.replaceChildren(el("div", { class: "empty" }, el("h3", { text: "No events to display" }),
      el("p", { text: "Add events with a date/time in the Timeline and tick “Visual?” to show them here." })));
    return;
  }
  R.timeline = new vis.Timeline(graph, new vis.DataSet(items), {
    moment: d => moment(d).utc(),
    stack: true, zoomKey: "", horizontalScroll: false, orientation: { axis: "bottom" },
    margin: { item: { horizontal: 6, vertical: 8 } }, maxHeight: 720, minHeight: 360, verticalScroll: true,
    selectable: true, showCurrentTime: false, xss: { disabled: false },
  });
  R.timeline.on("select", props => {
    const ev = R.data.sections.timeline.find(e => e.recid === props.items[0]);
    if (ev) showEventDetail(ev);
  });
}

/* ------------------------------------------------------------------ lateral movement (Aurora: getLateralMovements) */

const LM = { onlyVisual: true, physics: false };

function iconUri(type) {
  const t = ICONS[type] ? type : "Other";
  let c = SYSTEM_COLORS[t];
  if (c === "ATTACKER") c = cssVar("--text") || "#000";
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">${ICONS[t].replaceAll('"C"', `"${c}"`)}</svg>`;
  return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
}

function lateralData() {
  const systems = sysByName();
  const hosts = new Map();      // host -> node id
  const nodes = [], edges = [];
  const pairCount = new Map();
  const nodeId = host => {
    if (!hosts.has(host)) {
      const sys = systems.get(host);
      const type = sys && sys.system_type ? sys.system_type : "Other";
      const id = hosts.size;
      hosts.set(host, id);
      nodes.push({ id, label: `${host}\n${(sys && sys.ip) || "N/A"}`, shape: "image", image: iconUri(type), size: 22, group: type, title: nodeTooltip(host, sys) });
    }
    return hosts.get(host);
  };
  for (const ev of R.data.sections.timeline) {
    if (!ev.event_host || !ev.event_source_host) continue;     // both hosts required
    if (LM.onlyVisual && !ev.visual) continue;                 // Aurora: only "Visual?" events
    const a = nodeId(ev.event_host), b = nodeId(ev.event_source_host);
    const [from, to] = ev.direction === "->" ? [a, b] : [b, a]; // Aurora: anything but "->" is remote -> event host
    const key = [Math.min(from, to), Math.max(from, to)].join("-");
    const k = pairCount.get(key) || 0;
    pairCount.set(key, k + 1);
    edges.push({
      id: ev.recid, from, to, arrows: { to: { enabled: true, type: "arrow", scaleFactor: 0.7 } }, width: 3,
      color: { color: evColor(ev.event_type)[0], highlight: evColor(ev.event_type)[1], hover: evColor(ev.event_type)[1] },
      smooth: { enabled: true, type: k % 2 ? "curvedCCW" : "curvedCW", roundness: 0.12 + 0.12 * Math.floor(k / 2) },
      title: edgeTooltip(ev),
    });
  }
  return { nodes, edges };
}

function nodeTooltip(host, sys) {
  return el("div", { class: "vis-tip" }, el("b", { text: host }),
    sys ? el("div", { text: [sys.system_type, sys.ip, sys.os, sys.description].filter(Boolean).join(" · ") }) : null);
}
function edgeTooltip(ev) {
  return el("div", { class: "vis-tip" }, el("b", { text: `[${ev.event_type || "?"}] ` }), ev.date_time || "",
    el("div", { text: ev.event_data || "" }));
}

async function renderLateral(content, fromPoll) {
  const data = lateralData();
  if (fromPoll && R.network) {
    R.network.setData({ nodes: new vis.DataSet(data.nodes), edges: new vis.DataSet(data.edges) });
    return;
  }
  destroyReport();
  const graph = el("div", { class: "rep-graph tall", id: "graph" });
  const usedTypes = [...new Set(R.data.sections.timeline.filter(e => e.event_host && e.event_source_host).map(e => e.event_type).filter(Boolean))].sort();
  const sysTypes = [...new Set(data.nodes.map(n => n.group))].sort();
  content.replaceChildren(
    reportHeader("Lateral Movement", "Systems connected by timeline events that name both an event system and a remote system. Arrows follow the ⇄ direction. Drag nodes to rearrange, hover for details, click an arrow for the event.",
      [checkbox("Only events marked “Visual?”", LM.onlyVisual, v => { LM.onlyVisual = v; renderReport("rep_lateral"); }),
       checkbox("Physics layout", LM.physics, v => { LM.physics = v; if (R.network) R.network.setOptions({ physics: { enabled: v } }); }),
       el("button", { class: "btn small", text: "Fit", onclick: () => R.network && R.network.fit({ animation: true }) })]),
    el("div", { class: "legend" }, el("span", { class: "muted", text: "Edges:" }), usedTypes.map(t => el("span", { class: "legend-item" }, swatch(...evColor(t)), t)),
      el("span", { class: "muted", text: "  Systems:" }), sysTypes.map(t => el("span", { class: "legend-item" }, el("img", { src: iconUri(t), alt: "", class: "legend-icon" }), t))),
    graph, detailPanel());
  if (!data.nodes.length) {
    graph.replaceChildren(el("div", { class: "empty" }, el("h3", { text: "No events to display" }),
      el("p", { text: "Add timeline events with both an Event System and a Remote System and tick “Visual?” to show them here." })));
    return;
  }
  R.network = new vis.Network(graph, { nodes: new vis.DataSet(data.nodes), edges: new vis.DataSet(data.edges) }, {
    physics: { enabled: LM.physics, solver: "forceAtlas2Based", stabilization: { iterations: 200 } },
    layout: { improvedLayout: true, randomSeed: 7 },
    interaction: { hover: true, tooltipDelay: 120, navigationButtons: false, keyboard: false },
    nodes: { font: { size: 13, color: cssVar("--text") || "#222", multi: false }, shapeProperties: { useImageSize: false } },
    edges: { selectionWidth: 2, hoverWidth: 1.5 },
  });
  R.network.once("afterDrawing", () => R.network.fit());
  R.network.on("click", params => {
    if (params.edges.length && !params.nodes.length) {
      const ev = R.data.sections.timeline.find(e => e.recid === params.edges[0]);
      if (ev) showEventDetail(ev);
    }
  });
}

/* ------------------------------------------------------------------ activity plot (Aurora: getActivity) */

const AP = { includeEngagement: false, onlyVisual: false };

function activityBuckets() {
  const buckets = new Array(24).fill(0);
  for (const ev of R.data.sections.timeline) {
    if (!AP.includeEngagement && ev.event_type === "Engagement") continue;   // not attacker activity
    if (AP.onlyVisual && !ev.visual) continue;
    const m = /^\d{4}-\d{2}-\d{2} (\d{2}):/.exec(ev.date_time || "");
    if (m) buckets[Number(m[1])]++;
  }
  return buckets;
}

function chartTheme() {
  return { text: cssVar("--muted") || "#666", grid: cssVar("--border") || "#ddd", series: cssVar("--series-1") || "#2a78d6" };
}

function barChart(canvas, labels, values, label, opts = {}) {
  const th = chartTheme();
  const chart = new Chart(canvas, {
    type: "bar",
    data: { labels, datasets: [{ label, data: values, backgroundColor: th.series, hoverBackgroundColor: th.series + "cc",
      borderRadius: { topLeft: 4, topRight: 4, bottomLeft: 0, bottomRight: 0 }, borderSkipped: "start", maxBarThickness: 24,
      ...(opts.horizontal ? { borderRadius: { topRight: 4, bottomRight: 4, topLeft: 0, bottomLeft: 0 } } : {}) }] },
    options: {
      indexAxis: opts.horizontal ? "y" : "x", responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: false }, tooltip: { displayColors: false, callbacks: { label: c => `${c.parsed[opts.horizontal ? "x" : "y"]} event(s)` } } },
      scales: {
        [opts.horizontal ? "x" : "y"]: { beginAtZero: true, ticks: { precision: 0, color: th.text }, grid: { color: th.grid, lineWidth: 1 }, border: { display: false } },
        [opts.horizontal ? "y" : "x"]: { ticks: { color: th.text, autoSkip: !opts.horizontal, maxRotation: 0 }, grid: { display: false }, border: { color: th.grid } },
      },
    },
  });
  R.charts.push(chart);
  return chart;
}

function dataTable(headers, rows) {
  return el("table", { class: "plain" }, el("thead", null, el("tr", null, headers.map(h => el("th", { text: h })))),
    el("tbody", null, rows.map(r => el("tr", null, r.map(c => el("td", { class: "wrap", text: String(c ?? "") }))))));
}

async function renderActivityPlot(content, fromPoll) {
  const buckets = activityBuckets();
  const tableWasOpen = !!(document.getElementById("ap-table") && !document.getElementById("ap-table").hidden);
  destroyReport();
  const total = buckets.reduce((a, b) => a + b, 0);
  const canvas = el("canvas", { "aria-label": "Events per hour of day", role: "img" });
  const table = el("div", { id: "ap-table", hidden: !tableWasOpen }, dataTable(["Hour (UTC)", "Events"], HOURS.map((h, i) => [`${h}–${HOURS[(i + 1) % 24]}`, buckets[i]])));
  const peak = buckets.indexOf(Math.max(...buckets));
  content.replaceChildren(
    reportHeader("Activity Plot", "Activity distribution over the time of day: number of timeline events per UTC hour. Engagement-management events are excluded by default because they are not attacker activity.",
      [checkbox("Include “Engagement” events", AP.includeEngagement, v => { AP.includeEngagement = v; renderReport("rep_activity"); }),
       checkbox("Only events marked “Visual?”", AP.onlyVisual, v => { AP.onlyVisual = v; renderReport("rep_activity"); }),
       el("button", { class: "btn small", text: "Table view", onclick: () => { table.hidden = !table.hidden; } })]),
    el("div", { class: "panel" },
      el("h3", { text: "Activity distribution (time of day, UTC)" }),
      el("p", { class: "muted", text: total ? `${total} events · busiest hour ${HOURS[peak]}–${HOURS[(peak + 1) % 24]} (${buckets[peak]} events)` : "No timestamped events." }),
      el("div", { class: "chart-box" }, canvas), table));
  barChart(canvas, HOURS, buckets, "Events");
}

/* ------------------------------------------------------------------ incident overview */

function statTile(label, value, note) {
  const compact = value.length > 10;    // timestamps: smaller so they never wrap
  return el("div", { class: "stat" }, el("div", { class: "stat-label", text: label }), el("div", { class: "stat-value" + (compact ? " compact" : ""), text: value }),
    note ? el("div", { class: "stat-note", text: note }) : null);
}

function fmtSpan(a, b) {
  const d = b.diff(a, "minutes");
  if (d < 60) return `${d} min`;
  if (d < 48 * 60) return `${Math.round(d / 60)} h`;
  return `${Math.round(d / 1440)} days`;
}

async function renderOverview(content) {
  destroyReport();
  const sec = R.data.sections, m = R.data.meta;
  const attackerEvents = sec.timeline.filter(e => e.event_type !== "Engagement");
  const times = attackerEvents.map(e => parseUtc(e.date_time)).filter(t => t && t.isValid()).sort((a, b) => a - b);
  const first = times[0], last = times[times.length - 1];
  const compromised = sec.investigated_systems.filter(s => ["Infected", "Accessed"].includes(s.verdict));
  const involvedHosts = new Set(sec.timeline.flatMap(e => [e.event_host, e.event_source_host]).filter(Boolean));
  const attackerInfra = sec.systems.filter(s => s.system_type === "Attacker Infra");

  const tiles = el("div", { class: "stats" },
    statTile("Timeline events", String(sec.timeline.length), `${sec.timeline.filter(e => e.visual).length} marked visual`),
    statTile("First attacker activity", first ? first.format("YYYY-MM-DD HH:mm") : "—", "UTC"),
    statTile("Last recorded activity", last ? last.format("YYYY-MM-DD HH:mm") : "—", first && last ? `UTC · span ${fmtSpan(first, last)}` : "UTC"),
    statTile("Systems involved", String(involvedHosts.size), `${sec.investigated_systems.length} investigated · ${compromised.length} infected/accessed`),
    statTile("Compromised accounts", String(sec.compromised_accounts.length)),
    statTile("Malware / tools", String(sec.malware.length)),
    statTile("Network indicators", String(sec.network_indicators.length), `${attackerInfra.length} attacker-infra systems`),
    statTile("Exfiltration events", String(sec.exfiltration.length)));

  // Kill-chain coverage (ordinal stages, single series)
  const kc = (R.data.lookups.killchain || []);
  const kcCounts = kc.map(k => sec.timeline.filter(e => e.killchain === k).length);
  const kcCanvas = el("canvas", { role: "img", "aria-label": "Timeline events per kill-chain phase" });
  // Events per day
  const perDay = new Map();
  for (const t of times) { const d = t.format("YYYY-MM-DD"); perDay.set(d, (perDay.get(d) || 0) + 1); }
  const days = [];
  if (first) for (let d = first.clone().startOf("day"); !d.isAfter(last, "day"); d.add(1, "day")) days.push(d.format("YYYY-MM-DD"));
  const dayCanvas = el("canvas", { role: "img", "aria-label": "Attacker events per day" });

  const keyEvents = [...sec.timeline].filter(e => e.date_time).sort((a, b) => a.date_time.localeCompare(b.date_time));

  content.replaceChildren(
    reportHeader("Incident Overview", null),
    el("div", { class: "panel" },
      el("h3", { text: `${m.case_id}${m.client ? " — " + m.client : ""}` }),
      el("p", { class: "muted", text: m.start_date ? `Engagement start ${m.start_date}` : "" }),
      el("p", { class: "wrap", text: m.summary || "No case summary yet (Case Details)." })),
    tiles,
    el("div", { class: "rep-grid" },
      el("div", { class: "panel" }, el("h3", { text: "Kill-chain coverage" }), el("p", { class: "muted", text: "Timeline events per phase" }),
        el("div", { class: "chart-box short" }, kcCanvas)),
      el("div", { class: "panel" }, el("h3", { text: "Attacker events per day" }), el("p", { class: "muted", text: "Engagement events excluded · UTC days" }),
        el("div", { class: "chart-box short" }, dayCanvas))),
    el("div", { class: "panel" }, el("h3", { text: "Investigated systems" }),
      dataTable(["Hostname", "Verdict", "First compromise (UTC)", "Status", "Analyst", "Summary"],
        sec.investigated_systems.map(s => [s.hostname, s.verdict, s.first_compromise, s.analysis_status, s.analyst, s.summary]))),
    el("div", { class: "panel" }, el("h3", { text: "Compromised accounts" }),
      dataTable(["Account", "Domain", "SID", "Context"], sec.compromised_accounts.map(a => [a.account_name, a.domain, a.sid, a.context]))),
    el("div", { class: "panel" }, el("h3", { text: "Exfiltration" }),
      dataTable(["Exfil time (UTC)", "Staging system", "Exfiltrated to", "File", "Contents"], sec.exfiltration.map(x => [x.exfiltime, x.stagingsystem, x.exfil_to, x.filename, x.contents]))),
    el("div", { class: "panel" }, el("h3", { text: "Network indicators" }),
      dataTable(["IP", "Domain", "Port", "Context"], sec.network_indicators.map(n => [n.ip, n.domainname, n.port, n.context]))),
    el("div", { class: "panel" }, el("h3", { text: "Malware / tools" }),
      dataTable(["File", "Host", "Path", "Hash", "Notes"], sec.malware.map(x => [x.text, x.hostname, x.path_on_disk, x.md5, x.notes]))),
    el("div", { class: "panel" }, el("h3", { text: "Chronology" }),
      dataTable(["Date/Time (UTC)", "Type", "System", "⇄", "Remote", "Killchain", "Event"],
        keyEvents.map(e => [e.date_time, e.event_type, e.event_host, e.direction, e.event_source_host, e.killchain, e.event_data]))));
  barChart(kcCanvas, kc, kcCounts, "Events", { horizontal: true });
  barChart(dayCanvas, days, days.map(d => perDay.get(d) || 0), "Events");
}

/* ------------------------------------------------------------------ about & credits */

function renderAbout() {
  const a = (href, text) => el("a", { href, target: "_blank", rel: "noopener noreferrer", text });
  document.getElementById("content").replaceChildren(
    el("div", { class: "toolbar" }, el("h2", { text: "About & Credits" })),
    el("div", { class: "panel about" },
      el("h3", { text: "Aurora IR Web" }),
      el("p", null, "Aurora IR Web lets an incident-response team document a case together from their browsers, with live updates and a REST API. Cases export to Excel, PDF, LaTeX and the .fox file the Aurora desktop application opens."),
      el("p", null, "It is an independent community project. It is not part of, affiliated with or endorsed by the Aurora Incident Response project or its authors. Please report issues with Aurora IR Web to its own maintainers, not to the Aurora project."),
      el("p", null, "Aurora IR Web is © 2026–present the Aurora IR Web contributors, and licensed under the ", a("https://www.apache.org/licenses/LICENSE-2.0", "Apache License 2.0"),
        ". Source code and issue tracker: ", a("https://github.com/setecstuff/aurorair-web", "github.com/setecstuff/aurorair-web"), "."),
      el("h3", { text: "Credit: Aurora Incident Response" }),
      el("p", null, a("https://github.com/cyb3rfox/Aurora-Incident-Response", "Aurora Incident Response"),
        " is the original project, created by ", el("b", { text: "Mathias Fuchs" }), " (", a("https://cyberfox.blog", "cyb3rfox / cyberfox.blog"),
        ") and its contributors, “developed by Incident Responders for Incident Responders”. All credit for the tool goes to them: the case-file format, the data model, the investigation and case-management sections and their layout, the organization of the screens and menus, and the Visual Timeline, Lateral Movement and Activity Plot reports that Aurora IR Web builds on are their work. Thank you for an amazing tool."),
      el("p", null, "Aurora Incident Response is © 2018–2021 Mathias Fuchs and licensed under the ", a("https://www.apache.org/licenses/LICENSE-2.0", "Apache License 2.0"),
        ". A copy is included with this application (", a("vendor/licenses/aurora-LICENSE-APACHE-2.0.txt", "LICENSE"), "). Get the original desktop application for Windows, macOS and Linux from the ",
        a("https://github.com/cyb3rfox/Aurora-Incident-Response/releases", "Aurora releases page"), "."),
      el("h3", { text: "Third-party components" }),
      el("ul", null,
        el("li", null, a("https://visjs.github.io/vis-timeline/", "vis-timeline"), ", ", a("https://visjs.github.io/vis-network/", "vis-network"), ", vis-data: © Almende B.V. and vis.js contributors, Apache-2.0 / MIT (the libraries Aurora uses for its reports)"),
        el("li", null, a("https://www.chartjs.org", "Chart.js"), ": © Chart.js contributors, MIT"),
        el("li", null, a("https://momentjs.com", "Moment.js"), ": © JS Foundation and other contributors, MIT")),
      el("p", { class: "muted" }, "License texts are in ", el("span", { class: "mono", text: "vendor/licenses/" }), ".")));
}

Object.assign(window, { REPORT_VIEWS, renderReport, destroyReport, renderAbout });
})();
