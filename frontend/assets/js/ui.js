// DOM helpers. Rule: sample-derived text only ever reaches the page through text nodes (never innerHTML).

export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "data") for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = dv;
    else el.setAttribute(k, v === true ? "" : v);
  }
  add(el, kids);
  return el;
}

function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === undefined || k === null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

export function svg(tag, attrs, ...kids) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== undefined && v !== null) el.setAttribute(k, v);
  for (const k of kids.flat()) if (k !== undefined && k !== null) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return el;
}

export function clear(el) { while (el.firstChild) el.firstChild.remove(); return el; }

// ---------------------------------------------------------------- formatting (all UTC, format chosen in settings)
const pad = (n, w = 2) => String(Math.floor(n)).padStart(w, "0");
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export const DATE_FORMATS = {
  short: "Nov 11, 15:20",
  seconds: "Nov 11, 15:20:05",
  iso: "2026-11-11 15:20",
  full: "2026-11-11 15:20:05",
};
export function fmt(ts, withSeconds = false) {
  if (ts == null || ts === "") return "";
  const d = new Date(ts * 1000);
  const mode = store.get("datefmt", "short");
  const hm = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  const sec = `:${pad(d.getUTCSeconds())}`;
  if (mode === "iso" || mode === "full") {
    const day = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    return `${day} ${hm}${mode === "full" || withSeconds ? sec : ""}`;
  }
  return `${MONTHS[d.getUTCMonth()]} ${pad(d.getUTCDate())}, ${hm}${mode === "seconds" || withSeconds ? sec : ""}`;
}
export function fmtS(ts) { return fmt(ts, true); }
export function isoZ(ts) { return ts == null ? "" : new Date(ts * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"); }
export function dur(sec) {
  if (sec == null) return "";
  if (sec < 60) return `${Math.round(sec)}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${pad(sec % 60)}s`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ${pad((sec % 3600) / 60)}m`;
  return `${Math.floor(sec / 86400)}d ${Math.floor((sec % 86400) / 3600)}h`;
}
export function ago(ts) {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  return s < 10 ? "just now" : `${dur(s)} ago`;
}
export function into(ts, start) { return ts == null || start == null ? "" : `${dur(Math.max(0, ts - start))} into the session`; }
export function bytes(n) {
  if (n == null) return "";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return i ? `${n.toFixed(1)} ${u[i]}` : `${n} B`;
}
export function defangHost(v) {
  if (!v) return v;
  if (v.includes(":") && !v.includes(".")) { const i = v.lastIndexOf(":"); return v.slice(0, i) + "[:]" + v.slice(i + 1); }
  const i = v.lastIndexOf(".");
  return i < 0 ? v : v.slice(0, i) + "[.]" + v.slice(i + 1);
}
export function defangDest(dest) {
  if (!dest) return dest;
  const m = /^(\[?[^\]]+\]?):(\d+)$/.exec(dest);
  return m ? `${defangHost(m[1])}:${m[2]}` : defangHost(dest);
}
export function defangUrl(u) {
  if (!u) return u;
  const v = u.replace(/^http/i, "hxxp");
  const m = /^([\w+.-]+:\/\/)([^/:?#\[]+|\[[^\]]+\])(.*)$/.exec(v);
  return m ? m[1] + defangHost(m[2]) + m[3] : v;
}
// Defang addresses inside free text (findings, beacons): URLs first, then bare IPv4 and host:port.
export function defangText(t) {
  if (!t) return t;
  return t.replace(/\b(?:https?|wss?|ftp):\/\/[^\s'"<>]+/gi, u => defangUrl(u))
    .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\b/g, "$1[.]$2")
    .replace(/\b((?:[a-z0-9-]+\.)+)(com|net|org|io|app|dev|xyz|top|ru|cn|info|biz|cc|me|co|site|online|link|live|vercel|pages|example)\b(?![.\w])/gi,
      (m, a, b) => a.slice(0, -1) + "[.]" + b);
}
export function bar(frac, width = 16) {
  const n = Math.max(0, Math.min(width, Math.round(frac * width)));
  return h("span", { class: "bar" }, "|".repeat(n), h("i", {}, "·".repeat(width - n)));
}

// ---------------------------------------------------------------- small components
// Severity is shown by colour only (the row edge and the text); the word stays in the filters and the drawer.
export function sev(level) { return h("span", { class: `sev ${level}` }, level === "medium" ? "medium" : level); }
export function hx(text, title) { return h("span", { class: "hx", title: title || text }, text); }
export function tag(text, cls = "") { return h("span", { class: `tag ${cls}` }, text); }
export function btn(label, onclick, opts = {}) {
  return h("button", { class: `btn ${opts.cls || ""}`, onclick, title: opts.title, type: "button", disabled: opts.disabled }, label);
}
// A row of joined buttons: actions that belong together.
export function grp(...buttons) { return h("span", { class: "grp" }, buttons.flat().filter(Boolean)); }
// One choice out of a few, as joined buttons.
export function seg(options, value, onChange, label) {
  const g = h("span", { class: "grp seg", role: "group", "aria-label": label || "choice" });
  for (const [v, l] of options) {
    g.append(h("button", { type: "button", class: `btn ${v === value ? "on" : ""}`, "aria-pressed": String(v === value),
      onclick: () => onChange(v) }, l));
  }
  return g;
}

// Every panel folds: click its title. The state is kept per panel in this browser.
export function panel(id, title, opts = {}, ...kids) {
  const key = `fold.${id}`;
  let collapsed = store.get(key, !!opts.collapsed);
  const body = h("div", { class: "pbody" }, kids);
  const tools = opts.tools && [opts.tools].flat().filter(Boolean).length ? h("div", { class: "tools" }, opts.tools) : null;
  const caret = h("span", { class: "caret", "aria-hidden": "true" });
  const head = h("button", { type: "button", class: "ph", "aria-expanded": String(!collapsed) },
    caret, h("span", { class: "pt" }, title), opts.count != null ? h("span", { class: "n" }, `[${opts.count}]`) : null);
  const el = h("section", { class: `box ${opts.cls || ""} ${collapsed ? "collapsed" : ""}`, data: { panel: id } },
    h("h2", {}, head), tools, body);
  head.addEventListener("click", () => {
    collapsed = !collapsed;
    store.set(key, collapsed);
    el.classList.toggle("collapsed", collapsed);
    head.setAttribute("aria-expanded", String(!collapsed));
  });
  return el;
}
export function notice(text, cls = "") { return text ? h("div", { class: `notice ${cls}` }, text) : null; }
export function empty(art, title, text, ...actions) {
  return h("div", { class: "empty" }, art ? h("pre", {}, art) : null, h("div", {}, h("b", {}, title)),
    text ? h("div", {}, text) : null, actions.length ? h("div", { class: "acts" }, actions) : null);
}
export function kv(pairs) {
  const dl = h("dl", { class: "kv" });
  for (const [k, v] of pairs) if (v !== undefined && v !== null && v !== "") dl.append(h("dt", {}, k), h("dd", {}, v));
  return dl;
}
export function rawBlock(label, value) {
  const copy = btn("copy", async () => {
    try { await navigator.clipboard.writeText(value); toast("Copied raw value."); }
    catch (_) { toast("Clipboard not available here.", true); }
  });
  return h("div", {}, h("div", { class: "raw-h" }, h("span", {}, label), copy), h("div", { class: "raw" }, value));
}

// ---------------------------------------------------------------- hunting queries (KQL, CQL, SPL)
const q = v => String(v ?? "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
const rx = v => String(v ?? "").replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

export function huntProcess(name, cmdline) {
  const args = (cmdline || "").split(/\s+/).slice(1).map(a => a.replace(/^["']|["']$/g, "")).filter(a => a.length > 2);
  const arg = args.sort((a, b) => b.length - a.length)[0]?.slice(0, 60) || "";
  return [
    ["KQL (Defender / Sentinel)", `DeviceProcessEvents | where FileName =~ "${q(name)}"${arg ? ` and ProcessCommandLine has "${q(arg)}"` : ""} | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine`],
    ["CQL (Falcon)", `#event_simpleName=ProcessRollup2 FileName="${q(name)}"${arg ? ` CommandLine=/${rx(arg)}/i` : ""} | table([@timestamp, ComputerName, UserName, CommandLine, ParentBaseFileName])`],
    ["SPL", `index=* (process_name="${q(name)}" OR Image="*\\${q(name)}")${arg ? ` "${q(arg)}"` : ""} | table _time host user process parent_process`],
  ];
}

export function huntNet(ip, port) {
  const v6 = String(ip).includes(":");
  return [
    ["KQL (Defender / Sentinel)", `DeviceNetworkEvents | where RemoteIP == "${q(ip)}"${port ? ` and RemotePort == ${Number(port)}` : ""} | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl`],
    ["CQL (Falcon)", `#event_simpleName=${v6 ? "NetworkConnectIP6 RemoteAddressIP6" : "NetworkConnectIP4 RemoteAddressIP4"}="${q(ip)}"${port ? ` RemotePort=${Number(port)}` : ""} | table([@timestamp, ComputerName, ContextBaseFileName, RemotePort])`],
    ["SPL", `index=* (dest_ip="${q(ip)}" OR dest="${q(ip)}")${port ? ` dest_port=${Number(port)}` : ""} | stats count min(_time) max(_time) by src dest dest_port`],
  ];
}

export function huntIndicator(type, value) {
  if (type === "ip") return huntNet(value, null);
  const m = type === "url" ? /^[a-z]+:\/\/(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?/i.exec(value) : null;
  const host = m ? m[1].replace(/^\[|\]$/g, "") : value;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return huntNet(host, m && m[2] ? Number(m[2]) : (m ? 80 : null));
  return [
    ["KQL (Defender / Sentinel)", `union DeviceNetworkEvents, DeviceEvents | where RemoteUrl has "${q(host)}" | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP`],
    ["CQL (Falcon)", `#event_simpleName=DnsRequest DomainName=/${rx(host)}$/i | table([@timestamp, ComputerName, DomainName, ContextBaseFileName])`],
    ["SPL", `index=* (query="*${q(host)}" OR url="*${q(host)}*" OR dest="${q(host)}") | stats count min(_time) max(_time) by src query url`],
  ];
}

export function huntBlock(queries) {
  return h("div", {}, h("div", { class: "raw-h" }, h("span", {}, "hunt for it (review before running)")),
    queries.map(([label, text]) => rawBlock(label, text)));
}

// ---------------------------------------------------------------- tables (click a row to open it)
export function table(columns, rows, opts = {}) {
  const t = { columns, rows, filtered: rows, opts, el: null, body: null };
  const thead = h("thead", {}, h("tr", {}, columns.map((c, i) => {
    const th = h("th", { class: [c.num ? "num" : "", c.sort ? "sortable" : ""].join(" ") }, c.label);
    if (c.sort && opts.onSort) {
      const s = opts.sortState || {};
      if (s.col === i) th.append(h("span", { class: "sd" }, s.dir > 0 ? " \u2191" : " \u2193"));
      th.setAttribute("tabindex", "0");
      th.setAttribute("role", "button");
      th.title = "sort";
      th.addEventListener("click", () => opts.onSort(i));
    }
    return th;
  })));
  t.body = h("tbody");
  t.el = h("table", { class: "tbl" }, thead, t.body);
  t.render = () => {
    clear(t.body);
    if (!t.filtered.length) {
      t.body.append(h("tr", {}, h("td", { colspan: columns.length, class: "faint" }, opts.emptyText || "nothing here")));
      return;
    }
    t.filtered.forEach(r => {
      const cls = [opts.open ? "row" : "", opts.dim && opts.dim(r) ? "dim" : "", opts.rowCls ? opts.rowCls(r) : ""].join(" ");
      const tr = h("tr", { class: cls },
        columns.map(c => h("td", { class: [c.cls, c.num ? "num" : ""].filter(Boolean).join(" ") }, c.render ? c.render(r) : r[c.key])));
      if (opts.open) tr.addEventListener("click", () => {
        for (const x of t.body.querySelectorAll("tr.sel")) x.classList.remove("sel");
        tr.classList.add("sel");
        opts.open(r);
      });
      t.body.append(tr);
    });
  };
  t.render();
  return t;
}

// ---------------------------------------------------------------- shared time window (drag on a timeline)
const winSubs = new Set();
export const timeWin = {
  v: null,                                   // {sid, a, b} in epoch seconds
  get(sid) { return this.v && this.v.sid === sid ? this.v : null; },
  set(v) { this.v = v; for (const f of [...winSubs]) f(v); },
  on(f) { winSubs.add(f); },
  reset() { winSubs.clear(); },
};

// Histogram of event times; drag across it to focus every table on the page on that window.
export function timeline(sid, title, times, start, end) {
  const W = 600, H = 44, N = 72;
  end = Math.max(end, start + 60);
  const width = (end - start) / N;
  const bins = new Array(N).fill(0);
  for (const t of times) { const i = Math.floor((t - start) / width); if (i >= 0 && i < N) bins[i]++; }
  const max = Math.max(1, ...bins);
  const g = svg("svg", { class: "hist brush", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img",
    "aria-label": `${title}: drag to choose a time window` }, svg("line", { x1: 0, y1: H - 0.5, x2: W, y2: H - 0.5 }));
  bins.forEach((v, i) => {
    if (!v) return;
    const bh = Math.max(2, (v / max) * (H - 3));
    g.append(svg("rect", { x: i * (W / N) + 0.5, y: H - 1 - bh, width: Math.max(1, W / N - 1), height: bh, class: v === max ? "hot" : "" },
      svg("title", {}, `${fmt(start + i * width)}  ${v}`)));
  });
  const sel = svg("rect", { class: "selwin", x: 0, y: 0, width: 0, height: H });
  g.append(sel);
  const label = h("span", { class: "winl" });
  const clearB = btn("all of the session", () => timeWin.set(null), { cls: "small" });
  const draw = () => {
    const w = timeWin.get(sid);
    if (w) {
      const x1 = ((w.a - start) / (end - start)) * W, x2 = ((w.b - start) / (end - start)) * W;
      sel.setAttribute("x", Math.max(0, x1)); sel.setAttribute("width", Math.max(2, Math.min(W, x2) - Math.max(0, x1)));
      label.textContent = `window ${fmt(w.a, true)} to ${fmt(w.b, true)}`;
      label.classList.add("acc");
      clearB.hidden = false;
    } else {
      sel.setAttribute("width", 0);
      label.textContent = "drag across the chart to focus on a time window";
      label.classList.remove("acc");
      clearB.hidden = true;
    }
  };
  let x0 = null;
  const toTs = ev => { const r = g.getBoundingClientRect(); return start + Math.min(1, Math.max(0, (ev.clientX - r.left) / r.width)) * (end - start); };
  g.addEventListener("pointerdown", ev => { x0 = toTs(ev); g.setPointerCapture(ev.pointerId); });
  g.addEventListener("pointermove", ev => {
    if (x0 == null) return;
    const x1 = toTs(ev), a = Math.min(x0, x1), b = Math.max(x0, x1);
    sel.setAttribute("x", ((a - start) / (end - start)) * W); sel.setAttribute("width", ((b - a) / (end - start)) * W);
  });
  g.addEventListener("pointerup", ev => {
    if (x0 == null) return;
    const x1 = toTs(ev), a = Math.min(x0, x1), b = Math.max(x0, x1);
    x0 = null;
    if (b - a < (end - start) / 200) { timeWin.set(null); return; }      // a click clears
    timeWin.set({ sid, a, b });
  });
  timeWin.on(draw);
  draw();
  return h("div", { class: "tl" }, g, h("div", { class: "hist-l" }, h("span", {}, fmt(start)), h("span", { class: "winbar" }, label, clearB), h("span", {}, fmt(end))));
}

// ---------------------------------------------------------------- explorer: a table with filters, grouping, paging
// Filter state lives in memory per explorer id, so a refresh keeps what you were looking at.
const EXP = new Map();
const num = n => Number(n || 0).toLocaleString("en-US");

const expDefaults = () => ({ q: "", facets: {}, toggles: {}, group: "", sort: null, limit: 200 });
// Open another explorer with a filter already set (used by "show these" links between views).
export function presetFilter(id, patch) { EXP.set(id, Object.assign(EXP.get(id) || expDefaults(), patch)); }

export function explorer(spec) {
  const st = EXP.get(spec.id) || Object.assign(expDefaults(), { limit: spec.pageSize || 200 });
  EXP.set(spec.id, st);
  for (const t of spec.toggles || []) if (st.toggles[t.key] === undefined) st.toggles[t.key] = !!t.def;
  const root = h("div", { class: "exp" });
  const bar = h("div", { class: "fbar" });
  const out = h("div", { class: "scroll" });
  const foot = h("div", { class: "pager" });
  root.append(bar, out, foot);
  const api = { filtered: [] };

  const inWin = r => {
    const w = spec.sid != null ? timeWin.get(spec.sid) : null;
    if (!w || !spec.time) return true;
    const [a, b] = spec.time(r);
    return (b ?? a) >= w.a && a <= w.b;
  };
  const passToggles = r => (spec.toggles || []).every(t => st.toggles[t.key] || !t.hide(r));
  const passFacets = (r, except) => (spec.facets || []).every(f => {
    if (f.key === except) return true;
    const sel = st.facets[f.key];
    return !sel || !sel.length || sel.includes(f.get(r));
  });
  const passSearch = (r, search) => {
    if (!st.q) return true;
    const q = st.q.toLowerCase();
    return (search ? search(r) : JSON.stringify(r)).toLowerCase().includes(q);
  };

  function buildBar() {
    clear(bar);
    const input = h("input", { class: "filter", type: "search", placeholder: spec.placeholder || "filter", value: st.q, "aria-label": "Filter rows" });
    let tmo = null;
    input.addEventListener("input", () => { clearTimeout(tmo); tmo = setTimeout(() => { st.q = input.value; st.limit = spec.pageSize || 200; render(); }, 120); });
    bar.append(input);
    const base = spec.rows.filter(r => inWin(r) && passToggles(r));
    for (const f of spec.facets || []) {
      const g = h("span", { class: "grp chips", role: "group", "aria-label": f.label || f.key });
      const sel = st.facets[f.key] || [];
      for (const [v, l] of f.options) {
        const n = base.filter(r => passFacets(r, f.key) && f.get(r) === v).length;
        if (!n && !sel.includes(v) && f.hideEmpty !== false) continue;
        g.append(h("button", { type: "button", class: `btn chip ${sel.includes(v) ? "on" : ""} ${f.cls ? f.cls(v) : ""}`, "aria-pressed": String(sel.includes(v)),
          onclick: () => { st.facets[f.key] = sel.includes(v) ? sel.filter(x => x !== v) : [...sel, v]; st.limit = spec.pageSize || 200; buildBar(); render(); } },
        l, h("span", { class: "cn" }, num(n))));
      }
      if (g.childNodes.length) bar.append(g);
    }
    for (const t of spec.toggles || []) {
      const hidden = spec.rows.filter(r => inWin(r) && t.hide(r)).length;
      if (!hidden && !st.toggles[t.key]) continue;
      bar.append(h("button", { type: "button", class: `btn chip tog ${st.toggles[t.key] ? "on" : ""}`, "aria-pressed": String(!!st.toggles[t.key]), title: t.title || "",
        onclick: () => { st.toggles[t.key] = !st.toggles[t.key]; buildBar(); render(); } }, t.label, h("span", { class: "cn" }, num(hidden))));
    }
    if (spec.groups && spec.groups.length > 1) {
      bar.append(h("span", { class: "sp" }), h("span", { class: "faint lbl" }, "show"),
        seg(spec.groups.map(g => [g.key, g.label]), st.group, v => { st.group = v; st.sort = null; buildBar(); render(); }, "grouping"));
    } else bar.append(h("span", { class: "sp" }));
    if (spec.actions) bar.append(grp(spec.actions));
  }

  function render() {
    const g = (spec.groups || []).find(x => x.key === st.group) || null;
    let rows = spec.rows.filter(r => inWin(r) && passToggles(r) && passFacets(r));
    const columns = g && g.columns ? g.columns : spec.columns;
    if (g && g.agg) rows = g.agg(rows);
    rows = rows.filter(r => passSearch(r, g && g.search ? g.search : spec.search));
    if (st.sort && columns[st.sort.col] && columns[st.sort.col].sort) {
      const k = columns[st.sort.col].sort, d = st.sort.dir;
      rows = [...rows].sort((a, b) => { const x = k(a), y = k(b); return (x > y ? 1 : x < y ? -1 : 0) * d; });
    }
    api.filtered = rows;
    const filtering = !!st.q || Object.values(st.facets).some(v => v && v.length) || (spec.sid != null && !!timeWin.get(spec.sid));
    const slice = rows.slice(0, st.limit);
    const t = table(columns, slice, {
      emptyText: spec.rows.length ? "nothing matches the filters" : (spec.emptyText || "nothing here"),
      open: g && g.agg ? (g.drill ? (r => { st.q = g.drill(r); st.group = ""; st.sort = null; buildBar(); render(); }) : null) : spec.open,
      dim: g && g.agg ? g.dim : spec.dim, rowCls: g && g.agg ? null : spec.rowCls,
      sortState: st.sort, onSort: i => { st.sort = st.sort && st.sort.col === i ? { col: i, dir: -st.sort.dir } : { col: i, dir: 1 }; render(); },
      filtering,
    });
    if (spec.flat && filtering) t.el.classList.add("flat");
    clear(out).append(t.el);
    clear(foot);
    if (spec.rows.length) {
      foot.append(h("span", { class: "faint" }, rows.length === spec.rows.length && !(g && g.agg) ? `${num(rows.length)} row${rows.length === 1 ? "" : "s"}` : `${num(rows.length)} of ${num(spec.rows.length)}`));
      if (rows.length > st.limit) {
        foot.append(h("span", { class: "faint" }, ` · showing ${num(st.limit)}`),
          btn("show 500 more", () => { st.limit += 500; render(); }, { cls: "small" }));
      }
    }
    if (spec.onChange) spec.onChange(rows);
  }
  if (spec.sid != null) timeWin.on(() => { buildBar(); render(); });
  buildBar();
  render();
  api.el = root;
  return api;
}

export function aggregate(rows, keyFn, init, step) {
  const m = new Map();
  for (const r of rows) {
    const k = keyFn(r);
    let a = m.get(k);
    if (!a) { a = init(r); m.set(k, a); }
    step(a, r);
  }
  return [...m.values()];
}

// ---------------------------------------------------------------- terminal recipes
export function cmdRow(cmd) {
  const copy = btn("copy", async () => {
    try { await navigator.clipboard.writeText(cmd); toast("Copied."); } catch (_) { toast("Clipboard not available here.", true); }
  }, { cls: "small" });
  return h("div", { class: "cmd" }, h("code", {}, cmd), copy);
}

export function recipeCard(r) {
  const cls = r.safety === "read-only" ? "" : r.safety.startsWith("sudo") ? "med" : "warn";
  return h("div", { class: "recipe" },
    h("div", { class: "rh" }, h("span", {}, r.title), tag(r.safety, cls)),
    cmdRow(r.cmd),
    h("details", { class: "explain" }, h("summary", {}, "explain"),
      h("dl", { class: "kv parts" }, r.parts.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
      r.note ? h("p", { class: "faint" }, r.note) : null));
}

// ---------------------------------------------------------------- drawer, modal, toast
const $ = id => document.getElementById(id);

export function openDrawer(title, ...sections) {
  const d = $("drawer");
  clear(d);
  d.append(h("header", {}, h("h3", {}, title), btn("close", closeDrawer)), h("div", { class: "body" }, sections));
  d.hidden = false;
  d.scrollTop = 0;
}
export function closeDrawer() { const d = $("drawer"); d.hidden = true; clear(d); }
export function drawerOpen() { return !$("drawer").hidden; }

let modalClose = null;
export function modal(title, content) {
  const scrim = $("scrim");
  clear(scrim);
  const m = h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title }, h("h2", {}, title), content);
  scrim.append(m);
  scrim.hidden = false;
  const onScrim = e => { if (e.target === scrim) closeModal(); };
  scrim.addEventListener("click", onScrim);
  modalClose = () => { scrim.removeEventListener("click", onScrim); scrim.hidden = true; clear(scrim); modalClose = null; };
  const first = m.querySelector("input,select,button");
  if (first) first.focus();
  return closeModal;
}
export function closeModal() { if (modalClose) modalClose(); }
export function modalOpen() { return !!modalClose; }

export function toast(msg, err = false) {
  const t = h("div", { class: `toast ${err ? "err" : ""}` }, msg);
  $("toasts").append(t);
  setTimeout(() => t.remove(), err ? 7000 : 3500);
}

// ---------------------------------------------------------------- per-viewer settings (best effort)
export const store = {
  get(k, d) { try { const v = localStorage.getItem("noxy." + k); return v === null ? d : JSON.parse(v); } catch (_) { return d; } },
  set(k, v) { try { localStorage.setItem("noxy." + k, JSON.stringify(v)); } catch (_) { /* private mode */ } },
};
