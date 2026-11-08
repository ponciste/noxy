// The views. Every panel folds; every long table filters, groups and pages. Sample-derived text is text nodes only.
// Terminal equivalents live in one place only: the lab page.
import { api, download } from "./api.js";
import {
  h, panel, btn, grp, seg, notice, explorer, aggregate, presetFilter, timeline, table, sev, hx, tag, empty, kv, rawBlock,
  openDrawer, closeDrawer, modal, closeModal, toast, store, fmt, fmtS, dur, into, bytes, bar, defangHost, defangDest,
  defangText, recipeCard, cmdRow, huntProcess, huntNet, huntIndicator, huntBlock, DATE_FORMATS, clear,
} from "./ui.js";

const ART_IDLE = " _ __   ___ __  __ _   _\n| '_ \\ / _ \\\\ \\/ /| | | |\n| | | | (_) |>  < | |_| |\n|_| |_|\\___//_/\\_\\ \\__, |\n                   |___/";
const ART_CUP = "   ( (\n    ) )\n  ........\n  |      |]\n  \\      /\n   `----'";
const SEV_FACET = { key: "sev", label: "severity", options: [["high", "high"], ["medium", "medium"], ["info", "other"]], get: r => r.sev, cls: v => `c-${v}` };
const sevCls = r => (r.noise ? "" : r.sev === "high" ? "sev-high" : r.sev === "medium" ? "sev-medium" : "");
const whatCell = (text, level) => h("span", { class: level === "high" ? "high" : level === "medium" ? "med" : "" }, text);
const n = v => Number(v || 0).toLocaleString("en-US");

function treePrefix(p) {
  if (!p.depth) return "";
  const t = p.trail || [];
  return t.slice(0, -1).map(last => (last ? "   " : "│  ")).join("") + (t[t.length - 1] ? "└─ " : "├─ ");
}

function sessionBar(ctx, s) {
  return h("div", { class: "sbar" }, h("b", { class: "acc sname" }, hx(s.name)), h("span", { class: "sp" }),
    btn("refresh", () => ctx.refresh(), { cls: "primary", title: "Read the audit log, captures and file events again" }));
}

function needSession(ctx) {
  if (ctx.state.sessionId) return null;
  return empty(ART_IDLE, "No session yet.", "Start one before you open a sample, so noxy knows which window of evidence to read.",
    btn("start a session", () => newSessionModal(ctx), { cls: "primary" }));
}

function sessionEnd(s) { return s.ended || Date.now() / 1000; }

function findingsPanel(ctx, id, findings, s, extra) {
  const kinds = [["exec", "execution"], ["net", "connection"], ["watch", "persistence"], ["file", "file"], ["artefact", "artefact"]];
  const kindsHere = kinds.filter(([k]) => findings.some(f => (f.kind || "net") === k));
  const ex = explorer({
    id: `${id}.${s.id}`, sid: s.id, rows: findings, placeholder: "filter findings",
    facets: [SEV_FACET, ...(kindsHere.length > 1 ? [{ key: "kind", label: "source", options: kindsHere, get: f => f.kind || "net" }] : [])],
    columns: [
      { label: "time", render: f => fmt(f.ts), cls: "faint", sort: f => f.ts || 0 },
      { label: "what", render: f => whatCell(f.count > 1 ? `${f.what} (×${f.count})` : f.what, f.sev), sort: f => f.what },
      { label: "evidence", render: f => hx(defangText(f.evidence)), cls: "clip" },
    ],
    search: f => `${f.what} ${f.evidence}`, time: f => [f.ts || s.started], rowCls: f => `sev-${f.sev}`,
    emptyText: "no findings", open: f => findingDrawer(ctx, f, s), pageSize: 100,
  });
  return panel(id, "findings", { count: findings.length }, extra, ex.el);
}

function findingDrawer(ctx, f, s) {
  const jump = f.kind === "file" ? btn("show these files", () => {
    presetFilter(`files.${s.id}`, { q: f.evidence.split(" (and ")[0].replace(/\/[^/]*$/, "/"), group: "", facets: {} });
    closeDrawer(); ctx.go("files");
  }) : null;
  openDrawer("finding", kv([["severity", sev(f.sev)], ["what", f.what], ["first seen", f.ts ? `${fmtS(f.ts)} (${into(f.ts, s.started)})` : ""],
    ["seen", `${f.count} time${f.count === 1 ? "" : "s"}`]]),
  rawBlock("evidence (defanged)", defangText(f.evidence)), rawBlock("evidence (raw, from the sample: do not open)", f.evidence),
  jump ? h("div", { class: "acts" }, jump) : null);
}

function confirmModal(title, text, label, onOk, danger = false) {
  modal(title, h("div", {}, h("p", {}, text),
    h("div", { class: "row" }, btn("cancel", closeModal), btn(label, async () => { closeModal(); await onOk(); }, { cls: danger ? "danger" : "primary" }))));
}

// ================================================================= lab (status and console)
export async function lab(ctx) {
  const [st, ip, c, d, fw, cmds] = await Promise.all([api("/api/status"), ctx.publicIp(false), api("/api/console"), api("/api/disk"),
    api(`/api/firewall${ctx.state.fwRefresh ? "?refresh=1" : ""}`).catch(e => ({ available: false, error: e.message })),
    api(`/api/commands?topic=all${ctx.state.sessionId ? `&session=${ctx.state.sessionId}` : ""}`)]);
  const eg = st.egress;
  const ipText = eg.mode === "offline" ? "offline" : ip && ip.ip ? ip.ip : ip && ip.error ? "unknown" : store.get("publicip", true) ? "..." : "lookup off";
  const network = panel("lab.network", "network", { tools: btn("check again", () => ctx.publicIp(true).then(() => ctx.reload()), { cls: "small" }) },
    h("div", { class: `egress ${eg.mode}` },
      h("div", { class: "lbl" }, eg.mode === "home" ? "home IP" : eg.mode === "vpn" ? "VPN IP" : "no internet"),
      h("div", { class: "v" }, ipText)),
    h("p", { class: "muted" }, eg.mode === "home"
      ? "Attacker infrastructure sees this address. Turn Proton on first, or disconnect the NAT adapter for offline work."
      : eg.mode === "vpn" ? `Traffic leaves through ${eg.iface}${eg.killswitch ? ", kill switch on." : ". Kill switch OFF: run vpn on again."}`
        : eg.killswitch ? "Kill switch on, tunnel down: nothing leaves the VM. Turn the VPN on, or off to go back to your home IP."
          : "No default route: nothing leaves the VM."),
    ip && ip.error && eg.mode !== "offline" ? h("p", { class: "faint" }, `lookup failed: ${ip.error}`) : null,
    vpnBlock(ctx, st.vpn || {}));

  const fs = d.filesystems.map(f => h("div", { class: "dk" }, h("span", { class: "dkl" }, f.label),
    bar(f.used / Math.max(1, f.total), 20), h("span", { class: f.free < 2 * 1024 ** 3 ? "med" : "muted" }, `${bytes(f.free)} free of ${bytes(f.total)}`)));
  const disk = panel("lab.disk", "disk", {}, fs,
    h("div", { class: "dk" }, h("span", { class: "dkl" }, "audit log"), bar(d.audit.size / d.audit.cap, 20),
      h("span", { class: "muted" }, `${bytes(d.audit.size)} of ${bytes(d.audit.cap)}, back to ${d.audit.earliest ? fmt(d.audit.earliest) : "?"}`)),
    kv([["captures", `${bytes(d.captures.size)} in ${d.captures.files} files${d.captures.oldest ? `, oldest ${fmt(d.captures.oldest)}` : ""}`],
      ["file events", d.sysmon && d.sysmon.size ? bytes(d.sysmon.size) : "none (Sysmon not set up)"],
      ["database", bytes(d.database.size)], ["exports", `${bytes(d.exports.size)} (${d.exports.files} files)`]]));
  const w = d.wipe || {};
  const fresh = panel("lab.fresh", "start fresh", { count: bytes(w.logs || 0) },
    h("p", { class: "muted" }, "Delete the collected logs: audit log, captures, Sysmon log and the system journal. Run it in a terminal; it asks for your password, so nothing running as your user can erase the evidence on its own. It refuses while a session is open."),
    cmdRow(w.command || "sudo python3 ~/noxy/noxy.py wipe"),
    h("p", { class: "faint" }, `Add --dry-run to preview, --keep-journal to leave the journal alone. Last wipe: ${w.last ? fmt(w.last) : "never"}. Sessions and notes are deleted separately, on the sessions tab.`));

  const problems = st.checks.filter(x => x.state === "fail" || x.state === "warn");
  const showAll = ctx.state.allChecks;
  const shown = showAll ? st.checks : problems;
  const checks = panel("lab.checks", "checks", {
    count: problems.length ? `${problems.length} to fix` : "all good",
    tools: [seg([[false, `to fix (${problems.length})`], [true, `all (${st.checks.length})`]], showAll, v => { ctx.state.allChecks = v; ctx.reload(); }, "checks shown"),
      btn("recheck", () => ctx.reload(), { cls: "small" })],
  }, shown.length ? h("ul", { class: "checks" }, shown.map(x => h("li", {},
    h("span", { class: `st ${x.state}` }, x.state), h("span", {}, x.label), h("span", { class: "muted" }, x.detail),
    x.hint && x.state !== "ok" ? h("span", { class: "hint" }, x.hint) : null)))
    : h("p", { class: "ok" }, `All ${st.summary.ok} checks pass.`));

  ctx.state.fwRefresh = false;
  return [h("div", { class: "cols" }, network, disk), checks, firewallPanel(ctx, fw), fresh, terminalPanel(ctx, cmds.topics), commandLog(c.log)];
}

// Proton with a kill switch: the commands, never a button (a passwordless switch would let anything running as your
// user turn the VPN off and expose your home IP).
function vpnBlock(ctx, v) {
  const cfgs = v.configs || [];
  if (!cfgs.length) {
    return h("div", { class: "vpn" }, h("div", { class: "faint" }, "VPN: not set up. Download WireGuard configs from Proton (one per country), then:"),
      cmdRow(`${v.command || "sudo python3 noxy.py vpn"} install ~/path/to/*.conf`));
  }
  const active = v.active || [];
  const chips = h("span");
  const cmds = h("div", { class: "pbody" });
  const select = name => {
    ctx.state.vpnPick = name;
    clear(chips).append(seg(cfgs.map(c => [c.name, active.includes(`proton-${c.name}`) ? `${c.name} (on)` : c.name]), name, select, "VPN country"));
    clear(cmds);
    if (!active.includes(`proton-${name}`)) cmds.append(cmdRow(`${v.command} on ${name}`));
    if (v.mode !== "off") cmds.append(cmdRow(`${v.command} off`));
  };
  select(cfgs.some(c => c.name === ctx.state.vpnPick) ? ctx.state.vpnPick : (cfgs.find(c => active.includes(`proton-${c.name}`)) || cfgs[0]).name);
  return h("div", { class: "vpn" },
    h("div", { class: "vrow" }, h("span", { class: "faint" }, "VPN"),
      h("span", { class: v.mode === "on" && v.killswitch ? "ok" : v.mode === "off" ? "muted" : "med" }, v.text)),
    h("div", { class: "vrow" }, h("span", { class: "faint" }, "through"), chips),
    cmds,
    h("p", { class: "faint" }, "Run it in a terminal. On applies the kill switch first, so if the tunnel drops the VM goes offline instead of using your home IP."));
}

// The VM firewall (ufw) as a read-only snapshot. The Windows host firewall is checked with host_harden.py audit.
function firewallPanel(ctx, fw) {
  const refresh = btn("refresh", () => { ctx.state.fwRefresh = true; ctx.reload(); }, { cls: "small" });
  if (!fw.available) return panel("lab.firewall", "firewall", { tools: refresh }, notice(fw.error || "not available", "warn"));
  const dflt = fw.defaults || {};
  const tone = v => (v === "deny" || v === "reject" ? "ok" : "med");
  const ks = dflt.outgoing === "deny" || dflt.outgoing === "reject";
  const summary = h("div", { class: "fwsum" },
    h("span", { class: fw.status === "active" ? "ok" : "high" }, fw.status || "?"),
    h("span", {}, h("span", { class: "faint" }, "incoming "), h("span", { class: tone(dflt.incoming) }, dflt.incoming || "?")),
    h("span", {}, h("span", { class: "faint" }, "outgoing "), h("span", { class: ks ? "ok" : "muted" }, `${dflt.outgoing || "?"}${ks ? " (kill switch on)" : ""}`)),
    h("span", {}, h("span", { class: "faint" }, "routed "), h("span", { class: tone(dflt.routed) }, dflt.routed || "?")),
    h("span", { class: "faint" }, `logging ${fw.logging || "?"}`));
  const ex = explorer({
    id: "lab.firewall", rows: fw.rules || [], placeholder: "filter rules", pageSize: 100,
    facets: [{ key: "dir", label: "direction", options: [["in", "in"], ["out", "out"]], get: r => r.direction },
      { key: "act", label: "action", options: [["allow", "allow"], ["deny", "deny"], ["reject", "reject"], ["limit", "limit"]], get: r => r.action },
      { key: "ip", label: "ip version", options: [["v4", "IPv4"], ["v6", "IPv6"]], get: r => (r.v6 ? "v6" : "v4") }],
    columns: [
      { label: "action", render: r => h("span", { class: r.action === "allow" ? "ok" : r.action === "limit" ? "med" : "high" }, `${r.action} ${r.direction}`) },
      { label: "to", render: r => r.to, cls: "clip" },
      { label: "from", render: r => r.from },
      { label: "ip", render: r => (r.v6 ? "v6" : "v4"), cls: "faint" },
      { label: "comment", render: r => (r.comment ? tag(r.comment, r.comment.includes("noxy-vpn") ? "acc" : "") : "") },
    ],
    search: r => `${r.to} ${r.from} ${r.action} ${r.comment}`, emptyText: "no rules: only the defaults apply",
  });
  return panel("lab.firewall", "firewall (VM)", { count: (fw.rules || []).length, tools: refresh },
    summary, ex.el,
    h("p", { class: "faint" }, `Snapshot of ufw status, ${fw.ts ? fmt(fw.ts) : "?"}. Rules apply top to bottom; noxy-vpn rules come from vpn on. The Windows host firewall: py hardening\\host_harden.py audit on the host.`),
    fw.error ? notice(fw.error, "warn") : null);
}

function terminalPanel(ctx, topics) {
  const st = ctx.state.term || (ctx.state.term = { q: "", topic: "" });
  const list = h("div", { class: "recipes" });
  const input = h("input", { class: "filter", type: "search", placeholder: "search commands", value: st.q, "aria-label": "Search commands" });
  const chips = h("span", { class: "grp chips" });
  const draw = () => {
    clear(chips);
    for (const [k, l] of [["", "all"], ...topics.map(t => [t.topic, t.title])]) {
      chips.append(h("button", { type: "button", class: `btn chip ${st.topic === k ? "on" : ""}`, "aria-pressed": String(st.topic === k),
        onclick: () => { st.topic = k; draw(); } }, l));
    }
    clear(list);
    const q = st.q.toLowerCase();
    let total = 0;
    for (const t of topics) {
      if (st.topic && st.topic !== t.topic) continue;
      const rs = t.recipes.filter(r => !q || `${r.title} ${r.cmd} ${r.parts.flat().join(" ")} ${r.note}`.toLowerCase().includes(q));
      if (!rs.length) continue;
      total += rs.length;
      list.append(h("details", { class: "cat", open: !!(q || st.topic) || undefined },
        h("summary", {}, t.title, h("span", { class: "n" }, ` [${rs.length}]`)), h("div", { class: "recipes" }, rs.map(recipeCard))));
    }
    if (!total) list.append(h("p", { class: "faint" }, "no command matches"));
  };
  input.addEventListener("input", () => { st.q = input.value; draw(); });
  draw();
  return panel("lab.terminal", "terminal equivalents", { count: topics.reduce((a, t) => a + t.recipes.length, 0) },
    h("p", { class: "muted" }, ctx.state.sessionId ? "The Linux commands behind every noxy panel, filled in with the selected session's times and capture files."
      : "The Linux commands behind every noxy panel. Select a session to fill in its times and capture files."),
    h("div", { class: "fbar" }, input, chips), list);
}

function commandLog(rows) {
  const ex = explorer({
    id: "lab.log", rows, placeholder: "filter commands",
    facets: [{ key: "ok", label: "result", options: [["ok", "ok"], ["failed", "failed"]], get: r => (r.exit === 0 ? "ok" : "failed") }],
    columns: [
      { label: "time", render: r => fmt(r.ts), cls: "faint", sort: r => r.ts },
      { label: "command", render: r => h("span", {}, h("code", {}, r.command), r.python ? h("span", { class: "faint" }, "  (python)") : null), cls: "clip" },
      { label: "", render: r => (r.exit === 0 ? h("span", { class: "ok" }, "ok") : h("span", { class: "high" }, `exit ${r.exit}`)) },
    ],
    search: r => `${r.command} ${r.action} ${r.output}`, emptyText: "noxy hasn't run anything yet", pageSize: 100,
    open: r => openDrawer(r.action || "command", kv([["time", fmtS(r.ts)], ["from", r.source], ["exit", String(r.exit)], ["duration", `${r.seconds}s`],
      ["how", r.python ? "performed by noxy in Python; the command shown is the terminal equivalent" : "executed by noxy"]]),
    cmdRow(r.command), rawBlock("output", r.output || "(no output)")),
  });
  return panel("lab.log", "command log", { count: rows.length, collapsed: true },
    h("p", { class: "muted" }, "Every command noxy has run, or performed in Python where marked."), ex.el);
}

// ================================================================= sessions
export function newSessionModal(ctx) {
  if (ctx.state.current) { toast("A session is already open. End it first.", true); return; }
  const name = h("input", { type: "text", maxlength: "80", placeholder: "lure-demo", "aria-label": "Session name" });
  const when = h("select", { "aria-label": "Start time" },
    [["", "now"], ["15m", "15 minutes ago"], ["1h", "1 hour ago"], ["4h", "4 hours ago"], ["custom", "custom time (UTC)"]].map(([v, l]) => h("option", { value: v }, l)));
  const custom = h("input", { type: "text", placeholder: "2026-11-07 09:00", hidden: true, "aria-label": "Custom start time (UTC)" });
  when.addEventListener("change", () => { custom.hidden = when.value !== "custom"; });
  const go = async () => {
    const at = when.value === "custom" ? custom.value.trim() : when.value;
    try {
      const s = await api("/api/sessions", { method: "POST", body: { name: name.value.trim() || "session", at: at || null } });
      closeModal();
      ctx.state.sessionId = s.id;
      toast(`Session started ${fmt(s.started)}.`);
      await ctx.pulse();
      ctx.go("exec");
    } catch (e) { toast(e.message, true); }
  };
  name.addEventListener("keydown", e => { if (e.key === "Enter") go(); });
  const eg = (ctx.state.pulse && ctx.state.pulse.egress) || {};
  const warn = eg.mode === "home"
    ? h("p", { class: "notice warn" }, "This session will use your home IP: attacker infrastructure would see it. Turn Proton on first (lab tab) if you will open live URLs.")
    : eg.mode === "vpn" ? h("p", { class: "faint" }, `Egress: ${eg.label}.`) : null;
  modal("new session", h("div", {}, warn,
    h("label", {}, "name", name), h("label", {}, "starts", when, custom),
    h("p", { class: "faint" }, "Backdate it if you started before remembering to open a session."),
    h("div", { class: "row" }, btn("cancel", closeModal), btn("start", go, { cls: "primary" }))));
}

const VERDICT_CLS = { suspicious: "high", review: "med", clean: "ok", unknown: "info" };

export async function sessions(ctx) {
  const data = await api("/api/sessions");
  const rows = data.sessions.map(s => Object.assign(s, { state: s.ended == null ? "open" : (s.verdict || "closed") }));
  const ex = explorer({
    id: "sessions", rows, placeholder: "filter sessions",
    facets: [{ key: "state", label: "state", options: [["open", "open"], ["suspicious", "suspicious"], ["review", "review"], ["clean", "clean"], ["unknown", "unknown"], ["closed", "not refreshed"]], get: s => s.state }],
    columns: [
      { label: "name", render: s => h("span", { class: s.id === ctx.state.sessionId ? "acc" : "" }, hx(s.name)), cls: "clip", sort: s => s.name.toLowerCase() },
      { label: "started", render: s => fmt(s.started), sort: s => s.started },
      { label: "duration", render: s => dur(s.duration), num: true, sort: s => s.duration || 0 },
      { label: "state", render: s => s.state === "open" ? tag("open", "acc") : h("span", { class: VERDICT_CLS[s.state] || "faint" }, s.state === "closed" ? "not refreshed" : s.state) },
    ],
    search: s => `${s.name} ${s.state}`, emptyText: "no sessions yet", open: s => sessionDrawer(ctx, s),
    actions: [btn("new session", () => newSessionModal(ctx), { cls: "primary" }), btn("export all", exportAll),
      btn("delete all", () => purgeSessions(ctx, rows.length), { cls: "danger" })],
  });
  return [panel("sessions", "sessions", { count: rows.length }, ex.el)];
}

function sessionDrawer(ctx, s) {
  openDrawer(s.name, kv([["started", fmt(s.started)], ["ended", s.ended ? fmt(s.ended) : "open"], ["duration", dur(s.duration)],
    ["egress", s.egress], ["state", s.state === "closed" ? "not refreshed" : s.state]]),
  h("div", { class: "acts" },
    grp(btn("open", () => { ctx.state.sessionId = s.id; closeDrawer(); ctx.go("exec"); }, { cls: "primary" }),
      s.ended == null ? btn("end session", () => endSession(ctx)) : null,
      btn("indicators csv", () => download(`/api/sessions/${s.id}/iocs.csv`, `noxy-session-${s.id}-iocs.csv`).catch(e => toast(e.message, true)))),
    btn("delete", () => deleteSession(ctx, s), { cls: "danger" })));
}

function purgeSessions(ctx, count) {
  if (ctx.state.current) { toast("A session is open: end it first.", true); return; }
  const inp = h("input", { type: "text", placeholder: "delete all", "aria-label": "Confirmation" });
  const go = async () => {
    if (inp.value.trim() !== "delete all") { toast("Type: delete all", true); return; }
    try {
      const r = await api("/api/sessions", { method: "DELETE", body: { confirm: "delete all" } });
      closeModal();
      ctx.state.sessionId = null;
      toast(`Deleted ${r.deleted} sessions.`);
      await ctx.pulse();
      ctx.reload();
    } catch (e) { toast(e.message, true); }
  };
  modal("delete all sessions", h("div", {},
    h("p", {}, `This removes all ${count} sessions with their parsed evidence and notes, and clears the command log. Export first if you want to keep anything.`),
    h("p", { class: "faint" }, "Raw logs and captures are not touched: use start fresh on the lab tab for those."),
    h("label", {}, 'type "delete all" to confirm', inp),
    h("div", { class: "row" }, btn("cancel", closeModal), btn("delete all", go, { cls: "danger" }))));
}

export async function endSession(ctx) {
  const cur = ctx.state.current;
  if (!cur) { toast("No open session.", true); return; }
  try {
    toast("Reading the evidence one last time...");
    await api(`/api/sessions/${cur.id}/refresh`, { method: "POST", body: {} });
    await api(`/api/sessions/${cur.id}/end`, { method: "POST", body: {} });
    closeDrawer();
    toast("Session closed. Export what you need, then revert the VM if the session called for it.");
    await ctx.pulse();
    ctx.reload();
  } catch (e) { toast(e.message, true); }
}

function deleteSession(ctx, s) {
  const inp = h("input", { type: "text", placeholder: `delete ${s.id}`, "aria-label": "Confirmation" });
  const go = async () => {
    if (inp.value.trim() !== `delete ${s.id}`) { toast(`Type: delete ${s.id}`, true); return; }
    try {
      await api(`/api/sessions/${s.id}`, { method: "DELETE", body: { confirm: `delete ${s.id}` } });
      closeModal();
      closeDrawer();
      if (ctx.state.sessionId === s.id) ctx.state.sessionId = null;
      toast("Session deleted.");
      await ctx.pulse();
      ctx.reload();
    } catch (e) { toast(e.message, true); }
  };
  modal("delete session", h("div", {},
    h("p", {}, "This removes ", hx(s.name), " with its parsed evidence and notes. Raw logs and captures are not touched."),
    h("label", {}, `type "delete ${s.id}" to confirm`, inp),
    h("div", { class: "row" }, btn("cancel", closeModal), btn("delete", go, { cls: "danger" }))));
}

export async function exportAll() {
  try {
    const r = await api("/api/export", { method: "POST", body: {} });
    await download(`/api/exports/${r.name}`, r.name);
    toast(`Exported ${r.sessions} sessions.\nSHA-256 ${r.sha256.slice(0, 16)}...`);
  } catch (e) { toast(e.message, true); }
}

// ================================================================= exec
export async function exec(ctx) {
  const none = needSession(ctx);
  if (none) return none;
  const sid = ctx.state.sessionId;
  const x = await api(`/api/sessions/${sid}/exec`);
  if (!x.session) return empty(ART_IDLE, "Session not found.", "Pick another one in sessions.");
  const s = x.session;
  const cov = [x.coverage.state !== "ok" ? notice(`coverage: ${x.coverage.text}`, "warn") : null,
    ...(x.coverage.notes || []).map(t => notice(t))];
  const out = [sessionBar(ctx, s),
    panel("exec.timeline", "executions over time", { count: x.counts.exec }, timeline(sid, "executions", x.processes.filter(p => !p.noise).map(p => p.ts), s.started, sessionEnd(s))),
    findingsPanel(ctx, "exec.findings", x.findings, s, cov)];

  const pt = explorer({
    id: `exec.procs.${sid}`, sid, rows: x.processes, flat: true, placeholder: "filter by name, argument or folder",
    facets: [SEV_FACET],
    toggles: [{ key: "noise", label: "background noise", hide: p => !!p.noise, title: x.noise_rules.map(r => `${r.id}: ${r.label}`).join("\n") }],
    columns: [
      { label: "time", render: p => fmt(p.ts), cls: "faint", sort: p => p.ts },
      { label: "process", render: p => h("span", {}, h("span", { class: "tree" }, treePrefix(p)), whatCell(p.name, p.noise ? "" : p.sev)), sort: p => p.name },
      { label: "command line", render: p => hx(defangText(p.cmdline)), cls: "clip" },
      { label: "", render: p => (p.noise ? tag(p.noise) : "") },
    ],
    search: p => `${p.name} ${p.cmdline} ${p.cwd}`, time: p => [p.ts], dim: p => !!p.noise, rowCls: sevCls,
    emptyText: x.counts.exec ? "only background noise so far" : "no executions recorded yet: refresh after you work",
    open: p => procDrawer(p, x),
  });
  out.push(panel("exec.procs", "process tree", { count: x.counts.exec }, pt.el));

  const ct = explorer({
    id: `exec.conns.${sid}`, sid, rows: x.connections, placeholder: "filter by process or address",
    facets: [SEV_FACET, { key: "scope", label: "destination", options: [["public", "public"], ["private", "private"]], get: c => (c.public ? "public" : "private") }],
    toggles: [{ key: "noise", label: "background noise", hide: c => !!c.noise }],
    columns: [
      { label: "first", render: c => fmt(c.ts), cls: "faint", sort: c => c.ts },
      { label: "process", render: c => whatCell(c.name, c.noise ? "" : c.sev), sort: c => c.name },
      { label: "destination", render: c => hx(c.public ? defangDest(c.dest) : c.dest), cls: "clip", sort: c => c.dest },
      { label: "attempts", render: c => n(c.count), num: true, sort: c => c.count },
    ],
    search: c => `${c.name} ${c.dest}`, time: c => [c.ts, c.last], dim: c => !!c.noise, rowCls: sevCls,
    emptyText: "no outbound connections recorded",
    open: c => openDrawer("connection", kv([["process", `${c.name} (pid ${c.pid})`], ["first", fmtS(c.ts)], ["last", fmtS(c.last)],
      ["attempts", String(c.count)], ["result", c.success === "yes" ? "connected" : `attempted (exit ${c.exit})`], ["assessment", c.why || c.sev]]),
    rawBlock("destination (raw)", c.dest), huntBlock(huntNet(c.ip, c.port))),
  });
  out.push(panel("exec.conns", "connections (audit)", { count: x.connections.length }, ct.el));

  const wt = explorer({
    id: `exec.watch.${sid}`, sid, rows: x.watches, placeholder: "filter by process or path",
    toggles: [{ key: "noise", label: "background noise", hide: w => !!w.noise }],
    columns: [
      { label: "time", render: w => fmt(w.ts), cls: "faint", sort: w => w.ts },
      { label: "process", render: w => whatCell(w.name, w.noise ? "" : w.sev) },
      { label: "path", render: w => hx(w.paths.join(", ")), cls: "clip" },
    ],
    search: w => `${w.name} ${w.paths.join(" ")}`, time: w => [w.ts], dim: w => !!w.noise, rowCls: sevCls,
    emptyText: "nothing written to persistence locations or editor settings",
    open: w => openDrawer("write", kv([["time", fmtS(w.ts)], ["process", `${w.name} (pid ${w.pid})`], ["rule", w.key], ["assessment", w.why || w.sev]]),
      rawBlock("paths (raw)", w.paths.join("\n"))),
  });
  out.push(panel("exec.watch", "persistence and editor writes", { count: x.watches.length, collapsed: !x.watches.length }, wt.el));
  out.push(artefactsPanel(x.artefacts || {}));
  return out;
}

function procDrawer(p, x) {
  const kids = x.processes.filter(c => c.ppid === p.pid && c.ts >= p.ts);
  openDrawer(p.name, kv([["time", `${fmtS(p.ts)} (${into(p.ts, x.session.started)})`], ["pid / ppid", `${p.pid} / ${p.ppid}`], ["exe", p.exe],
    ["user id", p.uid], ["folder", p.cwd], ["result", p.success === "yes" ? "executed" : `failed (${p.success})`],
    ["assessment", p.noise ? `background noise: ${p.noise}` : `${p.sev}${p.why ? ": " + p.why : ""}`],
    ["started", kids.length ? kids.map(k => `${k.name} (${k.pid})`).join(", ") : "nothing"]]),
  rawBlock("command line (raw, from the sample)", p.cmdline || ""), huntBlock(huntProcess(p.name, p.cmdline)));
}

function artefactsPanel(a) {
  const vs = a.vscode || {};
  const parts = [kv([["VS Code auto tasks", String(vs.automatic_tasks ?? "unknown")], ["trusted folders", String((vs.trusted || []).length)],
    ["opened this session", String((vs.opened || []).length)], ["npm runs", String((a.npm || []).length)], ["changed files (scan)", String((a.files || []).length)]])];
  if ((vs.trusted || []).length) parts.push(table([{ label: "trusted folder", render: t => hx(t.path), cls: "clip" }, { label: "", render: t => t.trusted ? tag("trusted", "acc") : tag("no") }], vs.trusted).el);
  if ((a.npm || []).length) parts.push(table([{ label: "time", render: x => fmt(x.ts) }, { label: "npm command", render: x => hx(x.argv), cls: "clip" }, { label: "exit", key: "exit" }], a.npm).el);
  if ((a.files || []).length) parts.push(h("div", { class: "scroll short" }, table([
    { label: "time", render: f => fmt(f.ts), cls: "faint" }, { label: "path (modified in the window)", render: f => whatCell(hx(f.path), f.flag ? "medium" : ""), cls: "clip" }], a.files).el));
  return panel("exec.artefacts", "artefacts outside auditd", { collapsed: true }, parts);
}

// ================================================================= files (Sysmon file creation)
export async function files(ctx) {
  const none = needSession(ctx);
  if (none) return none;
  const sid = ctx.state.sessionId;
  const f = await api(`/api/sessions/${sid}/files`);
  if (!f.session) return empty(ART_IDLE, "Session not found.", "");
  const s = f.session;
  const src = f.source || {};
  const out = [sessionBar(ctx, s)];
  if (src.error) out.push(notice(src.error, "warn"));
  else if (!src.files) out.push(notice("Not refreshed yet: press refresh to read the Sysmon log.", "warn"));
  if (src.capped) out.push(notice("Very many file events in this window: only the first 200,000 were read.", "warn"));
  if (f.shown < f.total) out.push(notice(`${n(f.total)} file events; the ${n(f.shown)} shown keep everything that is not background noise.`));
  out.push(panel("files.timeline", "files created over time", { count: f.total }, timeline(sid, "files created", f.rows.filter(r => !r.noise).map(r => r.ts), s.started, sessionEnd(s))));
  out.push(findingsPanel(ctx, "files.findings", f.findings, s));
  const byFolder = rows => aggregate(rows, r => r.folder, r => ({ folder: r.folder, n: 0, procs: new Set(), first: r.ts, last: r.ts, sev: "info", noise: true }),
    (a, r) => { a.n++; a.procs.add(r.name); a.first = Math.min(a.first, r.ts); a.last = Math.max(a.last, r.ts); if (!r.noise) a.noise = false; if (r.sev === "high" || (r.sev === "medium" && a.sev !== "high")) a.sev = r.sev; });
  const byProc = rows => aggregate(rows, r => r.image || r.name, r => ({ image: r.image || r.name, name: r.name, n: 0, folders: new Set(), first: r.ts, last: r.ts, noise: true }),
    (a, r) => { a.n++; a.folders.add(r.folder); a.first = Math.min(a.first, r.ts); a.last = Math.max(a.last, r.ts); if (!r.noise) a.noise = false; });
  const ex = explorer({
    id: `files.${sid}`, sid, rows: f.rows, placeholder: "filter by path or process",
    facets: [SEV_FACET, { key: "area", label: "where", options: [["home", "home"], ["temp", "temp"], ["system", "system"], ["other", "other"]], get: r => r.area }],
    toggles: [{ key: "noise", label: "background noise", hide: r => !!r.noise, title: f.noise_rules.map(r => `${r.id} (${r.count}): ${r.label}`).join("\n") }],
    groups: [
      { key: "", label: "files" },
      { key: "folder", label: "by folder", agg: byFolder, search: a => a.folder, dim: a => a.noise, drill: a => a.folder + "/",
        columns: [
          { label: "folder", render: a => whatCell(hx(a.folder), a.noise ? "" : a.sev), cls: "clip", sort: a => a.folder },
          { label: "files", render: a => n(a.n), num: true, sort: a => a.n },
          { label: "by", render: a => [...a.procs].slice(0, 3).join(", ") + (a.procs.size > 3 ? ` +${a.procs.size - 3}` : "") },
          { label: "first", render: a => fmt(a.first), cls: "faint", sort: a => a.first },
        ] },
      { key: "proc", label: "by process", agg: byProc, search: a => a.image, dim: a => a.noise, drill: a => a.image,
        columns: [
          { label: "process", render: a => hx(a.image), cls: "clip", sort: a => a.name },
          { label: "files", render: a => n(a.n), num: true, sort: a => a.n },
          { label: "folders", render: a => n(a.folders.size), num: true, sort: a => a.folders.size },
          { label: "first", render: a => fmt(a.first), cls: "faint", sort: a => a.first },
        ] },
    ],
    columns: [
      { label: "time", render: r => fmt(r.ts), cls: "faint", sort: r => r.ts },
      { label: "process", render: r => whatCell(r.name, r.noise ? "" : r.sev), sort: r => r.name },
      { label: "file", render: r => hx(r.path), cls: "clip", sort: r => r.path },
      { label: "", render: r => (r.noise ? tag(r.noise) : r.why && r.sev === "info" ? tag(r.why) : "") },
    ],
    search: r => `${r.path} ${r.image}`, time: r => [r.ts], dim: r => !!r.noise, rowCls: sevCls,
    emptyText: src.error ? "file creation is not watched yet" : "no files created in this session",
    open: r => openDrawer("file created", kv([["time", `${fmtS(r.ts)} (${into(r.ts, s.started)})`], ["process", `${r.name} (pid ${r.pid})`],
      ["image", r.image], ["user", r.user], ["assessment", r.noise ? `background noise: ${r.noise}` : `${r.sev}${r.why ? ": " + r.why : ""}`]]),
    rawBlock("path (raw, from the sample)", r.path)),
  });
  out.push(panel("files.list", "files created", { count: f.total }, ex.el));
  return out;
}

// ================================================================= net
export async function net(ctx) {
  const none = needSession(ctx);
  if (none) return none;
  const sid = ctx.state.sessionId;
  const nt = await api(`/api/sessions/${sid}/net`);
  if (!nt.session) return empty(ART_IDLE, "Session not found.", "");
  const s = nt.session;
  const cap = nt.capture || {};
  const out = [sessionBar(ctx, s)];
  if (cap.error) out.push(notice(cap.error, "warn"));
  if (cap.errors && cap.errors.length) out.push(notice(cap.errors.join(" · "), "warn"));
  const times = [...nt.http.map(r => r.ts), ...nt.dns.map(r => r.ts), ...nt.flows.map(r => r.ts), ...nt.tls.map(r => r.ts)];
  out.push(panel("net.timeline", "traffic over time", {}, timeline(sid, "traffic", times, s.started, sessionEnd(s))));
  out.push(findingsPanel(ctx, "net.findings", nt.findings, s));

  const kinds = [["http", `http ${n(nt.http.length)}`], ["dns", `dns ${n(nt.dns.length)}`], ["tls", `tls ${n(nt.tls.length)}`], ["flows", `connections ${n(nt.flows.length)}`]];
  const kind = ctx.state.netKind || "http";
  const common = { key: "common", label: "common infrastructure", hide: r => !!r.benign, title: "Ubuntu, Mozilla, GitHub, package registries and similar" };
  let ex;
  if (kind === "http") {
    ex = explorer({
      id: `net.http.${sid}`, sid, rows: nt.http, placeholder: "filter by host, path or user-agent",
      facets: [{ key: "method", label: "method", options: [["GET", "GET"], ["POST", "POST"], ["other", "other"]], get: r => (["GET", "POST"].includes(r.method) ? r.method : "other") }],
      toggles: [common],
      groups: [{ key: "", label: "requests" },
        { key: "host", label: "by host", search: a => a.host, dim: a => a.benign, drill: a => a.host,
          agg: rows => aggregate(rows, r => r.name || r.dst, r => ({ host: r.name || r.dst, n: 0, paths: new Set(), first: r.ts, last: r.ts, benign: r.benign }),
            (a, r) => { a.n++; a.paths.add((r.uri || "").split("?")[0]); a.first = Math.min(a.first, r.ts); a.last = Math.max(a.last, r.ts); }),
          columns: [
            { label: "host", render: a => hx(defangHost(a.host)), cls: "clip", sort: a => a.host },
            { label: "requests", render: a => n(a.n), num: true, sort: a => a.n },
            { label: "paths", render: a => n(a.paths.size), num: true, sort: a => a.paths.size },
            { label: "first", render: a => fmt(a.first), cls: "faint", sort: a => a.first },
            { label: "last", render: a => fmt(a.last), cls: "faint", sort: a => a.last },
          ] }],
      columns: [
        { label: "time", render: r => fmt(r.ts), cls: "faint", sort: r => r.ts },
        { label: "", key: "method" },
        { label: "host", render: r => hx(defangHost(r.name || r.dst)), sort: r => r.name || r.dst },
        { label: "path", render: r => hx(r.uri), cls: "clip" },
      ],
      search: r => `${r.name} ${r.dst} ${r.uri} ${r.ua}`, time: r => [r.ts], dim: r => r.benign, emptyText: "no HTTP requests captured",
      open: r => openDrawer("http request", kv([["time", fmtS(r.ts)], ["from", `${r.src}:${r.sport}`], ["to", `${defangHost(r.dst)}:${r.dport}`],
        ["method", r.method], ["host", defangHost(r.name)], ["user-agent", r.ua]]), rawBlock("url (raw, live: do not open)", r.url), decodeBlock(r.uri),
      huntBlock(huntIndicator("url", r.url))),
    });
  } else if (kind === "dns") {
    const types = [...new Set(nt.dns.map(r => r.qtype || "?"))].sort();
    ex = explorer({
      id: `net.dns.${sid}`, sid, rows: nt.dns, placeholder: "filter names",
      facets: types.length > 1 ? [{ key: "qtype", label: "type", options: types.map(t => [t, t]), get: r => r.qtype || "?" }] : [],
      toggles: [common],
      columns: [
        { label: "first", render: r => fmt(r.ts), cls: "faint", sort: r => r.ts },
        { label: "name", render: r => hx(defangHost(r.name)), cls: "clip", sort: r => r.name },
        { label: "type", render: r => r.qtype || "" },
        { label: "queries", render: r => n(r.count), num: true, sort: r => r.count },
      ],
      search: r => r.name, time: r => [r.ts, r.last], dim: r => r.benign, emptyText: "no DNS queries",
      open: r => openDrawer("dns query", kv([["name", defangHost(r.name)], ["type", r.qtype], ["first", fmtS(r.ts)], ["last", fmtS(r.last)], ["queries", String(r.count)]]),
        rawBlock("name (raw)", r.name), huntBlock(huntIndicator("domain", r.name))),
    });
  } else if (kind === "tls") {
    ex = explorer({
      id: `net.tls.${sid}`, sid, rows: nt.tls.map(r => Object.assign(r, { benign: r.benign ?? false })), placeholder: "filter server names",
      columns: [
        { label: "first", render: r => fmt(r.ts), cls: "faint", sort: r => r.ts },
        { label: "server name", render: r => hx(defangHost(r.name)), cls: "clip", sort: r => r.name },
        { label: "address", render: r => `${defangHost(r.dst)}:${r.dport}` },
        { label: "handshakes", render: r => n(r.count), num: true, sort: r => r.count },
      ],
      search: r => `${r.name} ${r.dst}`, time: r => [r.ts], emptyText: "no TLS handshakes",
      open: r => openDrawer("tls server name", kv([["name", defangHost(r.name)], ["server", `${defangHost(r.dst)}:${r.dport}`], ["first", fmtS(r.ts)], ["handshakes", String(r.count)]]),
        rawBlock("name (raw)", r.name), huntBlock(huntIndicator("domain", r.name))),
    });
  } else {
    const portCls = p => (p === 443 || p === 80 ? "web" : p === 53 || p === 853 ? "dns" : "other");
    ex = explorer({
      id: `net.flows.${sid}`, sid, rows: nt.flows, placeholder: "filter by address or port",
      facets: [{ key: "proto", label: "protocol", options: [["tcp", "tcp"], ["udp", "udp"]], get: r => r.proto },
        { key: "scope", label: "destination", options: [["public", "public"], ["private", "private"]], get: r => (r.public ? "public" : "private") },
        { key: "port", label: "port", options: [["web", "80 / 443"], ["dns", "53"], ["other", "other ports"]], get: r => portCls(r.dport) }],
      groups: [{ key: "", label: "connections" },
        { key: "ip", label: "by address", search: a => a.dst, drill: a => a.dst,
          agg: rows => aggregate(rows, r => r.dst, r => ({ dst: r.dst, public: r.public, n: 0, ports: new Set(), first: r.ts, last: r.last }),
            (a, r) => { a.n += r.count; a.ports.add(r.dport); a.first = Math.min(a.first, r.ts); a.last = Math.max(a.last, r.last); }),
          columns: [
            { label: "address", render: a => hx(a.public ? defangHost(a.dst) : a.dst), cls: "clip", sort: a => a.dst },
            { label: "ports", render: a => [...a.ports].sort((x, y) => x - y).slice(0, 6).join(", ") + (a.ports.size > 6 ? " ..." : "") },
            { label: "packets", render: a => n(a.n), num: true, sort: a => a.n },
            { label: "first", render: a => fmt(a.first), cls: "faint", sort: a => a.first },
          ] }],
      columns: [
        { label: "first", render: r => fmt(r.ts), cls: "faint", sort: r => r.ts },
        { label: "", render: r => r.proto },
        { label: "destination", render: r => hx(r.public ? defangHost(r.dst) : r.dst), cls: "clip", sort: r => r.dst },
        { label: "port", render: r => String(r.dport), num: true, sort: r => r.dport },
        { label: "packets", render: r => n(r.count), num: true, sort: r => r.count },
        { label: "last", render: r => fmt(r.last), cls: "faint", sort: r => r.last },
      ],
      search: r => `${r.dst} ${r.dport} ${r.proto}`, time: r => [r.ts, r.last], emptyText: "no new connections captured",
      open: r => openDrawer("connection", kv([["protocol", r.proto], ["destination", `${r.public ? defangHost(r.dst) : r.dst}:${r.dport}`], ["first", fmtS(r.ts)], ["last", fmtS(r.last)], ["packets", String(r.count)]]),
        rawBlock("address (raw)", r.dst), huntBlock(huntNet(r.dst, r.dport))),
    });
  }
  out.push(panel("net.traffic", "traffic", { tools: seg(kinds, kind, v => { ctx.state.netKind = v; ctx.reload(); }, "traffic type") }, ex.el));
  return out;
}

function decodeBlock(uri) {
  const q = (uri || "").split("?")[1];
  if (!q) return null;
  const parts = [];
  for (const kvp of q.split("&").slice(0, 30)) {
    const [k, ...rest] = kvp.split("=");
    let v = rest.join("=");
    try { v = decodeURIComponent(v.replace(/\+/g, " ")); } catch (_) { /* keep raw */ }
    let pretty = v;
    try { const j = JSON.parse(v); pretty = JSON.stringify(j, null, 2); if (j && typeof j === "object" && !Array.isArray(j)) pretty = `${Object.keys(j).length} keys: ${Object.keys(j).join(", ")}\n\n${pretty}`; } catch (_) { /* not JSON */ }
    parts.push(rawBlock(`query: ${k} (decoded)`, pretty));
  }
  return h("div", {}, parts);
}

// ================================================================= iocs
export async function iocs(ctx) {
  const none = needSession(ctx);
  if (none) return none;
  const sid = ctx.state.sessionId;
  const [data, s] = await Promise.all([api(`/api/sessions/${sid}/iocs`), api(`/api/sessions/${sid}`)]);
  let ex = null;
  const copy = async () => {
    const rows = ex ? ex.filtered : [];
    try { await navigator.clipboard.writeText(rows.map(i => `${i.type}\t${i.defanged}`).join("\n")); toast(`Copied ${rows.length} indicators (defanged).`); }
    catch (_) { toast("Clipboard not available here.", true); }
  };
  ex = explorer({
    id: `iocs.${sid}`, sid, rows: data.iocs, placeholder: "filter indicators",
    facets: [{ key: "type", label: "type", options: [["url", "url"], ["domain", "domain"], ["ip", "ip"]], get: i => i.type }],
    toggles: [{ key: "common", label: "common infrastructure", hide: i => !!i.benign }],
    columns: [
      { label: "type", render: i => tag(i.type, i.type === "url" ? "acc" : ""), sort: i => i.type },
      { label: "indicator", render: i => hx(i.defanged), cls: "clip", sort: i => i.value },
      { label: "seen", render: i => n(i.count), num: true, sort: i => i.count },
      { label: "first seen", render: i => fmt(i.first), cls: "faint", sort: i => i.first },
    ],
    search: i => `${i.type} ${i.value}`, time: i => [i.first, i.last], dim: i => i.benign, emptyText: "no indicators in this session",
    open: i => openDrawer(i.type, kv([["first seen", fmtS(i.first)], ["last seen", fmtS(i.last)], ["count", String(i.count)], ["seen in", i.sources.join(", ")],
      ["common infrastructure", i.benign ? "yes" : "no"]]), rawBlock("defanged", i.defanged), rawBlock("raw (live: do not open)", i.value),
    huntBlock(huntIndicator(i.type, i.value))),
    actions: [btn("copy shown", copy, { title: "Copy the indicators shown, defanged" }),
      btn("csv", () => download(`/api/sessions/${sid}/iocs.csv`, `noxy-session-${sid}-iocs.csv`).catch(e => toast(e.message, true)), { title: "All indicators of the session" })],
  });
  return [sessionBar(ctx, s), panel("iocs", "indicators", { count: data.iocs.length }, ex.el)];
}

// ================================================================= notes
export async function notes(ctx) {
  const none = needSession(ctx);
  if (none) return none;
  const sid = ctx.state.sessionId;
  const [s, data] = await Promise.all([api(`/api/sessions/${sid}`), api(`/api/sessions/${sid}/notes`)]);
  const input = h("input", { class: "note-in", type: "text", maxlength: "4000", placeholder: "what did you just see? (gets the current time)", "aria-label": "New note", id: "note-input" });
  const save = async () => {
    const text = input.value.trim();
    if (!text) return;
    try { await api(`/api/sessions/${sid}/notes`, { method: "POST", body: { text } }); input.value = ""; ctx.reload(); }
    catch (e) { toast(e.message, true); }
  };
  input.addEventListener("keydown", e => { if (e.key === "Enter") save(); });
  const list = data.notes.length ? h("ul", { class: "notes" }, data.notes.map(x => h("li", {},
    h("span", { class: "acc" }, fmt(x.ts)), h("span", { class: "t" }, x.text),
    btn("delete", async () => { await api(`/api/sessions/${sid}/notes/${x.id}`, { method: "DELETE", body: {} }); ctx.reload(); }, { cls: "danger small" }))))
    : empty(ART_CUP, "No notes yet.", "Type what you saw and press add. Each note gets the time.");
  return [sessionBar(ctx, s), panel("notes", "notes", { count: data.notes.length }, h("div", { class: "note-form" }, input, btn("add", save, { cls: "primary" })), list)];
}

// ================================================================= stats
export async function stats(ctx) {
  const none = needSession(ctx);
  if (none) return none;
  const sid = ctx.state.sessionId;
  const st = await api(`/api/sessions/${sid}/stats`);
  if (!st.session) return empty(ART_IDLE, "Session not found.", "");
  const s = st.session;
  const tile = (label, value, cls = "") => h("div", { class: "tile" }, h("div", { class: `tv ${cls}` }, value == null ? "-" : n(value)), h("div", { class: "tl" }, label));
  const hist = (id, title, hg) => {
    const bins = hg?.bins || [];
    if (!bins.some(Boolean)) return null;
    const times = [];
    bins.forEach((v, i) => { for (let k = 0; k < v; k++) times.push(hg.start + (i + 0.5) * hg.width); });
    return panel(id, title, {}, timeline(sid, title, times, hg.start, hg.end));
  };
  return [
    sessionBar(ctx, s),
    panel("stats.summary", "summary", { count: dur(st.duration) }, h("div", { class: "tiles" },
      tile("high findings", st.findings.high, st.findings.high ? "high" : ""), tile("medium findings", st.findings.medium, st.findings.medium ? "med" : ""),
      tile("executions", st.exec.exec), tile("connections (audit)", st.exec.net), tile("persistence writes", st.exec.watch),
      tile("files created", st.files.total), tile("flagged files", st.files.flagged, st.files.flagged ? "med" : ""), tile("background noise", st.exec.suppressed + st.files.noise)),
    h("div", { class: "tiles" },
      tile("dns queries", st.net.dns), tile("http requests", st.net.http), tile("tls names", st.net.tls), tile("connections captured", st.net.flows),
      tile("beacons", st.net.beacons, st.net.beacons ? "high" : ""), tile("packets read", st.net.packets))),
    hist("stats.exec", "executions over time", st.histograms.exec),
    hist("stats.files", "files created over time", st.histograms.files),
    hist("stats.net", "network events over time", st.histograms.net),
    panel("stats.sources", "sources", {}, kv([
      ["audit records", `${st.audit.parsed ?? "-"} parsed from ${st.audit.files} files; log reaches back to ${st.audit.earliest ? fmt(st.audit.earliest) : "?"}`],
      ["capture", `${st.net.capture_files} files, ${n(st.net.packets)} packets in the session window`],
      ["file events", `${n(st.files.total)} from Sysmon`],
      ["coverage", st.coverage.text], ...(st.coverage.notes || []).map(x => ["note", x]),
      ["audit activity now", st.audit_rate == null ? "unknown" : `about ${st.audit_rate} records per minute`],
      ["last refresh", st.refreshed ? fmt(st.refreshed) : "never"], ["notes", String(st.notes)]])),
  ];
}

// ================================================================= settings
export function settingsModal(ctx, apply) {
  const ACCENTS = ["green", "cyan", "magenta", "red", "yellow", "amber", "white"];
  const cur = store.get("accent", "green");
  const re = () => { apply(); settingsModal(ctx, apply); ctx.reload(); };
  const sw = ACCENTS.map(a => h("button", { class: `swatch sw-${a}`, title: a, "aria-label": a, "aria-pressed": String(a === cur), type: "button",
    onclick: () => { store.set("accent", a); re(); } }));
  const df = store.get("datefmt", "short");
  const onOff = (key, def) => seg([[true, "on"], [false, "off"]], store.get(key, def), v => { store.set(key, v); re(); });
  const row = (label, control) => h("div", { class: "srow" }, h("span", { class: "muted" }, label), control);
  modal("settings", h("div", {},
    row("accent colour", h("div", { class: "choices" }, sw)),
    row("dates (always UTC)", seg(Object.entries(DATE_FORMATS), df, v => { store.set("datefmt", v); re(); }, "date format")),
    row("density", seg([["comfortable", "comfortable"], ["compact", "compact"]], store.get("density", "comfortable"), v => { store.set("density", v); re(); })),
    row("rain", onOff("rain", true)),
    row("boot screen", onOff("boot", true)),
    row("public IP lookup (api.ipify.org)", onOff("publicip", true)),
    h("p", { class: "faint" }, "Settings are kept in this browser. Severity colours never change with the accent."),
    h("div", { class: "row" }, btn("done", closeModal, { cls: "primary" }))));
}
