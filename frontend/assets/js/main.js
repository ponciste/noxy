// noxy frontend: router, header, settings, boot screen. No keyboard shortcuts: everything is a click.
import { api } from "./api.js";
import { Rain } from "./rain.js";
import * as V from "./views.js";
import { h, svg, clear, toast, store, fmt, closeDrawer, timeWin, modal, closeModal, btn } from "./ui.js";

const VIEWS = {
  lab: V.lab, sessions: V.sessions, exec: V.exec, files: V.files, net: V.net, iocs: V.iocs, notes: V.notes, stats: V.stats,
};
const OLD = { status: "lab", console: "lab" };
const $ = id => document.getElementById(id);

const state = {
  view: "lab", sessionId: null, current: null, pulse: null, serverSkew: 0, ip: null, allChecks: false, netKind: "http",
};
let rain = null;

function applySettings() {
  const root = document.documentElement;
  root.dataset.accent = store.get("accent", "green");
  root.dataset.density = store.get("density", "comfortable");
  if (rain) { rain.colors(); rain.setEnabled(store.get("rain", true)); }
}

// ---------------------------------------------------------------- header
async function pulse() {
  try {
    const p = await api("/api/pulse");
    state.pulse = p;
    state.serverSkew = p.now - Date.now() / 1000;
    state.current = p.session;
    if (!state.sessionId && p.session) state.sessionId = p.session.id;
    if (rain) rain.setLevel(p.audit_rate);
  } catch (e) {
    state.pulse = null;
  }
  drawHeader();
}

async function publicIp(force) {
  if (!store.get("publicip", true)) { state.ip = null; return null; }
  try {
    state.ip = await api(`/api/publicip${force ? "?refresh=1" : ""}`);
  } catch (e) {
    state.ip = { ip: null, error: e.message, egress: state.pulse?.egress || { mode: "offline" } };
  }
  drawHeader();
  return state.ip;
}

function drawHeader() {
  const sl = clear($("statusline"));
  const p = state.pulse;
  if (!p) {
    sl.append(h("div", { class: "high" }, "noxy is not answering: systemctl --user status noxy"));
    return;
  }
  const now = Date.now() / 1000 + state.serverSkew;
  const eg = p.egress;
  const ip = state.ip && state.ip.ip;
  const label = eg.mode === "offline" ? h("b", { class: "ok" }, "offline")
    : [h("span", {}, eg.mode === "vpn" ? "VPN IP " : "home IP "), h("b", { class: eg.mode === "vpn" ? "ok" : "med" }, ip || (!store.get("publicip", true) ? "lookup off" : state.ip && state.ip.error ? "unknown" : "..."))];
  sl.append(h("div", {}, h("b", {}, fmt(now)), h("span", { class: "faint" }, " UTC")), h("div", {}, label));
  if (p.session) sl.append(h("div", { class: "faint" }, "session ", h("span", { class: "acc" }, p.session.name)));
  const rb = $("restart");
  rb.disabled = !p.restartable;
  rb.title = p.restartable ? "restart noxy" : "restart noxy: only when noxy runs as the user service (python3 noxy.py setup service)";
}

// ---------------------------------------------------------------- restart (the only control in the UI)
function restartIcon() {
  return svg("svg", { viewBox: "0 0 16 16", width: 14, height: 14, "aria-hidden": "true" },
    svg("path", { d: "M13 8a5 5 0 1 1-1.6-3.7", fill: "none", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "square" }),
    svg("path", { d: "M13.5 1.5v4h-4", fill: "none", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "square" }));
}

function askRestart() {
  if (!state.pulse || !state.pulse.restartable) { toast("Restart works when noxy runs as the user service: python3 noxy.py setup service", true); return; }
  modal("restart noxy", h("div", {},
    h("p", {}, "noxy restarts as your user service and this page reloads by itself. Sessions, notes and evidence are kept."),
    h("div", { class: "row" }, btn("cancel", closeModal), btn("restart", async () => {
      closeModal();
      try { await api("/api/control", { method: "POST", body: { action: "noxy-restart" } }); }
      catch (e) { toast(e.message, true); return; }
      toast("Restarting noxy...");
      await new Promise(r => setTimeout(r, 2500));
      for (let i = 0; i < 40; i++) {
        try { const r = await fetch("/", { cache: "no-store" }); if (r.ok) { location.reload(); return; } } catch (_) { /* not up yet */ }
        await new Promise(r => setTimeout(r, 500));
      }
      toast("noxy did not come back: systemctl --user status noxy", true);
    }, { cls: "primary" }))));
}

// ---------------------------------------------------------------- router
async function go(view) {
  view = OLD[view] || view;
  if (!VIEWS[view]) view = "lab";
  state.view = view;
  if (location.hash !== `#${view}`) history.replaceState(null, "", `#${view}`);
  for (const b of document.querySelectorAll("nav.keys [data-view]")) b.setAttribute("aria-selected", String(b.dataset.view === view));
  closeDrawer();
  await render(true);
}

async function render(top = false) {
  const main = $("view");
  const scroll = top ? 0 : window.scrollY;
  try {
    if (timeWin.v && timeWin.v.sid !== state.sessionId) timeWin.v = null;
    timeWin.reset();                                  // the old view's tables are about to go
    const nodes = await VIEWS[state.view](ctx);
    clear(main);
    main.append(...[nodes].flat().filter(Boolean));
  } catch (e) {
    clear(main);
    main.append(h("div", { class: "empty" }, h("b", {}, "Could not load this view."), h("div", { class: "high" }, e.message)));
  }
  window.scrollTo(0, scroll);
}

async function refresh() {
  const sid = state.sessionId;
  if (!sid) { toast("No session selected.", true); return; }
  toast("Reading the audit log and captures...");
  try {
    const r = await api(`/api/sessions/${sid}/refresh`, { method: "POST", body: {} });
    const bits = [r.verdict.title];
    if (r.audit.error) bits.push(r.audit.error);
    if (r.pcap.error) bits.push(r.pcap.error);
    toast(bits.join("\n"), r.verdict.level === "suspicious" || !!r.audit.error);
    await render();
  } catch (e) { toast(e.message, true); }
}

const ctx = { state, go, refresh, pulse, publicIp, reload: () => render() };

// ---------------------------------------------------------------- boot screen
async function boot() {
  const el = $("boot");
  const ver = document.querySelector('meta[name="noxy-version"]')?.content || "";
  let seen = false;
  try { seen = sessionStorage.getItem("noxy.booted") === "1"; sessionStorage.setItem("noxy.booted", "1"); } catch (_) { /* ignore */ }
  if (seen || !store.get("boot", true) || matchMedia("(prefers-reduced-motion: reduce)").matches) { el.remove(); return; }
  const line = (st, txt) => el.append(h("div", { class: "l" }, h("span", { class: `st ${st}` }, st === "ok" ? "[ ok ]" : st === "fail" ? "[FAIL]" : `[${st}]`), " ", txt));
  el.append(h("div", { class: "l acc" }, `noxy ${ver}  //  wake up, analyst...`), h("div", { class: "l faint" }, " "));
  let skip = false;
  const done = () => { if (skip && !el.isConnected) return; skip = true; el.classList.add("fade"); setTimeout(() => el.remove(), 380); };
  el.addEventListener("click", done);
  try {
    const st = await api("/api/status");
    for (const c of st.checks) {
      if (skip) return;
      line(c.state, `${c.label.padEnd(22)} ${c.detail}`);
      await new Promise(r => setTimeout(r, 55));
    }
    if (!skip) { el.append(h("div", { class: "l faint" }, " "), h("div", { class: "l acc" }, "coffee's ready.")); await new Promise(r => setTimeout(r, 450)); }
  } catch (e) {
    line("fail", `server: ${e.message}`);
    await new Promise(r => setTimeout(r, 900));
  }
  if (!skip) done();
}

// ---------------------------------------------------------------- start
function start() {
  applySettings();
  rain = new Rain($("rain"));
  applySettings();
  $("foot-ver").textContent = `noxy ${document.querySelector('meta[name="noxy-version"]')?.content || ""} · all times UTC`;
  for (const b of document.querySelectorAll("nav.keys [data-view]")) b.addEventListener("click", () => go(b.dataset.view));
  $("restart").append(restartIcon());
  $("restart").addEventListener("click", askRestart);
  document.querySelector('nav.keys [data-action="settings"]').addEventListener("click", () => V.settingsModal(ctx, () => { applySettings(); drawHeader(); }));
  boot();
  pulse().then(() => { publicIp(false); go((location.hash || "#lab").slice(1)); });
  setInterval(pulse, 5000);
  setInterval(() => publicIp(false), 60000);
  setInterval(drawHeader, 1000);
}

start();
