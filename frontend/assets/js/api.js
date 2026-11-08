// API client. Every call carries the per-launch token in a custom header; the server refuses calls without it.
const TOKEN = document.querySelector('meta[name="noxy-token"]')?.content || "";

export async function api(path, { method = "GET", body } = {}) {
  const opt = { method, headers: { "X-Noxy-Token": TOKEN }, credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try { msg = (await r.json()).error || msg; } catch (_) { /* not JSON */ }
    throw new Error(msg);
  }
  const ct = r.headers.get("Content-Type") || "";
  return ct.startsWith("application/json") ? r.json() : r.blob();
}

export async function download(path, filename) {
  const blob = await api(path);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
