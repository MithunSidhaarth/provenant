// Every call goes to the same origin: the local Python server, or the hosted function on Vercel.
export async function api(path, body, headers = {}) {
  const opts = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  };
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error page */ }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

export const DECISION = {
  ALLOW: { cls: "allow", label: "ALLOW" },
  DENY: { cls: "deny", label: "DENY" },
  REQUIRE_APPROVAL: { cls: "hold", label: "HOLD" },
};

export const decisionOf = (d) => DECISION[d] || { cls: "muted", label: d || "—" };

export function short(v, n = 90) {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s && s.length > n ? s.slice(0, n - 1) + "…" : s || "";
}

export function argsLine(args) {
  if (!args || typeof args !== "object") return "";
  return Object.entries(args).map(([k, v]) => `${k}=${short(v, 48)}`).join("  ");
}

export async function copy(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { /* ignore */ }
    ta.remove();
    return ok;
  }
}

export const reduced = () => typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
