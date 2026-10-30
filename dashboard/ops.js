(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const state = { after: 0, entries: [], stats: null, status: null, pending: [], filter: "ALL", search: "", busy: false, lastUpdated: null };
  const escapeHtml = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const fmt = (v) => Number.isFinite(Number(v)) ? Number(v).toLocaleString() : "—";
  const time = (v) => { if (!v) return "—"; const d = new Date(v); return Number.isNaN(d.getTime()) ? String(v) : d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"}); };
  const decision = (v) => ({ALLOW:["allow","ALLOW"],DENY:["deny","BLOCKED"],REQUIRE_APPROVAL:["hold","HELD"]}[v] || ["neutral", String(v || "EVENT").toUpperCase()]);
  async function get(path) { const r = await fetch(path, {cache:"no-store"}); let data; try { data = await r.json(); } catch { data = {}; } if (!r.ok) throw new Error(data.error || "HTTP " + r.status); return data; }
  function setConnection(ok, label) { $("connection-label").textContent = label; $("connection-dot").className = "dot " + (ok ? "live" : "error"); $("connection-pill").setAttribute("aria-label", label); }
  function renderMetrics() {
    const s = state.stats || {};
    $("metric-sessions").textContent = fmt(s.live_sessions);
    $("metric-requests").textContent = fmt(s.tool_requests_observed);
    $("metric-blocked").textContent = fmt(s.blocked);
    $("metric-held").textContent = fmt(s.held);
    $("metric-allowed").textContent = fmt(s.allowed);
    $("metric-prompts").textContent = fmt(s.user_prompts_observed);
    $("metric-results").textContent = fmt(s.tool_results_observed);
    $("metric-decisions").textContent = fmt(s.policy_decisions);
    $("stat-mcp").textContent = fmt(s.mcp_tool_requests);
    $("stat-claude").textContent = fmt(s.claude_code_tool_requests);
    $("stat-approvals").textContent = fmt(s.approval_requests);
    $("stat-outcomes").textContent = fmt(s.approval_outcomes);
    $("stat-grants").textContent = fmt(s.execution_grants_redeemed);
    $("last-event").textContent = s.last_event_at ? time(s.last_event_at) : "No live events";
    $("live-count").textContent = fmt(s.audit_entries) + " observed events";
    const hosted = !!state.status?.hosted;
    $("hosted-note").hidden = !hosted;
    $("integrity-title").textContent = state.status?.audit?.ok === true ? "Audit chain verified" : state.status?.audit?.ok === false ? "Audit chain check failed" : hosted ? "Local audit unavailable" : "Audit status unavailable";
    $("integrity-dot").className = "dot " + (state.status?.audit?.ok === true ? "live" : "error");
    $("integrity-detail").textContent = state.status?.audit?.checked != null ? fmt(state.status.audit.checked) + " records checked" : "Integrity is reported by the local Guard engine";
    $("policy-version").textContent = state.status?.policy_version ? "Policy " + state.status.policy_version : "Policy status unavailable";
    $("hook-status").textContent = state.status?.claude_code_hook ? "Installed" : (hosted ? "Not inspected on hosted demo" : "Not detected");
    $("hook-status").className = state.status?.claude_code_hook ? "tone-mint" : "tone-amber";
    $("policy-error").hidden = !state.status?.policy_error;
    $("policy-error").textContent = state.status?.policy_error ? "Policy load issue: " + state.status.policy_error : "";
    $("last-refresh").textContent = state.lastUpdated ? "Updated " + time(state.lastUpdated) : "Waiting for first poll";
  }
  function renderFeed() {
    const q = state.search.trim().toLowerCase();
    const items = state.entries.filter(e => {
      const d = e.event === "policy_decision" ? e.data?.decision : e.event;
      const filterMatch = state.filter === "ALL" || (state.filter === "DENY" && d === "DENY") || (state.filter === "HOLD" && d === "REQUIRE_APPROVAL") || (state.filter === "ALLOW" && d === "ALLOW");
      return filterMatch && (!q || JSON.stringify(e).toLowerCase().includes(q));
    });
    $("feed").innerHTML = items.length ? items.slice().reverse().slice(0,120).map(e => {
      const d = e.event === "policy_decision" ? decision(e.data?.decision) : ["neutral", String(e.event || "event").replaceAll("_"," ").toUpperCase()];
      const source = e.data?.source || "source not recorded";
      const tool = e.data?.tool || e.event?.replaceAll("_"," ") || "audit event";
      const reasons = Array.isArray(e.data?.reasons) ? e.data.reasons.join(" · ") : "";
      const sid = e.session_id ? "session " + e.session_id : "";
      return '<article class="event"><time class="event-time">'+escapeHtml(time(e.ts))+'</time><div><div class="event-title">'+escapeHtml(tool)+'</div><div class="event-meta">'+escapeHtml(source)+(sid ? " · "+escapeHtml(sid) : "")+(reasons ? "<br>"+escapeHtml(reasons) : "")+'</div></div><span class="decision '+d[0]+'">'+escapeHtml(d[1])+'</span></article>';
    }).join("") : '<div class="empty"><strong>'+(state.entries.length ? "No matching events" : "No live activity observed yet")+'</strong>'+(state.entries.length ? "Try another filter or search term." : "Start a protected MCP or Claude Code session. Demo runs and untagged legacy records are intentionally excluded.")+'</div>';
    $("feed-count").textContent = fmt(items.length) + " shown";
  }
  function renderClients() {
    const s = state.status;
    if (!s || s.hosted) { $("clients-list").innerHTML = '<div class="empty"><strong>Local client status unavailable</strong>The hosted page cannot inspect your computer. Run the local dashboard to see your own config.</div>'; return; }
    const clients = Array.isArray(s.clients) ? s.clients : [];
    $("clients-list").innerHTML = clients.length ? clients.map(c => {
      const servers = Array.isArray(c.servers) ? c.servers : [];
      const protectedCount = servers.filter(x => x.protected).length;
      const status = c.error ? '<span class="tone-red">Config error</span>' : !c.present ? '<span>Not configured</span>' : servers.length && protectedCount === servers.length ? '<span class="tone-mint">Protected</span>' : '<span class="tone-amber">Needs review</span>';
      return '<div class="client"><div class="client-top"><span class="client-name">'+escapeHtml(c.client)+'</span>'+status+'</div><div class="client-path">'+escapeHtml(c.present ? c.path : "No config file detected")+'</div>'+(c.error ? '<div class="client-path tone-red">'+escapeHtml(c.error)+'</div>' : '')+'<div class="client-servers">'+(servers.length ? servers.map(srv => '<span class="server-chip '+(srv.protected ? "on" : "off")+'">'+escapeHtml(srv.name)+(srv.protected ? " · protected" : " · unwrapped")+'</span>').join("") : '<span class="server-chip">No MCP servers detected</span>')+'</div></div>';
    }).join("") : '<div class="empty"><strong>No client configurations detected</strong>Set up a supported MCP client with <code>provenant setup</code>.</div>';
  }
  function renderPending() {
    const items = state.pending || [];
    $("pending-count").textContent = fmt(items.length) + " waiting";
    $("pending").innerHTML = items.length ? items.map(p => {
      const reasons = Array.isArray(p.reasons) ? p.reasons : [];
      return '<div class="approval"><div class="approval-top"><span class="decision hold">HELD</span><span class="approval-tool">'+escapeHtml(p.tool || "Unknown tool")+'</span></div>'+(reasons.length ? '<div class="approval-reason">'+escapeHtml(reasons.slice(0,3).join(" · "))+'</div>' : '')+'<div class="cmd"><code>'+escapeHtml("provenant approve "+(p.approval_id || ""))+'</code><button class="copy" data-copy="'+escapeHtml("provenant approve "+(p.approval_id || ""))+'">Copy</button></div><div class="event-meta">Created '+escapeHtml(time(p.created_at))+' · Approval is terminal-only.</div></div>';
    }).join("") : '<div class="empty"><strong>No calls waiting for approval</strong>Held calls appear here when Guard requests a human decision.</div>';
  }
  async function poll() {
    if (state.busy) return; state.busy = true;
    try {
      const [status, log, pending] = await Promise.all([get("/api/guard/status"), get("/api/guard/log?after="+state.after), get("/api/guard/pending")]);
      state.status = status; state.stats = log.stats || null; state.pending = Array.isArray(pending) ? pending : [];
      const entries = Array.isArray(log.entries) ? log.entries : [];
      if (entries.length) {
        const seen = new Set(state.entries.map(e => e.seq));
        const fresh = entries.filter(e => !seen.has(e.seq));
        state.entries = [...state.entries, ...fresh].sort((a,b) => (a.seq||0)-(b.seq||0)).slice(-500);
      }
      if (Number.isInteger(log.cursor)) state.after = log.cursor;
      else if (entries.length) state.after = entries[entries.length-1].seq || state.after;
      state.lastUpdated = new Date();
      setConnection(true, status.hosted ? "HOSTED · LOCAL DATA UNAVAILABLE" : "LOCAL GUARD CONNECTED");
      renderMetrics(); renderFeed(); renderClients(); renderPending();
    } catch (err) {
      setConnection(false, "GUARD DISCONNECTED");
      $("connection-label").textContent = "GUARD DISCONNECTED";
      $("last-refresh").textContent = "Could not reach the local Guard API";
      if (!state.lastUpdated) {
        $("feed").innerHTML = '<div class="empty"><strong>Can’t connect to Provenant</strong>Make sure the local server is running, then refresh this page.</div>';
        $("clients-list").innerHTML = '<div class="empty">Client status is unavailable until the server responds.</div>';
      }
    } finally { state.busy = false; }
  }
  document.addEventListener("click", async e => {
    const filter = e.target.closest("[data-filter]");
    if (filter) { state.filter = filter.dataset.filter; document.querySelectorAll("[data-filter]").forEach(b => b.classList.toggle("on", b === filter)); renderFeed(); }
    const copy = e.target.closest("[data-copy]");
    if (copy) { try { await navigator.clipboard.writeText(copy.dataset.copy); copy.textContent = "Copied"; } catch { copy.textContent = "Select command"; } }
  });
  $("search").addEventListener("input", e => { state.search = e.target.value; renderFeed(); });
  $("refresh").addEventListener("click", () => poll());
  poll(); setInterval(poll, 2500);

  // Make sidebar navigation explicit: scroll to the section and keep the active item in sync.
  const navItems = Array.from(document.querySelectorAll(".nav-item[href^='#']"));
  function activateSection(hash, shouldScroll = false) {
    const link = navItems.find((item) => item.getAttribute("href") === hash);
    const target = hash ? document.getElementById(hash.slice(1)) : null;
    if (!link || !target) return;
    navItems.forEach((item) => {
      const active = item === link;
      item.classList.toggle("active", active);
      if (active) item.setAttribute("aria-current", "location");
      else item.removeAttribute("aria-current");
    });
    if (shouldScroll) {
      target.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
        block: "start"
      });
    }
  }
  navItems.forEach((link) => {
    link.addEventListener("click", (event) => {
      const hash = link.getAttribute("href");
      const target = document.getElementById(hash.slice(1));
      if (!target) return;
      event.preventDefault();
      if (window.location.hash !== hash) history.pushState(null, "", hash);
      activateSection(hash, true);
    });
  });
  window.addEventListener("hashchange", () => activateSection(window.location.hash, true));
  window.addEventListener("popstate", () => activateSection(window.location.hash, true));
  if (window.location.hash) activateSection(window.location.hash, true);

})();