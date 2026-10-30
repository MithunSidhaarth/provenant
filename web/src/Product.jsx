import React, { useEffect, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { api, reduced } from "./api.js";
import { Section, Reveal, Badge, Cmd, CopyButton } from "./ui.jsx";

const REPO = "https://github.com/MithunSidhaarth/provenant";
const fmt = (n) => (typeof n === "number" ? n.toLocaleString("en-US") : "—");

function useJson(path) {
  const [d, setD] = useState(null);
  useEffect(() => { fetch(path).then((r) => (r.ok ? r.json() : null)).then(setD).catch(() => setD(null)); }, [path]);
  return d;
}

function useCycle(n, ms) {
  const [i, setI] = useState(0);
  useEffect(() => {
    if (reduced()) return;
    const t = setInterval(() => setI((x) => (x + 1) % n), ms);
    return () => clearInterval(t);
  }, [n, ms]);
  return i;
}

// ---------- architecture -------------------------------------------------------------------------
const STAGES = [
  ["Agent", "any model proposes a tool call"],
  ["Gateway", "MCP proxy · provenant-tools · Claude Code hook"],
  ["Policy", "deterministic rules, most restrictive wins"],
  ["Approval", "only if required: terminal or phone"],
  ["Grant", "single use, bound to this exact call"],
  ["Execution", "the tool runs, or nothing does"],
  ["Audit", "hash-chained, HMAC, optional external checkpoint"],
];
const CALLS = [
  { label: "read_file src/app.py", d: "ALLOW", path: [0, 1, 2, 4, 5, 6], why: "inside the workspace, not a secret" },
  { label: "read_file .env", d: "DENY", path: [0, 1, 2, 6], why: "credential file: blocked before it runs" },
  { label: "send_email to lead@corp.example", d: "REQUIRE_APPROVAL", path: [0, 1, 2, 3, 4, 5, 6], why: "outbound message: a human approves this exact call" },
  { label: "frobnicate (unknown tool)", d: "REQUIRE_APPROVAL", path: [0, 1, 2, 3, 6], why: "unclassified tools never run on their own" },
];

export function HowItWorks() {
  const ci = useCycle(CALLS.length, 4200);
  const call = CALLS[ci];
  const [step, setStep] = useState(0);
  useEffect(() => {
    if (reduced()) { setStep(call.path.length - 1); return; }
    setStep(0);
    const t = setInterval(() => setStep((s) => Math.min(s + 1, call.path.length - 1)), 480);
    return () => clearInterval(t);
  }, [ci, call.path.length]);
  const lit = new Set(call.path.slice(0, step + 1));
  const at = call.path[step];
  const cls = { ALLOW: "allow", DENY: "deny", REQUIRE_APPROVAL: "hold" }[call.d];
  return (
    <Section id="how" kicker="How it works" title={<>A model can propose. <em>Only policy can authorize.</em></>}
      lede="Every protected tool call takes one path. The decision is plain code over the call's structure: no extra LLM call, the same answer for the same input, and anything it cannot classify or evaluate is held or blocked.">
      <Reveal>
        <div className="arch" role="img" aria-label="Agent, gateway, policy, approval if required, single-use grant, execution, audit">
          <div className="arch-call">
            <span className="muted">proposed</span>
            <AnimatePresence mode="wait">
              <motion.code key={ci} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }}>{call.label}</motion.code>
            </AnimatePresence>
          </div>
          <ol className="arch-row">
            {STAGES.map(([name, sub], i) => (
              <li key={name} className={`arch-node${lit.has(i) ? " lit " + cls : ""}${at === i ? " at" : ""}${!call.path.includes(i) ? " skip" : ""}`}>
                <b>{name}</b><span>{sub}</span>
                {at === i && <motion.i layoutId="arch-dot" className={`arch-dot ${cls}`} transition={{ type: "spring", stiffness: 300, damping: 30 }} />}
              </li>
            ))}
          </ol>
          <div className="arch-out">
            <Badge d={call.d} /><span>{call.why}</span>
          </div>
        </div>
      </Reveal>
      <div className="outcomes">
        {[["ALLOW", "The call matches policy. A one-time grant is issued and redeemed right before the tool runs."],
          ["DENY", "Credentials, destructive commands, private-network fetches, tampering with Provenant itself. Nothing runs."],
          ["REQUIRE_APPROVAL", "Side effects a person should see. Held until a named human approves this exact call."]].map(([d, t], i) => (
          <Reveal key={d} delay={i * 0.08} className="outcome card"><Badge d={d} /><p>{t}</p></Reveal>
        ))}
      </div>
    </Section>
  );
}

// ---------- phone approval ------------------------------------------------------------------------
const TRANSCRIPT = [
  ["ivy", "Hi, it's Ivy for your agent. Provenant paused one action: send an email to lead@corp.example saying the deploy finished."],
  ["you", "What exactly will it send?"],
  ["ivy", "One line: “Deploy finished, all checks green.” To approve, say approve and the code 4 7 1 9. To refuse, say deny."],
  ["you", "Approve, four seven one nine."],
  ["ivy", "Got it. Provenant will check that and decide."],
];
const CHECKS = [
  ["call completed, answered by a person", true],
  ["the approving words came from you, not the agent", true],
  ["a question is never an approval", true],
  ["code 4719 matches this request's fingerprint", true],
  ["no “no”, “deny” or “stop” anywhere", true],
];

export function PhoneApproval() {
  const [n, setN] = useState(reduced() ? TRANSCRIPT.length : 0);
  useEffect(() => {
    if (reduced()) return;
    const t = setInterval(() => setN((x) => (x >= TRANSCRIPT.length + 3 ? 0 : x + 1)), 1500);
    return () => clearInterval(t);
  }, []);
  const done = n >= TRANSCRIPT.length;
  return (
    <Section id="phone" kicker="Human approval · by phone" title={<>When it matters, <em>Provenant calls you.</em></>}
      lede="A held action can ring your phone through the claude-call-me voice agent. You can ask questions, then approve or refuse that one action. The voice agent only carries words: Provenant reads the transcript with fixed rules and is the only thing that can change the approval.">
      <div className="phone-grid">
        <Reveal className="phone card">
          <div className="phone-top"><span className={`ring${done ? "" : " on"}`} /> <b>Ivy · Provenant approval</b><span className="vis-tag">simulation · no live call</span></div>
          <ol className="phone-lines">
            <AnimatePresence initial={false}>
              {TRANSCRIPT.slice(0, Math.min(n, TRANSCRIPT.length)).map(([who, text], i) => (
                <motion.li key={i} className={who} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                  <span>{who === "ivy" ? "Ivy" : "You"}</span>{text}
                </motion.li>
              ))}
            </AnimatePresence>
          </ol>
        </Reveal>
        <Reveal className="card validator" delay={0.08}>
          <div className="card-head"><h3>What Provenant checks</h3><span className="muted">deterministic</span></div>
          <ul className="checks">
            {CHECKS.map(([t], i) => (
              <li key={t} className={done ? "ok" : ""} style={{ transitionDelay: `${i * 90}ms` }}><i />{t}</li>
            ))}
          </ul>
          <div className={`phone-verdict${done ? " show" : ""}`}><Badge d="ALLOW" /> approved once, for this call, for 15 minutes</div>
          <div className="phone-rules">
            <div><b>Stays blocked</b> no answer · voicemail · timeout · provider error · approval without the code · any refusal word</div>
            <div><b>Bound</b> the code is an HMAC of this request's id and call fingerprint; changed arguments need a new approval</div>
            <div><b>Status</b> adapter and validator are built and tested against simulated transcripts. A live call needs your own Bolna account and claude-call-me; we have not claimed one in this demo.</div>
          </div>
          <p className="muted small">Illustrative transcript only. No phone call is placed and no approval is recorded by this animation.</p>
        </Reveal>
      </div>
    </Section>
  );
}

// ---------- efficiency ----------------------------------------------------------------------------
function Bar({ label, a, b, unit = "" }) {
  const max = Math.max(a, b) || 1;
  const pct = a ? Math.round(((b - a) / a) * 100) : 0;
  return (
    <div className="ebar">
      <div className="ebar-label"><span>{label}</span><b className={pct <= 0 ? "allow-t" : "hold-t"}>{pct > 0 ? "+" : ""}{pct}%</b></div>
      <div className="ebar-row"><span className="muted">baseline</span><div className="ebar-track"><motion.i className="base" initial={{ width: 0 }} whileInView={{ width: `${(a / max) * 100}%` }} viewport={{ once: true }} transition={{ duration: 1 }} /></div><code>{fmt(a)}{unit}</code></div>
      <div className="ebar-row"><span className="muted">provenant</span><div className="ebar-track"><motion.i className="prov" initial={{ width: 0 }} whileInView={{ width: `${(b / max) * 100}%` }} viewport={{ once: true }} transition={{ duration: 1, delay: 0.2 }} /></div><code>{fmt(b)}{unit}</code></div>
    </div>
  );
}

export function Efficiency() {
  const tb = useJson("/eval/token_benchmark.json");
  const s = tb?.summary;
  return (
    <Section id="efficiency" kicker="Efficiency" title={<>Security that <em>saves tokens.</em></>}
      lede="Policy checks cost zero model calls. For tools Provenant runs itself, long files come back as an outline plus the lines you ask for, test runs keep only failures and the summary, and unchanged re-reads become a short reference. Authorization is never cached; writes and sends are never cached.">
      <div className="eff-grid">
        <Reveal className="card">
          <div className="card-head"><h3>Measured on one workload</h3><span className="muted">{tb ? `${tb.generated_utc} · ${tb.commit}` : "loading"}</span></div>
          {s ? (
            <>
              <Bar label="Tool-result tokens entering context" a={s.context_tokens.baseline} b={s.context_tokens.provenant} />
              <Bar label="Cumulative input tokens (no prompt cache)" a={s.reread_input_tokens.baseline} b={s.reread_input_tokens.provenant} />
              <Bar label="Tool calls" a={s.tool_calls.baseline} b={s.tool_calls.provenant} />
              <p className="muted small">{s.workload}. Task success: baseline {String(s.task_success.baseline)}, Provenant {String(s.task_success.provenant)}.
                Tokens are estimated as characters ÷ 4. Provenant makes more, smaller calls (targeted reads), which adds round trips. Other workloads will save more, less or nothing.</p>
            </>
          ) : <p className="muted">Benchmark results are not available on this deployment.</p>}
        </Reveal>
        <Reveal className="card" delay={0.08}>
          <div className="card-head"><h3>How</h3></div>
          <ul className="plain">
            <li><b>Deterministic policy</b> about 0.14 ms per decision, no LLM in the loop</li>
            <li><b>Outline + targeted reads</b> long files return definitions with line numbers; ask for a range or <code>full: true</code></li>
            <li><b>Test output</b> failures, tracebacks and the summary; progress lines dropped</li>
            <li><b>Safe cache</b> read-only tools only, keyed by tool, args, session, mode, policy version and file freshness</li>
            <li><b>Dedup</b> an unchanged re-read returns a reference to the earlier result</li>
          </ul>
          <Cmd>python evals/token_bench.py</Cmd>
        </Reveal>
      </div>
    </Section>
  );
}

// ---------- features ------------------------------------------------------------------------------
const FEATURES = [
  ["Deterministic policy engine", "tested", "Explicit rules over the call's structure. Unknown tools are held; any error is a DENY."],
  ["Model independence", "tested", "Works on the tool call, not the model. Claude Code, Claude Desktop, Cursor, Windsurf or any stdio MCP client."],
  ["Gateway enforcement", "tested", "MCP proxy, the provenant-tools server and the Claude Code hook. Calls run only with a redeemed single-use grant."],
  ["Phone approval", "experimental", "claude-call-me adapter with a deterministic transcript validator. Tested with simulated transcripts; no live call claimed."],
  ["SQLite authorization state", "tested", "Approvals, grants and sessions with atomic transitions; 8 racing processes, exactly one wins."],
  ["Tamper-evident audit", "tested", "Hash chain + HMAC, minimal metadata by default, secrets redacted, external checkpoints catch truncation and rewrites."],
  ["MCP protocol coverage", "tested", "Explicit method allow-list, gated resources/read, refused sampling, dropped notification-shaped calls."],
  ["Secret detection", "tested", "Recognisable keys, tokens and private keys in outbound arguments, including split across fields. Pattern-based."],
  ["Network destination checks", "tested", "Decimal, hex, octal, IPv6-mapped and NAT64 forms; resolve-then-pin connections; every redirect re-checked."],
  ["Policy simulator", "tested", "Saved scenarios, explanations of the deciding rule, and lint for shadowed and overbroad rules."],
  ["Security evaluation", "tested", "128 attacks, 35 legitimate actions, live process checks, latency. One command, regenerated from code."],
  ["Token optimization", "tested", "Outline reads, test-output trimming, safe cache, dedup. Measured, with the caveats shown."],
  ["Fail-closed behaviour", "tested", "Corrupt state, newer schema, broken policy, garbage input, failed grant redemption: nothing runs."],
  ["Signed releases", "experimental", "SHA256SUMS, CycloneDX SBOM and provenance on every build; Sigstore attestations in the release workflow (not yet run)."],
  ["Remote MCP (HTTP) proxying", "planned", "Only stdio servers are proxied today."],
  ["OS-level containment", "planned", "Pattern checks are not isolation. A sandboxed executor is the next boundary."],
];

export function Features() {
  return (
    <Section id="features" kicker="What ships" title={<>Every claim, <em>labelled.</em></>}
      lede="Tested means covered by the test suite or the evaluation in this repository. Experimental means built but not yet proven end to end. Planned means not built.">
      <div className="features">
        {FEATURES.map(([t, st, d], i) => (
          <Reveal key={t} delay={(i % 4) * 0.05} className="feature card">
            <span className={`fstatus ${st}`}>{st}</span>
            <h3>{t}</h3>
            <p>{d}</p>
          </Reveal>
        ))}
      </div>
    </Section>
  );
}

// ---------- download + developers -----------------------------------------------------------------
export function Download() {
  const rel = useJson("/download/latest.json");
  const wheel = rel?.wheel;
  const pub = rel?.urls;                       // public GitHub URLs: the site itself may sit behind Vercel sign-in
  const base = pub ? pub.wheel.slice(0, pub.wheel.lastIndexOf("/")) : null;
  const sha = wheel && rel.sha256?.[wheel];
  const snippet = JSON.stringify({ mcpServers: { provenant: { command: "provenant", args: ["serve", "--workspace", "/path/to/project"] } } }, null, 2);
  return (
    <Section id="download" kicker="Install" title={<>Download Provenant. <em>Run the attacks yourself.</em></>}
      lede="One wheel, no dependencies, Python 3.10 or newer. Everything below uses the commands that ship in this version.">
      <div className="dl-grid">
        <Reveal className="card dl-main">
          <div className="card-head"><h3>{rel ? `Provenant ${rel.version}` : "Provenant"}</h3><span className="muted">{rel ? `commit ${rel.commit.slice(0, 7)}` : ""}</span></div>
          {wheel && pub ? (
            <>
              <a className="btn primary big" href="/getting-started">Get protected: guided setup <span aria-hidden="true">→</span></a>
              <a className="btn ghost big" href={pub.wheel}>Download the wheel <span aria-hidden="true">↓</span> <span className="muted small">{rel.size?.[wheel] ? `${Math.round(rel.size[wheel] / 1024)} KB` : ""}</span></a>
              <div className="sha"><span className="muted">SHA-256</span><code>{sha}</code><CopyButton text={sha || ""} /></div>
              <Cmd>{`python -m pip install --user ${pub.wheel}`}</Cmd>
              <div className="dl-links">
                <a href={pub.sha256sums}>SHA256SUMS</a>
                <a href={`${base}/sbom.cdx.json`}>SBOM (CycloneDX)</a>
                <a href={`${base}/provenance.json`}>Build provenance</a>
                <a href={pub.sdist}>Source archive</a>
                <a href={REPO} rel="noopener">GitHub</a>
                <a href="/eval/REPORT.md">Security results</a>
              </div>
              <p className="muted small">Requires Python 3.10+. Files are served from GitHub, so the link works without signing in anywhere. Checked by <code>scripts/check_download.py</code>: HTTP 200, binary content type, SHA-256, zip integrity, and a clean virtualenv install on Linux (Python 3.13). Windows and macOS run in CI once the workflows run.</p>
            </>
          ) : <p className="muted" role="status">Release details could not be loaded on this deployment. Use the <a href="/getting-started">guided setup</a> or install from source: <code>git clone {REPO}</code>.</p>}
        </Reveal>
        <Reveal className="card dev" delay={0.08}>
          <div className="card-head"><h3>Developers</h3><span className="muted">quick start</span></div>
          <ol className="dev-steps">
            <li><b>Protect your clients</b> shows a plan for Claude Desktop, Cursor, Windsurf and the Claude Code hook, asks, then applies it (reversible with <code>provenant rollback</code>).<Cmd>provenant setup</Cmd></li>
            <li><b>Prove it</b> a harmless enforcement test: allow, deny, hold, audit. Then see which clients are actually connected.<Cmd>provenant verify && provenant status</Cmd></li>
            <li><b>Or add Provenant's own tools</b> to any MCP client. <code>provenant config --workspace DIR</code> prints this with your real paths:<pre className="snippet">{snippet}</pre></li>
            <li><b>See a denial</b> dry-run a call through the policy; nothing executes.<Cmd>{`provenant check Bash '{"command": "cat .env"}'`}</Cmd></li>
            <li><b>Write policy</b> copy the built-in policy, then test and lint it.<Cmd>provenant policy init && provenant policy test && provenant policy lint</Cmd></li>
            <li><b>Approve</b> held calls in a terminal, or by phone with claude-call-me installed.<Cmd>provenant pending && provenant approve ID</Cmd></li>
            <li><b>Watch and verify</b> the live decision feed and the audit chain.<Cmd>provenant log -f</Cmd></li>
            <li><b>Evaluate</b> from a clone: the full attack corpus, live checks and the token benchmark.<Cmd>python evals/run_eval.py</Cmd></li>
          </ol>
        </Reveal>
      </div>
    </Section>
  );
}

// ---------- trust ---------------------------------------------------------------------------------
export function Trust() {
  const r = useJson("/eval/results.json");
  const c = r?.corpus, lv = r?.live, ut = r?.unit_tests;
  const stats = r ? [
    [`${c.attacks.contained}/${c.attacks.total}`, "attacks contained", "never ALLOWed; 110 denied, 18 held"],
    [`${c.benign.allowed_as_expected}/${c.benign.total}`, "legitimate actions", "decided as expected, 0 false positives"],
    [`${lv.passed}/${lv.total}`, "live process checks", "real MCP server behind the real proxy"],
    [`${ut.ran - ut.failed.length}/${ut.ran}`, "tests", "unit and integration"],
    [`${c.latency_ms.p50} ms`, "policy decision p50", `p95 ${c.latency_ms.p95} ms, no model call`],
    [`${lv.timing_ms.overhead_ms_p50} ms`, "gateway overhead p50", "per call, with SQLite and audit writes"],
  ] : [];
  return (
    <Section id="trust" kicker="Security and trust" title={<>Proof, <em>not promises.</em></>}
      lede="Passing these cases is evidence for the cases listed, not proof that no bypass exists. The numbers below are read from the evaluation output this deployment was built with.">
      {r && (
        <Reveal className="trust-stats">
          {stats.map(([v, l, s]) => (
            <div key={l} className="tstat"><b>{v}</b><span>{l}</span><em>{s}</em></div>
          ))}
        </Reveal>
      )}
      <div className="trust-grid">
        <Reveal className="card">
          <div className="card-head"><h3>The boundary</h3></div>
          <ul className="plain">
            <li>Protected actions pass through the gateway: the MCP proxy, provenant-tools, or the Claude Code hook.</li>
            <li>Unknown tools and unknown MCP methods are held or refused. There is no fallback to direct execution.</li>
            <li>A tool runs only after its single-use grant is redeemed for that exact call.</li>
            <li>Demo and live keep separate state; a demo approval can never unlock a live call.</li>
            <li>Not covered: an agent or attacker with its own unrestricted access to the host. That needs OS-level isolation.</li>
          </ul>
        </Reveal>
        <Reveal className="card" delay={0.06}>
          <div className="card-head"><h3>Known limitations</h3></div>
          <ul className="plain">{(r?.known_gaps || []).map((g) => <li key={g}>{g}</li>)}</ul>
          {r && <p className="muted small">Generated {r.generated_utc}, commit {r.environment.commit}, policy {r.environment.policy_version}. <a href="/eval/REPORT.md">Full report</a></p>}
        </Reveal>
      </div>
    </Section>
  );
}

export function FinalCTA() {
  return (
    <section className="final">
      <Reveal>
        <h2>We are not building another agent.<br /><em>We are building the layer that makes agents accountable.</em></h2>
        <div className="cta-row">
          <a className="btn primary big" href="/getting-started">Get protected</a>
          <a className="btn ghost big" href={REPO} rel="noopener">Read the source</a>
          <a className="btn ghost big" href="#top">Run the security demo</a>
        </div>
      </Reveal>
    </section>
  );
}

export function DemoVideo() {
  const m = useJson("/media/manifest.json");
  if (!m || !m.video) return null;
  return (
    <Section id="video" kicker="Watch" title={<>Provenant in <em>two minutes.</em></>}>
      <Reveal className="video-wrap">
        <video controls preload="none" poster={m.poster || undefined} src={m.video} />
      </Reveal>
    </Section>
  );
}
