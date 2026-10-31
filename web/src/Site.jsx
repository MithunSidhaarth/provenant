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

function Hero() {
  return (
    <section className="hero" id="top">
      <div className="glow" aria-hidden="true" />
      <div className="wrap hero-inner">
        <Reveal className="eyebrow"><span className="dot" />Open source · local-first · works with MCP and Claude Code</Reveal>
        <Reveal as="h1" delay={0.05}>The firewall between<br />AI agents and <span className="grad">their tools.</span></Reveal>
        <Reveal as="p" className="lede" delay={0.1}>
          Your agent reads email, web pages and documents. Any of them can carry instructions. Provenant checks every tool call
          against deterministic policy before it runs, so a fooled model still can't do damage.
        </Reveal>
        <Reveal className="hero-cta" delay={0.15}>
          <a className="btn" href="#install">Install in one line</a>
          <a className="btn ghost-btn" href={GH} rel="noopener">View on GitHub</a>
        </Reveal>
        <Reveal className="hero-console" delay={0.2}><Console /></Reveal>
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
        <Reveal as="h2">The model proposes.<br /><span className="mute">Policy decides.</span></Reveal>
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
