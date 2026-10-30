import React, { useEffect, useState, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { motion, useScroll, useSpring, MotionConfig } from "motion/react";
import { api } from "./api.js";
import { ToastHost, useToast } from "./ui.jsx";
import { Intro, Hero } from "./Hero.jsx";
import { Guard } from "./Guard.jsx";
import { Lab, Playground, Approvals, Evidence, Audit, Policy } from "./Sim.jsx";
import { HowItWorks, PhoneApproval, Efficiency, Features, Download, Trust, FinalCTA, DemoVideo } from "./Product.jsx";

const NAV = [["how", "How it works"], ["guard", "Try it"], ["phone", "Phone"], ["efficiency", "Efficiency"],
  ["features", "Features"], ["download", "Install"], ["trust", "Trust"], ["lab", "Lab"]];

function Nav({ chain, pending, onReset }) {
  const [active, setActive] = useState("");
  const { scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 200, damping: 40 });
  useEffect(() => {
    const obs = new IntersectionObserver((es) => {
      es.forEach((e) => { if (e.isIntersecting) setActive(e.target.id); });
    }, { rootMargin: "-45% 0px -50% 0px" });
    NAV.forEach(([id]) => { const el = document.getElementById(id); if (el) obs.observe(el); });
    return () => obs.disconnect();
  }, []);
  return (
    <nav className="nav" aria-label="Sections">
      <a href="#top" className="brand">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2v20" /><path d="M5 6h14M5 18h14" /></svg>
        Provenant
      </a>
      <div className="nav-links">
        <a href="/getting-started" className="nav-start" data-nav="start"><span>Get started</span></a>
        {NAV.map(([id, label]) => (
          <a key={id} href={`#${id}`} className={active === id ? "on" : ""} data-nav={id}>
            {active === id && <motion.span layoutId="nav-bg" className="nav-bg" transition={{ type: "spring", stiffness: 500, damping: 40 }} />}
            <span>{label}</span>
          </a>
        ))}
      </div>
      <div className="nav-status">
        <a href="#audit" className={`pill ${chain?.ok ? "allow" : chain ? "deny" : ""}`} title="Simulated demo audit chain">
          <i />{chain ? (chain.ok ? `demo chain · ${chain.checked}` : "demo chain broken") : "demo chain …"}
        </a>
        <a href="#approvals" className={`pill ${pending ? "hold" : ""}`}><i />{pending} demo held</a>
        <button className="pill btnlike" onClick={onReset} title="Clear runs, approvals and the in-memory audit log">Reset</button>
      </div>
      <motion.div className="nav-progress" style={{ scaleX: progress }} />
    </nav>
  );
}

function Footer() {
  return (
    <footer className="footer">
      <div className="footer-big">Provenant</div>
      <div className="footer-cols">
        <div><b>What it is</b><p>A deterministic policy enforcement point between AI agents and their tools. Built for PARALLAX 2026, AgentShield track.</p></div>
        <div><b>Honest limits</b><p>The Lab, Playground, architecture animation and phone transcript are explicit simulations, not live agent activity. Only the local Guard feed reads observed, mode-tagged audit events. The Vercel site cannot inspect your machine and does not collect remote agent telemetry. The gateway is a hackathon build, not an audited product.</p></div>
        <div><b>Built with</b><p>Python standard library · React · Motion · anime.js · Bricolage Grotesque, Geist and Geist Mono (OFL). Licences in <a href="/vendor/licenses/react-LICENSE.txt">/vendor/licenses</a>.</p></div>
        <div><b>Source</b><p><a href="https://github.com/MithunSidhaarth/provenant" rel="noopener">github.com/MithunSidhaarth/provenant</a></p></div>
      </div>
    </footer>
  );
}

function App() {
  const [ready, setReady] = useState(false);
  const [scenarios, setScenarios] = useState([]);
  const [policy, setPolicy] = useState(null);
  const [chain, setChain] = useState(null);
  const [pending, setPending] = useState(0);
  const [tick, setTick] = useState(0);
  const toast = useToast();

  const refresh = useCallback(async () => {
    try {
      const [v, p] = await Promise.all([api("/api/audit/verify"), api("/api/approvals")]);
      setChain(v); setPending(p.length); setTick((t) => t + 1);
    } catch { /* offline */ }
  }, []);

  useEffect(() => {
    api("/api/scenarios").then(setScenarios).catch(() => toast("Can't reach the Provenant server.", "deny"));
    api("/api/policy").then(setPolicy).catch(() => {});
    refresh();
  }, [refresh, toast]);

  const reset = async () => {
    try { await api("/api/reset", {}); toast("Demo state cleared", "allow"); refresh(); } catch (e) { toast(e.message, "deny"); }
  };
  const done = useCallback(() => setReady(true), []);

  return (
    <>
      {!ready && <Intro onDone={done} />}
      <Nav chain={chain} pending={pending} onReset={reset} />
      <main>
        <Hero ready={ready} scenarios={scenarios} onRun={refresh} />
        <DemoVideo />
        <HowItWorks />
        <Guard />
        <PhoneApproval />
        <Efficiency />
        <Features />
        <Download />
        <Trust />
        <Lab />
        <Playground tools={policy?.tools || []} />
        <Approvals refreshKey={tick} onChange={refresh} />
        <Evidence />
        <Audit refreshKey={tick} />
        <Policy policy={policy} />
        <FinalCTA />
      </main>
      <Footer />
    </>
  );
}

createRoot(document.getElementById("root")).render(<MotionConfig reducedMotion="user"><ToastHost><App /></ToastHost></MotionConfig>);
