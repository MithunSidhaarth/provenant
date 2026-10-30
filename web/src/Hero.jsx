import React, { useEffect, useRef, useState, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Arena } from "./Arena.jsx";
import { api, reduced } from "./api.js";
import { ErrorNote } from "./ui.jsx";

const HEADLINE = [["Give", "your", "AI", "agents"], ["a", "security"], ["boundary."]];

// The load sequence: a hairline draws across the screen, the screen splits along it, the page is underneath.
export function Intro({ onDone }) {
  const [phase, setPhase] = useState(0);
  useEffect(() => {
    if (reduced()) { onDone(); return; }
    const t1 = setTimeout(() => setPhase(1), 950);
    const t2 = setTimeout(() => onDone(), 1900);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, [onDone]);
  return (
    <div className="intro" aria-hidden="true">
      <motion.div className="intro-half top" animate={phase ? { y: "-100%" } : { y: 0 }}
        transition={{ duration: 0.9, ease: [0.76, 0, 0.24, 1] }} />
      <motion.div className="intro-half bottom" animate={phase ? { y: "100%" } : { y: 0 }}
        transition={{ duration: 0.9, ease: [0.76, 0, 0.24, 1] }} />
      <motion.div className="intro-line" initial={{ scaleX: 0 }} animate={phase ? { scaleX: 1, opacity: 0 } : { scaleX: 1 }}
        transition={phase ? { duration: 0.4 } : { duration: 0.85, ease: [0.65, 0, 0.35, 1] }} />
      <motion.div className="intro-mark" initial={{ opacity: 0, y: 8 }} animate={phase ? { opacity: 0 } : { opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: phase ? 0 : 0.3 }}>
        PROVENANT
      </motion.div>
    </div>
  );
}

function Headline({ ready }) {
  let n = 0;
  return (
    <h1 className="hero-title" aria-label="Give your AI agents a security boundary.">
      {HEADLINE.map((line, li) => (
        <span className={`hl-line${li === 1 ? " accent" : ""}`} key={li} aria-hidden="true">
          {line.map((w) => {
            const i = n++;
            return (
              <span className="hl-mask" key={w + i}>
                <motion.span className="hl-word" initial={{ y: "110%" }} animate={ready ? { y: "0%" } : { y: "110%" }}
                  transition={{ duration: 1.05, delay: 0.08 * i, ease: [0.16, 1, 0.3, 1] }}>{w}</motion.span>
              </span>
            );
          })}
        </span>
      ))}
    </h1>
  );
}

const SHORT = { doc_injection: "Poisoned document", kb_injection: "Poisoned knowledge base", sensitive_data_request: "Data grab",
  excess_permissions: "Permission over-reach", fail_closed_malformed: "Malformed calls" };

export function Hero({ ready, scenarios, onRun }) {
  const attacks = scenarios.filter((s) => s.kind !== "benign");
  const [sid, setSid] = useState("doc_injection");
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [runKey, setRunKey] = useState(0);
  const run = useCallback(async (id) => {
    setErr(null);
    try {
      const d = await api("/api/compare", { scenario_id: id });
      setData(d); setRunKey((k) => k + 1); onRun && onRun(d);
    } catch (e) { setErr(e); }
  }, [onRun]);

  useEffect(() => { if (scenarios.length) run(sid); }, [scenarios.length, sid, run]);

  const cur = scenarios.find((s) => s.id === sid);
  const play = ready && !!data;
  return (
    <header className="hero" id="top">
      <div className="hero-grid" aria-hidden="true" />
      <div className="hero-copy">
        <motion.div className="eyebrow" initial={{ opacity: 0 }} animate={ready ? { opacity: 1 } : {}} transition={{ delay: 0.5 }}>
          Model-independent policy enforcement for AI agents · MCP · Claude Code
        </motion.div>
        <Headline ready={ready} />
        <motion.p className="hero-lede" initial={{ opacity: 0, y: 12 }} animate={ready ? { opacity: 1, y: 0 } : {}} transition={{ delay: 0.7, duration: 0.8 }}>
          Provenant evaluates tool calls, enforces deterministic security policies, routes configured risky actions
          for human approval, and records auditable decisions. Add optional model-assisted risk intelligence without
          surrendering policy control to an LLM.
        </motion.p>
        <motion.div className="hero-cta" initial={{ opacity: 0, y: 10 }} animate={ready ? { opacity: 1, y: 0 } : {}} transition={{ delay: 0.8 }}>
          <a className="btn primary big" href="/getting-started">Get protected</a>
          <a className="btn ghost big" href="#how">See how it works</a>
          <a className="hero-link" href="#trust">Security model →</a>
        </motion.div>
        <motion.div className="hero-steps" initial={{ opacity: 0 }} animate={ready ? { opacity: 1 } : {}} transition={{ delay: 0.9 }}>
          <span><b>1</b> Install</span><span><b>2</b> <code>provenant setup</code> connects Claude Code, Claude Desktop, Cursor or Windsurf</span>
          <span><b>3</b> <code>provenant verify</code> proves a forbidden action is blocked on your machine</span>
        </motion.div>
      </div>

      <motion.div className="scenario-bar" role="tablist" aria-label="Attack scenario"
        initial={{ opacity: 0, y: 10 }} animate={ready ? { opacity: 1, y: 0 } : {}} transition={{ delay: 0.85 }}>
        {attacks.map((s) => (
          <button key={s.id} role="tab" aria-selected={s.id === sid} className={`chip${s.id === sid ? " on" : ""}`}
            onClick={() => (s.id === sid ? run(sid) : setSid(s.id))}>
            {s.id === sid && <motion.span layoutId="chip-bg" className="chip-bg" transition={{ type: "spring", stiffness: 500, damping: 40 }} />}
            <span>{SHORT[s.id] || s.title}</span>
          </button>
        ))}
        <button className="chip ghost" onClick={() => run(sid)} title="Run the scenario again">Replay ↻</button>
      </motion.div>

      <motion.div className="stage" initial={{ opacity: 0, y: 40, scale: 0.98 }}
        animate={ready ? { opacity: 1, y: 0, scale: 1 } : {}} transition={{ delay: 0.95, duration: 1, ease: [0.16, 1, 0.3, 1] }}>
        <ErrorNote error={err} />
        <div className="stage-label">Live replay · simulated world · fake data</div>
        {cur && <div className="stage-task"><span>Task</span>{cur.user_task}</div>}
        <Arena data={data} play={play} runKey={runKey} />
      </motion.div>
      <AnimatePresence>
        {ready && (
          <motion.a href="#how" className="scroll-cue" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2.4 }}>
            See how it works <span aria-hidden="true">↓</span>
          </motion.a>
        )}
      </AnimatePresence>
    </header>
  );
}
