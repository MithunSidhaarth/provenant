import React, { useEffect, useRef, useState, useCallback } from "react";
import { motion, AnimatePresence, useMotionValue, useSpring, useTransform, animate } from "motion/react";
import { api, argsLine, reduced } from "./api.js";
import { Stamp, Badge, ErrorNote } from "./ui.jsx";

const HEADLINE = [["Same", "agent."], ["Same", "attack."], ["Different", "world."]];

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
    <h1 className="hero-title" aria-label="Same agent. Same attack. Different world.">
      {HEADLINE.map((line, li) => (
        <span className={`hl-line${li === 2 ? " accent" : ""}`} key={li} aria-hidden="true">
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

function Step({ step, protectedSide, play, i }) {
  const r = step.result || {};
  const call = r.call || {};
  const injected = step.source === "injected";
  const malformed = step.source === "malformed";
  const denied = protectedSide && r.decision && r.decision !== "ALLOW";
  return (
    <motion.li className={`tstep${injected ? " injected" : ""}${denied ? " denied" : ""}`}
      initial={{ opacity: 0, y: 10 }} animate={play ? { opacity: 1, y: 0 } : { opacity: 0, y: 10 }}
      transition={{ duration: 0.45, delay: 0.35 + i * 0.32, ease: [0.16, 1, 0.3, 1] }}>
      <div className="tstep-row">
        <span className="tstep-src">{injected ? "injected" : malformed ? "malformed" : "user plan"}</span>
        <span className="tstep-tool">{call.tool || "(malformed call)"}</span>
        {protectedSide ? (play && <Stamp d={r.decision} play={play} />) : <span className="tstep-ok">ran</span>}
      </div>
      <div className="tstep-args">{argsLine(call.args)}</div>
      {protectedSide && r.reasons && r.reasons.length > 0 && r.decision !== "ALLOW" && (
        <div className="tstep-why">{r.reasons[0]}{r.reasons.length > 1 ? `  +${r.reasons.length - 1} more` : ""}</div>
      )}
    </motion.li>
  );
}

function Pane({ report, side, play }) {
  const prot = side === "after";
  const harms = report?.outcome?.harms || [];
  const steps = report?.trace?.steps || [];
  return (
    <div className={`pane ${side}`}>
      <div className="pane-head">
        <span className={`pane-dot ${prot ? "allow" : "deny"}`} />
        <span className="pane-label">{prot ? "With Provenant" : "Unprotected agent"}</span>
        <span className="pane-sub">{prot ? "every call passes one enforcement point" : "tool calls run as proposed"}</span>
      </div>
      <ol className="tsteps">
        {steps.map((s, i) => <Step key={i} step={s} i={i} protectedSide={prot} play={play} />)}
      </ol>
      <motion.div className={`verdict ${prot ? (harms.length ? "deny" : "allow") : (harms.length ? "deny" : "allow")}`}
        initial={{ opacity: 0 }} animate={play ? { opacity: 1 } : { opacity: 0 }} transition={{ delay: 0.5 + steps.length * 0.32 }}>
        <div className="verdict-title">{report?.verdict || "…"}</div>
        <div className="verdict-sub">
          {harms.length ? harms.map((h) => h.detail).join(" · ") : "no harm reached the world"}
        </div>
      </motion.div>
    </div>
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
  const stage = useRef(null);
  const pos = useMotionValue(50);
  const spring = useSpring(pos, { stiffness: 260, damping: 30, mass: 0.6 });
  const clip = useTransform(spring, (v) => `inset(0 0 0 ${v}%)`);
  const left = useTransform(spring, (v) => `${v}%`);
  const dragging = useRef(false);

  const run = useCallback(async (id) => {
    setErr(null);
    try {
      const d = await api("/api/compare", { scenario_id: id });
      setData(d); setRunKey((k) => k + 1); onRun && onRun(d);
    } catch (e) { setErr(e); }
  }, [onRun]);

  useEffect(() => { if (scenarios.length) run(sid); }, [scenarios.length, sid, run]);

  // On load the divider sweeps across once, then springs back to the middle.
  useEffect(() => {
    if (!ready || reduced()) return;
    const a = animate(pos, [50, 86, 14, 50], { duration: 2.4, delay: 1.1, ease: "easeInOut" });
    return () => a.stop();
  }, [ready, pos]);

  const setFromEvent = (e) => {
    const r = stage.current.getBoundingClientRect();
    pos.set(Math.max(4, Math.min(96, ((e.clientX - r.left) / r.width) * 100)));
  };
  const onDown = (e) => { dragging.current = true; e.currentTarget.setPointerCapture?.(e.pointerId); setFromEvent(e); };
  const onMove = (e) => { if (dragging.current) setFromEvent(e); };
  const onUp = () => { dragging.current = false; };
  const onKey = (e) => {
    if (e.key === "ArrowLeft") pos.set(Math.max(4, pos.get() - 5));
    if (e.key === "ArrowRight") pos.set(Math.min(96, pos.get() + 5));
  };

  const cur = scenarios.find((s) => s.id === sid);
  const play = ready && !!data;
  return (
    <header className="hero" id="top">
      <div className="hero-grid" aria-hidden="true" />
      <div className="hero-copy">
        <motion.div className="eyebrow" initial={{ opacity: 0 }} animate={ready ? { opacity: 1 } : {}} transition={{ delay: 0.5 }}>
          A deterministic firewall for AI agents · MCP · Claude Code
        </motion.div>
        <Headline ready={ready} />
        <motion.p className="hero-lede" initial={{ opacity: 0, y: 12 }} animate={ready ? { opacity: 1, y: 0 } : {}} transition={{ delay: 0.7, duration: 0.8 }}>
          A poisoned document tells the agent to steal a secret. On the left nothing stops it. On the right
          Provenant checks every tool call against policy and provenance before it runs. Drag the line.
        </motion.p>
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

      <motion.div className="stage" ref={stage} initial={{ opacity: 0, y: 40, scale: 0.98 }}
        animate={ready ? { opacity: 1, y: 0, scale: 1 } : {}} transition={{ delay: 0.95, duration: 1, ease: [0.16, 1, 0.3, 1] }}
        onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} onPointerCancel={onUp}>
        <ErrorNote error={err} />
        {cur && <div className="stage-task"><span>Task</span>{cur.user_task}</div>}
        <div className="stage-panes" key={runKey}>
          <Pane report={data?.before} side="before" play={play} />
          <motion.div className="pane-clip" style={{ clipPath: clip }}>
            <Pane report={data?.after} side="after" play={play} />
          </motion.div>
          <motion.div className="divider" style={{ left }} role="slider" tabIndex={0} aria-label="Compare unprotected and protected"
            aria-valuemin={0} aria-valuemax={100} aria-valuenow={50} onKeyDown={onKey}>
            <span className="divider-handle"><span>‹</span><span>›</span></span>
          </motion.div>
        </div>
      </motion.div>
      <AnimatePresence>
        {ready && (
          <motion.a href="#guard" className="scroll-cue" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2.4 }}>
            Protect your own agents <span aria-hidden="true">↓</span>
          </motion.a>
        )}
      </AnimatePresence>
    </header>
  );
}
