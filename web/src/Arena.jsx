import React, { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import anime from "animejs/lib/anime.es.js";
import { argsLine, decisionOf, reduced } from "./api.js";

// The hero replay: the same scenario runs twice, side by side in time. Each tool call flies down two lanes.
// Top lane: no enforcement, every call lands in the world. Bottom lane: every call hits the Provenant gate first.
// Everything shown comes from /api/compare (the simulated world); nothing here is decided in the browser.

const GATE = 50;          // gate position, % of lane width
const START = 10;         // agent position
const WORLD = 88;         // world position
const STEP_MS = 1500;
const SHARDS = 14;

const srcLabel = (s) => (s === "injected" ? "injected" : s === "malformed" ? "malformed" : "user plan");

function Packet({ step, lane, i }) {
  const call = step?.result?.call || {};
  const inj = step?.source === "injected";
  return (
    <div className={`pk pk-${lane}-${i}`} style={{ left: `${START}%` }}>
      <div className={`pk-chip${inj ? " inj" : ""}${step?.source === "malformed" ? " bad" : ""}`}>
        {inj && <i aria-hidden="true">⚠</i>}{call.tool || "malformed"}
      </div>
    </div>
  );
}

function World({ lane, count, harmed }) {
  return (
    <div className={`world world-${lane}${harmed ? " harmed" : ""}`} style={{ left: `${WORLD}%` }}>
      <div className="world-orb"><span>{count}</span></div>
      <div className="world-label">{lane === "top" ? "hits on the world" : "reached the world"}</div>
    </div>
  );
}

export function Arena({ data, play, runKey }) {
  const root = useRef(null);
  const [shown, setShown] = useState(0);
  const [score, setScore] = useState({ top: 0, bot: 0, blocked: 0, held: 0 });
  const [end, setEnd] = useState(false);
  const before = data?.before?.trace?.steps || [];
  const after = data?.after?.trace?.steps || [];
  const n = Math.max(before.length, after.length);
  const harms = data?.before?.outcome?.harms || [];
  const afterHarms = data?.after?.outcome?.harms || [];

  useEffect(() => {
    if (!play || !root.current || !n) return;
    setShown(0); setEnd(false); setScore({ top: 0, bot: 0, blocked: 0, held: 0 });
    const q = (s) => root.current.querySelectorAll(s);
    const one = (s) => root.current.querySelector(s);
    const flash = (sel, cls, ms = 650) => { const el = one(sel); if (!el) return; el.classList.remove(cls); void el.offsetWidth; el.classList.add(cls); setTimeout(() => el.classList.remove(cls), ms); };
    const tl = anime.timeline({ easing: "easeOutExpo" });
    tl.add({ targets: q(".lane-rail"), scaleX: [0, 1], duration: 700, easing: "easeInOutQuart", delay: anime.stagger(140) }, 0)
      .add({ targets: q(".gate"), scaleY: [0, 1], opacity: [0, 1], duration: 650, easing: "easeOutElastic(1, .6)" }, 350)
      .add({ targets: q(".agent"), scale: [0.3, 1], opacity: [0, 1], duration: 700, delay: anime.stagger(120) }, 150)
      .add({ targets: q(".world"), scale: [0.3, 1], opacity: [0, 1], duration: 700, delay: anime.stagger(120) }, 300);

    for (let i = 0; i < n; i++) {
      const t0 = 1000 + i * STEP_MS;
      const b = before[i], a = after[i];
      tl.add({ duration: 1, begin: () => { flash(".agent-top", "fire"); flash(".agent-bot", "fire"); } }, t0);
      if (b) {
        const pk = q(`.pk-top-${i}`);
        tl.add({ targets: pk, left: [`${START}%`, `${WORLD}%`], opacity: [{ value: 1, duration: 120 }], duration: 950, easing: "easeInCubic" }, t0)
          .add({ targets: pk, scale: [1, 0.2], opacity: 0, duration: 260, easing: "easeInQuad",
            begin: () => { flash(".world-top", "hit", 700); flash(".lane-top", "shake", 500); setScore((s) => ({ ...s, top: s.top + 1 })); } }, t0 + 950);
      }
      if (a) {
        const d = a.result?.decision || "DENY";
        const pk = q(`.pk-bot-${i}`);
        tl.add({ targets: pk, left: [`${START}%`, `${GATE - 4}%`], opacity: [{ value: 1, duration: 120 }], duration: 640, easing: "easeInCubic" }, t0)
          .add({ duration: 1, begin: () => { flash(".gate", `g-${decisionOf(d).cls}`, 800); setShown(i + 1); } }, t0 + 640);
        if (d === "ALLOW") {
          tl.add({ targets: pk, left: [`${GATE - 4}%`, `${WORLD}%`], duration: 520, easing: "easeOutQuad" }, t0 + 700)
            .add({ targets: pk, scale: [1, 0.2], opacity: 0, duration: 220,
              begin: () => { flash(".world-bot", "ok", 700); setScore((s) => ({ ...s, bot: s.bot + 1 })); } }, t0 + 1220);
        } else if (d === "DENY") {
          tl.add({ targets: pk, scale: [1, 1.5], opacity: 0, duration: 220, easing: "easeOutQuad", begin: () => flash(".lane-bot", "zap", 600) }, t0 + 640)
            .add({ targets: q(`.shard-${i}`), opacity: [1, 0], duration: 1000, easing: "easeOutExpo",
              translateX: () => anime.random(-110, 40), translateY: () => anime.random(-70, 70), rotate: () => anime.random(-240, 240),
              scale: () => [1, anime.random(2, 6) / 10] }, t0 + 640)
            .add({ targets: q(`.gstamp-${i}`), scale: [2.6, 1], opacity: [0, 1], rotate: [-24, -8], duration: 480, easing: "easeOutBack",
              begin: () => setScore((s) => ({ ...s, blocked: s.blocked + 1 })) }, t0 + 660)
            .add({ targets: q(`.gstamp-${i}`), opacity: 0, translateY: -14, duration: 300, easing: "easeInQuad" }, t0 + 1380);
        } else {
          tl.add({ targets: pk, left: `${GATE - 9}%`, duration: 380, easing: "easeOutBack" }, t0 + 660)
            .add({ targets: q(`.gstamp-${i}`), scale: [2.6, 1], opacity: [0, 1], rotate: [-24, -8], duration: 480, easing: "easeOutBack",
              begin: () => setScore((s) => ({ ...s, held: s.held + 1 })) }, t0 + 660)
            .add({ targets: q(`.gstamp-${i}`), opacity: 0, translateY: -14, duration: 300 }, t0 + 1380)
            .add({ targets: pk, opacity: 0.25, duration: 300 }, t0 + 1380);
        }
      }
    }
    tl.add({ duration: 1, begin: () => setEnd(true) }, 1000 + n * STEP_MS);
    tl.add({ targets: q(".end-top"), translateX: [{ value: -6, duration: 60 }, { value: 5, duration: 60 }, { value: -3, duration: 60 }, { value: 0, duration: 60 }],
      duration: 240, easing: "linear" }, 1100 + n * STEP_MS);
    if (reduced()) { tl.seek(tl.duration); setShown(n); setEnd(true); }
    return () => tl.pause();
  }, [play, runKey, n]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="arena" ref={root}>
      <div className="lanes">
        <div className="lane lane-top">
          <div className="lane-name"><span className="pane-dot deny" /> Unprotected agent <em>calls run as proposed</em></div>
          <div className="lane-rail" />
          <div className="agent agent-top" style={{ left: `${START}%` }}><span>agent</span></div>
          {before.map((s, i) => <Packet key={i} step={s} lane="top" i={i} />)}
          <World lane="top" count={score.top} harmed={harms.length > 0 && score.top > 0} />
          <AnimatePresence>{end && (
            <motion.div className="lane-end end-top deny" initial={{ opacity: 0, scale: 1.4 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 380, damping: 18 }}>
              {data?.before?.verdict || "ATTACK SUCCEEDED"}
            </motion.div>)}
          </AnimatePresence>
        </div>
        <div className="lane lane-bot">
          <div className="lane-name"><span className="pane-dot allow" /> With Provenant <em>one enforcement point</em></div>
          <div className="lane-rail" />
          <div className="agent agent-bot" style={{ left: `${START}%` }}><span>agent</span></div>
          <div className="gate" style={{ left: `${GATE}%` }}>
            <div className="gate-bar" /><div className="gate-name">PROVENANT</div>
            {after.map((s, i) => {
              const d = decisionOf(s.result?.decision);
              return <div key={i} className={`gstamp gstamp-${i} ${d.cls}`}>{d.label}</div>;
            })}
          </div>
          <div className="shards" style={{ left: `${GATE - 4}%` }} aria-hidden="true">
            {after.map((_, i) => Array.from({ length: SHARDS }, (_, k) => <i key={`${i}-${k}`} className={`shard shard-${i}`} />))}
          </div>
          {after.map((s, i) => <Packet key={i} step={s} lane="bot" i={i} />)}
          <World lane="bot" count={score.bot} harmed={afterHarms.length > 0} />
          <AnimatePresence>{end && (
            <motion.div className={`lane-end end-bot ${afterHarms.length ? "deny" : "allow"}`} initial={{ opacity: 0, scale: 1.4 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 380, damping: 18, delay: 0.15 }}>
              {data?.after?.verdict || "ATTACK BLOCKED"}
            </motion.div>)}
          </AnimatePresence>
        </div>
      </div>

      <div className="arena-score">
        <div><b className="c-deny">{score.top}</b><span>calls hit the world unprotected</span></div>
        <div><b className="c-deny">{score.blocked}</b><span>denied at the gate</span></div>
        <div><b className="c-hold">{score.held}</b><span>held for a human</span></div>
        <div><b className="c-allow">{score.bot}</b><span>allowed through</span></div>
      </div>

      <ol className="arena-log">
        <AnimatePresence initial={false}>
          {after.slice(0, shown).map((s, i) => {
            const r = s.result || {};
            const d = decisionOf(r.decision);
            return (
              <motion.li key={`${i}-${r.decision}`} className={`alog ${d.cls}`} initial={{ opacity: 0, x: -16, filter: "blur(4px)" }}
                animate={{ opacity: 1, x: 0, filter: "blur(0px)" }} transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}>
                <span className={`alog-src ${s.source}`}>{srcLabel(s.source)}</span>
                <code className="alog-tool">{r.call?.tool || "(malformed)"}</code>
                <span className={`alog-d ${d.cls}`}>{d.label}</span>
                <span className="alog-args">{argsLine(r.call?.args)}</span>
                {r.decision !== "ALLOW" && r.reasons?.length > 0 && <span className="alog-why">{r.reasons[0]}</span>}
              </motion.li>
            );
          })}
        </AnimatePresence>
      </ol>
      <AnimatePresence>{end && harms.length > 0 && (
        <motion.div className="arena-harms" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
          <b>Without Provenant:</b> {harms.map((h) => h.detail).join(" · ")}
        </motion.div>)}
      </AnimatePresence>
    </div>
  );
}
