import React, { useEffect, useRef, useState } from "react";
import { motion, useScroll, useVelocity, useSpring, useTransform, useMotionValue, useAnimationFrame } from "motion/react";
import anime from "animejs/lib/anime.es.js";
import { reduced } from "./api.js";

// Page loader: a counter runs to 100 while the wordmark rises; then the wordmark leaves, a gate line
// draws across the middle and the screen splits along it. onReveal fires as the split starts so the
// hero animates in underneath; the loader removes itself when the split ends.
export function Loader({ onReveal }) {
  const root = useRef(null);
  const [n, setN] = useState(0);
  const [gone, setGone] = useState(false);
  useEffect(() => {
    if (reduced()) { onReveal(); setGone(true); return; }
    const q = (s) => root.current.querySelectorAll(s);
    const o = { v: 0 };
    const tl = anime.timeline({ easing: "easeOutExpo" });
    tl.add({ targets: o, v: 100, duration: 1500, easing: "easeInOutQuart", update: () => setN(Math.round(o.v)) }, 0)
      .add({ targets: q(".ld-bar i"), scaleX: [0, 1], duration: 1500, easing: "easeInOutQuart" }, 0)
      .add({ targets: q(".ld-char"), translateY: ["110%", "0%"], duration: 900, delay: anime.stagger(45) }, 120)
      .add({ targets: q(".ld-meta span"), opacity: [0, 1], translateY: [10, 0], duration: 700, delay: anime.stagger(140) }, 500)
      .add({ targets: q(".ld-char"), translateY: ["0%", "-110%"], duration: 550, easing: "easeInExpo", delay: anime.stagger(25) }, 1650)
      .add({ targets: q(".ld-fade"), opacity: 0, duration: 350, easing: "linear" }, 1650)
      .add({ targets: q(".ld-line"), scaleX: [0, 1], duration: 500, easing: "easeInOutQuart" }, 1800)
      .add({ targets: q(".ld-top"), translateY: "-100%", duration: 950, easing: "easeInOutQuart", begin: () => onReveal() }, 2300)
      .add({ targets: q(".ld-bot"), translateY: "100%", duration: 950, easing: "easeInOutQuart" }, 2300)
      .add({ targets: q(".ld-line"), opacity: 0, duration: 400, easing: "linear", complete: () => setGone(true) }, 2600);
    return () => tl.pause();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  if (gone) return null;
  return (
    <div className="ld" ref={root} aria-hidden="true">
      <div className="ld-top" /><div className="ld-bot" />
      <div className="ld-line" />
      <div className="ld-word">{"PROVENANT".split("").map((c, i) => <span className="ld-mask" key={i}><span className="ld-char">{c}</span></span>)}</div>
      <div className="ld-meta ld-fade"><span>Intelligence can propose.</span><span>Policy decides.</span></div>
      <div className="ld-count ld-fade">{String(n).padStart(3, "0")}</div>
      <div className="ld-bar ld-fade"><i /></div>
    </div>
  );
}

const wrap = (min, max, v) => { const r = max - min; return ((((v - min) % r) + r) % r) + min; };

// One marquee row. It drifts on its own and speeds up (and flips direction) with scroll velocity.
function Row({ base, children }) {
  const { scrollY } = useScroll();
  const vel = useSpring(useVelocity(scrollY), { damping: 50, stiffness: 400 });
  const factor = useTransform(vel, [-1200, 0, 1200], [-5, 0, 5], { clamp: false });
  const x = useMotionValue(0);
  const dir = useRef(1);
  useAnimationFrame((_, delta) => {
    if (reduced()) return;
    const f = factor.get();
    if (f < 0) dir.current = -1; else if (f > 0) dir.current = 1;
    const move = dir.current * base * (delta / 1000) * (1 + Math.abs(f));
    x.set(wrap(-50, 0, x.get() + move));
  });
  const tx = useTransform(x, (v) => `${v}%`);
  return (
    <div className="mq-row">
      <motion.div className="mq-track" style={{ x: tx }}>
        {[0, 1].map((k) => <div className="mq-half" key={k}>{children}{children}</div>)}
      </motion.div>
    </div>
  );
}

export function Marquee() {
  return (
    <div className="marquee" aria-hidden="true">
      <Row base={-3}>
        <span className="mq-w allow">ALLOW</span><i className="mq-dot" />
        <span className="mq-w deny">DENY</span><i className="mq-dot" />
        <span className="mq-w hold">REQUIRE APPROVAL</span><i className="mq-dot" />
      </Row>
      <Row base={2}>
        <span className="mq-s">Intelligence can propose</span><i className="mq-slash">/</i>
        <span className="mq-s on">Policy decides</span><i className="mq-slash">/</i>
        <span className="mq-s">Nothing runs without a grant</span><i className="mq-slash">/</i>
      </Row>
    </div>
  );
}

const STATEMENT = "The model is never the security boundary. We assume the most gullible agent possible, and the world stays safe anyway.";
const HOT = new Set(["never", "safe", "anyway."]);

function Word({ p, range, w }) {
  const o = useTransform(p, range, [0.12, 1]);
  const y = useTransform(p, range, [8, 0]);
  return <motion.span className={`sw${HOT.has(w) ? " hot" : ""}`} style={{ opacity: o, y }}>{w} </motion.span>;
}

// A statement whose words light up as it scrolls through the viewport.
export function Statement() {
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start 0.85", "end 0.45"] });
  const words = STATEMENT.split(" ");
  return (
    <section className="statement" ref={ref} aria-label={STATEMENT}>
      <p aria-hidden="true">{words.map((w, i) => <Word key={i} w={w} p={scrollYProgress} range={[i / words.length, (i + 1) / words.length]} />)}</p>
    </section>
  );
}

// Hero copy drifts up and fades as the page scrolls past it.
export function useHeroParallax() {
  const { scrollY } = useScroll();
  const y = useTransform(scrollY, [0, 700], [0, -120]);
  const opacity = useTransform(scrollY, [0, 520], [1, 0.15]);
  const scale = useTransform(scrollY, [0, 700], [1, 0.96]);
  return { y, opacity, scale };
}
