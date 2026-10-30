import React, { useEffect, useRef, useState, createContext, useContext, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import anime from "animejs/lib/anime.es.js";
import { copy, decisionOf, reduced } from "./api.js";

const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastHost({ children }) {
  const [items, setItems] = useState([]);
  const push = useCallback((text, kind = "info") => {
    const id = Math.random().toString(36).slice(2);
    setItems((xs) => [...xs, { id, text, kind }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 3200);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        <AnimatePresence>
          {items.map((t) => (
            <motion.div key={t.id} className={`toast ${t.kind}`} initial={{ opacity: 0, y: 16, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 8 }} transition={{ type: "spring", stiffness: 420, damping: 32 }}>
              {t.text}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastCtx.Provider>
  );
}

export function Section({ id, kicker, title, lede, children, className = "" }) {
  return (
    <section id={id} className={`section ${className}`} data-section={id}>
      <Reveal className="section-head">
        {kicker && <div className="kicker"><span className="kicker-dot" />{kicker}</div>}
        <h2 className="section-title">{title}</h2>
        {lede && <p className="lede">{lede}</p>}
      </Reveal>
      {children}
    </section>
  );
}

export function Reveal({ children, className = "", delay = 0, as = "div" }) {
  const M = motion[as];
  return (
    <M className={className} initial={{ opacity: 0, y: 28 }} whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-60px" }} transition={{ duration: 0.8, delay, ease: [0.16, 1, 0.3, 1] }}>
      {children}
    </M>
  );
}

export function Badge({ d, small }) {
  const x = decisionOf(d);
  return <span className={`badge ${x.cls}${small ? " small" : ""}`}>{x.label}</span>;
}

// A rubber stamp that slams onto a denied step (anime.js).
export function Stamp({ d, play = true }) {
  const ref = useRef(null);
  const x = decisionOf(d);
  useEffect(() => {
    if (!play || !ref.current || reduced()) return;
    const a = anime({ targets: ref.current, scale: [2.4, 1], opacity: [0, 1], rotate: [-18, -7],
      duration: 620, easing: "easeOutExpo" });
    return () => a.pause();
  }, [play, d]);
  return <span ref={ref} className={`stamp ${x.cls}`} aria-label={x.label}>{x.label}</span>;
}

// Number that rolls to its value when it scrolls into view (anime.js).
export function Counter({ value, decimals = 0, suffix = "" }) {
  const ref = useRef(null);
  const last = useRef(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const fmt = (v) => v.toFixed(decimals) + suffix;
    if (reduced() || typeof IntersectionObserver === "undefined") { el.textContent = fmt(value); return; }
    let anim;
    const obs = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting) return;
      const o = { v: last.current };
      anim = anime({ targets: o, v: value, duration: 1400, easing: "easeOutQuart",
        update: () => { el.textContent = fmt(o.v); } });
      last.current = value;
      obs.disconnect();
    }, { threshold: 0.4 });
    obs.observe(el);
    return () => { obs.disconnect(); anim && anim.pause(); };
  }, [value, decimals, suffix]);
  return <span ref={ref} className="counter">{(0).toFixed(decimals) + suffix}</span>;
}

export function CopyButton({ text, label = "Copy" }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" className="copy" onClick={async () => {
      if (await copy(text)) { setDone(true); setTimeout(() => setDone(false), 1400); }
    }} aria-label={`Copy: ${text}`}>
      {done ? "Copied" : label}
    </button>
  );
}

export function Cmd({ children, prompt = "$" }) {
  return (
    <div className="cmd">
      <span className="cmd-prompt" aria-hidden="true">{prompt}</span>
      <code>{children}</code>
      <CopyButton text={children} />
    </div>
  );
}

export function Button({ children, variant = "primary", busy, ...rest }) {
  return (
    <motion.button whileTap={{ scale: 0.97 }} className={`btn ${variant}${busy ? " busy" : ""}`} disabled={busy || rest.disabled} {...rest}>
      {busy ? <span className="spinner" aria-hidden="true" /> : null}
      <span>{children}</span>
    </motion.button>
  );
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

export function ErrorNote({ error }) {
  if (!error) return null;
  return <div className="error-note" role="alert">{String(error.message || error)}</div>;
}

export function Findings({ findings }) {
  if (!findings || !findings.length) return null;
  return (
    <ol className="findings">
      {findings.map((f, i) => (
        <motion.li key={i} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }}>
          <Badge d={f.decision} small />
          <span className="f-rule">{f.rule}</span>
          <span className="f-reason">{f.reason}</span>
        </motion.li>
      ))}
    </ol>
  );
}
