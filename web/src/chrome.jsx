import React, { useEffect, useRef, useState } from "react";
import { motion, useScroll, useSpring } from "motion/react";

// Shared chrome for the public pages (product page and /audit): nav, footer, reveals, command boxes, cursor.

export const GH = "https://github.com/MithunSidhaarth/provenant";

const up = { hidden: { opacity: 0, y: 18 }, show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] } } };
const wipe = { hidden: { opacity: 0, y: 40, clipPath: "inset(0 0 96% 0)" }, show: { opacity: 1, y: 0, clipPath: "inset(0 0 -20% 0)", transition: { duration: 0.9, ease: [0.16, 1, 0.3, 1] } } };
export const Reveal = ({ as = "div", className, children, delay = 0 }) => {
  const C = motion[as];
  return <C className={className} variants={as === "h2" || as === "h1" ? wipe : up} initial="hidden" whileInView="show" viewport={{ once: true, margin: "-80px" }}
            transition={{ delay }}>{children}</C>;
};

function Copy({ text }) {
  const [done, setDone] = useState(false);
  return (
    <button className="copy" onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1400); }, () => {}); }}
            aria-label="Copy command">{done ? "Copied" : "Copy"}</button>
  );
}

export function Cmd({ text, prompt = "$" }) {
  return <div className="cmd"><code><span className="pr">{prompt}</span>{text}</code><Copy text={text} /></div>;
}

// ---------------------------------------------------------------- nav
// `page` is "home" or "audit". Section links point back to the product page when we are elsewhere.
export function Nav({ page = "home" }) {
  const [solid, setSolid] = useState(false);
  useEffect(() => {
    const on = () => setSolid(window.scrollY > 24);
    on(); window.addEventListener("scroll", on, { passive: true });
    return () => window.removeEventListener("scroll", on);
  }, []);
  const home = page === "home" ? "" : "/";
  const audit = page === "audit" ? { "aria-current": "page", className: "on" } : {};
  return (
    <header className={`nav${solid ? " solid" : ""}`}>
      <a href={page === "home" ? "#top" : "/"} className="brand" aria-label="Provenant home"><Mark />Provenant</a>
      <nav className="links" aria-label="Sections">
        <a href={`${home}#how`}>How it works</a><a href={`${home}#features`}>Features</a><a href={`${home}#proof`}>Proof</a>
        <a href="/audit" {...audit}>Audit</a><a href={`${home}#install`}>Install</a>
      </nav>
      <div className="nav-cta">
        <a href="/audit" {...audit} className={`audit-m${page === "audit" ? " on" : ""}`}>Audit</a>
        <a className="ghost" href={GH} rel="noopener">GitHub</a>
        <a className="btn sm" href="/getting-started">Get started</a>
      </div>
    </header>
  );
}

export const Mark = () => (
  <svg className="mark" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5v19" /><path d="M5 7h14M5 17h14" /></svg>
);

export function Footer() {
  return (
    <footer className="foot">
      <div className="wrap foot-inner">
        <div className="brand"><Mark />Provenant</div>
        <p>Built by Team Parivartan for PARALLAX 2026, AgentShield track. A hackathon build, not an audited product.</p>
        <div className="foot-links">
          <a href={GH} rel="noopener">GitHub</a><a href="/getting-started">Get started</a><a href="/audit">Audit</a><a href="/console">Console</a>
          <a href="/vendor/licenses/react-LICENSE.txt">Licences</a>
        </div>
      </div>
    </footer>
  );
}

// ---------------------------------------------------------------- cursor, scroll progress
export function Cursor() {
  const dot = useRef(null), ring = useRef(null), label = useRef(null);
  useEffect(() => {
    if (!window.matchMedia?.("(pointer: fine)").matches) return;
    document.documentElement.classList.add("has-cur");
    let mx = innerWidth / 2, my = innerHeight / 2, rx = mx, ry = my, raf;
    const move = (e) => { mx = e.clientX; my = e.clientY; dot.current.style.transform = `translate(${mx}px,${my}px)`; };
    const over = (e) => {
      const t = e.target.closest?.("a, button, .cmd, [role=tab]");
      ring.current.classList.toggle("hov", !!t);
      label.current.textContent = t ? (t.matches(".cmd") ? "COPY" : "ALLOW") : "";
    };
    const down = () => { ring.current.classList.add("down"); label.current.textContent = ring.current.classList.contains("hov") ? "GRANT" : "DENY"; };
    const up = () => { ring.current.classList.remove("down"); if (!ring.current.classList.contains("hov")) label.current.textContent = ""; };
    const leave = () => { ring.current.style.opacity = 0; dot.current.style.opacity = 0; };
    const enter = () => { ring.current.style.opacity = 1; dot.current.style.opacity = 1; };
    const loop = () => { rx += (mx - rx) * 0.16; ry += (my - ry) * 0.16; ring.current.style.transform = `translate(${rx}px,${ry}px)`; raf = requestAnimationFrame(loop); };
    loop();
    window.addEventListener("pointermove", move, { passive: true }); window.addEventListener("pointerover", over);
    window.addEventListener("pointerdown", down); window.addEventListener("pointerup", up);
    document.addEventListener("mouseleave", leave); document.addEventListener("mouseenter", enter);
    return () => { cancelAnimationFrame(raf); document.documentElement.classList.remove("has-cur");
      window.removeEventListener("pointermove", move); window.removeEventListener("pointerover", over);
      window.removeEventListener("pointerdown", down); window.removeEventListener("pointerup", up);
      document.removeEventListener("mouseleave", leave); document.removeEventListener("mouseenter", enter); };
  }, []);
  return (
    <>
      <div ref={ring} className="cur-ring" aria-hidden="true"><div className="cur-ret"><i /><i /><i /><i /></div><span ref={label} className="cur-label" /></div>
      <div ref={dot} className="cur-dot" aria-hidden="true" />
    </>
  );
}

export function ScrollBar() {
  const { scrollYProgress } = useScroll();
  const scaleX = useSpring(scrollYProgress, { stiffness: 140, damping: 30 });
  return <motion.div className="scrollbar" style={{ scaleX }} aria-hidden="true" />;
}
