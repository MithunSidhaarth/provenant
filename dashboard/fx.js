// Provenant background: a procedural gaussian-splat particle field (Three.js, vendored).
// This is NOT a captured 3D Gaussian Splatting scene. Each particle is an anisotropic point
// sprite with a gaussian falloff, blended additively, so dense regions glow like splats.
// The field reacts to policy decisions: a DENY sends a red shockwave out of the shield sphere
// that repels particles; an ALLOW is a soft acid ripple; REQUIRE_APPROVAL is amber.
// Lite mode (button, or prefers-reduced-motion) never creates a WebGL context at all.
import * as THREE from "./vendor/three.module.min.js";

const KIND = { deny: 0, allow: 1, approve: 2 };
const MAX_PULSES = 6;
const FULL_COUNT = 22000;

const vert = /* glsl */ `
uniform float uTime;
uniform float uPixel;
uniform float uShield;
uniform vec4 uPulses[${MAX_PULSES}];   // x = start time, y = kind, z = strength
attribute vec3 aSeed;                  // random per particle
attribute float aSize;
varying vec3 vColor;
varying float vAlpha;

vec3 kindColor(float k) {
  if (k < 0.5) return vec3(1.0, 0.16, 0.13);    // deny: hard red
  if (k < 1.5) return vec3(0.83, 1.0, 0.0);     // allow: acid
  return vec3(1.0, 0.69, 0.0);                  // approval: amber
}

void main() {
  vec3 p = position;
  // slow curl-ish drift so the cloud breathes
  float t = uTime * 0.12;
  p += 0.18 * vec3(sin(t + aSeed.x * 6.28 + p.y * 0.6),
                   cos(t * 1.3 + aSeed.y * 6.28 + p.z * 0.5),
                   sin(t * 0.7 + aSeed.z * 6.28 + p.x * 0.4));
  float r = length(p);
  vec3 dir = r > 0.0001 ? p / r : vec3(0.0, 1.0, 0.0);
  // the shield: nothing sits inside it, particles near its skin are pushed outward
  p += dir * max(0.0, uShield - r) * 1.2;

  vec3 col = mix(vec3(0.55), vec3(1.0), aSeed.x) * 0.55;
  float glow = 0.0;
  for (int i = 0; i < ${MAX_PULSES}; i++) {
    vec4 pu = uPulses[i];
    float age = uTime - pu.x;
    if (pu.z <= 0.0 || age < 0.0 || age > 4.0) continue;
    float front = uShield + age * 3.2;
    float d = r - front;
    float band = exp(-d * d * 1.6) * (1.0 - age / 4.0) * pu.z;
    float push = pu.y < 0.5 ? 1.1 : 0.35;              // deny repels hard
    p += dir * band * push;
    col = mix(col, kindColor(pu.y) * 1.6, clamp(band, 0.0, 1.0));
    glow += band;
  }
  vColor = col;
  vAlpha = clamp(0.32 + glow * 0.8, 0.0, 1.0) * (aSize > 50.0 ? 0.1 : 1.0);
  vec4 mv = modelViewMatrix * vec4(p, 1.0);
  gl_Position = projectionMatrix * mv;
  gl_PointSize = aSize * uPixel * (1.0 + glow * 0.9) / -mv.z;
}`;

const frag = /* glsl */ `
varying vec3 vColor;
varying float vAlpha;
void main() {
  vec2 q = gl_PointCoord * 2.0 - 1.0;
  float d2 = dot(q, q);
  if (d2 > 1.0) discard;
  float g = exp(-d2 * 4.0);                       // gaussian falloff
  gl_FragColor = vec4(vColor * g, g * vAlpha);
}`;

// Anisotropic gaussian clusters: a handful of "splats of splats" around a shield sphere.
function buildCloud(count) {
  const pos = new Float32Array(count * 3), seed = new Float32Array(count * 3), size = new Float32Array(count);
  const rnd = mulberry(1337);
  const gauss = () => { let u = 0, v = 0; while (!u) u = rnd(); v = rnd(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(6.2831853 * v); };
  const clusters = Array.from({ length: 14 }, () => {
    const th = rnd() * Math.PI * 2, ph = Math.acos(2 * rnd() - 1), rad = 2.6 + rnd() * 3.2;
    return { c: [rad * Math.sin(ph) * Math.cos(th), rad * Math.cos(ph) * 0.7, rad * Math.sin(ph) * Math.sin(th)],
             s: [0.4 + rnd() * 1.4, 0.2 + rnd() * 0.7, 0.4 + rnd() * 1.4] };
  });
  for (let i = 0; i < count; i++) {
    let x, y, z;
    if (i % 5 === 0) {                              // a thin shell hugging the shield
      const th = rnd() * Math.PI * 2, ph = Math.acos(2 * rnd() - 1), rad = 1.7 + Math.abs(gauss()) * 0.25;
      x = rad * Math.sin(ph) * Math.cos(th); y = rad * Math.cos(ph); z = rad * Math.sin(ph) * Math.sin(th);
    } else {
      const k = clusters[i % clusters.length];
      x = k.c[0] + gauss() * k.s[0]; y = k.c[1] + gauss() * k.s[1]; z = k.c[2] + gauss() * k.s[2];
    }
    pos.set([x, y, z], i * 3);
    seed.set([rnd(), rnd(), rnd()], i * 3);
    size[i] = rnd() < 0.03 ? 60 + rnd() * 80 : 4 + rnd() * rnd() * 22;   // a few wide, faint nebula splats
  }
  const g = new THREE.BufferGeometry();
  g.setAttribute("position", new THREE.BufferAttribute(pos, 3));
  g.setAttribute("aSeed", new THREE.BufferAttribute(seed, 3));
  g.setAttribute("aSize", new THREE.BufferAttribute(size, 1));
  return g;
}

function mulberry(a) {
  return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

function webglAvailable() {
  try { const c = document.createElement("canvas"); return !!(c.getContext("webgl2") || c.getContext("webgl")); }
  catch { return false; }
}

class Field {
  constructor(canvas) {
    this.canvas = canvas;
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: false, alpha: true, powerPreference: "low-power" });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(55, 1, 0.1, 100);
    this.camera.position.set(0, 0.4, 9);
    this.geom = buildCloud(FULL_COUNT);
    this.pulses = Array.from({ length: MAX_PULSES }, () => new THREE.Vector4(0, 0, 0, 0));
    this.uniforms = { uTime: { value: 0 }, uPixel: { value: 1 }, uShield: { value: 1.6 }, uPulses: { value: this.pulses } };
    this.mat = new THREE.ShaderMaterial({ vertexShader: vert, fragmentShader: frag, uniforms: this.uniforms,
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending });
    this.points = new THREE.Points(this.geom, this.mat);
    this.scene.add(this.points);
    this.clock = new THREE.Clock();
    this.mouse = { x: 0, y: 0 };
    this.next = 0;
    this.frames = []; this.degraded = 0; this.lastCheck = performance.now();
    this.onResize = () => this.resize();
    this.onMove = (e) => { this.mouse.x = e.clientX / innerWidth - 0.5; this.mouse.y = e.clientY / innerHeight - 0.5; };
    addEventListener("resize", this.onResize);
    addEventListener("pointermove", this.onMove, { passive: true });
    canvas.addEventListener("webglcontextlost", (e) => { e.preventDefault(); FX.setLite(true, "WebGL context lost"); });
    this.resize();
    this.running = true;
    this.loop = this.loop.bind(this);
    requestAnimationFrame(this.loop);
  }
  resize() {
    const w = innerWidth, h = innerHeight;
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h; this.camera.updateProjectionMatrix();
    this.uniforms.uPixel.value = h * this.renderer.getPixelRatio() * 0.0045;
  }
  pulse(kind, strength) {
    const p = this.pulses[this.next++ % MAX_PULSES];
    p.set(this.uniforms.uTime.value, KIND[kind] ?? 0, strength, 0);
  }
  loop(now) {
    if (!this.running) return;
    requestAnimationFrame(this.loop);
    if (document.hidden) return;
    const dt = this.clock.getDelta();
    this.uniforms.uTime.value += Math.min(dt, 0.05);
    this.watchdog(now);
    const t = this.uniforms.uTime.value;
    this.points.rotation.y = t * 0.04;
    this.camera.position.x += (this.mouse.x * 1.6 - this.camera.position.x) * 0.04;
    this.camera.position.y += (0.4 - this.mouse.y * 1.0 - this.camera.position.y) * 0.04;
    this.camera.lookAt(0, 0, 0);
    this.renderer.render(this.scene, this.camera);
  }
  // Low-GPU fallback: if the frame rate stays low, halve the particle count, then fall back to lite.
  watchdog(now) {
    this.frames.push(now);
    while (this.frames.length && now - this.frames[0] > 2000) this.frames.shift();
    if (this.frames.length < 2 || now - this.lastCheck < 2500) return;
    this.lastCheck = now;
    const fps = (this.frames.length - 1) / ((now - this.frames[0]) / 1000);
    FX.fps = Math.round(fps);
    if (fps >= 48) return;
    this.degraded++;
    if (this.degraded <= 2) {
      this.geom.setDrawRange(0, Math.floor(FULL_COUNT / (2 ** this.degraded)));
      this.renderer.setPixelRatio(1);
      this.resize();
    } else FX.setLite(true, `low frame rate (${Math.round(fps)} fps)`);
  }
  dispose() {
    this.running = false;
    removeEventListener("resize", this.onResize);
    removeEventListener("pointermove", this.onMove);
    this.geom.dispose(); this.mat.dispose(); this.renderer.dispose();
  }
}

const FX = {
  lite: false, reason: "", fps: null, field: null,
  init() {
    let saved = null;
    try { saved = localStorage.getItem("provenant.motion"); } catch { /* storage blocked: use defaults */ }
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const lite = saved ? saved === "lite" : reduced;
    this.setLite(lite || !webglAvailable(), lite ? (saved ? "chosen" : "reduced motion") : "no WebGL", false);
  },
  setLite(on, reason = "chosen", remember = true) {
    this.lite = !!on; this.reason = on ? reason : "";
    document.documentElement.classList.toggle("lite", this.lite);
    if (remember) { try { localStorage.setItem("provenant.motion", this.lite ? "lite" : "full"); } catch { /* ignore */ } }
    if (this.lite && this.field) { this.field.dispose(); this.field = null; }
    if (!this.lite && !this.field) {
      try { this.field = new Field(document.getElementById("fx")); }
      catch (e) { this.lite = true; this.reason = "WebGL failed"; document.documentElement.classList.add("lite"); }
    }
    document.dispatchEvent(new CustomEvent("provenant:motion", { detail: { lite: this.lite, reason: this.reason } }));
  },
  pulse(kind, n = 1) {
    if (!this.field) return;
    for (let i = 0; i < Math.min(n, 3); i++) setTimeout(() => this.field && this.field.pulse(kind, 1), i * 260);
  },
};
window.ProvenantFX = FX;
FX.init();
