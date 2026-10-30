import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import G from "./onboarding.json";

// The guided setup. Everything shown is generated from onboarding.json (checked against the real CLI by
// tests/test_site_commands.py) and from fixed choices: no free-text input ever becomes a command, and nothing
// here runs on, or detects anything about, the visitor's computer.

const STEPS = [
  ["client", "Choose your AI client"], ["install", "Install Provenant"], ["connect", "Connect the client"],
  ["activate", "Activate protection"], ["verify", "Run a safe security test"], ["done", "Checklist"],
];
const FULL = /^(py|python3|curl|\(Invoke|winget|brew|sudo|pipx|irm|powershell)\b/;
const pick = (m, os) => (typeof m === "string" ? m : m?.[os] ?? m?.all ?? "");

function guessOs() {
  const p = (typeof navigator !== "undefined" && (navigator.userAgentData?.platform || navigator.platform || "")) || "";
  return /win/i.test(p) ? "windows" : /mac/i.test(p) ? "macos" : /linux|x11/i.test(p) ? "linux" : "windows";
}

async function writeClipboard(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { /* fall back */ }
  try {
    const t = document.createElement("textarea");
    t.value = text; t.setAttribute("readonly", ""); t.style.position = "fixed"; t.style.opacity = "0";
    document.body.appendChild(t); t.select();
    const ok = document.execCommand("copy"); t.remove(); return ok;
  } catch { return false; }
}

function Copy({ text }) {
  const [st, setSt] = useState("idle");
  return (
    <button type="button" className={`gs-copy ${st}`} data-copy={text} aria-live="polite"
      onClick={async () => { setSt((await writeClipboard(text)) ? "ok" : "err"); setTimeout(() => setSt("idle"), 1800); }}>
      {st === "ok" ? "Copied" : st === "err" ? "Select and copy" : "Copy"}
    </button>
  );
}

function Command({ text, label }) {
  return (
    <div className="gs-cmd" data-cmd={label || ""}>
      <code tabIndex={0}>{text}</code>
      <Copy text={text} />
    </div>
  );
}

function Choice({ name, value, current, onPick, children, disabled }) {
  const on = value === current;
  return (
    <button type="button" role="radio" aria-checked={on} className={`gs-choice${on ? " on" : ""}`} disabled={disabled}
      data-choice={`${name}:${value}`} onClick={() => onPick(value)}>{children}</button>
  );
}

function Status({ s }) {
  return <span className={`gs-status ${s}`}>{s === "supported" ? "Supported" : s === "experimental" ? "Experimental" : s}</span>;
}

function Trouble({ step, os, shell, run }) {
  const items = G.troubleshooting.filter((t) => t.step === step);
  if (!items.length) return null;
  return (
    <div className="gs-trouble">
      <h3>Something went wrong?</h3>
      {items.map((t) => (
        <details key={t.id} data-trouble={t.id}>
          <summary>{t.title}</summary>
          <dl>
            <dt>What it means</dt><dd>{t.means}</dd>
            <dt>Fix</dt><dd>{pick(t.fix, os)}</dd>
            <dt>Check it worked</dt><dd><Command text={run(pick(t.verify, shell) || pick(t.verify, os))} /></dd>
            <dt>Still failing?</dt><dd>{pick(t.if_fails, os)}</dd>
          </dl>
        </details>
      ))}
    </div>
  );
}

function App() {
  const [step, setStep] = useState(0);
  const [os, setOs] = useState(guessOs);
  const [shell, setShell] = useState(guessOs() === "windows" ? "powershell" : "sh");
  const [client, setClient] = useState("claude-code");
  const [method, setMethod] = useState("installer");
  const [mode, setMode] = useState("deterministic");
  const top = useRef(null);

  const osDef = G.os.find((o) => o.id === os);
  const shellDef = osDef.shells.find((s) => s.id === shell) || osDef.shells[0];
  const sh = shellDef.id;
  const m = G.methods.find((x) => x.id === method);
  const c = G.clients.find((x) => x.id === client);
  const prefix = m.prefix[sh];
  const run = (x) => (FULL.test(x) ? x : `${prefix} ${x}`);

  useEffect(() => { if (!osDef.shells.some((s) => s.id === shell)) setShell(osDef.shells[0].id); }, [os]);
  const go = (n) => { setStep(Math.max(0, Math.min(STEPS.length - 1, n))); top.current?.focus({ preventScroll: true }); top.current?.scrollIntoView({ behavior: "smooth", block: "start" }); };
  const restart = () => { setStep(0); setClient("claude-code"); setMethod("installer"); setMode("deterministic"); go(0); };
  const [id, title] = STEPS[step];

  const checklist = useMemo(() => [
    [`${prefix} --version`, `prints provenant ${G.version}`],
    [run("status"), "Engine ready is ticked"],
    [run(client === "manual" ? c.setup_apply : c.setup), "the client shows as protected"],
    [run("verify"), "Enforcement verified, with 6 ticks"],
    [run("status"), "Connected and Verified are ticked after you use the client once"],
  ], [prefix, client]);

  return (
    <div className="gs">
      <header className="gs-top">
        <a href="/" className="brand"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2v20" /><path d="M5 6h14M5 18h14" /></svg>Provenant</a>
        <span className="gs-ver">v{G.version}</span>
        <a className="gs-toplink" href="/#how">How it works</a>
      </header>

      <main className="gs-main">
        <div className="gs-intro">
          <p className="kicker"><span className="kicker-dot" />Get protected</p>
          <h1>Connect your AI agent. Set your rules. <em>Verify that Provenant is protecting you.</em></h1>
          <p className="gs-lede">Six short steps, about five minutes. You run each command yourself in your own terminal.
            This page cannot see or change your computer, and it never claims a command has run: the proof appears in your terminal.</p>
        </div>

        <ol className="gs-progress" aria-label="Progress">
          {STEPS.map(([sid, label], i) => (
            <li key={sid} className={i === step ? "on" : i < step ? "done" : ""}>
              <button type="button" onClick={() => go(i)} aria-current={i === step ? "step" : undefined}>
                <span className="n">{i < step ? "✓" : i + 1}</span><span className="l">{label}</span>
              </button>
            </li>
          ))}
        </ol>

        <section className="gs-card" aria-labelledby="gs-step-title" data-step={id}>
          <h2 id="gs-step-title" tabIndex={-1} ref={top}><span className="gs-stepn">Step {step + 1} of {STEPS.length}</span>{title}</h2>

          {id === "client" && <>
            <h3>Your computer</h3>
            <div className="gs-choices" role="radiogroup" aria-label="Operating system">
              {G.os.map((o) => <Choice key={o.id} name="os" value={o.id} current={os} onPick={setOs}>{o.label}</Choice>)}
            </div>
            {osDef.shells.length > 1 && <>
              <h3>Terminal you will use</h3>
              <div className="gs-choices" role="radiogroup" aria-label="Terminal">
                {osDef.shells.map((s) => <Choice key={s.id} name="shell" value={s.id} current={sh} onPick={setShell}>{s.label}</Choice>)}
              </div>
            </>}
            <p className="gs-note">This page can't detect your computer, so check that these are right.</p>
            <h3>AI client to protect</h3>
            <div className="gs-clients" role="radiogroup" aria-label="AI client">
              {G.clients.map((x) => (
                <Choice key={x.id} name="client" value={x.id} current={client} onPick={setClient}>
                  <span className="gs-client-head"><b>{x.label}</b><Status s={x.status} /></span>
                  <span className="gs-client-body">{x.connects}</span>
                </Choice>
              ))}
            </div>
            <div className="gs-detail">
              <p><b>{c.label}:</b> {c.status_note}</p>
              <p><b>Changes:</b> <code>{pick(c.changes, os)}</code>. You will see the plan and confirm it before anything is written, and a timestamped backup is kept.</p>
            </div>
          </>}

          {id === "install" && <>
            <div className="gs-choices" role="radiogroup" aria-label="Install method">
              {G.methods.map((x) => <Choice key={x.id} name="method" value={x.id} current={method} onPick={setMethod}>{x.label}{x.recommended && <small> recommended</small>}</Choice>)}
            </div>
            <p>{m.what}</p>
            <p className="gs-where"><b>Where to run it:</b> {shellDef.where}</p>
            <Command text={m.commands[sh]} label="install" />
            {m.note && <p className="gs-note">{m.note}</p>}
            <details className="gs-sub"><summary>First, check Python 3.10+ is installed</summary>
              <Command text={G.python_check[sh]} label="python" />
              <p>Expect {G.python_check.expect}. If it is missing: {G.python_check.install[os]}</p>
            </details>
            <p className="gs-after">After installing, this should print <code>provenant {G.version}</code>:</p>
            <Command text={`${prefix} --version`} label="version" />
            <p className="gs-note">Installing does not protect anything yet. Steps 3 and 4 connect a client. <a href="https://github.com/MithunSidhaarth/provenant/blob/main/docs/REAL_GUARD.md" rel="noopener">Advanced install options</a></p>
          </>}

          {id === "connect" && <>
            <p>{c.connects}</p>
            <ul className="gs-facts">
              <li><b>File changed</b><code>{pick(c.changes, os)}</code></li>
              <li><b>Before writing</b>setup lists what it will change and asks you to confirm. Nothing is written if you say no.</li>
              <li><b>Restart</b>{c.restart}</li>
              <li><b>Undo</b><Command text={run(c.undo)} label="undo" /></li>
            </ul>
            {client === "manual" && <p>Preview first, then apply:</p>}
            <Command text={run(c.setup)} label="connect" />
            {client === "manual" && <Command text={run(c.setup_apply)} label="connect-apply" />}
            <p className="gs-note">Replace <code>path/to/mcp.json</code> only if you chose Manual. Remote (HTTP) MCP servers are listed but not proxied yet.</p>
          </>}

          {id === "activate" && <>
            <p>Provenant reports protection in layers. Each one needs its own evidence, so "installed" never shows as "protected".</p>
            <ol className="gs-levels">{G.levels.map((l) => <li key={l.id}><b>{l.label}</b><span>{l.means}</span></li>)}</ol>
            <Command text={run("status")} label="status" />
            <p className="gs-note">For scripts: <code>{run("status --json")}</code> prints the same layers as JSON.</p>
            <h3>Protection mode</h3>
            <div className="gs-choices" role="radiogroup" aria-label="Protection mode">
              <Choice name="mode" value="deterministic" current={mode} onPick={setMode}>Deterministic protection</Choice>
              <Choice name="mode" value="model" current={mode} onPick={setMode}>Model-assisted risk intelligence</Choice>
            </div>
            {mode === "deterministic" ? (
              <div className="gs-detail">
                <p><b>Mode A, the default.</b> No model, no API key, no inference calls. The policy decides ALLOW, DENY or REQUIRE_APPROVAL for every call that goes through a connected client. Nothing more to do.</p>
              </div>
            ) : (
              <div className="gs-detail" data-model-status={G.model.status}>
                <p className="gs-warn"><b>Model status: not available.</b> {G.model.status_text}</p>
                <p><b>Mode B</b> adds advisory risk labels from a model you host. It never allows a call or overrides a denial: it can only send an already-allowed call to a human, and only if your policy opts in. It adds latency and may cost money per call.</p>
                <p>1. Put the key in an environment variable on your machine (never in a file, URL or this page):</p>
                <Command text={G.model.env[sh]} label="model-env" />
                <p>2. Create <code>{G.model.config_path}</code>:</p>
                <pre className="gs-pre">{G.model.config_example}</pre>
                <p>3. Opt in to escalation in your policy (<code>{run("policy init")}</code> creates it):</p>
                <pre className="gs-pre">{G.model.policy_example}</pre>
                <p>4. Check the connection:</p>
                <Command text={run(G.model.check)} label="model-status" />
                <Command text={run(G.model.test)} label="model-test" />
              </div>
            )}
          </>}

          {id === "verify" && <>
            <p>This test is harmless: it evaluates a forbidden command without running it, uses a throwaway temp folder, reads no secrets and contacts no server.</p>
            <Command text={run(G.verify.command)} label="verify" />
            <h3>What you should see</h3>
            <ul className="gs-expect">{G.verify.expected.map((e) => <li key={e}><span aria-hidden="true">✓</span>{e}</li>)}</ul>
            <p>Then <b>Enforcement verified</b>, followed by the audit entries it wrote.</p>
            <div className="gs-detail">
              <p><b>What this proves:</b> the policy engine on your machine allows a harmless call, refuses to reuse a grant for different arguments, denies a destructive command (and its simulated side effect does not happen), sends a high-impact command to a human, and records all of it in the hash-chained audit log.</p>
              <p><b>What it does not prove:</b> that your client routes calls through Provenant. <code>{run("status")}</code> shows <b>Connected</b> only after a real tool call from your client.</p>
            </div>
          </>}

          {id === "done" && <>
            <p>Tick these off in your terminal. Each line says what a pass looks like.</p>
            <ol className="gs-check">{checklist.map(([cmd, ok]) => <li key={cmd + ok}><Command text={cmd} /><span>{ok}</span></li>)}</ol>
            <p>Diagnose anything odd with <code>{run("doctor")}</code>. Undo all client changes with <code>{run("rollback")}</code>.</p>
          </>}

          <Trouble step={id} os={os} shell={sh} run={run} />

          <nav className="gs-nav" aria-label="Guide navigation">
            <button type="button" className="btn ghost" onClick={() => go(step - 1)} disabled={step === 0}>← Previous</button>
            <button type="button" className="gs-restart" onClick={restart}>Restart guide</button>
            {step < STEPS.length - 1
              ? <button type="button" className="btn primary" onClick={() => go(step + 1)}>Next: {STEPS[step + 1][1]} →</button>
              : <a className="btn primary" href="/">Back to Provenant</a>}
          </nav>
        </section>

        <p className="gs-foot">Provenant is a hackathon-stage security prototype. It enforces policy on the clients and servers you connect; tools that bypass it are not protected. <a href="https://github.com/MithunSidhaarth/provenant/blob/main/docs/THREAT_MODEL.md" rel="noopener">Threat model</a></p>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
