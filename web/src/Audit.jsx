import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { MotionConfig } from "motion/react";
import { GH, Reveal, Cmd, Nav, Footer, Cursor, ScrollBar } from "./chrome.jsx";

// /audit: every attack and test we ran, as numbers. Live numbers are read from the files `python evals/run_eval.py`
// and `scripts/audit_mail_examples.py` write to dashboard/eval/. History below comes from CLAUDE.md, UPDATE.md,
// docs/REDTEAM_ROUND2.md and docs/FINAL_TEST_REPORT.md; nothing here is estimated.

const CAT = {
  shell: "Destructive shell", rce: "Remote code exec", path: "Path escape", tamper: "Guard tampering", ssrf: "SSRF / internal hosts",
  dlp: "Secret leaks (DLP)", taint: "Provenance taint", classify: "Tool misclassification", failclosed: "Fail-closed", pii: "Personal data",
  family: "Command families", cloud: "Cloud / infra destroy", database: "Database destroy", credtheft: "Credential theft",
  exfil: "Exfiltration", injection: "Prompt injection", persist: "Persistence", evasion: "Evasion / obfuscation",
};

// Unit-test count at each release (CLAUDE.md version table and status notes).
const TESTS = [["v4", 97], ["v5", 99], ["v6", 124], ["v7", 131], ["v8", 166], ["v8.1", 169], ["0.9", 193], ["0.10.0", 235],
  ["0.10.2", 246], ["0.10.3", 257], ["inbox", 291], ["voice", 298]];

const ROUNDS = [
  { n: "Round 1", v: "v8 · policy guard-2026.10-3", big: "128", unit: "attacks", body: "128/128 contained: 110 denied, 18 held. Building it closed a notification-shaped tools/call bypass and 18 gaps the old red-team file hid.", benign: "35/35 benign allowed" },
  { n: "Round 2", v: "guard-2026.10-4", big: "100", unit: "new practical cases", body: "Written to break the v8 guard. It contained 59 of the 100; 41 slipped through. All 41 fixed, whole corpus 225/225 (168 denied, 57 held).", benign: "53/53 benign allowed" },
  { n: "0.10.3 hardening", v: "boundary pass", big: "9", unit: "bugs fixed", body: "3 high, 5 medium, 1 low: agents switching Provenant off, path-less MCP deletes, proxy crashes, unsolicited responses, hook timeouts. Each has a regression test; corpus now 231.", benign: "53/53 benign allowed" },
];
const GAPS = [["Cloud / infra destroy", 13], ["Credential theft", 11], ["Database destroy", 9], ["Regulated IDs (IBAN, Aadhaar, PAN)", 5], ["Non-HTTP exfil, code args", 3]];

const UNTESTED = [
  ["Real Gmail inbox", "The inbox watch is tested against a fake IMAP server only. We have not run it on a real mailbox."],
  ["Real phone calls", "Automated tests use a fake Bolna client. A real call from the laptop has rung (31 Oct); the spoken keep-or-trash code has not been checked on a real call by us."],
  ["Windows and macOS", "Every number on this page comes from Linux, Python 3.13. The suite has not been run on Windows or macOS by us."],
  ["Third-party MCP servers", "The proxy is tested with our own real stdio MCP server. Remote HTTP/SSE servers are not proxied at all."],
];

const pct = (a, b) => (b ? (100 * a) / b : 0);
const fmt = (n) => n.toLocaleString("en-US");

function useJSON(url) {
  const [d, setD] = useState(null), [err, setErr] = useState(false);
  useEffect(() => { fetch(url).then((r) => (r.ok ? r.json() : Promise.reject(r.status))).then(setD, () => setErr(true)); }, [url]);
  return [d, err];
}

// ---------------------------------------------------------------- header + headline
function Head({ r }) {
  const e = r?.environment;
  return (
    <section className="sec au-head" id="top">
      <div className="wrap">
        <Reveal className="kicker">Audit</Reveal>
        <Reveal as="h1" className="au-h1">Every attack we threw.<br /><span className="mute">Every number, reproducible.</span></Reveal>
        <Reveal as="p" className="sub">We attack our own guard, then publish what happened: what got through before each fix, what holds now, and what we have not tested for real.</Reveal>
        {e && (
          <Reveal className="au-meta">
            <span>generated <b>{r.generated_utc}</b></span><span>commit <b>{e.commit}</b></span>
            <span>policy <b>{e.policy_version}</b></span><span>Python <b>{e.python}</b> · Linux</span>
          </Reveal>
        )}
      </div>
    </section>
  );
}

function Headline({ r }) {
  const c = r.corpus, u = r.unit_tests;
  const tiles = [
    [`${c.attacks.contained}/${c.attacks.total}`, "attacks contained", `${c.attacks.decisions.DENY} denied · ${c.attacks.decisions.REQUIRE_APPROVAL} held · 0 allowed`],
    [`${c.benign.allowed_as_expected}/${c.benign.total}`, "legitimate actions allowed", `${c.benign.false_positives.length} false positives`],
    [`${u.ran - u.failures - u.errors}/${u.ran}`, "unit and integration tests", `passed in ${u.seconds} s`],
    [`${r.live.passed}/${r.live.total}`, "live checks, real processes", "real MCP server behind the proxy"],
  ];
  const minor = [
    [`${c.scenarios.passed}/${c.scenarios.total}`, "policy scenarios"],
    [`${c.latency_ms.p50} ms`, `median decision, ${fmt(c.latency_ms.samples)} runs`],
    [`${c.latency_ms.p95} ms`, "p95 decision"],
    [`${r.token_benchmark.policy_llm_calls}`, "model calls in the policy"],
  ];
  return (
    <section className="wrap">
      <div className="stats au-stats">
        {tiles.map(([v, l, s], i) => <Reveal key={l} className="stat" delay={i * 0.06}><b>{v}</b><span>{l}</span><small>{s}</small></Reveal>)}
      </div>
      <div className="au-minor">
        {minor.map(([v, l]) => <div key={l}><b>{v}</b><span>{l}</span></div>)}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- tooltip
function useTip() {
  const [t, setT] = useState(null);
  const bind = (content) => ({
    onPointerMove: (e) => setT({ x: e.clientX, y: e.clientY, content }),
    onPointerLeave: () => setT(null),
  });
  const el = t && (
    <div className="au-tip" style={{ left: Math.min(t.x + 14, window.innerWidth - 230), top: t.y + 14 }} role="status">{t.content}</div>
  );
  return [bind, el];
}

// ---------------------------------------------------------------- decisions + categories
function Decisions({ red }) {
  const [bind, tip] = useTip();
  const s = red.summary;
  const cats = useMemo(() => {
    const m = {};
    for (const a of red.attacks) {
      const k = (m[a.category] ||= { cat: a.category, deny: 0, hold: 0, total: 0, pass: 0 });
      k.total++; if (a.pass) k.pass++;
      if (a.actual === "DENY") k.deny++; else if (a.actual === "REQUIRE_APPROVAL") k.hold++;
    }
    return Object.values(m).sort((a, b) => b.total - a.total);
  }, [red]);
  const max = cats[0]?.total || 1;
  return (
    <section className="sec" id="attacks">
      <div className="wrap">
        <Reveal className="kicker">Red-team corpus</Reveal>
        <Reveal as="h2">{s.total} attacks. <span className="mute">{s.allowed} got through.</span></Reveal>
        <Reveal as="p" className="sub">Each attack is a real tool call an injected agent might make. Contained means it never ran: denied outright, or held until a named human approves.</Reveal>

        <Reveal className="au-seg">
          <div className="au-seg-bar" role="img" aria-label={`${s.blocked} denied, ${s.held} held, ${s.allowed} allowed`}>
            <i className="deny" style={{ flexGrow: s.blocked }} {...bind(<><b>Denied</b> {s.blocked} of {s.total}</>)} />
            <i className="hold" style={{ flexGrow: s.held }} {...bind(<><b>Held for a human</b> {s.held} of {s.total}</>)} />
          </div>
          <div className="au-legend">
            <span><i className="sw deny" />Denied <b>{s.blocked}</b> · {pct(s.blocked, s.total).toFixed(0)}%</span>
            <span><i className="sw hold" />Held for approval <b>{s.held}</b> · {pct(s.held, s.total).toFixed(0)}%</span>
            <span><i className="sw allow" />Allowed <b>{s.allowed}</b></span>
          </div>
        </Reveal>

        <Reveal className="au-card">
          <div className="au-card-h"><h3>By attack family</h3><span>contained / total</span></div>
          <div className="au-bars">
            {cats.map((c) => (
              <div className="au-bar" key={c.cat} {...bind(<><b>{CAT[c.cat] || c.cat}</b><br />{c.deny} denied · {c.hold} held · {c.total - c.pass} missed</>)}>
                <span className="au-bar-l">{CAT[c.cat] || c.cat}</span>
                <span className="au-bar-t">
                  <span className="au-bar-f" style={{ width: `${pct(c.total, max)}%` }}>
                    {c.deny > 0 && <i className="deny" style={{ flexGrow: c.deny }} />}
                    {c.hold > 0 && <i className="hold" style={{ flexGrow: c.hold }} />}
                  </span>
                  <em>{c.pass}/{c.total}</em>
                </span>
              </div>
            ))}
          </div>
          <div className="au-legend sm"><span><i className="sw deny" />Denied</span><span><i className="sw hold" />Held</span></div>
        </Reveal>
      </div>
      {tip}
    </section>
  );
}

// ---------------------------------------------------------------- rounds
function Rounds() {
  return (
    <section className="sec" id="rounds">
      <div className="wrap">
        <Reveal className="kicker">How the corpus grew</Reveal>
        <Reveal as="h2">Built to break it. <span className="mute">Then fixed.</span></Reveal>
        <div className="au-rounds">
          {ROUNDS.map((x, i) => (
            <Reveal key={x.n} className="au-round" delay={i * 0.08}>
              <div className="au-round-h"><span>{x.n}</span><small>{x.v}</small></div>
              <b>{x.big}</b><span className="u">{x.unit}</span>
              <p>{x.body}</p>
              <small className="ok">{x.benign}</small>
            </Reveal>
          ))}
        </div>
        <div className="au-two">
          <Reveal className="au-card">
            <div className="au-card-h"><h3>Round 2, new attacks contained</h3></div>
            <div className="au-ba">
              <div><span>v8 guard, before</span><div className="au-meter"><i className="deny" style={{ width: "59%" }} /></div><b>59 / 100</b></div>
              <div><span>guard-2026.10-4, after</span><div className="au-meter"><i className="allow" style={{ width: "100%" }} /></div><b>100 / 100</b></div>
            </div>
          </Reveal>
          <Reveal className="au-card">
            <div className="au-card-h"><h3>The 41 gaps round 2 found</h3><span>all fixed</span></div>
            <div className="au-bars tight">
              {GAPS.map(([l, n]) => (
                <div className="au-bar" key={l}><span className="au-bar-l">{l}</span>
                  <span className="au-bar-t"><span className="au-bar-f" style={{ width: `${pct(n, 13)}%` }}><i className="acc" style={{ flexGrow: 1 }} /></span><em>{n}</em></span></div>
              ))}
            </div>
          </Reveal>
        </div>
        <Reveal className="note">Sources: <a href={`${GH}/blob/main/docs/REDTEAM_ROUND2.md`} rel="noopener">REDTEAM_ROUND2.md</a> and <a href={`${GH}/blob/main/docs/FINAL_TEST_REPORT.md`} rel="noopener">FINAL_TEST_REPORT.md</a>.</Reveal>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- live + tests
function Live({ r }) {
  const t = r.live.timing_ms;
  return (
    <section className="sec" id="live">
      <div className="wrap">
        <Reveal className="kicker">Live integration</Reveal>
        <Reveal as="h2">Real processes, <span className="mute">real MCP server.</span></Reveal>
        <div className="au-two">
          <Reveal className="au-card">
            <div className="au-card-h"><h3>Checks</h3><span>{r.live.passed}/{r.live.total} pass</span></div>
            <ul className="au-checks">
              {r.live.checks.map((c) => <li key={c.check}><span className={`badge ${c.pass ? "allow" : "deny"}`}>{c.pass ? "PASS" : "FAIL"}</span>{c.check}</li>)}
            </ul>
          </Reveal>
          <Reveal className="au-card">
            <div className="au-card-h"><h3>Cost per tool call</h3><span>same read_file, {t.proxied.n} samples</span></div>
            <div className="au-ba">
              <div><span>Direct to the server</span><div className="au-meter"><i className="acc" style={{ width: `${Math.max(1, pct(t.direct.p50, t.proxied.p95))}%` }} /></div><b>{t.direct.p50} ms</b></div>
              <div><span>Through Provenant, median</span><div className="au-meter"><i className="acc" style={{ width: `${pct(t.proxied.p50, t.proxied.p95)}%` }} /></div><b>{t.proxied.p50} ms</b></div>
              <div><span>Through Provenant, p95</span><div className="au-meter"><i className="acc" style={{ width: "100%" }} /></div><b>{t.proxied.p95} ms</b></div>
            </div>
            <p className="au-fine">The overhead includes the SQLite grant writes and the signed audit append. The policy decision alone is {r.corpus.latency_ms.p50} ms.</p>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

function Tests({ r }) {
  const [bind, tip] = useTip();
  const W = 640, H = 220, P = { l: 36, r: 46, t: 18, b: 30 }, max = 300;
  const x = (i) => P.l + (i * (W - P.l - P.r)) / (TESTS.length - 1), y = (v) => H - P.b - (v / max) * (H - P.t - P.b);
  const line = TESTS.map(([, v], i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const area = `${line}L${x(TESTS.length - 1)},${y(0)}L${x(0)},${y(0)}Z`;
  const areas = r.unit_tests.by_area.slice().sort((a, b) => b.tests - a.tests), amax = areas[0].tests;
  return (
    <section className="sec" id="tests">
      <div className="wrap">
        <Reveal className="kicker">Unit and integration tests</Reveal>
        <Reveal as="h2">{r.unit_tests.ran} tests. <span className="mute">{r.unit_tests.failures + r.unit_tests.errors} failing.</span></Reveal>
        <div className="au-two">
          <Reveal className="au-card">
            <div className="au-card-h"><h3>Test count by release</h3></div>
            <svg className="au-line" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Tests grew from 97 at v4 to ${TESTS.at(-1)[1]}`}>
              {[0, 100, 200, 300].map((v) => <g key={v}><line x1={P.l} x2={W - P.r} y1={y(v)} y2={y(v)} className="grid" /><text x={P.l - 8} y={y(v) + 4} className="tick" textAnchor="end">{v}</text></g>)}
              <path d={area} className="wash" /><path d={line} className="ln" />
              {TESTS.map(([k, v], i) => (
                <g key={k} {...bind(<><b>{k}</b> {v} tests</>)}>
                  <rect x={x(i) - 18} y={P.t} width={36} height={H - P.t - P.b} fill="transparent" />
                  <circle cx={x(i)} cy={y(v)} r={i === TESTS.length - 1 ? 5 : 3.5} className="dot" />
                  {(i % 2 === 0 || i === TESTS.length - 1) && <text x={x(i)} y={H - 10} className="tick" textAnchor="middle">{k}</text>}
                </g>
              ))}
              <text x={x(TESTS.length - 1) + 10} y={y(TESTS.at(-1)[1]) + 4} className="end">{TESTS.at(-1)[1]}</text>
            </svg>
          </Reveal>
          <Reveal className="au-card">
            <div className="au-card-h"><h3>Where the tests point</h3><span>passed / tests</span></div>
            <div className="au-bars tight">
              {areas.map((a) => (
                <div className="au-bar" key={a.area}><span className="au-bar-l" title={a.area}>{a.area}</span>
                  <span className="au-bar-t"><span className="au-bar-f" style={{ width: `${Math.max(2, pct(a.tests, amax))}%` }}><i className="acc" style={{ flexGrow: 1 }} /></span><em>{a.passed}/{a.tests}</em></span></div>
              ))}
            </div>
          </Reveal>
        </div>
      </div>
      {tip}
    </section>
  );
}

// ---------------------------------------------------------------- mail
function Mail({ m }) {
  if (!m) return null;
  const { medium, high } = m.thresholds;
  const risky = m.examples.filter((e) => e.level !== "low"), clean = m.examples.filter((e) => e.level === "low");
  return (
    <section className="sec" id="mail">
      <div className="wrap">
        <Reveal className="kicker">Mail scanner</Reveal>
        <Reveal as="h2">Scored, <span className="mute">not guessed.</span></Reveal>
        <Reveal as="p" className="sub">Each mail an agent reads gets a 0 to 100 score from fixed signals. {medium}+ is medium, {high}+ is high and makes every later send or delete wait for a human. These are the test inputs, scored by the real scanner. 52 tests cover the scanner, the inbox watch and the call flow.</Reveal>
        <div className="au-mails">
          {risky.map((e, i) => (
            <Reveal key={e.label} className="au-mail" delay={i * 0.05}>
              <div className="au-mail-h"><span>{e.label}</span><span className={`badge ${e.level === "high" ? "deny" : "hold"}`}>{e.level.toUpperCase()} {e.score}</span></div>
              <code className="from">{e.from}</code>
              <div className="au-score" aria-hidden="true"><i style={{ width: `${e.score}%` }} /><s style={{ left: `${medium}%` }} /><s style={{ left: `${high}%` }} /></div>
              <ul>{e.signals.map((s) => <li key={s.code}>{s.reason}</li>)}</ul>
            </Reveal>
          ))}
        </div>
        <Reveal className="au-card au-clean">
          <div className="au-card-h"><h3>Ordinary mail stays quiet</h3><span>score / level</span></div>
          {clean.map((e) => <div key={e.label} className="au-clean-r"><code>{e.from}</code><span>{e.subject}</span><span className="badge allow">LOW {e.score}</span></div>)}
        </Reveal>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- tokens
function Tokens({ t }) {
  const rows = [["Tool-result tokens in context", t.context_tokens], ["Input tokens across the run", t.reread_input_tokens], ["Output tokens", t.output_tokens], ["Tool calls", t.tool_calls]];
  return (
    <section className="sec" id="tokens">
      <div className="wrap">
        <Reveal className="kicker">Token benchmark</Reveal>
        <Reveal as="h2">Fewer tokens, <span className="mute">a few more calls.</span></Reveal>
        <Reveal as="p" className="sub">One scripted workload ({t.workload}) on Provenant's own tool server (provenant serve), tokens estimated as {t.token_estimate}; a recount with real BPE tokenizers gives the same 73% (docs/TOKENS.md). The guard hook alone does not shrink tool output. Both runs finished the task.</Reveal>
        <Reveal className="au-card">
          <table className="au-table">
            <thead><tr><th>Measure</th><th>Without</th><th>With Provenant</th><th>Change</th></tr></thead>
            <tbody>{rows.map(([l, v]) => (
              <tr key={l}><td>{l}</td><td>{fmt(v.baseline)}</td><td>{fmt(v.provenant)}</td>
                <td className={v.change_pct < 0 ? "good" : "cost"}>{v.change_pct > 0 ? "+" : ""}{v.change_pct}%</td></tr>))}</tbody>
          </table>
        </Reveal>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- explorer
function Explorer({ red }) {
  const [cat, setCat] = useState("all"), [q, setQ] = useState(""), [all, setAll] = useState(false);
  const cats = useMemo(() => [...new Set(red.attacks.map((a) => a.category))], [red]);
  const rows = red.attacks.filter((a) => (cat === "all" || a.category === cat) &&
    (!q || `${a.id} ${a.note} ${a.tool} ${JSON.stringify(a.args)}`.toLowerCase().includes(q.toLowerCase())));
  const shown = all ? rows : rows.slice(0, 25);
  return (
    <section className="sec" id="explore">
      <div className="wrap">
        <Reveal className="kicker">Every attack</Reveal>
        <Reveal as="h2">Look for yourself.</Reveal>
        <div className="au-filters">
          <input type="search" placeholder="Search attacks, tools, arguments" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search attacks" />
          <div className="au-chips">
            {["all", ...cats].map((c) => <button key={c} className={cat === c ? "on" : ""} onClick={() => setCat(c)}>{c === "all" ? "All" : CAT[c] || c}</button>)}
          </div>
        </div>
        <div className="au-card au-tablewrap">
          <table className="au-table au-atk">
            <thead><tr><th>Attack</th><th>Tool call</th><th>Decision</th></tr></thead>
            <tbody>{shown.map((a) => (
              <tr key={a.id}>
                <td><b>{a.note}</b><small>{CAT[a.category] || a.category} · {a.id}</small></td>
                <td><code>{a.tool} {JSON.stringify(a.args).slice(0, 140)}</code><small>{a.reasons?.[0]}</small></td>
                <td><span className={`badge ${a.actual === "DENY" ? "deny" : a.actual === "REQUIRE_APPROVAL" ? "hold" : "allow"}`}>{a.actual === "REQUIRE_APPROVAL" ? "HELD" : a.actual}</span></td>
              </tr>))}</tbody>
          </table>
          {rows.length > 25 && <button className="au-more" onClick={() => setAll(!all)}>{all ? "Show fewer" : `Show all ${rows.length}`}</button>}
          {!rows.length && <p className="au-fine pad">No attack matches.</p>}
        </div>
        <Reveal className="note">Secrets in the corpus are fake placeholders. The raw file: <a href="/eval/guard_redteam.json">guard_redteam.json</a>.</Reveal>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- honesty
function Untested({ r }) {
  return (
    <section className="sec" id="untested">
      <div className="wrap">
        <Reveal className="kicker">Not tested for real</Reveal>
        <Reveal as="h2">What these numbers <span className="mute">don't cover.</span></Reveal>
        <div className="limits">
          {UNTESTED.map(([t, p], i) => <Reveal key={t} className="limit" delay={i * 0.05}><b>{t}</b><p>{p}</p></Reveal>)}
        </div>
        <Reveal className="au-card au-gaps">
          <div className="au-card-h"><h3>Known gaps, from the eval itself</h3></div>
          <ul>{r.known_gaps.map((g) => <li key={g}>{g}</li>)}</ul>
        </Reveal>
        <Reveal className="au-repro">
          <p>Run it yourself. It fails on any miss or false positive.</p>
          <Cmd text="python evals/run_eval.py" />
          <p className="note">Passing these cases is evidence for the cases listed, not proof that no bypass exists. <a href={`${GH}/blob/main/docs/eval/REPORT.md`} rel="noopener">Full report →</a></p>
        </Reveal>
      </div>
    </section>
  );
}

function Audit() {
  const [r, rErr] = useJSON("/eval/results.json");
  const [red] = useJSON("/eval/guard_redteam.json");
  const [mail] = useJSON("/eval/mail_examples.json");
  useEffect(() => { document.getElementById("boot")?.remove(); }, []);
  return (
    <MotionConfig reducedMotion="user">
      <Cursor /><ScrollBar /><Nav page="audit" />
      <main className="au">
        <Head r={r} />
        {rErr && <div className="wrap"><p className="note">Could not load the eval results. They are in <a href={`${GH}/blob/main/docs/eval/REPORT.md`}>docs/eval/REPORT.md</a>.</p></div>}
        {r && <Headline r={r} />}
        {red && <Decisions red={red} />}
        <Rounds />
        {r && <Live r={r} />}
        {r && <Tests r={r} />}
        <Mail m={mail} />
        {r && <Tokens t={r.token_benchmark} />}
        {red && <Explorer red={red} />}
        {r && <Untested r={r} />}
      </main>
      <Footer />
    </MotionConfig>
  );
}

createRoot(document.getElementById("root")).render(<Audit />);
