const pptxgen = require("pptxgenjs");
const { applyTheme } = require(process.env.APPLY_THEME || "./apply_theme.js");
const THEME = { name: "Provenant Console", headFontFace: "Arial", bodyFontFace: "Calibri",
  colors: { dk1: "0B0D0C", lt1: "E9EFEC", dk2: "141816", lt2: "8A958F", accent1: "3DDC97", accent2: "FF5D5D", accent3: "F5B544",
            accent4: "1E2522", accent5: "2A332F", accent6: "6FE7B4", hlink: "3DDC97", folHlink: "6FE7B4" } };
const HEX = { bg: "0B0D0C", panel: "141816", line: "2A332F", mint: "3DDC97", red: "FF5D5D", amber: "F5B544", fg: "E9EFEC", muted: "8A958F" };
const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
pres.title = "Provenant: the firewall for AI agents"; pres.author = "Team Provenant";
const C = pres.SchemeColor;
const MONO = "Courier New";

pres.defineSlideMaster({ title: "TITLE", background: { color: HEX.bg },
  objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.8, y: 1.8, w: 11.7, h: 2.1, fontSize: 54, bold: true, color: C.background1, valign: "bottom", align: "left", margin: 0 }, text: "" } },
            { placeholder: { options: { name: "body", type: "body", x: 0.8, y: 4.15, w: 10.5, h: 1.2, fontSize: 22, color: C.background2, align: "left", valign: "top", margin: 0 }, text: "" } }] });
pres.defineSlideMaster({ title: "CONTENT", background: { color: HEX.bg },
  objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.45, w: 12.1, h: 0.9, fontSize: 36, bold: true, color: C.background1, valign: "top", align: "left", margin: 0 }, text: "" } },
            { text: { text: "PROVENANT", options: { x: 0.6, y: 6.95, w: 3, h: 0.3, fontFace: MONO, fontSize: 10, color: C.background2, charSpacing: 3, margin: 0 } } }],
  slideNumber: { x: 12.2, y: 6.95, w: 0.6, h: 0.3, fontFace: MONO, fontSize: 10, color: HEX.muted, align: "right" } });

let n = 0;
const kicker = (s, t, who) => s.addText(`${t}  ·  ${who}`, { x: 0.6, y: 0.15, w: 8, h: 0.3, fontFace: MONO, fontSize: 11, color: C.accent1, charSpacing: 2, margin: 0, isTextBox: true, objectName: "kicker" });
const card = (s, x, y, w, h, name) => s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.12, fill: { color: C.text2 }, line: { color: C.accent5, width: 1 }, objectName: name });
const text = (s, t, o) => s.addText(t, { isTextBox: true, margin: 0, color: C.background1, fontSize: 16, valign: "top", ...o });
const pill = (s, label, x, y, color, w = 2.6) => { s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h: 0.5, rectRadius: 0.25, fill: { color: HEX.bg }, line: { color, width: 1.5 }, objectName: "pill " + label });
  s.addText(label, { x, y, w, h: 0.5, align: "center", valign: "middle", fontFace: MONO, bold: true, fontSize: 14, color, margin: 0, isTextBox: true }); };
const slide = (master, section) => { const s = pres.addSlide({ masterName: master, sectionTitle: section }); return s; };

// 1 Title
pres.addSection({ title: "Problem and vision" });
let s = slide("TITLE", "Problem and vision");
s.addText("PARALLAX 2026  ·  AGENTSHIELD TRACK", { x: 0.8, y: 1.2, w: 8, h: 0.4, fontFace: MONO, fontSize: 14, color: C.accent1, charSpacing: 3, margin: 0, isTextBox: true });
s.addText([{ text: "Provenant", options: { color: C.background1 } }], { placeholder: "title" });
s.addText("The firewall between AI agents and their tools. Intelligence can propose. Policy decides.", { placeholder: "body" });
pill(s, "ALLOW", 0.8, 5.6, HEX.mint, 2.2); pill(s, "DENY", 3.2, 5.6, HEX.red, 2.2); pill(s, "REQUIRE APPROVAL", 5.6, 5.6, HEX.amber, 3.2);
s.addNotes("P1. 15 seconds. 'We are Provenant. Agents now read your email and hold real tools. We built the thing that sits between the two.' Introduce the three of us by role: P1 problem, P2 architecture, P3 live demo.");

// 2 Problem
s = slide("CONTENT", "Problem and vision"); kicker(s, "THE PROBLEM", "P1");
s.addText("Agents read untrusted text and hold real tools", { placeholder: "title" });
const probs = [["Inbox", "An email says: forward the last five invoices to this address. The agent cannot tell an instruction from data."],
               ["Web and documents", "A page hides an instruction in white text, base64 or zero-width characters."],
               ["MCP tools", "A tool result or a changed tool definition quietly asks for your .env or a shell."]];
probs.forEach(([h, b], i) => { const x = 0.6 + i * 4.1; card(s, x, 1.7, 3.8, 3.4, "problem " + h);
  text(s, h, { x: x + 0.3, y: 1.95, w: 3.2, h: 0.5, fontSize: 22, bold: true, color: C.accent2 });
  text(s, b, { x: x + 0.3, y: 2.6, w: 3.2, h: 2.3, fontSize: 16, color: C.background1 }); });
text(s, "Prompt-level defences ask the model to be careful. The model is the thing being attacked.", { x: 0.6, y: 5.5, w: 12, h: 0.8, fontSize: 20, italic: true, color: C.background2 });
s.addNotes("P1. 45 seconds. Prompt injection is not a model bug you can patch: any text the agent reads can carry instructions. Three doors: inbox, web/documents, MCP tool results and manifests. Most projects add a smarter prompt or a classifier. That puts the security boundary inside the thing being attacked.");

// 3 Use case
s = slide("CONTENT", "Problem and vision"); kicker(s, "THE USE CASE", "P1");
s.addText("One phishing email, end to end", { placeholder: "title" });
const steps = [["1", "The email arrives", "From micros0ft-verify.example. Reply-To elsewhere. A bit.ly link. A hidden line for the AI.", HEX.muted],
               ["2", "The agent obeys", "It proposes send_email to the attacker with your invoices. We assume the worst model.", HEX.amber],
               ["3", "Provenant decides", "DENY: the destination came from content the agent read, not from you. Nothing is sent.", HEX.mint],
               ["4", "You get a call", "A phone alert: high-risk email, do not click, verify the sender. No links read aloud.", HEX.mint]];
steps.forEach(([k, h, b, col], i) => { const y = 1.6 + i * 1.28;
  s.addShape(pres.shapes.OVAL, { x: 0.6, y, w: 0.8, h: 0.8, fill: { color: HEX.panel }, line: { color: col, width: 2 }, objectName: "step " + k });
  text(s, k, { x: 0.6, y, w: 0.8, h: 0.8, align: "center", valign: "middle", fontFace: MONO, fontSize: 22, bold: true, color: col });
  text(s, h, { x: 1.7, y: y + 0.02, w: 4, h: 0.5, fontSize: 22, bold: true });
  text(s, b, { x: 5.4, y: y + 0.05, w: 7.3, h: 0.9, fontSize: 16, color: C.background2 }); });
s.addNotes("P1. 45 seconds. Walk the story the judges will see live. Emphasise step 2: we do not rely on the model refusing. We assume it obeys. Hand over to P2: 'So how can step 3 be guaranteed?'");

// 4 Principle
pres.addSection({ title: "Architecture and enforcement" });
s = slide("CONTENT", "Architecture and enforcement"); kicker(s, "THE PRINCIPLE", "P2");
s.addText("The model is never the security boundary", { placeholder: "title" });
text(s, "Every tool call the agent proposes passes one deterministic decision point, written in plain Python. No model call. No findings means DENY.", { x: 0.6, y: 1.55, w: 11.8, h: 1.0, fontSize: 20, color: C.background2 });
[["ALLOW", HEX.mint, "Runs once, under a single-use grant bound to that exact call"], ["DENY", HEX.red, "Never reaches the tool. Reasons go back to the agent and the audit log"], ["REQUIRE APPROVAL", HEX.amber, "Held until a person types provenant approve, or answers a verified call"]]
.forEach(([h, col, b], i) => { const x = 0.6 + i * 4.1; card(s, x, 2.9, 3.8, 3.2, "decision " + h); pill(s, h, x + 0.3, 3.2, col, 3.2);
  text(s, b, { x: x + 0.3, y: 4.0, w: 3.2, h: 1.9, fontSize: 18 }); });
s.addNotes("P2. 30 seconds. The core claim. The engine is deterministic and fails closed: an exception, a bad policy file, or no matching rule all mean DENY. An optional advisory model exists but can only escalate, never allow.");

// 5 Architecture
s = slide("CONTENT", "Architecture and enforcement"); kicker(s, "ARCHITECTURE", "P2");
s.addText("One gate, every entry point", { placeholder: "title" });
const box = (label, sub, x, y, w, col) => { card(s, x, y, w, 1.1, "arch " + label);
  text(s, label, { x: x + 0.2, y: y + 0.15, w: w - 0.4, h: 0.4, fontSize: 18, bold: true, color: col || C.background1 });
  text(s, sub, { x: x + 0.2, y: y + 0.58, w: w - 0.4, h: 0.45, fontSize: 13, fontFace: MONO, color: C.background2 }); };
box("MCP clients", "Claude Desktop, Cursor, VS Code", 0.6, 1.6, 3.4); box("Claude Code", "Pre/PostToolUse hooks", 0.6, 3.0, 3.4); box("Gated tools", "provenant serve", 0.6, 4.4, 3.4);
s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 4.9, y: 2.3, w: 3.5, h: 2.5, rectRadius: 0.15, fill: { color: HEX.panel }, line: { color: HEX.mint, width: 2.5 }, objectName: "guard" });
text(s, "Guard.check", { x: 5.1, y: 2.55, w: 3.1, h: 0.5, fontSize: 24, bold: true, color: C.accent1 });
text(s, "policy · provenance · injection context · netguard · DLP", { x: 5.1, y: 3.15, w: 3.1, h: 1.4, fontSize: 15, fontFace: MONO, color: C.background1 });
[2.15, 3.55, 4.95].forEach((y) => s.addShape(pres.shapes.LINE, { x: 4.0, y, w: 0.9, h: 3.55 - y, line: { color: HEX.muted, width: 1.5, endArrowType: "triangle" }, objectName: "arrow in" }));
box("Real tools", "only after ALLOW + grant", 9.3, 1.6, 3.4, HEX.mint); box("Approvals", "SQLite, TTL, one use", 9.3, 3.0, 3.4, HEX.amber); box("Audit chain", "hash-chained + HMAC", 9.3, 4.4, 3.4);
[2.15, 3.55, 4.95].forEach((y) => s.addShape(pres.shapes.LINE, { x: 8.4, y: 3.55, w: 0.9, h: y - 3.55, flipV: y < 3.55, line: { color: HEX.muted, width: 1.5, endArrowType: "triangle" }, objectName: "arrow out" }));
text(s, "Tool results flow back through taint + injection scanning, so what the agent reads changes what it may do next.", { x: 0.6, y: 5.9, w: 12, h: 0.7, fontSize: 17, italic: true, color: C.background2 });
s.addNotes("P2. 35 seconds. Three ways in: the MCP proxy that wraps every stdio MCP server, the Claude Code hooks, and our own gated tool server. All call the same Guard.check. Out the other side: a real tool only after ALLOW plus a single-use grant; held calls live in SQLite with a TTL; every decision lands in a hash-chained HMAC audit log.");

// 6 Integration
s = slide("CONTENT", "Architecture and enforcement"); kicker(s, "MCP AND CLAUDE INTEGRATION", "P2");
s.addText("Drops into the agents people already use", { placeholder: "title" });
const col = (x, h, lines) => { card(s, x, 1.6, 5.9, 4.3, "integration " + h); text(s, h, { x: x + 0.3, y: 1.85, w: 5.3, h: 0.5, fontSize: 22, bold: true, color: C.accent1 });
  text(s, lines.map((t, i) => ({ text: t, options: { bullet: true, breakLine: i < lines.length - 1 } })), { x: x + 0.3, y: 2.55, w: 5.3, h: 3.2, fontSize: 16, paraSpaceAfter: 8 }); };
col(0.6, "MCP proxy", ["provenant setup wraps each MCP server, with a plan, a backup and a consent prompt", "Only allowed tools/call requests reach the server, including ones disguised as notifications", "Tool manifests pinned by HMAC: a changed definition (rug pull) is withheld"]);
col(6.8, "Claude Code hook", ["PreToolUse: DENY blocks, REQUIRE_APPROVAL becomes Claude's own ask prompt", "PostToolUse: results feed taint and injection tracking", "Held real Claude Code back from rm -rf ./* and cat .env, even in bypassPermissions mode"]);
text(s, "One line to install, provenant rollback to undo. Status reports a client as connected only after real audit traffic.", { x: 0.6, y: 6.15, w: 12, h: 0.6, fontSize: 16, color: C.background2 });
s.addNotes("P2. 30 seconds. Emphasise zero code changes for the user. The rug-pull defence: if an MCP server changes a tool description after you approved it, the new definition is withheld. Claude Code: we tested real Claude Code in bypassPermissions mode; the hook still blocked rm -rf and reading .env.");

// 7 Enforcement
s = slide("CONTENT", "Architecture and enforcement"); kicker(s, "WHAT THE GATE CHECKS", "P2");
s.addText("Defense in depth, all deterministic", { placeholder: "title" });
const cells = [["Provenance", "A destination copied from content the agent read cannot receive data"], ["Injection context", "After reading injected text, every side effect needs a human"], ["Shell and paths", "Root deletes, pipe-to-shell, workspace escape, credential files"],
               ["Network", "Private, metadata and encoded IPs; resolve once and pin; recheck redirects"], ["Single-use grants", "Bound to the exact call. No replay, no swapped arguments"], ["Human approval", "Terminal-only approve; phone code checked by HMAC"]];
cells.forEach(([h, b], i) => { const x = 0.6 + (i % 3) * 4.1, y = 1.6 + Math.floor(i / 3) * 2.45; card(s, x, y, 3.8, 2.2, "check " + h);
  text(s, h, { x: x + 0.3, y: y + 0.25, w: 3.2, h: 0.5, fontSize: 20, bold: true, color: C.accent1 }); text(s, b, { x: x + 0.3, y: y + 0.85, w: 3.2, h: 1.2, fontSize: 16 }); });
s.addNotes("P2. 25 seconds. Pick two to explain, not all six: provenance (the reason the phishing send is denied) and single-use grants (why a held call cannot be replayed or swapped). Hand over to P3 for the live demo.");

// 8 Demo
pres.addSection({ title: "Demo, evaluation and close" });
s = slide("CONTENT", "Demo, evaluation and close"); kicker(s, "LIVE DEMO", "P3");
s.addText("Live: a fake phish, a blocked send, a real call", { placeholder: "title" });
const demo = [["provenant mail demo", "Scanner: HIGH, 7 reasons. send_email to the attacker: DENY"], ["Operations console", "The run appears under Demo scenarios, labelled DEMO, not counted as live"],
              ["provenant mail demo --call", "The phone on stage rings: a labelled Provenant alert about the fake email"], ['provenant check Bash "rm -rf ~"', "The same engine Claude Code uses says DENY, with reasons"]];
demo.forEach(([cmd, what], i) => { const y = 1.6 + i * 1.25; card(s, 0.6, y, 12.1, 1.05, "demo " + i);
  text(s, cmd, { x: 0.9, y: y + 0.3, w: 5.2, h: 0.5, fontFace: MONO, fontSize: 17, bold: true, color: C.accent1 }); text(s, what, { x: 6.3, y: y + 0.27, w: 6.2, h: 0.6, fontSize: 17 }); });
text(s, "Every domain is a reserved .example domain. Nothing is emailed. The call is placed only with --call and a yes.", { x: 0.6, y: 6.6, w: 11, h: 0.35, fontSize: 13, color: C.background2 });
s.addNotes("P3. 90 seconds. Switch to the laptop. Follow docs/DEMO_RUNBOOK.md. If the phone does not ring within 20 seconds, say the call is queued, show provenant mail call-status, and move on. Fallback: the launch video.");

// 9 Evaluation
s = slide("CONTENT", "Demo, evaluation and close"); kicker(s, "EVALUATION", "P3");
s.addText("Measured, regenerated from code", { placeholder: "title" });
[["225/225", "attacks contained", HEX.mint], ["53/53", "legitimate actions allowed", HEX.mint], ["9/9", "live proxy checks", HEX.mint], ["0.16 ms", "policy decision p50", HEX.fg]]
.forEach(([v, l, c], i) => { const x = 0.6 + i * 3.08; card(s, x, 1.6, 2.85, 1.9, "stat " + l); text(s, v, { x: x + 0.25, y: 1.8, w: 2.4, h: 0.9, fontSize: 40, bold: true, color: c, fontFace: "Arial" }); text(s, l, { x: x + 0.25, y: 2.75, w: 2.4, h: 0.6, fontSize: 14, color: C.background2 }); });
s.addChart(pres.charts.BAR, [{ name: "Attacks contained", labels: ["shell", "path", "ssrf", "cloud", "pii", "credtheft", "exfil", "tamper", "rce", "family", "dlp", "database"], values: [44, 19, 19, 14, 12, 12, 12, 11, 10, 10, 9, 8] }],
  { x: 0.6, y: 3.7, w: 7.6, h: 3.1, barDir: "col", chartColors: [HEX.mint], showValue: true, dataLabelPosition: "outEnd", dataLabelColor: HEX.fg, dataLabelFontSize: 10, dataLabelFontFace: "+mn-lt",
    catAxisLabelColor: HEX.muted, valAxisLabelColor: HEX.muted, catAxisLabelFontSize: 10, valAxisHidden: true, valGridLine: { style: "none" }, catGridLine: { style: "none" }, showLegend: false,
    catAxisLabelFontFace: "+mn-lt", showTitle: true, title: "Largest 12 of 18 attack categories (all 100% contained)", titleColor: HEX.fg, titleFontSize: 13, titleFontFace: "+mn-lt", objectName: "category chart" });
text(s, [{ text: "235 unit tests pass, including a wheel built and installed in a clean venv.", options: { breakLine: true } }, { text: "Attacks found 41 gaps in our own v8 guard in round 2. All fixed, all now regression cases.", options: { breakLine: true } }, { text: "Passing these cases is evidence for these cases, not proof of no bypass.", options: { italic: true, color: HEX.muted } }],
  { x: 8.6, y: 3.8, w: 4.1, h: 3.0, fontSize: 15, paraSpaceAfter: 10 });
s.addNotes("P3. 40 seconds. Numbers come from python evals/run_eval.py, rerun today. 225 attacks across 18 categories: every one is DENY or REQUIRE_APPROVAL, never ALLOW. 53 legitimate actions all allowed: no false positives. Mention round 2: we red-teamed ourselves and found 41 gaps, fixed them. The six smaller categories not on the chart (injection, persist, evasion, taint, classify, failclosed) are also 100%.");

// 10 Limitations
s = slide("CONTENT", "Demo, evaluation and close"); kicker(s, "HONEST LIMITS", "P3");
s.addText("What we have not proven yet", { placeholder: "title" });
const lim = [["Paraphrase", "Provenance is value-based. A reworded destination can slip that one rule; the others still apply."], ["Shell", "Pattern-based. Writing a script, then running it, is judged by the run command."],
             ["Remote MCP", "Only stdio MCP servers are proxied today, not HTTP ones."], ["Field tests", "Phone approval and the Windows one-liner have not run on real infrastructure yet."]];
lim.forEach(([h, b], i) => { const x = 0.6 + (i % 2) * 6.15, y = 1.6 + Math.floor(i / 2) * 2.4; card(s, x, y, 5.95, 2.15, "limit " + h);
  text(s, h, { x: x + 0.3, y: y + 0.25, w: 5.3, h: 0.5, fontSize: 20, bold: true, color: C.accent3 }); text(s, b, { x: x + 0.3, y: y + 0.85, w: 5.3, h: 1.1, fontSize: 16 }); });
s.addNotes("P3. 20 seconds. Say these before the judges ask. It earns trust. The phone alert you just saw is the mail alert path; the phone approval path for held calls has not been tested with a real call.");

// 11 Close
s = slide("TITLE", "Demo, evaluation and close");
s.addText("Assume the model will obey anything", { placeholder: "title" });
s.addText("and keep the world safe anyway. Provenant is open, local-first and installs in one line.", { placeholder: "body" });
text(s, "irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex", { x: 0.8, y: 5.6, w: 11.8, h: 0.5, fontFace: MONO, fontSize: 15, color: C.accent1 });
text(s, "github.com/MithunSidhaarth/provenant", { x: 0.8, y: 6.2, w: 8, h: 0.4, fontFace: MONO, fontSize: 15, color: C.background2 });
s.addNotes("P3. 15 seconds. Close on the one line. Then: 'Happy to take questions.' Q&A bank: team/QA_BANK.md.");

(async () => { await pres.writeFile({ fileName: require("path").join(__dirname, "Provenant_Hackathon_Final.pptx") });
  await applyTheme(require("path").join(__dirname, "Provenant_Hackathon_Final.pptx"), THEME); console.log("ok"); })();
