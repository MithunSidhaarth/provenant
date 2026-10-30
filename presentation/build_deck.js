// Provenant hackathon deck (Team Parivartan): 8 slides, P1 slides 1-3, P2 4-5, P3 6-8.
// The slides are designed in slides/deck.html (site fonts) and rendered to PNG by slides/render.js;
// this script places them full-bleed and adds the speaker notes.
// Build: node presentation/slides/render.js && NODE_PATH=<node_modules> node presentation/build_deck.js
const path = require("path");
const pptxgen = require("pptxgenjs");
const NOTES = [
  "P1. 15 seconds. 'We are team Parivartan: Mithun, Kundan, Huzefa and Nithya. Agents now read your email and hold real tools. Provenant is the thing that sits between the two.'",
  "P1. 45 seconds. The threat model (docs/THREAT_MODEL.md, T1 to T16) names what's at risk and who attacks. Prompt injection is not a model bug you can patch: any text the agent reads can carry instructions. Three doors: inbox, web/documents, MCP tool results and definitions. Most projects add a smarter prompt or a classifier, which puts the security boundary inside the thing being attacked.",
  "P1. 45 seconds. Same email, same gullible agent, two worlds. We do not rely on the model refusing; we assume it obeys. Without Provenant the invoices leave. With it, the send is denied because the address came from the email, and the user gets a call. Hand over to P2: 'So how can that DENY be guaranteed, when the model already obeyed?'",
  "P2. 60 seconds. The decision isn't made by a model. Three ways in: MCP clients through our proxy, Claude Code through its hooks, and our own gated tool server. All call the same Guard.check, written in plain Python. Three answers: ALLOW runs once under a single-use grant tied to that exact call; DENY never reaches the tool; REQUIRE APPROVAL waits for a person. It fails closed. The loop at the bottom matters most: reading a malicious email changes what the agent is allowed to do next. An optional advisory model exists but can only escalate, never allow.",
  "P2. 60 seconds. Pick two checks to explain, not all six: provenance (the reason the phishing send is denied) and single-use grants (an approved call can't be replayed or swapped). On the right: no code changes for the user. We ran real Claude Code with permission checks switched off, told it to delete everything and read .env, and the hook blocked both. Then: 'Enough slides. Mithun will show it live.'",
  "P3. 90 seconds. Switch to the laptop. Follow docs/DEMO_RUNBOOK.md. If the phone does not ring within 20 seconds, say the call is queued, show provenant mail call-status, and move on. Fallback: the 45-second video.",
  "P3. 40 seconds. Numbers come from python evals/run_eval.py, rerun today. Each square is one attack: 225 across 18 categories, every one DENY (green) or REQUIRE_APPROVAL (amber), never ALLOW. 53 legitimate actions all allowed: no false positives. Round 2: we red-teamed ourselves and found 41 gaps, all fixed. Proxy overhead per call is roughly 15 to 25 ms depending on the machine. Bonus: the gated tool server shapes output, so on our 15-step benchmark tool-result tokens fell 72% (52,432 to 14,541), task still completed; one scripted workload, tokens estimated. Then read the limits strip out loud before the judges ask.",
  "P3. 30 seconds. Don't read all eight. Say: 'Here is every judging criterion and the slide where we proved it.' Point at 02 (before and after, live) and 06 (fails closed, local-first, limits stated). Close: 'Assume the model will obey anything, and keep the world safe anyway. Happy to take questions.' Q&A bank: team/QA_BANK.md."
];
const ALT = ["Provenant title: the firewall between AI agents and their tools. Team Parivartan: Mithun, Kundan, Huzefa, Nithya.",
  "The threat: any text your agent reads can give it orders. A phishing email with a hidden instruction for the AI.",
  "Before and after: without Provenant the invoices are sent; with Provenant the send is denied and the phone rings.",
  "Architecture: MCP clients, Claude Code and the gated tool server all pass one deterministic gate that returns ALLOW, REQUIRE APPROVAL or DENY.",
  "Six deterministic checks, and real Claude Code with permissions bypassed blocked from rm -rf and reading .env.",
  "Live demo in three steps: mail demo flags HIGH and denies, mail demo --call rings the phone, check rm -rf is denied.",
  "Evaluation: 225 of 225 attacks contained, 53 of 53 legitimate actions allowed, 9 of 9 live checks, 235 tests, 72 percent fewer tool-result tokens, 0.15 ms decisions, 41 self-found gaps fixed.",
  "How each of the eight judging criteria is met, with the slide that proves it."];
const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.title = "Provenant: the firewall for AI agents"; pres.author = "Team Parivartan";
NOTES.forEach((n, i) => {
  const s = pres.addSlide();
  s.background = { color: "0B0B0C" };
  s.addImage({ path: path.join(__dirname, "slides", `slide-${i + 1}.png`), x: 0, y: 0, w: 13.333, h: 7.5, altText: ALT[i], objectName: `slide ${i + 1}` });
  s.addNotes(n);
});
pres.writeFile({ fileName: path.join(__dirname, "Provenant_Hackathon_Final.pptx") }).then(() => console.log("ok"));
