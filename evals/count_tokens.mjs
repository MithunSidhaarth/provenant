// Recount the token benchmark with real BPE tokenizers instead of the chars/4 estimate.
//
//   python evals/token_bench.py --dump trace.json
//   npm i --prefix /tmp/tok @anthropic-ai/tokenizer@0.0.4 gpt-tokenizer@2.9.0
//   NODE_PATH=/tmp/tok/node_modules node evals/count_tokens.mjs trace.json
//
// Both tokenizers run offline. @anthropic-ai/tokenizer is Anthropic's published *legacy* tokenizer (pre-Claude 3);
// current Claude models tokenize differently, so treat it as a close proxy, not the billed count. o200k_base is a
// current OpenAI tokenizer, included as an independent second check. "Context" sums every tool result that enters
// the model's context; "re-read" adds the running context total after each call (no prompt cache), as
// token_bench.py does.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const claude = require("@anthropic-ai/tokenizer");
const o200k = require("gpt-tokenizer/encoding/o200k_base");

const counters = {
  "chars/4 estimate": (t) => Math.ceil(t.length / 4),
  "Claude legacy BPE": (t) => claude.countTokens(t),
  "o200k_base BPE": (t) => o200k.encode(t).length,
};

const trace = JSON.parse(readFileSync(process.argv[2] || "trace.json", "utf8"));
const totals = {};
for (const [mode, texts] of Object.entries(trace)) {
  totals[mode] = {};
  for (const [name, count] of Object.entries(counters)) {
    let ctx = 0, reread = 0;
    for (const { text } of texts) { ctx += count(text); reread += ctx; }
    totals[mode][name] = { context: ctx, reread };
  }
}

const pct = (a, b) => `${b - a > 0 ? "+" : ""}${(((b - a) / a) * 100).toFixed(1)}%`;
const rows = ["| Tokenizer | Metric | Baseline | Provenant | Change |", "|---|---|---|---|---|"];
for (const name of Object.keys(counters)) {
  for (const k of ["context", "reread"]) {
    const a = totals.baseline[name][k], b = totals.provenant[name][k];
    rows.push(`| ${name} | ${k === "context" ? "Tool-result tokens" : "Re-read input (no cache)"} | ${a.toLocaleString("en-US")} | ${b.toLocaleString("en-US")} | ${pct(a, b)} |`);
  }
}
console.log(rows.join("\n"));
