"""Builds the HTML for team/TEAMMATE_N_BRIEFING.pdf from the speaking scripts.

    python3 team/build_briefings.py . /tmp/out && node team/briefing_pdf.js /tmp/out/brief1.html team/TEAMMATE_1_BRIEFING.pdf /tmp/out/brief2.html team/TEAMMATE_2_BRIEFING.pdf
"""
import html, re, subprocess, sys
from pathlib import Path
ROOT = Path(sys.argv[1])
COMMON = [
 ("Product", "Provenant: a deterministic firewall between AI agents and their tools. Every tool call gets ALLOW, DENY or REQUIRE_APPROVAL. The model is never the security boundary."),
 ("Team", "P1 problem and use case (slides 1-3) · P2 architecture and enforcement (4-5) · P3 mithun: live demo, evaluation, limits, close (6-8). 6.5 minutes total."),
 ("Numbers you may quote", "231/231 attacks contained · 53/53 legitimate actions allowed · 11/11 live proxy checks · 257 unit tests · decision p50 about 0.2 ms · 41 gaps found and fixed in red-team round 2."),
 ("What is covered", "Only tool calls that go through a wrapped MCP server, the Claude Code hook or provenant serve. Remote HTTP MCP servers and agents calling APIs from their own code are not seen. Seeing a call is not stopping it: we only claim what we stop."),
 ("Never say", "Unhackable, 100% secure, stops all prompt injection, tamper-proof, protects every app. Phone approval for held calls is built but not tested with a real call."),
 ("If stuck", "\"Great question, [owner] built that part.\" Hand over; never guess. Answers: team/QA_BANK.md."),
]
JOB = {1: "Make the judges feel the problem in under two minutes, then hand to P2 with the exact line at the end of slide 3.",
       2: "Make the judges believe step three is guaranteed: one deterministic gate, three doors, fail closed, and an honest line on what is not covered. Then hand to mithun at the end of slide 5."}
def inline(t):
    t = html.escape(t, quote=False)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"\*(.+?)\*", r"<em>\1</em>", t)
    return re.sub(r"`(.+?)`", r"<code>\1</code>", t)
def md(text):
    out, para, quote, items = [], [], [], []
    def flush():
        if para: out.append("<p>" + inline(" ".join(para)) + "</p>"); para.clear()
        if quote: out.append("<blockquote>" + "".join(f"<p>{inline(q)}</p>" for q in " ".join(quote).split("\x00") if q.strip()) + "</blockquote>"); quote.clear()
        if items: out.append("<ul>" + "".join(f"<li>{inline(i)}</li>" for i in items) + "</ul>"); items.clear()
    for line in text.splitlines():
        if line.startswith("#"):
            flush(); n = len(line) - len(line.lstrip("#")); out.append(f"<h{n+1}>{inline(line.lstrip('# '))}</h{n+1}>")
        elif line.startswith(">"):
            if para or items: flush()
            body = line[1:].strip(); quote.append(body if body else "\x00")
        elif line.startswith("- "):
            if para or quote: flush()
            items.append(line[2:])
        elif not line.strip():
            if para or items: flush()
        else:
            if quote: flush()
            para.append(line.strip())
    flush(); return "\n".join(out)
CSS = """@page{size:A4;margin:16mm 16mm 18mm}body{font:10.5pt/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;color:#111}
.top{font:600 8pt/1 ui-monospace,monospace;letter-spacing:.12em;color:#555;margin-bottom:6mm}h2{font-size:18pt;margin:0 0 3mm}
h3{font-size:12pt;margin:6mm 0 2mm;border-top:1px solid #ddd;padding-top:3mm}blockquote{margin:0 0 2mm;padding-left:4mm;border-left:3px solid #6d5efc}
blockquote p{margin:0 0 2mm}table{border-collapse:collapse;width:100%;margin:2mm 0 4mm;font-size:9.5pt}th{text-align:left;width:32%;vertical-align:top;padding:1.5mm 3mm 1.5mm 0;color:#333}
td{padding:1.5mm 0;vertical-align:top}tr{border-bottom:1px solid #eee}code{font:9pt ui-monospace,monospace;background:#f3f3f5;padding:0 1mm}"""
for n in (1, 2):
    src = (ROOT / f"team/TEAMMATE_{n}_SPEAKING_SCRIPT.md").read_text(encoding="utf-8")
    first, rest = src.split("\n", 1)
    rows = "".join(f"<tr><th>{k}</th><td>{inline(v)}</td></tr>" for k, v in COMMON + [("Your job", JOB[n])])
    body = (f"<div class='top' aria-hidden='true'>PROVENANT · PARALLAX 2026 · TEAMMATE {n} BRIEFING</div>" + md(first) +
            md(rest.split("\n## ", 1)[0]) + "<h3>What you need to know</h3><table>" + rows + "</table>" + md("## " + rest.split("\n## ", 1)[1]))
    page = f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Provenant: Teammate {n} briefing</title><style>{CSS}</style></head><body>{body}</body></html>"
    out = Path(sys.argv[2]) / f"brief{n}.html"; out.write_text(page, encoding="utf-8")
    print(out)
