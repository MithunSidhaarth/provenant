# Speaker notes: Provenant hackathon final (11 slides, 6.5 minutes + Q&A)

Deck: `Provenant_Hackathon_Final.pptx` (and the PDF beside it). Rebuild it with `NODE_PATH=<node_modules with pptxgenjs> APPLY_THEME=<path to an apply_theme.js helper> node presentation/build_deck.js` (the theme helper is not vendored here). The same notes are inside the PowerPoint file.

| # | Slide | Speaker | Time | Running |
|---|---|---|---|---|
| 1 | Provenant (title) | P1 | 0:15 | 0:15 |
| 2 | Agents read untrusted text and hold real tools | P1 | 0:45 | 1:00 |
| 3 | One phishing email, end to end | P1 | 0:45 | 1:45 |
| 4 | The model is never the security boundary | P2 | 0:30 | 2:15 |
| 5 | One gate, every entry point | P2 | 0:35 | 2:50 |
| 6 | Drops into the agents people already use | P2 | 0:30 | 3:20 |
| 7 | Defense in depth, all deterministic | P2 | 0:25 | 3:45 |
| 8 | Live: a fake phish, a blocked send, a real call | P3 | 1:30 | 5:15 |
| 9 | Measured, regenerated from code | P3 | 0:40 | 5:55 |
| 10 | What we have not proven yet | P3 | 0:20 | 6:15 |
| 11 | Assume the model will obey anything | P3 | 0:15 | 6:30 |

The full word-for-word scripts are in `team/`:
- P1: `team/TEAMMATE_1_SPEAKING_SCRIPT.md`
- P2: `team/TEAMMATE_2_SPEAKING_SCRIPT.md`
- P3 (mithun): `team/TEAM_PRESENTER_RUNBOOK.md` and `docs/DEMO_RUNBOOK.md`

## Every number on the slides, and where it comes from

| Claim | Source | Re-check with |
|---|---|---|
| 225/225 attacks contained | `docs/eval/REPORT.md` | `python3 evals/run_eval.py` |
| 53/53 legitimate actions allowed | same | same |
| 9/9 live proxy checks | same | same |
| 0.16 ms policy decision p50 | `run_eval.py` summary line (0.156 ms on the last run) | same; it varies by machine |
| 235 unit tests | `python3 -m unittest discover -s tests -t .` | run it |
| 41 gaps found in round 2 | `docs/REDTEAM_ROUND2.md` | read it |
| Real Claude Code held back from `rm -rf ./*` and `cat .env` | v6 test, `docs/REAL_GUARD.md` | `provenant check Bash "rm -rf ./*"` |
| Scanner HIGH with 7 reasons | `provenant mail demo` | run it |

Say nothing that is not in this table.

## Handovers (memorise these lines)

- P1 to P2, end of slide 3: "So how can step three be guaranteed, when the model already obeyed? [P2's name]."
- P2 to P3, end of slide 7: "Enough slides. [mithun] will show it live."
- P3 back to everyone, end of slide 11: "Happy to take questions." Questions go to whoever owns that slide (see `team/QA_BANK.md`).
