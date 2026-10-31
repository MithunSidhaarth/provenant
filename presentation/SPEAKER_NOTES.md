# Speaker notes: Provenant hackathon final (8 slides, 6.5 minutes + Q&A)

Deck: `Provenant_Hackathon_Final.pptx` (and the PDF beside it). The slides are designed in `presentation/slides/deck.html`. Rebuild: `node presentation/slides/render.js`, then `NODE_PATH=<node_modules with pptxgenjs> node presentation/build_deck.js`. The PDF is the eight rendered slides. The same notes are inside the PowerPoint file.

| # | Slide | Speaker | Time | Running |
|---|---|---|---|---|
| 1 | Provenant (title) | P1 | 0:15 | 0:15 |
| 2 | The threat: the email gives the orders | P1 | 0:45 | 1:00 |
| 3 | Same phish, same obedient agent: sent vs denied | P1 | 0:45 | 1:45 |
| 4 | The model proposes. Policy decides. (three doors, one gate, what is not covered) | P2 | 1:00 | 2:45 |
| 5 | Six checks, zero model calls; drops into the agents people use | P2 | 1:00 | 3:45 |
| 6 | Live demo | P3 | 1:30 | 5:15 |
| 7 | Evaluation, regenerated from code, and what is not proven yet | P3 | 0:55 | 6:10 |
| 8 | Every judging criterion, covered | P3 | 0:20 | 6:30 |

The full word-for-word scripts are in `team/`:
- P1: `team/TEAMMATE_1_SPEAKING_SCRIPT.md`
- P2: `team/TEAMMATE_2_SPEAKING_SCRIPT.md`
- P3 (mithun): `team/TEAM_PRESENTER_RUNBOOK.md` and `docs/DEMO_RUNBOOK.md`

## Every number on the slides, and where it comes from

| Claim | Source | Re-check with |
|---|---|---|
| 231/231 attacks contained | `docs/eval/REPORT.md` | `python3 evals/run_eval.py` |
| 53/53 legitimate actions allowed | same | same |
| 11/11 live proxy checks | same | same |
| 0.2 ms policy decision p50 | `run_eval.py` summary line (0.199 ms on the last run) | same; it varies by machine |
| 257 unit tests | `python3 -m unittest discover -s tests -t .` | run it |
| 41 gaps found in round 2 | `docs/REDTEAM_ROUND2.md` | read it |
| Real Claude Code held back from `rm -rf ./*` and `cat .env` | v6 test, `docs/REAL_GUARD.md` | `provenant check Bash "rm -rf ./*"` |
| Scanner HIGH with 7 reasons | `provenant mail demo` | run it |

Say nothing that is not in this table.

## Handovers (memorise these lines)

- P1 to P2, end of slide 3: "So how can step three be guaranteed, when the model already obeyed? [P2's name]."
- P2 to P3, end of slide 5: "Enough slides. [mithun] will show it live."
- P3 back to everyone, end of slide 8: "Happy to take questions." Questions go to whoever owns that slide (see `team/QA_BANK.md`).
