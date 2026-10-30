# Team presenter runbook

P1: problem, vision, use case (slides 1 to 3). P2: architecture, MCP and Claude integration, enforcement (slides 4 to 7). P3, mithun: live demo, evaluation, limitations, close (slides 8 to 11). Total 6.5 minutes, then Q&A.

Files: deck `presentation/Provenant_Hackathon_Final.pptx` (PDF backup beside it), scripts in `team/`, demo steps in `docs/DEMO_RUNBOOK.md`, answers in `team/QA_BANK.md`.

## Timeline (submission day, Oct 31, IST)

| When | Who | What |
|---|---|---|
| Before 11:00 (freeze) | P3 | `git pull`, `test.bat` (expect OK), `provenant mail test` (phone must ring), screenshots |
| 11:00 to 12:00 | all | Two full run-throughs with a timer. Cut words, not slides, if over 6:30 |
| 12:00 to 13:30 | all | Q&A drill: each person answers 5 questions from QA_BANK.md out loud |
| 14:00 to 16:00 | P3 | Submission: repo link, README, video, deck PDF |
| 10 min before stage | P3 | Laptop checklist below |

## P3 laptop checklist (10 minutes before)

1. Charger in. Notifications off. Wi-Fi connected (needed only for the call).
2. Terminal 1, in `D:\AUTO\provenant`: `provenant dashboard` (leave it running).
3. Browser tabs in order: `http://127.0.0.1:8765/` (console), `http://127.0.0.1:8765/site.html` (product site), the deck.
4. Terminal 2: type `provenant mail demo` but do not press Enter.
5. Phone: ringer loud, not silent, unlocked, face up on the table.
6. Run `provenant verify` once. It must say "Enforcement verified".

## Stage

| Slide | Who | Cue to start | Handover line |
|---|---|---|---|
| 1 to 3 | P1 | Host introduces you | "So how can step three be guaranteed, when the model already obeyed? [P2]." |
| 4 to 7 | P2 | P1's handover | "Enough slides. [mithun] will show it live." |
| 8 | P3 | P2's handover | Run the four demo steps (DEMO_RUNBOOK.md) |
| 9 to 11 | P3 | Demo done | "Happy to take questions." |

P1 clicks the slides for P2. P3 drives the laptop during the demo, and P1 clicks back to slide 9 when P3 says "back to the slides".

### What P3 says during the demo (slide 8)

1. `provenant mail demo` (Enter): "This is a fake Microsoft phishing email: reserved domains, nothing real. The scanner says HIGH, seven reasons. The agent obeyed the hidden instruction and tried to send the invoices. Provenant: DENY, because that address came from the email, not from me. Nothing was sent."
2. Switch to the console tab, scroll to **Demo scenarios**: "It's recorded, and labelled DEMO. Our live numbers only count real agent traffic."
3. `provenant mail demo --call --yes`: "Now the alert." Phone rings: answer it on speaker and let Ivy talk for a few seconds, then hang up. "That's a real call, placed through Bolna."
4. `provenant check Bash "rm -rf ~"`: "Same engine that sits in front of Claude Code. DENY, with reasons."
5. "Back to the slides."

If the phone doesn't ring in 20 seconds: "The call is queued with Bolna, it can take a moment", then run `provenant mail call-status <id>` and move on. Never wait in silence.

## Q&A routing

The person who owns the slide answers. If a question spans slides, P3 answers. Two sentences, then stop. If nobody knows: "We haven't measured that yet, happy to follow up."

## Hard rules for everyone

- Only say numbers that are on the slides.
- Never say "unhackable", "100% secure" or "stops all prompt injection". Say "contained in every case we tested".
- The phone call we demo is the email alert. Phone approval for held calls is built but not yet tested with a real call. Say so if asked.
