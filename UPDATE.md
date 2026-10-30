# Provenant 0.9.0 update log

## Shortest path for a new user
1. Install: `irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex` (Windows PowerShell) or `curl -fsSL https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.sh | sh` (macOS/Linux). Needs Python 3.10+.
2. `provenant setup` (shows a plan, asks first; `--client claude-code` to pick one).
3. `provenant verify` (safe enforcement test), then `provenant status`. "Connected" appears only after the client makes a real tool call.
If `provenant` is not found: `py -m provenant ...` / `python3 -m provenant ...`.

## Done
- CLI: setup (consent, --yes, --client, read-back), status layers + `--json`, verify self-test, doctor, rollback, model status/test.
- Optional model classifier: advisory, escalate-only, opt-in via policy `model_assist`; secrets redacted; strict schema; fail-safe. Not trained.
- Packaging: `python -m provenant`, wheel tested in a fresh venv outside the repo (tests/test_packaging.py).
- Downloads: public GitHub URLs (the 0.8.0 Vercel link returned a login page); `scripts/check_download.py`.
- Site: new hero copy, `/getting-started` wizard (OS, shell, client, method, mode), contextual troubleshooting, honest model status.
- `model/`: dataset build/validate (group splits), QLoRA script, evaluator, model card template. Nothing trained.

## Tests (run here, Linux, Python 3.13)
- Unit: 193/193. Eval: 128/128 attacks, 35/35 benign, 9/9 live.

## Not done / blockers
- Not deployed; download URL goes live only after merge to main. Then run `python3 scripts/check_download.py --install`.
- install.ps1 never run on real Windows; Cursor/Windsurf untested in the real apps.
- No browser/accessibility pass of the new page yet; no model trained or benchmarked.
