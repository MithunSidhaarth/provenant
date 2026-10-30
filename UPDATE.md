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

## 0.9.1: Windows installer repair
- Root cause: Windows PowerShell 5.1 strips double quotes from arguments passed to native programs. The 0.9.0 installer
  ran `python -c 'import sys; print(".".join(...))'`, which Python received as `print(..join(...))` (SyntaxError); the failed
  command's null output then hit `.Trim()` ("cannot call a method on a null-valued expression"). The served script was
  identical to the repository's; it was not stale or cached. PowerShell 7.3+ passes quotes through, so 7 did not show it.
- install.ps1 rewritten: quote-free Python snippets, exit code checked after every native call, candidate interpreters
  probed and validated, wheel validated (zip, metadata version, entry point, SHA-256 pinned by build_release.py), import and
  wrapper verified, PATH deduplicated, no `exit` under iex. See tests/test_installer.py and the `installer-windows` CI job.
- Not run on real Windows from here. The `installer-windows` job has not executed yet.
