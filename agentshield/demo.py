"""Terminal demo: replay every scenario without and with AgentShield. Needs no browser or network.

    python3 -m agentshield.demo            # summary table
    python3 -m agentshield.demo -v         # plus every decision and reason
"""
from __future__ import annotations

import argparse
import os
import sys

from .fuzzer import run_campaign
from .runner import Shield

RED, GREEN, YELLOW, DIM, BOLD, RESET = "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"


def colour(text: str, verdict: str, enabled: bool) -> str:
    if not enabled:
        return text
    tone = GREEN if verdict in ("ATTACK BLOCKED", "TASK COMPLETED", "ALLOW") else \
        YELLOW if verdict in ("AWAITING APPROVAL", "REQUIRE_APPROVAL") else RED
    return f"{tone}{text}{RESET}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)
    if os.name == "nt":
        os.system("")          # enables ANSI colours in the classic Windows console
    c = sys.stdout.isatty() and not args.no_color
    shield = Shield()
    failures = 0
    print(f"{'scenario':26} {'without AgentShield':34} {'with AgentShield'}")
    print("-" * 96)
    for sid, sc in shield.scenarios.items():
        before = shield.run(sid, protected=False)
        after = shield.run(sid, protected=True)
        n = len(before["outcome"]["harms"])
        b = f"{before['verdict']} ({n} harm{'s' if n != 1 else ''})" if sc["kind"] == "attack" else before["verdict"]
        print(f"{sid:26} {colour(f'{b[:33]:33}', before['verdict'] if sc['kind'] == 'attack' else 'x', c)} "
              f"{colour(after['verdict'], after['verdict'], c)}  {' '.join(after['decisions'])}")
        if after["outcome"]["harms"] or after["decisions"] != sc["expected_protected"]:
            failures += 1
        if args.verbose:
            for h in before["outcome"]["harms"]:
                print(f"    before: {h['detail']}")
            for s in after["trace"]["steps"]:
                if s["skipped"]:
                    print(f"    {DIM if c else ''}[{s['source']}] skipped: {s['skipped']}{RESET if c else ''}")
                    continue
                r = s["result"]
                print(f"    [{s['source']}] {r['call']['tool']} -> {colour(r['decision'], r['decision'], c)}")
                for reason in r["reasons"]:
                    print(f"        - {reason}")
    fz = run_campaign(shield.engine)["summary"]
    print("-" * 96)
    print(f"fuzzer: {fz['live_attacks']}/{fz['variants']} obfuscated variants live without AgentShield; "
          f"{fz['containment_pct']}% contained with it ({fz['hard_denied_pct']}% by DENY alone), "
          f"detection {fz['detection_pct']}%")
    if fz["containment_pct"] < 100:
        failures += 1
    v = shield.audit.verify()
    print(f"audit chain: {'verified' if v['ok'] else 'BROKEN'} ({v['checked']} entries)")
    print("result:", "all attacks contained, all benign tasks allowed" if not failures else f"{failures} FAILURES")
    return 1 if failures or not v["ok"] else 0


if __name__ == "__main__":
    sys.exit(main())
