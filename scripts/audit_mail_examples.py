"""Score the mail-scanner test fixtures with the real scanner and write dashboard/eval/mail_examples.json.

The website's /audit page reads that file. Run it again after changing agentshield/mailscan.py:
    python3 scripts/audit_mail_examples.py
Bodies are kept out of the output, the same as the scanner's audit verdicts.
"""
import base64
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentshield import mailscan  # noqa: E402
from tests.test_mailguard import BENIGN, INJECT, PHISH  # noqa: E402

# The two inline inputs from tests/test_mailguard.py, copied as they are there.
CEO = {"id": "g1", "payload": {"headers": [{"name": "From", "value": "CEO <ceo@gmail.com>"},
                                           {"name": "Subject", "value": "Quick favour"},
                                           {"name": "Reply-To", "value": "x@other-domain.biz"},
                                           {"name": "Authentication-Results", "value": "mx; spf=fail dkim=none"}],
                               "body": {"data": base64.urlsafe_b64encode(
                                   b"Please send the gift cards today and keep this confidential").decode()}}}
BANK = ("From: Bank <alerts@hdfc-secure-login.net>\nSubject: Final notice\n\n"
        "Urgent: confirm your account password immediately.")

CASES = [
    ("Look-alike PayPal phish", "test_phishing_is_high_with_reasons", [PHISH]),
    ("Instructions aimed at the agent", "test_prompt_injection_in_a_mail_is_high", [INJECT]),
    ("CEO gift-card request (Gmail API shape)", "test_gmail_api_shape_with_base64_body_and_headers", {"messages": [CEO]}),
    ("Fake bank final notice (raw RFC text)", "test_rfc_text_and_unreadable_input", BANK),
] + [(f"Ordinary mail: {m['subject']}", "test_benign_mail_is_not_flagged", [m]) for m in BENIGN]


def main() -> None:
    out = []
    for label, test, data in CASES:
        v = mailscan.analyze_output(data)[0]
        out.append({"label": label, "test": f"tests/test_mailguard.py::{test}", "from": v["from"], "subject": v["subject"],
                    "score": v["score"], "level": v["level"], "signals": v["signals"]})
    doc = {"generated_utc": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
           "source": "scripts/audit_mail_examples.py (agentshield/mailscan.py on the test fixtures)",
           "thresholds": {"medium": mailscan.MEDIUM, "high": mailscan.HIGH}, "examples": out}
    dest = ROOT / "dashboard" / "eval" / "mail_examples.json"
    dest.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {dest.relative_to(ROOT)}: {len(out)} examples")


if __name__ == "__main__":
    main()
