"""
Measures detection accuracy on the emails in database/seed_data.sql, without a database.
Run from the backend folder:   python tests/test_seed_inbox.py
Only the local checks run: VirusTotal and Safe Browsing are switched off, so results are
repeatable and no request leaves your computer.
"""

import re
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from config import Config
Config.VT_API_KEY = ""
Config.SAFE_BROWSING_API_KEY = ""

from detection.combiner import combine_results
from detection.text_check import extract_domain_from_email

SEED_FILE = BACKEND.parent / "database" / "seed_data.sql"
ROW = re.compile(r"\('([^']*)',\s*'([^']*)',\s*'([^']*)',\s*(TRUE|FALSE)\)")


def main():
    rows = ROW.findall(SEED_FILE.read_text(encoding="utf-8"))
    if not rows:
        print("No rows found in", SEED_FILE)
        return 1

    correct = 0
    problems = []
    print("row  label    score  verdict  result  sender")
    for i, (sender, subject, body, label) in enumerate(rows, 1):
        is_phishing = label == "TRUE"
        result = combine_results(
            subject=subject, body=body,
            sender_domain=extract_domain_from_email(sender), sender_email=sender,
        )
        ok = (result["verdict"] == "risky") == is_phishing
        correct += ok
        if not ok:
            problems.append((i, sender, is_phishing, result))
        print(f"{i:>3}  {'phish ' if is_phishing else 'normal'}  {result['score']:>4}   {result['verdict']:<7}  {'ok' if ok else 'WRONG':<6}  {sender}")

    print(f"\nCorrect: {correct}/{len(rows)}")
    for i, sender, is_phishing, result in problems:
        kind = "missed phishing" if is_phishing else "false alarm"
        print(f"\nRow {i} ({kind}): {sender}")
        for reason in result["reasons"]:
            print("   -", reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
