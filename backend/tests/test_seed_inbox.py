"""
Diagnostic evaluation on the seed emails, without a database. Prints false positives and missed phishing.
The larger threshold-gated regression set is backend/tests/test_detection_evaluation.py.
Only local checks run; no requests leave the computer.
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
    true_positives = 0
    true_negatives = 0
    false_positives = []
    missed_phishing = []
    print("row  label    score  verdict  result  sender")
    for i, (sender, subject, body, label) in enumerate(rows, 1):
        is_phishing = label == "TRUE"
        result = combine_results(
            subject=subject, body=body,
            sender_domain=extract_domain_from_email(sender), sender_email=sender,
        )
        ok = (result["verdict"] == "risky") == is_phishing
        correct += ok
        predicted_phishing = result["verdict"] == "risky"
        if is_phishing and predicted_phishing:
            true_positives += 1
        elif not is_phishing and not predicted_phishing:
            true_negatives += 1
        if not ok:
            item = (i, sender, result)
            (missed_phishing if is_phishing else false_positives).append(item)
        print(f"{i:>3}  {'phish ' if is_phishing else 'normal'}  {result['score']:>4}   {result['verdict']:<7}  {'ok' if ok else 'WRONG':<6}  {sender}")

    precision = true_positives / max(1, true_positives + len(false_positives))
    recall = true_positives / max(1, true_positives + len(missed_phishing))
    print(f"\nCorrect: {correct}/{len(rows)} | false positives: {len(false_positives)} | missed phishing: {len(missed_phishing)}")
    print(f"Precision: {precision:.1%} | Recall: {recall:.1%}")
    for heading, cases in (("False positives", false_positives), ("Missed phishing", missed_phishing)):
        print(f"\n{heading}:")
        for i, sender, result in cases:
            print(f"Row {i}: {sender} (score {result['score']})")
            for reason in result["reasons"]:
                print("   -", reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
