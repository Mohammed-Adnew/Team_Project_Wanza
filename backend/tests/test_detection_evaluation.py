"""Deterministic labeled regression set for the local phishing rules.
Run from the repository root: python backend/tests/test_detection_evaluation.py
No external services or database are called.
"""
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from config import Config
Config.VT_API_KEY = ""
Config.SAFE_BROWSING_API_KEY = ""
from detection.combiner import combine_results
from detection.text_check import extract_domain_from_email

CASES = Path(__file__).parent / "fixtures" / "detection_evaluation.json"
MIN_PRECISION = 0.95
MIN_RECALL = 0.85


def evaluate():
    cases = json.loads(CASES.read_text(encoding="utf-8-sig"))
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    false_positives = []
    missed = []
    for case in cases:
        expected = case["label"] == "phishing"
        result = combine_results(
            subject=case["subject"], body=case["body"],
            sender_domain=extract_domain_from_email(case["sender"]),
            sender_email=case["sender"], sender_display_name=case.get("display_name", ""),
            claimed_org=case.get("claimed_org", ""),
            attachment_filename=case.get("attachment_filename"),
        )
        predicted = result["verdict"] == "risky"
        counts["tp" if expected and predicted else "fn" if expected else "fp" if predicted else "tn"] += 1
        if predicted and not expected:
            false_positives.append((case["id"], case["subject"], result["score"]))
        elif expected and not predicted:
            missed.append((case["id"], case["subject"], result["score"]))
    precision = counts["tp"] / max(1, counts["tp"] + counts["fp"])
    recall = counts["tp"] / max(1, counts["tp"] + counts["fn"])
    return cases, counts, precision, recall, false_positives, missed


def main():
    cases, counts, precision, recall, false_positives, missed = evaluate()
    print(f"Evaluation: {len(cases)} labeled messages ({counts['tp'] + counts['fn']} phishing, {counts['tn'] + counts['fp']} legitimate)")
    print(f"Precision: {precision:.1%} | Recall: {recall:.1%} | TP={counts['tp']} FP={counts['fp']} TN={counts['tn']} FN={counts['fn']}")
    print("False positives:")
    for item in false_positives:
        print(f"  {item[0]}: {item[1]} (score {item[2]})")
    print("Missed phishing:")
    for item in missed:
        print(f"  {item[0]}: {item[1]} (score {item[2]})")
    if len(cases) < 40 or precision < MIN_PRECISION or recall < MIN_RECALL:
        print(f"FAIL: require >=40 cases, precision >= {MIN_PRECISION:.0%}, and recall >= {MIN_RECALL:.0%}.")
        return 1
    print("PASS: labeled regression thresholds met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
