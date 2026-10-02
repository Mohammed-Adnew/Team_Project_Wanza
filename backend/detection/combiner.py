"""
Combines the results of text_check, link_check, and attachment_check
into one final result ready to be saved as a Report.

This is the ONLY file in the detection layer that knows about the
database's field names (score, verdict, reasons) - the individual
checks (text_check, link_check, attachment_check) stay independent
and don't know anything about how their results get stored.
"""

import json

from detection.text_check import check_text
from detection.link_check import check_link
from detection.attachment_check import check_attachment


def combine_results(subject, body, sender_domain="", claimed_org="",
                     attachment_filename=None, attachment_bytes=b""):
    """
    Runs all applicable detection checks and merges them into one result.

    Link checking runs automatically on any links found in the body.
    Attachment checking only runs if attachment_filename is provided.

    Returns:
        {
            "score": int,          # 0-100, matches models.py Report.score
            "verdict": str,        # "safe" or "risky", matches Report.verdict
            "severity": str,       # "low" / "medium" / "high"
            "reasons": list[str],  # combined, human-readable reasons
        }
    """
    all_reasons = []
    total_score = 0
    force_risky = False  # set True by any single decisive signal, regardless of total score

    # 1. Text check always runs
    text_result = check_text(subject, body, sender_domain, claimed_org)
    total_score += text_result["risk_score"]
    all_reasons.extend(text_result["reasons"])

    # 2. Link check always runs (it finds its own links inside the body, or finds none)
    link_result = check_link(body)
    total_score += link_result["risk_score"]
    all_reasons.extend(link_result["reasons"])
    if link_result["risk_score"] >= 40:  # a confirmed VirusTotal/Safe Browsing match
        force_risky = True

    # 3. Attachment check only runs if an attachment was actually provided
    if attachment_filename:
        attachment_result = check_attachment(attachment_filename, attachment_bytes)
        total_score += attachment_result["risk_score"]
        all_reasons.extend(attachment_result["reasons"])
        if attachment_result["risk_score"] >= 25:
            force_risky = True

    total_score = min(total_score, 100)

    verdict = "risky" if (total_score >= 50 or force_risky) else "safe"

    if total_score >= 75:
        severity = "high"
    elif total_score >= 40:
        severity = "medium"
    else:
        severity = "low"

    return {
        "score": total_score,
        "verdict": verdict,
        "severity": severity,
        "reasons": all_reasons,
    }


def reasons_to_json(reasons: list) -> str:
    """Helper for saving the reasons list into a database Text column."""
    return json.dumps(reasons)


if __name__ == "__main__":
    result = combine_results(
        subject="URGENT: Verify your account now",
        body="Dear customer, your account will be suspended within 24 hours. Confirm your password here: https://bit.ly/fake123",
        sender_domain="fake-cbe-alert.com",
        claimed_org="cbe",
    )
    print("=== Risky email + risky link ===")
    print(result)
    print()

    result = combine_results(
        subject="Monthly newsletter",
        body="Hello Abebe, here are this month's company updates.",
        sender_domain="mycompany.com",
        claimed_org="",
    )
    print("=== Safe email, no link ===")
    print(result)
    print()

    result = combine_results(
        subject="Please review the attached invoice",
        body="Hi, please find the invoice attached for last month's services.",
        sender_domain="smallvendor.et",
        claimed_org="",
        attachment_filename="invoice.exe",
    )
    print("=== Normal email, risky attachment ===")
    print(result)