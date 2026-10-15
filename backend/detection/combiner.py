"""
Combines the results of text_check, link_check, and attachment_check
into one final result ready to be saved as a Report.

This is the ONLY file in the detection layer that knows about the
database's field names - the individual checks stay independent
and don't know anything about how their results get stored.
"""

import json

from detection.text_check import check_text
from detection.link_check import check_link
from detection.attachment_check import check_attachment


def combine_results(subject, body, sender_domain="", claimed_org="",
                    attachment_filename=None, attachment_bytes=b"",
                    sender_display_name="", sender_email=""):
    """
    Runs all applicable detection checks and merges them into one result.

    Link checking runs automatically on any links found in the body.
    Attachment checking only runs if attachment_filename is provided.
    sender_display_name / sender_email are optional and enable the
    display-name and free-email-provider checks.

    Returns:
        {
            "score": int,          # 0-100
            "verdict": str,        # "safe" or "risky"
            "severity": str,       # "low" / "medium" / "high"
            "reasons": list[str],  # combined, human-readable reasons
        }
    """
    all_reasons = []
    total_score = 0
    force_risky = False  # set True by any single decisive signal, regardless of total score

    text_result = check_text(
        subject, body, sender_domain, claimed_org,
        sender_display_name=sender_display_name, sender_email=sender_email,
    )
    total_score += text_result["risk_score"]
    all_reasons.extend(text_result["reasons"])

    link_result = check_link(body)
    total_score += link_result["risk_score"]
    all_reasons.extend(link_result["reasons"])
    if link_result["risk_score"] >= 40:  # a confirmed VirusTotal/Safe Browsing match
        force_risky = True

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