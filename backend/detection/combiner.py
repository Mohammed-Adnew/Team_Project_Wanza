"""
Combines the results of text_check, scam_signals, link_check and attachment_check
into one final result ready to be saved as a Report.

This is the ONLY file in the detection layer that knows about the
database's field names - the individual checks stay independent
and don't know anything about how their results get stored.
"""

import json

from detection.text_check import check_text
from detection.scam_signals import check_scam_signals
from detection.link_check import check_link
from detection.attachment_check import check_attachment


def combine_results(subject, body, sender_domain="", claimed_org="",
                    attachment_filename=None, attachment_bytes=b"",
                    sender_display_name="", sender_email=""):
    """
    Runs all applicable detection checks and merges them into one result.

    Returns:
        {
            "score": int,          # 0-100
            "verdict": str,        # "safe" or "risky"
            "severity": str,       # "low" / "medium" / "high"
            "reasons": list[str],  # combined, human-readable reasons
        }
    """
    total_score = 0
    force_risky = False  # set True by any single decisive signal, regardless of total score

    text_result = check_text(
        subject, body, sender_domain, claimed_org,
        sender_display_name=sender_display_name, sender_email=sender_email,
    )
    total_score += text_result["risk_score"]

    scam_result = check_scam_signals(subject, body, sender_domain, claimed_org)
    total_score += scam_result["risk_score"]

    link_result = check_link(body)
    total_score += link_result["risk_score"]
    if link_result["risk_score"] >= 40:  # a confirmed VirusTotal/Safe Browsing match
        force_risky = True

    attachment_result = None
    if attachment_filename:
        attachment_result = check_attachment(attachment_filename, attachment_bytes)
        total_score += attachment_result["risk_score"]
        if attachment_result["risk_score"] >= 25:
            force_risky = True

    # If another check found a problem, drop text_check's "No obvious ..." / "No known ..." lines so the
    # reasons never say both "nothing found" and "this looks suspicious".
    other_risk = (
        scam_result["risk_score"] > 0
        or link_result["risk_score"] > 0
        or (attachment_result is not None and attachment_result["risk_score"] > 0)
    )
    text_reasons = text_result["reasons"]
    if other_risk:
        text_reasons = [r for r in text_reasons if not r.startswith(("No obvious", "No known"))]

    all_reasons = list(text_reasons) + scam_result["reasons"] + link_result["reasons"]
    if attachment_result is not None:
        all_reasons += attachment_result["reasons"]

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
