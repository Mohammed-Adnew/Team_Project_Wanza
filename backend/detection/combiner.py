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
from config import Config


def combine_results(subject, body, sender_domain="", claimed_org="",
                    attachment_filename=None, attachment_bytes=b"",
                    sender_display_name="", sender_email="", authentication_results="",
                    allow_virustotal_upload=False):
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

    link_result = check_link(f"{subject}\n{body}")
    total_score += link_result["risk_score"]
    has_sender_domain_signal = any(reason.startswith("Sender domain") for reason in scam_result["reasons"])
    has_credential_request = any(reason.startswith("Asks for credentials") for reason in scam_result["reasons"])
    if link_result.get("confirmed_threat") or (has_sender_domain_signal and has_credential_request):
        force_risky = True

    attachment_results = []
    if attachment_filename:
        filenames = attachment_filename if isinstance(attachment_filename, (list, tuple)) else [attachment_filename]
        for filename in filenames:
            file_bytes = attachment_bytes if len(filenames) == 1 else b""
            attachment_result = check_attachment(
                filename, file_bytes,
                allow_virustotal_upload=allow_virustotal_upload,
            )
            attachment_results.append(attachment_result)
            total_score += attachment_result["risk_score"]
            if attachment_result["risk_score"] >= 25:
                force_risky = True

    # If another check found a problem, drop text_check's "No obvious ..." / "No known ..." lines so the
    # reasons never say both "nothing found" and "this looks suspicious".
    other_risk = (
        scam_result["risk_score"] > 0
        or link_result["risk_score"] > 0
        or any(result["risk_score"] > 0 for result in attachment_results)
    )
    text_reasons = text_result["reasons"]
    if other_risk:
        text_reasons = [r for r in text_reasons if not r.startswith(("No obvious", "No known"))]

    all_reasons = ["Coverage: text, sender-domain, and local scam heuristics ran; these rule-based checks do not authenticate a sender."] + list(text_reasons) + scam_result["reasons"] + link_result["reasons"]
    if link_result["checked_urls"]:
        if not Config.SAFE_BROWSING_API_KEY:
            all_reasons.append("Coverage: URL heuristics ran; Google Safe Browsing was skipped because no API key is configured.")
        else:
            all_reasons.append("Coverage: URL heuristics and Google Safe Browsing lookup ran for extracted links; no match or lookup failure does not prove safety.")
    if not attachment_filename:
        all_reasons.append("Coverage: attachment check not applicable; no attachment was provided.")
    if authentication_results:
        from detection.sender_auth import summarize_authentication_results
        all_reasons.extend(summarize_authentication_results(authentication_results))
    else:
        all_reasons.append("Coverage: sender SPF/DKIM/DMARC results were not provided; sender-domain heuristics are not authentication proof.")
    for attachment_result in attachment_results:
        all_reasons += attachment_result["reasons"]

    total_score = min(total_score, 100)
    verdict = "risky" if (total_score >= 45 or force_risky) else "safe"

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
