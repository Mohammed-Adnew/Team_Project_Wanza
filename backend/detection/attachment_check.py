"""
Checks an ATTACHMENT for phishing/malware indicators.

Attachment checks:
  - Risky file extension check always runs.
  - When bytes are supplied, compute SHA-256 locally and query VirusTotal if configured.
  - Submit unknown file contents only when the submitter consents and the server flag is enabled.

Does NOT check email text or links - see text_check.py and
link_check.py for those.
"""

import hashlib

try:
    import requests
except ImportError:
    requests = None

from config import Config


RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs",
    ".docm", ".xlsm", ".pptm", ".jar", ".msi",
}


def get_file_extension(filename: str) -> str:
    filename = filename.lower().strip()
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[1]


def check_extension(filename: str) -> tuple[bool, str]:
    """
    Always-available check: flags file types commonly used to deliver malware.
    Returns (is_risky, reason).
    """
    ext = get_file_extension(filename)
    if ext in RISKY_EXTENSIONS:
        return True, f"File type '{ext}' is commonly used to deliver malware."
    return False, ""


def compute_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def check_virustotal_hash(file_hash: str, file_bytes: bytes = b"", filename: str = "attachment",
                          allow_upload: bool = False) -> tuple[str, str]:
    """Look up SHA-256 and optionally submit the sample after explicit consent.

    Standard VirusTotal submissions may be shared with its community and partners.
    Upload requires both per-report consent and the server-side enable switch.
    """
    api_key = Config.VT_API_KEY
    if not api_key:
        return "not_configured", "VirusTotal hash lookup was skipped because no API key is configured."
    if requests is None:
        return "unavailable", "VirusTotal hash lookup is unavailable because requests is not installed."

    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            if malicious_count > 0:
                return "malicious", f"Flagged as malicious by {malicious_count} antivirus engines on VirusTotal."
            if suspicious_count > 0:
                return "suspicious", f"Flagged as suspicious by {suspicious_count} antivirus engines on VirusTotal."
            return "clean", "No antivirus engines on VirusTotal flagged this file."

        if response.status_code == 404:
            if not (allow_upload and Config.VT_FILE_UPLOAD_ENABLED and file_bytes):
                return "unknown", "Hash not found in VirusTotal; file contents were not uploaded (consent and server enablement are required)."
            if len(file_bytes) > Config.MAX_ATTACHMENT_BYTES:
                return "unavailable", "Upload skipped because the file exceeds the 10 MB application limit."
            try:
                upload = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers,
                    files={"file": (filename, file_bytes)},
                    timeout=30,
                )
                upload.raise_for_status()
                analysis_id = upload.json().get("data", {}).get("id")
                if analysis_id:
                    return "pending", "File was submitted to VirusTotal with the submitter's consent; analysis is pending."
                return "unavailable", "VirusTotal returned no analysis ID for the uploaded file."
            except (requests.RequestException, AttributeError, ValueError):
                return "unavailable", "VirusTotal could not accept the upload; check API entitlement, quota, and provider status."

        return "unavailable", f"VirusTotal returned HTTP {response.status_code}; hash result is unavailable."

    except (requests.RequestException, AttributeError, KeyError, TypeError, ValueError):
        return "unavailable", "VirusTotal hash lookup failed; no clean result was established."


def check_attachment(filename: str, file_bytes: bytes = b"", allow_virustotal_upload: bool = False):
    """
    Check an attachment for phishing/malware indicators.

    Returns:
        {
            "risk_score": int,
            "reasons": list[str],
            "vt_status": str  # malicious, suspicious, clean, unknown, pending, not_configured, unavailable
        }
    """
    reasons = []
    score = 0

    is_risky_ext, ext_reason = check_extension(filename)
    if is_risky_ext:
        score += 25
        reasons.append(ext_reason)

    vt_status = "unknown"
    if file_bytes:
        file_hash = compute_sha256(file_bytes)
        vt_status, vt_reason = check_virustotal_hash(
            file_hash, file_bytes=file_bytes, filename=filename, allow_upload=allow_virustotal_upload,
        )

        if vt_status == "malicious":
            score += 60
            reasons.append(vt_reason)
        elif vt_status == "suspicious":
            score += 30
            reasons.append(vt_reason)
        elif vt_status == "clean":
            reasons.append(vt_reason)
        elif vt_status in {"unknown", "not_configured", "unavailable"} and vt_reason:
            reasons.append(vt_reason)

    score = min(score, 100)

    if not file_bytes:
        reasons.append("Coverage: filename extension only; no attachment bytes were supplied, so file content and hash were not scanned.")
    elif vt_status == "unknown":
        reasons.append("Coverage: local filename/extension check ran; VirusTotal hash was unknown; file content was not uploaded.")
    elif vt_status == "not_configured":
        reasons.append("Coverage: local filename/extension check ran; VirusTotal hash lookup was skipped because no API key is configured.")
    elif vt_status == "clean":
        reasons.append("Coverage: local filename/extension check and VirusTotal hash lookup ran; a clean lookup does not prove the file is safe.")
    elif vt_status == "pending":
        reasons.append("Coverage: local filename/extension check ran; VirusTotal upload was accepted and analysis is pending.")
    elif vt_status == "suspicious":
        reasons.append("Coverage: local filename/extension check and VirusTotal hash lookup ran; file was flagged suspicious.")
    elif vt_status == "malicious":
        reasons.append("Coverage: local filename/extension check and VirusTotal hash lookup ran; file was flagged.")
    elif vt_status == "unavailable":
        reasons.append("Coverage: local filename/extension check ran; VirusTotal lookup/upload was unavailable.")
    if not reasons:
        reasons.append("No risky file type detected, and no antivirus data available for this file.")

    return {
        "risk_score": score,
        "reasons": reasons,
        "vt_status": vt_status,
    }


if __name__ == "__main__":
    result = check_attachment("invoice_update.exe")
    print("Risky .exe, no bytes:", result)

    result = check_attachment("quarterly_report.pdf")
    print("Safe .pdf, no bytes:", result)

    fake_bytes = b"this is not a real exe, just test bytes"
    result = check_attachment("payment_form.docm", fake_bytes)
    print("Risky .docm, with bytes (no VT key yet):", result)