"""
Checks an ATTACHMENT for phishing/malware indicators.

Two layers, both always applied:
  - Risky file extension check (always runs, no API needed, free).
  - VirusTotal hash lookup (only runs if an API key is configured;
    otherwise silently skipped, and the extension check alone is used).

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


def check_virustotal_hash(file_hash: str) -> tuple[str, str]:
    """
    Real check against VirusTotal's hash-lookup endpoint.
    Only called when an API key is configured.

    Returns (status, reason) where status is one of:
        "malicious", "clean", "unknown" (not found / no key / error)
    """
    api_key = Config.VT_API_KEY
    if not api_key or requests is None:
        return "unknown", ""

    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0)
            if malicious_count > 0:
                return "malicious", f"Flagged as malicious by {malicious_count} antivirus engines on VirusTotal."
            return "clean", "No antivirus engines on VirusTotal flagged this file."

        if response.status_code == 404:
            return "unknown", "File hash not found in VirusTotal's database (unrecognized file)."

        return "unknown", ""

    except Exception:
        return "unknown", ""


def check_attachment(filename: str, file_bytes: bytes = b""):
    """
    Check an attachment for phishing/malware indicators.

    Returns:
        {
            "risk_score": int,
            "reasons": list[str],
            "vt_status": str  # "malicious" / "clean" / "unknown"
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
        vt_status, vt_reason = check_virustotal_hash(file_hash)

        if vt_status == "malicious":
            score += 60
            reasons.append(vt_reason)
        elif vt_status == "clean":
            reasons.append(vt_reason)
        elif vt_status == "unknown" and vt_reason:
            reasons.append(vt_reason)

    score = min(score, 100)

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