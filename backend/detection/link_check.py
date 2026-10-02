"""
Checks LINKS found in an email for phishing/malicious indicators.

Three layers, applied in order of confidence:
  1. VirusTotal URL check (if a VirusTotal API key is configured) -
     real threat-intelligence data from 70+ antivirus/blocklist engines.
  2. Google Safe Browsing (if a Safe Browsing API key is configured) -
     real threat-intelligence data from Google.
  3. Local heuristics (always runs as a baseline) - suspicious TLDs,
     excessive hyphens, IP addresses, link shorteners, typosquatting
     against known organization domains.

This lets the whole detection pipeline work end-to-end before any API
key exists, and automatically use real data the moment a key is added
to .env - no code changes needed.

Does NOT check email text or attachments - see text_check.py and
attachment_check.py for those.
"""

import re
import base64
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

from config import Config
from detection.text_check import KNOWN_ORG_DOMAINS, normalize_domain


LINK_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd"}
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz"}

ALL_KNOWN_DOMAINS = {d for domains in KNOWN_ORG_DOMAINS.values() for d in domains}


def extract_urls(text: str) -> list:
    """Extract HTTP/HTTPS URLs from text."""
    return re.findall(r"https?://[^\s<>\"]+", text, flags=re.IGNORECASE)


def get_url_domain(url: str) -> str:
    try:
        return normalize_domain(urlparse(url).netloc)
    except ValueError:
        return ""


def levenshtein(a: str, b: str) -> int:
    """Simple edit-distance calculation, used for typosquat detection."""
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_url_heuristics(domain: str) -> tuple[bool, str]:
    """
    Local, offline heuristic check for a single URL's domain.
    Returns (is_suspicious, reason).
    """
    if not domain:
        return True, "URL had no readable domain."

    if any(domain == known or domain.endswith("." + known) for known in ALL_KNOWN_DOMAINS):
        return False, ""

    if domain in LINK_SHORTENERS:
        return True, f"Uses a link shortener ({domain}), which can hide the real destination."

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        return True, "Uses a raw IP address instead of a domain name."

    if domain.count(".") >= 4:
        return True, "Has an unusually deep subdomain structure."

    tld = domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        return True, f"Uses a top-level domain ('.{tld}') commonly abused for phishing."

    if domain.count("-") >= 2:
        return True, "Contains multiple hyphens, a common phishing-domain pattern."

    labels = domain.split(".")
    suspicious_words = ["login", "verify", "verification", "secure", "security",
                         "account", "update", "confirm", "password", "wallet"]
    if any(any(word in label for word in suspicious_words) for label in labels[:-2]):
        return True, "Contains suspicious keywords typically used to imitate a login/security page."

    domain_root = ".".join(labels[-2:]) if len(labels) >= 2 else domain
    for known_root in ALL_KNOWN_DOMAINS:
        if domain_root != known_root and levenshtein(domain_root, known_root) <= 2:
            return True, f"Closely resembles the known domain '{known_root}' (possible lookalike/typosquat)."

    return False, ""


def check_url_safe_browsing(url: str) -> tuple[bool, str]:
    """
    Returns (is_flagged, reason). Silently returns (False, "") if no
    key is configured or the request fails.
    """
    api_key = Config.SAFE_BROWSING_API_KEY
    if not api_key or requests is None:
        return False, ""

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishwatch", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get("matches"):
            threat_type = data["matches"][0].get("threatType", "unknown threat")
            return True, f"Flagged by Google Safe Browsing as {threat_type}."
        return False, ""
    except Exception:
        return False, ""


def _vt_url_id(url: str) -> str:
    """VirusTotal identifies URLs by the base64 (URL-safe, no padding) of the URL string."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_url_virustotal(url: str) -> tuple[str, str]:
    """
    Checks a URL against VirusTotal.

    Returns (status, reason) where status is one of:
        "malicious", "clean", "unknown"
    """
    api_key = Config.VT_API_KEY
    if not api_key or requests is None:
        return "unknown", ""

    headers = {"x-apikey": api_key}
    url_id = _vt_url_id(url)
    lookup_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(lookup_endpoint, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0)
            if malicious_count > 0:
                return "malicious", f"Flagged as malicious by {malicious_count} security engines on VirusTotal."
            return "clean", "No security engines on VirusTotal flagged this URL."

        if response.status_code == 404:
            try:
                requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=10,
                )
            except Exception:
                pass
            return "unknown", "URL has not been analyzed by VirusTotal before (submitted for future analysis)."

        return "unknown", ""

    except Exception:
        return "unknown", ""


def check_link(text: str):
    """
    Check all links found in the given text (typically an email body).

    Returns:
        {
            "risk_score": int,
            "reasons": list[str],
            "checked_urls": list[str]
        }
    """
    urls = extract_urls(text)
    reasons = []
    score = 0

    for url in urls:
        domain = get_url_domain(url)
        decided = False

        vt_status, vt_reason = check_url_virustotal(url)
        if vt_status == "malicious":
            score += 40
            reasons.append(f"VirusTotal - {vt_reason}")
            decided = True
        elif vt_status == "unknown" and vt_reason:
            reasons.append(f"VirusTotal - {vt_reason}")

        if not decided:
            flagged, sb_reason = check_url_safe_browsing(url)
            if flagged:
                score += 40
                reasons.append(f"Safe Browsing - {sb_reason}")
                decided = True

        is_suspicious, heuristic_reason = check_url_heuristics(domain)
        if is_suspicious:
            score += 15
            reasons.append(f"Heuristic ({domain}) - {heuristic_reason}")

    score = min(score, 100)

    if urls and not reasons:
        reasons.append("No suspicious link indicators detected.")

    return {
        "risk_score": score,
        "reasons": reasons,
        "checked_urls": urls,
    }


if __name__ == "__main__":
    result = check_link("Click here to verify your account: https://bit.ly/fake123")
    print("Shortened link:", result)

    result = check_link("Please log in at https://comnbanketh.et/login")
    print("Typosquat domain:", result)

    result = check_link("View your statement at https://combanketh.et/statements")
    print("Legit domain:", result)

    result = check_link("This email has no links in it.")
    print("No links:", result)