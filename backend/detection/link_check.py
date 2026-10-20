"""
Checks links with local URL/domain parsing and Google Safe Browsing.
VirusTotal is used for file-hash lookups only; URLs are sent to Safe Browsing
only when the API key is configured.
"""

import re
from urllib.parse import urlsplit

try:
    import requests
except ImportError:
    requests = None

from config import Config
from detection.text_check import KNOWN_ORG_DOMAINS, normalize_domain


LINK_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd"}
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz"}
MAX_URLS_PER_EMAIL = 5
ALL_KNOWN_DOMAINS = {d for domains in KNOWN_ORG_DOMAINS.values() for d in domains}


def extract_urls(text: str) -> list:
    """Extract HTTP(S)/www URLs, trim punctuation, and deduplicate exact matches."""
    matches = re.findall(r"(?:https?://|www\.)[^\s<>\"']+", text or "", flags=re.IGNORECASE)
    urls = []
    for match in matches:
        candidate = match.rstrip(".,;:!?}]")
        while candidate.endswith(")") and candidate.count(")") > candidate.count("("):
            candidate = candidate[:-1]
        if candidate:
            if candidate.lower().startswith("www."):
                candidate = "http://" + candidate
            urls.append(candidate)
    return list(dict.fromkeys(urls))


def get_url_domain(url: str) -> str:
    """Return a normalized IDNA hostname, never a userinfo/port/path component."""
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return ""
        hostname = parts.hostname.rstrip(".").encode("idna").decode("ascii")
        return normalize_domain(hostname)
    except (ValueError, UnicodeError):
        return ""


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if not b:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            current_row.append(min(current_row[-1] + 1, previous_row[j + 1] + 1,
                                   previous_row[j] + (ca != cb)))
        previous_row = current_row
    return previous_row[-1]


def check_url_heuristics(domain: str) -> tuple[bool, str]:
    if not domain:
        return True, "URL had no valid HTTP(S) hostname."
    if any(domain == known or domain.endswith("." + known) for known in ALL_KNOWN_DOMAINS):
        return False, ""
    if domain in LINK_SHORTENERS:
        return True, f"Uses a link shortener ({domain}), which can hide the destination."
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
        return True, "Uses a raw IP address instead of a domain name."
    if domain.count(".") >= 4:
        return True, "Has an unusually deep subdomain structure."
    tld = domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        return True, f"Uses a top-level domain ('.{tld}') commonly abused for phishing."
    if domain.count("-") >= 2:
        return True, "Contains multiple hyphens, a common phishing-domain pattern."
    labels = domain.split(".")
    suspicious_words = {"login", "verify", "verification", "secure", "security", "account", "update", "confirm", "password", "wallet"}
    if any(suspicious_words.intersection(re.findall(r"[a-z]+", label)) for label in labels[:-2]):
        return True, "Contains suspicious keywords typically used to imitate a login/security page."
    root = ".".join(labels[-2:]) if len(labels) >= 2 else domain
    for known_root in ALL_KNOWN_DOMAINS:
        if root != known_root and levenshtein(root, known_root) <= 2:
            return True, f"Closely resembles the known domain '{known_root}' (possible lookalike/typosquat)."
    return False, ""


def check_url_safe_browsing(url: str) -> tuple[bool, str, str]:
    """Return (flagged, reason, status) where status makes skipped/errors explicit."""
    if not Config.SAFE_BROWSING_API_KEY:
        return False, "Google Safe Browsing was skipped because no API key is configured.", "not_configured"
    if requests is None:
        return False, "Google Safe Browsing is unavailable because requests is not installed.", "unavailable"
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={Config.SAFE_BROWSING_API_KEY}"
    payload = {"client": {"clientId": "phishwatch", "clientVersion": "1.0"}, "threatInfo": {
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}],
    }}
    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        response.raise_for_status()
        matches = response.json().get("matches") or []
        if matches:
            kind = matches[0].get("threatType", "unknown threat")
            return True, f"Flagged by Google Safe Browsing as {kind}.", "threat"
        return False, "Google Safe Browsing reported no match.", "clean"
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        return False, "Google Safe Browsing lookup failed; this URL was not verified by that service.", "unavailable"


def check_link(text: str):
    """Check up to five unique links and report coverage per URL."""
    urls = extract_urls(text)
    checked = urls[:MAX_URLS_PER_EMAIL]
    reasons = []
    score = 0
    confirmed_threat = False
    lookup_statuses = []

    for url in checked:
        try:
            parts = urlsplit(url)
        except ValueError:
            parts = None
        domain = get_url_domain(url)
        if parts and (parts.username or parts.password):
            score += 20
            reasons.append("URL contains user-info before the hostname, a technique that can disguise its destination.")
        flagged, provider_reason, provider_status = check_url_safe_browsing(url)
        lookup_statuses.append(provider_status)
        if flagged:
            score += 40
            confirmed_threat = True
            reasons.append(f"Safe Browsing - {provider_reason}")
        else:
            reasons.append(f"Safe Browsing coverage ({provider_status}) - {provider_reason}")
        suspicious, heuristic_reason = check_url_heuristics(domain)
        if suspicious:
            score += 15
            reasons.append(f"Heuristic ({domain or 'invalid URL'}) - {heuristic_reason}")
        else:
            reasons.append("Local URL heuristics found no known suspicious pattern; this does not prove the URL is safe.")
    score = min(score, 100)
    if len(urls) > MAX_URLS_PER_EMAIL:
        reasons.append(f"Only {MAX_URLS_PER_EMAIL} of {len(urls)} unique links were checked; the remainder were skipped to limit request volume.")
    if not urls:
        reasons.append("Coverage: URL check not applicable; no HTTP(S) links were found.")
    return {"risk_score": score, "reasons": reasons, "checked_urls": checked,
            "skipped_url_count": max(0, len(urls)-len(checked)), "lookup_statuses": lookup_statuses,
            "confirmed_threat": confirmed_threat}
