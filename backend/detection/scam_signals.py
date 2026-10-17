"""
Extra scam signals, added after measuring accuracy on the simulated inbox:
  1. Look-alike sender domains: a brand or government name inside an unrelated domain,
     phishing-style words, or many hyphens.
  2. Common scam lure phrases in English and Amharic: click-the-link prompts, prize scams,
     "storage is full", identity checks and crypto seed phrases.

It does not check links or attachments (see link_check.py and attachment_check.py)
and does not touch the database.
"""

import re

from detection.text_check import (
    KNOWN_ORG_DOMAINS, domain_is_or_under, normalize_amharic, normalize_domain,
)

# Brands that are often impersonated but are not in KNOWN_ORG_DOMAINS. They are kept here so the
# link checker's look-alike test does not start comparing every URL with short domains like bbc.com.
EXTRA_BRANDS = {
    "netflix": {"netflix.com"},
    "telegram": {"telegram.org", "t.me"},
    "github": {"github.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "linkedin": {"linkedin.com"},
    "bbc": {"bbc.com", "bbc.co.uk"},
}
_TOO_SHORT_TO_BE_A_BRAND = {"mor"}

BRANDS = {}
for _name, _domains in list(KNOWN_ORG_DOMAINS.items()) + list(EXTRA_BRANDS.items()):
    if _name.isascii() and _name not in _TOO_SHORT_TO_BE_A_BRAND:
        BRANDS.setdefault(_name, set()).update(_domains)

LEGIT_DOMAINS = (
    {d for domains in KNOWN_ORG_DOMAINS.values() for d in domains}
    | {d for domains in EXTRA_BRANDS.values() for d in domains}
)

PHISHING_DOMAIN_WORDS = {
    "verify", "verification", "secure", "security", "login", "signin", "update",
    "auth", "authenticate", "confirm", "account", "wallet", "billing", "payment",
    "check", "validate", "recovery", "unlock",
}

# Points
BRAND_OR_GOV_IMPERSONATION = 40
SECRET_REQUEST = 25
PRIZE_SCAM = 15
LURE = 10
SENDER_DOMAIN_CAP = 60

SECRET_PHRASES = [
    "verify your credentials", "confirm your credentials", "verify your identity",
    "seed phrase", "recovery phrase", "private key",
]
LURE_PHRASES_EN = [
    "click here", "click the link", "click on the link", "click below",
    "update details", "update required", "payment failed",
    "restore access", "regain access", "storage is full", "mailbox is full",
]
LURE_PHRASES_AM = [
    "ሊንክ በመጫን",       # by clicking the link
    "ሊንኩን በመጫን",
    "ሊንኩን ይጫኑ",       # click the link
    "ሊንክ ይጫኑ",
    "በዚህ ሊንክ",        # via this link
    "ከታች ያለውን ሊንክ",   # the link below
    "እዚህ ይጫኑ",        # click here
]
PRIZE_PHRASES = [
    "you have won", "you've won", "you won", "claim your prize", "lottery",
    "ሎተሪ አሸንፈዋል",     # you won the lottery
    "ሽልማት አሸንፈዋል",    # you won a prize
    "ተሸልመዋል",         # you have been awarded
]


def registrable_label(domain: str) -> str:
    """The main part of a domain: 'mail.cbe-secure.com' -> 'cbe-secure'; 'x.com.et' -> 'x'."""
    labels = domain.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"com", "org", "gov", "edu", "net", "co", "ac"}:
        return labels[-3]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0]


def _brand_in_domain(tokens: list, compact: str):
    """Returns a brand name that appears in the domain label. Short names must be a whole word."""
    for name in BRANDS:
        brand = re.sub(r"[^a-z0-9]", "", name)
        if len(brand) >= 8:
            if brand in compact:
                return name
        elif brand in tokens:
            return name
    return None


def _looks_like_government(domain: str, tokens: list) -> bool:
    """'gov' inside a normal domain name (real government domains end in .gov or .gov.xx)."""
    if not {"gov", "govt", "government"} & set(tokens):
        return False
    return not re.search(r"(^|\.)gov(\.[a-z]{2})?$", domain)


def check_sender_domain(sender_domain: str, skip_impersonation: bool = False):
    """Returns (points, reasons) for the domain the email was really sent from."""
    domain = normalize_domain(sender_domain)
    if not domain or "." not in domain:
        return 0, []
    if any(domain_is_or_under(domain, legit) for legit in LEGIT_DOMAINS):
        return 0, []

    label = registrable_label(domain)
    tokens = [t for t in label.split("-") if t]
    compact = label.replace("-", "")
    points = 0
    reasons = []

    if not skip_impersonation:
        brand = _brand_in_domain(tokens, compact)
        if brand:
            points += BRAND_OR_GOV_IMPERSONATION
            reasons.append(f"Sender domain '{domain}' contains the name '{brand}' but is not an official domain for it.")
        elif _looks_like_government(domain, tokens):
            points += BRAND_OR_GOV_IMPERSONATION
            reasons.append(f"Sender domain '{domain}' imitates a government name but is not a government domain.")

    keywords = sorted({t for t in tokens if t in PHISHING_DOMAIN_WORDS})
    if keywords:
        points += min(20, 10 * len(keywords))
        reasons.append(f"Sender domain contains phishing-style words ({', '.join(keywords)}).")

    if label.count("-") >= 2:
        points += 10
        reasons.append("Sender domain contains several hyphens, a common pattern in fake domains.")

    return min(points, SENDER_DOMAIN_CAP), reasons


def _found(text: str, phrases: list) -> list:
    return [p for p in phrases if normalize_amharic(p) in text]


def check_scam_signals(subject: str, body: str, sender_domain: str = "", claimed_org: str = ""):
    """
    Returns {"risk_score": int, "reasons": list[str]}. The reasons list is empty when nothing was found.
    If the email names who it claims to be (claimed_org), the brand check is skipped because
    text_check already compares the claim with the real domain.
    """
    text = normalize_amharic(f"{subject} {body}".lower())
    score = 0
    reasons = []

    points, domain_reasons = check_sender_domain(sender_domain, skip_impersonation=bool(claimed_org))
    score += points
    reasons.extend(domain_reasons)

    secrets = _found(text, SECRET_PHRASES)
    if secrets:
        score += SECRET_REQUEST
        reasons.append(f"Asks for credentials, an identity check or a wallet seed phrase ({', '.join(secrets[:2])}).")

    prizes = _found(text, PRIZE_PHRASES)
    if prizes:
        score += PRIZE_SCAM
        reasons.append(f"Looks like a prize or lottery scam ({', '.join(prizes[:2])}).")

    lures = _found(text, LURE_PHRASES_EN + LURE_PHRASES_AM)
    if lures:
        score += LURE
        reasons.append(f"Pushes the reader to click or act through a link ({', '.join(lures[:2])}).")

    return {"risk_score": min(score, 100), "reasons": reasons}
