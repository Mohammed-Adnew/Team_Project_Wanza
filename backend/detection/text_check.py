"""
Checks the TEXT of an email (subject + body + sender info) for common
phishing indicators. Does NOT check links or attachments — that's the
job of link_check.py and attachment_check.py.
"""

URGENCY_PHRASES = [
    "act now", "within 24 hours", "account will be suspended",
    "immediate action required", "verify your account now",
    "final warning", "action required", "your account has been locked",
    "your account will be closed",
]

CREDENTIAL_REQUEST_PHRASES = [
    "confirm your password", "enter your pin", "provide your credentials",
    "enter your password", "verify your password", "social security number",
    "bank account number", "update your payment details", "wire transfer",
    "credit card number", "debit card number", "security code", "cvv",
]

GENERIC_GREETINGS = [
    "dear valued customer", "dear customer", "dear user", "dear account holder",
]

KNOWN_ORG_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com"},
    "google": {"google.com"},
    "amazon": {"amazon.com"},
    "apple": {"apple.com"},
    "commercial bank of ethiopia": {"combanketh.et"},
    "cbe": {"combanketh.et"},
    "dashen bank": {"dashenbanksc.com"},
    "dashen": {"dashenbanksc.com"},
    "bank of abyssinia": {"bankofabyssinia.com"},
    "boa": {"bankofabyssinia.com"},
    "awash bank": {"awashbank.com"},
    "awash": {"awashbank.com"},
    "national bank of ethiopia": {"nbe.gov.et"},
    "nbe": {"nbe.gov.et"},
    "ethio telecom": {"ethiotelecom.et"},
    "ethiotelecom": {"ethiotelecom.et"},
    "telebirr": {"ethiotelecom.et"},
    "safaricom": {"safaricom.et"},
    "safaricom ethiopia": {"safaricom.et"},
    "m-pesa": {"safaricom.et"},
    "mpesa": {"safaricom.et"},
    "insa": {"insa.gov.et"},
    "information network security agency": {"insa.gov.et"},
    "ethiopian airlines": {"ethiopianairlines.com"},
    "ministry of revenue": {"mor.gov.et"},
    "mor": {"mor.gov.et"},
    "ethiopian government portal": {"ethiopia.gov.et"},
}


def normalize_domain(domain: str) -> str:
    """Normalize a sender domain before comparison."""
    if not domain:
        return ""
    domain = domain.lower().strip()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0].split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def domain_matches_org(sender_domain: str, claimed_org: str) -> bool:
    """Return True if the sender's domain is a known domain for the claimed org."""
    sender_domain = normalize_domain(sender_domain)
    claimed_org = claimed_org.lower().strip()
    allowed_domains = KNOWN_ORG_DOMAINS.get(claimed_org)
    if not allowed_domains:
        return False
    return any(
        sender_domain == domain or sender_domain.endswith("." + domain)
        for domain in allowed_domains
    )


def check_text(subject: str, body: str, sender_domain: str = "", claimed_org: str = ""):
    """
    Analyze an email's TEXT (subject, body, and claimed sender) for
    common phishing indicators.

    Returns:
        {
            "risk_score": int,     # 0-100
            "risk_level": str,     # "Low" / "Moderate" / "High" / "Very High"
            "risky": bool,
            "reasons": list[str]
        }

    Note: does not check links or attachments — see link_check.py and
    attachment_check.py for those. A low score does not prove an email
    is legitimate.
    """
    text = f"{subject} {body}".lower()
    score = 0
    reasons = []

    urgency_found = [p for p in URGENCY_PHRASES if p in text]
    if urgency_found:
        score += min(25, 10 + (len(urgency_found) - 1) * 5)
        reasons.append(f"Uses urgent or pressuring language ({', '.join(urgency_found[:3])}).")

    credentials_found = [p for p in CREDENTIAL_REQUEST_PHRASES if p in text]
    if credentials_found:
        score += min(35, 25 + (len(credentials_found) - 1) * 5)
        reasons.append(
            f"Requests sensitive credentials or financial information ({', '.join(credentials_found[:3])})."
        )

    if any(phrase in text for phrase in GENERIC_GREETINGS):
        score += 5
        reasons.append("Uses a generic greeting rather than addressing the recipient specifically.")

    if claimed_org and sender_domain:
        normalized_sender = normalize_domain(sender_domain)
        normalized_org = claimed_org.lower().strip()

        if normalized_org in KNOWN_ORG_DOMAINS:
            if domain_matches_org(sender_domain, claimed_org):
                reasons.append("Sender domain matches a known domain for the claimed organization.")
            else:
                score += 30
                reasons.append(
                    f"Sender domain ('{normalized_sender}') does not match a known domain for '{claimed_org}'."
                )
        else:
            reasons.append(
                f"The claimed organization ('{claimed_org}') is not in the built-in domain database."
            )

    score = min(score, 100)

    if score >= 75:
        risk_level = "Very High"
    elif score >= 50:
        risk_level = "High"
    elif score >= 25:
        risk_level = "Moderate"
    else:
        risk_level = "Low"

    if not reasons:
        reasons = [
            "No obvious urgency or pressure language detected.",
            "No obvious credential or financial-information request detected.",
            "No known generic phishing greeting detected.",
        ]
        if claimed_org and sender_domain and domain_matches_org(sender_domain, claimed_org):
            reasons.append("Sender domain matches a known domain for the claimed organization.")
        reasons.append("No obvious phishing indicators were detected by these rules.")

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "risky": score >= 50,
        "reasons": reasons,
    }


if __name__ == "__main__":
    result = check_text(
        subject="URGENT: Verify your account now",
        body="Dear customer, your account will be suspended within 24 hours. Please confirm your password.",
        sender_domain="fake-example.com",
        claimed_org="Commercial Bank of Ethiopia",
    )
    print("Fake CBE:", result)

    result = check_text(
        subject="Monthly newsletter",
        body="Hello Abebe, here are this month's company updates.",
        sender_domain="example.com",
        claimed_org="",
    )
    print("Ordinary email:", result)