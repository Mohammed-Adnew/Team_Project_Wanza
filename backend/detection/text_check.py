"""
Checks the TEXT of an email (subject + body + sender info) for common
phishing indicators, in English and Amharic. Does NOT check links or
attachments - that's the job of link_check.py and attachment_check.py.
"""

import re

# ---------------------------------------------------------------------------
# English phrases
# ---------------------------------------------------------------------------

URGENCY_PHRASES_EN = [
    "act now", "within 24 hours", "account will be suspended",
    "immediate action required", "verify your account now",
    "final warning", "action required", "your account has been locked",
    "your account will be closed",
]

CREDENTIAL_REQUEST_PHRASES_EN = [
    "confirm your password", "enter your pin", "provide your credentials",
    "enter your password", "verify your password", "social security number",
    "bank account number", "update your payment details", "wire transfer",
    "credit card number", "debit card number", "security code", "cvv",
]

GENERIC_GREETINGS_EN = [
    "dear valued customer", "dear customer", "dear user", "dear account holder",
]

# ---------------------------------------------------------------------------
# Amharic phrases (አማርኛ)
#
# Written from general knowledge of how phishing is phrased in Amharic, so have
# an Amharic speaker on the team review these lists. Phrases are kept short
# because Amharic words change with suffixes, and a wrong word simply never
# matches.
# ---------------------------------------------------------------------------

URGENCY_PHRASES_AM = [
    "አስቸኳይ",                # urgent
    "ወዲያውኑ",               # immediately
    "አሁኑኑ",                 # right now
    "የመጨረሻ ማስጠንቀቂያ",     # final warning
    "በ24 ሰዓት ውስጥ",         # within 24 hours
    "በ24 ሰአት ውስጥ",         # (alternative spelling of "hour")
    "በ48 ሰዓት ውስጥ",         # within 48 hours
    "በ48 ሰአት ውስጥ",
    "ይታገዳል",               # will be suspended / blocked
    "ታግዷል",                # has been suspended / blocked
]

# Amharic puts the verb at the end of the sentence, so other words can sit between
# the item and the verb ("your password, urgently, change"). These are matched
# together in the same sentence by find_secret_requests() below.
_AM_SECRETS = ["የይለፍ ቃልዎን", "ፒን ቁጥርዎን", "መረጃዎን"]  # your password / your PIN number / your information
_AM_ACTIONS = ["ያስገቡ", "ያረጋግጡ", "ይላኩ", "ያዘምኑ", "ይቀይሩ", "ይለውጡ"]  # enter / verify / send / update / change / change
_AM_MAX_GAP = 40  # most characters allowed between the item and the verb

CREDENTIAL_REQUEST_PHRASES_AM = [
    "የባንክ አካውንት ቁጥር",      # bank account number
    "የባንክ ሂሳብ ቁጥር",        # bank account number (formal word for account)
    "የክሬዲት ካርድ ቁጥር",       # credit card number
    "ገንዘብ ያስተላልፉ",         # transfer money
]

GENERIC_GREETINGS_AM = [
    "ውድ ደንበኛ",    # dear customer
    "ውድ ተጠቃሚ",    # dear user
    "ክቡር ደንበኛ",   # esteemed customer
]

URGENCY_PHRASES = URGENCY_PHRASES_EN + URGENCY_PHRASES_AM
CREDENTIAL_REQUEST_PHRASES = CREDENTIAL_REQUEST_PHRASES_EN + CREDENTIAL_REQUEST_PHRASES_AM
GENERIC_GREETINGS = GENERIC_GREETINGS_EN + GENERIC_GREETINGS_AM

# Extra points when an email BOTH pressures the reader to hurry AND asks for sensitive
# information - the classic phishing combination. Set to 0 to turn this off.
URGENCY_AND_CREDENTIALS_BONUS = 15

# ---------------------------------------------------------------------------
# Sender / organization data
# ---------------------------------------------------------------------------

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "aol.com", "icloud.com", "mail.com", "yandex.com",
}

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
    # The same organizations written in Amharic
    "የኢትዮጵያ ንግድ ባንክ": {"combanketh.et"},
    "ዳሽን ባንክ": {"dashenbanksc.com"},
    "አዋሽ ባንክ": {"awashbank.com"},
    "አቢሲኒያ ባንክ": {"bankofabyssinia.com"},
    "ቴሌብር": {"ethiotelecom.et"},
    "ኢትዮ ቴሌኮም": {"ethiotelecom.et"},
    "ሳፋሪኮም": {"safaricom.et"},
    "የኢትዮጵያ አየር መንገድ": {"ethiopianairlines.com"},
}

# ---------------------------------------------------------------------------
# Amharic spelling variants
#
# Some Amharic sounds can be written with more than one letter (for example
# ሀ / ሐ / ኀ, ሰ / ሠ, አ / ዐ, ጸ / ፀ), and spelling is not fully standardized
# (ሂሳብ and ሒሳብ are the same word). Both the text and the phrase lists are
# mapped to one standard letter before matching. Each variant row is mapped
# to its standard row, 8 code points at a time.
# ---------------------------------------------------------------------------

_AMHARIC_VARIANT_ROWS = [
    (0x1210, 0x1200),  # ሐ -> ሀ
    (0x1280, 0x1200),  # ኀ -> ሀ
    (0x1220, 0x1230),  # ሠ -> ሰ
    (0x12D0, 0x12A0),  # ዐ -> አ
    (0x1340, 0x1338),  # ፀ -> ጸ
]
_AMHARIC_MAP = {
    variant + i: standard + i
    for variant, standard in _AMHARIC_VARIANT_ROWS
    for i in range(8)
}


def normalize_amharic(text: str) -> str:
    """Maps Amharic spelling variants to one standard letter. English text is unchanged."""
    return text.translate(_AMHARIC_MAP)


def find_phrases(text: str, phrases: list) -> list:
    """Returns the phrases that appear in text (text must already be lowercased and normalized)."""
    return [p for p in phrases if normalize_amharic(p) in text]


def find_secret_requests(text: str) -> list:
    """
    Finds Amharic requests like "change your password" even when other words sit between
    the item and the verb. The item and the verb must be in the same sentence and at most
    _AM_MAX_GAP characters apart (a sentence ends at ። . ! ? or a new line).
    """
    found = []
    for secret in _AM_SECRETS:
        for action in _AM_ACTIONS:
            pattern = (
                re.escape(normalize_amharic(secret))
                + "[^።.!?\n]{0," + str(_AM_MAX_GAP) + "}?"
                + re.escape(normalize_amharic(action))
            )
            if re.search(pattern, text):
                found.append(f"{secret} ... {action}")
    return found


def mentions_org(text: str, org_name: str) -> bool:
    """
    True if an organization name appears in text. English names must match as whole
    words (so 'mor' does not match 'Morgan'). Amharic names match anywhere, because
    Amharic prefixes such as በ- or ለ- attach directly to the word.
    """
    if org_name.isascii():
        return re.search(rf"(?<![a-z0-9]){re.escape(org_name)}(?![a-z0-9])", text) is not None
    return normalize_amharic(org_name) in text


# ---------------------------------------------------------------------------
# Domain and sender helpers
# ---------------------------------------------------------------------------

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


def domain_is_or_under(domain: str, parent: str) -> bool:
    """True if domain is parent or a subdomain of it (mail.example.com is under example.com)."""
    return domain == parent or domain.endswith("." + parent)


def domain_matches_org(sender_domain: str, claimed_org: str) -> bool:
    """Return True if the sender's domain is a known domain for the claimed org."""
    sender_domain = normalize_domain(sender_domain)
    claimed_org = claimed_org.lower().strip()
    allowed_domains = KNOWN_ORG_DOMAINS.get(claimed_org)
    if not allowed_domains:
        return False
    return any(domain_is_or_under(sender_domain, domain) for domain in allowed_domains)


def extract_domain_from_email(email_address: str) -> str:
    """Pulls the domain out of a full email address, e.g. 'alerts@combanketh.et' -> 'combanketh.et'."""
    if not email_address or "@" not in email_address:
        return ""
    return normalize_domain(email_address.rsplit("@", 1)[-1].strip(" >"))


_SENDER_WITH_NAME = re.compile(r'^\s*"?([^"<]*?)"?\s*<([^>]*)>\s*$')


def split_sender(sender: str) -> tuple:
    """
    Splits a sender string into (display name, address).
      'Commercial Bank <alerts@x.com>' -> ('Commercial Bank', 'alerts@x.com')
      'alerts@x.com'                   -> ('', 'alerts@x.com')
    """
    sender = (sender or "").strip()
    match = _SENDER_WITH_NAME.match(sender)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return "", sender


def check_sender_identity(sender_display_name: str, sender_email: str, claimed_org: str) -> list:
    """
    Checks for sender-identity spoofing patterns that go beyond a simple
    domain comparison:
      - The display name names a known organization, but the actual email
        domain isn't one of that organization's domains.
      - The email claims to represent an organization but is sent from
        a free consumer email provider (gmail, yahoo, etc.).

    Returns a list of (is_risky, reason) tuples; empty if nothing was provided.
    """
    findings = []

    if not sender_email:
        return findings

    email_domain = extract_domain_from_email(sender_email)

    if claimed_org and email_domain in FREE_EMAIL_PROVIDERS:
        findings.append((
            True,
            f"Claims to represent '{claimed_org}' but was sent from a free email "
            f"provider ({email_domain}) rather than the organization's own domain."
        ))

    if sender_display_name:
        display = normalize_amharic(sender_display_name.lower())
        for org_name, org_domains in KNOWN_ORG_DOMAINS.items():
            if mentions_org(display, org_name):
                if not any(domain_is_or_under(email_domain, d) for d in org_domains):
                    findings.append((
                        True,
                        f"Display name mentions '{org_name}', but the sending address "
                        f"('{sender_email}') does not match any known domain for that organization."
                    ))
                break

    return findings


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_text(
    subject: str,
    body: str,
    sender_domain: str = "",
    claimed_org: str = "",
    sender_display_name: str = "",
    sender_email: str = "",
):
    """
    Analyze an email's TEXT (subject, body, and sender information) for
    common phishing indicators, in English and Amharic.

    claimed_org: who the email says it is from. Either an organization name
      ("Commercial Bank of Ethiopia") or an address ("support@bank.com"). A name
      is checked against the known-organization list; an address is compared with
      the real sending domain.
    sender_domain: the domain the email was really sent from.
    sender_display_name / sender_email: optional, enable the display-name and
      free-email-provider checks.

    Returns:
        {
            "risk_score": int,     # 0-100
            "risk_level": str,     # "Low" / "Moderate" / "High" / "Very High"
            "risky": bool,
            "reasons": list[str]
        }

    A low score does not prove an email is legitimate.
    """
    text = normalize_amharic(f"{subject} {body}".lower())
    score = 0
    reasons = []  # risk signals
    notes = []    # informational lines that are not risk signals

    urgency_found = find_phrases(text, URGENCY_PHRASES)
    if urgency_found:
        score += min(25, 10 + (len(urgency_found) - 1) * 5)
        reasons.append(f"Uses urgent or pressuring language ({', '.join(urgency_found[:3])}).")

    credentials_found = find_phrases(text, CREDENTIAL_REQUEST_PHRASES) + find_secret_requests(text)
    if credentials_found:
        score += min(35, 25 + (len(credentials_found) - 1) * 5)
        reasons.append(
            f"Requests sensitive credentials or financial information ({', '.join(credentials_found[:3])})."
        )

    if urgency_found and credentials_found and URGENCY_AND_CREDENTIALS_BONUS:
        score += URGENCY_AND_CREDENTIALS_BONUS
        reasons.append(
            "Combines pressure to act quickly with a request for sensitive information, "
            "a classic phishing pattern."
        )

    if find_phrases(text, GENERIC_GREETINGS):
        score += 5
        reasons.append("Uses a generic greeting rather than addressing the recipient specifically.")

    if claimed_org and sender_domain:
        normalized_sender = normalize_domain(sender_domain)
        claim = claimed_org.strip()

        if "@" in claim:
            # The email claims to come from a specific address
            claimed_domain = extract_domain_from_email(claim)
            if claimed_domain:
                if domain_is_or_under(normalized_sender, claimed_domain):
                    notes.append("The sender's real domain matches the domain the email claims to come from.")
                else:
                    score += 30
                    reasons.append(
                        f"The email claims to come from '{claimed_domain}' but was actually "
                        f"sent from '{normalized_sender}'."
                    )
        elif claim.lower() in KNOWN_ORG_DOMAINS:
            if domain_matches_org(sender_domain, claim):
                notes.append("Sender domain matches a known domain for the claimed organization.")
            else:
                score += 30
                reasons.append(
                    f"Sender domain ('{normalized_sender}') does not match a known domain for '{claimed_org}'."
                )
        else:
            notes.append(f"The claimed organization ('{claimed_org}') is not in the built-in domain database.")

    for is_risky, reason in check_sender_identity(sender_display_name, sender_email, claimed_org):
        if is_risky:
            score += 30
            reasons.append(reason)

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
        ] + notes + ["No obvious phishing indicators were detected by these rules."]
    else:
        reasons.extend(notes)

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "risky": score >= 50,
        "reasons": reasons,
    }


if __name__ == "__main__":
    def show(title, result):
        print(f"{title}: score={result['risk_score']} level={result['risk_level']} risky={result['risky']}")
        for reason in result["reasons"]:
            print("   -", reason)
        print()

    show("English fake CBE", check_text(
        subject="URGENT: Verify your account now",
        body="Dear customer, your account will be suspended within 24 hours. Please confirm your password.",
        sender_domain="fake-example.com",
        claimed_org="Commercial Bank of Ethiopia",
    ))

    # The Amharic seed email from the database: "Please verify your information by clicking the link."
    show("Amharic seed email, with the claimed address", check_text(
        subject="የየካቲት ወር የባንክ ማስተካከያ",
        body="እባክዎ ሊንኩን በመጫን መረጃዎን ያረጋግጡ።",
        sender_domain="malicious-domain.com",
        claimed_org="support@ethiopian-bank.com",
    ))

    show("Amharic seed email, no claim known", check_text(
        subject="የየካቲት ወር የባንክ ማስተካከያ",
        body="እባክዎ ሊንኩን በመጫን መረጃዎን ያረጋግጡ።",
        sender_domain="malicious-domain.com",
    ))