"""Interpret SPF/DKIM/DMARC results reported in an Authentication-Results header.

These values are evidence reported by the mail system that added the header; this
module does not verify header provenance or perform DNS/authentication itself.
"""
import re

_AUTH_RESULT = re.compile(r"(?:^|[;\s])(?P<method>spf|dkim|dmarc)\s*=\s*(?P<result>pass|fail|softfail|neutral|none|temperror|permerror|policy|bestguesspass)", re.IGNORECASE)
_METHODS = ("spf", "dkim", "dmarc")


def summarize_authentication_results(header_values):
    """Return explicit coverage/findings for an Authentication-Results value or values."""
    if isinstance(header_values, str):
        values = [header_values]
    elif isinstance(header_values, (list, tuple)):
        values = [v for v in header_values if isinstance(v, str)]
    else:
        values = []

    parsed = {}
    for value in values:
        for match in _AUTH_RESULT.finditer(value):
            parsed.setdefault(match.group("method").lower(), match.group("result").lower())

    if not parsed:
        return ["Coverage: no parseable SPF/DKIM/DMARC Authentication-Results were supplied; sender identity is unverified."]

    findings = []
    for method in _METHODS:
        result = parsed.get(method)
        if result is None:
            findings.append(f"Authentication-Results did not report {method.upper()}.")
        else:
            findings.append(f"Authentication-Results reports {method.upper()} {result.upper()}.")
    findings.append("These are reported email-header values; their trust depends on the receiving mail system and was not independently verified by this backend.")
    if any(parsed.get(method) in {"fail", "softfail", "permerror"} for method in _METHODS):
        findings.append("At least one reported sender-authentication check failed; treat the sender as unverified.")
    elif all(parsed.get(method) == "pass" for method in _METHODS):
        findings.append("All three reported sender-authentication checks passed; this alone does not prove the message is safe.")
    return findings
