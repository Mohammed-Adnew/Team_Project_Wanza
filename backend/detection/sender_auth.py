"""Interpret SPF/DKIM/DMARC results reported in an Authentication-Results header.

These values are evidence reported by the mail system that added the header; this
module does not verify header provenance or perform DNS/authentication itself.
"""
import re

_AUTH_RESULT = re.compile(r"(?:^|[;\s])(?P<method>spf|dkim|dmarc)\s*=\s*(?P<result>pass|fail|softfail|neutral|none|temperror|permerror|policy|bestguesspass)", re.IGNORECASE)
_METHODS = ("spf", "dkim", "dmarc")


def authentication_statuses_from_reasons(reasons):
    """Recover normalized auth results from the persisted human-readable reasons."""
    text = "\n".join(item for item in (reasons or []) if isinstance(item, str))
    results = {method: "not available" for method in _METHODS}
    header_seen = False
    for method in _METHODS:
        match = re.search(
            rf"Authentication-Results reports {method.upper()} ([A-Z]+)",
            text,
            re.IGNORECASE,
        )
        if match:
            header_seen = True
            results[method] = match.group(1).lower()
        elif re.search(rf"Authentication-Results did not report {method.upper()}", text, re.IGNORECASE):
            header_seen = True
            results[method] = "not reported"
    return {
        "results": results,
        "source": "reported Authentication-Results header" if header_seen else "not supplied or not parseable",
        "independently_verified": False,
    }


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
