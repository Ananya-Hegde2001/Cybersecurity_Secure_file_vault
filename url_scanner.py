import ipaddress
import math
import re
from urllib.parse import parse_qs, unquote, urlparse


SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"
}
SUSPICIOUS_TERMS = {
    "account", "billing", "confirm", "credential", "login", "password", "payment",
    "recover", "secure", "signin", "unlock", "verify", "wallet",
}
DANGEROUS_SCHEMES = {"javascript", "data", "file", "vbscript"}


def _finding(code, severity, message):
    return {"code": code, "severity": severity, "message": message}


def _entropy(value):
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    length = len(value)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 2)


def analyze_url(raw_url: str) -> dict:
    """Analyze URL indicators locally. No network request is made."""
    value = raw_url.strip()
    findings = []
    parsed = urlparse(value if "://" in value else f"https://{value}")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    scheme = parsed.scheme.lower()
    query_values = "&".join(parse_qs(parsed.query, keep_blank_values=True).keys())
    decoded = unquote(value).lower()
    parameters = parse_qs(parsed.query, keep_blank_values=True)
    labels = [label for label in hostname.split(".") if label]
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    host_is_ip = False
    try:
        ipaddress.ip_address(hostname)
        host_is_ip = True
    except ValueError:
        pass

    if not hostname:
        findings.append(_finding("INVALID_HOST", "HIGH", "No valid hostname could be parsed."))
    if scheme in DANGEROUS_SCHEMES:
        findings.append(_finding("DANGEROUS_SCHEME", "HIGH", f"The {scheme}: scheme can execute or load local content."))
    elif scheme != "https":
        findings.append(_finding("NO_TLS", "MEDIUM", "The URL does not use HTTPS."))
    if "@" in parsed.netloc:
        findings.append(_finding("USERINFO_SPOOF", "HIGH", "User-info before the host can disguise the real destination."))
    if hostname.startswith("xn--") or ".xn--" in hostname:
        findings.append(_finding("PUNYCODE_HOST", "HIGH", "The hostname contains internationalized punycode and may imitate another domain."))
    try:
        ipaddress.ip_address(hostname)
        findings.append(_finding("IP_HOST", "MEDIUM", "The destination is a raw IP address instead of a named domain."))
    except ValueError:
        pass
    if len(labels) >= 5:
        findings.append(_finding("DEEP_SUBDOMAINS", "MEDIUM", "The hostname contains an unusual number of subdomain layers."))
    if hostname in SHORTENERS:
        findings.append(_finding("URL_SHORTENER", "MEDIUM", "A shortened URL hides the final destination."))
    if len(value) > 180:
        findings.append(_finding("LONG_URL", "LOW", "An unusually long URL can hide deceptive parameters."))
    if value.count("%") >= 3 or "%2f" in decoded or "%40" in decoded:
        findings.append(_finding("ENCODED_PAYLOAD", "MEDIUM", "Multiple encoded characters may conceal the true route or host."))
    if parsed.port and parsed.port not in {80, 443}:
        findings.append(_finding("UNUSUAL_PORT", "MEDIUM", f"The URL uses non-standard port {parsed.port}."))
    term_hits = sorted({term for term in SUSPICIOUS_TERMS if term in decoded})
    if len(term_hits) >= 2:
        findings.append(_finding("SOCIAL_ENGINEERING_TERMS", "MEDIUM", "Credential or payment language appears in the URL: " + ", ".join(term_hits)))
    if query_values.count("=") >= 6 or len(parse_qs(parsed.query, keep_blank_values=True)) >= 6:
        findings.append(_finding("PARAMETER_DENSITY", "LOW", "The URL contains a dense parameter payload."))

    weights = {"HIGH": 32, "MEDIUM": 16, "LOW": 5}
    score_breakdown = [{"label": item["code"].replace("_", " "), "points": weights[item["severity"]]} for item in findings]
    risk_score = min(100, sum(item["points"] for item in score_breakdown))
    verdict = "BLOCK" if risk_score >= 65 else "SUSPICIOUS" if risk_score >= 25 else "LOW RISK"
    host_class = "IP address" if host_is_ip else "Punycode hostname" if "xn--" in hostname else "Named domain" if hostname else "Unresolved"
    tld = labels[-1] if len(labels) > 1 else "n/a"
    return {
        "input": value,
        "normalized": parsed.geturl(),
        "hostname": hostname or "unresolved",
        "scheme": scheme or "unknown",
        "risk_score": risk_score,
        "verdict": verdict,
        "findings": findings,
        "score_breakdown": score_breakdown,
        "telemetry": {
            "url_length": len(value),
            "hostname_length": len(hostname),
            "host_class": host_class,
            "tld": tld,
            "subdomain_depth": max(0, len(labels) - 2),
            "path_depth": len(path_segments),
            "parameter_count": len(parameters),
            "encoded_characters": value.count("%"),
            "special_characters": len(re.findall(r"[^a-zA-Z0-9]", value)),
            "url_entropy": _entropy(value),
            "port": parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else "none"),
            "suspicious_terms": term_hits,
        },
        "network_accessed": False,
    }
