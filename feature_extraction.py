import ipaddress
import re
from urllib.parse import unquote, urlsplit, urlunsplit

import numpy as np

FEATURE_ORDER = [
    "total_url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special_chars",
    "num_subdomains",
    "has_ip_address",
    "has_at_symbol",
    "suspicious_keyword_count",
    "is_https",
    "has_unusual_port",
    "has_suspicious_encoding",
    "has_misleading_hostname",
    "has_url_shortening_indicator",
]

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "account", "secure", "bank", "paypal",
    "confirm", "update", "password", "invoice", "billing", "delivery",
    "suspicious", "urgent", "action", "claim", "free", "winner", "credit",
    "alert", "security",
}

SHORTENING_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "tiny.cc",
    "buff.ly", "youtu.be", "shorturl.at",
}
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_INVALID_PERCENT_RE = re.compile(r"%(?![0-9a-fA-F]{2})")


def _normalize_hostname(hostname):
    if not hostname or hostname.endswith(".") or hostname.startswith(".") or ".." in hostname:
        raise ValueError("Hostname structure is invalid.")
    try:
        return ipaddress.ip_address(hostname).compressed.lower()
    except ValueError:
        pass

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Hostname contains an invalid internationalized domain.") from exc
    if len(ascii_hostname) > 253:
        raise ValueError("Hostname is too long.")
    labels = ascii_hostname.split(".")
    if len(labels) < 2 or any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Hostname is not a valid domain.")
    if not labels[-1].isalpha() and not labels[-1].startswith("xn--"):
        raise ValueError("Domain suffix is invalid.")
    return ascii_hostname


def validate_url(url):
    if not isinstance(url, str):
        raise ValueError("URL must be a string.")
    cleaned = url.strip()
    if not cleaned:
        raise ValueError("URL cannot be empty.")
    if len(cleaned) > 4096:
        raise ValueError("URL is too long.")
    if any(ord(character) < 32 or character.isspace() for character in cleaned):
        raise ValueError("URL cannot contain whitespace or control characters.")
    if _INVALID_PERCENT_RE.search(cleaned):
        raise ValueError("URL contains malformed percent encoding.")

    potential_scheme = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", cleaned)
    if potential_scheme:
        scheme = potential_scheme.group(1).lower()
        if scheme in {"http", "https"}:
            if not cleaned.lower().startswith((f"{scheme}://",)):
                raise ValueError("HTTP and HTTPS URLs must include // after the scheme.")
        elif "." not in scheme:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        else:
            cleaned = "https://" + cleaned
    else:
        cleaned = "https://" + cleaned
    try:
        parsed = urlsplit(cleaned)
    except ValueError as exc:
        raise ValueError("URL is malformed.") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.netloc:
        raise ValueError("URL is missing a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not supported.")
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid hostname or port.") from exc
    normalized_hostname = _normalize_hostname(hostname)
    if parsed.netloc.endswith(":"):
        raise ValueError("URL contains an empty port.")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    host_is_ipv6 = ":" in normalized_hostname
    netloc = f"[{normalized_hostname}]" if host_is_ipv6 else normalized_hostname
    if port is not None:
        netloc = f"{netloc}:{port}"
    normalized = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "", parsed.query, parsed.fragment))
    return normalized


def _count_subdomains(hostname):
    try:
        ipaddress.ip_address(hostname)
        return 0
    except ValueError:
        labels = hostname.split(".")
        return max(0, len(labels) - 2)


def _count_special_characters(url):
    return len(re.findall(r"[^a-zA-Z0-9]", url))


def _has_suspicious_encoding(url):
    return bool(re.search(r"%[0-9a-fA-F]{2}", url))


def _has_misleading_hostname(hostname):
    labels = hostname.split(".")
    return (
        hostname.count("-") > 2
        or len(labels) > 4
        or any(label.startswith("xn--") for label in labels)
        or bool(re.search(r"(?:^|[.-])[a-z0-9-]+\.(?:com|net|org)\.[a-z]{2,}$", hostname))
    )


def _suspicious_keywords_in_url(url):
    tokens = set(re.findall(r"[a-z0-9]+", url.lower()))
    return len(tokens.intersection(SUSPICIOUS_KEYWORDS))


def _has_shortening_indicator(hostname):
    return any(hostname == domain or hostname.endswith("." + domain) for domain in SHORTENING_DOMAINS)


def extract_url_features(url):
    normalized_url = validate_url(url)
    parsed = urlsplit(normalized_url)
    hostname = (parsed.hostname or "").lower()
    try:
        is_ip = int(ipaddress.ip_address(hostname) is not None)
    except ValueError:
        is_ip = 0

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port.") from exc

    feature_text = f"{hostname} {unquote(parsed.path)} {unquote(parsed.query)}"
    features = {
        "total_url_length": len(normalized_url),
        "domain_length": len(hostname),
        "num_dots": hostname.count("."),
        "num_hyphens": hostname.count("-"),
        "num_digits": sum(character.isdigit() for character in hostname),
        "num_special_chars": _count_special_characters(normalized_url),
        "num_subdomains": _count_subdomains(hostname),
        "has_ip_address": is_ip,
        "has_at_symbol": int("@" in normalized_url),
        "suspicious_keyword_count": _suspicious_keywords_in_url(feature_text),
        "is_https": int(parsed.scheme == "https"),
        "has_unusual_port": int(port is not None and port not in (80, 443)),
        "has_suspicious_encoding": int(_has_suspicious_encoding(normalized_url)),
        "has_misleading_hostname": int(_has_misleading_hostname(hostname)),
        "has_url_shortening_indicator": int(_has_shortening_indicator(hostname)),
    }
    return features


def feature_vector_from_dict(feature_map, feature_order=FEATURE_ORDER):
    values = []
    for name in feature_order:
        value = feature_map.get(name, 0)
        if isinstance(value, bool):
            value = int(value)
        values.append(float(value))
    return np.asarray(values, dtype=float).reshape(1, -1)
