import pytest

from feature_extraction import extract_url_features, validate_url


@pytest.mark.parametrize(
    ("submitted", "expected"),
    [
        ("https://www.google.com", "https://www.google.com"),
        ("www.example.com", "https://www.example.com"),
        ("example.com:8443/path", "https://example.com:8443/path"),
        ("https://bücher.de", "https://xn--bcher-kva.de"),
        ("http://[2001:db8::1]:8080/path", "http://[2001:db8::1]:8080/path"),
    ],
)
def test_valid_url_normalization(submitted, expected):
    assert validate_url(submitted) == expected


@pytest.mark.parametrize(
    "submitted",
    [
        "",
        "   ",
        "not a valid url",
        "ftp://example.com",
        "http:example.com",
        "https:///missing-host",
        "https://example..com",
        "https://-bad.example.com",
        "https://example.com:99999",
        "https://example.com:",
        "https://example.com/%GG",
        "https://user:password@example.com/",
        "https://[invalid-ipv6]/",
    ],
)
def test_invalid_url_is_rejected(submitted):
    with pytest.raises(ValueError):
        validate_url(submitted)


def test_ip_address_and_port_features():
    features = extract_url_features("http://185.234.72.5:8080/login.php")
    assert features["has_ip_address"] == 1
    assert features["has_unusual_port"] == 1


def test_path_hostname_does_not_override_actual_hostname():
    features = extract_url_features("https://example.com/185.234.72.5/login")
    assert features["has_ip_address"] == 0
    assert features["domain_length"] == len("example.com")


def test_suspicious_keywords_are_token_matched():
    suspicious = extract_url_features("https://example.com/account/login")
    unrelated_substrings = extract_url_features("https://loginside.example.com")
    assert suspicious["suspicious_keyword_count"] == 2
    assert unrelated_substrings["suspicious_keyword_count"] == 0


def test_shortening_domains_require_hostname_boundary():
    actual_shortener = extract_url_features("https://sub.bit.ly/path")
    misleading_substring = extract_url_features("https://notbit.ly.example.com/path")
    assert actual_shortener["has_url_shortening_indicator"] == 1
    assert misleading_substring["has_url_shortening_indicator"] == 0


def test_unicode_and_encoded_url_features():
    features = extract_url_features("https://bücher.de/path%2Flogin")
    assert features["domain_length"] == len("xn--bcher-kva.de")
    assert features["has_suspicious_encoding"] == 1
    assert features["suspicious_keyword_count"] == 1
