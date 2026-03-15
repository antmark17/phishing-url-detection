import re
import sys
import math
import csv
import ipaddress
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

import tldextract

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update",
    "bank", "signin", "confirm", "password", "paypal",
    "free", "bonus", "unlock", "webscr", "security",
    "billing", "support", "recover", "wallet", "authentication"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "pw", "cc", "click", "link", "work",
    "gq", "tk", "ml", "ga", "cf", "rest", "fit", "buzz"
}

SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
    "shorte.st", "tiny.cc", "lnkd.in"
}

KNOWN_BRANDS = [
    "google", "apple", "microsoft", "amazon", "paypal",
    "facebook", "instagram", "netflix", "bankofamerica",
    "dropbox", "linkedin", "github", "outlook", "whatsapp"
]

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = BASE_DIR / "data" / "output" / "features.csv"


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "http://" + url
    return url


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.hostname)
    except Exception:
        return False


def decode_url(url: str) -> str:
    return unquote(url)


def count_digits(text: str) -> int:
    return sum(ch.isdigit() for ch in text)


def count_letters(text: str) -> int:
    return sum(ch.isalpha() for ch in text)


def count_special_chars(text: str) -> int:
    return sum(not ch.isalnum() for ch in text)


def count_vowels(text: str) -> int:
    return sum(ch.lower() in "aeiou" for ch in text if ch.isalpha())


def count_consonants(text: str) -> int:
    return sum(ch.isalpha() and ch.lower() not in "aeiou" for ch in text)


def safe_ratio(num: int, den: int) -> float:
    return 0.0 if den == 0 else num / den


def vowel_consonant_ratio(text: str) -> float:
    vowels = count_vowels(text)
    consonants = count_consonants(text)
    return 0.0 if consonants == 0 else vowels / consonants


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0

    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    length = len(text)

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def longest_token_length(text: str) -> int:
    if not text:
        return 0

    tokens = re.split(r"[\/\.\-\_\?\=\&]+", text)
    tokens = [token for token in tokens if token]
    return max((len(token) for token in tokens), default=0)


def get_query_param_count(query: str) -> int:
    if not query:
        return 0
    return len(parse_qs(query, keep_blank_values=True))


def has_ip_address(hostname: str) -> int:
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def has_punycode(hostname: str) -> int:
    return int(bool(hostname) and "xn--" in hostname.lower())


def get_subdomain_count(subdomain: str) -> int:
    if not subdomain:
        return 0
    return len([part for part in subdomain.split(".") if part])


def has_double_slash_in_path(path: str) -> int:
    return int(bool(path) and "//" in path)


def count_double_slashes(path: str) -> int:
    return path.count("//") if path else 0


def normalize_hostname_for_lookup(hostname: str) -> str:
    hostname = (hostname or "").lower().strip()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def is_shortened_url(hostname: str) -> int:
    normalized = normalize_hostname_for_lookup(hostname)
    return int(normalized in SHORTENING_SERVICES)


def has_suspicious_tld(suffix: str) -> int:
    if not suffix:
        return 0
    last_part = suffix.lower().split(".")[-1]
    return int(last_part in SUSPICIOUS_TLDS)


def has_non_standard_port(parsed) -> int:
    if parsed.port is None:
        return 0

    scheme = parsed.scheme.lower()

    if scheme == "http" and parsed.port == 80:
        return 0
    if scheme == "https" and parsed.port == 443:
        return 0

    return 1


def count_suspicious_words(url: str) -> int:
    lowered = decode_url(url).lower()
    return sum(1 for word in SUSPICIOUS_WORDS if word in lowered)


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

    for i in range(len(a) + 1):
        dp[i][0] = i
    for j in range(len(b) + 1):
        dp[0][j] = j

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            )

    return dp[len(a)][len(b)]


def closest_brand_distance(domain: str) -> tuple[str, int]:
    if not domain:
        return "", 999

    best_brand = ""
    best_distance = 999

    for brand in KNOWN_BRANDS:
        dist = levenshtein_distance(domain.lower(), brand.lower())
        if dist < best_distance:
            best_distance = dist
            best_brand = brand

    return best_brand, best_distance


def extract_url_features(url: str) -> dict:
    normalized_url = normalize_url(url)

    if not is_valid_url(normalized_url):
        raise ValueError("Invalid URL")

    parsed = urlparse(normalized_url)
    ext = tldextract.extract(normalized_url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    domain = (ext.domain or "").lower()
    suffix = (ext.suffix or "").lower()
    subdomain = (ext.subdomain or "").lower()

    decoded = decode_url(normalized_url).lower()

    digit_count_url = count_digits(normalized_url)
    letter_count_url = count_letters(normalized_url)
    special_count_url = count_special_chars(normalized_url)

    digit_count_host = count_digits(hostname)
    letter_count_host = count_letters(hostname)
    special_count_host = count_special_chars(hostname)

    digit_count_path = count_digits(path)
    letter_count_path = count_letters(path)
    special_count_path = count_special_chars(path)

    query_param_count = get_query_param_count(query)

    closest_brand, min_brand_distance = closest_brand_distance(domain)
    is_typosquatting_candidate = int(
        min_brand_distance <= 2 and domain not in KNOWN_BRANDS
    )

    features = {
        "original_url": url,
        "normalized_url": normalized_url,

        "url_length": len(normalized_url),
        "hostname_length": len(hostname),
        "domain_length": len(domain),
        "suffix_length": len(suffix),
        "subdomain_length": len(subdomain),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "path_depth": len([part for part in path.split("/") if part]),
        "subdomain_count": get_subdomain_count(subdomain),

        "is_ip": has_ip_address(hostname),
        "has_non_standard_port": has_non_standard_port(parsed),
        "has_suspicious_tld": has_suspicious_tld(suffix),
        "is_shortened": is_shortened_url(hostname),

        "digit_count_url": digit_count_url,
        "letter_count_url": letter_count_url,
        "special_count_url": special_count_url,
        "digit_ratio_url": round(safe_ratio(digit_count_url, len(normalized_url)), 6),
        "letter_ratio_url": round(safe_ratio(letter_count_url, len(normalized_url)), 6),
        "special_ratio_url": round(safe_ratio(special_count_url, len(normalized_url)), 6),

        "digit_count_host": digit_count_host,
        "letter_count_host": letter_count_host,
        "special_count_host": special_count_host,

        "digit_count_path": digit_count_path,
        "letter_count_path": letter_count_path,
        "special_count_path": special_count_path,

        "count_dots": normalized_url.count("."),
        "count_hyphens": normalized_url.count("-"),
        "count_underscores": normalized_url.count("_"),
        "count_slashes": normalized_url.count("/"),
        "count_questionmarks": normalized_url.count("?"),
        "count_ampersands": normalized_url.count("&"),
        "count_equals": normalized_url.count("="),
        "count_percent": normalized_url.count("%"),
        "count_at_symbol": normalized_url.count("@"),

        "has_at_symbol": int("@" in normalized_url),
        "has_double_slash_path": has_double_slash_in_path(path),
        "count_double_slashes": count_double_slashes(path),
        "has_fragment": int(bool(fragment)),
        "uses_http": int(parsed.scheme.lower() == "http"),
        "uses_https": int(parsed.scheme.lower() == "https"),

        "suspicious_words_count": count_suspicious_words(normalized_url),
        "has_punycode": has_punycode(hostname),
        "min_levenshtein_to_brand": min_brand_distance,
        "is_typosquatting_candidate": is_typosquatting_candidate,

        "url_entropy": round(shannon_entropy(normalized_url), 6),
        "domain_entropy": round(shannon_entropy(domain), 6),
        "hostname_entropy": round(shannon_entropy(hostname), 6),
        "longest_word_length": longest_token_length(normalized_url),
        "longest_path_token_length": longest_token_length(path.lower()),
        "longest_query_token_length": longest_token_length(query.lower()),
        "domain_vowel_count": count_vowels(domain),
        "domain_consonant_count": count_consonants(domain),
        "domain_vowel_consonant_ratio": round(vowel_consonant_ratio(domain), 6),

        "query_param_count": query_param_count,
        "decoded_url_length": len(decoded),

        # utile per debug/analisi esplorativa
        "closest_brand": closest_brand,
    }

    for word in SUSPICIOUS_WORDS:
        features[f"sw_{word}"] = int(word in decoded)

    return features


def build_dataset_row(url: str, label: int) -> dict:
    if label not in (0, 1):
        raise ValueError("Label must be 0 or 1")

    features = extract_url_features(url)
    row = {"label": label, **features}
    return row


def get_csv_columns() -> list[str]:
    base_columns = [
        "label",
        "original_url",
        "normalized_url",

        "url_length",
        "hostname_length",
        "domain_length",
        "suffix_length",
        "subdomain_length",
        "path_length",
        "query_length",
        "fragment_length",
        "path_depth",
        "subdomain_count",

        "is_ip",
        "has_non_standard_port",
        "has_suspicious_tld",
        "is_shortened",

        "digit_count_url",
        "letter_count_url",
        "special_count_url",
        "digit_ratio_url",
        "letter_ratio_url",
        "special_ratio_url",

        "digit_count_host",
        "letter_count_host",
        "special_count_host",

        "digit_count_path",
        "letter_count_path",
        "special_count_path",

        "count_dots",
        "count_hyphens",
        "count_underscores",
        "count_slashes",
        "count_questionmarks",
        "count_ampersands",
        "count_equals",
        "count_percent",
        "count_at_symbol",

        "has_at_symbol",
        "has_double_slash_path",
        "count_double_slashes",
        "has_fragment",
        "uses_http",
        "uses_https",

        "suspicious_words_count",
        "has_punycode",
        "min_levenshtein_to_brand",
        "is_typosquatting_candidate",

        "url_entropy",
        "domain_entropy",
        "hostname_entropy",
        "longest_word_length",
        "longest_path_token_length",
        "longest_query_token_length",
        "domain_vowel_count",
        "domain_consonant_count",
        "domain_vowel_consonant_ratio",

        "query_param_count",
        "decoded_url_length",
        "closest_brand",
    ]

    suspicious_word_columns = [f"sw_{word}" for word in SUSPICIOUS_WORDS]
    return base_columns + suspicious_word_columns


def save_features_to_csv(row: dict, filename: Path = OUTPUT_FILE) -> None:
    file_path = Path(filename)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    columns = get_csv_columns()
    write_header = not file_path.exists() or file_path.stat().st_size == 0

    with open(file_path, "a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=columns, extrasaction="ignore")

        if write_header:
            writer.writeheader()

        writer.writerow(row)


def main() -> int:
    try:
        raw_url = sys.argv[1]
        label = int(sys.argv[2])

        row = build_dataset_row(raw_url, label)
        save_features_to_csv(row, OUTPUT_FILE)

        print(f"[OK] Features extracted and saved to {OUTPUT_FILE}")
        return 0

    except IndexError:
        print("[ERROR FEATURE] MISSING URL OR LABEL")
        print("Usage: python feature_extractor.py <url> <label>")
        return -1

    except ValueError as e:
        print(f"[ERROR FEATURE] {e}")
        return 1

    except Exception as e:
        print(f"[ERROR FEATURE] Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())