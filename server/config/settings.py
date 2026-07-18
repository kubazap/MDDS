"""
config/settings.py

Stale konfiguracyjne serwera MDDS.

Zawiera sciezki do zasobow modelu, parametry sieciowe oraz slowniki
normalizacyjne uzywane podczas ekstrakcji cech domenowych. Wartosci
empiryczne wyznaczono na podstawie zbioru malicious_phish.csv.
"""

import os

# Sciezki do plikow modelu
BASE_DIR          = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR        = os.path.join(BASE_DIR, "models")
MODEL_PATH        = os.path.join(MODELS_DIR, "model.pkl")
FEATURE_COLS_PATH = os.path.join(MODELS_DIR, "feature_columns.pkl")
META_PATH         = os.path.join(MODELS_DIR, "model_meta.json")
TRANCO_CACHE_FILE = os.path.join(MODELS_DIR, "tranco_top1m.csv")
CACHE_DIR         = os.path.join(BASE_DIR, "cache")
HTTP_CACHE_FILE   = os.path.join(CACHE_DIR, "http_cache")

# Parametry sieciowe
TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"  # aktualizacja tygodniowa
DEFAULT_SCHEME = "https"
GLOBAL_TIMEOUT = 5  # [s]

# Rejestratorzy o najwyzszej liczbie rejestracji wg ICANN 2023.
# Domeny spoza listy otrzymuja etykiete "Other".
TOP_REGISTRARS = {
    "MarkMonitor, Inc.",
    "CSC Corporate Domains, Inc.",
    "Network Solutions, LLC",
    "GoDaddy.com, LLC",
    "Namecheap, Inc.",
    "Cloudflare, Inc.",
    "PDR Ltd.",
    "Tucows Domains Inc.",
    "OVH SAS",
    "Hetzner Online GmbH",
    "Gandi SAS",
}

# Kody ISO 3166-1 alfa-2 krajow o najwyzszym ruchu i udziale w kampaniach
# phishingowych wg APWG eCrime 2023. Pozostale normalizowane do "Other".
TOP_COUNTRIES = {
    "US", "CN", "RU", "DE", "GB", "FR", "NL", "CA", "AU", "IN",
    "BR", "UA", "PL", "JP", "KR", "IT", "ES", "SE", "SG", "HK",
    "TR", "MX", "AR", "ZA", "NG",
}

# Mapowanie fragmentow naglowkow HTTP na znormalizowane nazwy dostawcow WAF/CDN.
WAF_VENDOR_MAPPING = {
    "cloudflare":       "Cloudflare",
    "cf-ray":           "Cloudflare",
    "akamai":           "Akamai",
    "akamaighost":      "Akamai",
    "edgesuite":        "Akamai",
    "imperva":          "Imperva",
    "incapsula":        "Imperva",
    "x-iinfo":          "Imperva",
    "sucuri":           "Sucuri",
    "x-sucuri":         "Sucuri",
    "f5":               "F5 BIG-IP",
    "big-ip":           "F5 BIG-IP",
    "bigip":            "F5 BIG-IP",
    "fortiweb":         "Fortinet",
    "fortinet":         "Fortinet",
    "ddos-guard":       "DDoS-Guard",
    "qrator":           "Qrator",
    "aws":              "AWS",
    "amazon":           "AWS",
    "cloudfront":       "AWS CloudFront",
    "awselb":           "AWS",
    "azure":            "Azure",
    "microsoft-azure":  "Azure",
    "fastly":           "Fastly",
    "nginx":            "Nginx",
    "apache":           "Apache",
    "gfe":              "Google CDN",
    "google frontend":  "Google CDN",
    "varnish":          "Varnish",
    "barracuda":        "Barracuda",
}

# Tokeny leksykalne czeste w domenach phishingowych.
SUSPICIOUS_KEYWORDS = {
    "secure", "login", "verify", "verification", "account", "update",
    "bank", "wallet", "recover", "recovery", "password", "signin",
    "confirm", "alert", "free", "win", "prize", "click", "support",
    "help", "service", "online", "web", "portal", "access",
}

# Nazwy marek najczesciej imitowanych w atakach phishingowych
# wg raportow APWG 2022-2023; uzywane jako cechy binarne lex_has_brand_kw.
BRAND_KEYWORDS = {
    "paypal", "google", "apple", "amazon", "microsoft", "facebook",
    "instagram", "twitter", "netflix", "ebay", "dhl", "fedex",
    "wellsfargo", "chase", "citibank", "bankofamerica", "hsbc",
}

# Lista SLD referencyjnych marek dla obliczania odleglosci Levenshteina
# przy detekcji typosquattingu.
BRAND_NAMES = [
    "paypal", "google", "apple", "amazon", "microsoft", "facebook",
    "instagram", "twitter", "netflix", "ebay", "dropbox", "linkedin",
    "dhl", "fedex", "wellsfargo", "chase", "citibank", "bankofamerica",
    "hsbc", "allegro", "olx", "santander", "pko", "mbank",
]
