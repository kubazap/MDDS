"""
features/http.py

Ekstrakcja cech HTTP: dostepnosc robots.txt i security.txt (RFC 9116)
oraz detekcja WAF/CDN na podstawie naglowkow odpowiedzi.

Odpowiedzi buforowane przez requests-cache w pliku http_cache.sqlite, 
co ogranicza liczbe zapytan do powtarzajacych
sie domen w ramach jednej sesji serwera.
"""

import requests
import requests_cache

from config import DEFAULT_SCHEME, GLOBAL_TIMEOUT, WAF_VENDOR_MAPPING, HTTP_CACHE_FILE

_robots_cache:   dict = {}
_security_cache: dict = {}
_headers_cache:  dict = {}

requests_cache.install_cache(HTTP_CACHE_FILE, backend="sqlite", expire_after=3600)

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; DomainClassifier/1.0)"})


def _build_url(domain: str, path: str) -> str:
    """Zwraca pelny URL z nazwy domeny i sciezki."""
    return f"{DEFAULT_SCHEME}://{domain}{path}"


def _fetch_text(url: str) -> tuple:
    """
    Wykonuje zadanie GET pod wskazany adres URL.

    Returns
    -------
    tuple
        (status_code, body) lub (None, '') przy bledzie polaczenia.
    """
    try:
        r = session.get(url, timeout=GLOBAL_TIMEOUT, allow_redirects=True)
        return r.status_code, (r.text or "")
    except Exception:
        return None, ""


def get_robots(domain: str) -> dict:
    """
    Sprawdza dostepnosc i zawartosc pliku robots.txt.

    Obecnosc dyrektyw Disallow jest posrednim sygnałem wiarygodnosci;
    domeny phishingowe rzadko utrzymuja kompletna konfiguracje serwerowa.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny.

    Returns
    -------
    dict
        Klucze: robots_status (int, kod HTTP lub -1), robots_has_disallow (bool).
    """
    if domain in _robots_cache:
        return _robots_cache[domain]
    status, text = _fetch_text(_build_url(domain, "/robots.txt"))
    result = {
        "robots_status":       status if status is not None else -1,
        "robots_has_disallow": ("disallow:" in text.lower()) if text else False,
    }
    _robots_cache[domain] = result
    return result


def get_security_txt(domain: str) -> dict:
    """
    Weryfikuje dostepnosc pliku security.txt (RFC 9116).

    Sprawdzane sciezki: /.well-known/security.txt, /security.txt.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny.

    Returns
    -------
    dict
        Klucze: security_present (bool), security_status (int, kod HTTP lub -1).
    """
    if domain in _security_cache:
        return _security_cache[domain]
    found = {"security_present": False, "security_status": -1}
    for path in ("/.well-known/security.txt", "/security.txt"):
        status, text = _fetch_text(_build_url(domain, path))
        if status and status < 400 and text:
            found = {"security_present": True, "security_status": status}
            break
        if found["security_status"] == -1 and status is not None:
            found["security_status"] = status
    _security_cache[domain] = found
    return found


def _get_http_headers(domain: str) -> dict:
    """
    Pobiera naglowki HTTP metoda HEAD z buforowaniem wynikow.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny.

    Returns
    -------
    dict
        Slownik naglowkow HTTP (klucze lowercase).
    """
    if domain in _headers_cache:
        return _headers_cache[domain]
    try:
        r = session.head(_build_url(domain, "/"), timeout=GLOBAL_TIMEOUT, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
    except Exception:
        headers = {}
    _headers_cache[domain] = headers
    return headers


def _normalize_waf_vendor(vendor: str) -> str:
    """
    Normalizuje sygnature WAF/CDN do nazwy dostawcy z WAF_VENDOR_MAPPING.

    Returns
    -------
    str
        Znormalizowana nazwa dostawcy, "None" lub "Other".
    """
    if not vendor or str(vendor).lower() in ("none", ""):
        return "None"
    vendor_lower = str(vendor).lower()
    for key, normalized in WAF_VENDOR_MAPPING.items():
        if key in vendor_lower:
            return normalized
    return "Other"


def get_waf_features(domain: str) -> dict:
    """
    Wykrywa obecnosc WAF/CDN na podstawie naglowkow HTTP.

    Analizowane: naglowek Server oraz klucze naglowkow specyficzne
    dla dostawcow.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny.

    Returns
    -------
    dict
        Klucze: has_waf (int 0/1), waf_vendor (str).
    """
    headers     = _get_http_headers(domain)
    server      = headers.get("server", "").lower()
    header_keys = " ".join(headers.keys()).lower()
    combined    = server + " " + header_keys

    waf = None
    for sig, name in WAF_VENDOR_MAPPING.items():
        if sig in combined:
            waf = name
            break

    normalized = _normalize_waf_vendor(waf) if waf else "None"
    return {
        "has_waf":    int(normalized not in ("None", "Other")),
        "waf_vendor": normalized,
    }


def clear_cache() -> None:
    """Czysci bufory _robots_cache, _security_cache, _headers_cache."""
    _robots_cache.clear()
    _security_cache.clear()
    _headers_cache.clear()
