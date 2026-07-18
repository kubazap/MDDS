"""
src/api/router.py

Warstwa HTTP serwera MDDS: definicje endpointów, walidacja parametrów,
buforowanie wyników klasyfikacji i kompozycja odpowiedzi JSON.

GET /health       stan serwera i załadowanych zasobów
GET /classify     klasyfikacja domeny z pomiarami czasu ekstrakcji per moduł
GET /cache/clear  czyszczenie buforów wyników i cech sieciowych
"""

import time
from collections import OrderedDict

from fastapi import APIRouter, Query, HTTPException

import src.core.classifier as classifier
import features.dns        as _dns
import features.whois      as _whois
import features.http       as _http
import features.tranco     as _tranco

from features.dns         import get_dns_records, get_spf_dkim_dmarc
from features.whois       import get_whois_features
from features.http        import get_robots, get_security_txt, get_waf_features
from features.lexical     import get_lexical_features, get_domain_type
from features.levenshtein import get_levenshtein_features
from features.url         import get_url_features
from features.tranco      import get_tranco_features

router = APIRouter()

_DEFAULT_URL_FEATURES = {
    "url_length": 0, "url_path_depth": 0, "url_param_count": 0,
    "url_has_double_slash": 0, "url_pct_encoded": 0, "url_subdomain_count": 0,
}

# Podzbiór cech dołączanych do odpowiedzi /classify.
_DETAIL_KEYS = [
    "domain_age_days", "days_to_expire",
    "tranco_rank", "tranco_in_top1m", "tranco_in_top10k",
    "whois_registrar_group", "whois_country_group", "whois_registered",
    "has_spf", "has_dkim", "has_dmarc",
    "has_waf", "waf_vendor",
    "lev_min_dist", "lev_is_typosquat",
    "dns_a_count", "dns_mx_count", "dns_ns_count",
    "robots_status", "security_present",
]

# Bufor wyników klasyfikacji — LRU z limitem 10 000 wpisów.
# Zapobiega niekontrolowanemu wzrostowi pamięci przy długich sesjach serwera.
_CACHE_MAX = 10_000


class _LRUCache:
    """Prosty bufor LRU oparty na OrderedDict — thread-safe dla jednego workera."""

    def __init__(self, maxsize: int = _CACHE_MAX):
        self._data    = OrderedDict()
        self._maxsize = maxsize

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __getitem__(self, key: str):
        self._data.move_to_end(key)
        return self._data[key]

    def __setitem__(self, key: str, value) -> None:
        if key in self._data:
            self._data.move_to_end(key)
        self._data[key] = value
        if len(self._data) > self._maxsize:
            self._data.popitem(last=False)

    def copy_item(self, key: str) -> dict:
        return self[key].copy()

    def clear(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


_result_cache = _LRUCache(maxsize=_CACHE_MAX)


def _gather_with_timings(domain: str, url: str) -> tuple[dict, dict]:
    """
    Wykonuje ekstrakcję cech z pomiarem czasu per moduł.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny.
    url : str
        Pełny adres URL (opcjonalny).

    Returns
    -------
    tuple[dict, dict]
        (features, timings_ms) — słownik cech i słownik czasów w ms.
    """
    out      = {"domain": domain}
    timings  = {}

    def _t(key: str, fn, *args, **kwargs):
        t0          = time.perf_counter()
        result      = fn(*args, **kwargs)
        timings[key] = round((time.perf_counter() - t0) * 1000, 2)
        return result

    # Grupa 1 + 2: DNS i SPF/DKIM/DMARC — jeden moduł sieciowy
    dns_info = _t("dns", get_dns_records, domain)
    out["dns_a_count"]    = dns_info.get("dns_a_count",    0)
    out["dns_aaaa_count"] = dns_info.get("dns_aaaa_count", 0)
    out["dns_mx_count"]   = dns_info.get("dns_mx_count",   0)
    out["dns_ns_count"]   = dns_info.get("dns_ns_count",   0)
    out["dns_txt_count"]  = dns_info.get("dns_txt_count",  0)
    out["ipv6_supported"] = dns_info.get("ipv6_supported", False)
    out["has_mx"]         = dns_info.get("has_mx",         False)

    sec = _t("spf_dkim_dmarc", get_spf_dkim_dmarc, domain)
    out["has_spf"]   = sec.get("has_spf",   False)
    out["has_dkim"]  = sec.get("has_dkim",  False)
    out["has_dmarc"] = sec.get("has_dmarc", False)

    # Grupa 3: WHOIS
    out.update(_t("whois", get_whois_features, domain))

    # Grupa 4: HTTP
    t0 = time.perf_counter()
    out.update(get_robots(domain))
    out.update(get_security_txt(domain))
    out.update(get_waf_features(domain))
    timings["http"] = round((time.perf_counter() - t0) * 1000, 2)

    # Grupy 5–7: lokalne (TLD, leksykalne, Levenshtein, URL)
    t0 = time.perf_counter()
    out.update(get_domain_type(domain))
    out.update(get_lexical_features(domain))
    out.update(get_levenshtein_features(domain))
    out.update(get_url_features(url) if url else _DEFAULT_URL_FEATURES)
    timings["lex_url_lev"] = round((time.perf_counter() - t0) * 1000, 2)

    # Grupa 9: Tranco
    out.update(_t("tranco", get_tranco_features, domain))

    # Cechy pochodne — wyznaczane PO DNS i WHOIS
    out["dns_resolves"]    = int(out.get("dns_a_count", 0) > 0)
    out["whois_age_known"] = int(out.get("domain_age_days", -1) >= 0)

    return out, timings


@router.get("/health")
def health():
    """
    Zwraca stan serwera i załadowanych zasobów.

    Returns
    -------
    dict
        Typ modelu, liczba cech, liczba wpisów Tranco, rozmiar bufora,
        metadane eksperymentu.
    """
    return {
        "status":        "ok",
        "model":         type(classifier.model).__name__ if classifier.model else None,
        "feature_count": len(classifier.feature_cols),
        "tranco_loaded": len(_tranco.TRANCO_RANKING),
        "cache_size":    len(_result_cache),
        "meta":          classifier.model_meta or {},
    }


@router.get("/classify")
def classify(
    domain: str  = Query(...,   description="Nazwa domeny, np. 'example.com'"),
    url:    str  = Query("",    description="Pełny adres URL (opcjonalny)"),
    force:  bool = Query(False, description="Pomiń bufor i wykonaj ponowną klasyfikację"),
):
    """
    Klasyfikuje domenę jako BEZPIECZNA lub ZLOSLIWA.

    Wywołuje potok ekstrakcji 38 cech z pomiarem czasu per moduł,
    a następnie predykcję modelu. Wyniki są buforowane per (domain, url);
    force=True wymusza ponowną analizę.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny (bez prefiksu www. i schematu).
    url : str
        Pełny adres URL; jeśli podany, obliczane są cechy struktury URL.
    force : bool
        Jeśli True, bufor jest pomijany.

    Returns
    -------
    dict
        Pola: domain, url, klasyfikacja, p_malicious, p_benign,
        cached, elapsed_ms, timings_ms oraz podzbiór cech infrastrukturalnych.

    Raises
    ------
    HTTPException 503
        Model nie został załadowany.
    HTTPException 400
        Nieprawidłowy format nazwy domeny.
    """
    if classifier.model is None:
        raise HTTPException(status_code=503, detail="Model klasyfikacyjny nie jest załadowany.")

    # Normalizacja wejścia
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Nieprawidłowa nazwa domeny.")

    # Trafienie w bufor
    cache_key = f"{domain}||{url}"
    if not force and cache_key in _result_cache:
        result           = _result_cache.copy_item(cache_key)
        result["cached"] = True
        return result

    # Ekstrakcja cech z pomiarami czasu
    t_total  = time.perf_counter()
    features, timings = _gather_with_timings(domain, url)

    # Predykcja
    t0               = time.perf_counter()
    result           = classifier.predict(features)
    timings["model"] = round((time.perf_counter() - t0) * 1000, 2)

    timings["total_ms"] = round((time.perf_counter() - t_total) * 1000, 2)

    result.update({k: features.get(k) for k in _DETAIL_KEYS})
    result.update({
        "domain":      domain,
        "url":         url,
        "cached":      False,
        "timings_ms":  timings,
    })
    result.update({
        "debug_features": {k: features.get(k) for k in classifier.feature_cols}
    })

    _result_cache[cache_key] = result
    return result


@router.get("/cache/clear")
def cache_clear():
    """
    Czyści bufor wyników i bufory cech sieciowych (DNS, WHOIS, HTTP).

    Returns
    -------
    dict
        Potwierdzenie operacji.
    """
    _result_cache.clear()
    _dns.clear_cache()
    _whois.clear_cache()
    _http.clear_cache()
    return {"status": "ok", "message": "Wszystkie bufory zostały wyczyszczone."}