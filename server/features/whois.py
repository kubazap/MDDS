"""
features/whois.py

Ekstrakcja cech rejestracyjnych domeny z protokolu WHOIS.

domain_age_days jest najsilniejsza cecha predykcyjna modelu. Domeny phishingowe
sa zazwyczaj rejestrowane na krotko przed atakiem (wiek < 30 dni).
Brak danych WHOIS (whois_registered = False) stanowi rownie silny
sygnal zloslwości.
"""

import datetime
from functools import lru_cache

from config import TOP_REGISTRARS, TOP_COUNTRIES

try:
    import whois as _whois_lib
except ImportError:
    _whois_lib = None


@lru_cache(maxsize=512)
def cached_whois(domain: str):
    """
    Odpytuje serwer WHOIS z memoizacja wynikow (lru_cache, maxsize=512).

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny (str wymagany przez lru_cache).

    Returns
    -------
    obiekt whois lub None w przypadku bledu.
    """
    if _whois_lib is None or not isinstance(domain, str) or not domain:
        return None
    try:
        return _whois_lib.whois(domain)
    except Exception:
        return None


def normalize_registrar(registrar: str) -> str:
    """
    Normalizuje nazwe rejestratora do kategorii z TOP_REGISTRARS lub "Other".

    Domeny spoza listy otrzymuja etykiete "Other", cecha o wysokiej wartosci
    predykcyjnej dla klasy zlosliwej.

    Parameters
    ----------
    registrar : str
        Surowa nazwa rejestratora z rekordu WHOIS.

    Returns
    -------
    str
        Znormalizowana nazwa lub "Unknown" / "Other".
    """
    if not registrar or str(registrar).lower() in ("none", "unknown", ""):
        return "Unknown"
    reg_clean = registrar.lower().replace(".", "").replace(",", "").strip()
    for top in TOP_REGISTRARS:
        top_clean = top.lower().replace(".", "").replace(",", "").strip()
        if top_clean in reg_clean or reg_clean in top_clean:
            return top
    return "Other"


def normalize_country(country: str) -> str:
    """
    Normalizuje kod kraju ISO 3166-1 alfa-2 do kategorii z TOP_COUNTRIES lub "Other".

    Kraje spoza listy sa grupowane jako "Other", co redukuje przestrzen
    kategorii i ogranicza efekt rzadkich wartosci przy one-hot encoding.

    Parameters
    ----------
    country : str
        Dwuliterowy kod kraju z rekordu WHOIS.

    Returns
    -------
    str
        Znormalizowany kod lub "Unknown" / "Other".
    """
    if not country or str(country).lower() in ("none", "unknown", ""):
        return "Unknown"
    code = str(country).upper()[:2]
    return code if code in TOP_COUNTRIES else "Other"


def get_whois_features(domain: str) -> dict:
    """
    Wyznacza cechy rejestracyjne domeny na podstawie danych WHOIS.

    Oblicza wiek domeny wzgledem biezacej daty oraz liczbe dni
    do wygasniecia rejestracji.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny.

    Returns
    -------
    dict
        Klucze: whois_registrar_group (str), whois_country_group (str),
        domain_age_days (int), days_to_expire (int), whois_registered (bool).
        Wartosci -1 oznaczaja brak danych.
    """
    w = cached_whois(domain)

    if w is None:
        return {
            "whois_registrar_group": "Unknown",
            "whois_country_group":   "Unknown",
            "domain_age_days":       -1,
            "days_to_expire":        -1,
            "whois_registered":      False,
        }

    registrar = getattr(w, "registrar", None)
    if isinstance(registrar, (list, tuple)):
        registrar = registrar[0] if registrar else None
    registrar_group = normalize_registrar(str(registrar)) if registrar else "Unknown"

    country = getattr(w, "country", None)
    if isinstance(country, (list, tuple)):
        country = country[0] if country else None
    country_group = normalize_country(str(country)) if country else "Unknown"

    created = getattr(w, "creation_date", None)
    if isinstance(created, (list, tuple)):
        created = created[0] if created else None
    try:
        domain_age_days = max(
            0, (datetime.datetime.now().date() - created.date()).days
        ) if created and hasattr(created, "date") else -1
    except Exception:
        domain_age_days = -1

    expires = getattr(w, "expiration_date", None)
    if isinstance(expires, (list, tuple)):
        expires = expires[0] if expires else None
    try:
        days_to_expire = max(-365, min(3650, (
            expires.date() - datetime.datetime.now().date()
        ).days)) if expires and hasattr(expires, "date") else -1
    except Exception:
        days_to_expire = -1

    return {
        "whois_registrar_group": registrar_group,
        "whois_country_group":   country_group,
        "domain_age_days":       domain_age_days,
        "days_to_expire":        days_to_expire,
        "whois_registered":      created is not None,
    }


def clear_cache() -> None:
    """Czysci bufor memoizacji zapytan WHOIS."""
    cached_whois.cache_clear()
