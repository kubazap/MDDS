"""
features/lexical.py

Ekstrakcja cech leksykalnych nazwy domeny i kategoryzacja TLD.

Cechy wyznaczane wylacznie na podstawie ciagu znakow, bez zapytan
sieciowych. Istotne jako uzupelnienie przy klasyfikacji domen imitujacych 
marki (np. "secure-paypal-login.xyz").

Kategoryzacja TLD (get_domain_type) grupuje domeny w 6 klas:
com, net, org, edu, gov, other.
"""

import re
import math

import tldextract

from config import SUSPICIOUS_KEYWORDS, BRAND_KEYWORDS


def _shannon_entropy(s: str) -> float:
    """
    Oblicza entropie Shannona ciagu znakow [bity/znak].

    Wysoka entropia wskazuje na domeny generowane algorytmicznie (DGA).
    Zakres: 0 (jednorodny ciag) do log2(|alfabet|).

    Parameters
    ----------
    s : str

    Returns
    -------
    float
    """
    if not s:
        return 0.0
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _max_digit_run(s: str) -> int:
    """
    Wyznacza dlugosc najdluzszego ciagłego bloku cyfr.

    Parameters
    ----------
    s : str

    Returns
    -------
    int
    """
    best, cur = 0, 0
    for ch in s:
        if ch.isdigit():
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def get_lexical_features(domain: str) -> dict:
    """
    Wyznacza zbior cech leksykalnych nazwy domeny.

    Parameters
    ----------
    domain : str
        Pelna nazwa domeny (np. "secure-login-update.xyz").

    Returns
    -------
    dict
        Klucze:
        lex_length         liczba znakow nazwy domeny
        lex_digit_ratio    proporcja cyfr w nazwie [0, 1]
        lex_hyphen_count   liczba mysnikow
        lex_dot_count      liczba kropek (przyblizenie glebokosci subdomeny)
        lex_entropy        entropia Shannona [bity/znak]
        lex_max_digit_run  dlugosc najdluzszego bloku cyfr
        lex_has_suspicious 1 jesli nazwa zawiera token z SUSPICIOUS_KEYWORDS
        lex_has_brand_kw   1 jesli nazwa zawiera token z BRAND_KEYWORDS
    """
    d      = domain.lower()
    tokens = set(re.split(r"[.\-]", d))

    return {
        "lex_length":         len(d),
        "lex_digit_ratio":    sum(ch.isdigit() for ch in d) / max(len(d), 1),
        "lex_hyphen_count":   d.count("-"),
        "lex_dot_count":      d.count("."),
        "lex_entropy":        round(_shannon_entropy(d), 4),
        "lex_max_digit_run":  _max_digit_run(d),
        "lex_has_suspicious": int(bool(tokens & SUSPICIOUS_KEYWORDS)),
        "lex_has_brand_kw":   int(bool(tokens & BRAND_KEYWORDS)),
    }


def get_domain_type(domain: str) -> dict:
    """
    Kategoryzuje domene na podstawie sufiksu TLD.

    Klasy: com, net, org, edu, gov, other.
    TLD z klasy "other" (np. .xyz, .top) maja wyzszy udzial domen
    phishingowych w zbiorze treningowym niz .gov i .edu.

    Parameters
    ----------
    domain : str

    Returns
    -------
    dict
        Klucz: domain_type (str).
    """
    try:
        tld = tldextract.extract(str(domain)).suffix.lower()
    except Exception:
        tld = ""

    if tld.endswith(("edu", "ac")):    bucket = "edu"
    elif tld.endswith(("gov", "gob")): bucket = "gov"
    elif tld == "org":                 bucket = "org"
    elif tld == "com":                 bucket = "com"
    elif tld == "net":                 bucket = "net"
    else:                              bucket = "other"

    return {"domain_type": bucket}
