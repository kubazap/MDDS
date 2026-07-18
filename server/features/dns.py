"""
features/dns.py

Ekstrakcja cech DNS: licznosci rekordow A/AAAA/MX/NS/TXT
oraz weryfikacja mechanizmow uwierzytelniania poczty SPF/DKIM/DMARC.

Brak rekordow DNS jest silnym sygnałem zloslwości; domeny phishingowe
rejestrowane krótko przed atakiem rzadko posiadaja skonfigurowana
infrastrukture pocztowa lub wpisy SPF/DMARC.
"""

_dns_cache:            dict = {}
_spf_dkim_dmarc_cache: dict = {}

try:
    import dns.resolver as _resolver
except ImportError:
    _resolver = None

# Typowe selektory DKIM sprawdzane podczas weryfikacji obecnosci rekordu
_DKIM_SELECTORS = (
    "default", "selector1", "selector2",
    "google", "k1", "s1", "s2", "mail", "dkim",
)


def get_dns_records(domain: str) -> dict:
    """
    Wyznacza licznosci rekordow DNS dla podanej domeny.

    Odpytywane typy: A, AAAA, MX, NS, TXT.
    Wyniki buforowane w _dns_cache per domena.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny.

    Returns
    -------
    dict
        Klucze: dns_a_count, dns_aaaa_count, dns_mx_count,
        dns_ns_count, dns_txt_count, ipv6_supported (bool), has_mx (bool).
    """
    if domain in _dns_cache:
        return _dns_cache[domain]

    out = {
        "dns_a_count":    0,
        "dns_aaaa_count": 0,
        "dns_mx_count":   0,
        "dns_ns_count":   0,
        "dns_txt_count":  0,
        "ipv6_supported": False,
        "has_mx":         False,
    }

    if _resolver is None:
        _dns_cache[domain] = out
        return out

    try:
        resolver          = _resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout  = 2.0

        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                ans = resolver.resolve(domain, rtype, raise_on_no_answer=False)
                if ans:
                    n = len(ans)
                    if   rtype == "A":    out["dns_a_count"]    = n
                    elif rtype == "AAAA": out["dns_aaaa_count"] = n; out["ipv6_supported"] = True
                    elif rtype == "MX":   out["dns_mx_count"]   = n; out["has_mx"]         = True
                    elif rtype == "NS":   out["dns_ns_count"]   = n
                    elif rtype == "TXT":  out["dns_txt_count"]  = n
            except Exception:
                pass
    except Exception:
        pass

    _dns_cache[domain] = out
    return out


def get_spf_dkim_dmarc(domain: str) -> dict:
    """
    Weryfikuje obecnosc rekordow SPF, DKIM i DMARC.

    SPF: rekord TXT zaczynajacy sie od "v=spf1".
    DMARC: rekord TXT poddomeny _dmarc.<domain> z prefixem "v=dmarc1".
    DKIM: rekord TXT <selector>._domainkey.<domain> z polem "v=dkim1" lub "k=".
    Sprawdzanych jest 9 typowych selektorow DKIM.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny.

    Returns
    -------
    dict
        Klucze: has_spf, has_dkim, has_dmarc (bool).
    """
    if domain in _spf_dkim_dmarc_cache:
        return _spf_dkim_dmarc_cache[domain]

    result = {"has_spf": False, "has_dkim": False, "has_dmarc": False}

    if _resolver is None:
        _spf_dkim_dmarc_cache[domain] = result
        return result

    try:
        resolver          = _resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout  = 2.0

        try:
            for r in resolver.resolve(domain, "TXT", raise_on_no_answer=False):
                if str(r).strip('"').lower().startswith("v=spf1"):
                    result["has_spf"] = True
                    break
        except Exception:
            pass

        try:
            for r in resolver.resolve(f"_dmarc.{domain}", "TXT", raise_on_no_answer=False):
                if str(r).strip('"').lower().startswith("v=dmarc1"):
                    result["has_dmarc"] = True
                    break
        except Exception:
            pass

        for selector in _DKIM_SELECTORS:
            try:
                for r in resolver.resolve(
                    f"{selector}._domainkey.{domain}", "TXT", raise_on_no_answer=False
                ):
                    content = str(r).strip('"').lower()
                    if "v=dkim1" in content or "k=" in content:
                        result["has_dkim"] = True
                        break
                if result["has_dkim"]:
                    break
            except Exception:
                continue

    except Exception:
        pass

    _spf_dkim_dmarc_cache[domain] = result
    return result


def clear_cache() -> None:
    """Czysci bufory _dns_cache i _spf_dkim_dmarc_cache."""
    _dns_cache.clear()
    _spf_dkim_dmarc_cache.clear()
