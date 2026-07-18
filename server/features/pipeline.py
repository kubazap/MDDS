"""
features/pipeline.py

Potok ekstrakcji cech domenowych.

gather_domain_features() agreguje wyniki wszystkich modulow ekstrakcji
w jednorodny slownik 38 cech wejsciowych modelu klasyfikacyjnego.

Kolejnosc grup cech:
DNS -> SPF/DKIM/DMARC -> WHOIS -> HTTP -> TLD -> Leksykalne -> Levenshtein
-> URL -> Tranco.
"""

from features.dns         import get_dns_records, get_spf_dkim_dmarc
from features.whois       import get_whois_features
from features.http        import get_robots, get_security_txt, get_waf_features
from features.lexical     import get_lexical_features, get_domain_type
from features.levenshtein import get_levenshtein_features
from features.url         import get_url_features
from features.tranco      import get_tranco_features

# Wartosci domyslne cech URL stosowane gdy parametr url nie zostal przekazany
_DEFAULT_URL_FEATURES = {
    "url_length": 0, "url_path_depth": 0, "url_param_count": 0,
    "url_has_double_slash": 0, "url_pct_encoded": 0, "url_subdomain_count": 0,
}


def gather_domain_features(domain: str, url: str = "") -> dict:
    """
    Agreguje cechy infrastrukturalne i leksykalne dla podanej domeny.

    Parameters
    ----------
    domain : str
        Znormalizowana nazwa domeny (bez prefiksu www. i schematu).
    url : str, optional
        Pelny adres URL; jesli podany, obliczane sa cechy struktury URL.
        W przeciwnym razie cechy URL przyjmuja wartosc 0.

    Returns
    -------
    dict
        Slownik 38 cech gotowy do przeksztalcenia w wiersz DataFrame.
    """
    out = {"domain": domain}

    # Grupa 1: rekordy DNS
    dns_info = get_dns_records(domain)
    out["dns_a_count"]    = dns_info.get("dns_a_count",    0)
    out["dns_aaaa_count"] = dns_info.get("dns_aaaa_count", 0)
    out["dns_mx_count"]   = dns_info.get("dns_mx_count",   0)
    out["dns_ns_count"]   = dns_info.get("dns_ns_count",   0)
    out["dns_txt_count"]  = dns_info.get("dns_txt_count",  0)
    out["ipv6_supported"] = dns_info.get("ipv6_supported", False)
    out["has_mx"]         = dns_info.get("has_mx",         False)

    # Grupa 2: uwierzytelnianie poczty SPF/DKIM/DMARC
    sec = get_spf_dkim_dmarc(domain)
    out["has_spf"]   = sec.get("has_spf",   False)
    out["has_dkim"]  = sec.get("has_dkim",  False)
    out["has_dmarc"] = sec.get("has_dmarc", False)

    # Grupa 3: dane rejestracyjne WHOIS
    out.update(get_whois_features(domain))

    # Grupa 4: zasoby HTTP (robots.txt, security.txt, WAF/CDN)
    out.update(get_robots(domain))
    out.update(get_security_txt(domain))
    out.update(get_waf_features(domain))

    # Grupa 5: kategoryzacja TLD
    out.update(get_domain_type(domain))

    # Grupa 6: cechy leksykalne
    out.update(get_lexical_features(domain))

    # Grupa 7: odleglosc Levenshteina (detekcja typosquattingu)
    out.update(get_levenshtein_features(domain))

    # Grupa 8: cechy strukturalne URL (opcjonalne)
    out.update(get_url_features(url) if url else _DEFAULT_URL_FEATURES)

    # Grupa 9: ranking popularnosci Tranco
    out.update(get_tranco_features(domain))

    # Cechy pochodne wyznaczane po DNS i WHOIS, nie wymagają zapytań sieciowych.
    out["dns_resolves"]    = int(out.get("dns_a_count", 0) > 0)
    out["whois_age_known"] = int(out.get("domain_age_days", -1) >= 0)

    return out
