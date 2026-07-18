"""
features/url.py

Ekstrakcja cech strukturalnych pelnego adresu URL.

Modul operuje wylacznie na ciagu znakow URL, bez zapytan sieciowych.
Zlosliwe adresy URL wykazuja tendencje do wiekszej glebokosci sciezki,
wyzszej liczby parametrow GET i obecnosci sekwencji procentowych
uzywanych do zaciemnienia tresci.
"""

import re
from urllib.parse import urlparse, parse_qs


def get_url_features(url: str) -> dict:
    """
    Wyznacza cechy strukturalne pelnego adresu URL.

    Parameters
    ----------
    url : str
        Pelny adres URL poddawany analizie.

    Returns
    -------
    dict
        Klucze:
        url_length           liczba znakow URL
        url_path_depth       liczba niepustych segmentow sciezki
        url_param_count      liczba unikalnych parametrow GET
        url_has_double_slash 1 jesli URL zawiera '//' poza schematem
        url_pct_encoded      liczba sekwencji procentowych (%XX)
        url_subdomain_count  liczba poziomow subdomeny powyzej SLD
    """
    try:
        p     = urlparse(url if "://" in url else "http://" + url)
        host  = p.hostname or ""
        path  = p.path or ""
        query = p.query or ""

        # Wykrywanie '//' poza czescia schematu protokolu
        after_scheme     = url.split("//", 1)[-1] if "//" in url else url
        has_double_slash = int("//" in after_scheme)

        depth  = len([s for s in path.split("/") if s])
        params = len(parse_qs(query))
        pct    = len(re.findall(r"%[0-9a-fA-F]{2}", url))

        # lstrip("www.") usuwa kazdy znak ze zbioru {'w','.'}, stad startswith
        clean_host      = re.sub(r"^www\.", "", host)
        subdomain_count = max(0, clean_host.count(".") - 1)

        return {
            "url_length":           len(url),
            "url_path_depth":       depth,
            "url_param_count":      params,
            "url_has_double_slash": has_double_slash,
            "url_pct_encoded":      pct,
            "url_subdomain_count":  subdomain_count,
        }
    except Exception:
        return {
            "url_length": 0, "url_path_depth": 0, "url_param_count": 0,
            "url_has_double_slash": 0, "url_pct_encoded": 0, "url_subdomain_count": 0,
        }
