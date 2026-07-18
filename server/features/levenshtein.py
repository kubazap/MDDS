"""
features/levenshtein.py

Detekcja typosquattingu metoda odleglosci edycyjnej Levenshteina.

Minimalna odleglosc Levenshteina miedzy SLD analizowanej domeny
a lista BRAND_NAMES stanowi ceche ciagla lev_min_dist, uzupelniona
binarna flaga lev_is_typosquat dla odleglosci w przedziale [1, 2].
"""

import tldextract

from config import BRAND_NAMES

try:
    import Levenshtein as _lev
    _lev_distance = _lev.distance
except ImportError:
    def _lev_distance(a: str, b: str) -> int:
        """Odleglosc Levenshteina metoda programowania dynamicznego."""
        m, n = len(a), len(b)
        dp = list(range(n + 1))
        for i in range(1, m + 1):
            prev = dp[:]
            dp[0] = i
            for j in range(1, n + 1):
                dp[j] = (
                    prev[j - 1] if a[i - 1] == b[j - 1]
                    else 1 + min(prev[j], dp[j - 1], prev[j - 1])
                )
        return dp[n]


def get_levenshtein_features(domain: str) -> dict:
    """
    Oblicza minimalna odleglosc edycyjna SLD domeny od listy BRAND_NAMES.

    Parameters
    ----------
    domain : str
        Nazwa domeny poddawana analizie (np. "paypa1.com").

    Returns
    -------
    dict
        Klucze:
        lev_min_dist     minimalna odleglosc Levenshteina (0 = identycznosc)
        lev_is_typosquat 1 jesli lev_min_dist w [1, 2], 0 w pozostalych przypadkach
    """
    try:
        sld = tldextract.extract(domain).domain.lower()
        if not sld:
            return {"lev_min_dist": 99, "lev_is_typosquat": 0}
        min_dist = min(_lev_distance(sld, brand) for brand in BRAND_NAMES)
        return {
            "lev_min_dist":     min_dist,
            "lev_is_typosquat": int(1 <= min_dist <= 2),
        }
    except Exception:
        return {"lev_min_dist": 99, "lev_is_typosquat": 0}
