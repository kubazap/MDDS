"""
features/tranco.py

Ekstrakcja cech popularnosci domeny z listy Tranco Top 1M.

Tranco to tygodniowo aktualizowany ranking agregujacy dane 
z list Alexa, Majestic, Umbrella i Quantcast.
Domeny zlosliwe praktycznie nie figuruja w rankingu Tranco.
"""

import os
import io
import zipfile
import urllib.request

import tldextract

from config import TRANCO_CACHE_FILE, TRANCO_ZIP_URL

# Slownik rankingowy {nazwa_domeny: pozycja} ladowany jednorazowo przy starcie
TRANCO_RANKING: dict = {}


def load_tranco(cache_path: str = TRANCO_CACHE_FILE) -> dict:
    """
    Laduje liste Tranco do slownika {domena: pozycja}.

    Jezeli lokalny plik CSV istnieje, jest wczytywany bezposrednio.
    W przeciwnym razie archiwum ZIP pobierane jest z TRANCO_ZIP_URL
    i zapisywane lokalnie na potrzeby kolejnych sesji.

    Parameters
    ----------
    cache_path : str
        Sciezka do lokalnego pliku CSV z lista Tranco.

    Returns
    -------
    dict
        {domena (str): pozycja (int, 1-based)}.
        Pusty slownik przy bledzie pobierania.
    """
    if not os.path.exists(cache_path):
        print(f"Pobieranie listy Tranco z {TRANCO_ZIP_URL}...")
        try:
            with urllib.request.urlopen(TRANCO_ZIP_URL, timeout=30) as resp:
                raw = resp.read()
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                csv_name = zf.namelist()[0]
                with zf.open(csv_name) as f:
                    content = f.read().decode("utf-8")
            with open(cache_path, "w") as out:
                out.write(content)
            print(f"Lista Tranco zapisana lokalnie: {cache_path}")
        except Exception as e:
            print(f"UWAGA: Nie udalo sie pobrac listy Tranco: {e}")
            print("Cechy tranco_rank i tranco_in_top1m przyjma wartosc 0.")
            return {}

    ranking: dict = {}
    with open(cache_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",", 1)
            if len(parts) == 2:
                try:
                    ranking[parts[1].lower()] = int(parts[0])
                except ValueError:
                    pass

    print(f"Wczytano {len(ranking):,} domen z listy Tranco.")
    return ranking


def get_tranco_features(domain: str) -> dict:
    """
    Wyznacza cechy popularnosci domeny na podstawie TRANCO_RANKING.

    Lookup O(1). Przy braku bezposredniego trafienia wykonywane jest
    dodatkowe sprawdzenie dla domeny apex (np. sub.example.com -> example.com),
    co obsługuje subdomeny nieobecne samodzielnie w liscie.

    Parameters
    ----------
    domain : str
        Nazwa domeny (np. "example.com", "www.example.com").

    Returns
    -------
    dict
        Klucze:
        tranco_rank      pozycja na liscie (0 jesli nieobecna)
        tranco_in_top1m  1 jesli domena figuruje w Top 1M
        tranco_in_top10k 1 jesli domena figuruje w Top 10k
    """
    d = domain.lower()
    if d.startswith("www."):
        d = d[4:]

    rank = TRANCO_RANKING.get(d, 0)

    # Fallback na domene apex dla subdomen nieobecnych samodzielnie w liscie
    if rank == 0:
        try:
            ext  = tldextract.extract(d)
            apex = f"{ext.domain}.{ext.suffix}".lower()
            rank = TRANCO_RANKING.get(apex, 0)
        except Exception:
            pass

    return {
        "tranco_rank":      rank,
        "tranco_in_top1m":  int(rank > 0),
        "tranco_in_top10k": int(0 < rank <= 10_000),
    }
