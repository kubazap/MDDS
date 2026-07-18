# MDDS - Malicious Domain Detection System

System wykrywania złośliwych domen w czasie rzeczywistym, opracowany jako praktyczne zastosowanie wyników pracy dyplomowej *„Analiza skuteczności wybranych modeli uczenia maszynowego w detekcji złośliwych stron internetowych"*.

Projekt składa się z dwóch komponentów:

- **serwera klasyfikacyjnego** (FastAPI + model XGBoost),
- **rozszerzenia do przeglądarki Chrome**, które analizuje domenę każdej odwiedzanej strony i wyświetla ocenę ryzyka na podstawie wektora 44 cech infrastrukturalnych, leksykalnych, strukturalnych i reputacyjnych.

![Popup rozszerzenia MDDS](extension/icons/UI.png)

## Struktura projektu

```
MDDS/
├── extension/                     # Rozszerzenie Chrome, Manifest V3
│   ├── manifest.json              # Konfiguracja rozszerzenia i uprawnień
│   ├── background.js              # Monitorowanie kart i obsługa odznaki
│   ├── popup.html                 # Interfejs rozszerzenia
│   ├── popup.js                   # Komunikacja z API i prezentacja wyników
│   └── icons/                     # Ikony rozszerzenia
│
└── server/                        # Serwer klasyfikacyjny FastAPI
    ├── main.py                    # Punkt wejścia aplikacji i konfiguracja CORS
    ├── config/
    │   └── settings.py            # Ścieżki, listy referencyjne i konfiguracja
    ├── src/
    │   ├── api/
    │   │   └── router.py          # Endpointy /health, /classify i /cache/clear
    │   └── core/
    │       └── classifier.py      # Ładowanie modelu i wykonywanie predykcji
    ├── features/
    │   ├── pipeline.py            # Agregacja 44 cech domenowych
    │   ├── dns.py                 # Cechy DNS, SPF, DKIM i DMARC
    │   ├── whois.py               # Wiek domeny, rejestrator i kraj
    │   ├── http.py                # robots.txt, security.txt oraz WAF/CDN
    │   ├── lexical.py             # Cechy leksykalne nazwy domeny
    │   ├── levenshtein.py         # Detekcja podobieństwa do nazw marek
    │   ├── url.py                 # Cechy strukturalne adresu URL
    │   └── tranco.py              # Cechy rankingu Tranco
    ├── models/                    # Model, lista cech i metadane
    └── cache/                     # Bufor zapytań HTTP
```

## Instalacja i uruchomienie

### Wymagania

- Python 3.12+
- Google Chrome (lub inna przeglądarka oparta na Chromium, wspierająca Manifest V3)

### 1. Klonowanie repozytorium

```bash
git clone https://github.com/kubazap/MDDS
cd MDDS
```

### 2. Uruchomienie serwera API

```bash
cd server
pip install fastapi uvicorn scikit-learn pandas joblib dnspython python-whois requests requests-cache tldextract
python main.py
```

Serwer uruchomi się pod adresem `http://127.0.0.1:8000`, ładując model XGBoost oraz listę Tranco Top 1M (pobieraną automatycznie przy pierwszym starcie i aktualizowaną co tydzień).

### 3. Instalacja rozszerzenia w Chrome

1. Otwórz `chrome://extensions`.
2. Włącz **Tryb dewelopera**.
3. Kliknij **Załaduj rozpakowane** i wskaż katalog `extension/`.
4. Upewnij się, że serwer API działa na porcie **8000**.

### 4. Weryfikacja działania

Otwórz dowolną stronę internetową i kliknij ikonę wtyczki MDDS w pasku narzędzi przeglądarki - powinien pojawić się wynik klasyfikacji analizowanej domeny wraz z panelem szczegółów cech.

## Funkcjonalności

### Rozszerzenie Chrome

- **Automatyczna klasyfikacja** - przy każdej zmianie karty lub załadowaniu strony domena jest wysyłana do lokalnego API (`127.0.0.1:8000`).
- **Odznaka ikony** - procentowa wartość `p_malicious` wyświetlana bezpośrednio na ikonie wtyczki, kolorowana według progu ryzyka.
- **Panel popup** - pasek ryzyka (gauge), werdykt (Bezpieczna / Podejrzana / Złośliwa) oraz status połączenia z serwerem.
- **Panel szczegółów** - siatka cech domeny: wiek domeny, pozycja w rankingu Tranco, grupa rejestratora, SPF/DKIM/DMARC, WAF/CDN, wynik detekcji typosquattingu.
- **Buforowanie dwupoziomowe** - wyniki cache'owane w service workerze i w `chrome.storage.session` (TTL 5 min), z możliwością wymuszenia odświeżenia (`force=true`).

System wykorzystuje trzystopniową skalę ryzyka opartą na prawdopodobieństwie klasy złośliwej:

| Wynik          | Poziom ryzyka |
| -------------- | ------------- |
| poniżej 30%    | bezpieczna    |
| od 30% do 70%  | podejrzana    |
| powyżej 70%    | złośliwa      |

Skala ryzyka uzupełnia klasyfikację binarną i pozwala wyróżnić adresy wymagające dodatkowej weryfikacji.

### Serwer API

| Endpoint       | Opis                                                            |
| -------------- | ---------------------------------------------------------------- |
| `GET /health`  | Stan serwera, typ modelu, liczba cech, rozmiar bufora           |
| `GET /classify`| Klasyfikacja domeny - ekstrakcja 44 cech i predykcja modelu     |
| `GET /cache/clear` | Czyszczenie bufora wyników oraz buforów DNS/WHOIS/HTTP       |

Serwer implementuje dodatkowo bufor wyników w pamięci (LRU, limit 10 000 wpisów) oraz pomiar czasu ekstrakcji per moduł, zwracany w polu `timings_ms` odpowiedzi.

## Cechy modelu

System wykorzystuje 44 cechy pochodzące z siedmiu źródeł danych, podzielone na cztery kategorie:

| Kategoria         | Grupy                              | Liczba cech | Sposób pozyskiwania |
| ------------------ | ----------------------------------- | ----------: | -------------------- |
| Infrastrukturalne | DNS, WHOIS, HTTP                    |          24 | zapytania sieciowe   |
| Leksykalne         | nazwa domeny                        |           9 | analiza lokalna      |
| Strukturalne       | adres URL, odległość Levenshteina   |           8 | analiza lokalna      |
| Reputacyjne        | ranking Tranco                      |           3 | analiza lokalna      |

### Grupy cech

1. **DNS - 12 cech**
   Informacje o rozwiązywaniu domeny, rekordach A, AAAA, MX, NS i TXT oraz mechanizmach SPF, DKIM i DMARC.

2. **WHOIS - 6 cech**
   Wiek domeny, liczba dni do wygaśnięcia rejestracji, status rejestracji, grupa rejestratora oraz informacje o kraju.

3. **HTTP - 6 cech**
   Dostępność zasobów `robots.txt` i `security.txt`, odpowiedzi serwera oraz obecność rozwiązań WAF lub CDN.

4. **Cechy leksykalne - 9 cech**
   Długość nazwy domeny, udział cyfr, liczba separatorów, entropia Shannona, podejrzane słowa, nazwy marek i kategoria TLD.

5. **Struktura adresu URL - 6 cech**
   Długość adresu, liczba parametrów, głębokość ścieżki, liczba subdomen oraz obecność kodowania procentowego.

6. **Odległość Levenshteina - 2 cechy**
   Podobieństwo analizowanej domeny do nazw chronionych marek, wykorzystywane przy wykrywaniu prób typosquattingu.

7. **Tranco - 3 cechy**
   Pozycja domeny oraz jej obecność w rankingach Tranco Top 1M i Top 10k.

Najwyższe wartości statystyki F testu ANOVA uzyskały cechy `domain_age_days` oraz `tranco_in_top1m`, co wskazuje na dużą wartość informacyjną historii rejestracji domeny i jej obecności w rankingu popularności.

## Technologie

### Serwer

- **Python 3.12**
- **FastAPI 0.111** - warstwa REST API, asynchroniczne przetwarzanie żądań
- **scikit-learn 1.4** - ColumnTransformer, ocena jakości modelu
- **dnspython 2.6** - zapytania DNS, weryfikacja SPF/DKIM/DMARC
- **python-whois 0.9** - dane rejestracyjne WHOIS
- **requests** + **requests-cache 1.2** - zapytania HTTP z buforowaniem (SQLite)
- **tldextract** - parsowanie domen i TLD
- **joblib**, **pandas** - wczytywanie modelu i przygotowanie wektora cech

### Rozszerzenie

- **Chrome Extensions API**, Manifest V3
- **Vanilla JavaScript** - service worker + logika popup
- **chrome.storage.session** - przekazywanie wyników między tłem a popupem
