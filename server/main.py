"""
main.py

Punkt wejscia serwera MDDS.

Odpowiedzialnosci modulu:
    lifespan  ladowanie modelu i listy Tranco przy starcie serwera
    app       instancja FastAPI z middleware CORS i zarejestrowanym routerem

Logika endpointow:   src/api/router.py
Logika klasyfikacji: src/core/classifier.py

Uruchomienie:
    python main.py
"""
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import src.core.classifier as classifier
import features.tranco     as _tranco
from src.api.router        import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Zarzadza cyklem zycia aplikacji FastAPI.

    Przy starcie laduje model klasyfikacyjny i liste Tranco Top 1M.
    """
    print("=== Inicjalizacja serwera MDDS ===")
    classifier.load_model()
    _tranco.TRANCO_RANKING.update(_tranco.load_tranco())
    print("=== Serwer gotowy do przyjmowania zadan ===\n")
    yield
    print("=== Zamykanie serwera ===")


app = FastAPI(
    title="MDDS API",
    description=(
        "Interfejs API klasyfikatora zlosliwych domen opartego na cechach "
        "infrastrukturalnych (DNS, WHOIS, HTTP, Tranco) i leksykalnych. "
        "Model referencyjny: Random Forest, ROC AUC = 0.9683, Accuracy = 0.9161."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Naglowki CORS wymagane dla zadan z kontekstu wtyczki Chrome
# (schemat chrome-extension://).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
