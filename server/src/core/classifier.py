"""
src/core/classifier.py

Ladowanie modelu klasyfikacyjnego i wykonywanie predykcji.

Wczytuje potok scikit-learn (RandomForest + ColumnTransformer)
z pliku binarnego .pkl. Predykcja zwraca prawdopodobienstwa obu klas
oraz etykiete decyzyjna przy progu 0.5.

Model referencyjny (RandomForest, n_estimators=600, GroupShuffleSplit):
    ROC AUC = 0.9683, PR AUC = 0.9222, F1 = 0.8325, MCC = 0.7771,
    Accuracy = 0.9161, Precision = 0.8561, Recall = 0.8101
"""

import json
import time

import joblib
import pandas as pd

from config import MODEL_PATH, FEATURE_COLS_PATH, META_PATH

# Stany globalne inicjalizowane jednorazowo w fazie lifespan serwera.
model:        object = None
feature_cols: list   = []
model_meta:   dict   = {}


def load_model() -> None:
    """
    Laduje model, liste kolumn cech i metadane eksperymentu z dysku.

    Wywolywana jednokrotnie przez lifespan FastAPI. Wyniki zapisywane
    w zmiennych modulowych eliminuja narzut I/O przy kazdym zadaniu.

    Raises
    ------
    FileNotFoundError
        Brak pliku model.pkl lub feature_columns.pkl.
    """
    global model, feature_cols, model_meta

    model        = joblib.load(MODEL_PATH)
    feature_cols = joblib.load(FEATURE_COLS_PATH)
    print(f"  Model:  {type(model).__name__}  |  Liczba cech: {len(feature_cols)}")

    try:
        with open(META_PATH) as f:
            model_meta = json.load(f)
        roc = model_meta.get("roc_auc", "?")
        print(f"  Metryki: ROC AUC={roc:.4f}" if isinstance(roc, float) else f"  Metryki: {roc}")
    except FileNotFoundError:
        print(f"  Plik {META_PATH} nieobecny, kontynuuje bez metadanych.")


def predict(features: dict) -> dict:
    """
    Wykonuje predykcje dla wektora cech podanego jako slownik.

    Slownik jest przeksztalcany w jednowierszowy DataFrame i dopasowywany
    do kolejnosci kolumn modelu przez reindex. Typy bool sa konwertowane
    do int64 zgodnie z wymaganiami ColumnTransformer.

    Parameters
    ----------
    features : dict
        Slownik cech zwrocony przez gather_domain_features().

    Returns
    -------
    dict
        Pola: klasyfikacja (str), p_malicious (float), p_benign (float),
        elapsed_ms (float).
    """
    t0 = time.perf_counter()

    df = pd.DataFrame([features])
    df = df.reindex(columns=feature_cols, fill_value=0)

    # bool -> int64 wymagane przez potok preprocessingowy
    for col in df.select_dtypes(include=["bool"]).columns:
        df[col] = df[col].astype("int64")

    probs       = model.predict_proba(df)[0]
    p_malicious = float(probs[1])
    p_benign    = float(probs[0])
    elapsed_ms  = round((time.perf_counter() - t0) * 1000, 1)

    return {
        "klasyfikacja": "ZLOSLIWA" if p_malicious >= 0.5 else "BEZPIECZNA",
        "p_malicious":  round(p_malicious, 4),
        "p_benign":     round(p_benign, 4),
        "elapsed_ms":   elapsed_ms,
    }
