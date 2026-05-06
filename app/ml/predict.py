import joblib
import pandas as pd

_model = None
_model_load_error = None

labels = {
    0: "Normal",
    1: "Attack"
}

def _get_model():
    global _model, _model_load_error
    if _model is not None:
        return _model
    if _model_load_error is not None:
        return None
    try:
        _model = joblib.load("app/ml/model.pkl")
        return _model
    except Exception as exc:
        _model_load_error = str(exc)
        return None


def _fallback_predict(features):
    # Basic fallback heuristic to keep service available when model cannot load.
    packet_len = features[0] if features else 0
    proto = features[1] if len(features) > 1 else 0
    if packet_len > 1400 or proto == 0:
        return "Attack"
    return "Normal"


def predict(features):
    model = _get_model()
    if model is None:
        return _fallback_predict(features)

    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    return labels.get(prediction, "Unknown")