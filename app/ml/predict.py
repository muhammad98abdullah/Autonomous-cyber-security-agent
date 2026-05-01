import joblib
import numpy as np
import pandas as pd

model = joblib.load("app/ml/model.pkl")

labels = {
    0: "Normal",
    1: "Attack"
}

def predict(features):
    # Convert to DataFrame (fix warning)
    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]

    return labels.get(prediction, "Unknown")