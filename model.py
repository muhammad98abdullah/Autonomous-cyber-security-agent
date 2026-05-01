import joblib
import numpy as np

def load_model():
    return joblib.load("model.pkl")

def predict(data):
    model = load_model()
    arr = np.array(data).reshape(1, -1)
    prediction = model.predict(arr)
    return int(prediction[0])