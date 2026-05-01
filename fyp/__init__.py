from fastapi import FastAPI
import sklearn
import numpy as np

app = FastAPI()

@app.get("/train")
def root():
    return {"message": "FastAPI is working"}

@app.get("/test")
def test():
    return {
        "sklearn_version": sklearn.__version__,
        "array": np.array([1, 2, 3]).tolist()
    }