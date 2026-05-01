from fastapi import FastAPI
from app.api.routes import router

app = FastAPI(
    title="ASTRA Cybersecurity AI",
    description="Autonomous Threat Detection System",
    version="1.0.0"
)

app.include_router(router)

@app.get("/")
def root():
    return {"message": "ASTRA is running"}