from fastapi import APIRouter
from app.ml.predict import predict
from app.ai.explain import explain_attack
from app.response.actions import respond
from app.ai.explain import explain_attack

router = APIRouter()

@router.post("/detect")
def detect(data: dict):
    features = data.get("features", [])

    attack = predict(features)
    explanation = explain_attack(attack)

    return {
        "attack": attack,
        "explanation": explanation,
        "action": "Monitored"
    }