from langchain.tools import tool
from app.ml.predict import predict
from app.response.actions import respond

@tool
def detect_attack(features: list):
    """Detect attack from features"""
    return predict(features)

@tool
def take_action(attack: str):
    """Take action based on attack"""
    return respond(attack)