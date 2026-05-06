import os
from langgraph.graph import StateGraph
from typing import TypedDict
from openai import OpenAI
from app.ai.tools import detect_attack, take_action

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1"
)
# 🔹 Agent state
class AgentState(TypedDict):
    features: list
    attack: str
    reasoning: str
    action: str


# 🔹 Step 1: Detect
def detect_node(state):
    attack = detect_attack.invoke({
    "features": state["features"]})
    return {"attack": attack}


# 🔹 Step 2: Reason (LLM)
def reasoning_node(state):
    prompt = f"""
You are a cybersecurity AI agent.

Attack: {state['attack']}

Explain:
- What is happening
- How dangerous it is
- What should be done
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert."},
            {"role": "user", "content": prompt}
        ]
    )

    return {"reasoning": response.choices[0].message.content}


# 🔹 Step 3: Action
def action_node(state):
    action = take_action.invoke({
    "attack": state["attack"]
})
    return {"action": action}


# 🔹 Build graph
def build_agent():
    graph = StateGraph(AgentState)

    graph.add_node("detect", detect_node)
    graph.add_node("reason", reasoning_node)
    graph.add_node("action", action_node)

    graph.set_entry_point("detect")

    graph.add_edge("detect", "reason")
    graph.add_edge("reason", "action")

    return graph.compile()