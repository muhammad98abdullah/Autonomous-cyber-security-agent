import os

from openai import OpenAI


DEFAULT_SOLUTIONS = {
    "brute_force": [
        "Temporarily block the source IP.",
        "Enable rate limiting on login endpoints.",
        "Require strong passwords and multi-factor authentication.",
    ],
    "web_scan": [
        "Block the scanning IP if the requests continue.",
        "Hide or remove unused admin tools and test files.",
        "Keep CMS, plugins, and server packages updated.",
    ],
    "suspicious_payload": [
        "Block the source IP and review the requested URL.",
        "Validate and sanitize all request parameters.",
        "Check application logs for successful exploitation indicators.",
    ],
    "server_error_spike": [
        "Review application error logs for the affected path.",
        "Check recent deployments and upstream service health.",
        "Rate limit the source IP if errors are request-driven.",
    ],
}


def _fallback_advice(event):
    attack_type = event.get("attackType") or event.get("attack_type") or "unknown"
    severity = event.get("severity", "medium")
    source_ip = event.get("sourceIp") or event.get("source_ip") or "unknown"
    path = event.get("path") or "unknown path"
    solutions = DEFAULT_SOLUTIONS.get(
        attack_type,
        [
            "Review the source IP and requested paths.",
            "Check server logs around the event time.",
            "Apply temporary blocking if the activity continues.",
        ],
    )
    return {
        "explanation": (
            f"{severity.title()} severity {attack_type.replace('_', ' ')} activity "
            f"was detected from {source_ip} targeting {path}."
        ),
        "solutions": solutions,
    }


def explain_security_event(event):
    api_key = os.getenv("GROQ_KEY")
    if not api_key:
        return _fallback_advice(event)

    try:
        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
        prompt = f"""
You are ASTRA, a cybersecurity assistant for Linux website servers.

Explain this security event for a site owner in concise, practical language.
Return only this format:
Explanation: <one paragraph>
Solutions:
- <solution 1>
- <solution 2>
- <solution 3>

Event:
{event}
"""
        response = client.chat.completions.create(
            model=os.getenv("ASTRA_GROQ_MODEL", "llama-3.3-70b-versatile"),
            messages=[
                {"role": "system", "content": "You explain website security incidents clearly."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        content = response.choices[0].message.content or ""
        explanation = content
        solutions = []
        if "Solutions:" in content:
            explanation_part, solution_part = content.split("Solutions:", 1)
            explanation = explanation_part.replace("Explanation:", "").strip()
            solutions = [
                line.strip().lstrip("-").strip()
                for line in solution_part.splitlines()
                if line.strip().startswith("-")
            ]
        if not explanation:
            return _fallback_advice(event)
        return {"explanation": explanation, "solutions": solutions[:5] or _fallback_advice(event)["solutions"]}
    except Exception:
        return _fallback_advice(event)
