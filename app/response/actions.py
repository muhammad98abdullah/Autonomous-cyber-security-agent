def respond(attack, ip="Unknown"):
    if attack == "Normal":
        return "No action needed"

    action = f"⚠️ Threat detected from {ip} → Blocking (simulated)"

    print(action)

    return action