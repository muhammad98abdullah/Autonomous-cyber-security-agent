def explain_attack(attack):
    explanations = {
        "Normal": "Traffic appears safe, no suspicious pattern detected",

        "Attack": "Unusual packet behavior detected, possible intrusion attempt",

        "DDoS": "High traffic volume detected targeting system, possible Denial-of-Service attack",

        "Port Scan": "Multiple ports accessed rapidly, indicates scanning activity",

        "Brute Force": "Repeated authentication attempts detected, possible password attack"
    }

    return explanations.get(attack, "Unknown network behavior detected")