from scapy.all import sniff, TCP, UDP, IP
from app.ml.predict import predict
from app.response.actions import respond
from app.ai.explain import explain_attack

def extract_features(packet):
    features = []

    # Packet length
    features.append(len(packet))

    # Protocol detection
    if packet.haslayer(TCP):
        features.append(1)
    elif packet.haslayer(UDP):
        features.append(2)
    else:
        features.append(0)

    # Pad features to match model input size
    while len(features) < 77:
        features.append(0)

    return features[:77]


def process_packet(packet):
    features = extract_features(packet)

    try:
        result = predict(features)
        explanation = explain_attack(result)

        # 🔥 GET SOURCE IP
        if packet.haslayer(IP):
            ip = packet[IP].src
        else:
            ip = "Unknown"

        # 🔥 CALL RESPONSE FUNCTION
        action = respond(result, ip)

        print("🚨 Packet detected →", result)
        print("🧠 Reason →", explanation)
        print("🛡️ Action →", action)
        print("-" * 50)

    except Exception as e:
        print("⚠️ Error:", e)


def start_sniffing():
    print("🔍 Starting packet capture...")
    sniff(prn=process_packet, count=20)