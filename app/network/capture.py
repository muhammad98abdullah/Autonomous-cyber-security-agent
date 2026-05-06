from datetime import datetime, timezone
from typing import Callable, Optional

from scapy.all import AsyncSniffer, IP, TCP, UDP

from app.ai.explain import explain_attack
from app.ml.predict import predict
from app.response.actions import respond

_sniffer: Optional[AsyncSniffer] = None


def extract_features(packet):
    features = []
    features.append(len(packet))

    if packet.haslayer(TCP):
        features.append(1)
    elif packet.haslayer(UDP):
        features.append(2)
    else:
        features.append(0)

    while len(features) < 77:
        features.append(0)

    return features[:77]


def analyze_packet(packet):
    features = extract_features(packet)
    source_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
    attack = predict(features)
    explanation = explain_attack(attack)
    action = respond(attack, source_ip)
    return {
        "id": f"pkt-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack": attack,
        "explanation": explanation,
        "action": action,
        "sourceIp": source_ip,
    }


def is_sniffing():
    return _sniffer is not None and _sniffer.running


def start_sniffing(on_event: Callable[[dict], None], iface: Optional[str] = None):
    global _sniffer

    if is_sniffing():
        return False

    def _process(packet):
        try:
            event = analyze_packet(packet)
            on_event(event)
        except Exception as exc:
            on_event(
                {
                    "id": f"err-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "attack": "Unknown",
                    "explanation": f"Packet processing error: {exc}",
                    "action": "Monitored",
                    "sourceIp": "Unknown",
                }
            )

    _sniffer = AsyncSniffer(prn=_process, store=False, iface=iface)
    _sniffer.start()
    return True


def stop_sniffing():
    global _sniffer

    if not is_sniffing():
        return False

    _sniffer.stop()
    _sniffer = None
    return True