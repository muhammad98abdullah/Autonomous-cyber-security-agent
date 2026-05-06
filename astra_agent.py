import argparse
import random
import socket
import time
from datetime import datetime, timezone

import requests


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def make_event():
    suspicious = random.random() < 0.15
    return {
        "id": f"evt-{int(time.time() * 1000)}",
        "timestamp": now_iso(),
        "attack": "Attack" if suspicious else "Normal",
        "explanation": "Suspicious request burst detected" if suspicious else "Traffic pattern is within normal baseline",
        "action": "Blocked IP (simulated)" if suspicious else "No action needed",
        "sourceIp": f"10.0.0.{random.randint(2, 250)}",
    }


def main():
    parser = argparse.ArgumentParser(description="ASTRA Edge Connector")
    parser.add_argument("--backend-url", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--interval", type=int, default=10)
    args = parser.parse_args()

    backend = args.backend_url.rstrip("/")
    payload = {"siteId": args.site_id, "token": args.token, "hostname": socket.gethostname()}
    register = requests.post(f"{backend}/agents/register", json=payload, timeout=10)
    print("register:", register.text)

    while True:
        hb = requests.post(f"{backend}/agents/heartbeat", json={"siteId": args.site_id, "token": args.token}, timeout=10)
        print("heartbeat:", hb.status_code)
        event_payload = {"siteId": args.site_id, "token": args.token, "events": [make_event()]}
        ev = requests.post(f"{backend}/agents/events", json=event_payload, timeout=10)
        print("events:", ev.status_code)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
