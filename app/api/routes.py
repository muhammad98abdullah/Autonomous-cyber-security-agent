from datetime import datetime, timezone
import secrets
from threading import Thread
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter

from app.ai.explain import explain_attack
from app.ml.predict import predict
from app.ml.train import train_model
from app.network.capture import is_sniffing, start_sniffing, stop_sniffing
from app.response.actions import respond

router = APIRouter()
EVENTS = []
MAX_EVENTS = 500
TRAINING_STATUS = {"running": False, "lastRun": None, "message": "Idle"}
SITES = {}
SITE_EVENTS = {}
AGENTS = {}


def _append_event(event: dict):
    EVENTS.insert(0, event)
    if len(EVENTS) > MAX_EVENTS:
        del EVENTS[MAX_EVENTS:]


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _require_site(site_id: str):
    site = SITES.get(site_id)
    if not site:
        return None
    return site


@router.post("/detect")
def detect(data: dict):
    features = data.get("features", [])
    source_ip = data.get("sourceIp", "Manual Input")

    attack = predict(features)
    explanation = explain_attack(attack)
    action = respond(attack, source_ip)

    event = {
        "id": f"manual-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack": attack,
        "explanation": explanation,
        "action": action,
        "sourceIp": source_ip,
    }
    _append_event(event)

    return {"attack": attack, "explanation": explanation, "action": action}


@router.get("/status")
def status():
    return {
        "status": "running" if is_sniffing() else "stopped",
        "mode": "autonomous",
        "eventsTracked": len(EVENTS),
        "training": TRAINING_STATUS,
    }


@router.get("/logs")
def logs(limit: int = 100, attack_type: Optional[str] = None):
    items = EVENTS
    if attack_type:
        normalized = attack_type.lower()
        items = [event for event in items if event.get("attack", "").lower() == normalized]
    return {"items": items[: max(1, min(limit, 500))], "total": len(items)}


@router.post("/monitoring/start")
def monitoring_start(data: Optional[dict] = None):
    payload = data or {}
    iface = payload.get("iface")
    started = start_sniffing(_append_event, iface=iface)
    return {"status": "started" if started else "already_running"}


@router.post("/monitoring/stop")
def monitoring_stop():
    stopped = stop_sniffing()
    return {"status": "stopped" if stopped else "already_stopped"}


@router.post("/model/retrain")
def model_retrain():
    if TRAINING_STATUS["running"]:
        return {"status": "already_running", "message": "Training is already in progress."}

    def _run_training():
        TRAINING_STATUS["running"] = True
        TRAINING_STATUS["message"] = "Training started"
        try:
            train_model()
            TRAINING_STATUS["message"] = "Training completed successfully"
        except Exception as exc:
            TRAINING_STATUS["message"] = f"Training failed: {exc}"
        finally:
            TRAINING_STATUS["running"] = False
            TRAINING_STATUS["lastRun"] = datetime.now(timezone.utc).isoformat()

    Thread(target=_run_training, daemon=True).start()
    return {"status": "queued", "message": "Model retraining started in background."}


@router.post("/sites")
def create_site(data: dict):
    site_id = f"site-{uuid4().hex[:12]}"
    token = secrets.token_urlsafe(24)
    site = {
        "id": site_id,
        "name": data.get("name", "Untitled Site"),
        "domain": data.get("domain", ""),
        "serverType": data.get("serverType", "nginx"),
        "osType": data.get("osType", "linux"),
        "mode": "monitor",
        "createdAt": _iso_now(),
        "token": token,
        "lastHeartbeatAt": None,
    }
    SITES[site_id] = site
    SITE_EVENTS[site_id] = []
    return {
        "site": {k: v for k, v in site.items() if k != "token"},
        "agentToken": token,
    }


@router.get("/sites")
def list_sites():
    items = []
    for site in SITES.values():
        site_copy = {k: v for k, v in site.items() if k != "token"}
        site_copy["eventCount"] = len(SITE_EVENTS.get(site["id"], []))
        items.append(site_copy)
    return {"items": items}


@router.get("/sites/{site_id}/install-command")
def site_install_command(site_id: str):
    site = _require_site(site_id)
    if not site:
        return {"error": "Site not found"}
    command = (
        f"python -m pip install requests && python astra_agent.py "
        f"--backend-url http://YOUR-ASTRA-SERVER:8000 "
        f"--site-id {site_id} "
        f"--token {site['token']}"
    )
    return {"siteId": site_id, "command": command}


@router.patch("/sites/{site_id}/policy")
def update_site_policy(site_id: str, data: dict):
    site = _require_site(site_id)
    if not site:
        return {"error": "Site not found"}
    mode = data.get("mode")
    if mode in {"monitor", "autoprotect"}:
        site["mode"] = mode
    return {"site": {k: v for k, v in site.items() if k != "token"}}


@router.get("/sites/{site_id}/overview")
def site_overview(site_id: str):
    site = _require_site(site_id)
    if not site:
        return {"error": "Site not found"}
    events = SITE_EVENTS.get(site_id, [])
    attacks = [e for e in events if str(e.get("attack", "")).lower() == "attack"]
    return {
        "siteId": site_id,
        "status": "online" if site.get("lastHeartbeatAt") else "pending",
        "totalEvents": len(events),
        "attacksDetected": len(attacks),
        "lastHeartbeatAt": site.get("lastHeartbeatAt"),
        "mode": site.get("mode", "monitor"),
    }


@router.post("/agents/register")
def agent_register(data: dict):
    site_id = data.get("siteId")
    token = data.get("token")
    hostname = data.get("hostname", "unknown-host")
    site = _require_site(site_id)
    if not site or token != site.get("token"):
        return {"status": "unauthorized"}
    AGENTS[site_id] = {"hostname": hostname, "registeredAt": _iso_now()}
    site["lastHeartbeatAt"] = _iso_now()
    return {"status": "registered", "siteId": site_id}


@router.post("/agents/heartbeat")
def agent_heartbeat(data: dict):
    site_id = data.get("siteId")
    token = data.get("token")
    site = _require_site(site_id)
    if not site or token != site.get("token"):
        return {"status": "unauthorized"}
    site["lastHeartbeatAt"] = _iso_now()
    return {"status": "ok", "mode": site.get("mode", "monitor")}


@router.post("/agents/events")
def agent_events(data: dict):
    site_id = data.get("siteId")
    token = data.get("token")
    events = data.get("events", [])
    site = _require_site(site_id)
    if not site or token != site.get("token"):
        return {"status": "unauthorized"}

    site_buffer = SITE_EVENTS.setdefault(site_id, [])
    for event in events:
        event_obj = {
            "id": event.get("id", f"agent-{uuid4().hex[:10]}"),
            "timestamp": event.get("timestamp", _iso_now()),
            "attack": event.get("attack", "Unknown"),
            "explanation": event.get("explanation", "No explanation provided"),
            "action": event.get("action", "Monitored"),
            "sourceIp": event.get("sourceIp", "Unknown"),
            "siteId": site_id,
            "siteName": site.get("name"),
        }
        site_buffer.insert(0, event_obj)
        EVENTS.insert(0, event_obj)

    if len(site_buffer) > MAX_EVENTS:
        del site_buffer[MAX_EVENTS:]
    if len(EVENTS) > MAX_EVENTS:
        del EVENTS[MAX_EVENTS:]

    return {"status": "ok", "received": len(events)}