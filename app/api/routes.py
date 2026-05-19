from datetime import datetime, timedelta, timezone
import ipaddress
import secrets
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse

from app.ai.advisor import explain_security_event
from app.db import get_db, init_db, json_dumps, json_loads, row_to_dict


router = APIRouter()
MAX_EVENTS = 500
BLOCK_DURATION_HOURS = 24
AGENT_VERSION = "0.1.0"

init_db()


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _bearer_token(authorization: Optional[str]):
    if not authorization:
        return None
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return None
    return authorization[len(prefix) :].strip()


def _site_public(site):
    return {
        "id": site["id"],
        "name": site["name"],
        "domain": site["domain"],
        "serverType": site["server_type"],
        "osType": site["os_type"],
        "mode": site["mode"],
        "createdAt": site["created_at"],
        "lastHeartbeatAt": site["last_heartbeat_at"],
    }


def _require_agent(site_id: str, token: str):
    with get_db() as db:
        site = db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
        if not site or token != site["agent_token"]:
            raise HTTPException(status_code=401, detail="Unauthorized agent")
        return row_to_dict(site)


def _require_dashboard(site_id: str, authorization: Optional[str]):
    token = _bearer_token(authorization)
    with get_db() as db:
        site = db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
        if not site or token != site["dashboard_token"]:
            raise HTTPException(status_code=401, detail="Unauthorized dashboard")
        return row_to_dict(site)


def _is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def _normalize_severity(value):
    value = str(value or "medium").lower()
    return value if value in {"low", "medium", "high", "critical"} else "medium"


def _validate_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _site_allowlist(db, site_id: str):
    rows = db.execute("SELECT ip FROM allowlist WHERE site_id = ?", (site_id,)).fetchall()
    return {row["ip"] for row in rows}


def _should_block(event, allowlist=None):
    severity = _normalize_severity(event.get("severity"))
    source_ip = event.get("sourceIp") or event.get("source_ip") or ""
    return severity in {"high", "critical"} and _is_public_ip(source_ip) and source_ip not in (allowlist or set())


def _active_blocks_count(db, site_id: str):
    return db.execute(
        """
        SELECT COUNT(DISTINCT b.source_ip) AS count
        FROM blocks b
        WHERE b.site_id = ?
        AND b.action = 'block'
        AND b.status = 'success'
        AND (b.expires_at IS NULL OR b.expires_at > ?)
        AND NOT EXISTS (
            SELECT 1 FROM blocks u
            WHERE u.site_id = b.site_id
            AND u.source_ip = b.source_ip
            AND u.action = 'unblock'
            AND u.status = 'success'
            AND u.created_at > b.created_at
        )
        """,
        (site_id, _iso_now()),
    ).fetchone()["count"]


def _block_public(row):
    item = row_to_dict(row)
    item["ports"] = json_loads(item.get("ports"))
    return item


def _build_install_command(request: Request, site_id: str, enrollment_token: str):
    backend_url = str(request.base_url).rstrip("/")
    return (
        f"curl -fsSL {backend_url}/install.sh | sudo bash -s -- "
        f"--backend-url {backend_url} "
        f"--site-id {site_id} "
        f"--enroll-token {enrollment_token}"
    )


@router.get("/install.sh", response_class=PlainTextResponse)
def install_script():
    return """#!/usr/bin/env bash
set -euo pipefail

BACKEND_URL=""
SITE_ID=""
ENROLL_TOKEN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-url) BACKEND_URL="$2"; shift 2 ;;
    --site-id) SITE_ID="$2"; shift 2 ;;
    --enroll-token) ENROLL_TOKEN="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$BACKEND_URL" || -z "$SITE_ID" || -z "$ENROLL_TOKEN" ]]; then
  echo "Usage: install.sh --backend-url URL --site-id ID --enroll-token TOKEN" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run with sudo." >&2
  exit 1
fi

apt-get update
apt-get install -y python3 python3-venv python3-pip curl ufw

install -d /opt/astra-agent /etc/astra-agent /var/lib/astra-agent
curl -fsSL "$BACKEND_URL/agent/astra_agent.py" -o /opt/astra-agent/astra_agent.py
python3 -m venv /opt/astra-agent/.venv
/opt/astra-agent/.venv/bin/pip install --upgrade pip requests

cat > /etc/astra-agent/config.json <<EOF
{
  "backend_url": "$BACKEND_URL",
  "site_id": "$SITE_ID",
  "enroll_token": "$ENROLL_TOKEN",
  "agent_token": "",
  "interval": 10,
  "state_dir": "/var/lib/astra-agent"
}
EOF

cat > /etc/systemd/system/astra-agent.service <<'EOF'
[Unit]
Description=ASTRA website security agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/astra-agent/.venv/bin/python /opt/astra-agent/astra_agent.py --config /etc/astra-agent/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now astra-agent.service
echo "ASTRA agent installed and started."
"""


@router.get("/agent/astra_agent.py", response_class=PlainTextResponse)
def agent_source():
    with open("astra_agent.py", "r", encoding="utf-8") as agent_file:
        return agent_file.read()


@router.post("/v1/sites")
def create_v1_site(data: dict, request: Request):
    site_id = f"site_{uuid4().hex[:12]}"
    enrollment_token = secrets.token_urlsafe(32)
    dashboard_token = secrets.token_urlsafe(32)
    now = _iso_now()
    with get_db() as db:
        db.execute(
            """
            INSERT INTO sites (
                id, name, domain, server_type, os_type, mode, enrollment_token,
                dashboard_token, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                site_id,
                data.get("name") or "Untitled Site",
                data.get("domain") or "",
                data.get("serverType") or "auto",
                data.get("osType") or "linux",
                data.get("mode") or "autoprotect",
                enrollment_token,
                dashboard_token,
                now,
            ),
        )
        site = db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    return {
        "site": _site_public(site),
        "enrollmentToken": enrollment_token,
        "dashboardToken": dashboard_token,
        "installCommand": _build_install_command(request, site_id, enrollment_token),
    }


@router.post("/v1/agents/enroll")
def enroll_agent(data: dict):
    site_id = data.get("siteId")
    enrollment_token = data.get("enrollToken") or data.get("enrollmentToken")
    hostname = data.get("hostname") or "unknown-host"
    version = data.get("version") or AGENT_VERSION
    now = _iso_now()
    with get_db() as db:
        site = db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
        if not site or enrollment_token != site["enrollment_token"]:
            raise HTTPException(status_code=401, detail="Unauthorized enrollment")
        agent_token = site["agent_token"] or secrets.token_urlsafe(32)
        db.execute(
            "UPDATE sites SET agent_token = ?, last_heartbeat_at = ? WHERE id = ?",
            (agent_token, now, site_id),
        )
        db.execute(
            """
            INSERT INTO agents (site_id, hostname, version, enrolled_at, last_heartbeat_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(site_id) DO UPDATE SET
                hostname = excluded.hostname,
                version = excluded.version,
                last_heartbeat_at = excluded.last_heartbeat_at
            """,
            (site_id, hostname, version, now, now),
        )
    return {"status": "enrolled", "siteId": site_id, "agentToken": agent_token}


@router.post("/v1/agents/heartbeat")
def agent_heartbeat(data: dict):
    site_id = data.get("siteId")
    token = data.get("agentToken")
    _require_agent(site_id, token)
    now = _iso_now()
    with get_db() as db:
        db.execute("UPDATE sites SET last_heartbeat_at = ? WHERE id = ?", (now, site_id))
        db.execute("UPDATE agents SET last_heartbeat_at = ? WHERE site_id = ?", (now, site_id))
        site = db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
        allowlist = sorted(_site_allowlist(db, site_id))
        commands = [
            row_to_dict(row)
            for row in db.execute(
                "SELECT id, type, source_ip AS sourceIp FROM commands WHERE site_id = ? AND status = 'pending' ORDER BY created_at ASC",
                (site_id,),
            ).fetchall()
        ]
    return {
        "status": "ok",
        "mode": site["mode"],
        "blockDurationHours": BLOCK_DURATION_HOURS,
        "allowlist": allowlist,
        "commands": commands,
    }


@router.post("/v1/agents/events")
def agent_events(data: dict):
    site_id = data.get("siteId")
    token = data.get("agentToken")
    site = _require_agent(site_id, token)
    events = data.get("events") or []
    responses = []
    now = _iso_now()
    with get_db() as db:
        allowlist = _site_allowlist(db, site_id)
        for event in events:
            event_id = event.get("id") or f"evt_{uuid4().hex[:12]}"
            attack_type = event.get("attackType") or event.get("attack_type") or "unknown"
            severity = _normalize_severity(event.get("severity"))
            source_ip = event.get("sourceIp") or event.get("source_ip") or "Unknown"
            enriched_event = {
                **event,
                "attackType": attack_type,
                "severity": severity,
                "sourceIp": source_ip,
                "siteName": site["name"],
            }
            advice = explain_security_event(enriched_event)
            is_allowlisted = source_ip in allowlist
            should_block = site["mode"] == "autoprotect" and _should_block(enriched_event, allowlist)
            if should_block:
                action_taken = "Block requested on web ports 80/443"
            elif is_allowlisted and severity in {"high", "critical"}:
                action_taken = "Detected but not blocked: IP is allowlisted"
            else:
                action_taken = "Monitored"
            db.execute(
                """
                INSERT OR REPLACE INTO events (
                    id, site_id, timestamp, attack_type, severity, source_ip, method, path,
                    status_code, user_agent, rule_id, event_count, sample_lines, explanation,
                    solutions, action_taken, should_block, block_duration_hours, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    site_id,
                    event.get("timestamp") or now,
                    attack_type,
                    severity,
                    source_ip,
                    event.get("method"),
                    event.get("path"),
                    event.get("statusCode"),
                    event.get("userAgent"),
                    event.get("ruleId"),
                    int(event.get("eventCount") or 1),
                    json_dumps(event.get("sampleLines")),
                    advice["explanation"],
                    json_dumps(advice["solutions"]),
                    action_taken,
                    1 if should_block else 0,
                    BLOCK_DURATION_HOURS,
                    now,
                ),
            )
            responses.append(
                {
                    "eventId": event_id,
                    "block": should_block,
                    "blockDurationHours": BLOCK_DURATION_HOURS,
                    "ports": [80, 443],
                    "attackType": attack_type,
                    "ruleId": event.get("ruleId"),
                    "explanation": advice["explanation"],
                    "solutions": advice["solutions"],
                    "action": action_taken,
                    "reason": "allowlisted" if is_allowlisted else "policy",
                }
            )
        db.execute(
            """
            DELETE FROM events
            WHERE site_id = ? AND id NOT IN (
                SELECT id FROM events WHERE site_id = ? ORDER BY created_at DESC LIMIT ?
            )
            """,
            (site_id, site_id, MAX_EVENTS),
        )
    return {"status": "ok", "received": len(events), "responses": responses}


@router.post("/v1/agents/block-result")
def block_result(data: dict):
    site_id = data.get("siteId")
    token = data.get("agentToken")
    _require_agent(site_id, token)
    now = _iso_now()
    with get_db() as db:
        db.execute(
            """
            INSERT INTO blocks (
                id, site_id, event_id, source_ip, attack_type, rule_id, ports,
                action, status, message, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.get("id") or f"blk_{uuid4().hex[:12]}",
                site_id,
                data.get("eventId"),
                data.get("sourceIp") or "Unknown",
                data.get("attackType") or "",
                data.get("ruleId") or "",
                json_dumps(data.get("ports") or [80, 443]),
                data.get("action") or "block",
                data.get("status") or "unknown",
                data.get("message") or "",
                data.get("expiresAt"),
                now,
            ),
        )
    return {"status": "ok"}


@router.post("/v1/agents/command-result")
def command_result(data: dict):
    site_id = data.get("siteId")
    token = data.get("agentToken")
    _require_agent(site_id, token)
    command_id = data.get("commandId")
    if not command_id:
        raise HTTPException(status_code=400, detail="commandId is required")
    now = _iso_now()
    with get_db() as db:
        db.execute(
            """
            UPDATE commands
            SET status = ?, message = ?, completed_at = ?
            WHERE id = ? AND site_id = ?
            """,
            (data.get("status") or "unknown", data.get("message") or "", now, command_id, site_id),
        )
    return {"status": "ok"}


@router.get("/v1/sites/{site_id}/health")
def site_health(site_id: str, authorization: Optional[str] = Header(default=None)):
    site = _require_dashboard(site_id, authorization)
    now = datetime.now(timezone.utc)
    heartbeat_at = _parse_dt(site.get("last_heartbeat_at"))
    agent_online = bool(heartbeat_at and now - heartbeat_at < timedelta(minutes=2))
    with get_db() as db:
        rows = db.execute(
            """
            SELECT * FROM events
            WHERE site_id = ? AND severity IN ('medium', 'high', 'critical')
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (site_id,),
        ).fetchall()
        active_blocks = _active_blocks_count(db, site_id)

    active_events = [row_to_dict(row) for row in rows]
    high_events = [e for e in active_events if e["severity"] in {"high", "critical"}]
    last = high_events[0] if high_events else (active_events[0] if active_events else None)
    status = "danger" if high_events else "ok"
    danger_level = "none" if not last else last["severity"]
    response = {
        "status": status,
        "siteId": site_id,
        "siteName": site["name"],
        "agentOnline": agent_online,
        "lastHeartbeatAt": site.get("last_heartbeat_at"),
        "dangerLevel": danger_level,
        "activeDangerCount": len(high_events),
        "activeBlocks": active_blocks,
        "lastDanger": None,
        "message": "Everything is OK" if status == "ok" else "Attack detected and blocked",
    }
    if last:
        response["lastDanger"] = {
            "attackType": last["attack_type"],
            "sourceIp": last["source_ip"],
            "explanation": last["explanation"],
            "solutions": json_loads(last["solutions"]),
            "actionTaken": last["action_taken"],
        }
    return response


@router.get("/v1/sites/{site_id}/events")
def site_events(site_id: str, authorization: Optional[str] = Header(default=None), limit: int = 100):
    _require_dashboard(site_id, authorization)
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM events WHERE site_id = ? ORDER BY created_at DESC LIMIT ?",
            (site_id, max(1, min(limit, 500))),
        ).fetchall()
    return {"items": [row_to_dict(row) for row in rows], "total": len(rows)}


@router.get("/v1/sites/{site_id}/blocks")
def site_blocks(site_id: str, authorization: Optional[str] = Header(default=None), limit: int = 100):
    _require_dashboard(site_id, authorization)
    with get_db() as db:
        rows = db.execute(
            """
            SELECT * FROM blocks
            WHERE site_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (site_id, max(1, min(limit, 500))),
        ).fetchall()
    return {"items": [_block_public(row) for row in rows], "total": len(rows)}


@router.post("/v1/sites/{site_id}/blocks/{source_ip}/unblock")
def request_unblock(site_id: str, source_ip: str, authorization: Optional[str] = Header(default=None)):
    _require_dashboard(site_id, authorization)
    if not _validate_ip(source_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    command_id = f"cmd_{uuid4().hex[:12]}"
    now = _iso_now()
    with get_db() as db:
        db.execute(
            """
            INSERT INTO commands (id, site_id, type, source_ip, status, created_at)
            VALUES (?, ?, 'unblock', ?, 'pending', ?)
            """,
            (command_id, site_id, source_ip, now),
        )
    return {"status": "queued", "commandId": command_id, "sourceIp": source_ip}


@router.get("/v1/sites/{site_id}/allowlist")
def get_allowlist(site_id: str, authorization: Optional[str] = Header(default=None)):
    _require_dashboard(site_id, authorization)
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM allowlist WHERE site_id = ? ORDER BY created_at DESC",
            (site_id,),
        ).fetchall()
    return {"items": [row_to_dict(row) for row in rows], "total": len(rows)}


@router.post("/v1/sites/{site_id}/allowlist")
def add_allowlist(site_id: str, data: dict, authorization: Optional[str] = Header(default=None)):
    _require_dashboard(site_id, authorization)
    ip = str(data.get("ip") or "").strip()
    if not _validate_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    now = _iso_now()
    with get_db() as db:
        db.execute(
            """
            INSERT INTO allowlist (id, site_id, ip, label, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(site_id, ip) DO UPDATE SET
                label = excluded.label
            """,
            (f"allow_{uuid4().hex[:12]}", site_id, ip, data.get("label") or "", now),
        )
    return {"status": "ok", "ip": ip}


@router.delete("/v1/sites/{site_id}/allowlist/{ip}")
def remove_allowlist(site_id: str, ip: str, authorization: Optional[str] = Header(default=None)):
    _require_dashboard(site_id, authorization)
    if not _validate_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    with get_db() as db:
        db.execute("DELETE FROM allowlist WHERE site_id = ? AND ip = ?", (site_id, ip))
    return {"status": "ok", "ip": ip}


@router.post("/sites")
def legacy_create_site(data: dict, request: Request):
    return create_v1_site(data, request)


@router.get("/sites")
def legacy_list_sites():
    with get_db() as db:
        sites = db.execute("SELECT * FROM sites ORDER BY created_at DESC").fetchall()
    return {"items": [_site_public(site) for site in sites]}


@router.get("/sites/{site_id}/install-command")
def legacy_install_command(site_id: str, request: Request):
    with get_db() as db:
        site = db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    return {"siteId": site_id, "command": _build_install_command(request, site_id, site["enrollment_token"])}


@router.get("/status")
def status():
    with get_db() as db:
        site_count = db.execute("SELECT COUNT(*) AS count FROM sites").fetchone()["count"]
        event_count = db.execute("SELECT COUNT(*) AS count FROM events").fetchone()["count"]
    return {"status": "running", "mode": "api-first", "sites": site_count, "eventsTracked": event_count}


@router.get("/logs")
def logs(limit: int = 100, attack_type: Optional[str] = None):
    query = "SELECT * FROM events"
    params = []
    if attack_type:
        query += " WHERE attack_type = ?"
        params.append(attack_type)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, min(limit, 500)))
    with get_db() as db:
        rows = db.execute(query, params).fetchall()
    return {"items": [row_to_dict(row) for row in rows], "total": len(rows)}
