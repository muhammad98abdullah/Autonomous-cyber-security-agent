# ASTRA API-First Security Agent MVP

ASTRA protects Linux VPS websites with a lightweight agent. The backend enrolls sites, receives security events, explains attacks with Groq when `GROQ_KEY` is available, and exposes one health API that a user dashboard can call.

## Start Backend

```powershell
E:/FYP/.venv/Scripts/python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

The backend stores MVP data in SQLite at `astra.db` by default. Override with:

```powershell
$env:ASTRA_DB_PATH="E:/FYP/astra-dev.db"
```

If the agent will run on a different VPS, the installer must use a backend URL that the VPS can reach. Set it before creating sites:

```powershell
$env:ASTRA_PUBLIC_BACKEND_URL="https://YOUR-ASTRA-BACKEND"
```

You can also enter the same value in the frontend's `Public Backend URL` field when creating a site. Do not leave it as `127.0.0.1` unless the agent is installed on the same machine as the backend.

## Start Frontend

The dashboard is isolated in `frontend/` and has no npm dependency.

```powershell
cd E:/FYP/frontend
python -m http.server 5173
```

Open:

```text
http://127.0.0.1:5173
```

Use the prefilled temporary login. The frontend stores its test session and dashboard tokens in browser localStorage.

## Create A Site

```bash
curl -X POST http://127.0.0.1:8000/v1/sites \
  -H "Content-Type: application/json" \
  -d '{"name":"Demo Site","domain":"example.com"}'
```

The response includes:

- `installCommand`: one command to run on the client Linux VPS with sudo.
- `dashboardToken`: bearer token for the user dashboard health API.
- `enrollmentToken`: one-time-style token used by the agent to receive its long-lived agent token.

## Install Agent On Client VPS

Run the generated install command on an Ubuntu/Debian server:

```bash
curl -fsSL http://YOUR-ASTRA-BACKEND/install.sh | sudo bash -s -- --backend-url http://YOUR-ASTRA-BACKEND --site-id SITE_ID --enroll-token ENROLL_TOKEN
```

The installer creates:

- `/opt/astra-agent/astra_agent.py`
- `/etc/astra-agent/config.json`
- `/var/lib/astra-agent/`
- `astra-agent.service`

The agent watches nginx/apache logs, detects suspicious web traffic, reports events, and applies 24-hour web-only UFW blocks when the backend requests protection.

## Dashboard Health API

The user's dashboard only needs this call:

```bash
curl http://127.0.0.1:8000/v1/sites/SITE_ID/health \
  -H "Authorization: Bearer DASHBOARD_TOKEN"
```

Healthy response:

```json
{
  "status": "ok",
  "message": "Everything is OK",
  "agentOnline": true
}
```

Danger response:

```json
{
  "status": "danger",
  "message": "Attack detected and blocked",
  "lastDanger": {
    "attackType": "brute_force",
    "sourceIp": "1.2.3.4",
    "actionTaken": "Block requested"
  }
}
```

## Agent Detection MVP

The current version focuses on reliable, demo-ready detection for:

- brute force attempts against login/admin paths such as `/wp-login.php`, `/xmlrpc.php`, `/login`, and `/admin`
- web-layer DoS / HTTP floods from a single IP, the same path, or total site traffic spikes
- suspicious sensitive-file scans such as `/.env`, `/phpmyadmin`, `/.git`, and backup/config paths
- suspicious payloads such as SQL injection-looking text, XSS-looking text, command parameters, and path traversal

When ASTRA blocks an IP, it blocks website access only:

```bash
ufw deny from ATTACKER_IP to any port 80
ufw deny from ATTACKER_IP to any port 443
```

This protects the website while reducing the chance of blocking SSH access.

## Blocklist And Allowlist

The frontend includes:

- `Blocked IPs`: shows IPs ASTRA blocked, why they were blocked, target ports, status, and expiry.
- `Allowlist`: lets the user add trusted IPs for admin/testing. Allowlisted IPs are detected but never blocked.
- Manual unblock: queues an unblock command for the agent; the agent applies it on heartbeat and reports the result.

Packet capture and advanced ML training are later phases after the log-based agent is stable.
