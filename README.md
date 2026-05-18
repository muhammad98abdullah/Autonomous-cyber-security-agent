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

The agent watches nginx/apache logs, detects suspicious web traffic, reports events, and applies 24-hour UFW blocks when the backend requests protection.

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

The first version detects:

- suspicious paths such as `/.env`, `/wp-login.php`, `/phpmyadmin`, and `/.git`
- SQL injection and path traversal-looking payloads
- repeated login attempts
- repeated suspicious HTTP status codes
- high request rate from a single IP

Packet capture and advanced ML training are later phases after the log-based agent is stable.
