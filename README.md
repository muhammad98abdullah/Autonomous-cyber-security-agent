# ASTRA End-to-End Setup

## 1) Start backend

```powershell
E:/FYP/.venv/Scripts/python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

## 2) Start frontend

```powershell
cd E:/FYP/frontend
npm install
npm run dev
```

## 3) Onboard a website

1. Open frontend and go to `Website Onboarding`.
2. Fill website details and create site.
3. Copy generated install command and token.
4. On client infrastructure, run `astra_agent.py` with the generated arguments.

## 4) Monitor connected clients

1. Open `Connected Sites` page.
2. Verify heartbeat appears.
3. Switch mode between `Monitor Only` and `Auto Protect`.
4. Review events from `Logs & Alerts`.
