# ASTRA Frontend

This is a static, dependency-free dashboard for the ASTRA MVP. It stores temporary auth and site tokens in browser localStorage for testing.

## Run

Start the backend first:

```powershell
cd E:\FYP
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Then start the frontend:

```powershell
cd E:\FYP\frontend
python -m http.server 5173
```

Open:

```text
http://127.0.0.1:5173
```

## Demo Flow

1. Login with the prefilled temporary account.
2. Open `Connect Site`.
3. Create a website.
4. Copy the generated Linux agent install command.
5. Open `Protected Sites`.
6. Use authorized curl/k6 traffic from a separate machine to trigger brute-force or DoS detections.
7. Open `Blocked IPs` to see what ASTRA blocked and why.
8. Open `Allowlist` before testing from your own/admin IP.

The frontend calls the real backend APIs and does not modify backend code.
