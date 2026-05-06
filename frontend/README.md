# ASTRA Frontend

Professional React frontend for the ASTRA Cybersecurity AI system.

## Features
- Dashboard with KPIs and detection trend chart
- Manual detection interface integrated with `POST /detect`
- Logs and alerts viewer with filter support
- Monitoring controls with live feed (polling-based placeholder)
- Model management panel with retraining trigger placeholder
- Settings page with local persistence

## Run locally
1. Install Node.js 18+ and npm.
2. Open a terminal in `frontend`.
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start development server:
   ```bash
   npm run dev
   ```
5. Open the shown URL (usually `http://localhost:5173`).

## Backend assumptions
- API base URL is `http://localhost:8000` in `src/config.js`.
- Existing backend route used:
  - `POST /detect`
- The following capabilities are wired as placeholders in `src/services/api.js` and should be replaced with real endpoints:
  - System status (`GET /`)
  - Logs and alerts retrieval
  - Start/stop monitoring
  - Retrain model
  - Dataset upload

## Suggested backend endpoints
- `GET /status`
- `GET /logs?query=&page=`
- `POST /monitoring/start`
- `POST /monitoring/stop`
- `POST /model/retrain`
- `POST /model/upload-dataset`
