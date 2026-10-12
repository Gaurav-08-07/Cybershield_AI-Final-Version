# CyberShield-AI

A cybersecurity platform with real-time URL threat scanning, browser protection, log analysis, and threat intelligence.

## Quick Start

### 1. Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend
```bash
cd frontend
npm install
npm run dev                    # Runs on http://localhost:5173
```

### 3. Chrome Extension
1. Open Chrome -> chrome://extensions
2. Enable Developer Mode
3. Click "Load unpacked" and select the `extension/` folder

### 4. Docker (all-in-one)
```bash
docker-compose up --build
```
Frontend: http://localhost:3000  |  API: http://localhost:8000

## Project Structure

```
CYBERSHIELD_AI/
+-- backend/               FastAPI backend
|   +-- app/
|   |   +-- api/v1/        REST endpoints
|   |   +-- models/        SQLAlchemy models
|   |   +-- services/      Business logic
|   |   +-- schemas/       Pydantic schemas
|   +-- tests/             27 unit tests
+-- frontend/              React + Vite + Tailwind dashboard
|   +-- src/
|   |   +-- pages/         Route pages
|   |   +-- components/    Reusable UI components
|   |   +-- lib/           API client + utilities
+-- extension/             Chrome Extension (Manifest V3)
|   +-- manifest.json
|   +-- background.js      Service worker - rule sync
|   +-- blocked.html       NOT SAFE TO BROWSE page
|   +-- popup.html/js      Extension popup
+-- docker-compose.yml
```

## Key Features

- **URL Scanner** - Heuristic risk scoring + URLhaus threat intelligence
- **SafeBrowse Extension** - Chrome MV3 extension blocks malicious navigation
- **Threat Intelligence DB** - Searchable indicator database
- **Log Analyzer** - BST / Queue / HashTable / Stack data structures for log parsing
- **Reports & Charts** - Recharts-powered analytics with CSV/JSON export
- **Scan History** - Paginated, filterable history with CSV export

## API Documentation

When the backend is running, visit: http://localhost:8000/docs

## Threat Providers

| Provider | Key Required | Notes |
|----------|-------------|-------|
| URLhaus  | No (free)   | Default - active feeds |
| VirusTotal | Yes       | Set `VIRUSTOTAL_API_KEY` in `.env` |

## Tests

```bash
cd backend && pytest tests/ -v    # 27/27 tests
```

## Disclaimer

CyberShield-AI is a research and educational cybersecurity tool. It does not guarantee protection against all threats.
Absence of a positive detection does not mean a URL is safe.
