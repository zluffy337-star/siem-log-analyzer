# SIEM Log Analyzer & Security Dashboard

A compact SIEM prototype that ingests security logs (CSV), persists events to SQLite, runs SQL-based detection rules, and visualizes results in an interactive Streamlit dashboard.

---

## Key Features
- CSV → SQLite ingestion (load_logs.py)
- Rule-based detection engine writing alerts to DB (detect_threats.py)
- Interactive Streamlit dashboard (dashboard.py) with:
  - Filters (event type, date, IP, user)
  - Run Detection Now button (invokes detect_threats.py)
  - KPI gauge, donut & bar charts, time-series, pydeck world map
  - Alerts and detection result tables
- Geocoding with caching (country_cache.json) to avoid rate limits
- Local dev automation scripts (run_all.ps1 / run_all.bat)

---

## Technology Stack
- Python 3.x, pandas, sqlite3, Streamlit
- Visualization: plotly, matplotlib, pydeck
- Geocoding: geopy (Nominatim)
- Dev: Git, venv (.venv), requirements.txt

---

## Repository Structure
- security_logs.csv — sample input  
- load_logs.py — CSV ingestion → `logs` table in siem.db  
- detect_threats.py — detection engine → `alerts` table in siem.db  
- dashboard.py — Streamlit UI (reads logs + alerts; can run detection)  
- country_cache.json — geocode cache  
- siem.db — SQLite DB (ignored by Git)  
- run_all.ps1 / run_all.bat — optional automation to run ingestion, detection, and dashboard  
- requirements.txt, .streamlit/config.toml, README.md, .gitignore

---

## Quick Install (Windows PowerShell)
1. Clone repo:
```powershell
git clone https://github.com/YOUR_USERNAME/siem-log-analyzer.git
#for me below is the path for project
cd "c:\Users\(username)\OneDrive\Desktop\Project SIEM\SIEM_Log_Analyzer"
```
2. Create and activate venv:
```powershell
python -m venv .venv
# Temporarily allow script execution for this session:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& ".\.venv\Scripts\Activate.ps1"
```
3. Install dependencies:
```powershell
pip install -r requirements.txt
```

---

## Usage (run order)
1. Ingest sample logs:
```powershell
& ".\.venv\Scripts\python.exe" .\load_logs.py
```
2. Run detection (writes alerts):
```powershell
& ".\.venv\Scripts\python.exe" .\detect_threats.py
```
Or inside the dashboard click "Run Detection Now" (sidebar) — this calls detect_threats.py and shows output.

3. Start the dashboard:
```powershell
& ".\.venv\Scripts\streamlit.exe" run .\dashboard.py
```
Open the Local URL printed by Streamlit (http://localhost:8501).

Optional: use run_all scripts in repo root to automate steps.

---

## Detection Rules (implemented)
- Brute-force IPs: source IPs with multiple failed auth attempts
- Geo-anomalies: same username observed in multiple countries
- Credential-stuffing candidates: IPs with many distinct usernames or many attempts
- Rapid country change: same user from different countries within short time window
- Off-hours successful logins: successful logins between 00:00–05:00
- Process/PowerShell spikes: many process/powershell events from same IP
- User-added events: recent account creation events

Alerts are persisted to `alerts` table as JSON details with UTC timestamp.

---

## DB Schema (summary)
- logs: id, timestamp, event_type, username, src_ip, status, country, details...
- alerts: id, alert_type, details (JSON), detected_at (ISO8601 UTC)

---

## Git & Deployment Notes
- .gitignore excludes `.venv`, `siem.db`, and other generated files.
- Commit changes often: git add . → git commit -m "msg" → git push origin main
- Use a GitHub Personal Access Token (PAT) or SSH for authentication.
- Deploy to Streamlit Cloud: connect GitHub repo and set app entry to `SIEM_Log_Analyzer/dashboard.py`.

---

## Troubleshooting
- "Database not found": run load_logs.py in SIEM_Log_Analyzer folder.
- Streamlit errors about config.toml: ensure `.streamlit/config.toml` is valid UTF‑8 TOML (no BOM).
- PowerShell activation blocked: use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.
- Use venv Python and streamlit executables directly if you don't activate the venv.

---

## Demo
1. Show GitHub repo README and files.
2. Run `load_logs.py` → confirm `siem.db` created.
3. Run `detect_threats.py` → show console alerts.
4. Start dashboard → demonstrate filters, charts, Run Detection Now button, and map.

---
