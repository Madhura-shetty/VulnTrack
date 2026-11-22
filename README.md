# VulnTrack - Vulnerability and Security Data Management System

A Flask + PostgreSQL web app that pulls **real** vulnerability data from the NVD CVE API 2.0 and the CISA Known Exploited Vulnerabilities (KEV) catalog, stores it in PostgreSQL, and lets users manage assets, vulnerabilities and risk assessments.

## Features
Login/logout with roles (Admin, Viewer) - dashboard with live DB statistics - asset CRUD - vulnerability search/filter/sort/detail with NVD sync and KEV flag - risk assessment CRUD with explainable scoring - API integration page (status, fetch, counts, history) - append-only audit log - CSV asset import and CSV reports.

## Technology
Python 3, Flask, PostgreSQL (psycopg2), requests, python-dotenv, Werkzeug (scrypt password hashing), HTML5/CSS3/vanilla JavaScript. No frontend frameworks.

## Architecture
```
Browser (HTML + JS fetch) -> Flask routes (app/routes) -> services (app/services) -> PostgreSQL (app/database)
                                                      \-> NVD API / CISA KEV (HTTPS, server-side only)
```
* `routes/` HTTP only: auth, validation call, permission checks, JSON.  `services/` API clients, parsing, validation, sync, reports.  `database/` connection + schema.
* The browser never calls NVD/CISA; only Flask does.

## Database schema (vulntrack_db)
`users` (role admin/viewer) - `assets` - `vulnerabilities` (UNIQUE cve_id, source = nvd/sample/manual, is_kev, kev_data JSONB) - `risk_assessments` (FK asset + vulnerability, UNIQUE pair, generated risk_code) - `audit_logs` (trigger blocks UPDATE/DELETE) - `api_sync_logs`.
CHECK constraints, foreign keys, NOT NULL and indexes are in `app/database/schema.sql`.

## API -> Python -> PostgreSQL workflow
1. Admin clicks **Fetch & synchronize** (JS `fetch` POST `/api/sync`, with CSRF header).
2. `services/nvd.py` calls `https://services.nvd.nist.gov/rest/json/cves/2.0` (`keywordSearch`, `cveId`, or `pubStartDate/pubEndDate` for recent; `resultsPerPage` <= 100, one page only). Optional `NVD_API_KEY` header. Timeouts, HTTP 429 retry, network and malformed-JSON errors raise a safe `ApiError`.
3. `parse_cve` extracts CVE ID, English description, CVSS (v4.0/v3.1/v3.0/v2 fallback, missing -> UNKNOWN), dates, CPE products, reference URLs. Bad records are counted, not fatal.
4. `services/sync.py` upserts into PostgreSQL with `INSERT ... ON CONFLICT (cve_id) DO UPDATE` (`xmax = 0` tells inserted vs updated). Manual records are never overwritten; sample records are replaced by live data; analyst notes are preserved.
5. `services/cisa.py` downloads `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`; stored CVEs are matched by CVE ID and flagged `is_kev` with date added, required action, due date, ransomware use. Nothing is assumed exploited.
6. A row is written to `api_sync_logs` and `audit_logs`; the UI re-renders the table.

### Endpoints (all JSON, all require login; writes require Admin + CSRF header)
`POST /api/login` `POST /api/logout` `GET /api/me` - `GET /api/dashboard` - `/api/assets` (GET, POST, PUT/DELETE `/<id>`) - `GET /api/vulnerabilities[?q,severity,is_kev,source,sort,dir]`, `GET/PUT/DELETE /api/vulnerabilities/<id>`, `POST /api/vulnerabilities` (manual) - `/api/risks` (CRUD) - `POST /api/sync`, `POST /api/sync/check`, `GET /api/sync/logs`, `POST /api/sync/sample` - `GET /api/audit-logs` - `GET /api/reports/{assets|vulnerabilities|risks}.csv`.

## CRUD & JavaScript
`static/js/crud.js` is one reusable table module: it calls the Flask endpoint with `fetch`, rebuilds the table with DOM methods (`textContent`, so no XSS), handles debounced live search, filter dropdowns, click-to-sort headers, HTML `<dialog>` forms with client validation (server validates again), a confirmation dialog before delete, loading spinner and toast messages. No `prompt()` boxes.
API-sourced (nvd) vulnerabilities: only analyst notes are editable and they cannot be deleted; manual/sample records are fully editable.

**Risk score** = likelihood (1-5) x impact (1-5). 20-25 Critical, 12-19 High, 6-11 Medium, 1-5 Low (computed on the server).

## Data security (what is and is not implemented)
* **At rest:** data lives in PostgreSQL, protected by a non-superuser DB role and password; audit table is append-only (trigger). *Disk/database encryption at rest is NOT configured by this project*; use disk encryption (BitLocker) and encrypted backups (`pg_dump` to an encrypted location) in real deployments.
* **In transit:** calls to NVD/CISA use HTTPS (TLS verified by `requests`). Running locally on `http://127.0.0.1:5000` is **not encrypted**. In deployment, run Waitress behind a reverse proxy (Nginx/Caddy/IIS) that terminates TLS, then set `SESSION_COOKIE_SECURE=true` (this also enables the HSTS header).
* **In use:** data is processed in the Flask process memory after server-side authentication, role checks and validation. *No memory encryption is implemented.*
* **App security:** scrypt password hashes (Werkzeug), server-side sessions cookie signed with `SECRET_KEY` (HttpOnly, SameSite=Lax, 30-min sliding expiry), session reset on login, CSRF token on every POST/PUT/DELETE, role checks in Flask decorators, parameterized SQL (`%s`) with whitelisted sort columns, Jinja autoescape + DOM `textContent` + CSP (`script-src 'self'`), login rate limit (5 failures / 5 min per IP+username; in-memory, single process), generic login errors, security headers, generic 500 errors (details only in the server log), CSV formula-injection neutralisation.

## Installation (Windows PowerShell)
Prerequisites: Python 3.10+, PostgreSQL 14+ (psql on PATH).
```powershell
cd VulnTrack
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SECRET_KEY in .env
notepad .env                                                    # set DB_PASSWORD (same as below)
```
Edit the password in `scripts\setup_postgres.sql`, then create the role and database (once, as the postgres superuser):
```powershell
psql -U postgres -f scripts\setup_postgres.sql
python scripts\init_db.py        # creates tables
python scripts\seed_db.py        # demo users, assets, labelled SAMPLE vulnerabilities, risks
python scripts\import_assets.py  # optional: CSV import of data\sample_assets.csv
python run.py                    # open http://127.0.0.1:5000
```
**Demo logins** (set by `SEED_*_PASSWORD` in `.env`): `admin` / `Admin#Demo2026` (full access), `viewer` / `Viewer#Demo2026` (read-only). Change them for anything beyond a demo.

### Using it
1. Sign in as admin -> **API Integration** -> *Check connections* -> choose *Recent*, *Keyword* (e.g. `log4j`) or *CVE ID* -> *Fetch & synchronize*. Counts of fetched / new / updated / failed appear immediately and in the history table.
2. If the APIs are unreachable, click *Load labeled sample data* (rows are tagged `sample`, never presented as live).
3. **Vulnerabilities** page: search, filter, sort, click a CVE for details (KEV info, references).
4. Reports: *Export CSV* buttons, or `python scripts\generate_report.py` (writes `reports\*.csv`).

### Production-style run
```powershell
waitress-serve --listen=127.0.0.1:8000 run:app     # put an HTTPS reverse proxy in front
```

## Testing
```powershell
pip install pytest
python -m pytest -q tests
```
`test_services.py` and `test_app_security.py` need no database. `test_integration_db.py` runs against your real PostgreSQL (after init/seed) and covers login, admin CRUD, viewer 403, SQL-injection-as-data and audit logging. Live NVD/CISA calls are verified manually through the API Integration page.

## Troubleshooting
* `RuntimeError: SECRET_KEY is not set` - create `.env` from `.env.example`.
* `connection refused` / `password authentication failed` - start the PostgreSQL service; match `DB_*` in `.env` with `setup_postgres.sql`.
* NVD "HTTP 429" - wait 30 s or set `NVD_API_KEY` (free from nvd.nist.gov).
* `Activate.ps1 cannot be loaded` - run `Set-ExecutionPolicy -Scope Process Bypass` first.
* "Too many failed attempts" - wait 5 minutes or restart the app.
