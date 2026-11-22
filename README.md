# VulnTrack – Vulnerability and IT Asset Management System

VulnTrack is a web-based application built using **Python, Flask and PostgreSQL** to manage IT assets, track security vulnerabilities and assess security risks.

It integrates with the **National Vulnerability Database (NVD)** and the **CISA Known Exploited Vulnerabilities (KEV) catalog** to retrieve vulnerability information and help users identify security issues.

## Features

- **User Authentication:** Secure login with Admin and Viewer roles.
- **Dashboard:** View asset statistics, vulnerability counts and recent activity.
- **Asset Management:** Add, view, edit, delete, search and filter IT assets.
- **Vulnerability Management:** View, search, filter and manage vulnerabilities.
- **NVD Integration:** Fetch vulnerability information from the NVD CVE API.
- **CISA KEV Integration:** Identify vulnerabilities listed in CISA's Known Exploited Vulnerabilities catalog.
- **Risk Assessment:** Calculate risk scores based on likelihood and impact.
- **Audit Logs:** Maintain a record of important user activities.
- **CSV Import and Export:** Import asset information and export reports.
- **Sample Data:** Load labelled sample data when external APIs are unavailable.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Database | PostgreSQL |
| Frontend | HTML, CSS, JavaScript |
| Database Connectivity | psycopg2 |
| External APIs | NVD CVE API 2.0, CISA KEV |
| Authentication | Flask sessions, Werkzeug password hashing |

## Application Architecture

The application follows a simple three-layer architecture:

1. **Frontend:** Provides the user interface using HTML, CSS and JavaScript.
2. **Backend:** Flask handles authentication, requests, validation, business logic and API integration.
3. **Database:** PostgreSQL stores users, assets, vulnerabilities, risk assessments and audit records.

External vulnerability information is retrieved by the Flask backend and stored in PostgreSQL.

## Getting Started

Follow these instructions to run VulnTrack on your Windows computer.

### 1. Prerequisites

Install the following:

- Python 3.10 or later
- PostgreSQL 14 or later
- Git (optional, for cloning the repository)

### 2. Download the Project

Clone the repository:

```bash
git clone https://github.com/Madhura-shetty/VulnTrack.git
cd VulnTrack
```

Alternatively, download the repository as a ZIP file and extract it.

### 3. Create a Virtual Environment

Open PowerShell inside the project folder and run:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

Then activate the environment again.

### 4. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 5. Configure Environment Variables

Create your local environment file:

```powershell
Copy-Item .env.example .env
```

Open `.env` and configure the following:

- Flask `SECRET_KEY`
- PostgreSQL database name
- PostgreSQL username
- PostgreSQL password
- Demo admin and viewer passwords

Generate a Flask secret key using:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Copy the generated value into `SECRET_KEY` in `.env`.

**Important:** Never upload your actual `.env` file or share its secret values on GitHub.

### 6. Set Up PostgreSQL

Open `scripts/setup_postgres.sql`.

Update the database role password to match the `DB_PASSWORD` value in your `.env` file.

Open PostgreSQL using the `postgres` superuser and execute the setup script:

```powershell
psql -U postgres -f scripts/setup_postgres.sql
```

This creates the VulnTrack database and its application user.

### 7. Initialize the Database

Run the following commands in order:

```powershell
python scripts/init_db.py
```

This creates the required database tables.

Next, run:

```powershell
python scripts/seed_db.py
```

This creates demo users, sample assets, sample vulnerabilities and risk assessments.

Optionally, import additional sample assets:

```powershell
python scripts/import_assets.py
```

### 8. Start the Application

Run:

```powershell
python run.py
```

Open the application in your browser:

http://127.0.0.1:5000

**Windows port alternative:** If port 5000 cannot be used, start the application on port 8000:

```powershell
python -c "from run import app; app.run(host='127.0.0.1', port=8000, debug=False)"
```

Then open:

http://127.0.0.1:8000

Keep the terminal running while using the application.

## How to Use VulnTrack

### 1. Log In

Open the application in your browser and sign in using the demo credentials configured during database seeding.

| Account | Access |
|---|---|
| Admin | Full application access |
| Viewer | Read-only access |

The actual demo passwords are configured through `SEED_ADMIN_PASSWORD` and `SEED_VIEWER_PASSWORD` in `.env`.

### 2. Dashboard

After logging in, the dashboard displays an overview of the system, including:

- Total registered assets
- Total vulnerabilities
- Vulnerability severity information
- Risk assessment statistics
- Recent audit activity

### 3. Manage Assets

Open the **Assets** page.

Admins can:
- Add new IT assets.
- Edit existing asset information.
- Delete assets.
- Search and filter asset records.

Asset information includes asset code, name, type, owner, host, environment, criticality and status.

Viewers can view asset information but cannot modify it.

### 4. Manage Vulnerabilities

Open the **Vulnerabilities** page.

Users can:
- View vulnerability records.
- Search using CVE IDs or keywords.
- Filter by severity, source and KEV status.
- Sort vulnerability records.
- Open individual vulnerability details.

Manual vulnerability records can also be added by an administrator.

NVD-sourced records are protected from deletion and general editing. Analysts can update their notes.

### 5. Synchronize Vulnerability Data

Open the **API Integration** page.

As an administrator:

1. Select **Check Connections** to check NVD and CISA connectivity.
2. Choose a synchronization option:
   - Recent vulnerabilities
   - Keyword search (for example, `log4j`)
   - Specific CVE ID
3. Click **Fetch & Synchronize**.
4. View the synchronization results.
5. Check the synchronization history for previous operations.

The application retrieves vulnerability information from NVD and checks the CISA KEV catalog for known exploited vulnerabilities.

If external APIs are unavailable, use **Load Sample Data** to load clearly labelled demonstration records.

Sample records are not presented as live vulnerability data.

### 6. Perform Risk Assessments

Open the **Risks** page.

Administrators can create risk assessments by selecting an asset and an associated vulnerability.

Risk is calculated using:

**Risk Score = Likelihood × Impact**

Both likelihood and impact are rated from 1 to 5.

| Risk Score | Risk Level |
|---|---|
| 1–5 | Low |
| 6–11 | Medium |
| 12–19 | High |
| 20–25 | Critical |

The risk score and level are calculated by the backend.

### 7. View Audit Logs

Open the **Audit Logs** page to review recorded activities such as creating, updating and deleting records.

The audit log is designed to be append-only, preventing updates and deletions through the database trigger.

### 8. Import and Export Reports

VulnTrack supports:

- Importing assets from `data/sample_assets.csv`.
- Exporting asset reports.
- Exporting vulnerability reports.
- Exporting risk assessment reports.

CSV reports can be downloaded from the application.

## Security Features

The application includes several security controls:

- Password hashing using Werkzeug's scrypt support.
- Role-based access control.
- CSRF protection for write operations.
- Parameterized SQL queries.
- Server-side input validation.
- Login rate limiting.
- Secure session cookie settings.
- HTTP security headers.
- Audit logging.
- CSV formula-injection protection.

**Security considerations:**

- Local development uses HTTP and does not encrypt browser-to-server traffic.
- HTTPS should be configured through a reverse proxy for deployment.
- Disk/database encryption and encrypted backups must be configured separately.
- The login rate limiter uses in-memory storage and is intended for a single-process demonstration setup.

## Running Tests

Run the test suite using:

```powershell
python -m pytest -q tests
```

The tests cover application security, validation, vulnerability parsing, API error handling and database integration.

The database integration tests require a configured PostgreSQL database.

External API calls are mocked in service tests. Live NVD and CISA connectivity can be checked through the API Integration page.

## Project Structure

```text
VulnTrack/
│
├── app/
│   ├── database/       # Database connection and schema
│   ├── routes/         # Flask API routes
│   ├── services/       # Business logic and API integration
│   ├── static/         # CSS and JavaScript
│   ├── templates/      # HTML templates
│   ├── security.py     # Authentication and security controls
│   └── __init__.py
│
├── data/               # Sample CSV data
├── scripts/            # Database setup, seeding and utilities
├── tests/              # Automated tests
│
├── .env.example        # Environment configuration template
├── .gitignore
├── requirements.txt
├── run.py
└── README.md
```

## Limitations and Future Improvements

- Configure HTTPS for secure browser-to-server communication.
- Implement encryption for database storage and backups.
- Introduce a persistent rate limiter such as Redis for multi-process deployment.
- Add scheduled vulnerability synchronization.
- Run and expand automated tests in a dedicated test environment.

## Author

**Madhura Shetty**

GitHub: https://github.com/Madhura-shetty

---

**VulnTrack – Helping organizations track IT assets, identify vulnerabilities and manage security risks.**
