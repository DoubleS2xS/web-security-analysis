# Web Security Analysis

Web Security Analysis is a Flask-based web application for security-oriented reconnaissance and static code analysis. It provides both DAST (Dynamic Application Security Testing) capabilities for network intelligence, and SAST (Static Application Security Testing) features using a multi-agent LLM approach.

## Features

**DAST (Dynamic Analysis):**
- Port scanning for a configurable range
- HTTP header inspection
- Script discovery for `.js` and `.cgi` files
- Shodan host lookup
- AI-generated security report based on recon data

**SAST (Static Analysis):**
- Source code vulnerability scanning (via ZIP upload or GitHub URL)
- Multi-Agent LLM Architecture:
  - **Detector Agent:** High-recall agent to flag potential security flaws.
  - **Validator Agent:** High-precision agent to cross-verify findings against the CWE database and mitigate false positives.
- **Human-in-the-Loop (HITL):** Vulnerabilities failing strict confidence thresholds are flagged for manual review and can be approved/rejected via the UI.

**General:**
- Scan history stored in local SQLite database
- Modern tabbed user interface for SAST / DAST workflows

## Tech stack

- **Backend:** Python 3, Flask, SQLAlchemy (SQLite)
- **Frontend:** Vanilla HTML/CSS/JavaScript
- **AI Models:** 
  - OpenRouter/Gemini (DAST reporting)
  - DeepSeek API (`deepseek-chat`) (SAST multi-agent modules)
- **Utilities:** requests, shodan, werkzeug

## Requirements

- Python 3.10 or newer is recommended
- Internet access for downloading repos, querying Shodan, and LLM APIs
- Valid API keys:
  - Shodan API
  - OpenRouter / Google Gemini API
  - DeepSeek API

## Installation

1. Clone the repository and move into the project directory.

```bash
git clone <repo-url>
cd project-backup
```

2. Create and activate a virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies.

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## Configuration

The application reads API keys from environment variables. Create a `.env` file (you can copy `.env.example` if available) and configure keys:

```
SHODAN_API_KEY=your_shodan_key
GEMINI_API_KEY=your_gemini_or_openrouter_key
DEEPSEEK_API_KEY=your_deepseek_key
```

Do NOT commit the `.env` file to version control. Make sure the `instance/` folder is writeable for the SQLite database.

## Run locally

Start the Flask application with:

```bash
python3 app.py
```

Then open the app in your browser:

```text
http://127.0.0.1:5000
```

## Docker / Containerized run

You can run the application with Docker and docker-compose. Ensure your `.env` is configured, then run:

```bash
docker-compose up --build
```

The web app will be available at `http://localhost:5000`.

## API endpoints

### DAST Endpoints

- `POST /scan_ports`: Scan a target for open ports.
- `POST /analyze`: Run analysis modes like `shodan`, `headers`, or `search_scripts`.
- `GET /history`: Return saved DAST scan history.
- `POST /get_ai_report`: Generate an AI security report from collected data.

### SAST Endpoints

- `POST /scan_code`: Main entry point for static testing. Accepts a `file` (ZIP archive) or `github_url` via `multipart/form-data`.
- `POST /sast/vulnerability/<int:vuln_id>`: HITL endpoint. Update the status of a specific vulnerability (`Confirmed`, `Rejected`).

## Project structure

```text
project-backup/
├── app.py                # Main Flask application
├── detector_agent.py     # SAST Sub-agent #1 (Detection)
├── validator_agent.py    # SAST Sub-agent #2 (Validation)
├── sast_processor.py     # Code extraction, filtering, and chunking
├── requirements.txt      # Project dependencies
├── README.md             # Documentation
├── instance/             # SQLite databases
├── static/               # CSS and JS files
└── templates/            # HTML layouts
```

## Security note

Use this tool only on systems and repositories you own or have explicit permission to test. Port scanning, header analysis, and code pulling can generate alerts on target networks and platforms.
