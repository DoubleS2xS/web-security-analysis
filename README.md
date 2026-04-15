# Web Security Analysis

Web Security Analysis is a Flask-based web application for security-oriented reconnaissance and reporting. It can scan ports, inspect HTTP headers, look for scripts on a target website, query Shodan for host intelligence, and generate an AI-assisted security summary.

## Features

- Port scanning for a configurable range
- HTTP header inspection
- Script discovery for `.js` and `.cgi` files
- Shodan host lookup
- AI-generated security report with Gemini
- Scan history stored in SQLite
- Simple HTML pages for the main site, About, and Contact sections

## Tech stack

- Python 3
- Flask
- Flask-SQLAlchemy
- SQLite
- requests
- shodan
- google-generativeai

## Requirements

- Python 3.10 or newer is recommended
- Internet access for Shodan, HTTP requests, and Gemini API calls
- Valid API keys for:
  - Shodan
  - Google Gemini

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

The application currently reads the Shodan and Gemini API keys from `app.py`.

For better security, you should move those keys to environment variables before deploying or sharing the project.

Also make sure the following files and folders are available:

- `templates/`
- `static/`
- `instance/` (used for the SQLite database file)

## Run locally

Start the Flask application with:

```bash
python3 app.py
```

Then open the app in your browser:

```text
http://127.0.0.1:5000
```

The SQLite database file `instance/scan_history.db` is created automatically if it does not already exist.

## Pages

- `/` - Home page
- `/about.html` - About page
- `/contact.html` - Contact page

## API endpoints

### `POST /scan_ports`
Scan a target for open ports.

Request body example:

```json
{
  "domain": "example.com",
  "start_port": 20,
  "end_port": 100
}
```

Response example:

```json
{
  "open_ports": [80, 443]
}
```

### `POST /analyze`
Run one of the analysis modes: `shodan`, `headers`, or `search_scripts`.

Request body example:

```json
{
  "domain": "example.com",
  "action": "headers"
}
```

Possible actions:

- `shodan` - Return Shodan host data
- `headers` - Fetch HTTP response headers
- `search_scripts` - Find `.js` and `.cgi` references on the target page

### `GET /history`
Return the saved scan history from SQLite.

### `POST /get_ai_report`
Generate an AI security report from previously collected scan data.

Request body example:

```json
{
  "domain": "example.com",
  "open_ports": [80, 443],
  "headers": {
    "Server": "nginx"
  },
  "shodan": {
    "Operating System": "Linux",
    "Country": "United States",
    "Open Ports": [80, 443]
  },
  "scripts": {
    "js_scripts": ["/static/scripts.js"]
  }
}
```

## Example usage with curl

Scan ports:

```bash
curl -X POST http://127.0.0.1:5000/scan_ports \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","start_port":1,"end_port":100}'
```

Fetch headers:

```bash
curl -X POST http://127.0.0.1:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","action":"headers"}'
```

Get scan history:

```bash
curl http://127.0.0.1:5000/history
```

## Project structure

```text
project-backup/
├── app.py
├── requirements.txt
├── README.md
├── instance/
├── static/
└── templates/
```

## Security note

Use this tool only on systems you own or have explicit permission to test.

Port scanning, header analysis, and Shodan lookups can generate network traffic and should be performed responsibly.

## Notes

- The application uses SQLite for local history storage.
- The AI report depends on Gemini being available and correctly configured.
- If an API key is missing or invalid, related features will return an error.
