from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import socket
import concurrent.futures
import re
import json
import requests
import shodan
import google.generativeai as genai
import os
import logging
from dotenv import load_dotenv
from sast_processor import process_upload, cleanup_upload
from detector_agent import run_detector
from validator_agent import run_validator

# Load environment variables from .env file (do not commit .env to VCS)
load_dotenv()

# API keys are loaded from environment variables for security
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
if SHODAN_API_KEY:
    shodan_client = shodan.Shodan(SHODAN_API_KEY)
else:
    shodan_client = None

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

app = Flask(__name__, template_folder='templates', static_folder='static')


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scan_history.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    start_port = db.Column(db.Integer, nullable=True)
    end_port = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================================
# SAST Database Models
# ============================================================

class CodeScanResult(db.Model):
    """Stores metadata for each SAST code scan session."""
    id = db.Column(db.Integer, primary_key=True)
    source_type = db.Column(db.String(20), nullable=False)      # 'github' or 'zip'
    source_name = db.Column(db.String(500), nullable=False)      # URL or filename
    total_files = db.Column(db.Integer, default=0)
    total_chunks = db.Column(db.Integer, default=0)
    total_vulnerabilities = db.Column(db.Integer, default=0)
    confirmed_count = db.Column(db.Integer, default=0)
    false_positive_count = db.Column(db.Integer, default=0)
    needs_review_count = db.Column(db.Integer, default=0)
    languages = db.Column(db.Text, default='{}')                 # JSON string
    status = db.Column(db.String(20), default='completed')       # 'completed', 'error'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True,
                                      cascade='all, delete-orphan')


class Vulnerability(db.Model):
    """Stores individual vulnerability findings with HITL status."""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('code_scan_result.id'), nullable=False)

    # Detector fields
    filepath = db.Column(db.String(500), nullable=False)
    line_number = db.Column(db.Integer, default=0)
    vulnerability_type = db.Column(db.String(100), nullable=False)
    original_severity = db.Column(db.String(20), default='Medium')
    code_snippet = db.Column(db.Text, default='')
    description = db.Column(db.Text, default='')
    cwe_id = db.Column(db.String(20), default='N/A')

    # Validator fields
    confidence_score = db.Column(db.Integer, default=50)
    status = db.Column(db.String(30), default='Needs Human Review')  # Confirmed, False Positive, Needs Human Review
    adjusted_severity = db.Column(db.String(20), default='Medium')
    validation_reasoning = db.Column(db.Text, default='')
    recommendation = db.Column(db.Text, default='')

    # HITL fields
    analyst_decision = db.Column(db.String(30), nullable=True)   # 'Approved' or 'Rejected' (set by human)
    analyst_comment = db.Column(db.Text, nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()


# Функция для поиска скриптов
def search_scripts(domain_with_scheme):  # Expects domain with scheme e.g. http://example.com
    try:
        response = requests.get(domain_with_scheme)
        if response.status_code == 200:
            content = response.text
            cgi_scripts = re.findall(r'href=["\']([^"\']*\.cgi)["\']', content)
            js_scripts = re.findall(r'src=["\']([^"\']*\.js)["\']', content)
            return {
                "cgi_scripts": list(set(cgi_scripts)),
                "js_scripts": list(set(js_scripts))
            }
        else:
            return {"error": f"Unable to reach domain. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# Функция для преобразования домена в IP
def resolve_domain_to_ip(domain_without_scheme):  # Expects domain without scheme
    try:
        return socket.gethostbyname(domain_without_scheme)
    except socket.gaierror:
        return None


# Поиск информации в Shodan
def shodan_lookup(domain_without_scheme):  # Expects domain without scheme
    ip = resolve_domain_to_ip(domain_without_scheme)
    if not ip:
        # If domain resolution fails, try to see if the input itself was an IP
        try:
            socket.inet_aton(domain_without_scheme)  # Check if it's a valid IP format
            ip = domain_without_scheme
        except socket.error:
            return {"error": "Unable to resolve domain to IP and not a valid IP address"}

    # If Shodan isn't configured, return a helpful message instead of failing
    if not shodan_client:
        return {"error": "Shodan API key not configured"}

    try:
        host = shodan_client.host(ip)
        return {
            "IP": host.get('ip_str', 'N/A'),
            "Organization": host.get('org', 'N/A'),
            "Operating System": host.get('os', 'N/A'),
            "Country": host.get('country_name', 'N/A'),
            "City": host.get('city', 'N/A'),
            "Latitude": host.get('latitude', 'N/A'),
            "Longitude": host.get('longitude', 'N/A'),
            "Hostnames": host.get('hostnames', []),
            "Open Ports": host.get('ports', [])
        }
    except shodan.APIError as e:
        return {"error": str(e)}



@app.route('/')
def home():
    return render_template('index.html')


@app.route('/about.html')
def about():
    return render_template('about.html')


@app.route('/contact.html')
def contact():
    return render_template('contact.html')



@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    try:
        data = request.get_json()
        original_target = data.get('domain')  # This can be domain or IP, possibly with scheme
        start_port_str = data.get('start_port')
        end_port_str = data.get('end_port')

        if not all([original_target, start_port_str, end_port_str]):
            return jsonify({'error': 'Missing parameters'}), 400

        start_port = int(start_port_str)
        end_port = int(end_port_str)

        if not (1 <= start_port <= end_port <= 65535):
            return jsonify({'error': 'Invalid port range'}), 400

        cleaned_target = re.sub(r'^https?://', '', original_target)

        open_ports = []

        def scan(host_to_scan, port_to_scan):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)  # Short timeout for faster scanning
            try:
                s.connect((host_to_scan, port_to_scan))
                open_ports.append(port_to_scan)
            except (socket.timeout, ConnectionRefusedError, socket.error):
                pass  # Port is closed or host unreachable
            finally:
                s.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan, cleaned_target, port) for port in range(start_port, end_port + 1)]
            concurrent.futures.wait(futures)


        scan_entry = ScanHistory(
            domain=cleaned_target,
            start_port=start_port,
            end_port=end_port,
            action="ports"
        )
        db.session.add(scan_entry)
        db.session.commit()

        return jsonify({'open_ports': sorted(list(set(open_ports)))})


    except ValueError:  # Catches errors from int() conversion
        return jsonify({'error': 'Invalid port number format. Ports must be integers.'}), 400
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500


# Анализ Shodan, Scripts, Headers
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    action = data.get('action')
    original_domain = data.get('domain')

    if not original_domain:
        return jsonify({"error": "Domain not provided"}), 400

    shodan_domain_cleaned = re.sub(r'^https?://', '', original_domain)
    shodan_result = shodan_lookup(shodan_domain_cleaned)

    if action != "shodan":  # Shodan-only calls are just for data retrieval, not a full "scan"
        scan_entry = ScanHistory(domain=shodan_domain_cleaned, action=action)
        db.session.add(scan_entry)
        db.session.commit()

    if action == "search_scripts":
        domain_for_scripts = original_domain
        if not domain_for_scripts.startswith("http://") and not domain_for_scripts.startswith("https://"):
            domain_for_scripts = "http://" + domain_for_scripts  # Default to http
        scripts_result = search_scripts(domain_for_scripts)
        return jsonify({"shodan": shodan_result, **scripts_result})

    elif action == 'headers':
        domain_for_headers = original_domain
        if not domain_for_headers.startswith("http://") and not domain_for_headers.startswith("https://"):
            domain_for_headers = "http://" + domain_for_headers  # Default to http

        try:
            response = requests.get(domain_for_headers, timeout=10)
            headers_dict = dict(response.headers)
            return jsonify({"shodan": shodan_result, "status": "success", "headers": headers_dict})
        except requests.exceptions.RequestException as e:  # More specific exception
            return jsonify({"shodan": shodan_result, "status": "error", "message": str(e)})

    elif action == "shodan":  # Called by frontend to populate Shodan section
        return jsonify({"shodan": shodan_result})

    else:
        return jsonify({"shodan": shodan_result, "error": "Action not supported or endpoint mismatch"})


# Логирование запросов
"""
@app.route('/scan', methods=['POST'])
def scan_log_general():
    data = request.json
    domain = data.get('domain')
    # Clean domain for logging consistency if keeping this route
    cleaned_domain_for_log = re.sub(r'^https?://', '', domain) if domain else "N/A"

    start_port = data.get('start_port')
    end_port = data.get('end_port')
    action = data.get('action')

    result_message = f"General log: Domain: {cleaned_domain_for_log}, Action: {action}"
    if start_port and end_port: # If port scan related, though /scan_ports handles its own logging
        result_message += f", Ports: {start_port}-{end_port}"

    scan_entry = ScanHistory(
        domain=cleaned_domain_for_log,
        start_port=start_port if start_port else None,
        end_port=end_port if end_port else None,
        action=action if action else "general_log"
    )
    db.session.add(scan_entry)
    db.session.commit()

    return jsonify({'message': 'Scan logged successfully via /scan', 'result': result_message})
"""


@app.route('/history', methods=['GET'])
def history():
    try:
        history_entries = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()
        return jsonify([
            {
                'id': entry.id,
                'domain': entry.domain,
                'start_port': entry.start_port,
                'end_port': entry.end_port,
                'action': entry.action,
                'timestamp': entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }
            for entry in history_entries
        ])
    except Exception as e:
        return jsonify({"error": f"Could not retrieve history: {str(e)}"}), 500


#AI БЛОК
def generate_ai_report(scan_data):
    """
    Generate an executive summary and final recommendations using DeepSeek API.
    """
    if not scan_data:
        return "<p>No report available.</p>"

    deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
    deepseek_url = "https://api.deepseek.com/chat/completions"
    deepseek_model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    # Serialize scan data for the prompt
    scan_json = json.dumps(scan_data, indent=2)

    prompt = f"""You are a Principal Application Security Architect.
Based on the following SAST scan results, write an Executive Summary and Final Recommendations report.

SCAN RESULTS:
{scan_json}

INSTRUCTIONS:
1. Provide a brief 1-2 paragraph executive summary explaining the overall security posture and risk level.
2. List the Top 3 most critical vulnerabilities (if any) and a plain-English explanation of why they matter.
3. Provide actionable recommendations for the development team.
4. Keep the tone professional but accessible to non-security stakeholders.
5. Format your response strictly in HTML (using <h3>, <p>, <ul>, <li>, <strong>). Do NOT wrap it in ```html markdown fences.
"""

    try:
        headers = {
            "Authorization": f"Bearer {deepseek_api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": deepseek_model,
            "messages": [
                {"role": "system", "content": "You are a specialized application security reporting agent. Produce clean HTML output only."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }

        response = requests.post(deepseek_url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()

        html_report = response.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()

        # Clean up any potential markdown fences
        if html_report.startswith("```html"):
            html_report = html_report.replace("```html", "", 1)
        if html_report.endswith("```"):
            html_report = html_report[:-3]

        return html_report.strip()
    except Exception as e:
        logger.error(f"Failed to generate AI report: {e}")
        return f"""
        <div class="alert alert-warning">
            <h5>Report Generation Failed</h5>
            <p>Could not reach the DeepSeek API to generate the executive summary.</p>
            <p>Error details: {str(e)}</p>
        </div>
        """


@app.route('/get_ai_report', methods=['POST'])
def get_ai_report():
    data = request.json
    report = generate_ai_report(data)
    return jsonify({"report": report})

# ============================================================
# SAST — Source Code Analysis Pipeline
# ============================================================

@app.route('/scan_code', methods=['POST'])
def scan_code():
    """
    Full SAST pipeline: ingest → detect → validate → save to DB.

    Supported input formats:
      1. ZIP upload:   multipart/form-data with field 'file'
      2. GitHub URL:   JSON {"github_url": "https://github.com/owner/repo"}

    Pipeline:
      1. Ingest & chunk source code (sast_processor)
      2. Run Detector Agent on all chunks (detector_agent)
      3. Run Validator Agent with CWE context (validator_agent)
      4. Save results to SQLite database
      5. Return validated vulnerabilities + statistics
    """
    upload_dir = None  # track for cleanup
    source_type = None
    source_name = None

    try:
        # --- Step 1: Determine source type and ingest ---
        if 'file' in request.files:
            # ZIP file upload
            uploaded_file = request.files['file']

            if not uploaded_file.filename:
                return jsonify({'error': 'No file selected.'}), 400

            if not uploaded_file.filename.lower().endswith('.zip'):
                return jsonify({'error': 'Only ZIP archives are supported.'}), 400

            source_type = 'zip'
            source_name = uploaded_file.filename
            ingest_result = process_upload(uploaded_file, source_type='zip')

        elif request.is_json:
            # GitHub URL
            data = request.get_json()
            github_url = data.get('github_url', '').strip()

            if not github_url:
                return jsonify({'error': 'Please provide a github_url field.'}), 400

            if 'github.com' not in github_url:
                return jsonify({
                    'error': 'Invalid URL. Only public GitHub repository URLs are supported.'
                }), 400

            source_type = 'github'
            source_name = github_url
            ingest_result = process_upload(github_url, source_type='github')

        else:
            return jsonify({
                'error': 'Invalid request. Send a ZIP file (multipart/form-data) '
                         'or JSON with {"github_url": "..."}'
            }), 400

        # Save upload_dir for cleanup
        upload_dir = ingest_result.pop('upload_dir', None)
        chunks = ingest_result['chunks']

        # --- Step 2: Run Detector Agent ---

        detector_result = run_detector(chunks)

        # --- Step 3: Run Validator Agent ---
        raw_vulnerabilities = detector_result['vulnerabilities']
        validator_result = run_validator(raw_vulnerabilities)

        # --- Step 4: Save to database ---
        scan_record = CodeScanResult(
            source_type=source_type,
            source_name=source_name,
            total_files=ingest_result['stats']['total_files'],
            total_chunks=ingest_result['stats']['total_chunks'],
            total_vulnerabilities=validator_result['summary']['total_validated'],
            confirmed_count=validator_result['summary']['confirmed'],
            false_positive_count=validator_result['summary']['false_positives'],
            needs_review_count=validator_result['summary']['needs_review'],
            languages=json.dumps(ingest_result['stats']['languages']),
            status='completed',
        )
        db.session.add(scan_record)
        db.session.flush()  # Get scan_record.id before committing

        for vuln_data in validator_result['validated_vulnerabilities']:
            vuln_record = Vulnerability(
                scan_id=scan_record.id,
                filepath=vuln_data.get('filepath', ''),
                line_number=vuln_data.get('line_number', 0),
                vulnerability_type=vuln_data.get('vulnerability_type', ''),
                original_severity=vuln_data.get('original_severity', 'Medium'),
                code_snippet=vuln_data.get('code_snippet', ''),
                description=vuln_data.get('description', ''),
                cwe_id=vuln_data.get('cwe_id', 'N/A'),
                confidence_score=vuln_data.get('confidence_score', 50),
                status=vuln_data.get('status', 'Needs Human Review'),
                adjusted_severity=vuln_data.get('adjusted_severity', 'Medium'),
                validation_reasoning=vuln_data.get('validation_reasoning', ''),
                recommendation=vuln_data.get('recommendation', ''),
            )
            db.session.add(vuln_record)

        db.session.commit()

        # --- Step 5: Build response ---
        response_payload = {
            'status': 'success',
            'scan_id': scan_record.id,
            'ingestion': ingest_result['stats'],
            'detection': detector_result['summary'],
            'validation': validator_result['summary'],
            'vulnerabilities': validator_result['validated_vulnerabilities'],
        }

        return jsonify(response_payload), 200

    except ValueError as e:
        logging.error(f"SAST scan_code ValueError: {e}")
        return jsonify({'error': str(e)}), 400

    except Exception as e:
        logging.error(f"SAST scan_code unexpected error: {e}", exc_info=True)
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

    finally:
        # Always clean up temporary files
        if upload_dir:
            cleanup_upload(upload_dir)


# ============================================================
# SAST — Results & HITL API
# ============================================================

@app.route('/sast/results', methods=['GET'])
def sast_results():
    """List all SAST code scan results, newest first."""
    try:
        scans = CodeScanResult.query.order_by(CodeScanResult.timestamp.desc()).all()
        return jsonify([
            {
                'id': s.id,
                'source_type': s.source_type,
                'source_name': s.source_name,
                'total_files': s.total_files,
                'total_chunks': s.total_chunks,
                'total_vulnerabilities': s.total_vulnerabilities,
                'confirmed': s.confirmed_count,
                'false_positives': s.false_positive_count,
                'needs_review': s.needs_review_count,
                'languages': json.loads(s.languages) if s.languages else {},
                'status': s.status,
                'timestamp': s.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
            for s in scans
        ])
    except Exception as e:
        return jsonify({'error': f'Failed to load scan results: {str(e)}'}), 500


@app.route('/sast/results/<int:scan_id>', methods=['GET'])
def sast_result_detail(scan_id):
    """Get detailed results for a specific scan, including all vulnerabilities."""
    try:
        scan = CodeScanResult.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found.'}), 404

        vulns = Vulnerability.query.filter_by(scan_id=scan_id).order_by(
            # Confirmed first, then Needs Review, then FP
            db.case(
                (Vulnerability.status == 'Confirmed', 0),
                (Vulnerability.status == 'Needs Human Review', 1),
                (Vulnerability.status == 'False Positive', 2),
                else_=3,
            ),
            Vulnerability.confidence_score.desc(),
        ).all()

        return jsonify({
            'scan': {
                'id': scan.id,
                'source_type': scan.source_type,
                'source_name': scan.source_name,
                'total_files': scan.total_files,
                'total_chunks': scan.total_chunks,
                'total_vulnerabilities': scan.total_vulnerabilities,
                'confirmed': scan.confirmed_count,
                'false_positives': scan.false_positive_count,
                'needs_review': scan.needs_review_count,
                'languages': json.loads(scan.languages) if scan.languages else {},
                'status': scan.status,
                'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            },
            'vulnerabilities': [
                {
                    'id': v.id,
                    'filepath': v.filepath,
                    'line_number': v.line_number,
                    'vulnerability_type': v.vulnerability_type,
                    'original_severity': v.original_severity,
                    'code_snippet': v.code_snippet,
                    'description': v.description,
                    'cwe_id': v.cwe_id,
                    'confidence_score': v.confidence_score,
                    'status': v.status,
                    'adjusted_severity': v.adjusted_severity,
                    'validation_reasoning': v.validation_reasoning,
                    'recommendation': v.recommendation,
                    'analyst_decision': v.analyst_decision,
                    'analyst_comment': v.analyst_comment,
                    'reviewed_at': v.reviewed_at.strftime('%Y-%m-%d %H:%M:%S') if v.reviewed_at else None,
                }
                for v in vulns
            ],
        })
    except Exception as e:
        return jsonify({'error': f'Failed to load scan details: {str(e)}'}), 500


@app.route('/sast/vulnerability/<int:vuln_id>', methods=['PUT'])
def sast_update_vulnerability(vuln_id):
    """
    HITL endpoint: analyst approves or rejects a vulnerability.

    JSON body:
      {
        "decision": "Approved" | "Rejected",
        "comment": "optional analyst comment"
      }
    """
    try:
        vuln = Vulnerability.query.get(vuln_id)
        if not vuln:
            return jsonify({'error': 'Vulnerability not found.'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON body required.'}), 400

        decision = data.get('decision', '').strip()
        if decision not in ('Approved', 'Rejected'):
            return jsonify({
                'error': 'Invalid decision. Must be "Approved" or "Rejected".'
            }), 400

        # Update vulnerability record
        vuln.analyst_decision = decision
        vuln.analyst_comment = data.get('comment', '').strip() or None
        vuln.reviewed_at = datetime.utcnow()

        # Update status based on analyst decision
        if decision == 'Approved':
            vuln.status = 'Confirmed'
        elif decision == 'Rejected':
            vuln.status = 'False Positive'

        # Update parent scan counters
        scan = vuln.scan
        _recalculate_scan_counts(scan)

        db.session.commit()

        return jsonify({
            'status': 'success',
            'vulnerability_id': vuln.id,
            'new_status': vuln.status,
            'analyst_decision': vuln.analyst_decision,
            'reviewed_at': vuln.reviewed_at.strftime('%Y-%m-%d %H:%M:%S'),
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update vulnerability: {str(e)}'}), 500


def _recalculate_scan_counts(scan):
    """Recalculate confirmed/FP/review counts for a scan after HITL decision."""
    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()
    scan.confirmed_count = sum(1 for v in vulns if v.status == 'Confirmed')
    scan.false_positive_count = sum(1 for v in vulns if v.status == 'False Positive')
    scan.needs_review_count = sum(1 for v in vulns if v.status == 'Needs Human Review')


if __name__ == '__main__':
    app.run(debug=True)
