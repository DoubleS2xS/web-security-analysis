from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import socket
import concurrent.futures
import re
import requests
import shodan


SHODAN_API_KEY = 'pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM'
shodan_client = shodan.Shodan(SHODAN_API_KEY)

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


if __name__ == '__main__':
    app.run(debug=True)