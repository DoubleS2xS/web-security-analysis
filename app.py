from flask import Flask, render_template, request, jsonify
import socket
import concurrent.futures
import re
import requests
import shodan

# Shodan API Key
SHODAN_API_KEY = 'pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM'
shodan_client = shodan.Shodan(SHODAN_API_KEY)

app = Flask(__name__, template_folder='templates', static_folder='static')

def search_scripts(domain):
    try:
        response = requests.get(domain)
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

def resolve_domain_to_ip(domain):
    """Resolves a domain name to an IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def shodan_lookup(domain):
    """Looks up information on Shodan using an IP address."""
    ip = resolve_domain_to_ip(domain)
    if not ip:
        return {"error": "Unable to resolve domain to IP"}

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

# Главная страница
@app.route('/')
def home():
    return render_template('index.html')

# Порт-сканирование через веб-интерфейс
@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    try:
        data = request.get_json()
        target = data.get('domain')
        start_port = int(data.get('start_port'))
        end_port = int(data.get('end_port'))

        if not target or start_port < 1 or end_port > 65535 or start_port > end_port:
            return jsonify({'error': 'Invalid input parameters'}), 400

        # Запускаем сканирование
        open_ports = []

        def scan(ip, port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                s.connect((ip, port))
                open_ports.append(port)
                s.close()
            except:
                pass

        def run(ip, start, end):
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                for port in range(start, end + 1):
                    executor.submit(scan, ip, port)

        run(target, start_port, end_port)

        return jsonify({'open_ports': open_ports})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    action = data.get('action')
    domain = data.get('domain')

    # Shodan API lookup
    shodan_result = shodan_lookup(domain)

    if action == "search_scripts":
        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "http://" + domain
        scripts_result = search_scripts(domain)
        return jsonify({"shodan": shodan_result, **scripts_result})

    elif action == 'headers':
        try:
            response = requests.get(f'http://{domain}', timeout=10)
            headers = dict(response.headers)
            return jsonify({"shodan": shodan_result, "status": "success", "headers": headers})
        except Exception as e:
            return jsonify({"shodan": shodan_result, "status": "error", "message": str(e)})
    else:
        return jsonify({"shodan": shodan_result, "error": "Action not supported"})

if __name__ == '__main__':
    app.run(debug=True)
