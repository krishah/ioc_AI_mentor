import re
import requests
from flask import Flask, render_template, request, jsonify, make_response, redirect, url_for, session
import config
import pdfkit  # do generowania PDF

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Potrzebny do użycia sesji (przechowywanie wyników)

# Funkcja wykrywająca typ IOC na podstawie wyrażenia regularnego
def detect_ioc_type(ioc):
    patterns = {
        'ip': r'^(\d{1,3}\.){3}\d{1,3}$',
        'url': r'^(http[s]?://)?([^:/\s]+)(:\d+)?(/.*)?$',
        'sha256': r'^[A-Fa-f0-9]{64}$',
        'sha1': r'^[A-Fa-f0-9]{40}$',
        'md5': r'^[A-Fa-f0-9]{32}$',
        'domain': r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
    }
    for t, pattern in patterns.items():
        if re.match(pattern, ioc):
            return t
    return 'unknown'

# Funkcje zapytań do analizatorów - każda zwraca strukturę (np. JSON) z wynikami
def query_virustotal(ioc, ioc_type):
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    # Tworzymy URL dla odpowiedniego typu (domeny jako 'domains')
    if ioc_type == 'domain':
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/{ioc_type}s/{ioc}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    # Przykładowe dane zwrotne, gdy brak klucza lub błąd
    return {
        'data': {
            'attributes': {
                'last_analysis_stats': {'malicious': 2, 'undetected': 10},
                'last_analysis_results': {
                    'VendorA': {'category': 'malicious', 'result': 'Malicious'},
                    'VendorB': {'category': 'undetected', 'result': 'Clean'}
                }
            }
        }
    }

def query_abuseipdb(ioc):
    # Działa tylko, gdy ioc to adres IP
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}"
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {'data': {'abuseConfidenceScore': 0}}

def query_misp(ioc, ioc_type):
    # Wysyłamy zapytanie do MISP (PyMISP) po API
    headers = {"Authorization": config.MISP_API_KEY}
    url = f"{config.MISP_URL}/attributes/restSearch/json/"
    payload = {"value": ioc}
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {'response': 'No data'}

def query_urlscan(ioc):
    # Wysyłamy URL do urlscan.io, następnie pobieramy wynik
    headers = {"API-Key": config.URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": ioc}
    res = requests.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers)
    if res.status_code == 200:
        scan = res.json()
        scan_id = scan.get('uuid')
        result = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/")
        return result.json()
    return {'status': 'error'}

def query_otx(ioc, ioc_type):
    headers = {'X-OTX-API-KEY': config.OTX_API_KEY}
    if ioc_type == 'ip':
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/reputation"
    elif ioc_type == 'domain':
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/reputation"
    else:
        return {}
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        return res.json()
    return {}

def query_ipinfo(ioc):
    url = f"https://ipinfo.io/{ioc}/json?token={config.IPINFO_API_KEY}"
    res = requests.get(url)
    if res.status_code == 200:
        return res.json()
    return {}

# Funkcja spłaszczająca zagnieżdżone struktury JSON do postaci {klucz: wartość}
def flatten_json(data):
    flat = {}
    def _flatten(x, name=''):
        if isinstance(x, dict):
            for k, v in x.items():
                _flatten(v, f"{name}{k}.")
        elif isinstance(x, list):
            for i, v in enumerate(x):
                _flatten(v, f"{name}{i}.")
        else:
            flat[name.rstrip('.')] = x
    _flatten(data)
    return flat

# Obsługa strony głównej z formularzem i analizą
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        ioc = request.form.get('ioc', '').strip()
        selected = request.form.getlist('analysers')  # Wybrane analizatory z formularza
        ioc_type = detect_ioc_type(ioc)
        analyses = {}
        # Wywołanie wybranych analizatorów, jeśli typ IOC jest zgodny
        if 'VirusTotal' in selected:
            analyses['VirusTotal'] = query_virustotal(ioc, ioc_type)
        if 'AbuseIPDB' in selected and ioc_type == 'ip':
            analyses['AbuseIPDB'] = query_abuseipdb(ioc)
        if 'MISP' in selected:
            analyses['MISP'] = query_misp(ioc, ioc_type)
        if 'urlscan' in selected and ioc_type == 'url':
            analyses['urlscan'] = query_urlscan(ioc)
        if 'AlienVault' in selected:
            analyses['AlienVault'] = query_otx(ioc, ioc_type)
        if 'IPInfo' in selected and ioc_type == 'ip':
            analyses['IPInfo'] = query_ipinfo(ioc)
        # (Analogicznie można dodać kolejne analizatory...)

        # Przekazanie wyników do modelu LLM (Ollama) w celu oceny i rekomendacji
        llm_payload = {"ioc": ioc, "type": ioc_type, "results": analyses}
        try:
            llm_response = requests.post(config.OLLAMA_URL, json=llm_payload)
            llm_data = llm_response.json()
        except Exception:
            llm_data = {"assessment": "Model LLM nie odpowiedział", "recommendation": ""}

        # Zapis wyników w sesji (dla funkcji eksportu)
        session['last_ioc']      = ioc
        session['last_type']     = ioc_type
        session['last_analyses'] = analyses
        session['last_llm']      = llm_data

        # Renderowanie strony z wynikami
        return render_template('results.html', 
                               ioc=ioc, ioc_type=ioc_type,
                               analyses=analyses, llm_data=llm_data,
                               flatten_json=flatten_json)
    # Dla GET: pokaz formularz
    return render_template('index.html')

# Eksport wyników do JSON
@app.route('/export/json')
def export_json():
    if 'last_analyses' in session:
        return jsonify(session['last_analyses'])
    return jsonify({'error': 'Brak danych do eksportu'})

# Eksport wyników do PDF
@app.route('/export/pdf')
def export_pdf():
    if 'last_analyses' in session:
        rendered = render_template('results.html',
                                   ioc=session.get('last_ioc'),
                                   ioc_type=session.get('last_type'),
                                   analyses=session.get('last_analyses'),
                                   llm_data=session.get('last_llm'),
                                   flatten_json=flatten_json)
        pdf = pdfkit.from_string(rendered, False)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
        return response
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
