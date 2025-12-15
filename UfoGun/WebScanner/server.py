import os
import requests
import json
import socket
import ssl
import concurrent.futures
from urllib.parse import urlparse
from flask import Flask, send_from_directory, request, jsonify
from bs4 import BeautifulSoup
import database  # Import custom database module

app = Flask(__name__, static_folder='.')

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

@app.route('/api/reset_db', methods=['POST'])
def reset_database_api():
    try:
        import os
        if os.path.exists(database.DB_NAME):
            os.remove(database.DB_NAME)
        database.init_db()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Database API Routes ---

@app.route('/api/targets', methods=['GET'])
def list_targets():
    return jsonify(database.get_targets())

@app.route('/api/targets', methods=['POST'])
def create_target():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL missing"}), 400
    
    result = database.add_target(url)
    if result:
        return jsonify(result)
    else:
        return jsonify({"error": "Target already exists or invalid"}), 409

@app.route('/api/targets/<int:target_id>', methods=['DELETE'])
def remove_target(target_id):
    database.delete_target(target_id)
    return jsonify({"success": True})

@app.route('/api/targets/clear', methods=['POST'])
def clear_all_targets():
    database.clean_targets()
    return jsonify({"success": True})

@app.route('/api/reports', methods=['GET'])
def list_reports():
    return jsonify(database.get_reports())

@app.route('/api/reports', methods=['POST'])
def create_report():
    data = request.json
    # data should contain details of the scan results
    # We expect: { url, vulnerabilities: [...], ... }
    url = data.get('url')
    vulns = data.get('vulnerabilities', [])
    
    # Serialize the full data to store
    json_data = json.dumps(data)
    
    result = database.add_report(url, len(vulns), json_data)
    return jsonify(result)

@app.route('/api/reports/<int:report_id>', methods=['GET'])
def get_report(report_id):
    report = database.get_report_detail(report_id)
    if report:
        # Parse the JSON string back to object for the frontend
        try:
            report["data"] = json.loads(report["data"])
        except:
            pass
        return jsonify(report)
    return jsonify({"error": "Report not found"}), 404

@app.route('/api/settings', methods=['GET'])
def get_settings_api():
    return jsonify(database.get_settings())

@app.route('/api/settings', methods=['POST'])
def update_settings_api():
    data = request.json
    key = data.get('key')
    value = data.get('value')
    if key is None or value is None:
        return jsonify({"error": "Key or value missing"}), 400
    
    return jsonify(database.update_setting(key, value))

# --- Scan Logic ---

def analyze_headers(headers):
    issues = []
    
    security_headers = {
        'X-Frame-Options': 'Clickjacking saldırılarına karşı koruma sağlar.',
        'Content-Security-Policy': 'XSS ve veri enjeksiyonu saldırılarını engeller.',
        'X-Content-Type-Options': 'MIME-type sniffing saldırılarını engeller.',
        'Strict-Transport-Security': 'HTTPS kullanımını zorunlu kılar (HSTS).'
    }

    for header, desc in security_headers.items():
        if header not in headers:
            issues.append({
                "title": f"Eksik Header: {header}",
                "severity": "low",
                "desc": f"{header} başlığı sunucu yanıtında bulunamadı. Bu başlık, {desc}",
                "path": "HTTP Response Headers"
            })
            
    if 'Server' in headers:
        issues.append({
            "title": "Bilgi Sızıntısı: Server Versiyonu",
            "severity": "info",
            "desc": f"Sunucu başlığı açıkça belirtilmiş: {headers['Server']}. Saldırganlar bu bilgiyi exploit aramak için kullanabilir.",
            "path": "Header: Server"
        })

    return issues

def analyze_html(html_content, base_url):
    soup = BeautifulSoup(html_content, 'html.parser')
    issues = []
    logs = []

    # Form analizi
    forms = soup.find_all('form')
    if forms:
        logs.append(f"Tespit: Sayfada {len(forms)} adet form bulundu.")
        for i, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            inputs = form.find_all('input')
            
            issues.append({
                "title": f"Form Tespit Edildi ({method})",
                "severity": "info",
                "desc": f"'{action}' adresine giden bir form bulundu. {len(inputs)} adet girdi alanı var. SQLi ve XSS için test edilmelidir.",
                "path": f"Form #{i+1} -> {action}"
            })
            
            # Basit password input kontrolü
            for inp in inputs:
                if inp.get('type') == 'password' and method == 'GET':
                    issues.append({
                        "title": "Güvensiz Parola İletimi",
                        "severity": "high",
                        "desc": "Parola alanı içeren bir form GET metodu kullanıyor. Parolalar URL geçmişinde görünebilir.",
                        "path": f"Form #{i+1}"
                    })

    # External resource analysis
    scripts = soup.find_all('script', src=True)
    logs.append(f"Tespit: {len(scripts)} adet harici script kaynağı.")

    # 4. Sensitive File Check
    common_files = ['robots.txt', 'sitemap.xml', '.env', '.git/config', 'backup.sql']
    for file in common_files:
        try:
            file_url = f"{base_url.rstrip('/')}/{file}"
            resp = requests.head(file_url, timeout=3)
            if resp.status_code == 200:
                issues.append({
                    "title": f"Hassas Dosya Bulundu: {file}",
                    "severity": "medium",
                    "desc": f"'{file}' dosyası dışarıdan erişilebilir durumda. İçeriği kontrol edilmeli.",
                    "path": file_url
                })
        except:
            pass

    return issues, logs

import re

def check_advanced_vulnerabilities(url, html_content):
    issues = []
    
    # 1. Advanced SQLi / XSS Heuristic (Active-Passive)
    if '?' in url:
        # Check if parameters are vulnerable to basic reflection
        try:
            # Safe probe: harmless character
            probe_url = url + "'\""
            resp = requests.get(probe_url, timeout=3)
            
            sql_errors = ["syntax error", "mysql_fetch", "ora-", "programming error", "you have an error in your sql syntax"]
            for err in sql_errors:
                if err in resp.text.lower():
                    issues.append({
                        "title": "Possible SQL Injection",
                        "severity": "high",
                        "desc": f"Database error detected in response when probing with quote characters. Error signature: '{err}'",
                        "path": probe_url
                    })
                    break
        except:
            pass

    # 2. Email Extraction (OSINT)
    emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html_content))
    if emails:
        issues.append({
            "title": f"Information Disclosure: Emails ({len(emails)})",
            "severity": "info",
            "desc": "Public email addresses found: " + ", ".join(list(emails)[:5]),
            "path": "Source Code"
        })

    # 3. WAF Detection
    waf_signatures = ['cloudflare', 'sucuri', 'incapsula', 'akamai', 'aws-waf']
    detected_wafs = []
    lower_html = html_content.lower()
    for waf in waf_signatures:
        if waf in lower_html:
            detected_wafs.append(waf)
            
    if detected_wafs:
         issues.append({
            "title": "WAF Detected",
            "severity": "info",
            "desc": f"Web Application Firewall signature found: {', '.join(detected_wafs)}",
            "path": "WAF"
        })

    return issues

def scan_ports(hostname):
    open_ports = []
    # Comprehensive Port List
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5) 
            result = sock.connect_ex((hostname, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_port, ports)
    
    for p in results:
        if p:
            open_ports.append(p)
    return open_ports

def check_ssl_cert(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "subject": dict(x[0] for x in cert['subject']),
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "version": cert['version']
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}

def detect_tech_stack(headers, html_content):
    techs = []
    # Header Checks
    if 'Server' in headers: techs.append(f"Server: {headers['Server']}")
    if 'X-Powered-By' in headers: techs.append(f"Stack: {headers['X-Powered-By']}")
    
    # HTML Checks
    soup = BeautifulSoup(html_content, 'html.parser')
    meta_gen = soup.find('meta', attrs={'name': 'generator'})
    if meta_gen and meta_gen.get('content'):
        techs.append(f"Generator: {meta_gen.get('content')}")
    
    # Framework Signatures
    html_text = html_content.lower()
    if 'wp-content' in html_text: techs.append("CMS: WordPress")
    if 'laravel' in html_text: techs.append("Framework: Laravel")
    if 'django' in html_text: techs.append("Framework: Django")
    if 'react' in html_text or 'react-dom' in html_text: techs.append("Frontend: React")
    if 'vue' in html_text or 'vue.js' in html_text: techs.append("Frontend: Vue.js")
    if 'bootstrap' in html_text: techs.append("UI: Bootstrap")
        
    return techs

def check_admin_pages(base_url):
    issues = []
    # Common admin panel paths
    admin_paths = [
        'admin', 'administrator', 'login', 'wp-login.php', 'dashboard', 
        'cpanel', 'user', 'auth', 'panel', 'management'
    ]
    
    found_paths = []
    
    for path in admin_paths:
        try:
            full_url = f"{base_url.rstrip('/')}/{path}"
            # Short timeout to keep scan fast
            resp = requests.head(full_url, timeout=2, allow_redirects=True)
            
            if resp.status_code == 200:
                found_paths.append(path)
                issues.append({
                    "title": f"Admin Panel Detected: /{path}",
                    "severity": "medium",
                    "desc": f"Accessible page found at '{path}'. Vulnerable to brute-force.",
                    "path": full_url
                })
            elif resp.status_code == 403:
                issues.append({
                    "title": f"Protected Admin Page: /{path}",
                    "severity": "low",
                    "desc": f"Path '{path}' is forbidden (403), but exists.",
                    "path": full_url
                })
        except:
            pass
            
    return issues

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.json
    target_url = data.get('url')
    
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url

    parsed = urlparse(target_url)
    hostname = parsed.netloc

    results = {
        "url": target_url,
        "logs": [],
        "vulnerabilities": []
    }

    results["logs"].append(f"SCAN STARTED: {target_url}")
    results["logs"].append(f"Resolving Host: {hostname}...")

    try:
        # 1. Connection & Recon
        try:
            ip_addr = socket.gethostbyname(hostname)
            results["logs"].append(f"Target IP: {ip_addr}")
        except:
            results["logs"].append("DNS Resolution Failed")
            
        start_time = requests.get(target_url, timeout=5).elapsed.total_seconds()
        response = requests.get(target_url, timeout=10)
        results["logs"].append(f"Target is UP (HTTP {response.status_code}) - Latency: {start_time:.3f}s")
        
        # 2. Port Scan
        results["logs"].append("Initiating Port Scan (Top 20)...")
        open_ports = scan_ports(hostname)
        if open_ports:
            results["vulnerabilities"].append({
                "title": f"Open Ports Detected ({len(open_ports)})",
                "severity": "info",
                "desc": f"Services found: {', '.join(map(str, open_ports))}",
                "path": f"Ports: {open_ports}"
            })
            results["logs"].append(f"OPEN PORTS: {open_ports}")
        else:
            results["logs"].append("No common open ports found (Firewalled?)")

        # 3. SSL Check
        if target_url.startswith('https'):
            results["logs"].append("Analyzing SSL Certificate...")
            ssl_info = check_ssl_cert(hostname)
            if ssl_info.get("valid"):
                issuer = ssl_info.get('issuer', {}).get('organizationName', 'Unknown')
                results["logs"].append(f"SSL Valid. Issuer: {issuer}")
                results["vulnerabilities"].append({
                    "title": "SSL Certificate Info",
                    "severity": "info",
                    "desc": f"Issued by: {issuer}. Version: {ssl_info.get('version')}",
                    "path": "SSL"
                })
            else:
                results["vulnerabilities"].append({
                    "title": "SSL/TLS Issue",
                    "severity": "high",
                    "desc": f"Certificate Error: {ssl_info.get('error')}",
                    "path": "SSL Handshake"
                })

        # 4. Tech Stack Recon
        tech_stack = detect_tech_stack(response.headers, response.text)
        if tech_stack:
            results["vulnerabilities"].append({
                "title": "Technology Stack",
                "severity": "info",
                "desc": "Detected: " + ", ".join(tech_stack),
                "path": "Recon"
            })
            results["logs"].append(f"Tech Stack: {tech_stack}")

        # 5. Header Analysis
        header_issues = analyze_headers(response.headers)
        results["vulnerabilities"].extend(header_issues)

        # 6. Content Analysis
        html_issues, html_logs = analyze_html(response.text, target_url)
        results["vulnerabilities"].extend(html_issues)
        
        # 7. Advanced Analysis (SQLi, WAF, OSINT)
        results["logs"].append("Performing Advanced Threat Analysis...")
        adv_issues = check_advanced_vulnerabilities(target_url, response.text)
        results["vulnerabilities"].extend(adv_issues)
        if adv_issues:
             results["logs"].append(f"Advanced features detected {len(adv_issues)} new items.")

        # 8. Admin Enumeration
        results["logs"].append("Enumerating Admin Paths...")
        admin_issues = check_admin_pages(target_url)
        results["vulnerabilities"].extend(admin_issues)
        if admin_issues:
            results["logs"].append(f"Found {len(admin_issues)} administrative paths.")

        results["logs"].append("FULL SCAN COMPLETED.")
        
    except requests.exceptions.RequestException as e:
        results["logs"].append(f"HATA: Hedefe ulaşılamadı. {str(e)}")
        results["vulnerabilities"].append({
            "title": "Bağlantı Hatası",
            "severity": "error",
            "desc": str(e),
            "path": target_url
        })
    
    return jsonify(results)

if __name__ == '__main__':
    print("Server http://127.0.0.1:5000 adresinde çalışıyor...")
    # Initialize DB
    database.init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)
