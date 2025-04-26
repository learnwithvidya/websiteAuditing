from flask import Flask, render_template, request
import requests
import ssl
import socket
import re
import os

app = Flask(__name__)

# --- VirusTotal settings ---
VT_API_KEY = "acdd910ce209457ac926ee3a3dafedd49b3807ba3ca7677c1234605131e4beb4"  # <-- REPLACE with your own API key
VT_URL = "https://www.virustotal.com/api/v3/urls"

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        return True
    except Exception:
        return False

def check_security_headers(url):
    try:
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        result = {
            'Strict-Transport-Security': 'Strict-Transport-Security' in headers,
            'Content-Security-Policy': 'Content-Security-Policy' in headers,
            'X-Frame-Options': 'X-Frame-Options' in headers,
            'X-XSS-Protection': 'X-XSS-Protection' in headers,
            'Referrer-Policy': 'Referrer-Policy' in headers,
            'Permissions-Policy': 'Permissions-Policy' in headers,
            'Cache-Control': 'Cache-Control' in headers,
            'Pragma': 'Pragma' in headers
        }
        return result
    except Exception:
        return {}

def payment_page_https(domain):
    try:
        urls = [f"https://{domain}/payment", f"https://{domain}/checkout"]
        for u in urls:
            resp = requests.get(u, timeout=5)
            if resp.url.startswith("https://"):
                return True
    except Exception:
        return False
    return False

def detect_cms(url):
    try:
        resp = requests.get(url, timeout=5)
        content = resp.text.lower()
        if "wp-content" in content or "wordpress" in content:
            return "WordPress"
        elif "joomla" in content:
            return "Joomla"
        elif "drupal" in content:
            return "Drupal"
        else:
            return "Unknown/Custom"
    except Exception:
        return "Unknown"

def get_cms_version(url, cms):
    try:
        resp = requests.get(url, timeout=5)
        content = resp.text
        if cms == "WordPress":
            match = re.search(r'content="WordPress ([0-9\.]+)"', content)
            if match:
                return match.group(1)
        elif cms == "Joomla":
            match = re.search(r'content="Joomla! - Open Source Content Management" />.*?Joomla! ([0-9\.]+)', content, re.DOTALL)
            if match:
                return match.group(1)
        elif cms == "Drupal":
            match = re.search(r'content="Drupal ([0-9\.]+)"', content)
            if match:
                return match.group(1)
        return "Unknown"
    except Exception:
        return "Unknown"

def check_virustotal(domain):
    try:
        # Step 1: Submit URL for scanning
        url = f"https://{domain}"
        vt_resp = requests.post(VT_URL,
            headers={"x-apikey": VT_API_KEY},
            data={"url": url}
        )
        scan_id = vt_resp.json()["data"]["id"]
        # Step 2: Retrieve results
        result_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        vt_result = requests.get(result_url, headers={"x-apikey": VT_API_KEY})
        result_json = vt_result.json()
        verdict = result_json["data"]["attributes"]["stats"]
        return {
            "harmless": verdict.get("harmless", 0),
            "malicious": verdict.get("malicious", 0),
            "suspicious": verdict.get("suspicious", 0),
            "undetected": verdict.get("undetected", 0)
        }
    except Exception as e:
        return {"error": str(e)}

@app.route('/', methods=['GET', 'POST'])
def index():
    report = None
    if request.method == 'POST':
        domain = request.form['domain'].strip().replace('http://','').replace('https://','').split('/')[0]
        url = f"https://{domain}"
        ssl_status = check_ssl(domain)
        headers_result = check_security_headers(url)
        payment_https = payment_page_https(domain)
        cms = detect_cms(url)
        cms_version = get_cms_version(url, cms) if cms in ["WordPress", "Joomla", "Drupal"] else "N/A"
        vt_result = check_virustotal(domain)
        report = {
            'domain': domain,
            'ssl_status': ssl_status,
            'headers_result': headers_result,
            'payment_https': payment_https,
            'cms': cms,
            'cms_version': cms_version,
            'virustotal': vt_result
        }
    return render_template('index.html', report=report)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
