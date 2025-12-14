import sys
import os

# Add local directory to sys.path to allow importing 'tools'
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from tools.whois import whois_lookup
from tools.fetch import fetch_url, extract_page_signals
from tools.dns import get_dns_records

app = Flask(__name__)

@app.route('/mcp/whois', methods=['POST'])
def handle_whois():
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    result = whois_lookup(domain)
    return jsonify(result)

@app.route('/mcp/fetch', methods=['POST'])
def handle_fetch():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"error": "url is required"}), 400
    result = fetch_url(url)
    return jsonify(result)

@app.route('/mcp/signals', methods=['POST'])
def handle_signals():
    data = request.json
    url = data.get('url')
    html_content = data.get('html_content') # Optional, can be passed if already fetched
    if not url:
        return jsonify({"error": "url is required"}), 400
    result = extract_page_signals(url, html_content)
    return jsonify(result)

@app.route('/mcp/dns', methods=['POST'])
def handle_dns():
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    result = get_dns_records(domain)
    return jsonify(result)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
