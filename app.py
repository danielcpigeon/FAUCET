#!/usr/bin/env python3
from flask import Flask, request, render_template, redirect, url_for, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pymysql
import re
import os
import requests
import logging
from datetime import datetime, timedelta

# Flask app setup
app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["2 per minute"])

# DB connection setup
def db_connection():
    return pymysql.connect(host='localhost', user='faucetuser', password='StrongPassword!', db='faucet')

# Load API keys
if os.path.exists('API_Keys.txt'):
    with open('API_Keys.txt') as f:
        for line in f:
            if '=' in line:
                key, val = line.strip().split('=', 1)
                os.environ[key] = val

# Basic logging
logging.basicConfig(filename='faucet.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Regex for CVE ID validation
CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cve_id = request.form.get('cve_id', '').strip()
        if not CVE_PATTERN.match(cve_id):
            error = "Invalid CVE ID format. Please use CVE-YYYY-####."
            return render_template('faucet.html', error=error)

        cve_id = cve_id.upper()

        # Check DB for cached data
        conn = db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT last_fetch_date FROM cve_main WHERE cve_id=%s", (cve_id,))
        row = cursor.fetchone()

        cache_path = f'cache/{cve_id}.html'
        if row and (datetime.utcnow() - row[0]) < timedelta(days=180) and os.path.exists(cache_path):
            cursor.close()
            conn.close()
            return redirect(url_for('cve_page', cve_id=cve_id))

        # Fetch and cache data (simplified example fetching from NVD API)
        nvd_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
        resp = requests.get(nvd_url)
        if resp.status_code == 200:
            data = resp.json()
            # (Data parsing and DB insertion logic here...)

            rendered_html = render_template('faucet.html', data=data)
            os.makedirs('cache', exist_ok=True)
            with open(cache_path, 'w', encoding='utf-8') as f:
                f.write(rendered_html)

            cursor.close()
            conn.close()
            return redirect(url_for('cve_page', cve_id=cve_id))
        else:
            error = "Failed to fetch data. Try again later."
            cursor.close()
            conn.close()
            return render_template('faucet.html', error=error)

    return render_template('faucet.html')

@app.route('/<cve_id>/')
def cve_page(cve_id):
    if not CVE_PATTERN.match(cve_id):
        return "Invalid CVE ID", 404

    cache_path = f'cache/{cve_id}.html'
    if os.path.exists(cache_path):
        return send_file(cache_path)
    return "CVE not cached. Please query first.", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
