#!/usr/bin/env python3
"""
app.py – Flask web application for F.A.U.C.E.T. (Free And Unrestricted CVE Enrichment Tool).
Renders a CVE search form, fetches CVE data from cache/various APIs, and serves detailed CVE pages.
"""
import os
import re
import json
import logging
from datetime import datetime, timedelta

import requests
import pymysql
from flask import Flask, request, render_template, redirect, url_for, abort, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from requests.auth import HTTPBasicAuth

# Configuration variables loaded from /etc/environment
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "faucet")
DB_USER = os.getenv("DB_USER", "faucetuser")
DB_PASS = os.getenv("DB_PASS", "StrongPassword!")
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
GCP_API_KEY = os.getenv("GCP_API_KEY")
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
NVD_API_KEY = os.getenv("NVD_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # GitHub API token for higher rate limits
REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID")  # Reddit API credentials
REDDIT_SECRET = os.getenv("REDDIT_SECRET")
REDDIT_REDIRECT_URI = "https://cve.danielcpigeon.com/search"
TWITTER_BEARER_TOKEN = os.getenv("TWITTER_BEARER_TOKEN")  # Twitter API token

# Initialize Flask app
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["2 per minute"])

# Set up logging
logging.basicConfig(
    filename="faucet.log",
    level=logging.INFO,
    format="%(asctime)s %(remote_addr)s %(user_agent)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Reusable HTTP session
session = requests.Session()
session.headers.update({"User-Agent": "FaucetCVE/1.0"})

# Precompiled CVE ID pattern
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


# Verify reCAPTCHA Enterprise response
def verify_recaptcha(token):
    url = f"https://recaptchaenterprise.googleapis.com/v1/projects/{GCP_PROJECT_ID}/assessments?key={GCP_API_KEY}"
    payload = {
        "event": {
            "token": token,
            "siteKey": RECAPTCHA_SITE_KEY,
            "expectedAction": "LOGIN",
        }
    }
    try:
        resp = session.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        logging.error("reCAPTCHA verification failed: %s", exc)
        return {}


# Utility: Database connection (helper function to get a new connection)
def get_db_connection():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)

# Utility: Fetch EPSS score for a CVE (using FIRST.org EPSS API:contentReference[oaicite:3]{index=3})
def fetch_epss(cve_id):
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        resp = session.get(epss_url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            # data['data'] is a list of CVE info with 'epss' and 'percentile'
            if data.get("data"):
                entry = data["data"][0]
                score = entry.get("epss")
                percentile = entry.get("percentile")
                return float(score) if score is not None else None, float(percentile) if percentile is not None else None
    except Exception as e:
        logging.error(f"EPSS fetch error for {cve_id}: {e}")
    return None, None

# Utility: Check if CVE is in CISA KEV (Known Exploited) list (by checking local DB or KEV API)
def check_kev(cve_id, db_cursor):
    # First check local database (cve_kev table)
    db_cursor.execute("SELECT date_added FROM cve_kev WHERE cve_id=%s", (cve_id,))
    row = db_cursor.fetchone()
    if row:
        date_added = row[0]
        return True, date_added
    # If not found locally, optionally check live KEV API for assurance
    try:
        kev_check_url = f"https://kevin.gtfkd.com/kev/exists?cve={cve_id}"  # KEVin API for KEV:contentReference[oaicite:4]{index=4}
        resp = session.get(kev_check_url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if "exists" in data:
                exists = data["exists"]
                if exists:
                    # Fetch details for date if needed
                    detail_resp = session.get(f"https://kevin.gtfkd.com/kev/{cve_id}", timeout=5)
                    if detail_resp.status_code == 200:
                        detail = detail_resp.json()
                        date_added = detail.get("dateAdded") or detail.get("date_added")
                        # Save to DB for future
                        try:
                            db_cursor.execute("INSERT IGNORE INTO cve_kev (cve_id, date_added) VALUES (%s, %s)", (cve_id, date_added))
                        except Exception:
                            pass
                        return True, date_added
                    return True, None
    except Exception as e:
        logging.warning(f"KEV lookup failed for {cve_id}: {e}")
    return False, None

# Utility: Search Exploit-DB for exploits by CVE (web scrape)
def search_exploitdb(cve_id):
    exploits = []
    url = f"https://www.exploit-db.com/search?cve={cve_id}"
    headers = {"User-Agent": "FaucetCVE/1.0"}
    try:
        resp = session.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            text = resp.text
            # Find exploit entries in the HTML (id and title)
            matches = re.findall(r'/exploits/(\d+)">\s*([^<]+)\s*</a>', text)
            found_ids = set()
            for exploit_id, title in matches:
                if exploit_id in found_ids:
                    continue  # avoid duplicates
                found_ids.add(exploit_id)
                exploits.append({"source": "ExploitDB", "id": exploit_id, "title": title.strip(), 
                                 "url": f"https://www.exploit-db.com/exploits/{exploit_id}"})
    except Exception as e:
        logging.error(f"ExploitDB search error for {cve_id}: {e}")
    return exploits

# Utility: Search Metasploit modules on GitHub for a CVE reference
def search_metasploit(cve_id):
    results = []
    query = f'"{cve_id}" repo:rapid7/metasploit-framework'
    api_url = f"https://api.github.com/search/code?q={query}"
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    try:
        resp = session.get(api_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                file_path = item.get("path", "")
                html_url = item.get("html_url", "")
                # Only include exploits (to filter out documentation or other mentions)
                if "/exploits/" in file_path or "/auxiliary/" in file_path or "/post/" in file_path:
                    module_name = file_path.split("/")[-1]
                    results.append({"source": "Metasploit", "name": module_name, "url": html_url})
    except Exception as e:
        logging.error(f"Metasploit search error for {cve_id}: {e}")
    return results

# Utility: Search Nuclei template repository for CVE
def search_nuclei_templates(cve_id):
    results = []
    query = f'"{cve_id}" repo:projectdiscovery/nuclei-templates'
    api_url = f"https://api.github.com/search/code?q={query}"
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    try:
        resp = session.get(api_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                file_name = item.get("name")
                html_url = item.get("html_url", "")
                if file_name:
                    results.append({"source": "Nuclei", "name": file_name, "url": html_url})
    except Exception as e:
        logging.error(f"Nuclei search error for {cve_id}: {e}")
    return results

# Utility: Search social media (Twitter, Reddit, etc.) for CVE mentions
def search_social(cve_id):
    mentions = []
    # Twitter search via API (if token provided)
    if TWITTER_BEARER_TOKEN:
        twitter_api = "https://api.twitter.com/2/tweets/search/recent"
        query = f"{cve_id} -is:retweet lang:en"
        headers = {"Authorization": f"Bearer {TWITTER_BEARER_TOKEN}"}
        params = {"query": query, "max_results": 5, "tweet.fields": "text,created_at,author_id"}
        try:
            resp = session.get(twitter_api, headers=headers, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                for tweet in data.get("data", []):
                    text = tweet.get("text", "")
                    tid = tweet.get("id")
                    url = f"https://twitter.com/i/web/status/{tid}"
                    mentions.append({"platform": "Twitter", "text": text[:100] + "...", "url": url})
        except Exception as e:
            logging.error(f"Twitter API error: {e}")
    # Reddit search via API (if credentials provided)
    if REDDIT_CLIENT_ID and REDDIT_SECRET:
        try:
            # Obtain a temporary app-only OAuth token
            auth = requests.auth.HTTPBasicAuth(REDDIT_CLIENT_ID, REDDIT_SECRET)
            data = {"grant_type": "client_credentials"}
            headers = {"User-Agent": "FaucetCVE/1.0"}
            token_res = session.post("https://www.reddit.com/api/v1/access_token", auth=auth, data=data, headers=headers)
            if token_res.status_code == 200:
                token = token_res.json().get("access_token")
                if token:
                    headers["Authorization"] = f"bearer {token}"
                    search_res = session.get(f"https://oauth.reddit.com/search?q={cve_id}&limit=5", headers=headers)
                    if search_res.status_code == 200:
                        posts = search_res.json().get("data", {}).get("children", [])
                        for post in posts:
                            post_data = post.get("data", {})
                            title = post_data.get("title", "")
                            url = "https://reddit.com" + post_data.get("permalink", "")
                            mentions.append({"platform": "Reddit", "text": title[:100] + "...", "url": url})
        except Exception as e:
            logging.error(f"Reddit API error: {e}")
    # (Bluesky and Infosec Exchange integration would go here if APIs/credentials available)
    return mentions

# Route: Home page with search form
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("2 per minute")  # limit form submissions:contentReference[oaicite:5]{index=5}
def index():
    if request.method == 'GET':
        # Render initial search page
        return render_template('faucet.html', recaptcha_site_key=RECAPTCHA_SITE_KEY, data=None, error=None)
    # POST: handle search query
    user_ip = request.remote_addr or "UNKNOWN"
    user_agent = request.headers.get('User-Agent', '')[:100]
    cve_id = request.form.get('cve_id', '').strip()
    # Validate CVE ID format
    if not CVE_PATTERN.match(cve_id):
        error_msg = "Invalid CVE ID format. Please use CVE-YYYY-XXXX."
        logging.info({"remote_addr": user_ip, "user_agent": user_agent, "message": f"Invalid CVE format: {cve_id}"})
        return render_template('faucet.html', recaptcha_site_key=RECAPTCHA_SITE_KEY, data=None, error=error_msg)
    cve_id = cve_id.upper()
    # Verify reCAPTCHA v3 token with Google:contentReference[oaicite:6]{index=6}
    token = request.form.get('recaptcha_token')
    if RECAPTCHA_SECRET_KEY:
        try:
            verify_resp = session.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={'secret': RECAPTCHA_SECRET_KEY, 'response': token, 'remoteip': user_ip},
                timeout=5,
            )
            verify_result = verify_resp.json()
        except Exception as e:
            verify_result = {}
            logging.error(f"reCAPTCHA verification error: {e}")
        # Check if verification passed and score acceptable
        if not verify_result.get('success') or verify_result.get('score', 0) < 0.5:
            error_msg = "reCAPTCHA validation failed. Please try again."
            logging.warning(f"Failed reCAPTCHA for IP {user_ip}, CVE {cve_id}")
            return render_template('faucet.html', recaptcha_site_key=RECAPTCHA_SITE_KEY, data=None, error=error_msg)
    # Start processing the CVE query
    start_time = datetime.utcnow()
    conn = get_db_connection()
    cursor = conn.cursor()
    # Check cache: if CVE exists in DB and data is recent (<180 days)
    cursor.execute("SELECT last_fetch_date FROM cve_main WHERE cve_id=%s", (cve_id,))
    row = cursor.fetchone()
    data = {}
    use_cache = False
    if row:
        last_fetch = row[0]
        if last_fetch and datetime.utcnow() - last_fetch < timedelta(days=180):
            use_cache = True
    # If cached data is available and fresh, retrieve from DB
    if use_cache:
        # Fetch main info
        cursor.execute("SELECT description, published_date, last_modified_date, cvss2_score, cvss2_vector, cvss2_severity, cvss3_score, cvss3_vector, cvss3_severity FROM cve_main WHERE cve_id=%s", (cve_id,))
        main = cursor.fetchone()
        if main:
            desc, pub_date, mod_date, cvss2_score, cvss2_vec, cvss2_sev, cvss3_score, cvss3_vec, cvss3_sev = main
            data["cve_id"] = cve_id
            data["description"] = desc
            data["published_date"] = pub_date
            data["last_modified"] = mod_date
            data["cvss2_score"] = cvss2_score; data["cvss2_vector"] = cvss2_vec; data["cvss2_severity"] = cvss2_sev
            data["cvss3_score"] = cvss3_score; data["cvss3_vector"] = cvss3_vec; data["cvss3_severity"] = cvss3_sev
        # CWE list
        cursor.execute("SELECT cwe_id, cwe_name FROM cve_cwe WHERE cve_id=%s", (cve_id,))
        cwes = cursor.fetchall()
        data["cwe_list"] = []
        for cwe_id_val, cwe_name in cwes:
            data["cwe_list"].append({"id": cwe_id_val, "name": cwe_name if cwe_name else "Unknown"})
        # CPE list
        cursor.execute("SELECT cpe_uri FROM cve_cpe WHERE cve_id=%s", (cve_id,))
        cpe_rows = cursor.fetchall()
        data["cpe_list"] = []
        for (cpe_uri,) in cpe_rows:
            # Simplify CPE URI to vendor product version
            parts = cpe_uri.split(":")
            if len(parts) > 5:
                vendor = parts[3]; product = parts[4]
                version = parts[5] if parts[5] not in ["*", "-"] else "Multiple versions"
                data["cpe_list"].append(f"{vendor} {product} {version}")
            else:
                data["cpe_list"].append(cpe_uri)
        # Risk scores (EPSS, KEV) from DB
        cursor.execute("SELECT epss_score, epss_percentile FROM cve_epss WHERE cve_id=%s", (cve_id,))
        epss_row = cursor.fetchone()
        if epss_row:
            data["epss_score"], data["epss_percentile"] = epss_row
        else:
            data["epss_score"], data["epss_percentile"] = None, None
        cursor.execute("SELECT date_added FROM cve_kev WHERE cve_id=%s", (cve_id,))
        kev_row = cursor.fetchone()
        if kev_row:
            data["kev"] = True
            data["kev_date"] = kev_row[0]
        else:
            data["kev"] = False
            data["kev_date"] = None
        # Exploits
        cursor.execute("SELECT source, info, detail FROM cve_exploits WHERE cve_id=%s", (cve_id,))
        exploit_rows = cursor.fetchall()
        data["exploits"] = []
        for source, info, detail in exploit_rows:
            if source == "ExploitDB":
                exp = {"source": source, "id": info, "title": detail if detail else "", "url": f"https://www.exploit-db.com/exploits/{info}"}
            elif source == "Metasploit":
                exp = {"source": source, "name": info, "url": detail if detail else ""}
            elif source == "Nuclei":
                exp = {"source": source, "name": info, "url": detail if detail else ""}
            elif source == "GitHub":
                exp = {"source": source, "description": info, "url": detail if detail else ""}
            else:
                exp = {"source": source, "info": info, "url": detail if detail else ""}
            data["exploits"].append(exp)
        # Social mentions
        cursor.execute("SELECT platform, content, url FROM cve_social WHERE cve_id=%s", (cve_id,))
        social_rows = cursor.fetchall()
        data["social"] = []
        for platform, content, url in social_rows:
            data["social"].append({"platform": platform, "text": content, "url": url})
        # References
        cursor.execute("SELECT url, description FROM cve_refs WHERE cve_id=%s", (cve_id,))
        ref_rows = cursor.fetchall()
        data["references"] = []
        for url, desc in ref_rows:
            desc_text = desc
            if not desc_text:
                # derive a simple description if none
                if "://".encode() in url.encode():  # just a check for URL
                    desc_text = url
            data["references"].append({"url": url, "description": desc_text})
    else:
        # Not cached or stale: fetch fresh data from APIs
        data["cve_id"] = cve_id
        # Fetch CVE from NVD API:contentReference[oaicite:7]{index=7}
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        if NVD_API_KEY:
            nvd_url += f"&apiKey={NVD_API_KEY}"
        cve_json = {}
        try:
            nvd_resp = session.get(nvd_url, timeout=10)
            if nvd_resp.status_code == 200:
                result = nvd_resp.json()
                if result.get("vulnerabilities"):
                    cve_json = result["vulnerabilities"][0]["cve"]
        except Exception as e:
            logging.error(f"NVD API fetch failed for {cve_id}: {e}")
        # Parse NVD data
        desc = ""
        for d in cve_json.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        data["description"] = desc
        data["published_date"] = (cve_json.get("published", "").split("T")[0] or None)
        data["last_modified"] = (cve_json.get("lastModified", "").split("T")[0] or None)
        # CVSS scores
        data["cvss2_score"] = data["cvss2_vector"] = data["cvss2_severity"] = None
        data["cvss3_score"] = data["cvss3_vector"] = data["cvss3_severity"] = None
        metrics = cve_json.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss3 = metrics["cvssMetricV31"][0]["cvssData"]
            data["cvss3_score"] = cvss3.get("baseScore"); data["cvss3_vector"] = cvss3.get("vectorString"); data["cvss3_severity"] = cvss3.get("baseSeverity")
        elif "cvssMetricV30" in metrics:
            cvss3 = metrics["cvssMetricV30"][0]["cvssData"]
            data["cvss3_score"] = cvss3.get("baseScore"); data["cvss3_vector"] = cvss3.get("vectorString"); data["cvss3_severity"] = cvss3.get("baseSeverity")
        if "cvssMetricV2" in metrics:
            cvss2 = metrics["cvssMetricV2"][0]["cvssData"]
            data["cvss2_score"] = cvss2.get("baseScore"); data["cvss2_vector"] = cvss2.get("vectorString"); data["cvss2_severity"] = cvss2.get("baseSeverity")
        # CWE list
        data["cwe_list"] = []
        cwe_ids = []
        for w in cve_json.get("weaknesses", []):
            for d in w.get("description", []):
                cwe_val = d.get("value")
                if cwe_val:
                    cwe_ids.append(cwe_val)
                    # Attempt to get CWE name (if not present, can fetch from MITRE, here we skip name fetch for brevity)
                    data["cwe_list"].append({"id": cwe_val, "name": None})
        # CPE list (affected products)
        data["cpe_list"] = []
        cpe_set = set()
        for node in cve_json.get("configurations", {}).get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe_uri = match.get("criteria") or match.get("cpe23Uri")
                if cpe_uri:
                    cpe_set.add(cpe_uri)
        for cpe_uri in cpe_set:
            # Simplify cpe to vendor product version for display
            parts = cpe_uri.split(":")
            if len(parts) > 5:
                vendor = parts[3]; product = parts[4]
                version = parts[5] if parts[5] not in ["*", "-"] else "Multiple versions"
                data["cpe_list"].append(f"{vendor} {product} {version}")
            else:
                data["cpe_list"].append(cpe_uri)
        # EPSS score
        epss_score, epss_percentile = fetch_epss(cve_id)
        data["epss_score"] = epss_score
        data["epss_percentile"] = epss_percentile
        # KEV status
        kev_bool, kev_date = check_kev(cve_id, cursor)
        data["kev"] = kev_bool
        data["kev_date"] = kev_date
        # Exploits (search various sources)
        data["exploits"] = []
        # Exploit-DB
        exploits_db = search_exploitdb(cve_id)
        data["exploits"].extend(exploits_db)
        # Metasploit
        exploits_ms = search_metasploit(cve_id)
        data["exploits"].extend(exploits_ms)
        # Nuclei
        exploits_nuclei = search_nuclei_templates(cve_id)
        data["exploits"].extend(exploits_nuclei)
        # (Optional: search generic GitHub for PoC repositories could be added)
        # Social mentions
        data["social"] = search_social(cve_id)
        # References
        data["references"] = []
        for ref in cve_json.get("references", []):
            url = ref.get("url", "")
            desc = None
            tags = ref.get("tags")
            if tags:
                desc = ", ".join(tags)
            data["references"].append({"url": url, "description": desc})
        # Write fetched data to database (cache it)
        # Insert/update main CVE record
        try:
            cursor.execute("REPLACE INTO cve_main (cve_id, description, published_date, last_modified_date, "
                           "cvss2_score, cvss2_vector, cvss2_severity, cvss3_score, cvss3_vector, cvss3_severity, last_fetch_date) "
                           "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                           (cve_id, data["description"], data["published_date"], data["last_modified"],
                            data["cvss2_score"], data["cvss2_vector"], data["cvss2_severity"],
                            data["cvss3_score"], data["cvss3_vector"], data["cvss3_severity"], datetime.utcnow()))
        except Exception as e:
            logging.error(f"DB insert main failed for {cve_id}: {e}")
        # CWE entries
        for cwe_val in cwe_ids:
            try:
                cursor.execute("INSERT IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (%s, %s)", (cve_id, cwe_val))
            except Exception:
                pass
        # CPE entries
        for cpe_uri in cpe_set:
            try:
                cursor.execute("INSERT IGNORE INTO cve_cpe (cve_id, cpe_uri) VALUES (%s, %s)", (cve_id, cpe_uri))
            except Exception:
                pass
        # EPSS
        if epss_score is not None:
            try:
                cursor.execute("REPLACE INTO cve_epss (cve_id, epss_score, epss_percentile, last_update) VALUES (%s, %s, %s, %s)",
                               (cve_id, epss_score, epss_percentile, datetime.utcnow().date()))
            except Exception:
                pass
        # KEV
        if kev_bool:
            try:
                cursor.execute("REPLACE INTO cve_kev (cve_id, date_added) VALUES (%s, %s)", (cve_id, kev_date))
            except Exception:
                pass
        # Exploits
        for exp in data["exploits"]:
            try:
                if exp["source"] == "ExploitDB":
                    cursor.execute("INSERT IGNORE INTO cve_exploits (cve_id, source, info, detail) VALUES (%s, %s, %s, %s)",
                                   (cve_id, "ExploitDB", exp.get("id"), exp.get("title")))
                elif exp["source"] == "Metasploit":
                    cursor.execute("INSERT IGNORE INTO cve_exploits (cve_id, source, info, detail) VALUES (%s, %s, %s, %s)",
                                   (cve_id, "Metasploit", exp.get("name"), exp.get("url")))
                elif exp["source"] == "Nuclei":
                    cursor.execute("INSERT IGNORE INTO cve_exploits (cve_id, source, info, detail) VALUES (%s, %s, %s, %s)",
                                   (cve_id, "Nuclei", exp.get("name"), exp.get("url")))
                elif exp["source"] == "GitHub":
                    cursor.execute("INSERT IGNORE INTO cve_exploits (cve_id, source, info, detail) VALUES (%s, %s, %s, %s)",
                                   (cve_id, "GitHub", exp.get("description"), exp.get("url")))
                else:
                    cursor.execute("INSERT IGNORE INTO cve_exploits (cve_id, source, info, detail) VALUES (%s, %s, %s, %s)",
                                   (cve_id, exp.get("source"), exp.get("id") or exp.get("name"), exp.get("url")))
            except Exception:
                continue
        # Social
        for mention in data["social"]:
            try:
                cursor.execute("INSERT IGNORE INTO cve_social (cve_id, platform, content, url, mention_date) VALUES (%s, %s, %s, %s, %s)",
                               (cve_id, mention.get("platform"), mention.get("text"), mention.get("url"), datetime.utcnow().date()))
            except Exception:
                continue
        # References
        for ref in data["references"]:
            try:
                cursor.execute("INSERT IGNORE INTO cve_refs (cve_id, url, description) VALUES (%s, %s, %s)",
                               (cve_id, ref.get("url"), ref.get("description")))
            except Exception:
                continue
        conn.commit()
    # Finished fetching data
    cursor.close()
    conn.close()
    # Log the query and duration
    duration = (datetime.utcnow() - start_time).total_seconds()
    logging.info(f"{user_ip} \"{user_agent}\" {cve_id} fetched_in {duration:.2f}s")
    # Render a unique page for the CVE and cache it to disk
    rendered_html = render_template('faucet.html', recaptcha_site_key=RECAPTCHA_SITE_KEY, data=data, error=None)
    # Save rendered page for caching (static HTML)
    cache_dir = "cache"
    if not os.path.isdir(cache_dir):
        os.makedirs(cache_dir)
    cache_path = os.path.join(cache_dir, f"{cve_id}.html")
    try:
        with open(cache_path, 'w', encoding='utf-8') as f:
            f.write(rendered_html)
    except Exception as e:
        logging.error(f"Failed to write cache file for {cve_id}: {e}")
    # Redirect to the CVE-specific page URL
    return redirect(url_for('cve_page', cve_id=cve_id))

# Route: Serve cached CVE page
@app.route('/<cve_id>/')
def cve_page(cve_id):
    # Only allow valid CVE pattern to avoid any malicious path input
    if not CVE_PATTERN.match(cve_id):
        abort(404)
    cache_path = os.path.join("cache", f"{cve_id}.html")
    if os.path.exists(cache_path):
        return send_file(cache_path)
    else:
        # If not cached, inform user to search via form (direct access not allowed without prior caching)
        abort(404)
