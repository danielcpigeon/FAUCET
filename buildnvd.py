#!/usr/bin/env python3
"""
buildnvd.py – Build local CVE database by fetching data from NVD and prioritizing 
known exploited and critical CVEs.
"""
import os
import json
import requests
import pymysql
from datetime import datetime, timedelta

# Load API keys from environment file (if available)
if os.path.exists("API_Keys.txt"):
    with open("API_Keys.txt") as f:
        for line in f:
            if '=' in line:
                key, val = line.strip().split('=', 1)
                os.environ[key] = val

# Configuration: database connection settings (ensure DB is set up via database.sh)
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_NAME = os.getenv('DB_NAME', 'faucet')
DB_USER = os.getenv('DB_USER', 'faucetuser')
DB_PASS = os.getenv('DB_PASS', 'StrongPassword!')  # use the password set in database.sh

# NVD API base URL and optional API key for higher rate limits
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv('NVD_API_KEY')  # if provided

def get_nvd_cve(cve_id):
    """Fetch CVE details from NVD API:contentReference[oaicite:0]{index=0} and return JSON data or None."""
    params = {"cveId": cve_id}
    if NVD_API_KEY:
        params["apiKey"] = NVD_API_KEY
    try:
        resp = requests.get(NVD_API_BASE, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            # NVD API returns a 'vulnerabilities' list for the query
            if data.get("vulnerabilities"):
                return data["vulnerabilities"][0]["cve"]  # first (and only) CVE item
    except Exception as e:
        print(f"Error fetching {cve_id} from NVD: {e}")
    return None

def fetch_recent_critical():
    """Fetch recent (last 30 days) critical CVEs from NVD and return a list of CVE JSON data."""
    critical_cves = []
    # Set time window for recent CVEs (e.g., last 30 days)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    # Format dates to ISO8601 with milliseconds for NVD API
    start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    start_index = 0
    results_per_page = 100
    total_results = 1
    # Iterate through paginated results for critical CVEs
    while start_index < total_results:
        params = {
            "pubStartDate": start_str,
            "pubEndDate": end_str,
            "cvssV3Severity": "CRITICAL",
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        }
        if NVD_API_KEY:
            params["apiKey"] = NVD_API_KEY
        try:
            resp = requests.get(NVD_API_BASE, params=params, timeout=15)
            if resp.status_code != 200:
                print(f"NVD API returned status {resp.status_code} for recent critical query")
                break
            data = resp.json()
            total_results = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                critical_cves.append(item["cve"])
            start_index += results_per_page
        except Exception as e:
            print(f"Error fetching recent critical CVEs: {e}")
            break
    return critical_cves

# Connect to MySQL database
conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
cursor = conn.cursor()

# 1. Fetch CISA Known Exploited Vulnerabilities (KEV) list (JSON feed):contentReference[oaicite:1]{index=1}
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kev_cves = []
try:
    resp = requests.get(kev_url, timeout=10)
    if resp.status_code == 200:
        kev_data = resp.json()
        vulnerabilities = kev_data.get("vulnerabilities") or kev_data.get("Vulnerabilities") or kev_data.get("catalogItems")
        if not vulnerabilities:
            # If JSON structure is nested, try deeper (some versions wrap data differently)
            vulnerabilities = kev_data.get("body", {}).get("vulnerabilities", [])
        for item in vulnerabilities:
            cve = item.get("cveID") or item.get("cve") or item.get("CVE")
            if cve:
                kev_cves.append({
                    "cve_id": cve,
                    "date_added": item.get("dateAdded") or item.get("date_added"),
                    "due_date": item.get("dueDate") or item.get("due_date")
                })
                # Insert into cve_kev table (ignore if exists)
                try:
                    cursor.execute(
                        "INSERT IGNORE INTO cve_kev (cve_id, date_added, due_date) VALUES (%s, %s, %s)",
                        (cve, item.get("dateAdded") or item.get("date_added"), item.get("dueDate") or item.get("due_date"))
                    )
                except Exception as db_e:
                    print(f"DB insert error for KEV {cve}: {db_e}")
        conn.commit()
        print(f"Loaded KEV catalog with {len(kev_cves)} CVEs.")
    else:
        print(f"Failed to fetch KEV JSON (status {resp.status_code})")
except Exception as e:
    print(f"Error fetching KEV data: {e}")

# 2. For each CVE in KEV list, fetch from NVD and store if not present
for kev_entry in kev_cves:
    cve_id = kev_entry["cve_id"]
    # Check if CVE already in database
    cursor.execute("SELECT cve_id, last_fetch_date FROM cve_main WHERE cve_id=%s", (cve_id,))
    row = cursor.fetchone()
    if row:
        # Already in DB; optionally could update if outdated (not done here for efficiency)
        continue
    cve_json = get_nvd_cve(cve_id)
    if not cve_json:
        continue  # skip if not found or error
    # Parse NVD CVE JSON fields
    desc = ""
    if cve_json.get("descriptions"):
        # find English description
        for d in cve_json["descriptions"]:
            if d.get("lang", "") == "en":
                desc = d.get("value", "")
                break
    dates = cve_json.get("published", ""), cve_json.get("lastModified", "")
    pub_date = dates[0].split("T")[0] if dates[0] else None
    mod_date = dates[1].split("T")[0] if dates[1] else None
    # CVSS metrics (if present)
    cvss2_score = cvss2_vector = cvss2_sev = None
    cvss3_score = cvss3_vector = cvss3_sev = None
    metrics = cve_json.get("metrics", {})
    # The NVD JSON might have multiple products CVSS, but use NVD's own if available
    if "cvssMetricV31" in metrics:
        cvss3 = metrics["cvssMetricV31"][0]["cvssData"]
        cvss3_score = cvss3.get("baseScore")
        cvss3_vector = cvss3.get("vectorString")
        cvss3_sev = cvss3.get("baseSeverity")
    elif "cvssMetricV30" in metrics:  # sometimes v3.0
        cvss3 = metrics["cvssMetricV30"][0]["cvssData"]
        cvss3_score = cvss3.get("baseScore")
        cvss3_vector = cvss3.get("vectorString")
        cvss3_sev = cvss3.get("baseSeverity")
    if "cvssMetricV2" in metrics:
        cvss2 = metrics["cvssMetricV2"][0]["cvssData"]
        cvss2_score = cvss2.get("baseScore")
        cvss2_vector = cvss2.get("vectorString")
        cvss2_sev = cvss2.get("baseSeverity")
    # Insert into main CVE table
    try:
        cursor.execute(
            "INSERT INTO cve_main (cve_id, description, published_date, last_modified_date, "
            "cvss2_score, cvss2_vector, cvss2_severity, cvss3_score, cvss3_vector, cvss3_severity, last_fetch_date) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (cve_id, desc, pub_date, mod_date, cvss2_score, cvss2_vector, cvss2_sev,
             cvss3_score, cvss3_vector, cvss3_sev, datetime.utcnow())
        )
    except Exception as db_e:
        print(f"DB insert error for CVE {cve_id}: {db_e}")
        continue
    # Insert weaknesses (CWE)
    weaknesses = cve_json.get("weaknesses", [])
    for w in weaknesses:
        for d in w.get("description", []):
            cwe_id = d.get("value")
            if cwe_id:
                # Optionally fetch CWE name from MITRE (not done here due to offline)
                cursor.execute("INSERT IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (%s, %s)", (cve_id, cwe_id))
    # Insert configurations (CPEs)
    configs = cve_json.get("configurations", {}).get("nodes", [])
    cpe_set = set()
    for node in configs:
        for match in node.get("cpeMatch", []):
            cpe_uri = match.get("criteria") or match.get("cpe23Uri")
            if cpe_uri:
                cpe_set.add(cpe_uri)
    for cpe_uri in cpe_set:
        cursor.execute("INSERT IGNORE INTO cve_cpe (cve_id, cpe_uri) VALUES (%s, %s)", (cve_id, cpe_uri))
    # Insert references
    for ref in cve_json.get("references", []):
        url = ref.get("url")
        desc = None
        tags = ref.get("tags")
        if tags:
            desc = ", ".join(tags)  # combine tags as description (e.g., Vendor Advisory, Exploit)
        cursor.execute("INSERT IGNORE INTO cve_refs (cve_id, url, description) VALUES (%s, %s, %s)", 
                       (cve_id, url, desc))
    # (EPSS and exploit data will be fetched during web request or separate enrichment, not here to keep script light)
    conn.commit()
    print(f"Inserted CVE {cve_id} from KEV into database.")

# 3. Fetch recent critical CVEs and add to database if not present
critical_cves = fetch_recent_critical()
print(f"Fetched {len(critical_cves)} recent critical CVEs from NVD.")
for cve in critical_cves:
    cve_id = cve["id"] if isinstance(cve, dict) and cve.get("id") else cve.get("cveId", "")
    if not cve_id:
        continue
    cursor.execute("SELECT cve_id FROM cve_main WHERE cve_id=%s", (cve_id,))
    if cursor.fetchone():
        continue  # already in DB
    # Similar parsing as above for each CVE
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    pub_date = cve.get("published", "").split("T")[0] or None
    mod_date = cve.get("lastModified", "").split("T")[0] or None
    cvss2_score = cvss2_vector = cvss2_sev = None
    cvss3_score = cvss3_vector = cvss3_sev = None
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        cvss3 = metrics["cvssMetricV31"][0]["cvssData"]
        cvss3_score = cvss3.get("baseScore"); cvss3_vector = cvss3.get("vectorString"); cvss3_sev = cvss3.get("baseSeverity")
    elif "cvssMetricV30" in metrics:
        cvss3 = metrics["cvssMetricV30"][0]["cvssData"]
        cvss3_score = cvss3.get("baseScore"); cvss3_vector = cvss3.get("vectorString"); cvss3_sev = cvss3.get("baseSeverity")
    if "cvssMetricV2" in metrics:
        cvss2 = metrics["cvssMetricV2"][0]["cvssData"]
        cvss2_score = cvss2.get("baseScore"); cvss2_vector = cvss2.get("vectorString"); cvss2_sev = cvss2.get("baseSeverity")
    try:
        cursor.execute(
            "INSERT INTO cve_main (cve_id, description, published_date, last_modified_date, "
            "cvss2_score, cvss2_vector, cvss2_severity, cvss3_score, cvss3_vector, cvss3_severity, last_fetch_date) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (cve_id, desc, pub_date, mod_date, cvss2_score, cvss2_vector, cvss2_sev,
             cvss3_score, cvss3_vector, cvss3_sev, datetime.utcnow())
        )
    except Exception as db_e:
        print(f"DB insert error for CVE {cve_id}: {db_e}")
        continue
    # Weaknesses
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            cwe_id = d.get("value")
            if cwe_id:
                cursor.execute("INSERT IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (%s, %s)", (cve_id, cwe_id))
    # Configurations (CPEs)
    configs = cve.get("configurations", {}).get("nodes", [])
    cpe_set = set()
    for node in configs:
        for match in node.get("cpeMatch", []):
            cpe_uri = match.get("criteria") or match.get("cpe23Uri")
            if cpe_uri:
                cpe_set.add(cpe_uri)
    for cpe_uri in cpe_set:
        cursor.execute("INSERT IGNORE INTO cve_cpe (cve_id, cpe_uri) VALUES (%s, %s)", (cve_id, cpe_uri))
    # References
    for ref in cve.get("references", []):
        url = ref.get("url")
        desc = None
        tags = ref.get("tags")
        if tags:
            desc = ", ".join(tags)
        cursor.execute("INSERT IGNORE INTO cve_refs (cve_id, url, description) VALUES (%s, %s, %s)",
                       (cve_id, url, desc))
    conn.commit()
    print(f"Inserted recent critical CVE {cve_id} into database.")

# Close DB connection
cursor.close()
conn.close()
print("Build process completed.")
