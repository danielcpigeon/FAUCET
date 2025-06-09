#!/usr/bin/env python3
"""
buildnvd.py – Script to fetch CVE data from the NIST NVD API and store it in the local MySQL database for F.A.U.C.E.T.
"""
import os
import pymysql
import requests
from datetime import datetime

# Configuration from environment variables
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "faucet")
DB_USER = os.getenv("DB_USER", "faucetuser")
DB_PASS = os.getenv("DB_PASS", "StrongPassword!")
NVD_API_KEY = os.getenv("NVD_API_KEY")


# Connect to the database
def get_db_connection():
    """Return a database connection with utf8mb4 charset."""
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        db=DB_NAME,
        charset="utf8mb4",
        autocommit=True,
    )


# Fetch CVE data from NVD API
def fetch_nvd_data(cve_id):
    if not NVD_API_KEY:
        raise RuntimeError("NVD_API_KEY environment variable is not set")

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


# Insert or update CVE data into DB
def store_cve_data(conn, cve_id, data):
    """Insert or update a single CVE record."""
    description = data["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]
    published_date = data["vulnerabilities"][0]["cve"]["published"]
    last_modified_date = data["vulnerabilities"][0]["cve"]["lastModified"]

    with conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO cve_main (
                cve_id, description, published_date, last_modified_date, last_fetch_date
            ) VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                description = VALUES(description),
                published_date = VALUES(published_date),
                last_modified_date = VALUES(last_modified_date),
                last_fetch_date = VALUES(last_fetch_date)
            """,
            (
                cve_id,
                description,
                published_date,
                last_modified_date,
                datetime.utcnow(),
            ),
        )


# Main script execution
def main():
    """Fetch sample CVEs and store them in the database."""
    # Example CVE list; replace with actual retrieval logic
    cve_list = ["CVE-2024-21401", "CVE-2024-12345"]

    with get_db_connection() as conn:
        for cve_id in cve_list:
            try:
                data = fetch_nvd_data(cve_id)
                store_cve_data(conn, cve_id, data)
                print(f"Stored data for {cve_id}")
            except Exception as e:
                print(f"Error fetching/storing data for {cve_id}: {e}")


if __name__ == "__main__":
    main()
