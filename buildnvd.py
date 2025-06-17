#!/usr/bin/env python3
"""Utility for pulling CVE information from the NVD API.

This script fetches data for one or more CVE identifiers from the
`services.nvd.nist.gov` API and stores the results in a local MySQL
database used by F.A.U.C.E.T.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

import pymysql
import requests

# Configuration from environment variables.  These defaults mirror the values
# used by the rest of the project so the script works out of the box.
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "faucet")
DB_USER = os.getenv("DB_USER", "faucetuser")
DB_PASS = os.getenv("DB_PASS", "StrongPassword!")

# An NVD API key is required for successful requests.
NVD_API_KEY = os.getenv("NVD_API_KEY")


# Connect to the database
def get_db_connection() -> pymysql.connections.Connection:
    """Return a database connection configured for UTF-8."""
    try:
        return pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            db=DB_NAME,
            charset="utf8mb4",
            autocommit=True,
        )
    except pymysql.MySQLError as exc:
        # Provide a clear message if credentials are wrong or the server is not
        # reachable.  Raising ``SystemExit`` keeps the stack trace short for the
        # end user.
        raise SystemExit(f"Database connection failed: {exc}") from exc


# Fetch CVE data from NVD API
def fetch_nvd_data(cve_id: str) -> dict:
    """Retrieve JSON data for ``cve_id`` from the NVD API."""
    if not NVD_API_KEY:
        raise RuntimeError("NVD_API_KEY environment variable is not set")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        resp = requests.get(
            url, params={"cveId": cve_id}, headers={"apiKey": NVD_API_KEY}, timeout=30
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to fetch {cve_id}: {exc}") from exc
    return resp.json()


# Insert or update CVE data into DB
def store_cve_data(conn: pymysql.connections.Connection, cve_id: str, data: dict) -> None:
    """Insert or update a single CVE record."""
    vuln = data.get("vulnerabilities", [{}])[0]
    cve = vuln.get("cve", {})
    desc = ""
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            desc = entry.get("value", "")
            break
    if not desc and cve.get("descriptions"):
        desc = cve["descriptions"][0].get("value", "")

    published_date = cve.get("published")
    last_modified_date = cve.get("lastModified")

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
                desc,
                published_date,
                last_modified_date,
                datetime.utcnow(),
            ),
        )


# Main script execution
def main(args: list[str]) -> int:
    """Fetch CVE entries provided on the command line."""
    if not args:
        print("Usage: buildnvd.py CVE-ID [CVE-ID ...]", file=sys.stderr)
        return 1

    with get_db_connection() as conn:
        for cve_id in args:
            try:
                data = fetch_nvd_data(cve_id)
                store_cve_data(conn, cve_id, data)
                print(f"Stored data for {cve_id}")
            except Exception as exc:
                print(f"Error processing {cve_id}: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

