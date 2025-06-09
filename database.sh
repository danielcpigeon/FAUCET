#!/bin/bash

# Database configuration script for F.A.U.C.E.T. (Free And Unrestricted CVE Enrichment Tool)

# Load environment variables
source /etc/environment

# Connect to MySQL and set up database and tables
mysql -u root -p <<EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;

USE ${DB_NAME};

-- Main table for CVE details
CREATE TABLE IF NOT EXISTS cve_main (
    cve_id VARCHAR(20) PRIMARY KEY,
    description TEXT,
    published_date DATETIME,
    last_modified_date DATETIME,
    last_fetch_date DATETIME
);

-- Table for CWE data
CREATE TABLE IF NOT EXISTS cwe (
    cve_id VARCHAR(20),
    cwe_id VARCHAR(20),
    name VARCHAR(255),
    PRIMARY KEY (cve_id, cwe_id),
    FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
);

-- Table for CPE data
CREATE TABLE IF NOT EXISTS cpe (
    cve_id VARCHAR(20),
    cpe_entry TEXT,
    PRIMARY KEY (cve_id, cpe_entry(255)),
    FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
);

-- Table for Risk scoring (CVSS, EPSS, KEV)
CREATE TABLE IF NOT EXISTS risk_scoring (
    cve_id VARCHAR(20) PRIMARY KEY,
    cvss3_score FLOAT,
    cvss3_severity VARCHAR(20),
    cvss3_vector VARCHAR(100),
    cvss2_score FLOAT,
    cvss2_severity VARCHAR(20),
    cvss2_vector VARCHAR(100),
    epss_score FLOAT,
    epss_percentile FLOAT,
    kev BOOLEAN,
    kev_date DATE,
    FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
);

-- Table for Exploit data
CREATE TABLE IF NOT EXISTS exploits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20),
    source VARCHAR(50),
    name VARCHAR(255),
    description TEXT,
    url TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
);

-- Table for Social Media mentions
CREATE TABLE IF NOT EXISTS social_mentions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20),
    platform VARCHAR(50),
    text TEXT,
    url TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
);

-- Table for References
CREATE TABLE IF NOT EXISTS references (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20),
    description TEXT,
    url TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id)
);

EOF

# Indicate script completion
echo "Database setup complete."
