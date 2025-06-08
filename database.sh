#!/bin/bash
# Initialize and configure MySQL database for F.A.U.C.E.T.
# This will create the 'faucet' database, tables, and a user with appropriate privileges.
mysql -u root -p <<EOF
CREATE DATABASE IF NOT EXISTS faucet;
USE faucet;
-- Main CVE table (NVD data)
CREATE TABLE IF NOT EXISTS cve_main (
  cve_id VARCHAR(25) PRIMARY KEY,
  description TEXT,
  published_date DATE,
  last_modified_date DATE,
  cvss2_score FLOAT,
  cvss2_vector VARCHAR(100),
  cvss2_severity VARCHAR(20),
  cvss3_score FLOAT,
  cvss3_vector VARCHAR(200),
  cvss3_severity VARCHAR(20),
  last_fetch_date DATETIME
) ENGINE=InnoDB;
-- Table for CVE to CWE mappings
CREATE TABLE IF NOT EXISTS cve_cwe (
  cve_id VARCHAR(25),
  cwe_id VARCHAR(25),
  cwe_name VARCHAR(255),
  PRIMARY KEY (cve_id, cwe_id),
  FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB;
-- Table for affected product CPEs
CREATE TABLE IF NOT EXISTS cve_cpe (
  cve_id VARCHAR(25),
  cpe_uri VARCHAR(255),
  PRIMARY KEY (cve_id, cpe_uri),
  FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB;
-- Table for EPSS scores
CREATE TABLE IF NOT EXISTS cve_epss (
  cve_id VARCHAR(25) PRIMARY KEY,
  epss_score FLOAT,
  epss_percentile FLOAT,
  last_update DATE,
  FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB;
-- Table for Known Exploited Vulnerabilities (CISA KEV)
CREATE TABLE IF NOT EXISTS cve_kev (
  cve_id VARCHAR(25) PRIMARY KEY,
  date_added DATE,
  due_date DATE,
  FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB;
-- Table for exploit references
CREATE TABLE IF NOT EXISTS cve_exploits (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cve_id VARCHAR(25),
  source VARCHAR(50),
  info VARCHAR(255),
  detail TEXT,
  FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB;
-- Table for social media mentions
CREATE TABLE IF NOT EXISTS cve_social (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cve_id VARCHAR(25),
  platform VARCHAR(50),
  content TEXT,
  url TEXT,
  mention_date DATE,
  FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB;
-- Table for reference links
CREATE TABLE IF NOT EXISTS cve_refs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cve_id VARCHAR(25),
  url TEXT,
  description TEXT,
  FOREIGN KEY (cve_id) REFERENCES cve_main(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB;
-- Create an application user and grant privileges
CREATE USER IF NOT EXISTS 'faucetuser'@'localhost' IDENTIFIED BY 'StrongPassword!';
GRANT ALL PRIVILEGES ON faucet.* TO 'faucetuser'@'localhost';
FLUSH PRIVILEGES;
EOF
