"""
database.py

Cloud-Ready Database Persistence Layer for DevSecOps Framework.
Supports Local SQLite, AWS EC2 / RDS PostgreSQL, and AWS RDS MySQL.
Normalizes risk summaries and control-level compliance results into dedicated tables.
"""

from __future__ import annotations

import os
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from security.common.logger import logger

DB_TYPE = os.getenv("DB_TYPE", "sqlite").lower()
DB_PATH = Path(os.getenv("DB_PATH", "compliance/db/security_framework.db"))


class DatabaseManager:
    """
    Manages Database Initialization, Schema Migrations, and Report Ingestion across SQLite, MySQL, and PostgreSQL.
    """

    def __init__(self, db_path: str | Path = DB_PATH, db_type: Optional[str] = None):
        self.db_path = Path(db_path)
        self.db_type = (db_type or DB_TYPE).lower()
        self.init_db()

    def get_connection(self):
        """
        Creates DB connection (SQLite for local, PyMySQL / mysql-connector for MySQL, psycopg2 for PostgreSQL).
        """
        if self.db_type == "sqlite":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            return conn

        elif self.db_type in ("mysql", "mariadb"):
            host = os.getenv("DB_HOST", "localhost")
            port = int(os.getenv("DB_PORT", 3306))
            db_name = os.getenv("DB_NAME", "sentinelops")
            user = os.getenv("DB_USER", "root")
            password = os.getenv("DB_PASSWORD", "")

            try:
                import pymysql
                try:
                    return pymysql.connect(
                        host=host, port=port, database=db_name,
                        user=user, password=password,
                        cursorclass=pymysql.cursors.DictCursor, autocommit=True
                    )
                except pymysql.err.OperationalError as op_err:
                    if len(op_err.args) > 0 and op_err.args[0] in (1049, 1044):
                        logger.info(f"Database '{db_name}' missing on MySQL server. Creating database automatically...")
                        raw_conn = pymysql.connect(host=host, port=port, user=user, password=password, autocommit=True)
                        with raw_conn.cursor() as cur:
                            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`;")
                        raw_conn.close()
                        return pymysql.connect(
                            host=host, port=port, database=db_name,
                            user=user, password=password,
                            cursorclass=pymysql.cursors.DictCursor, autocommit=True
                        )
                    raise op_err
            except ImportError:
                try:
                    import mysql.connector
                    try:
                        return mysql.connector.connect(
                            host=host, port=port, database=db_name,
                            user=user, password=password
                        )
                    except Exception:
                        logger.info(f"Database '{db_name}' missing on MySQL server. Creating database automatically...")
                        raw_conn = mysql.connector.connect(host=host, port=port, user=user, password=password)
                        cur = raw_conn.cursor()
                        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`;")
                        raw_conn.close()
                        return mysql.connector.connect(
                            host=host, port=port, database=db_name,
                            user=user, password=password
                        )
                except ImportError:
                    raise RuntimeError(
                        "MySQL driver missing. Please install PyMySQL or mysql-connector-python: "
                        "pip install pymysql mysql-connector-python"
                    )

        elif self.db_type == "postgres":
            import psycopg2
            import psycopg2.extras
            conn = psycopg2.connect(
                host=os.getenv("DB_HOST", "localhost"),
                port=int(os.getenv("DB_PORT", 5432)),
                dbname=os.getenv("DB_NAME", "sentinelops"),
                user=os.getenv("DB_USER", "postgres"),
                password=os.getenv("DB_PASSWORD", "")
            )
            return conn
        else:
            raise ValueError(f"Unsupported DB_TYPE: {self.db_type}")

    def _ph(self, sql: str) -> str:
        """
        Converts ? SQL parameter placeholders to %s for MySQL / PostgreSQL.
        """
        if self.db_type in ("mysql", "mariadb", "postgres"):
            return sql.replace("?", "%s")
        return sql

    def init_db(self) -> None:
        """
        Creates projects, scans, risk_summary, findings, and compliance_results tables if missing.
        """
        id_auto = "INTEGER PRIMARY KEY AUTOINCREMENT" if self.db_type == "sqlite" else "INT AUTO_INCREMENT PRIMARY KEY"
        txt_type = "TEXT" if self.db_type == "sqlite" else "LONGTEXT"

        conn = self.get_connection()
        try:
            cursor = conn.cursor()

            # 1. Projects Table
            cursor.execute(self._ph("""
                CREATE TABLE IF NOT EXISTS projects (
                    project_id VARCHAR(64) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    repository_url VARCHAR(500),
                    branch VARCHAR(100),
                    created_at VARCHAR(64)
                );
            """))

            # 2. Scans Table
            cursor.execute(self._ph("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id VARCHAR(64) PRIMARY KEY,
                    project_id VARCHAR(64),
                    scan_time VARCHAR(64) NOT NULL,
                    title VARCHAR(255),
                    scanners_executed TEXT,
                    total_findings INT DEFAULT 0,
                    critical_count INT DEFAULT 0,
                    high_count INT DEFAULT 0,
                    medium_count INT DEFAULT 0,
                    low_count INT DEFAULT 0,
                    info_count INT DEFAULT 0,
                    fixable_count INT DEFAULT 0,
                    exploitable_count INT DEFAULT 0,
                    scanned_targets INT DEFAULT 0,
                    scanned_packages INT DEFAULT 0,
                    scanned_files INT DEFAULT 0,
                    total_risk_score INT DEFAULT 0,
                    risk_level VARCHAR(32) DEFAULT 'UNKNOWN',
                    compliance_score FLOAT DEFAULT 0.0,
                    owasp_score FLOAT DEFAULT 0.0,
                    cis_score FLOAT DEFAULT 0.0,
                    nist_score FLOAT DEFAULT 0.0,
                    verdict VARCHAR(32) DEFAULT 'UNKNOWN',
                    created_at VARCHAR(64)
                );
            """))

            # 3. Risk Summary Table
            cursor.execute(self._ph("""
                CREATE TABLE IF NOT EXISTS risk_summary (
                    scan_id VARCHAR(64) PRIMARY KEY,
                    project_id VARCHAR(64),
                    critical_score INT DEFAULT 0,
                    high_score INT DEFAULT 0,
                    medium_score INT DEFAULT 0,
                    low_score INT DEFAULT 0,
                    info_score INT DEFAULT 0,
                    overall_score INT DEFAULT 0,
                    risk_level VARCHAR(32) DEFAULT 'UNKNOWN',
                    created_at VARCHAR(64)
                );
            """))

            # 4. Findings Table
            cursor.execute(self._ph(f"""
                CREATE TABLE IF NOT EXISTS findings (
                    id {id_auto},
                    scan_id VARCHAR(64) NOT NULL,
                    project_id VARCHAR(64),
                    tool VARCHAR(64) NOT NULL,
                    category VARCHAR(128),
                    rule_id VARCHAR(128),
                    severity VARCHAR(32),
                    file {txt_type},
                    line INT,
                    message {txt_type},
                    recommendation {txt_type},
                    status VARCHAR(32),
                    scan_time VARCHAR(64),
                    package_name VARCHAR(255),
                    installed_version VARCHAR(100),
                    fixed_version VARCHAR(100),
                    cvss_score FLOAT,
                    cwe {txt_type},
                    cve VARCHAR(100),
                    severity_source VARCHAR(64),
                    target {txt_type},
                    target_class VARCHAR(64),
                    target_type VARCHAR(64),
                    description {txt_type},
                    primary_url {txt_type},
                    references_json {txt_type},
                    compliance_json {txt_type},
                    exploit_available INT DEFAULT 0,
                    fix_available INT DEFAULT 0,
                    epss_score FLOAT,
                    kev INT DEFAULT 0,
                    created_at VARCHAR(64)
                );
            """))

            # 5. Compliance Results Table (Normalized 1-row-per-control table)
            cursor.execute(self._ph(f"""
                CREATE TABLE IF NOT EXISTS compliance_results (
                    id {id_auto},
                    scan_id VARCHAR(64) NOT NULL,
                    project_id VARCHAR(64),
                    finding_rule_id VARCHAR(128),
                    tool VARCHAR(64),
                    severity VARCHAR(32),
                    framework VARCHAR(128) NOT NULL,
                    control_id VARCHAR(255) NOT NULL,
                    matched_layer VARCHAR(128),
                    status VARCHAR(32) DEFAULT 'FAILED',
                    created_at VARCHAR(64)
                );
            """))

            # Column Migration for existing tables
            cols_to_add_scans = [
                ("project_id", "VARCHAR(64)"),
                ("fixable_count", "INT DEFAULT 0"),
                ("exploitable_count", "INT DEFAULT 0"),
                ("scanned_targets", "INT DEFAULT 0"),
                ("scanned_packages", "INT DEFAULT 0"),
                ("scanned_files", "INT DEFAULT 0"),
                ("owasp_score", "FLOAT DEFAULT 0.0"),
                ("cis_score", "FLOAT DEFAULT 0.0"),
                ("nist_score", "FLOAT DEFAULT 0.0")
            ]
            for col_name, col_def in cols_to_add_scans:
                try:
                    cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_def};")
                except Exception:
                    pass

            cols_to_add_findings = [
                ("project_id", "VARCHAR(64)"),
                ("scan_time", "VARCHAR(64)"),
                ("package_name", "VARCHAR(255)"),
                ("installed_version", "VARCHAR(100)"),
                ("fixed_version", "VARCHAR(100)"),
                ("cvss_score", "FLOAT"),
                ("severity_source", "VARCHAR(64)"),
                ("target_class", "VARCHAR(64)"),
                ("target_type", "VARCHAR(64)"),
                ("description", txt_type),
                ("primary_url", txt_type),
                ("references_json", txt_type),
                ("compliance_json", txt_type),
                ("exploit_available", "INT DEFAULT 0"),
                ("fix_available", "INT DEFAULT 0"),
                ("epss_score", "FLOAT"),
                ("kev", "INT DEFAULT 0"),
                ("created_at", "VARCHAR(64)")
            ]
            for col_name, col_def in cols_to_add_findings:
                try:
                    cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def};")
                except Exception:
                    pass

            # 6. Reports Table (Tracks generated PDF/HTML/JSON report artifacts)
            cursor.execute(self._ph(f"""
                CREATE TABLE IF NOT EXISTS reports (
                    report_id VARCHAR(64) PRIMARY KEY,
                    scan_id VARCHAR(64) NOT NULL,
                    project_id VARCHAR(64),
                    report_type VARCHAR(32) NOT NULL,
                    title VARCHAR(255),
                    file_path {txt_type} NOT NULL,
                    file_size_bytes INT DEFAULT 0,
                    created_at VARCHAR(64)
                );
            """))

            # Column Migration for existing tables
            cols_to_add_scans = [
                ("project_id", "VARCHAR(64)"),
                ("fixable_count", "INT DEFAULT 0"),
                ("exploitable_count", "INT DEFAULT 0"),
                ("scanned_targets", "INT DEFAULT 0"),
                ("scanned_packages", "INT DEFAULT 0"),
                ("scanned_files", "INT DEFAULT 0"),
                ("owasp_score", "FLOAT DEFAULT 0.0"),
                ("cis_score", "FLOAT DEFAULT 0.0"),
                ("nist_score", "FLOAT DEFAULT 0.0")
            ]
            for col_name, col_def in cols_to_add_scans:
                try:
                    cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_def};")
                except Exception:
                    pass

            cols_to_add_findings = [
                ("project_id", "VARCHAR(64)"),
                ("scan_time", "VARCHAR(64)"),
                ("package_name", "VARCHAR(255)"),
                ("installed_version", "VARCHAR(100)"),
                ("fixed_version", "VARCHAR(100)"),
                ("cvss_score", "FLOAT"),
                ("severity_source", "VARCHAR(64)"),
                ("target_class", "VARCHAR(64)"),
                ("target_type", "VARCHAR(64)"),
                ("description", txt_type),
                ("primary_url", txt_type),
                ("references_json", txt_type),
                ("compliance_json", txt_type),
                ("exploit_available", "INT DEFAULT 0"),
                ("fix_available", "INT DEFAULT 0"),
                ("epss_score", "FLOAT"),
                ("kev", "INT DEFAULT 0"),
                ("created_at", "VARCHAR(64)")
            ]
            for col_name, col_def in cols_to_add_findings:
                try:
                    cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def};")
                except Exception:
                    pass

            if self.db_type == "sqlite":
                conn.commit()

        except Exception as ex:
            logger.warning(f"Database initialization warning ({self.db_type}): {ex}")
        finally:
            conn.close()

    def save_master_report(self, master_report: dict, project_name: Optional[str] = None, verdict: str = "UNKNOWN") -> str:
        """
        Ingests master_report.json into projects, scans, risk_summary, findings, compliance_results, and reports tables.
        Dynamic project_name, repository_url, and branch are sourced from environment variables.
        """
        resolved_project_name = project_name or os.getenv("PROJECT_NAME") or os.getenv("JOB_NAME") or "DevSecOps Pipeline"
        repo_url = os.getenv("REPOSITORY_URL") or os.getenv("GIT_URL") or "https://github.com/9MayanK2/DevSecOps"
        branch = os.getenv("BRANCH_NAME") or os.getenv("GIT_BRANCH") or "main"

        summary = master_report.get("summary", {})
        risk_summary = master_report.get("risk_summary", {})
        compliance_summary = master_report.get("compliance_summary", {})
        now_iso = datetime.utcnow().isoformat()
        scan_id = f"SCAN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        project_id = f"PRJ-{resolved_project_name.lower().replace(' ', '-')}"
        scanners_str = json.dumps(master_report.get("scanners_executed", []))

        owasp_score = compliance_summary.get("owasp_top_10_2021", {}).get("compliance_percentage", 0.0)
        cis_score = compliance_summary.get("cis_benchmarks", {}).get("compliance_percentage", 0.0)
        nist_score = compliance_summary.get("nist_sp_800_53", {}).get("compliance_percentage", 0.0)

        crit_cnt = summary.get("critical", 0)
        high_cnt = summary.get("high", 0)
        med_cnt = summary.get("medium", 0)
        low_cnt = summary.get("low", 0)
        info_cnt = summary.get("info", 0)

        crit_score = crit_cnt * 10
        high_score = high_cnt * 5
        med_score = med_cnt * 2
        low_score = low_cnt * 1
        overall_risk = risk_summary.get("total_risk_score", crit_score + high_score + med_score + low_score)
        risk_lvl = risk_summary.get("risk_level", "UNKNOWN")

        conn = self.get_connection()
        try:
            cursor = conn.cursor()

            # 1. Upsert Project
            cursor.execute(self._ph("""
                INSERT INTO projects (project_id, name, repository_url, branch, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET name = excluded.name, repository_url = excluded.repository_url, branch = excluded.branch, created_at = excluded.created_at;
            """ if self.db_type == "sqlite" else """
                INSERT INTO projects (project_id, name, repository_url, branch, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE name=VALUES(name), repository_url=VALUES(repository_url), branch=VALUES(branch);
            """), (project_id, resolved_project_name, repo_url, branch, now_iso))

            # 2. Insert Scan Record
            cursor.execute(self._ph("""
                INSERT INTO scans (
                    scan_id, project_id, scan_time, title, scanners_executed,
                    total_findings, critical_count, high_count, medium_count, low_count, info_count,
                    fixable_count, exploitable_count, scanned_targets, scanned_packages, scanned_files,
                    total_risk_score, risk_level, compliance_score, owasp_score, cis_score, nist_score,
                    verdict, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """), (
                scan_id, project_id,
                master_report.get("generated_at", now_iso),
                master_report.get("title", "Master DevSecOps Security Report"),
                scanners_str,
                summary.get("total_findings", len(master_report.get("findings", []))),
                crit_cnt, high_cnt, med_cnt, low_cnt, info_cnt,
                summary.get("fixable", 0),
                summary.get("exploitable", 0),
                summary.get("scanned_targets", 1),
                summary.get("scanned_packages", 0),
                summary.get("scanned_files", 0),
                overall_risk, risk_lvl,
                summary.get("compliance_score", 100.0),
                owasp_score, cis_score, nist_score,
                verdict, now_iso
            ))

            # 3. Insert Risk Summary Record
            cursor.execute(self._ph("""
                INSERT INTO risk_summary (
                    scan_id, project_id, critical_score, high_score, medium_score, low_score, info_score,
                    overall_score, risk_level, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET overall_score = excluded.overall_score;
            """ if self.db_type == "sqlite" else """
                INSERT INTO risk_summary (
                    scan_id, project_id, critical_score, high_score, medium_score, low_score, info_score,
                    overall_score, risk_level, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE overall_score=VALUES(overall_score);
            """), (
                scan_id, project_id,
                crit_score, high_score, med_score, low_score, 0,
                overall_risk, risk_lvl, now_iso
            ))

            # 4. Insert Findings & Compliance Results
            for finding in master_report.get("findings", []):
                cwe_str = json.dumps(finding.get("cwe", []))
                ref_str = json.dumps(finding.get("references", []))
                comp_list = finding.get("compliance", []) or []
                comp_str = json.dumps(comp_list)
                rule_id = finding.get("rule_id", "")
                tool = finding.get("tool", "Unknown")
                severity = finding.get("severity", "UNKNOWN")
                matched_layers = ", ".join(finding.get("compliance_layers", []))

                cursor.execute(self._ph("""
                    INSERT INTO findings (
                        scan_id, project_id, tool, category, rule_id, severity,
                        file, line, message, recommendation, status, scan_time,
                        package_name, installed_version, fixed_version, cvss_score,
                        cwe, cve, severity_source, target, target_class, target_type,
                        description, primary_url, references_json, compliance_json,
                        exploit_available, fix_available, epss_score, kev, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """), (
                    scan_id, project_id,
                    tool,
                    finding.get("category", "General"),
                    rule_id, severity,
                    finding.get("file", ""),
                    finding.get("line"),
                    finding.get("message", ""),
                    finding.get("recommendation", ""),
                    finding.get("status", "OPEN"),
                    finding.get("scan_time", now_iso),
                    finding.get("package_name"),
                    finding.get("installed_version"),
                    finding.get("fixed_version"),
                    finding.get("cvss_score"),
                    cwe_str,
                    finding.get("cve"),
                    finding.get("severity_source"),
                    finding.get("target"),
                    finding.get("target_class"),
                    finding.get("target_type"),
                    finding.get("description"),
                    finding.get("primary_url"),
                    ref_str, comp_str,
                    1 if finding.get("exploit_available") else 0,
                    1 if finding.get("fix_available") else 0,
                    finding.get("epss_score"),
                    1 if finding.get("kev") else 0,
                    now_iso
                ))

                # Insert Normalized Compliance Control Rows
                for comp in comp_list:
                    owasp = comp.get("owasp")
                    cis = comp.get("cis")
                    nist = comp.get("nist")

                    if owasp:
                        cursor.execute(self._ph("""
                            INSERT INTO compliance_results (
                                scan_id, project_id, finding_rule_id, tool, severity,
                                framework, control_id, matched_layer, status, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """), (scan_id, project_id, rule_id, tool, severity, "OWASP Top 10 2021", owasp, matched_layers, "FAILED", now_iso))

                    if cis:
                        cursor.execute(self._ph("""
                            INSERT INTO compliance_results (
                                scan_id, project_id, finding_rule_id, tool, severity,
                                framework, control_id, matched_layer, status, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """), (scan_id, project_id, rule_id, tool, severity, "CIS Benchmarks", cis, matched_layers, "FAILED", now_iso))

                    if nist:
                        cursor.execute(self._ph("""
                            INSERT INTO compliance_results (
                                scan_id, project_id, finding_rule_id, tool, severity,
                                framework, control_id, matched_layer, status, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """), (scan_id, project_id, rule_id, tool, severity, "NIST SP 800-53", nist, matched_layers, "FAILED", now_iso))

            if self.db_type == "sqlite":
                conn.commit()

        except Exception as ex:
            logger.error(f"Database Ingestion Error ({self.db_type}): {ex}")
            if self.db_type != "sqlite":
                logger.info("Attempting automatic fallback ingestion to local SQLite database...")
                try:
                    fallback_db = DatabaseManager(db_type="sqlite")
                    return fallback_db.save_master_report(master_report, project_name=project_name, verdict=verdict)
                except Exception as fallback_ex:
                    logger.error(f"Fallback SQLite Ingestion Error: {fallback_ex}")
            raise ex
        finally:
            conn.close()

        logger.info(f"Database Ingestion Successful [{self.db_type.upper()}] (Scan ID: {scan_id})")
        return scan_id

    def update_scan_verdict(self, scan_id: str, verdict: str) -> None:
        """
        Updates the security gate verdict (PASS / FAIL) for a scan record.
        """
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(self._ph("UPDATE scans SET verdict = ? WHERE scan_id = ?"), (verdict, scan_id))
            if self.db_type == "sqlite":
                conn.commit()
        except Exception as ex:
            logger.warning(f"Could not update scan verdict in primary DB ({self.db_type}): {ex}")
            if self.db_type != "sqlite":
                try:
                    fallback_db = DatabaseManager(db_type="sqlite")
                    fallback_db.update_scan_verdict(scan_id, verdict)
                except Exception:
                    pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def save_report_artifact(self, scan_id: str, report_type: str, title: str, file_path: str | Path) -> str:
        """
        Ingests a generated report artifact (HTML, PDF, JSON) into the reports table.
        """
        p = Path(file_path)
        file_size = p.stat().st_size if p.exists() else 0
        now_iso = datetime.utcnow().isoformat()
        report_id = f"RPT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{report_type.upper()}"
        project_name = os.getenv("PROJECT_NAME") or os.getenv("JOB_NAME") or "DevSecOps Pipeline"
        project_id = f"PRJ-{project_name.lower().replace(' ', '-')}"

        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(self._ph("""
                INSERT INTO reports (
                    report_id, scan_id, project_id, report_type, title, file_path, file_size_bytes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """), (report_id, scan_id, project_id, report_type.upper(), title, str(p), file_size, now_iso))
            if self.db_type == "sqlite":
                conn.commit()
        except Exception as ex:
            logger.warning(f"Could not save report artifact metadata ({self.db_type}): {ex}")
            if self.db_type != "sqlite":
                try:
                    fallback_db = DatabaseManager(db_type="sqlite")
                    return fallback_db.save_report_artifact(scan_id, report_type, title, file_path)
                except Exception:
                    pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

        logger.info(f"Saved report artifact metadata [{report_type.upper()}] (Report ID: {report_id})")
        return report_id

    def get_recent_scans(self, limit: int = 10) -> List[dict]:
        """
        Retrieves recent scan runs from database.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(self._ph("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?"), (limit,))
            rows = cursor.fetchall()
            if self.db_type == "sqlite":
                return [dict(row) for row in rows]
            return list(rows)
        finally:
            conn.close()


def main():
    db = DatabaseManager()
    scans = db.get_recent_scans(5)
    print(f"Database Manager ({db.db_type.upper()}) initialized. Recent scans count: {len(scans)}")


if __name__ == "__main__":
    main()
