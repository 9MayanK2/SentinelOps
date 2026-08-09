"""
database.py

Cloud-Ready Database Persistence Layer for DevSecOps Framework.
Supports Local SQLite & AWS EC2 / RDS PostgreSQL.
Stores risk scores and risk levels in scans table.
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
    Manages Database Initialization and Report Ingestion for Local & AWS Environments.
    """

    def __init__(self, db_path: str | Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_type = DB_TYPE
        self.init_db()

    def get_connection(self):
        """
        Creates DB connection (SQLite for local, PostgreSQL for AWS EC2/RDS).
        """
        if self.db_type == "sqlite":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            return conn
        elif self.db_type == "postgres":
            import psycopg2
            return psycopg2.connect(
                host=os.getenv("DB_HOST", "localhost"),
                port=os.getenv("DB_PORT", "5432"),
                dbname=os.getenv("DB_NAME", "devsecops"),
                user=os.getenv("DB_USER", "postgres"),
                password=os.getenv("DB_PASSWORD", "")
            )
        else:
            raise ValueError(f"Unsupported DB_TYPE: {self.db_type}")

    def init_db(self) -> None:
        """
        Creates scans and findings tables if missing.
        """
        if self.db_type == "sqlite":
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        scan_time TEXT NOT NULL,
                        title TEXT,
                        scanners_executed TEXT,
                        total_findings INTEGER,
                        critical_count INTEGER,
                        high_count INTEGER,
                        medium_count INTEGER,
                        low_count INTEGER,
                        info_count INTEGER,
                        total_risk_score INTEGER,
                        risk_level TEXT,
                        compliance_score REAL,
                        verdict TEXT,
                        created_at TEXT
                    );
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        category TEXT,
                        rule_id TEXT,
                        severity TEXT,
                        file TEXT,
                        line INTEGER,
                        message TEXT,
                        recommendation TEXT,
                        status TEXT,
                        cwe TEXT,
                        cve TEXT,
                        target TEXT,
                        FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
                    );
                """)

                # Add risk columns if existing table doesn't have them
                try:
                    cursor.execute("ALTER TABLE scans ADD COLUMN total_risk_score INTEGER DEFAULT 0;")
                    cursor.execute("ALTER TABLE scans ADD COLUMN risk_level TEXT DEFAULT 'UNKNOWN';")
                except Exception:
                    pass

                conn.commit()

    def save_master_report(self, master_report: dict, verdict: str = "UNKNOWN") -> str:
        """
        Ingests master_report.json into database tables.
        """
        summary = master_report.get("summary", {})
        risk_summary = master_report.get("risk_summary", {})
        now_iso = datetime.utcnow().isoformat()
        scan_id = f"SCAN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        scanners_str = json.dumps(master_report.get("scanners_executed", []))

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scans (
                    scan_id, scan_time, title, scanners_executed,
                    total_findings, critical_count, high_count, medium_count, low_count, info_count,
                    total_risk_score, risk_level, compliance_score, verdict, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                master_report.get("generated_at", now_iso),
                master_report.get("title", "Master DevSecOps Security Report"),
                scanners_str,
                summary.get("total_findings", 0),
                summary.get("critical", 0),
                summary.get("high", 0),
                summary.get("medium", 0),
                summary.get("low", 0),
                summary.get("info", 0),
                risk_summary.get("total_risk_score", 0),
                risk_summary.get("risk_level", "UNKNOWN"),
                summary.get("compliance_score", 100.0),
                verdict,
                now_iso
            ))

            for finding in master_report.get("findings", []):
                cwe_str = json.dumps(finding.get("cwe", []))
                cursor.execute("""
                    INSERT INTO findings (
                        scan_id, tool, category, rule_id, severity,
                        file, line, message, recommendation, status, cwe, cve, target
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    finding.get("tool", "Unknown"),
                    finding.get("category", "General"),
                    finding.get("rule_id", ""),
                    finding.get("severity", "UNKNOWN"),
                    finding.get("file", ""),
                    finding.get("line"),
                    finding.get("message", ""),
                    finding.get("recommendation", ""),
                    finding.get("status", "OPEN"),
                    cwe_str,
                    finding.get("cve"),
                    finding.get("target", "")
                ))
            conn.commit()

        logger.info(f"Database Ingestion Successful (Scan ID: {scan_id})")
        return scan_id

    def get_recent_scans(self, limit: int = 10) -> List[dict]:
        """
        Retrieves recent scan runs from database.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]


def main():
    db = DatabaseManager()
    scans = db.get_recent_scans(5)
    print(f"Database initialized. Recent scans count: {len(scans)}")


if __name__ == "__main__":
    main()
