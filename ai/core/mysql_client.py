"""
mysql_client.py

MySQL & SQLite Database Client for DevSecOps AI RAG Subsystem.
Connects to RDS MySQL or local SQLite database to fetch vulnerability findings and scan history.
"""

from __future__ import annotations

import os
import json
import sqlite3
import logging
from pathlib import Path
root_env = Path(__file__).parent.parent.parent / ".env"
ai_env = Path(__file__).parent.parent / ".env"
if root_env.exists():
    load_dotenv(root_env)
if ai_env.exists():
    load_dotenv(ai_env, override=True)

logger = logging.getLogger("DevSecOps-AI-MySQL")



class MySQLClient:
    """
    Database client for fetching vulnerability findings, scans, and updating remediation feedback.
    Supports RDS MySQL and local SQLite fallback.
    """

    def __init__(
        self,
        db_type: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        db_name: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        sqlite_path: Optional[str] = None,
    ):
        self.db_type = (db_type or os.getenv("DB_TYPE", "mysql")).lower()
        self.host = host or os.getenv("DB_HOST", "localhost")
        self.port = port or int(os.getenv("DB_PORT", 3306))
        self.db_name = db_name or os.getenv("DB_NAME", "sentinelops")
        self.user = user or os.getenv("DB_USER", "root")
        self.password = password or os.getenv("DB_PASSWORD", "")
        self.sqlite_path = Path(sqlite_path or os.getenv("DB_PATH", "compliance/db/security_framework.db"))

    def get_connection(self):
        """
        Establishes database connection to MySQL or falls back to SQLite.
        """
        if self.db_type == "sqlite" or not self.host:
            return self._get_sqlite_connection()

        try:
            import pymysql
            return pymysql.connect(
                host=self.host,
                port=self.port,
                database=self.db_name,
                user=self.user,
                password=self.password,
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=5,
                autocommit=True,
            )
        except Exception as err:
            logger.warning(f"MySQL connection failed ({err}). Falling back to SQLite at {self.sqlite_path}")
            return self._get_sqlite_connection()

    def _get_sqlite_connection(self):
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.sqlite_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _ph(self, sql: str) -> str:
        """Converts ? SQL parameter placeholders to %s for MySQL if needed."""
        if self.db_type in ("mysql", "mariadb", "postgres"):
            return sql.replace("?", "%s")
        return sql

    def fetch_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch recent scan executions."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            query = self._ph("SELECT * FROM scans ORDER BY scan_time DESC LIMIT ?")
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as err:
            logger.error(f"Error fetching scans: {err}")
            return []
        finally:
            conn.close()

    def fetch_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Fetch details of a single scan by scan_id."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            query = self._ph("SELECT * FROM scans WHERE scan_id = ?")
            cursor.execute(query, (scan_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as err:
            logger.error(f"Error fetching scan {scan_id}: {err}")
            return None
        finally:
            conn.close()

    def fetch_findings_by_scan_id(self, scan_id: str, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch vulnerability findings for a given scan."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            if severity:
                query = self._ph("SELECT * FROM findings WHERE scan_id = ? AND LOWER(severity) = LOWER(?) ORDER BY id ASC")
                cursor.execute(query, (scan_id, severity))
            else:
                query = self._ph("SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC")
                cursor.execute(query, (scan_id,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as err:
            logger.error(f"Error fetching findings for scan {scan_id}: {err}")
            return []
        finally:
            conn.close()

    def fetch_finding_by_id(self, finding_id: int) -> Optional[Dict[str, Any]]:
        """Fetch a specific vulnerability finding by ID."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            query = self._ph("SELECT * FROM findings WHERE id = ?")
            cursor.execute(query, (finding_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as err:
            logger.error(f"Error fetching finding #{finding_id}: {err}")
            return None
        finally:
            conn.close()

    def fetch_unresolved_findings(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch findings that are not marked as REMEDIATED or RESOLVED."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            query = self._ph("SELECT * FROM findings WHERE status IS NULL OR status NOT IN ('REMEDIATED', 'RESOLVED') LIMIT ?")
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as err:
            logger.error(f"Error fetching unresolved findings: {err}")
            return []
        finally:
            conn.close()

    def update_finding_remediation(self, finding_id: int, recommendation_text: str, status: str = "REMEDIATING") -> bool:
        """Update recommendation and status for a finding."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            query = self._ph("UPDATE findings SET recommendation = ?, status = ? WHERE id = ?")
            cursor.execute(query, (recommendation_text, status, finding_id))
            if hasattr(conn, "commit"):
                conn.commit()
            return True
        except Exception as err:
            logger.error(f"Failed to update finding #{finding_id}: {err}")
            return False
        finally:
            conn.close()

    def fetch_latest_scan(self) -> Optional[Dict[str, Any]]:
        """Fetch the single most recent scan from database."""
        scans = self.fetch_scans(limit=1)
        return scans[0] if scans else None

    def fetch_latest_findings(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch findings from the most recent scan execution."""
        latest_scan = self.fetch_latest_scan()
        if latest_scan and "scan_id" in latest_scan:
            return self.fetch_findings_by_scan_id(latest_scan["scan_id"])[:limit]
        
        # Fallback to recent unresolved findings
        return self.fetch_unresolved_findings(limit=limit)

