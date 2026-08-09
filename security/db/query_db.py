"""
query_db.py

CLI Utility to inspect Database scans and findings.
"""

from __future__ import annotations

import sys
import json
import sqlite3
from pathlib import Path

DB_PATH = Path("compliance/db/security_framework.db")


def main():
    if not DB_PATH.exists():
        print("❌ Database not found. Run ./security/run_pipeline.sh first to generate data.")
        sys.exit(1)

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    scans = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    findings = conn.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()

    print("\n" + "=" * 70)
    print("                DEVSECOPS DATABASE RECORD VIEWER")
    print("=" * 70)
    print(f" Database Path  : {DB_PATH.resolve()}")
    print(f" Total Scans    : {len(scans)}")
    print(f" Total Findings : {len(findings)}")
    print("=" * 70 + "\n")

    print("📊 SCAN RUN HISTORY:")
    for scan in scans:
        print(f" • Scan ID   : {scan['scan_id']}")
        print(f"   Time      : {scan['scan_time']}")
        print(f"   Scanners  : {scan['scanners_executed']}")
        print(f"   Score     : {scan['compliance_score']}%")
        print(f"   Verdict   : [{scan['verdict']}]")
        print(f"   Findings  : Total={scan['total_findings']} (Critical={scan['critical_count']}, High={scan['high_count']}, Med={scan['medium_count']}, Low={scan['low_count']})")
        print("-" * 70)

    print("\n🔍 RECENT DATABASE FINDINGS:")
    for finding in findings[:10]:
        print(f" • [{finding['severity']}] {finding['tool']} - {finding['rule_id']}")
        print(f"   Location  : {finding['file']}:{finding['line']}")
        print(f"   Message   : {finding['message']}")
        print("-" * 70)


if __name__ == "__main__":
    main()
