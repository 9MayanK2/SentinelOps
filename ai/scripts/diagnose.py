#!/usr/bin/env python3
"""
diagnose.py

CLI script to run RAG AI diagnosis on specific vulnerability findings or full scans.
Usage:
    python -m ai.scripts.diagnose --finding-id 1
    python -m ai.scripts.diagnose --scan-id SCAN-12345
    python -m ai.scripts.diagnose --query "SQL Injection in Python string formatting"
"""

from __future__ import annotations

import sys
import json
import argparse
import logging
from pathlib import Path

# Ensure project root is in python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.resolve()))

from ai.core.rag_engine import RAGEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("diagnose")


def main():
    parser = argparse.ArgumentParser(description="SentinelOps AI Security Vulnerability Diagnosis CLI.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--finding-id", type=int, help="Database Finding ID to diagnose.")
    group.add_argument("--scan-id", type=str, help="Scan ID to analyze and summarize.")
    group.add_argument("--query", type=str, help="Free-text query to search knowledge base.")
    parser.add_argument("--no-db-update", action="store_true", help="Do not write LLM recommendations back to DB.")

    args = parser.parse_args()
    engine = RAGEngine()

    if args.finding_id:
        logger.info(f"Diagnosing Finding #{args.finding_id}...")
        result = engine.diagnose_finding(finding=args.finding_id, update_db=not args.no_db_update)
        print("\n" + "=" * 60)
        print(f"DIAGNOSIS FOR FINDING #{args.finding_id}")
        print("=" * 60)
        print(result.get("remediation_advisory", json.dumps(result, indent=2)))

    elif args.scan_id:
        logger.info(f"Diagnosing Scan '{args.scan_id}'...")
        result = engine.diagnose_scan(scan_id=args.scan_id)
        print("\n" + "=" * 60)
        print(f"EXECUTIVE DIAGNOSIS SUMMARY FOR SCAN {args.scan_id}")
        print("=" * 60)
        print(result.get("executive_summary", json.dumps(result, indent=2)))

    elif args.query:
        logger.info(f"Querying Security KB for: '{args.query}'...")
        matches = engine.query_kb(query_text=args.query, n_results=3)
        print("\n" + "=" * 60)
        print(f"MATCHING REMEDIATION RECORDS FOR: '{args.query}'")
        print("=" * 60)
        for idx, match in enumerate(matches, 1):
            print(f"\n[{idx}] {match.get('title')} ({match.get('tool')}/{match.get('rule_id')})")
            print(f"    Category: {match.get('category')} | Severity: {match.get('severity')}")
            print(f"    Description: {match.get('description')}")
            if match.get("remediated_code_example"):
                print(f"    Remediated Example:\n{match.get('remediated_code_example')}")


if __name__ == "__main__":
    main()
