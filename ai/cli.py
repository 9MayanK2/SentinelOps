#!/usr/bin/env python3
"""
cli.py

Main Command Line Interface for SentinelOps AI Vulnerability Remediation Subsystem.
Usage:
    python -m ai.cli embed [--reset] [--kb-path PATH]
    python -m ai.cli diagnose --finding-id 1
    python -m ai.cli diagnose --scan-id SCAN-123
    python -m ai.cli query "SQL Injection"
    python -m ai.cli stats
"""

from __future__ import annotations

import sys
import json
import argparse
import logging
from pathlib import Path

# Ensure project root is in python path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from dotenv import load_dotenv

# Load root workspace .env first, then ai/.env
root_env = Path(__file__).parent.parent / ".env"
ai_env = Path(__file__).parent / ".env"
if root_env.exists():
    load_dotenv(root_env)
if ai_env.exists():
    load_dotenv(ai_env, override=True)

from ai.core.rag_engine import RAGEngine
from ai.data import REMEDIATION_KB_PATH

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("SentinelOps-AI-CLI")



def main():
    parser = argparse.ArgumentParser(
        prog="sentinelops-ai",
        description="SentinelOps AI RAG Vulnerability Remediation & Security Advisory CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: embed
    embed_parser = subparsers.add_parser("embed", help="Index & embed remediation knowledge base into vector store.")
    embed_parser.add_argument("--kb-path", type=str, default=str(REMEDIATION_KB_PATH), help="Path to remediation KB JSON.")
    embed_parser.add_argument("--reset", action="store_true", help="Reset existing vector collection before indexing.")

    # Command: diagnose
    diag_parser = subparsers.add_parser("diagnose", help="Diagnose a finding or scan using RAG AI.")
    diag_group = diag_parser.add_mutually_exclusive_group(required=True)
    diag_group.add_argument("--finding-id", type=int, help="Database Finding ID to analyze.")
    diag_group.add_argument("--scan-id", type=str, help="Scan ID to analyze.")
    diag_parser.add_argument("--no-db-update", action="store_true", help="Skip updating recommendation in database.")

    # Command: query
    query_parser = subparsers.add_parser("query", help="Query vector knowledge base for security remediation records.")
    query_parser.add_argument("query_text", type=str, help="Search query string.")
    query_parser.add_argument("--top-k", type=int, default=3, help="Number of matching records to return.")

    # Command: ask
    ask_parser = subparsers.add_parser("ask", help="Ask interactive question using RAG (MySQL RDS + ChromaDB + Free LLM).")
    ask_parser.add_argument("question", type=str, help="User question string.")

    # Command: stats
    subparsers.add_parser("stats", help="Display vector KB and database statistics.")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    engine = RAGEngine()

    if args.command == "embed":
        if args.reset:
            engine.chroma.reset()
        count = engine.index_remediation_kb(kb_path=args.kb_path)
        print(f"✅ Successfully indexed {count} remediation records into vector store.")

    elif args.command == "diagnose":
        if args.finding_id:
            res = engine.diagnose_finding(finding=args.finding_id, update_db=not args.no_db_update)
            print("\n" + "=" * 60)
            print(f"AI DIAGNOSIS ADVISORY FOR FINDING #{args.finding_id}")
            print("=" * 60)
            print(res.get("remediation_advisory", json.dumps(res, indent=2)))
        elif args.scan_id:
            res = engine.diagnose_scan(scan_id=args.scan_id)
            print("\n" + "=" * 60)
            print(f"AI EXECUTIVE DIAGNOSIS SUMMARY FOR SCAN {args.scan_id}")
            print("=" * 60)
            print(res.get("executive_summary", json.dumps(res, indent=2)))

    elif args.command == "query":
        matches = engine.query_kb(query_text=args.query_text, n_results=args.top_k)
        print("\n" + "=" * 60)
        print(f"SECURITY KB RESULTS FOR: '{args.query_text}'")
        print("=" * 60)
        for idx, m in enumerate(matches, 1):
            print(f"\n[{idx}] {m.get('title')} ({m.get('tool')}/{m.get('rule_id')})")
            print(f"    Severity: {m.get('severity')} | CWE: {m.get('cwe')}")
            print(f"    Description: {m.get('description')}")

    elif args.command == "ask":
        res = engine.ask_question(user_question=args.question)
        print("\n" + "=" * 60)
        print(f"QUESTION: {res['question']}")
        print(f"RETRIEVED CONTEXT: {res['mysql_findings_retrieved']} MySQL RDS findings | {res['chroma_kb_matches_retrieved']} ChromaDB KB matches")
        print("=" * 60)
        print(res["answer"])

    elif args.command == "stats":
        stats = engine.get_stats()
        print("\n" + "=" * 60)
        print("SENTINELOPS AI RAG SUBSYSTEM STATISTICS")
        print("=" * 60)
        print(f"Vector KB Indexed Documents: {stats['vector_kb_documents']}")
        print(f"Recent Scans Tracked:       {stats['recent_scans_count']}")
        print(f"Unresolved Findings Count:  {stats['unresolved_findings_count']}")



if __name__ == "__main__":
    main()
