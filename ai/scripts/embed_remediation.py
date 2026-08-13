#!/usr/bin/env python3
"""
embed_remediation.py

CLI script to index security remediation knowledge base records into ChromaDB vector store.
Usage:
    python -m ai.scripts.embed_remediation [--kb-path PATH] [--reset]
"""

from __future__ import annotations

import sys
import argparse
import logging
from pathlib import Path

# Ensure project root is in python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.resolve()))

from ai.core.rag_engine import RAGEngine
from ai.data import REMEDIATION_KB_PATH

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("embed_remediation")


def main():
    parser = argparse.ArgumentParser(description="Embed Security Remediation KB into Vector DB.")
    parser.add_argument(
        "--kb-path",
        type=str,
        default=str(REMEDIATION_KB_PATH),
        help="Path to JSON Knowledge Base file.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset existing vector collection before indexing.",
    )
    args = parser.parse_args()

    engine = RAGEngine()

    if args.reset:
        logger.info("Resetting existing vector store collection...")
        engine.chroma.reset()

    logger.info(f"Starting KB indexing from '{args.kb_path}'...")
    count = engine.index_remediation_kb(kb_path=args.kb_path)
    logger.info(f"Successfully embedded {count} remediation records.")
    print(f"✅ Successfully indexed {count} security knowledge base entries into vector store.")


if __name__ == "__main__":
    main()
