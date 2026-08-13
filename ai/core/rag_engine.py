"""
rag_engine.py

RAG Engine Orchestrator for Security Remediation.
Integrates MySQL relational findings, ChromaDB vector store, Prompt Context Builder, and LLM Client.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from ai.core.mysql_client import MySQLClient
from ai.core.chroma_client import ChromaClient
from ai.core.context_builder import ContextBuilder
from ai.core.llm_client import LLMClient
from ai.data import REMEDIATION_KB_PATH

logger = logging.getLogger("DevSecOps-AI-RAG")


class RAGEngine:
    """
    RAG Engine combining Relational Security Findings + Vector Search + LLM Generation.
    """

    def __init__(
        self,
        mysql_client: Optional[MySQLClient] = None,
        chroma_client: Optional[ChromaClient] = None,
        llm_client: Optional[LLMClient] = None,
    ):
        self.mysql = mysql_client or MySQLClient()
        self.chroma = chroma_client or ChromaClient()
        self.llm = llm_client or LLMClient()
        self.context_builder = ContextBuilder()

    def index_remediation_kb(self, kb_path: Optional[Path | str] = None) -> int:
        """
        Loads remediation records from JSON knowledge base and indexes them into ChromaDB.
        """
        path = Path(kb_path or REMEDIATION_KB_PATH)
        if not path.exists():
            logger.error(f"Knowledge Base JSON not found at: {path}")
            return 0

        with open(path, "r", encoding="utf-8") as f:
            kb_items = json.load(f)

        ids = []
        documents = []
        metadatas = []

        for item in kb_items:
            item_id = item.get("id", f"KB-{len(ids)}")
            title = item.get("title", "")
            rule_id = item.get("rule_id", "")
            cve = item.get("cve", "")
            cwe = item.get("cwe", "")
            tool = item.get("tool", "")
            description = item.get("description", "")
            remediation_steps = item.get("remediation_steps", [])
            steps_str = " ".join(remediation_steps) if isinstance(remediation_steps, list) else str(remediation_steps)

            doc_text = f"{title} {rule_id} {cve} {cwe} {tool} {description} {steps_str}"

            meta = {
                "id": item_id,
                "title": title,
                "rule_id": rule_id,
                "cve": cve,
                "cwe": cwe,
                "tool": tool,
                "severity": item.get("severity", "MEDIUM"),
                "category": item.get("category", "Security"),
                "description": description,
                "vulnerable_code_example": item.get("vulnerable_code_example", ""),
                "remediated_code_example": item.get("remediated_code_example", ""),
            }

            ids.append(item_id)
            documents.append(doc_text)
            metadatas.append(meta)

        success = self.chroma.add_documents(ids=ids, documents=documents, metadatas=metadatas)
        if success:
            logger.info(f"Indexed {len(ids)} security remediation records into vector DB.")
            return len(ids)
        return 0

    def query_kb(self, query_text: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Query vector database directly for matching remediation knowledge records.
        """
        results = self.chroma.query(query_text=query_text, n_results=n_results)
        metadatas = results.get("metadatas", [[]])[0]
        return metadatas

    def diagnose_finding(self, finding: int | Dict[str, Any], update_db: bool = True) -> Dict[str, Any]:
        """
        Performs AI diagnosis & remediation generation for a single finding.
        """
        if isinstance(finding, int):
            finding_data = self.mysql.fetch_finding_by_id(finding)
            if not finding_data:
                return {"error": f"Finding ID #{finding} not found in database."}
        else:
            finding_data = finding

        rule_id = finding_data.get("rule_id", "")
        message = finding_data.get("message") or finding_data.get("description") or ""
        search_query = f"{rule_id} {message} {finding_data.get('cve', '')} {finding_data.get('cwe', '')}"

        context_docs = self.query_kb(query_text=search_query, n_results=3)

        system_prompt = self.context_builder.build_system_prompt()
        user_prompt = self.context_builder.build_remediation_prompt(finding_data, context_docs)

        llm_response = self.llm.generate(prompt=user_prompt, system_prompt=system_prompt)

        finding_id = finding_data.get("id")
        if update_db and finding_id and isinstance(finding_id, int):
            self.mysql.update_finding_remediation(finding_id=finding_id, recommendation_text=llm_response, status="REMEDIATED")

        return {
            "finding_id": finding_id,
            "rule_id": rule_id,
            "severity": finding_data.get("severity"),
            "context_docs_count": len(context_docs),
            "remediation_advisory": llm_response
        }

    def diagnose_scan(self, scan_id: str) -> Dict[str, Any]:
        """
        Generates full scan diagnosis & executive summary for a given scan_id.
        """
        scan_data = self.mysql.fetch_scan_by_id(scan_id)
        if not scan_data:
            return {"error": f"Scan ID '{scan_id}' not found."}

        findings = self.mysql.fetch_findings_by_scan_id(scan_id)
        diagnosed_findings = []

        for f in findings[:10]: # Diagnose top findings
            res = self.diagnose_finding(f, update_db=True)
            diagnosed_findings.append(res)

        summary_prompt = self.context_builder.build_scan_summary_prompt(scan_data, findings, [])
        system_prompt = self.context_builder.build_system_prompt()
        executive_summary = self.llm.generate(prompt=summary_prompt, system_prompt=system_prompt)

        return {
            "scan_id": scan_id,
            "total_findings": len(findings),
            "diagnosed_count": len(diagnosed_findings),
            "executive_summary": executive_summary,
            "finding_advisories": diagnosed_findings
        }

    def get_stats(self) -> Dict[str, Any]:
        """Returns stats on Vector DB and MySQL DB."""
        kb_count = self.chroma.count()
        recent_scans = self.mysql.fetch_scans(limit=5)
        unresolved = self.mysql.fetch_unresolved_findings(limit=100)

        return {
            "vector_kb_documents": kb_count,
            "recent_scans_count": len(recent_scans),
            "unresolved_findings_count": len(unresolved)
        }

    def ask_question(self, user_question: str) -> Dict[str, Any]:
        """
        Processes an interactive user question by combining:
        1. User Question
        2. MySQL RDS real-time vulnerability findings
        3. ChromaDB vector knowledge base embeddings
        4. Combined Context -> Free LLM Generator -> Answer
        """
        # Step 1: Query MySQL RDS for latest findings
        latest_findings = self.mysql.fetch_latest_findings(limit=5)

        # Step 2: Query ChromaDB for vector knowledge embeddings matching user question
        context_docs = self.query_kb(query_text=user_question, n_results=3)

        # Step 3: Build Combined Context
        system_prompt = self.context_builder.build_system_prompt()
        combined_prompt = self.context_builder.build_user_question_prompt(
            user_question=user_question,
            findings=latest_findings,
            context_docs=context_docs
        )

        # Step 4: Pass Combined Context to LLM Generator (Free Tier / Ollama / Local Engine)
        answer = self.llm.generate(prompt=combined_prompt, system_prompt=system_prompt)

        return {
            "question": user_question,
            "mysql_findings_retrieved": len(latest_findings),
            "chroma_kb_matches_retrieved": len(context_docs),
            "answer": answer
        }

