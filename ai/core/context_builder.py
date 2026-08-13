"""
context_builder.py

RAG Context Builder for DevSecOps AI.
Formats security finding attributes, static analysis results, and vector knowledge base search hits into structured prompt context.
"""

from __future__ import annotations

import json
from typing import Dict, List, Any, Optional


class ContextBuilder:
    """
    Constructs high-precision prompt payloads for LLM vulnerability diagnosis and code remediation generation.
    """

    @staticmethod
    def build_system_prompt() -> str:
        """Standard System Prompt for DevSecOps AI Agent."""
        return (
            "You are SentinelOps AI, an expert DevSecOps and Application Security Architect. "
            "Your task is to analyze security vulnerabilities (SAST/DAST/SCA/Container findings), "
            "evaluate their severity and risk level, identify the underlying root cause, "
            "and produce concrete, secure, production-grade code remediation steps.\n\n"
            "Guidelines:\n"
            "1. Be precise, technical, and actionable.\n"
            "2. Provide clear before/after code blocks demonstrating the fix.\n"
            "3. Map the finding to compliance controls (NIST CSF, OWASP Top 10, CIS, ISO 27001) where relevant.\n"
            "4. Do NOT introduce new security flaws in your remediation code."
        )

    @staticmethod
    def build_remediation_prompt(finding: Dict[str, Any], context_docs: List[Dict[str, Any]]) -> str:
        """
        Builds user prompt by combining finding details from database and RAG reference context.
        """
        finding_id = finding.get("id", "N/A")
        tool = finding.get("tool", "Security Scanner")
        rule_id = finding.get("rule_id", "N/A")
        severity = finding.get("severity", "UNKNOWN")
        category = finding.get("category", "General Security")
        cve = finding.get("cve", "N/A")
        cwe = finding.get("cwe", "N/A")
        file_path = finding.get("file") or finding.get("target") or "N/A"
        line_no = finding.get("line", "N/A")
        message = finding.get("message") or finding.get("description") or "Security finding detected."
        recommendation = finding.get("recommendation", "")

        kb_context_str = ""
        if context_docs:
            kb_context_str += "=== RETRIEVED SECURITY KNOWLEDGE BASE CONTEXT ===\n"
            for idx, doc in enumerate(context_docs, 1):
                title = doc.get("title") or doc.get("id", f"KB-Record-{idx}")
                kb_context_str += f"\n--- Knowledge Record [{idx}]: {title} ---\n"
                if doc.get("cwe"):
                    kb_context_str += f"CWE: {doc['cwe']} | Rule ID: {doc.get('rule_id', 'N/A')}\n"
                if doc.get("description"):
                    kb_context_str += f"Description: {doc['description']}\n"
                if doc.get("remediation_steps"):
                    steps = doc['remediation_steps']
                    if isinstance(steps, list):
                        steps = "\n  - ".join(steps)
                    kb_context_str += f"Recommended Steps:\n  - {steps}\n"
                if doc.get("vulnerable_code_example"):
                    kb_context_str += f"Vulnerable Pattern:\n{doc['vulnerable_code_example']}\n"
                if doc.get("remediated_code_example"):
                    kb_context_str += f"Secure Pattern:\n{doc['remediated_code_example']}\n"

        prompt = f"""
=== DEVSECOPS VULNERABILITY FINDING DETAILS ===
Finding ID: {finding_id}
Tool / Scanner: {tool}
Rule ID: {rule_id}
Severity: {severity}
Category: {category}
CVE: {cve} | CWE: {cwe}
Location: File {file_path} (Line {line_no})
Details / Message: {message}
Existing Scanner Recommendation: {recommendation or 'None'}

{kb_context_str}

=== INSTRUCTIONS ===
Based on the vulnerability finding details and the retrieved security knowledge base context above:
1. Provide a concise Diagnosis explaining why this finding is a security risk.
2. Outline step-by-step technical Remediation Instructions.
3. Provide a side-by-side Code Comparison:
   - Vulnerable Code Snippet
   - Fixed / Remediated Code Snippet
4. List applicable Security Compliance Framework controls (OWASP, NIST CSF, CIS).
"""
        return prompt.strip()

    @staticmethod
    def build_scan_summary_prompt(scan_data: Dict[str, Any], findings: List[Dict[str, Any]], context_docs: List[Dict[str, Any]]) -> str:
        """
        Builds summary prompt for an entire scan execution.
        """
        scan_id = scan_data.get("scan_id", "N/A")
        total = scan_data.get("total_findings", len(findings))
        critical = scan_data.get("critical_count", 0)
        high = scan_data.get("high_count", 0)
        medium = scan_data.get("medium_count", 0)
        verdict = scan_data.get("verdict", "UNKNOWN")

        finding_summaries = []
        for f in findings[:15]:
            finding_summaries.append(
                f"- [#{f.get('id')}] [{f.get('severity')}] {f.get('tool')}/{f.get('rule_id')}: "
                f"{f.get('message', '')[:100]} in {f.get('file', 'unknown')}"
            )

        findings_block = "\n".join(finding_summaries) if finding_summaries else "No findings."

        return f"""
=== DEVSECOPS SCAN EXECUTIVE SUMMARY ===
Scan ID: {scan_id}
Total Findings: {total} (Critical: {critical}, High: {high}, Medium: {medium})
Pipeline Gate Verdict: {verdict}

Top Findings:
{findings_block}

=== INSTRUCTIONS ===
Analyze the scan findings, prioritize the top high-impact security risks, and provide an Executive Remediation Roadmap for the engineering team.
""".strip()

    @staticmethod
    def build_user_question_prompt(
        user_question: str,
        findings: List[Dict[str, Any]],
        context_docs: List[Dict[str, Any]]
    ) -> str:
        """
        Combines User Question + MySQL Findings + ChromaDB Remediation KB into single LLM prompt.
        """
        findings_block = ""
        if findings:
            findings_block += "=== MYSQL RDS REAL-TIME SCAN FINDINGS ===\n"
            for f in findings[:5]:
                findings_block += (
                    f"- [Finding #{f.get('id')}] Tool: {f.get('tool')} | Rule: {f.get('rule_id')} | "
                    f"Severity: {f.get('severity')} | File: {f.get('file', 'N/A')}:{f.get('line', 'N/A')}\n"
                    f"  Message: {f.get('message', f.get('description', 'N/A'))}\n"
                )
        else:
            findings_block += "=== MYSQL RDS REAL-TIME SCAN FINDINGS ===\nNo active database findings retrieved.\n"

        kb_block = ""
        if context_docs:
            kb_block += "\n=== CHROMADB RETRIEVED REMEDIATION KNOWLEDGE ===\n"
            for idx, doc in enumerate(context_docs, 1):
                kb_block += (
                    f"[{idx}] {doc.get('title', 'KB Record')} ({doc.get('tool')}/{doc.get('rule_id')})\n"
                    f"    CWE: {doc.get('cwe')} | Severity: {doc.get('severity')}\n"
                    f"    Description: {doc.get('description')}\n"
                    f"    Fix Steps: {doc.get('remediation_steps')}\n"
                    f"    Remediated Example: {doc.get('remediated_code_example')}\n"
                )
        else:
            kb_block += "\n=== CHROMADB RETRIEVED REMEDIATION KNOWLEDGE ===\nNo matching vector embeddings found.\n"

        prompt = f"""
USER QUESTION:
"{user_question}"

{findings_block}
{kb_block}

=== INSTRUCTIONS ===
Answer the user's question directly using the MySQL scan findings and ChromaDB remediation knowledge provided above.
Provide actionable security guidance, precise code snippets, and remediation steps.
"""
        return prompt.strip()

