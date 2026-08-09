"""
compliance_mapper.py

Compliance Mapping Engine for DevSecOps Framework.
Maps findings (CWEs / Rules) to OWASP Top 10 (2021), CIS Benchmarks, and NIST SP 800-53.
Provides percentage calculations, framework baselines, and controls passed/failed breakdown.
Outputs report to compliance/reports/compliance/compliance_matrix.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Any

from security.common.logger import logger

COMPLIANCE_DIR = Path("compliance/reports/compliance")
COMPLIANCE_MATRIX_PATH = COMPLIANCE_DIR / "compliance_matrix.json"


class ComplianceMapper:
    """
    Advanced Compliance Engine providing framework breakdown, compliance %, and control metrics.
    """

    MAPPING_RULES = {
        "CWE-798": {
            "owasp": "A02:2021-Cryptographic Failures",
            "cis": "CIS Controls v8 3.12 - Rekey or Revoke Credentials",
            "nist": "IA-5 Authenticator Management"
        },
        "aws-access-token": {
            "owasp": "A02:2021-Cryptographic Failures",
            "cis": "CIS Controls v8 3.12 - Protect Sensitive Cloud Credentials",
            "nist": "IA-5 Authenticator Management"
        },
        "generic-api-key": {
            "owasp": "A02:2021-Cryptographic Failures",
            "cis": "CIS Controls v8 3.12 - Avoid Hardcoded API Keys",
            "nist": "IA-5 Authenticator Management"
        },
        "DL3059": {
            "owasp": "A05:2021-Security Misconfiguration",
            "cis": "CIS Docker Benchmark 4.6 - Healthcheck Instruction",
            "nist": "CM-6 Configuration Settings"
        },
        "DL3002": {
            "owasp": "A05:2021-Security Misconfiguration",
            "cis": "CIS Docker Benchmark 4.1 - Non-root Container User",
            "nist": "AC-6 Least Privilege"
        }
    }

    # Baseline controls count per framework
    FRAMEWORK_BASELINES = {
        "owasp_top_10_2021": 10,
        "cis_benchmarks": 15,
        "nist_sp_800_53": 20
    }

    def map_finding(self, finding: dict) -> dict:
        """
        Enriches a finding with compliance standard mappings.
        """
        rule_id = finding.get("rule_id", "")
        cwes = finding.get("cwe", []) or []
        category = finding.get("category", "")

        compliance_entries: List[dict] = []

        if rule_id in self.MAPPING_RULES:
            compliance_entries.append(self.MAPPING_RULES[rule_id])

        for cwe in cwes:
            if cwe in self.MAPPING_RULES and self.MAPPING_RULES[cwe] not in compliance_entries:
                compliance_entries.append(self.MAPPING_RULES[cwe])

        if not compliance_entries:
            if category == "Secrets Detection":
                compliance_entries.append({
                    "owasp": "A02:2021-Cryptographic Failures",
                    "cis": "CIS Controls v8 3.12 - Protect Sensitive Data",
                    "nist": "IA-5 Authenticator Management"
                })
            elif category == "Container Security":
                compliance_entries.append({
                    "owasp": "A06:2021-Vulnerable and Outdated Components" if finding.get("cve") else "A05:2021-Security Misconfiguration",
                    "cis": "CIS Docker Benchmark 4.0 - Container Hardening",
                    "nist": "CM-6 Configuration Settings"
                })

        finding["compliance"] = compliance_entries
        return finding

    def process_master_report(self, master_report: dict) -> dict:
        """
        Enriches master report findings and calculates advanced compliance metrics.
        """
        logger.info("Processing Advanced Compliance Layer mappings...")

        owasp_controls: Dict[str, int] = {}
        cis_controls: Dict[str, int] = {}
        nist_controls: Dict[str, int] = {}

        enriched_findings = []
        for finding in master_report.get("findings", []):
            enriched = self.map_finding(finding)
            enriched_findings.append(enriched)

            for comp in enriched.get("compliance", []):
                owasp = comp.get("owasp")
                cis = comp.get("cis")
                nist = comp.get("nist")

                if owasp:
                    owasp_controls[owasp] = owasp_controls.get(owasp, 0) + 1
                if cis:
                    cis_controls[cis] = cis_controls.get(cis, 0) + 1
                if nist:
                    nist_controls[nist] = nist_controls.get(nist, 0) + 1

        master_report["findings"] = enriched_findings

        # Compute Framework Summaries & Percentages
        framework_summary: Dict[str, dict] = {}

        for fw_name, total_baseline in self.FRAMEWORK_BASELINES.items():
            if fw_name == "owasp_top_10_2021":
                failed_dict = owasp_controls
            elif fw_name == "cis_benchmarks":
                failed_dict = cis_controls
            else:
                failed_dict = nist_controls

            controls_failed = len(failed_dict)
            controls_passed = max(0, total_baseline - controls_failed)
            compliance_pct = round((controls_passed / total_baseline) * 100.0, 1)

            framework_summary[fw_name] = {
                "total_controls_baseline": total_baseline,
                "controls_passed": controls_passed,
                "controls_failed": controls_failed,
                "compliance_percentage": compliance_pct,
                "failed_controls_breakdown": failed_dict
            }

        # Calculate overall framework compliance average score
        total_pct = sum(fdata["compliance_percentage"] for fdata in framework_summary.values())
        overall_compliance_score = round(total_pct / len(framework_summary), 1) if framework_summary else 100.0

        compliance_matrix = {
            "title": "DevSecOps Enterprise Advanced Compliance Matrix",
            "generated_at": master_report.get("generated_at"),
            "overall_compliance_score": overall_compliance_score,
            "total_findings": len(enriched_findings),
            "framework_summaries": framework_summary
        }

        # Save to compliance/reports/compliance/compliance_matrix.json
        COMPLIANCE_DIR.mkdir(parents=True, exist_ok=True)
        with open(COMPLIANCE_MATRIX_PATH, "w", encoding="utf-8") as fp:
            json.dump(compliance_matrix, fp, indent=4)

        master_report["compliance_summary"] = framework_summary
        if "summary" in master_report:
            master_report["summary"]["compliance_score"] = overall_compliance_score

        # Also update master_report.json on disk with compliance_summary & score
        master_report_path = Path("compliance/master_reports/master_report.json")
        try:
            with open(master_report_path, "w", encoding="utf-8") as fp:
                json.dump(master_report, fp, indent=4)
        except Exception as ex:
            logger.warning(f"Could not update master_report.json on disk: {ex}")

        logger.info(f"Saved advanced compliance matrix with Overall Compliance Score: {overall_compliance_score}% to {COMPLIANCE_MATRIX_PATH}")
        return master_report



def main():
    mapper = ComplianceMapper()
    print("Advanced Compliance Mapper initialized.")


if __name__ == "__main__":
    main()
