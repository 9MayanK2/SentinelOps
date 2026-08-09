"""
orchestrator.py

Enterprise DevSecOps Security Orchestrator

Master controller implementing the 5-Stage Execution Flow:
  Stage 1: Pre-flight Checks (Configurations, Docker, Directories, Policy)
  Stage 2: Run Active Scanners (Gitleaks, Hadolint, Trivy, etc.)
  Stage 3: Run Parsers (ParserRegistry.run_all())
  Stage 4: Aggregate Results (Aggregator -> compliance/master_reports/)
  Stage 5: Security Gate Evaluation (SecurityGate) -> PASS (Exit 0) / FAIL (Exit 1)

Supports selective tool and stage execution via CLI arguments (--tools, --stage).
"""

from __future__ import annotations

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional

from security.common.logger import logger
from security.core.parser_registry import registry
from security.core.aggregator import Aggregator
from security.core.security_gate import SecurityGate
from security.core.compliance_mapper import ComplianceMapper
from security.core.report_generator import ReportGenerator
from security.db.database import DatabaseManager




# Import parsers to auto-register
import security.parsers.hadolint_parser
import security.parsers.trivy_parser
import security.parsers.gitleaks_parser
import security.parsers.zap_parser



class SecurityOrchestrator:
    """
    Master 5-Stage DevSecOps Security Orchestrator.
    """

    def __init__(self, selected_tools: Optional[List[str]] = None, selected_stages: Optional[List[str]] = None, soft_fail: bool = False):
        self.project_root = Path.cwd()
        self.selected_tools = [t.lower() for t in selected_tools] if selected_tools else None
        self.selected_stages = [s.lower() for s in selected_stages] if selected_stages else None
        self.soft_fail = soft_fail

    def should_run_tool(self, tool_name: str) -> bool:
        if not self.selected_tools:
            return True
        return tool_name.lower() in self.selected_tools

    def should_run_stage(self, stage_name: str) -> bool:
        if not self.selected_stages:
            return True
        return stage_name.lower() in self.selected_stages

    def stage_1_preflight(self) -> bool:
        """
        Stage 1: Pre-flight Checks.
        Validates environment, Docker daemon, and output directories.
        """
        if not self.should_run_stage("preflight"):
            return True

        logger.info("=== STAGE 1: Pre-flight Checks ===")

        # Check Docker daemon
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True
            )
            if res.returncode != 0:
                logger.error("Pre-flight Failed: Docker daemon is not running.")
                print("\n❌ Pre-flight Failed: Docker daemon is not running.")
                return False
        except Exception as ex:
            logger.error(f"Pre-flight Failed: Docker error - {ex}")
            print(f"\n❌ Pre-flight Failed: Docker is not accessible ({ex}).")
            return False

        # Create output directories
        (self.project_root / "compliance/reports").mkdir(parents=True, exist_ok=True)
        (self.project_root / "compliance/normalized").mkdir(parents=True, exist_ok=True)
        (self.project_root / "compliance/master_reports").mkdir(parents=True, exist_ok=True)
        (self.project_root / "compliance/logs").mkdir(parents=True, exist_ok=True)

        logger.info("Pre-flight Checks Passed.")
        return True

    def stage_2_run_scanners(self) -> None:
        """
        Stage 2: Run Active Scanners.
        Executes scanner shell scripts.
        """
        if not self.should_run_stage("scanners"):
            return

        logger.info("=== STAGE 2: Running Scanners ===")

        scanners: List[Tuple[str, str]] = [
            ("Gitleaks", "security/secrets/gitleaks.sh"),
            ("Hadolint", "security/container/hadolint.sh"),
            ("Trivy", "security/container/trivy.sh"),
            ("ZAP", "security/dast/zap.sh"),
        ]


        for name, script_path in scanners:
            if self.should_run_tool(name):
                full_path = self.project_root / script_path
                if full_path.exists():
                    logger.info(f"Running {name} scanner ({script_path})...")
                    res = subprocess.run(["bash", str(full_path)], check=False)
                    if res.returncode == 0:
                        logger.info(f"{name} scanner completed successfully.")
                    else:
                        logger.warning(f"{name} scanner exited with code {res.returncode}")
                else:
                    logger.warning(f"Scanner script not found: {script_path}")

    def stage_3_run_parsers(self) -> None:
        """
        Stage 3: Run Parsers.
        Executes registered parsers via ParserRegistry.
        """
        if not self.should_run_stage("parsers"):
            return

        logger.info("=== STAGE 3: Running Parsers ===")
        if self.selected_tools:
            for tool in self.selected_tools:
                try:
                    logger.info(f"Running parser for tool: {tool}")
                    registry.run(tool)
                except Exception as ex:
                    logger.warning(f"Parser for {tool} failed or not registered: {ex}")
        else:
            registry.run_all()

    def stage_4_aggregate(self) -> dict:
        """
        Stage 4: Aggregate Results.
        Combines normalized reports into compliance/master_reports/master_report.json.
        """
        if not self.should_run_stage("aggregate"):
            return {}

        logger.info("=== STAGE 4: Aggregating Results ===")
        aggregator = Aggregator()
        master_report = aggregator.aggregate()

        # Apply Compliance Mapping Layer (OWASP Top 10, CIS, NIST)
        try:
            mapper = ComplianceMapper()
            master_report = mapper.process_master_report(master_report)
        except Exception as ex:
            logger.warning(f"Compliance Mapper Warning: {ex}")

        # Step 4: Generate Executive HTML & PDF Security Reports
        try:
            reporter = ReportGenerator()
            reporter.generate_all(master_report)
        except Exception as ex:
            logger.warning(f"Report Generator Warning: {ex}")

        return master_report



    def stage_5_security_gate(self, master_report: Optional[Dict[str, Any]] = None) -> bool:
        """
        Stage 5: Security Gate Evaluation & Compliance Check.
        """
        if not self.should_run_stage("gate"):
            return True

        if master_report is None:
            master_file = self.project_root / "compliance/master_reports/master_report.json"
            if master_file.exists():
                with open(master_file, "r", encoding="utf-8") as fp:
                    master_report = json.load(fp)
            else:
                master_report = Aggregator().aggregate()

        gate = SecurityGate(master_report)
        passed = gate.evaluate(soft_fail=self.soft_fail)

        # Ingest into Database (SQLite for local, PostgreSQL for AWS EC2/RDS)
        try:
            db_mgr = DatabaseManager()
            db_mgr.save_master_report(master_report, verdict="PASS" if passed else "FAIL")
        except Exception as ex:
            logger.warning(f"Database Ingestion Warning: {ex}")

        return passed


    def run(self) -> None:

        """
        Main entrypoint executing the 5-Stage Pipeline.
        """
        print("\n🚀 STARTING DEVSECOPS SECURITY ORCHESTRATOR 🚀\n")

        if not self.stage_1_preflight():
            sys.exit(1)

        self.stage_2_run_scanners()
        self.stage_3_run_parsers()
        master_report = self.stage_4_aggregate()
        if self.should_run_stage("gate"):
            passed = self.stage_5_security_gate(master_report)
            if passed:
                sys.exit(0)
            else:
                sys.exit(1)
        else:
            sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="DevSecOps Security Orchestrator")
    parser.add_argument("intent", nargs="?", default="full", help="Intent profile (pre-build, post-build, report, gate, full)")
    parser.add_argument("tool", nargs="?", default=None, help="Target tool (gitleaks, hadolint, trivy)")

    # Legacy flags & options
    parser.add_argument("--tools", type=str, help="Comma-separated tools")
    parser.add_argument("--stage", type=str, help="Comma-separated stages")
    parser.add_argument("--soft-fail", action="store_true", help="Soft fail mode (returns exit code 0 for development/testing)")

    args = parser.parse_args()

    intent = args.intent.lower() if args.intent else "full"
    tool = args.tool.lower() if args.tool else None
    soft_fail = args.soft_fail or os.getenv("SOFT_FAIL", "false").lower() == "true" or os.getenv("ENFORCE_GATE", "true").lower() == "false"

    # Map Intent to internal framework execution plan
    if intent in ["pre-build", "prebuild"]:
        stages = ["preflight", "scanners", "parsers"]
        tools = [tool] if tool else ["gitleaks", "hadolint"]
    elif intent in ["post-build", "postbuild"]:
        stages = ["scanners", "parsers"]
        tools = [tool] if tool else ["trivy"]
    elif intent in ["dast", "zap"]:
        stages = ["scanners", "parsers"]
        tools = [tool] if tool else ["zap"]
    elif intent in ["report", "reports"]:
        stages = ["aggregate"]
        tools = None
    elif intent in ["gate", "evaluate"]:
        stages = ["aggregate", "gate"]
        tools = None
    elif intent in ["sign", "signing"]:
        import subprocess
        res = subprocess.run(["bash", "security/signing/sign_images.sh"])
        sys.exit(res.returncode)
    elif intent in ["verify", "verification"]:
        import subprocess
        res = subprocess.run(["bash", "security/signing/verify_images.sh"])
        sys.exit(res.returncode)
    else:
        stages = [s.strip() for s in args.stage.split(",")] if args.stage else None
        tools = [t.strip() for t in args.tools.split(",")] if args.tools else ([tool] if tool else None)

    orchestrator = SecurityOrchestrator(selected_tools=tools, selected_stages=stages, soft_fail=soft_fail)
    orchestrator.run()



if __name__ == "__main__":
    main()

