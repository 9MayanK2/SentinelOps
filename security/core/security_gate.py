"""
security_gate.py

Enterprise Security Gate Evaluator

Evaluates master report metrics and risk scores against security/config/policy.yaml.
Displays executive terminal summary and returns PASS/FAIL verdict.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any

from security.common.logger import logger

POLICY_YAML_PATH = Path("security/config/policy.yaml")


class SecurityGate:
    """
    Evaluates master report metrics and risk engine scores against policy.yaml.
    """

    def __init__(self, master_report: dict, policy_path: Path = POLICY_YAML_PATH):
        self.report = master_report
        self.summary = master_report.get("summary", {})
        self.risk_summary = master_report.get("risk_summary", {})
        self.compliance_summary = master_report.get("compliance_summary", {})
        self.policy_path = Path(policy_path)
        self.policy = self.load_policy()

    def load_policy(self) -> dict:
        """
        Loads policy rules from security/config/policy.yaml.
        """
        default_policy = {
            "fail_on_critical": True,
            "fail_on_high": False,
            "minimum_score": 70.0,
            "max_allowed_risk_score": 50
        }

        if not self.policy_path.exists():
            return default_policy

        try:
            # Simple YAML parser fallback if pyyaml is not installed
            policy_data = {}
            with open(self.policy_path, "r", encoding="utf-8") as fp:
                lines = fp.readlines()

            in_policy = False
            for line in lines:
                line_str = line.strip()
                if line_str.startswith("policy:"):
                    in_policy = True
                    continue
                elif line_str and not line_str.startswith("#") and not line.startswith(" ") and not line.startswith("\t"):
                    in_policy = False

                if in_policy and ":" in line_str:
                    key, val = line_str.split(":", 1)
                    key = key.strip()
                    val = val.strip().lower()
                    if val == "true":
                        policy_data[key] = True
                    elif val == "false":
                        policy_data[key] = False
                    else:
                        try:
                            policy_data[key] = float(val) if "." in val else int(val)
                        except ValueError:
                            policy_data[key] = val

            return {**default_policy, **policy_data}
        except Exception as ex:
            logger.warning(f"Could not parse {self.policy_path}: {ex}. Using default policy.")
            return default_policy

    def evaluate(self, soft_fail: bool = False) -> bool:
        """
        Evaluates metrics against policy.yaml and displays Executive Security & Risk Table.
        """
        logger.info("Evaluating Security Gate policy from policy.yaml...")

        fail_on_critical = self.policy.get("fail_on_critical", True)
        fail_on_high = self.policy.get("fail_on_high", False)
        min_score = float(self.policy.get("minimum_score", 70.0))
        max_risk_score = int(self.policy.get("max_allowed_risk_score", 50))

        total_findings = self.summary.get("total_findings", 0)
        critical_count = self.summary.get("critical", 0)
        high_count = self.summary.get("high", 0)
        medium_count = self.summary.get("medium", 0)
        low_count = self.summary.get("low", 0)
        info_count = self.summary.get("info", 0)

        # Risk Engine metrics
        total_risk_score = self.risk_summary.get("total_risk_score", (critical_count * 10) + (high_count * 5) + (medium_count * 2) + low_count)
        risk_level = self.risk_summary.get("risk_level", "UNKNOWN")
        score = self.summary.get("compliance_score", 100.0)

        reasons: List[str] = []

        if fail_on_critical and critical_count > 0:
            reasons.append(f"Found {critical_count} CRITICAL findings (Policy: 0 allowed).")

        if fail_on_high and high_count > 0:
            reasons.append(f"Found {high_count} HIGH findings (Policy: 0 allowed).")

        if score < min_score:
            reasons.append(f"Compliance score {score:.1f}% is below minimum {min_score}%.")

        if total_risk_score > max_risk_score:
            reasons.append(f"Total Risk Score ({total_risk_score}) exceeds max threshold ({max_risk_score}).")

        passed = len(reasons) == 0
        scanners = ", ".join(self.report.get("scanners_executed", [])) or "None"

        print("\n" + "=" * 70)
        print("             DEVSECOPS SECURITY GATE & RISK SUMMARY")
        print("=" * 70)
        print(f" Scanners Executed   : {scanners}")
        print(f" Total Findings      : {total_findings}")
        print(f"   - CRITICAL (10pt) : {critical_count}")
        print(f"   - HIGH     (5pt)  : {high_count}")
        print(f"   - MEDIUM   (2pt)  : {medium_count}")
        print(f"   - LOW      (1pt)  : {low_count}")
        print(f"   - INFO     (0pt)  : {info_count}")
        print(f" Total Risk Score    : {total_risk_score} Points")
        print(f" Overall Risk Level  : [ {risk_level} ]")
        print(f" Compliance Score    : {score:.1f}%")
        print("-" * 70)
        print(" COMPLIANCE POSTURE BY FRAMEWORK:")

        for fw_key, fw_data in self.compliance_summary.items():
            fw_title = fw_key.replace("_", " ").upper()
            pct = fw_data.get("compliance_percentage", 0.0)
            passed_cnt = fw_data.get("controls_passed", 0)
            baseline = fw_data.get("total_controls_baseline", 0)
            failed_cnt = fw_data.get("controls_failed", 0)
            print(f"  • {fw_title:<20} : {pct}% Pass ({passed_cnt}/{baseline} Passed, {failed_cnt} Failed)")

        print("=" * 70)

        if passed:
            print(" VERDICT             : [ PASS ] Security Gate Passed Successfully!")
            print("=" * 70 + "\n")
            return True
        else:
            print(" VERDICT             : [ FAIL ] Security Gate Failed!")
            for reason in reasons:
                print(f"  ❌ {reason}")
            print("=" * 70 + "\n")
            if soft_fail:
                print(" ⚠️  [WARNING] SOFT-FAIL MODE ACTIVE: Gate failed policy checks, but returning Exit Code 0 for downstream pipeline testing.\n")
                return True
            return False

