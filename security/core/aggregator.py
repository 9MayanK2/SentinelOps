"""
aggregator.py

Enterprise DevSecOps Report Aggregator with Risk Engine Integration.
Aggregates all normalized target reports into compliance/master_reports/master_report.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Set

from security.common.logger import logger
from security.core.risk_engine import RiskEngine

NORMALIZED_DIR = Path("compliance/normalized")
MASTER_DIR = Path("compliance/master_reports")
LATEST_MASTER_PATH = MASTER_DIR / "master_report.json"


class Aggregator:
    """
    Combines normalized scanner reports into a master report inside compliance/master_reports/master_report.json
    and evaluates risk via RiskEngine.
    """

    def __init__(self, normalized_dir: str | Path = NORMALIZED_DIR, master_dir: str | Path = MASTER_DIR):
        self.normalized_dir = Path(normalized_dir)
        self.master_dir = Path(master_dir)
        self.findings: List[dict] = []
        self.scanners_run: List[str] = []

    def collect_latest_reports(self) -> List[Path]:
        """
        Discovers the newest normalized report for EVERY target prefix in each tool subdirectory.
        """
        latest_reports: List[Path] = []
        if not self.normalized_dir.exists():
            return latest_reports

        for subdir in self.normalized_dir.iterdir():
            if subdir.is_dir():
                json_files = list(subdir.glob("*_normalized.json"))
                grouped: Dict[str, Path] = {}
                for fpath in json_files:
                    parts = fpath.name.split("_")
                    prefix = "_".join(parts[:-2]) if len(parts) >= 3 else fpath.stem
                    mtime = fpath.stat().st_mtime

                    if prefix not in grouped or mtime > grouped[prefix].stat().st_mtime:
                        grouped[prefix] = fpath

                latest_reports.extend(grouped.values())
        return latest_reports

    def aggregate(self) -> dict:
        """
        Reads normalized reports, deduplicates findings, runs Risk Engine, and builds master report.
        """
        logger.info("Starting master report aggregation with Risk Engine...")
        reports = self.collect_latest_reports()

        seen_keys: Set[str] = set()

        for report_path in reports:
            try:
                with open(report_path, "r", encoding="utf-8") as fp:
                    data = json.load(fp)

                tool_name = data.get("tool", "Unknown")
                if tool_name not in self.scanners_run:
                    self.scanners_run.append(tool_name)

                for finding in data.get("findings", []):
                    tool = finding.get("tool", tool_name)
                    rule_id = finding.get("rule_id", "")
                    file_path = finding.get("file", "")
                    line = finding.get("line", "")

                    key = f"{tool}:{rule_id}:{file_path}:{line}"
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    self.findings.append(finding)

            except Exception as ex:
                logger.error(f"Error reading report {report_path}: {ex}")

        # Compute Risk & Summary metrics using RiskEngine
        risk_engine = RiskEngine()
        risk_summary = risk_engine.calculate_risk(self.findings)

        master_report = {
            "title": "Master DevSecOps Security Report",
            "generated_at": datetime.utcnow().isoformat(),
            "scanners_executed": sorted(self.scanners_run),
            "summary": {
                "total_findings": risk_summary["total_findings"],
                "critical": risk_summary["critical"],
                "high": risk_summary["high"],
                "medium": risk_summary["medium"],
                "low": risk_summary["low"],
                "info": risk_summary["info"],
                "compliance_score": risk_summary["compliance_score"]
            },
            "risk_summary": {
                "total_risk_score": risk_summary["total_risk_score"],
                "risk_level": risk_summary["risk_level"]
            },
            "findings": self.findings
        }

        # Save single master_report.json inside compliance/master_reports/
        self.master_dir.mkdir(parents=True, exist_ok=True)
        with open(LATEST_MASTER_PATH, "w", encoding="utf-8") as fp:
            json.dump(master_report, fp, indent=4)

        logger.info(f"Master report saved at: {LATEST_MASTER_PATH}")
        return master_report


def main():
    aggregator = Aggregator()
    master = aggregator.aggregate()
    print(f"Aggregated {master['summary']['total_findings']} findings. Risk Score: {master['risk_summary']['total_risk_score']}")


if __name__ == "__main__":
    main()
