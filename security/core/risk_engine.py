"""
risk_engine.py

Enterprise Risk Engine for DevSecOps Framework.
Calculates weighted risk scores, risk levels (LOW/MEDIUM/HIGH/CRITICAL), and compliance posture.
"""

from __future__ import annotations

from typing import List, Dict, Any
from security.common.logger import logger

DEFAULT_RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 1
}


class RiskEngine:
    """
    Evaluates findings and produces risk scores, risk levels, and compliance percentages.
    """

    def __init__(self, weights: Dict[str, int] | None = None):
        self.weights = weights or DEFAULT_RISK_WEIGHTS

    def calculate_risk(self, findings: List[dict]) -> dict:
        """
        Calculates total risk score, severity breakdown, overall risk level, and compliance score.
        """
        total_risk_score = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0

        for finding in findings:
            sev = (finding.get("severity") or "UNKNOWN").upper()
            weight = self.weights.get(sev, 1)
            total_risk_score += weight

            if sev == "CRITICAL":
                critical_count += 1
            elif sev == "HIGH":
                high_count += 1
            elif sev == "MEDIUM":
                medium_count += 1
            elif sev == "LOW":
                low_count += 1
            elif sev == "INFO":
                info_count += 1

        # Determine Overall Risk Level
        if total_risk_score == 0:
            risk_level = "NONE"
        elif total_risk_score <= 10:
            risk_level = "LOW"
        elif total_risk_score <= 30:
            risk_level = "MEDIUM"
        elif total_risk_score <= 60:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # Compliance Score = max(0, 100 - (total_risk_score * 1.5))
        compliance_score = max(0.0, float(100 - (total_risk_score * 1.5)))

        result = {
            "total_risk_score": total_risk_score,
            "risk_level": risk_level,
            "compliance_score": round(compliance_score, 1),
            "total_findings": len(findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "info": info_count
        }

        logger.info(f"Risk Engine Computed: Total Risk Score={total_risk_score}, Level={risk_level}, Score={compliance_score}%")
        return result


def main():
    engine = RiskEngine()
    print("Risk Engine initialized.")


if __name__ == "__main__":
    main()
