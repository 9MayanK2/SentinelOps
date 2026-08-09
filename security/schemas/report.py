from dataclasses import dataclass, asdict
from typing import List

from .finding import Finding
from .summary import Summary


@dataclass
class Report:

    ############################################################
    # Report Information
    ############################################################

    tool: str

    category: str

    scanner_type: str

    scan_time: str

    status: str

    ############################################################
    # Report Summary
    ############################################################

    summary: Summary

    ############################################################
    # Scanner Metadata
    ############################################################

    metadata: dict

    ############################################################
    # Findings
    ############################################################

    findings: List[Finding]

    ############################################################
    # Serialization
    ############################################################

    def to_dict(self):

        return {

            "tool": self.tool,

            "category": self.category,

            "scanner_type": self.scanner_type,

            "scan_time": self.scan_time,

            "status": self.status,

            "summary": self.summary.to_dict(),

            "metadata": self.metadata,

            "findings": [

                finding.to_dict()

                for finding in self.findings

            ]

        }
