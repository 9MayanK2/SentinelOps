from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Finding:

    ############################################################
    # Common Fields
    ############################################################

    tool: str
    category: str

    rule_id: str

    severity: str

    file: Optional[str]

    line: Optional[int]

    message: Optional[str]

    recommendation: Optional[str]

    status: str

    scan_time: str

    ############################################################
    # Vulnerability Information
    ############################################################

    package_name: Optional[str] = None

    installed_version: Optional[str] = None

    fixed_version: Optional[str] = None

    ############################################################
    # Security Metadata
    ############################################################

    cvss_score: Optional[float] = None

    cwe: Optional[list[str]] = None

    cve: Optional[str] = None

    severity_source: Optional[str] = None

    ############################################################
    # Resource Information
    ############################################################

    target: Optional[str] = None

    target_class: Optional[str] = None

    target_type: Optional[str] = None

    ############################################################
    # Documentation
    ############################################################

    description: Optional[str] = None

    primary_url: Optional[str] = None

    references: list[str] | None = None

    ############################################################
    # Future Compliance Fields
    ############################################################

    compliance: Optional[list] = None

    exploit_available: Optional[bool] = None

    fix_available: Optional[bool] = None

    epss_score: Optional[float] = None

    kev: Optional[bool] = None

    ############################################################
    # Serialization
    ############################################################

    def to_dict(self):

        return asdict(self)

