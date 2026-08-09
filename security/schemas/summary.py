from dataclasses import dataclass, asdict


@dataclass
class Summary:

    ############################################################
    # Finding Counts
    ############################################################

    total: int = 0

    critical: int = 0

    high: int = 0

    medium: int = 0

    low: int = 0

    info: int = 0

    unknown: int = 0

    ############################################################
    # Vulnerability Statistics
    ############################################################

    fixable: int = 0

    exploitable: int = 0

    suppressed: int = 0

    ############################################################
    # Scan Statistics
    ############################################################

    scanned_targets: int = 0

    scanned_packages: int = 0

    scanned_files: int = 0

    ############################################################
    # Compliance
    ############################################################

    passed_checks: int = 0

    failed_checks: int = 0

    compliance_score: float = 0.0

    ############################################################
    # Serialization
    ############################################################

    ############################################################
    # Update Compliance Score
    ############################################################

    def update_compliance(self):

        if self.total == 0:

            self.compliance_score = 100.0

            return

        passed = (

            self.total

            - self.critical

            - self.high

        )

        self.compliance_score = round(

            (passed / self.total) * 100,

            2

        )

    def to_dict(self):

        return asdict(self)
