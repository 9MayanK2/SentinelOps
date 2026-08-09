"""
statistics.py

Enterprise Statistics Engine

Responsible for calculating normalized scan statistics
from parsed findings.
"""

from security.schemas.summary import Summary


class Statistics:

    ############################################################
    # Main Entry
    ############################################################

    @staticmethod
    def calculate(findings):

        summary = Summary()

        summary.total = len(findings)

        for finding in findings:

            Statistics._count_severity(summary, finding)

            Statistics._count_fixable(summary, finding)

            Statistics._count_exploitable(summary, finding)

            Statistics._count_status(summary, finding)

        ########################################################
        # Compliance
        ########################################################

        summary.compliance_score = Statistics.compliance(summary)

        ########################################################
        # Scan Statistics
        ########################################################

        summary.scanned_targets = 1

        summary.scanned_packages = 0

        summary.scanned_files = Statistics.unique_files(findings)

        return summary

    ############################################################
    # Severity
    ############################################################

    @staticmethod
    def _count_severity(summary, finding):

        severity = str(

            getattr(

                finding,

                "severity",

                "UNKNOWN"

            )

        ).upper()

        if severity == "CRITICAL":

            summary.critical += 1

        elif severity == "HIGH":

            summary.high += 1

        elif severity == "MEDIUM":

            summary.medium += 1

        elif severity == "LOW":

            summary.low += 1

        elif severity == "INFO":

            summary.info += 1

        else:

            summary.unknown += 1

    ############################################################
    # Fixable
    ############################################################

    @staticmethod
    def _count_fixable(summary, finding):

        if getattr(

            finding,

            "fixed_version",

            None

        ):

            summary.fixable += 1

    ############################################################
    # Exploitable
    ############################################################

    @staticmethod
    def _count_exploitable(summary, finding):

        score = getattr(

            finding,

            "cvss_score",

            None

        )

        if score is None:

            return

        try:

            score = float(score)

        except Exception:

            return

        if score >= 7.0:

            summary.exploitable += 1

    ############################################################
    # Status
    ############################################################

    @staticmethod
    def _count_status(summary, finding):

        status = str(

            getattr(

                finding,

                "status",

                ""

            )

        ).upper()

        if status == "SUPPRESSED":

            summary.suppressed += 1

    ############################################################
    # Compliance
    ############################################################

    @staticmethod
    def compliance(summary):

        if summary.total == 0:

            return 100.0

        passed = (

            summary.total

            - summary.critical

            - summary.high

            - summary.medium

        )

        return round(

            (passed / summary.total) * 100,

            2

        )

    ############################################################
    # Utility
    ############################################################

    @staticmethod
    def unique_files(findings):

        files = set()

        for finding in findings:

            filename = getattr(

                finding,

                "file",

                None

            )

            if filename:

                files.add(filename)

        return len(files)
