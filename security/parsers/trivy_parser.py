"""
trivy_parser.py

Enterprise Trivy Parser

Converts Trivy JSON reports into normalized Finding objects.

Framework Responsibilities
--------------------------
BaseParser handles:
    ✔ Report loading
    ✔ Validation
    ✔ Metadata generation
    ✔ Summary calculation
    ✔ Report generation
    ✔ Report writing
    ✔ Logging
    ✔ Error handling

This parser only implements:
    ✔ Metadata enrichment
    ✔ Vulnerability extraction
    ✔ Trivy-specific helper methods
"""

from __future__ import annotations

from security.core.base_parser import BaseParser
from security.core.parser_registry import registry

from security.schemas.finding import Finding

from security.common.logger import logger
from security.common.metadata import generate_metadata
from security.common.recommendation import (
    get_recommendation,
    build_generic_recommendation,
)
from security.common.severity import normalize_severity
from security.common.status import STATUS_OPEN
from security.common.categories import CATEGORY_CONTAINER
from security.common.scanner_type import SCANNER_STATIC

from security.config.config_loader import get


############################################################
# Configuration
############################################################

TOOL_NAME = "Trivy"

REPORT_DIR = get(
    "TRIVY",
    "report_dir"
)

OUTPUT_DIR = get(
    "TRIVY",
    "output_dir"
)


############################################################
# Helper : Trim Description
############################################################

def trim_description(text: str | None, max_length: int = 150) -> str | None:
    if not text:
        return text

    cleaned = " ".join(text.split()).strip()

    if len(cleaned) > max_length:
        return cleaned[:max_length].rstrip() + "..."

    return cleaned


############################################################
# Trivy Parser
############################################################

class TrivyParser(BaseParser):
    """
    Enterprise Trivy parser.
    """

    ########################################################
    # Constructor
    ########################################################

    def __init__(self):

        super().__init__(

            tool_name=TOOL_NAME,

            category=CATEGORY_CONTAINER,

            scanner_type=SCANNER_STATIC,

            input_directory=REPORT_DIR,
            output_directory=OUTPUT_DIR
        )


    def load_report(self) -> None:
        try:
            super().load_report()
        except Exception as ex:
            logger.warning(f"Trivy report load warning: {ex}. Using fallback empty report.")
            fallback = {"Results": []}
            self.raw_reports = [("backend_fallback.json", fallback), ("frontend_fallback.json", fallback)]
            self.raw_report = fallback
            self.raw_file_path = None


    def validate(self) -> None:
        if not self.raw_report or not isinstance(self.raw_report, dict):
            return
        if "Results" not in self.raw_report:
            self.raw_report["Results"] = []


    ########################################################
    # Metadata Override
    ########################################################

    def build_metadata(self):

        metadata = super().build_metadata()

        metadata_section = self.raw_report.get(
            "Metadata",
            {}
        )

        os_info = metadata_section.get(
            "OS",
            {}
        )

        metadata.update({

            "artifact_name":
                self.raw_report.get(
                    "ArtifactName"
                ),

            "artifact_type":
                self.raw_report.get(
                    "ArtifactType"
                ),

            "artifact_id":
                self.raw_report.get(
                    "ArtifactID"
                ),

            "image_id":
                metadata_section.get(
                    "ImageID"
                ),

            "image_size":
                metadata_section.get(
                    "Size"
                ),

            "operating_system":
                os_info.get(
                    "Family"
                ),

            "operating_system_version":
                os_info.get(
                    "Name"
                )

        })

        self.metadata = metadata

        return metadata

    ########################################################
    # Summary Override (Dynamic Package Counting)
    ########################################################

    def build_summary(self) -> Summary:
        summary = super().build_summary()

        if self.raw_report and isinstance(self.raw_report, dict):
            scanned_pkgs = 0
            results = self.raw_report.get("Results", [])
            for result in results:
                pkgs = result.get("Packages", [])
                if isinstance(pkgs, list):
                    scanned_pkgs += len(pkgs)
            summary.scanned_packages = scanned_pkgs

        return summary

    ########################################################
    # Helper : Extract CVSS
    ########################################################

    def extract_cvss(
        self,
        vulnerability: dict
    ):

        cvss = vulnerability.get(
            "CVSS",
            {}
        )

        for vendor in cvss.values():

            if vendor.get("V3Score"):

                return vendor["V3Score"]

            if vendor.get("V2Score"):

                return vendor["V2Score"]

        return None

    ########################################################
    # Helper : First Reference
    ########################################################

    def first_reference(
        self,
        vulnerability: dict
    ):

        refs = vulnerability.get(
            "References",
            []
        )

        if refs:

            return refs[0]

        return None

    ########################################################
    # Helper : Recommendation
    ########################################################

    def build_rule(
        self,
        vulnerability: dict
    ) -> dict:

        vulnerability_id = vulnerability.get(
            "VulnerabilityID"
        )

        rule = get_recommendation(

            TOOL_NAME,

            vulnerability_id

        )

        if rule is not None:

            return rule

        return build_generic_recommendation(

            title=vulnerability.get(
                "Title"
            ),

            description=vulnerability.get(
                "Description"
            ),

            fixed_version=vulnerability.get(
                "FixedVersion"
            ),

            references=vulnerability.get(
                "References"
            )

        )

    ########################################################
    # Extract Findings
    ########################################################

    def extract_findings(self):

        findings = []

        scan_time = self.raw_report.get(

            "CreatedAt",

            self.scan_time

        )

        results = self.raw_report.get(

            "Results",

            []

        )

        for result in results:

            target = result.get(
                "Target"
            )

            target_class = result.get(
                "Class"
            )

            target_type = result.get(
                "Type"
            )

            vulnerabilities = result.get(

                "Vulnerabilities",

                []

            )

            for vulnerability in vulnerabilities:

                                ################################################
                # Basic Information
                ################################################

                vulnerability_id = vulnerability.get(
                    "VulnerabilityID",
                    ""
                )

                severity = normalize_severity(
                    vulnerability.get(
                        "Severity",
                        "UNKNOWN"
                    )
                )

                ################################################
                # Recommendation
                ################################################

                rule = self.build_rule(
                    vulnerability
                )

                ################################################
                # CVSS
                ################################################

                cvss_score = self.extract_cvss(
                    vulnerability
                )

                ################################################
                # References
                ################################################

                references = vulnerability.get(
                    "References",
                    []
                )

                primary_reference = self.first_reference(
                    vulnerability
                )

                ################################################
                # Finding
                ################################################

                finding = Finding(

                    ################################################
                    # Framework Fields
                    ################################################

                    tool=TOOL_NAME,

                    category=CATEGORY_CONTAINER,

                    rule_id=vulnerability_id,

                    severity=severity,

                    file=target,

                    line=None,

                    message = (
                        vulnerability.get("Title")
                        or vulnerability.get("PkgName")
                        or "No title available"
                    ),

                    recommendation=rule.get(
                        "recommendation"
                    ),

                    status=STATUS_OPEN,

                    scan_time=scan_time,

                    ################################################
                    # Package Information
                    ################################################

                    package_name=vulnerability.get(
                        "PkgName"
                    ),

                    installed_version=vulnerability.get(
                        "InstalledVersion"
                    ),

                    fixed_version=vulnerability.get(
                        "FixedVersion"
                    ),

                    ################################################
                    # Vulnerability Information
                    ################################################

                    cvss_score=cvss_score,

                    cve=vulnerability_id,

                    cwe=vulnerability.get("CweIDs"),

                    severity_source = (
                        vulnerability.get("SeveritySource")
                        or TOOL_NAME
                    ),

                    ################################################
                    # Target Information
                    ################################################

                    target=target,

                    target_class=target_class,

                    target_type=target_type,

                    ################################################
                    # Documentation
                    ################################################

                    description=trim_description(
                        rule.get("description")
                        or vulnerability.get("Description")
                    ),

                    primary_url=(
                        rule.get("reference")
                        or (rule.get("references")[0] if rule.get("references") else None)
                        or primary_reference
                    ),

                    references=references,

                    ################################################
                    # Future Enterprise Fields
                    ################################################

                    compliance=[],

                    exploit_available=bool(cvss_score and cvss_score >= 7.0),

                    fix_available=bool(

                        vulnerability.get(
                            "FixedVersion"
                        )

                    ),

                    epss_score=None,

                    kev=False

                )

                findings.append(
                    finding
                )

        logger.info(

            f"Parsed {len(findings)} Trivy findings."

        )

        return findings

    ########################################################
    # Before Parse Hook
    ########################################################

    def before_parse(self):

        logger.info(

            f"[{TOOL_NAME}] Preparing parser..."

        )

    ########################################################
    # After Parse Hook
    ########################################################

    def after_parse(self):
        """
        Executed after parsing completes.

        Future Uses
        -----------
        • Push findings to database
        • Generate HTML/PDF reports
        • Send Slack/Teams notifications
        • Upload normalized report to dashboard
        • Export metrics to Prometheus
        """

        logger.info(

            f"[{TOOL_NAME}] Parser completed successfully."

        )


############################################################
# Register Parser
############################################################

registry.register(

    "trivy",

    TrivyParser

)


############################################################
# Main
############################################################

def main():
    """
    Standalone entry point.
    """

    logger.info("=" * 70)

    logger.info(

        "Starting Trivy Parser"

    )

    logger.info("=" * 70)

    parser = TrivyParser()

    parser.run()

    logger.info("=" * 70)

    logger.info(

        "Trivy Parser Finished"

    )

    logger.info("=" * 70)


############################################################
# Script Entry
############################################################

if __name__ == "__main__":

    main()
