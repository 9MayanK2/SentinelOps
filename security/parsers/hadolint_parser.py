"""
hadolint_parser.py

Enterprise Hadolint Parser

Converts Hadolint JSON reports into normalized Finding objects.

Framework Responsibilities
--------------------------
BaseParser handles:
    ✔ Report loading
    ✔ Validation
    ✔ Metadata generation
    ✔ Statistics
    ✔ Report generation
    ✔ Report writing
    ✔ Logging
    ✔ Error handling

This parser only implements:
    ✔ Hadolint finding extraction
    ✔ Rule recommendation lookup
"""

from __future__ import annotations

from security.core.base_parser import BaseParser
from security.core.parser_registry import registry

from security.schemas.finding import Finding

from security.common.logger import logger
from security.common.recommendation import get_recommendation
from security.common.severity import normalize_severity
from security.common.status import STATUS_OPEN
from security.common.categories import CATEGORY_CONTAINER
from security.common.scanner_type import SCANNER_STATIC

from security.common.validator import validate_hadolint_report
from security.config.config_loader import get


############################################################
# Configuration
############################################################

TOOL_NAME = "Hadolint"

REPORT_DIR = get(
    "HADOLINT",
    "report_dir"
)

OUTPUT_DIR = get(
    "HADOLINT",
    "output_dir"
)


############################################################
# Parser
############################################################

class HadolintParser(BaseParser):
    """
    Enterprise Hadolint parser.
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

    ########################################################
    # Validation Override
    ########################################################

    def validate(self) -> None:
        logger.info(f"[{self.tool_name}] Validating report...")
        validate_hadolint_report(self.raw_report)

    ########################################################
    # Helper : Rule Lookup
    ########################################################

    def build_rule(
        self,
        item: dict
    ) -> dict:
        """
        Returns recommendation information
        for a Hadolint rule.
        """

        rule = get_recommendation(

            TOOL_NAME,

            item.get(
                "code",
                ""
            )

        )

        if rule is not None:

            return rule

        logger.warning(

            f"No recommendation found for "

            f"{item.get('code')}"

        )

        return {
    "title": item.get("code", "Unknown Rule"),
    "description": item.get("message", ""),
    "recommendation": "No recommendation available.",
    "reference": None
    }

    ########################################################
    # Extract Findings
    ########################################################

    def extract_findings(self):

        findings = []

        if not self.raw_report:

            logger.warning(

                "Hadolint report is empty."

            )

            return findings

        for item in self.raw_report:
                        ################################################
            # Severity
            ################################################

            severity = normalize_severity(

                item.get(

                    "level",

                    "UNKNOWN"

                )

            )

            ################################################
            # Recommendation
            ################################################

            rule = self.build_rule(

                item

            )

            ################################################
            # Build Finding
            ################################################

            finding = Finding(

                ################################################
                # Framework Fields
                ################################################

                tool=TOOL_NAME,

                category=CATEGORY_CONTAINER,

                ################################################
                # Rule Information
                ################################################

                rule_id=item.get(

                    "code",

                    ""

                ),

                ################################################
                # Severity
                ################################################

                severity=severity,

                ################################################
                # Location
                ################################################

                file=item.get(

                    "file"

                ),

                line=item.get(

                    "line"

                ),

                ################################################
                # Message
                ################################################

                message=item.get(

                    "message"

                ),

                ################################################
                # Recommendation
                ################################################

                recommendation=rule.get(

                    "recommendation"

                ),

                ################################################
                # Runtime
                ################################################

                status=STATUS_OPEN,

                scan_time=self.scan_time,

                ################################################
                # Package Information
                ################################################

                package_name=None,

                installed_version=None,

                fixed_version=None,

                ################################################
                # Vulnerability Metadata
                ################################################

                cvss_score=None,

                cwe=None,

                cve=None,

                severity_source=TOOL_NAME,

                ################################################
                # Resource Information
                ################################################

                target=item.get(

                    "file"

                ),

                target_class="Dockerfile",

                target_type="Container",

                ################################################
                # Documentation
                ################################################

                description=rule.get("description"),

                primary_url=(
                    rule.get("references")[0]
                    if rule.get("references")
                    else None
                ),
                references=rule.get("references", []),

                ################################################
                # Future Enterprise Fields
                ################################################

                compliance=[],

                exploit_available=False,

                fix_available=False,

                epss_score=None,

                kev=False

            )

            ################################################
            # Store Finding
            ################################################

            findings.append(

                finding

            )

        ####################################################
        # Finished
        ####################################################

        logger.info(

            f"Parsed {len(findings)} Hadolint findings."

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

    "hadolint",

    HadolintParser

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

        "Starting Hadolint Parser"

    )

    logger.info("=" * 70)

    parser = HadolintParser()

    parser.run()

    logger.info("=" * 70)

    logger.info(

        "Hadolint Parser Finished"

    )

    logger.info("=" * 70)


############################################################
# Script Entry
############################################################

if __name__ == "__main__":

    main()
