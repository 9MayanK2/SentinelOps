"""
base_parser.py

Enterprise Base Parser

Every security scanner parser should inherit from this class.

Responsibilities
----------------
✔ Read reports
✔ Validate reports
✔ Generate metadata
✔ Calculate statistics
✔ Build normalized reports
✔ Save reports
✔ Logging
✔ Execution timing
✔ Exception handling
✔ Lifecycle hooks

Child parsers only implement scanner-specific logic.
"""

from __future__ import annotations

import time
import traceback

from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import List, Any

from security.common.logger import logger
from security.common.metadata import generate_metadata
from security.common.validator import validate_report

from security.core.report_reader import ReportReader
from security.core.report_writer import ReportWriter
from security.core.statistics import Statistics
from security.core.exceptions import ParserError

from security.schemas.finding import Finding
from security.schemas.summary import Summary
from security.schemas.report import Report


class BaseParser(ABC):

    """
    Base class for every parser.

    Every parser shares the same lifecycle.

        Load Report
              ↓
        Validate Report
              ↓
        Generate Metadata
              ↓
        Parse Findings
              ↓
        Calculate Statistics
              ↓
        Build Report
              ↓
        Save Report
    """

    ############################################################
    # Constructor
    ############################################################

    def __init__(
        self,
        tool_name: str,
        category: str,
        scanner_type: str,
        input_directory: str,
        output_directory: str,
    ) -> None:

        ########################################################
        # Scanner Information
        ########################################################

        self.tool_name = tool_name

        self.category = category

        self.scanner_type = scanner_type

        self.parser_version = "1.0.0"

        ########################################################
        # Directories
        ########################################################

        self.input_directory = Path(input_directory)

        self.output_directory = Path(output_directory)

        ########################################################
        # Shared Framework Components
        ########################################################

        self.reader = ReportReader(
            self.input_directory
        )

        self.writer = ReportWriter(
            self.output_directory
        )

        ########################################################
        # Runtime Objects
        ########################################################

        self.raw_report: Any = None

        self.raw_reports: list[tuple[str, Any]] = []

        self.current_filename: str | None = None

        self.findings: List[Finding] = []

        self.summary: Summary | None = None

        self.metadata: dict | None = None

        self.report: Report | None = None

        ########################################################
        # Runtime Statistics
        ########################################################

        self.scan_time: str | None = None

        self.start_time: float = 0.0

        self.end_time: float = 0.0

        self.duration: float = 0.0

    ############################################################
    # Report Loading
    ############################################################

    def load_report(
        self,
        filename: str | None = None
    ) -> Any:

        """
        Load report(s).

        If filename is None,
        all latest raw reports (by target prefix) are loaded.
        """

        logger.info(
            f"[{self.tool_name}] Loading report(s)..."
        )

        if filename:

            data = self.reader.read_json(
                filename
            )

            self.raw_reports = [(filename, data)]

            self.raw_report = data

        else:

            self.raw_reports = self.reader.latest_raw_reports()

            if self.raw_reports:

                self.raw_report = self.raw_reports[0][1]

        return self.raw_reports

    ############################################################
    # Validation
    ############################################################

    def validate(self) -> None:

        logger.info(
            f"[{self.tool_name}] Validating report..."
        )

        validate_report(
            self.raw_report
        )

    ############################################################
    # Metadata
    ############################################################

    def build_metadata(self) -> dict:

        logger.info(
            f"[{self.tool_name}] Generating metadata..."
        )

        self.metadata = generate_metadata(
            self.tool_name
        )

        self.metadata["parser_version"] = (
            self.parser_version
        )

        return self.metadata

    ############################################################
    # Scan Timestamp
    ############################################################

    def build_scan_time(self) -> str:

        self.scan_time = datetime.utcnow().isoformat()

        return self.scan_time

    ############################################################
    # Statistics
    ############################################################

    def build_summary(self) -> Summary:

        logger.info(
            f"[{self.tool_name}] Calculating statistics..."
        )

        self.summary = Statistics.calculate(
            self.findings
        )

        return self.summary

    ############################################################
    # Determine Scan Status
    ############################################################

    def determine_status(self) -> str:
        """
        Determine overall scan status.

        Child parsers may override this method
        if they need custom policy logic.
        """

        if self.summary is None:
            return "UNKNOWN"

        if self.summary.critical > 0:
            return "FAIL"

        if self.summary.high > 0:
            return "FAIL"

        if self.summary.medium > 0:
            return "WARN"

        return "PASS"

    ############################################################
    # Build Normalized Report
    ############################################################

    def build_report(self) -> Report:

        logger.info(
            f"[{self.tool_name}] Building normalized report..."
        )

        self.report = Report(

            tool=self.tool_name,

            category=self.category,

            scanner_type=self.scanner_type,

            scan_time=self.scan_time,

            status=self.determine_status(),

            summary=self.summary,

            metadata=self.metadata,

            findings=self.findings

        )

        return self.report

    ############################################################
    # Output Filename
    ############################################################

    def output_filename(self, source_filename: str | None = None) -> str:

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        target_prefix = ""
        src_name = source_filename or self.current_filename
        if src_name:
            base = Path(src_name).stem.replace("_normalized", "")
            parts = base.split("_")
            if parts[0] in ("backend", "frontend"):
                target_prefix = f"_{parts[0]}"

        return (

            f"{self.tool_name.lower()}"

            f"{target_prefix}"

            f"_{timestamp}"

            "_normalized.json"

        )

    ############################################################
    # Save Report
    ############################################################

    def save_report(self, filename: str | None = None) -> None:

        logger.info(
            f"[{self.tool_name}] Saving report..."
        )

        self.writer.write_json(

            self.report,

            self.output_filename(filename or self.current_filename)

        )

        logger.info(
            f"[{self.tool_name}] Report saved successfully."
        )

    ############################################################
    # Execution Timer
    ############################################################

    def start_timer(self) -> None:

        self.start_time = time.perf_counter()

    def stop_timer(self) -> None:

        self.end_time = time.perf_counter()

        self.duration = (

            self.end_time

            - self.start_time

        )

    ############################################################
    # Log Summary
    ############################################################

    def log_summary(self) -> None:

        logger.info("=" * 70)

        logger.info(
            f"{self.tool_name} Scan Summary"
        )

        logger.info("-" * 70)

        rows = (

            ("Status", self.report.status),

            ("Total", self.summary.total),

            ("Critical", self.summary.critical),

            ("High", self.summary.high),

            ("Medium", self.summary.medium),

            ("Low", self.summary.low),

            ("Info", self.summary.info),

            ("Unknown", self.summary.unknown),

            ("Fixable", self.summary.fixable),

            ("Exploitable", self.summary.exploitable),

            ("Compliance", f"{self.summary.compliance_score}%"),

            ("Duration", f"{self.duration:.2f} sec"),

        )

        for key, value in rows:

            logger.info(

                f"{key:<15}: {value}"

            )

        logger.info("=" * 70)


    ############################################################
    # Lifecycle Hooks
    ############################################################

    def before_parse(self) -> None:
        """
        Hook executed before parsing starts.

        Child parsers may override this method to
        initialize caches, load rule databases,
        establish connections, etc.
        """
        pass

    def after_parse(self) -> None:
        """
        Hook executed after parsing completes.

        Child parsers may override this method to
        perform cleanup or post-processing.
        """
        pass

    ############################################################
    # Exception Handling
    ############################################################

    def handle_exception(
        self,
        exception: Exception
    ) -> None:

        logger.exception(
            f"[{self.tool_name}] Parser failed."
        )

        traceback.print_exc()

        raise ParserError(

            f"{self.tool_name} parser failed: {exception}"

        ) from exception

    ############################################################
    # Parser Execution
    ############################################################

    def execute(self) -> None:

        logger.info("=" * 70)

        logger.info(

            f"Starting {self.tool_name} Parser"

        )

        logger.info("=" * 70)

        ########################################################
        # Timer
        ########################################################

        self.start_timer()

        ########################################################
        # Framework Steps
        ########################################################

        if not self.raw_reports:

            self.load_report()

        all_findings = []

        for filename, data in self.raw_reports:

            self.current_filename = filename

            self.raw_report = data

            logger.info(

                f"[{self.tool_name}] Processing {filename}..."

            )

            self.validate()

            self.build_metadata()

            self.build_scan_time()

            self.findings = self.extract_findings()

            all_findings.extend(self.findings)

            self.build_summary()

            self.build_report()

            self.save_report(filename)


        self.findings = all_findings

        self.build_summary()

        self.stop_timer()

        self.log_summary()

        logger.info(

            f"{self.tool_name} Parser Completed"

        )

        logger.info("=" * 70)

    ############################################################
    # Main Entry Point
    ############################################################

    def run(self) -> None:

        try:

            self.before_parse()

            self.execute()

            self.after_parse()

        except Exception as ex:

            self.handle_exception(ex)

    ############################################################
    # Extension Hooks
    ############################################################

    def report_filename(self) -> str:
        """
        Override this method if a parser wants
        a custom normalized report filename.
        """

        return self.output_filename()

    def report_directory(self) -> Path:
        """
        Override this method if a parser wants
        to save reports elsewhere.
        """

        return self.output_directory

    ############################################################
    # Helper Methods
    ############################################################

    def has_findings(self) -> bool:

        return len(self.findings) > 0

    def finding_count(self) -> int:

        return len(self.findings)

    def clear(self) -> None:
        """
        Reset parser state.

        Useful if the same parser instance is
        reused for multiple reports.
        """

        self.raw_report = None

        self.findings = []

        self.summary = None

        self.metadata = None

        self.report = None

        self.scan_time = None

        self.start_time = 0.0

        self.end_time = 0.0

        self.duration = 0.0

    ############################################################
    # Abstract Methods
    ############################################################

    @abstractmethod
    def extract_findings(self) -> list[Finding]:
        """
        Convert scanner-specific report into
        normalized Finding objects.

        Must return:

            List[Finding]
        """
        raise NotImplementedError

    ############################################################
    # String Representation
    ############################################################

    def __repr__(self):

        return (

            f"{self.__class__.__name__}("

            f"tool='{self.tool_name}', "

            f"category='{self.category}', "

            f"scanner='{self.scanner_type}')"

        )
