"""
report_reader.py

Enterprise Report Reader

Responsible for reading scanner reports from disk.

Current Support
---------------
✔ JSON

Future
------
✔ XML
✔ SARIF
✔ YAML
✔ CSV

All parsers should use this class instead of directly
calling json.load().
"""

import json
from pathlib import Path

from security.common.logger import logger

from security.core.exceptions import (
    ReportNotFoundError,
    InvalidReportError
)


class ReportReader:

    ###########################################################
    # Constructor
    ###########################################################

    def __init__(self, report_directory):

        self.report_directory = Path(report_directory)

    ###########################################################
    # Internal
    ###########################################################

    def _validate_exists(self, report_file):

        if not report_file.exists():

            raise ReportNotFoundError(

                f"Report not found: {report_file}"

            )

    ###########################################################
    # Read JSON
    ###########################################################

    def read_json(self, filename):

        report_file = self.report_directory / filename

        self._validate_exists(report_file)

        logger.info(

            f"Reading report: {report_file.name}"

        )

        try:

            with open(

                report_file,

                "r",

                encoding="utf-8"

            ) as fp:

                data = json.load(fp)

                logger.info(
                f"Successfully loaded {report_file.name}"
                )

                return data

        except json.JSONDecodeError as ex:

            raise InvalidReportError(

                f"Invalid JSON: {report_file}"

            ) from ex

    ###########################################################
    # Read Latest Report
    ###########################################################

    def latest_report(self):

        reports = sorted(
            [f for f in self.report_directory.glob("*.json") if "_normalized" not in f.name],
            key=lambda file: file.stat().st_mtime,
            reverse=True,
        )

        if not reports:

            raise ReportNotFoundError(

                f"No reports found in {self.report_directory}"

            )

        logger.info(
            f"Using report: {reports[0].resolve()}"
        )

        return self.read_json(

            reports[0].name

        )

    ###########################################################
    # Read Latest Raw Reports (By Target Prefix)
    ###########################################################

    def latest_raw_reports(self):
        """
        Discovers the latest raw (un-normalized) report for each target prefix
        (e.g., 'backend_*.json', 'frontend_*.json').

        Returns:
            List[Tuple[str, Any]]: List of (filename, report_data) tuples.
        """
        raw_reports = [
            f for f in self.report_directory.glob("*.json")
            if "_normalized" not in f.name
        ]

        if not raw_reports:
            raise ReportNotFoundError(
                f"No raw reports found in {self.report_directory}"
            )

        grouped = {}
        for rpath in raw_reports:
            filename = rpath.name
            prefix = filename.split("_")[0] if "_" in filename else "default"
            mtime = rpath.stat().st_mtime
            if prefix not in grouped or mtime > grouped[prefix][0]:
                grouped[prefix] = (mtime, filename)

        results = []
        for prefix, (mtime, filename) in grouped.items():
            data = self.read_json(filename)
            results.append((filename, data))

        return results

    ###########################################################
    # Read All Reports
    ###########################################################

    def read_all(self):

        report_list = []

        reports = sorted(

            self.report_directory.glob("*.json")

        )

        logger.info(

            f"Found {len(reports)} report(s)"

        )

        for report in reports:

            try:

                report_list.append(

                    self.read_json(

                        report.name

                    )

                )

            except Exception as ex:

                logger.error(

                    f"Failed reading {report.name}: {ex}"

                )

        return report_list

    ###########################################################
    # Count Reports
    ###########################################################

    def count(self):

        return len(

            list(

                self.report_directory.glob("*.json")

            )

        )

    ###########################################################
    # List Reports
    ###########################################################

    def list_reports(self):

        return sorted(

            [

                report.name

                for report in

                self.report_directory.glob("*.json")

            ]

        )

    ###########################################################
    # Read Specific Path
    ###########################################################

    @staticmethod
    def read(report_path):

        report_path = Path(report_path)

        if not report_path.exists():

            raise ReportNotFoundError(

                report_path

            )

        logger.info(

            f"Reading {report_path.name}"

        )

        try:

            with open(

                report_path,

                "r",

                encoding="utf-8"

            ) as fp:

                return json.load(fp)

        except json.JSONDecodeError as ex:

            raise InvalidReportError(

                report_path

            ) from ex
