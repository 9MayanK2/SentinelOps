"""
report_writer.py

Enterprise Report Writer

Responsible for writing normalized reports to disk.

Current Support
---------------
✔ JSON

Future
------
✔ XML
✔ SARIF
✔ YAML
✔ CSV

Every parser should use this class instead of
calling save_json().
"""

import json
from pathlib import Path
from dataclasses import is_dataclass, asdict

from security.common.logger import logger

from security.core.exceptions import ReportWriteError


class ReportWriter:

    ###########################################################
    # Constructor
    ###########################################################

    def __init__(self, output_directory):

        self.output_directory = Path(output_directory)

        self.output_directory.mkdir(

            parents=True,

            exist_ok=True

        )

    ###########################################################
    # Convert Object
    ###########################################################

    def _serialize(self, obj):

        if is_dataclass(obj):

            return asdict(obj)

        if hasattr(obj, "to_dict"):

            return obj.to_dict()

        return obj

    ###########################################################
    # Write JSON
    ###########################################################

    def write_json(

        self,

        report,

        filename

    ):

        output_file = self.output_directory / filename

        logger.info(

            f"Writing report: {output_file.name}"

        )

        try:

            with open(

                output_file,

                "w",

                encoding="utf-8"

            ) as fp:

                json.dump(

                    self._serialize(report),

                    fp,

                    indent=4,

                    ensure_ascii=False

                )

        except Exception as ex:

            raise ReportWriteError(

                f"Unable to write report: {output_file}"

            ) from ex

        logger.info(

            f"Report written successfully: {output_file.name}"

        )

        return output_file

    ###########################################################
    # Write Pretty JSON
    ###########################################################

    def write_pretty_json(

        self,

        report,

        filename

    ):

        return self.write_json(

            report,

            filename

        )

    ###########################################################
    # Write Raw Dictionary
    ###########################################################

    def write_dict(

        self,

        data,

        filename

    ):

        output_file = self.output_directory / filename

        logger.info(

            f"Writing dictionary: {output_file.name}"

        )

        try:

            with open(

                output_file,

                "w",

                encoding="utf-8"

            ) as fp:

                json.dump(

                    data,

                    fp,

                    indent=4,

                    ensure_ascii=False

                )

        except Exception as ex:

            raise ReportWriteError(

                f"Unable to write report: {output_file}"

            ) from ex

        return output_file

    ###########################################################
    # Future Placeholders
    ###########################################################

    def write_xml(self, report, filename):

        raise NotImplementedError(

            "XML writer not implemented."

        )

    def write_yaml(self, report, filename):

        raise NotImplementedError(

            "YAML writer not implemented."

        )

    def write_csv(self, report, filename):

        raise NotImplementedError(

            "CSV writer not implemented."

        )

    def write_sarif(self, report, filename):

        raise NotImplementedError(

            "SARIF writer not implemented."
        )
