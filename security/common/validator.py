"""
validator.py

Enterprise Validation Utilities

Reusable validation functions shared across
all security parsers.

Current Support
---------------
✔ File validation
✔ Directory validation
✔ JSON validation
✔ Report validation
✔ Required key validation
✔ Trivy validation
✔ Hadolint validation

Future
------
✔ SARIF
✔ XML
✔ YAML
✔ CycloneDX
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from security.core.exceptions import (
    ValidationError,
    InvalidReportError,
)

############################################################
# File Validation
############################################################

def validate_file_exists(path: str | Path) -> Path:
    """
    Ensure file exists.
    """

    path = Path(path)

    if not path.exists():

        raise FileNotFoundError(
            f"Report not found: {path}"
        )

    if not path.is_file():

        raise ValidationError(
            f"{path} is not a file."
        )

    return path


############################################################
# Directory Validation
############################################################

def validate_directory(path: str | Path) -> Path:
    """
    Ensure directory exists.
    """

    path = Path(path)

    if not path.exists():

        raise FileNotFoundError(
            f"Directory not found: {path}"
        )

    if not path.is_dir():

        raise ValidationError(
            f"{path} is not a directory."
        )

    return path


############################################################
# File Extension Validation
############################################################

def validate_extension(
    path: str | Path,
    extensions: Iterable[str],
) -> None:
    """
    Validate file extension.
    """

    path = Path(path)

    allowed = {
        ext.lower()
        for ext in extensions
    }

    if path.suffix.lower() not in allowed:

        raise ValidationError(

            f"Unsupported file type: "

            f"{path.suffix}"

        )


############################################################
# JSON Validation
############################################################

def validate_json(path: str | Path) -> dict | list:
    """
    Validate and return JSON.
    """

    path = validate_file_exists(path)

    validate_extension(
        path,
        [".json"],
    )

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as fp:

            return json.load(fp)

    except json.JSONDecodeError as ex:

        raise InvalidReportError(
            f"Invalid JSON file: {path}"
        ) from ex


############################################################
# Type Validation
############################################################

def validate_dict(data: Any) -> None:

    if not isinstance(data, dict):

        raise ValidationError(
            "Expected dictionary report."
        )


def validate_list(data: Any) -> None:

    if not isinstance(data, list):

        raise ValidationError(
            "Expected list report."
        )


############################################################
# Empty Validation
############################################################

def validate_not_empty(data: Any) -> None:

    if data is None:

        raise ValidationError(
            "Report is empty."
        )

    if hasattr(data, "__len__"):

        if len(data) == 0:

            raise ValidationError(
                "Report contains no data."
            )


############################################################
# Required Keys
############################################################

def validate_required_keys(
    data: dict,
    keys: Iterable[str],
) -> None:
    """
    Validate required keys.
    """

    validate_dict(data)

    missing = [

        key

        for key in keys

        if key not in data

    ]

    if missing:

        raise ValidationError(

            "Missing required keys: "

            + ", ".join(missing)

        )


############################################################
# Report Validation
############################################################

def validate_report(data: Any) -> None:
    """
    Generic report validation.
    """

    validate_not_empty(data)

    if not isinstance(
        data,
        (dict, list),
    ):

        raise ValidationError(
            "Unsupported report format."
        )


############################################################
# Report Collection Validation
############################################################

def validate_report_collection(
    reports: list,
) -> None:
    """
    Validate a collection of reports.
    """

    validate_list(reports)

    if len(reports) == 0:

        raise ValidationError(
            "No reports found."
        )


############################################################
# Trivy Validation
############################################################

def validate_trivy_report(
    data: dict,
) -> None:
    """
    Validate Trivy report.
    """

    validate_required_keys(
        data,
        [
            "Results",
        ],
    )


############################################################
# Hadolint Validation
############################################################

def validate_hadolint_report(
    data: list,
) -> None:
    """
    Validate Hadolint report.
    """

    validate_list(data)


############################################################
# Future Validators
############################################################

def validate_semgrep_report(data: dict) -> None:
    """
    Placeholder for Semgrep validation.
    """
    pass


def validate_bandit_report(data: dict) -> None:
    """
    Placeholder for Bandit validation.
    """
    pass


def validate_gitleaks_report(data: list) -> None:
    """
    Validate Gitleaks report.
    """
    validate_list(data)



def validate_checkov_report(data: dict) -> None:
    """
    Placeholder for Checkov validation.
    """
    pass


def validate_zap_report(data: dict) -> None:
    """
    Placeholder for OWASP ZAP validation.
    """
    pass
