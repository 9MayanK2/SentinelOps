"""
Common Parser Utilities

Reusable helper functions for all security scanners.

Supported Scanners:
- Hadolint
- Trivy
- Semgrep
- Gitleaks
- OWASP ZAP
"""

import glob
import json
import os
from pathlib import Path
from typing import Dict, List


# ============================================================
# Filesystem
# ============================================================

def ensure_directory(directory: str) -> None:
    """
    Create directory if it does not exist.
    """
    Path(directory).mkdir(parents=True, exist_ok=True)


# ============================================================
# JSON
# ============================================================

def load_json(file_path: str):
    """
    Safely load JSON.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(file_path: str, data) -> None:
    """
    Save JSON with indentation.
    """

    ensure_directory(os.path.dirname(file_path))

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


# ============================================================
# Report Discovery
# ============================================================

def latest_report(report_directory: str) -> str | None:
    """
    Returns newest JSON report.
    """

    reports = glob.glob(os.path.join(report_directory, "*.json"))

    if not reports:
        return None

    return max(reports, key=os.path.getmtime)


def latest_reports(report_directory: str) -> Dict[str, str]:
    """
    Returns newest backend/frontend reports.

    Example

    {
        "backend": "...",
        "frontend": "..."
    }
    """

    reports = glob.glob(os.path.join(report_directory, "*.json"))

    latest = {}

    backend = [
        f
        for f in reports
        if os.path.basename(f).startswith("backend_")
        and "_normalized" not in os.path.basename(f)
    ]

    frontend = [
        f
        for f in reports
        if os.path.basename(f).startswith("frontend_")
        and "_normalized" not in os.path.basename(f)
    ]

    if backend:
        latest["backend"] = max(backend, key=os.path.getmtime)

    if frontend:
        latest["frontend"] = max(frontend, key=os.path.getmtime)

    return latest


def report_timestamp(report_path: str) -> str:
    """
    Extract timestamp from filename.

    backend_20260728_084700.json

    ->
    20260728_084700
    """

    filename = os.path.basename(report_path)

    filename = filename.replace(".json", "")

    filename = filename.replace("_normalized", "")

    parts = filename.split("_")

    if len(parts) >= 3:
        return f"{parts[1]}_{parts[2]}"

    return ""


# ============================================================
# Normalized Report
# ============================================================

def normalized_filename(report_path: str) -> str:
    """
    backend_xxx.json

    ->
    backend_xxx_normalized.json
    """

    filename = os.path.basename(report_path)

    return filename.replace(".json", "_normalized.json")


def save_normalized_report(
    normalized_directory: str,
    original_report: str,
    report_object
) -> str:
    """
    Save normalized report.

    Returns saved path.
    """

    ensure_directory(normalized_directory)

    output_path = os.path.join(
        normalized_directory,
        normalized_filename(original_report)
    )

    save_json(output_path, report_object.to_dict())

    return output_path


# ============================================================
# Report Collection
# ============================================================

def get_scan_files(report_directory: str) -> List[str]:
    """
    Return all raw scan reports.
    """

    reports = glob.glob(os.path.join(report_directory, "*.json"))

    reports = [
        report
        for report in reports
        if "_normalized" not in report
    ]

    reports.sort()

    return reports


# ============================================================
# Future Enterprise Features
# ============================================================

def archive_report():
    """
    Future:
    Move processed reports to archive.
    """
    pass


def cleanup_old_reports():
    """
    Future:
    Delete reports older than retention policy.
    """
    pass


def calculate_checksum():
    """
    Future:
    SHA256 report integrity verification.
    """
    pass


def verify_report():
    """
    Future:
    Validate report integrity before parsing.
    """
    pass
