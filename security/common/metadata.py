"""
Enterprise Metadata Generator

Every scanner and parser should use this module.
"""

import getpass
import platform
import socket
import subprocess
import uuid
from datetime import datetime

from security.config.config_loader import get


PROJECT_NAME = get(
    "PROJECT",
    "name"
)

PARSER_VERSION = get(
    "PARSER",
    "version"
)


def get_git_branch():
    """
    Returns the current Git branch.
    """

    try:
        return subprocess.check_output(
            ["git", "branch", "--show-current"],
            text=True
        ).strip()

    except Exception:
        return "unknown"


def get_git_commit():
    """
    Returns the current Git commit hash.
    """

    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            text=True
        ).strip()

    except Exception:
        return "unknown"


def generate_scan_id(tool_name):
    """
    Generates a unique scan ID.
    """

    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")

    unique = uuid.uuid4().hex[:6].upper()

    return f"{tool_name.upper()}-{timestamp}-{unique}"


def generate_metadata(tool_name):
    """
    Returns metadata common to every scan.
    """

    scanner_version = get(
        tool_name.upper(),
        "scanner_version"
    )

    return {

        "project_name": PROJECT_NAME,

        "scanner": tool_name,

        "scanner_version": scanner_version,

        "parser_version": PARSER_VERSION,

        "hostname": socket.gethostname(),

        "username": getpass.getuser(),

        "operating_system": platform.system(),

        "os_version": platform.release(),

        "python_version": platform.python_version(),

        "git_branch": get_git_branch(),

        "git_commit": get_git_commit(),

        "scan_id": generate_scan_id(tool_name),

        "generated_at": datetime.utcnow().isoformat()

    }
