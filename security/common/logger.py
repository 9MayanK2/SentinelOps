"""
Enterprise logger for the DevSecOps platform.

Every scanner and parser should use this logger.
"""

import logging
from pathlib import Path


LOG_DIR = Path("compliance/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "parser.log"


logger = logging.getLogger("DevSecOps")

logger.setLevel(logging.INFO)

if not logger.handlers:

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(LOG_FILE)

    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
