"""
Remediation Knowledge Base Data Package.
Contains structured vulnerability remediation records and reference security mappings.
"""

from pathlib import Path

DATA_DIR = Path(__file__).parent.resolve()
REMEDIATION_KB_PATH = DATA_DIR / "remediation_kb.json"

__all__ = ["DATA_DIR", "REMEDIATION_KB_PATH"]
