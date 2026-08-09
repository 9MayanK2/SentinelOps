"""
Centralized severity normalization.

Every scanner (Hadolint, Trivy, Semgrep, Gitleaks, etc.)
must use this module instead of hardcoding severity values.
"""

SEVERITY_MAPPING = {
    # Hadolint
    "info": "INFO",
    "warning": "MEDIUM",
    "error": "HIGH",

    # Trivy
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",

    # Semgrep
    "warn": "MEDIUM",

    # Generic
    "unknown": "INFO"
}


def normalize_severity(severity: str) -> str:
    """
    Convert tool-specific severity into
    the project's standard severity.
    """

    if severity is None:
        return "INFO"

    severity = severity.strip().lower()

    return SEVERITY_MAPPING.get(severity, "INFO")
