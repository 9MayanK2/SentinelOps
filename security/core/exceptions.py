"""
exceptions.py

Centralized exceptions for the DevSecOps Security Framework.

All framework components should raise these exceptions instead
of generic Exception classes.
"""


class SecurityFrameworkError(Exception):
    """
    Base exception for the framework.
    """

    pass


############################################################
# Parser Errors
############################################################

class ParserError(SecurityFrameworkError):
    """
    Raised when a parser fails.
    """

    pass


class ParserRegistrationError(SecurityFrameworkError):
    """
    Raised when parser registration fails.
    """

    pass


############################################################
# Report Errors
############################################################

class ReportError(SecurityFrameworkError):
    """
    Base report exception.
    """

    pass


class ReportNotFoundError(ReportError):
    """
    Report file does not exist.
    """

    pass


class InvalidReportError(ReportError):
    """
    Invalid JSON/XML/SARIF report.
    """

    pass


class ReportWriteError(ReportError):
    """
    Report could not be written.
    """

    pass


############################################################
# Validation Errors
############################################################

class ValidationError(SecurityFrameworkError):
    """
    Validation failed.
    """

    pass


############################################################
# Metadata Errors
############################################################

class MetadataError(SecurityFrameworkError):
    """
    Metadata generation failed.
    """

    pass


############################################################
# Recommendation Errors
############################################################

class RecommendationError(SecurityFrameworkError):
    """
    Recommendation lookup failed.
    """

    pass


############################################################
# Configuration Errors
############################################################

class ConfigurationError(SecurityFrameworkError):
    """
    Invalid parser configuration.
    """

    pass
