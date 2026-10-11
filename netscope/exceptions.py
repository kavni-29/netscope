"""NetScope custom exceptions.

Provides a structured exception hierarchy for input validation, parsing,
configuration, and report generation errors.
"""


class NetScopeError(Exception):
    """Base exception for all NetScope errors."""

    pass


class InvalidCaptureError(NetScopeError):
    """Raised when a capture file does not exist, is empty, or is unreadable."""

    pass


class UnsupportedCaptureFormatError(NetScopeError):
    """Raised when a capture file format or magic number is not supported."""

    pass


class ParsingError(NetScopeError):
    """Raised when critical parsing failures occur on a capture file."""

    pass


class ConfigurationError(NetScopeError):
    """Raised when detection rule or system configuration parameters are invalid."""

    pass


class ExportError(NetScopeError):
    """Raised when an error occurs during report or summary export."""

    pass


class AnalysisError(NetScopeError):
    """Raised when an unrecoverable failure occurs during statistical analysis."""

    pass
