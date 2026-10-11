"""NetScope — Network Traffic Analyzer & Explainable Anomaly Detection System."""

from netscope.config import DetectionConfig
from netscope.exceptions import (
    AnalysisError,
    ConfigurationError,
    ExportError,
    InvalidCaptureError,
    NetScopeError,
    ParsingError,
    UnsupportedCaptureFormatError,
)
from netscope.models import (
    AlertRecord,
    AnalysisSummary,
    FlowKey,
    FlowRecord,
    PacketRecord,
)

__version__ = "1.0.0"
__all__ = [
    "DetectionConfig",
    "NetScopeError",
    "InvalidCaptureError",
    "UnsupportedCaptureFormatError",
    "ParsingError",
    "ConfigurationError",
    "ExportError",
    "AnalysisError",
    "PacketRecord",
    "FlowKey",
    "FlowRecord",
    "AlertRecord",
    "AnalysisSummary",
]
