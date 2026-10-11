"""NetScope configuration management.

Provides structured configuration for detection thresholds, timing windows,
statistical baselines, safety limits, and export options with validation.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from netscope.exceptions import ConfigurationError


@dataclass
class DetectionConfig:
    """Configurable thresholds for explainable anomaly detection rules."""

    # Rule 1: High packet rate
    high_packet_rate_threshold: int = 50
    high_packet_rate_window_sec: float = 1.0
    high_packet_rate_policy: str = "source"  # "source" or "both"

    # Rule 2: Destination port diversity (heuristic for port scanning/discovery)
    port_diversity_threshold: int = 15
    port_diversity_window_sec: float = 10.0

    # Rule 3: Repeated TCP SYN observations without ACK
    syn_ratio_threshold: float = 0.75  # 75% of TCP packets from source are SYN without ACK
    syn_min_packets: int = 10  # Minimum TCP packets required to evaluate ratio

    # Rule 4: Traffic volume deviation (z-score vs capture intervals)
    volume_deviation_zscore: float = 2.5
    volume_deviation_min_intervals: int = 4
    volume_deviation_interval_sec: float = 2.0

    # Rule 5: Endpoint traffic concentration
    traffic_concentration_threshold: float = 0.50  # 50% of total capture packets
    traffic_concentration_min_packets: int = 30

    # Rule 6: Repeated communication pattern (identical src->dst:port burst)
    repeated_comm_threshold: int = 25
    repeated_comm_window_sec: float = 5.0

    # Safety limits and time bucket defaults
    max_packets_safety_limit: Optional[int] = 500000
    time_bucket_interval_sec: float = 1.0

    def validate(self) -> None:
        """Validate configuration values, raising ConfigurationError if invalid."""
        if self.high_packet_rate_threshold <= 0:
            raise ConfigurationError(
                f"high_packet_rate_threshold must be > 0, got {self.high_packet_rate_threshold}"
            )
        if self.high_packet_rate_window_sec <= 0:
            raise ConfigurationError(
                f"high_packet_rate_window_sec must be > 0, got {self.high_packet_rate_window_sec}"
            )
        if self.high_packet_rate_policy not in ("source", "both"):
            raise ConfigurationError(
                f"high_packet_rate_policy must be 'source' or 'both', got '{self.high_packet_rate_policy}'"
            )

        if self.port_diversity_threshold <= 0:
            raise ConfigurationError(
                f"port_diversity_threshold must be > 0, got {self.port_diversity_threshold}"
            )
        if self.port_diversity_window_sec <= 0:
            raise ConfigurationError(
                f"port_diversity_window_sec must be > 0, got {self.port_diversity_window_sec}"
            )

        if not (0.0 < self.syn_ratio_threshold <= 1.0):
            raise ConfigurationError(
                f"syn_ratio_threshold must be in range (0.0, 1.0], got {self.syn_ratio_threshold}"
            )
        if self.syn_min_packets <= 0:
            raise ConfigurationError(
                f"syn_min_packets must be > 0, got {self.syn_min_packets}"
            )

        if self.volume_deviation_zscore <= 0:
            raise ConfigurationError(
                f"volume_deviation_zscore must be > 0, got {self.volume_deviation_zscore}"
            )
        if self.volume_deviation_min_intervals < 3:
            raise ConfigurationError(
                f"volume_deviation_min_intervals must be >= 3, got {self.volume_deviation_min_intervals}"
            )
        if self.volume_deviation_interval_sec <= 0:
            raise ConfigurationError(
                f"volume_deviation_interval_sec must be > 0, got {self.volume_deviation_interval_sec}"
            )

        if not (0.0 < self.traffic_concentration_threshold <= 1.0):
            raise ConfigurationError(
                f"traffic_concentration_threshold must be in range (0.0, 1.0], got {self.traffic_concentration_threshold}"
            )
        if self.traffic_concentration_min_packets <= 0:
            raise ConfigurationError(
                f"traffic_concentration_min_packets must be > 0, got {self.traffic_concentration_min_packets}"
            )

        if self.repeated_comm_threshold <= 0:
            raise ConfigurationError(
                f"repeated_comm_threshold must be > 0, got {self.repeated_comm_threshold}"
            )
        if self.repeated_comm_window_sec <= 0:
            raise ConfigurationError(
                f"repeated_comm_window_sec must be > 0, got {self.repeated_comm_window_sec}"
            )

        if self.time_bucket_interval_sec <= 0:
            raise ConfigurationError(
                f"time_bucket_interval_sec must be > 0, got {self.time_bucket_interval_sec}"
            )

        if self.max_packets_safety_limit is not None and self.max_packets_safety_limit <= 0:
            raise ConfigurationError(
                f"max_packets_safety_limit must be > 0 if specified, got {self.max_packets_safety_limit}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DetectionConfig:
        """Create and validate configuration from dictionary."""
        valid_keys = set(cls.__dataclass_fields__.keys())
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        cfg = cls(**filtered)
        cfg.validate()
        return cfg

    @classmethod
    def load_json(cls, file_path: str | Path) -> DetectionConfig:
        """Load configuration from a JSON file."""
        path = Path(file_path)
        if not path.is_file():
            raise ConfigurationError(f"Config file not found: {file_path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in config file {file_path}: {e}") from e

    def save_json(self, file_path: str | Path) -> None:
        """Save configuration to a JSON file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
