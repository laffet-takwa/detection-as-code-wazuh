"""Base converter interface and shared types for Sigma backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import ConversionOutcome, DetectionRule, LogSource

__all__ = [
    "Backend",
    "Converter",
    "ConverterContext",
]


@dataclass(frozen=True)
class ConverterContext:
    """Runtime context passed to every converter invocation."""

    rule: DetectionRule
    logsource: LogSource
    output_directory: Path
    mapping_overrides: dict[str, Any] = field(default_factory=dict)


class Converter(ABC):
    """Abstract base class for a Sigma backend converter."""

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Short identifier of the backend (e.g. 'wazuh')."""

    @abstractmethod
    def convert(self, context: ConverterContext) -> ConversionOutcome:
        """Convert a single rule and return the outcome."""

    def supports(self, rule: DetectionRule) -> bool:
        """Return True when the converter can handle *rule*."""
        return True


class Backend:
    """Registry of available converters."""

    def __init__(self) -> None:
        self._converters: dict[str, Converter] = {}

    def register(self, converter: Converter) -> None:
        self._converters[converter.backend_name] = converter

    def get(self, name: str) -> Converter | None:
        return self._converters.get(name)

    def names(self) -> list[str]:
        return sorted(self._converters)
