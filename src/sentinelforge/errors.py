"""Focused exception hierarchy for SentinelForge.

Every error raised by the package derives from :class:`SentinelForgeError` so that
the CLI can distinguish "expected, explainable" failures (validation problems,
unsupported Sigma features) from genuine programming errors.
"""

from __future__ import annotations

from collections.abc import Sequence

__all__ = [
    "SentinelForgeError",
    "ConfigurationError",
    "RuleValidationError",
    "ConversionError",
    "UnsupportedFeatureError",
    "IntegrationError",
    "ReportError",
]


class SentinelForgeError(Exception):
    """Base class for all errors raised by SentinelForge."""


class ConfigurationError(SentinelForgeError):
    """Raised when the runtime configuration is invalid or incomplete."""


class RuleValidationError(SentinelForgeError):
    """Raised when one or more rules fail a validation stage.

    The individual problems are kept in :attr:`issues` so that callers can render
    a complete diagnostic instead of only the first failure.
    """

    def __init__(self, message: str, issues: Sequence[object] = ()) -> None:
        super().__init__(message)
        self.issues: tuple[object, ...] = tuple(issues)


class ConversionError(SentinelForgeError):
    """Raised when a Sigma rule cannot be converted into a Wazuh custom rule.

    Attributes
    ----------
    rule_path:
        Repository relative path of the offending source rule, when known.
    rule_id:
        UUID of the offending source rule, when known.
    feature:
        Short, machine readable identifier of the feature that could not be
        represented, e.g. ``"correlation.event_count"``.
    limitation:
        Human readable explanation of *why* the feature is not supported and what
        the operator is expected to do instead.
    """

    def __init__(
        self,
        message: str,
        *,
        rule_path: str | None = None,
        rule_id: str | None = None,
        feature: str | None = None,
        limitation: str | None = None,
    ) -> None:
        super().__init__(message)
        self.rule_path = rule_path
        self.rule_id = rule_id
        self.feature = feature
        self.limitation = limitation

    def as_dict(self) -> dict[str, str | None]:
        """Return a JSON-serialisable representation of the error."""

        return {
            "message": str(self),
            "rule_path": self.rule_path,
            "rule_id": self.rule_id,
            "feature": self.feature,
            "limitation": self.limitation,
        }


class UnsupportedFeatureError(ConversionError):
    """Raised when a Sigma construct is outside the documented supported subset.

    This is the *expected* failure mode of the converter: SentinelForge refuses to
    emit a Wazuh rule whose semantics would differ from the Sigma source rather
    than silently weakening the detection.
    """


class IntegrationError(SentinelForgeError):
    """Raised when an optional external integration (e.g. Wazuh) cannot be used."""


class ReportError(SentinelForgeError):
    """Raised when a report cannot be rendered."""
