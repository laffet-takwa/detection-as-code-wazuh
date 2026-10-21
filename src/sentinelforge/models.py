"""Typed data models shared across the validation, conversion and testing layers.

The models are deliberately transport agnostic: they serialise to plain JSON via
``model_dump`` so that the reporting layer never has to know about pySigma types.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "Severity",
    "RuleStatus",
    "Platform",
    "RuleKind",
    "IssueSeverity",
    "Issue",
    "LogSource",
    "AttackReference",
    "DetectionRule",
    "ValidationReport",
    "ConversionOutcome",
    "ConversionReport",
    "FixtureResult",
    "TestReport",
    "CoverageReport",
]


class Severity(str, Enum):
    """Sigma rule severities."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_sigma_level(cls, level: str | None) -> Severity:
        """Map a pysigma level string onto the enum, defaulting to ``MEDIUM``."""

        if level is None:
            return cls.MEDIUM
        try:
            return cls(level.lower())
        except ValueError as exc:  # pragma: no cover - pysigma normalises the value
            raise ValueError(f"Unknown Sigma level: {level!r}") from exc


class RuleStatus(str, Enum):
    """Sigma rule lifecycle states."""

    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"


class Platform(str, Enum):
    """Target platforms used to organise the rule catalogue."""

    LINUX = "linux"
    WINDOWS = "windows"
    COMMON = "common"


class RuleKind(str, Enum):
    """The kind of Sigma artefact a file contains."""

    DETECTION = "detection"
    CORRELATION = "correlation"


class IssueSeverity(str, Enum):
    """Severity of a single validation issue."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Issue(BaseModel):
    """A single, actionable validation problem."""

    model_config = ConfigDict(frozen=True)

    severity: IssueSeverity
    code: str
    message: str
    rule_path: str | None = None
    rule_id: str | None = None
    field: str | None = None
    stage: str | None = None

    def format(self) -> str:
        """Render the issue as a single human readable line."""

        location = self.rule_path or "<repository>"
        suffix = f" [{self.field}]" if self.field else ""
        stage = f" ({self.stage})" if self.stage else ""
        return f"{self.severity.value.upper()}: {location}{suffix}{stage}: {self.message} ({self.code})"


class LogSource(BaseModel):
    """Normalised representation of a Sigma ``logsource`` block."""

    model_config = ConfigDict(frozen=True)

    category: str | None = None
    product: str | None = None
    service: str | None = None
    definition: str | None = None

    @property
    def key(self) -> str:
        """Return the stable lookup key used by the field mapping registry."""

        product = self.product or ""
        service = self.service or self.category or ""
        return f"{product}/{service}" if service else product

    @property
    def platform(self) -> Platform | None:
        """Best-effort platform inference from the log source."""

        if self.product in ("linux", "windows"):
            return Platform(self.product)
        return None


class AttackReference(BaseModel):
    """A MITRE ATT&CK technique reference attached to a rule."""

    model_config = ConfigDict(frozen=True)

    id: str
    tactic: str | None = None
    technique: str | None = None
    rationale: str | None = None
    url: str | None = None

    @field_validator("id")
    @classmethod
    def _normalise_id(cls, value: str) -> str:
        return value.strip().upper()


class DetectionRule(BaseModel):
    """An enriched view of a single Sigma source rule.

    The object is produced by the validation layer and consumed by the conversion,
    testing and reporting layers. It intentionally stores plain data only.
    """

    model_config = ConfigDict(frozen=True)

    path: str
    title: str
    id: UUID
    name: str | None = None
    kind: RuleKind = RuleKind.DETECTION
    status: RuleStatus = RuleStatus.EXPERIMENTAL
    description: str = ""
    author: str = ""
    rule_date: date | None = None
    level: Severity = Severity.MEDIUM
    logsource: LogSource
    condition: str = ""
    falsepositives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    attack: list[AttackReference] = Field(default_factory=list)
    platform: Platform | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    sha256: str = ""

    @property
    def rule_id(self) -> str:
        """Return the canonical UUID string of the rule."""

        return str(self.id)


class ValidationReport(BaseModel):
    """Result of a validation run over the rule catalogue."""

    model_config = ConfigDict(frozen=True)

    rules_discovered: int = 0
    rules_valid: int = 0
    rules_invalid: int = 0
    issues: list[Issue] = Field(default_factory=list)
    strict: bool = False
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    rule_ids: dict[str, str] = Field(default_factory=dict)

    @property
    def errors(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.severity is IssueSeverity.ERROR]

    @property
    def warnings(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.severity is IssueSeverity.WARNING]

    @property
    def passed(self) -> bool:
        """A run passes when no error level issue was recorded."""

        return not self.errors


class ConversionOutcome(BaseModel):
    """The result of converting a single source rule."""

    model_config = ConfigDict(frozen=True)

    rule_path: str
    rule_id: str
    title: str
    status: str
    converted: bool
    wazuh_rule_id: int | None = None
    output_path: str | None = None
    feature: str | None = None
    limitation: str | None = None
    message: str | None = None
    warnings: list[str] = Field(default_factory=list)


class ConversionReport(BaseModel):
    """Aggregate result of a conversion run."""

    model_config = ConfigDict(frozen=True)

    backend: str = "wazuh"
    outcomes: list[ConversionOutcome] = Field(default_factory=list)
    output_directory: str | None = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool_versions: dict[str, str] = Field(default_factory=dict)

    @property
    def converted(self) -> list[ConversionOutcome]:
        return [outcome for outcome in self.outcomes if outcome.converted]

    @property
    def rejected(self) -> list[ConversionOutcome]:
        return [outcome for outcome in self.outcomes if not outcome.converted]

    @property
    def warnings(self) -> list[str]:
        collected: list[str] = []
        for outcome in self.outcomes:
            collected.extend(outcome.warnings)
        return collected


class FixtureResult(BaseModel):
    """Result of executing a single synthetic fixture case."""

    model_config = ConfigDict(frozen=True)

    fixture: str
    rule_path: str
    rule_id: str
    expectation: str
    structured: str
    raw: str
    passed: bool
    detail: str | None = None
    events: int = 0


class TestReport(BaseModel):
    """Aggregate result of a fixture test run."""

    model_config = ConfigDict(frozen=True)

    fixtures_discovered: int = 0
    fixtures_passed: int = 0
    fixtures_failed: int = 0
    fixtures_not_evaluated: int = 0
    results: list[FixtureResult] = Field(default_factory=list)
    unit_tests_passed: int | None = None
    unit_tests_failed: int | None = None
    unit_tests_skipped: int | None = None
    wazuh_integration: str = "NOT RUN"
    wazuh_detail: str | None = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def passed(self) -> bool:
        return self.fixtures_failed == 0 and not (self.unit_tests_failed or 0)


class CoverageReport(BaseModel):
    """Coverage metrics over the detection catalogue."""

    model_config = ConfigDict(frozen=True)

    rules_total: int = 0
    rules_with_positive_fixture: int = 0
    rules_with_negative_fixture: int = 0
    rules_covered: int = 0
    rules_converted: int = 0
    rules_rejected: int = 0
    techniques: dict[str, list[str]] = Field(default_factory=dict)
    platform_counts: dict[str, int] = Field(default_factory=dict)
    uncovered_rules: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
