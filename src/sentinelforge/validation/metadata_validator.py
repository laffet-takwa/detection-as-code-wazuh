"""Stage C - metadata validation.

This stage checks the *conventions* SentinelForge enforces on top of the Sigma
specification: required fields, UUID well-formedness, severity vocabulary,
description quality, log source completeness and consistent file organisation.

None of these checks require pySigma; they operate on the raw YAML mapping so
that a rule with broken metadata still produces a precise diagnostic instead of
a generic parse error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from ..models import (
    AttackReference,
    Issue,
    IssueSeverity,
    LogSource,
    Platform,
    RuleStatus,
    Severity,
)
from ..utils.identifiers import is_valid_uuid

__all__ = ["RuleMetadata", "MetadataResult", "validate_metadata", "REQUIRED_FIELDS"]

#: Fields that every published rule must define.
REQUIRED_FIELDS: tuple[str, ...] = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
)

_PLACEHOLDER_VALUES = {
    "todo",
    "tbd",
    "n/a",
    "na",
    "none",
    "xxx",
    "...",
    "placeholder",
    "description",
    "fixme",
}

_URL_PATTERN = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
_MIN_DESCRIPTION_LENGTH = 40
_MIN_TITLE_LENGTH = 8


@dataclass
class RuleMetadata:
    """Validated metadata extracted from a Sigma document."""

    title: str = ""
    rule_id: str = ""
    status: RuleStatus = RuleStatus.EXPERIMENTAL
    description: str = ""
    author: str = ""
    date: date | None = None
    level: Severity = Severity.MEDIUM
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    logsource: LogSource = field(default_factory=LogSource)
    condition: str = ""
    platform: Platform | None = None
    name: str | None = None
    attack: list[AttackReference] = field(default_factory=list)


@dataclass
class MetadataResult:
    """Outcome of the metadata stage for a single rule."""

    path: str
    metadata: RuleMetadata = field(default_factory=RuleMetadata)
    issues: list[Issue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(issue.severity is IssueSeverity.ERROR for issue in self.issues)


def _issue(
    code: str,
    message: str,
    *,
    path: str,
    field_name: str | None = None,
    severity: IssueSeverity = IssueSeverity.ERROR,
) -> Issue:
    return Issue(
        severity=severity,
        code=code,
        message=message,
        rule_path=path,
        field=field_name,
        stage="metadata",
    )


def _is_placeholder(value: str) -> bool:
    stripped = value.strip().lower()
    if stripped in _PLACEHOLDER_VALUES:
        return True
    return bool(re.fullmatch(r"[<\[{(].*[>\]})]", stripped))


def validate_metadata(
    document: dict[str, Any],
    path: str,
    *,
    platform_directory: Platform | None = None,
) -> MetadataResult:
    """Validate the metadata of a single Sigma document."""

    result = MetadataResult(path=path)
    metadata = result.metadata
    issues = result.issues

    for field_name in REQUIRED_FIELDS:
        if field_name not in document:
            issues.append(
                _issue(
                    "metadata.missing_field",
                    f"Required field '{field_name}' is missing.",
                    path=path,
                    field_name=field_name,
                )
            )

    title = document.get("title")
    if title is not None:
        if not isinstance(title, str) or not title.strip():
            issues.append(
                _issue(
                    "metadata.invalid_title", "Field 'title' must be a non-empty string.", path=path, field_name="title"
                )
            )
        elif len(title.strip()) < _MIN_TITLE_LENGTH:
            issues.append(
                _issue(
                    "metadata.title_too_short",
                    f"Field 'title' must be at least {_MIN_TITLE_LENGTH} characters long.",
                    path=path,
                    field_name="title",
                )
            )
        else:
            metadata.title = title.strip()

    rule_id = document.get("id")
    if rule_id is not None:
        if not isinstance(rule_id, str) or not is_valid_uuid(rule_id):
            issues.append(
                _issue(
                    "metadata.invalid_uuid",
                    "Field 'id' must be a canonical UUID " "(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).",
                    path=path,
                    field_name="id",
                )
            )
        else:
            metadata.rule_id = rule_id.strip().lower()

    status = document.get("status")
    if status is not None:
        try:
            metadata.status = RuleStatus(str(status).strip().lower())
        except ValueError:
            issues.append(
                _issue(
                    "metadata.invalid_status",
                    f"Field 'status' must be one of " f"{', '.join(item.value for item in RuleStatus)}.",
                    path=path,
                    field_name="status",
                )
            )

    description = document.get("description")
    if description is not None:
        if not isinstance(description, str):
            issues.append(
                _issue(
                    "metadata.invalid_description",
                    "Field 'description' must be a string.",
                    path=path,
                    field_name="description",
                )
            )
        elif _is_placeholder(description):
            issues.append(
                _issue(
                    "metadata.placeholder_description",
                    "Field 'description' contains placeholder text instead of a real description.",
                    path=path,
                    field_name="description",
                )
            )
        elif len(description.strip()) < _MIN_DESCRIPTION_LENGTH:
            issues.append(
                _issue(
                    "metadata.description_too_short",
                    f"Field 'description' must be at least {_MIN_DESCRIPTION_LENGTH} characters "
                    "long and explain what the rule detects.",
                    path=path,
                    field_name="description",
                )
            )
        else:
            metadata.description = description.strip()

    author = document.get("author")
    if author is not None:
        if not isinstance(author, str) or _is_placeholder(author):
            issues.append(
                _issue(
                    "metadata.invalid_author",
                    "Field 'author' must be a non-placeholder string.",
                    path=path,
                    field_name="author",
                )
            )
        else:
            metadata.author = author.strip()

    raw_date = document.get("date")
    if raw_date is not None:
        if isinstance(raw_date, date):
            metadata.date = raw_date
        elif isinstance(raw_date, str):
            try:
                metadata.date = date.fromisoformat(raw_date.strip())
            except ValueError:
                issues.append(
                    _issue(
                        "metadata.invalid_date",
                        f"Field 'date' must be an ISO-8601 date (YYYY-MM-DD), got {raw_date!r}.",
                        path=path,
                        field_name="date",
                    )
                )
        else:
            issues.append(
                _issue(
                    "metadata.invalid_date",
                    "Field 'date' must be a string or date value.",
                    path=path,
                    field_name="date",
                )
            )

    level = document.get("level")
    if level is not None:
        if isinstance(level, str):
            try:
                metadata.level = Severity(level.strip().lower())
            except ValueError:
                issues.append(
                    _issue(
                        "metadata.invalid_level",
                        f"Field 'level' must be one of " f"{', '.join(item.value for item in Severity)}.",
                        path=path,
                        field_name="level",
                    )
                )
        else:
            issues.append(
                _issue("metadata.invalid_level", "Field 'level' must be a string.", path=path, field_name="level")
            )

    falsepositives = document.get("falsepositives")
    if falsepositives is not None:
        if not isinstance(falsepositives, list) or not falsepositives:
            issues.append(
                _issue(
                    "metadata.invalid_falsepositives",
                    "Field 'falsepositives' must be a non-empty list of strings describing "
                    "legitimate activity that may trigger the rule.",
                    path=path,
                    field_name="falsepositives",
                )
            )
        elif not all(isinstance(item, str) and item.strip() for item in falsepositives):
            issues.append(
                _issue(
                    "metadata.invalid_falsepositives",
                    "Every entry of 'falsepositives' must be a non-empty string.",
                    path=path,
                    field_name="falsepositives",
                )
            )
        else:
            metadata.falsepositives = [item.strip() for item in falsepositives]

    references = document.get("references")
    if references is not None:
        if not isinstance(references, list):
            issues.append(
                _issue(
                    "metadata.invalid_references",
                    "Field 'references' must be a list.",
                    path=path,
                    field_name="references",
                )
            )
        else:
            for reference in references:
                if not isinstance(reference, str) or not _URL_PATTERN.match(reference.strip()):
                    issues.append(
                        _issue(
                            "metadata.invalid_reference",
                            f"Reference {reference!r} is not a valid http(s) URL.",
                            path=path,
                            field_name="references",
                        )
                    )
            metadata.references = [str(item).strip() for item in references]

    tags = document.get("tags")
    if tags is not None:
        if not isinstance(tags, list) or not all(isinstance(item, str) for item in tags):
            issues.append(
                _issue("metadata.invalid_tags", "Field 'tags' must be a list of strings.", path=path, field_name="tags")
            )
        else:
            metadata.tags = [item.strip() for item in tags]

    logsource = document.get("logsource")
    if logsource is not None:
        if not isinstance(logsource, dict):
            issues.append(
                _issue(
                    "metadata.invalid_logsource",
                    "Field 'logsource' must be a mapping with 'category', 'product' and/or " "'service' keys.",
                    path=path,
                    field_name="logsource",
                )
            )
        else:
            metadata.logsource = LogSource(
                category=logsource.get("category"),
                product=logsource.get("product"),
                service=logsource.get("service"),
                definition=logsource.get("definition"),
            )
            if not any(logsource.get(key) for key in ("category", "product", "service")):
                issues.append(
                    _issue(
                        "metadata.incomplete_logsource",
                        "Field 'logsource' must define at least one of 'category', 'product' " "or 'service'.",
                        path=path,
                        field_name="logsource",
                    )
                )
            metadata.platform = metadata.logsource.platform
            if platform_directory is not None and metadata.platform is not None:
                if metadata.platform is not platform_directory:
                    issues.append(
                        _issue(
                            "metadata.platform_mismatch",
                            f"Rule declares product '{metadata.platform.value}' but is stored "
                            f"in the '{platform_directory.value}' directory.",
                            path=path,
                            field_name="logsource",
                        )
                    )

    detection = document.get("detection")
    if detection is not None:
        if not isinstance(detection, dict):
            issues.append(
                _issue(
                    "metadata.invalid_detection",
                    "Field 'detection' must be a mapping of detection names to definitions.",
                    path=path,
                    field_name="detection",
                )
            )
        else:
            names = [key for key in detection if key != "condition"]
            if not names:
                issues.append(
                    _issue(
                        "metadata.empty_detection",
                        "Field 'detection' does not define any named detection.",
                        path=path,
                        field_name="detection",
                    )
                )
            for name in names:
                if not isinstance(name, str) or not name.strip():
                    issues.append(
                        _issue(
                            "metadata.invalid_detection_name",
                            "Detection names must be non-empty strings.",
                            path=path,
                            field_name="detection",
                        )
                    )
            condition = detection.get("condition")
            if condition is None:
                issues.append(
                    _issue(
                        "metadata.missing_condition",
                        "Field 'detection' must contain a 'condition' key (Sigma 2.0 layout).",
                        path=path,
                        field_name="detection.condition",
                    )
                )
            elif isinstance(condition, str):
                metadata.condition = condition.strip()
            elif isinstance(condition, list) and all(isinstance(item, str) for item in condition):
                metadata.condition = " or ".join(item.strip() for item in condition)
            else:
                issues.append(
                    _issue(
                        "metadata.invalid_condition",
                        "Field 'detection.condition' must be a string or a list of strings.",
                        path=path,
                        field_name="detection.condition",
                    )
                )

    name = document.get("name")
    if name is not None:
        if not isinstance(name, str) or not name.strip():
            issues.append(
                _issue(
                    "metadata.invalid_name", "Field 'name' must be a non-empty string.", path=path, field_name="name"
                )
            )
        else:
            metadata.name = name.strip()

    return result
