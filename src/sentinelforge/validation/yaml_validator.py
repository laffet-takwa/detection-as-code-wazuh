"""Stage A - YAML validation.

The YAML stage is intentionally independent from pySigma.  It answers the question
"is this file a well formed, single document YAML mapping with no duplicated
keys?" before any Sigma specific semantics are considered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import Issue, IssueSeverity
from ..utils.filesystem import read_text

__all__ = ["YamlValidationResult", "validate_yaml_file", "validate_yaml_text", "DuplicateKeyError"]


class DuplicateKeyError(yaml.constructor.ConstructorError):
    """Raised when a YAML mapping contains the same key twice."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects duplicated mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise DuplicateKeyError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


@dataclass
class YamlValidationResult:
    """Outcome of validating a single YAML document."""

    path: str
    data: dict[str, Any] | None = None
    issues: list[Issue] = field(default_factory=list)
    sha256: str = ""

    @property
    def ok(self) -> bool:
        """``True`` when no error level issue was recorded."""

        return not any(issue.severity is IssueSeverity.ERROR for issue in self.issues)


def validate_yaml_text(text: str, path: str = "<memory>") -> YamlValidationResult:
    """Validate YAML *text* and return the parsed mapping (if any)."""

    result = YamlValidationResult(path=path)
    if not text.strip():
        result.issues.append(
            Issue(
                severity=IssueSeverity.ERROR,
                code="yaml.empty_file",
                message="File is empty; a Sigma rule must contain a YAML mapping.",
                rule_path=path,
                stage="yaml",
            )
        )
        return result

    try:
        documents = list(yaml.load_all(text, Loader=_UniqueKeyLoader))
    except yaml.YAMLError as exc:
        result.issues.append(
            Issue(
                severity=IssueSeverity.ERROR,
                code="yaml.parse_error",
                message=f"Invalid YAML: {exc}",
                rule_path=path,
                stage="yaml",
            )
        )
        return result

    if len(documents) == 0:
        result.issues.append(
            Issue(
                severity=IssueSeverity.ERROR,
                code="yaml.empty_file",
                message="File contains no YAML document.",
                rule_path=path,
                stage="yaml",
            )
        )
        return result
    if len(documents) > 1:
        result.issues.append(
            Issue(
                severity=IssueSeverity.ERROR,
                code="yaml.multiple_documents",
                message=(
                    f"File contains {len(documents)} YAML documents; a Sigma rule file "
                    "must contain exactly one document."
                ),
                rule_path=path,
                stage="yaml",
            )
        )
        return result

    document = documents[0]
    if document is None:
        result.issues.append(
            Issue(
                severity=IssueSeverity.ERROR,
                code="yaml.empty_file",
                message="YAML document is empty.",
                rule_path=path,
                stage="yaml",
            )
        )
        return result
    if not isinstance(document, dict):
        result.issues.append(
            Issue(
                severity=IssueSeverity.ERROR,
                code="yaml.invalid_structure",
                message=(
                    "Top level YAML structure must be a mapping, got "
                    f"{type(document).__name__}."
                ),
                rule_path=path,
                stage="yaml",
            )
        )
        return result

    result.data = document
    return result


def validate_yaml_file(path: Path, display_path: str | None = None) -> YamlValidationResult:
    """Validate the YAML document stored at *path*."""

    from ..utils.filesystem import file_sha256

    shown = display_path or path.as_posix()
    if not path.is_file():
        result = YamlValidationResult(path=shown)
        result.issues.append(
            Issue(
                severity=IssueSeverity.ERROR,
                code="yaml.file_not_found",
                message="File does not exist.",
                rule_path=shown,
                stage="yaml",
            )
        )
        return result

    result = validate_yaml_text(read_text(path), shown)
    result.sha256 = file_sha256(path)
    return result
