"""Stage D - repository validation.

The repository validator orchestrates the individual stages over the whole rule
catalogue and adds the checks that only make sense across files: duplicate
identifiers, duplicate titles, stable traversal order and consistent file
organisation.

The traversal is deterministic (files are processed in sorted POSIX path order)
so that two runs over the same catalogue always produce the same diagnostics in
the same order.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Settings
from ..models import (
    DetectionRule,
    Issue,
    IssueSeverity,
    Platform,
    RuleKind,
    ValidationReport,
)
from ..utils.filesystem import iter_sigma_files, relative_posix
from .attack_validator import validate_attack_tags
from .metadata_validator import RuleMetadata, validate_metadata
from .sigma_validator import (
    ParsedRule,
    parse_rule_document,
    run_best_practice_validators,
    validate_sigma_semantics,
)
from .yaml_validator import validate_yaml_file

__all__ = ["ValidationResult", "RepositoryValidator"]

_PLATFORM_BY_DIRECTORY = {
    "linux": Platform.LINUX,
    "windows": Platform.WINDOWS,
    "common": Platform.COMMON,
}


@dataclass
class ValidationResult:
    """The complete outcome of a repository validation run."""

    report: ValidationReport
    rules: list[DetectionRule] = field(default_factory=list)
    parsed: list[ParsedRule] = field(default_factory=list)
    metadata: dict[str, RuleMetadata] = field(default_factory=dict)

    @property
    def detection_rules(self) -> list[DetectionRule]:
        return [rule for rule in self.rules if rule.kind is RuleKind.DETECTION]

    @property
    def correlation_rules(self) -> list[DetectionRule]:
        return [rule for rule in self.rules if rule.kind is RuleKind.CORRELATION]


class RepositoryValidator:
    """Validate a directory of Sigma rules against the SentinelForge quality gates."""

    def __init__(self, settings: Settings, *, strict: bool | None = None) -> None:
        self._settings = settings
        self._strict = settings.strict if strict is None else strict
        self._issues: list[Issue] = []

    # ------------------------------------------------------------------ public

    def validate(self) -> ValidationResult:
        """Run every validation stage over the configured rules directory."""

        self._issues = []
        root = self._settings.rules_directory
        files = iter_sigma_files(root)
        display_paths = [relative_posix(path, self._settings.project_root) for path in files]

        parsed_rules: list[ParsedRule] = []
        metadata_by_path: dict[str, RuleMetadata] = {}
        valid_rules: list[DetectionRule] = []

        for path, display in zip(files, display_paths, strict=False):
            parsed, metadata = self._validate_file(path, display)
            parsed_rules.append(parsed)
            metadata_by_path[display] = metadata
            rule = self._build_rule(parsed, metadata, display)
            if rule is not None:
                valid_rules.append(rule)

        self._issues.extend(run_best_practice_validators(parsed_rules))
        self._check_repository_rules(valid_rules, display_paths)

        if self._strict:
            self._issues = [
                issue.model_copy(update={"severity": IssueSeverity.ERROR})
                if issue.severity is IssueSeverity.WARNING
                else issue
                for issue in self._issues
            ]

        error_paths = {issue.rule_path for issue in self._issues if issue.severity is IssueSeverity.ERROR}
        rule_ids = {rule.path: rule.rule_id for rule in valid_rules}
        report = ValidationReport(
            rules_discovered=len(files),
            rules_valid=len(valid_rules),
            rules_invalid=len({path for path in error_paths if path}),
            issues=self._issues,
            strict=self._strict,
            rule_ids=rule_ids,
        )
        return ValidationResult(
            report=report,
            rules=valid_rules,
            parsed=parsed_rules,
            metadata=metadata_by_path,
        )

    # ----------------------------------------------------------------- private

    def _validate_file(self, path: Path, display: str) -> tuple[ParsedRule, RuleMetadata]:
        yaml_result = validate_yaml_file(path, display)
        self._issues.extend(yaml_result.issues)
        if yaml_result.data is None:
            return ParsedRule(path=display, document={}), RuleMetadata()

        platform_directory = self._platform_directory(path)
        metadata_result = validate_metadata(
            yaml_result.data, display, platform_directory=platform_directory
        )
        self._issues.extend(metadata_result.issues)

        parsed = parse_rule_document(yaml_result.data, display)
        self._issues.extend(parsed.issues)
        self._issues.extend(validate_sigma_semantics(parsed))

        attack_references, attack_issues = validate_attack_tags(
            metadata_result.metadata.tags,
            rule_path=display,
            rule_id=metadata_result.metadata.rule_id or None,
            require_attack=parsed.kind is RuleKind.DETECTION,
        )
        self._issues.extend(attack_issues)
        metadata_result.metadata.attack = attack_references
        return parsed, metadata_result.metadata

    def _platform_directory(self, path: Path) -> Platform | None:
        """Return the platform implied by the directory the rule is stored in."""

        try:
            relative = path.resolve().relative_to(self._settings.rules_directory.resolve())
        except ValueError:  # pragma: no cover - defensive
            return None
        if not relative.parts:
            return None
        return _PLATFORM_BY_DIRECTORY.get(relative.parts[0].lower())

    def _build_rule(
        self, parsed: ParsedRule, metadata: RuleMetadata, display: str
    ) -> DetectionRule | None:
        """Assemble a :class:`DetectionRule` when the rule passed every stage."""

        if not metadata.rule_id or not metadata.title:
            return None
        if not metadata.logsource.product and not metadata.logsource.category:
            return None

        from uuid import UUID

        try:
            rule_uuid = UUID(metadata.rule_id)
        except ValueError:  # pragma: no cover - already validated
            return None

        platform = metadata.platform
        directory_platform = self._platform_directory(Path(display))
        if directory_platform is Platform.COMMON and platform in (Platform.LINUX, Platform.WINDOWS):
            self._issues.append(
                Issue(
                    severity=IssueSeverity.WARNING,
                    code="repository.platform_directory",
                    message=(
                        f"Rule targets '{platform.value}' but is stored in the shared 'common' "
                        f"directory; move it to 'rules/{platform.value}'."
                    ),
                    rule_path=display,
                    rule_id=metadata.rule_id,
                    stage="repository",
                )
            )

        raw: dict[str, Any] = dict(parsed.document)
        return DetectionRule(
            path=display,
            title=metadata.title,
            id=rule_uuid,
            name=metadata.name,
            kind=parsed.kind,
            status=metadata.status,
            description=metadata.description,
            author=metadata.author,
            rule_date=metadata.date,
            level=metadata.level,
            logsource=metadata.logsource,
            condition=metadata.condition,
            falsepositives=metadata.falsepositives,
            references=metadata.references,
            tags=metadata.tags,
            attack=list(getattr(metadata, "attack", [])),
            platform=platform,
            raw=raw,
        )

    def _check_repository_rules(
        self, rules: list[DetectionRule], display_paths: list[str]
    ) -> None:
        """Cross-file checks: duplicate identifiers, titles and names."""

        seen_ids: dict[str, str] = {}
        seen_titles: dict[str, str] = {}
        seen_names: dict[str, str] = {}

        for rule in rules:
            identifier = rule.rule_id
            if identifier in seen_ids:
                self._issues.append(
                    Issue(
                        severity=IssueSeverity.ERROR,
                        code="repository.duplicate_id",
                        message=(
                            f"UUID {identifier} is already used by '{seen_ids[identifier]}'. "
                            "Every published rule must use a unique UUID."
                        ),
                        rule_path=rule.path,
                        rule_id=identifier,
                        field="id",
                        stage="repository",
                    )
                )
            else:
                seen_ids[identifier] = rule.path

            title_key = rule.title.strip().lower()
            if title_key in seen_titles:
                self._issues.append(
                    Issue(
                        severity=IssueSeverity.ERROR,
                        code="repository.duplicate_title",
                        message=(
                            f"Title '{rule.title}' is already used by "
                            f"'{seen_titles[title_key]}'."
                        ),
                        rule_path=rule.path,
                        rule_id=identifier,
                        field="title",
                        stage="repository",
                    )
                )
            else:
                seen_titles[title_key] = rule.path

            if rule.name:
                name_key = rule.name.strip().lower()
                if name_key in seen_names:
                    self._issues.append(
                        Issue(
                            severity=IssueSeverity.ERROR,
                            code="repository.duplicate_name",
                            message=(
                                f"Rule name '{rule.name}' is already used by "
                                f"'{seen_names[name_key]}'. Rule names must be unique because "
                                "correlation rules reference them."
                            ),
                            rule_path=rule.path,
                            rule_id=identifier,
                            field="name",
                            stage="repository",
                        )
                    )
                else:
                    seen_names[name_key] = rule.path
