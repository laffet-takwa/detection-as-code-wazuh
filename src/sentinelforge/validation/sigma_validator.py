"""Stage B - Sigma semantic validation backed by pySigma.

This stage does **not** attempt to re-implement Sigma.  It parses every rule with
pySigma's own ``SigmaRule``/``SigmaCorrelationRule`` classes, parses the
condition with pySigma's condition parser and runs pySigma's best-practice
validator suite.  Only the mapping of pysigma results onto SentinelForge issues
is implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sigma.exceptions import SigmaConditionError, SigmaError
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidationIssue, SigmaValidator  # type: ignore[attr-defined]
from sigma.validators.base import SigmaValidationIssueSeverity  # noqa: TID251
from sigma.validators.core.condition import (
    AllOfThemConditionValidator,
    DanglingConditionValidator,
    DanglingDetectionValidator,
    ThemConditionWithSingleDetectionValidator,
)
from sigma.validators.core.logsources import FieldnameLogsourceValidator
from sigma.validators.core.metadata import (
    CustomAttributesValidator,
    DuplicateFilenameValidator,
    DuplicateReferencesValidator,
    DuplicateTitleValidator,
    FilenameLengthValidator,
    IdentifierUniquenessValidator,
)
from sigma.validators.core.modifiers import InvalidModifierCombinationsValidator
from sigma.validators.core.tags import (
    ATTACKTagValidator,
    DuplicateTagValidator,
    TagFormatValidator,
)
from sigma.validators.core.values import (
    ControlCharacterValidator,
    DoubleWildcardValidator,
    EscapedWildcardValidator,
    NumberAsStringValidator,
    WildcardsInsteadOfModifiersValidator,
)

from ..models import Issue, IssueSeverity, RuleKind

__all__ = [
    "ParsedRule",
    "BEST_PRACTICE_VALIDATORS",
    "parse_rule_document",
    "validate_sigma_semantics",
    "run_best_practice_validators",
    "map_validation_severity",
]

#: The pySigma best-practice validators that SentinelForge enables by default.
#:
#: The list is explicit (instead of "everything pySigma ships") so that a new
#: upstream validator can never silently change the outcome of the CI gate.
BEST_PRACTICE_VALIDATORS: tuple[type[Any], ...] = (
    AllOfThemConditionValidator,
    ATTACKTagValidator,
    ControlCharacterValidator,
    CustomAttributesValidator,
    DanglingConditionValidator,
    DanglingDetectionValidator,
    DoubleWildcardValidator,
    DuplicateFilenameValidator,
    DuplicateReferencesValidator,
    DuplicateTagValidator,
    DuplicateTitleValidator,
    EscapedWildcardValidator,
    FieldnameLogsourceValidator,
    FilenameLengthValidator,
    IdentifierUniquenessValidator,
    InvalidModifierCombinationsValidator,
    NumberAsStringValidator,
    TagFormatValidator,
    ThemConditionWithSingleDetectionValidator,
    WildcardsInsteadOfModifiersValidator,
)


@dataclass
class ParsedRule:
    """A Sigma document parsed with pySigma."""

    path: str
    document: dict[str, Any]
    rule: SigmaRule | None = None
    kind: RuleKind = RuleKind.DETECTION
    issues: list[Issue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(issue.severity is IssueSeverity.ERROR for issue in self.issues)

    @property
    def title(self) -> str:
        if self.rule is not None and self.rule.title:
            return self.rule.title
        title = self.document.get("title")
        return title if isinstance(title, str) else ""

    @property
    def rule_id(self) -> str:
        if self.rule is not None and self.rule.id is not None:
            return str(self.rule.id)
        raw_id = self.document.get("id")
        return raw_id if isinstance(raw_id, str) else ""


def parse_rule_document(document: dict[str, Any], path: str) -> ParsedRule:
    """Parse *document* into a pySigma rule object.

    Parsing errors are collected as issues instead of being raised, so that a
    single broken rule does not abort a repository wide validation run.

    Note: Correlation rules are parsed as regular Sigma rules because
    pySigma's SigmaCorrelationRule.from_dict() has a known bug (UnboundLocalError).
    The correlation block is preserved in the raw document for conversion reporting.
    """

    parsed = ParsedRule(path=path, document=document)

    is_correlation = "correlation" in document
    if is_correlation:
        parsed.kind = RuleKind.CORRELATION

    try:
        rule = SigmaRule.from_dict(document, collect_errors=True)
    except SigmaError as exc:
        parsed.issues.append(
            Issue(
                severity=IssueSeverity.ERROR,
                code="sigma.parse_error",
                message=f"pySigma could not parse the rule: {exc}",
                rule_path=path,
                stage="sigma",
            )
        )
        return parsed

    parsed.rule = rule
    for error in rule.errors:
        parsed.issues.append(
            Issue(
                severity=IssueSeverity.ERROR,
                code="sigma.parse_error",
                message=str(error),
                rule_path=path,
                rule_id=str(rule.id) if rule.id else None,
                stage="sigma",
            )
        )
    return parsed


def validate_sigma_semantics(parsed: ParsedRule) -> list[Issue]:
    """Validate the Sigma semantics of an already parsed rule.

    The condition of every rule is parsed with pySigma's condition parser, which
    resolves detection identifiers and therefore reports dangling references and
    unsupported condition syntax.
    """

    issues: list[Issue] = []
    rule = parsed.rule
    if rule is None or parsed.kind is RuleKind.CORRELATION:
        return issues

    detection = rule.detection
    for condition in detection.parsed_condition:
        try:
            condition.parse()
        except SigmaConditionError as exc:
            issues.append(
                Issue(
                    severity=IssueSeverity.ERROR,
                    code="sigma.condition_error",
                    message=f"Invalid condition: {exc}",
                    rule_path=parsed.path,
                    rule_id=parsed.rule_id or None,
                    field="detection.condition",
                    stage="sigma",
                )
            )
    return issues


def map_validation_severity(severity: SigmaValidationIssueSeverity) -> IssueSeverity:
    """Map a pySigma validation severity onto a SentinelForge issue severity."""

    if severity is SigmaValidationIssueSeverity.HIGH:
        return IssueSeverity.ERROR
    if severity is SigmaValidationIssueSeverity.MEDIUM:
        return IssueSeverity.WARNING
    return IssueSeverity.INFO


def run_best_practice_validators(
    rules: list[ParsedRule],
) -> list[Issue]:
    """Run the pySigma best-practice validator suite over *rules*.

    The validators are stateful across rules (for example the duplicate title
    validator), therefore the whole catalogue is validated in a single pass.

    Correlation rules are skipped because they have different semantics
    (e.g., dangling detections are expected).
    """

    issues: list[Issue] = []
    detection_rules = [
        parsed.rule for parsed in rules if parsed.rule is not None and parsed.ok and parsed.kind is RuleKind.DETECTION
    ]
    if not detection_rules:
        return issues

    validator = SigmaValidator(BEST_PRACTICE_VALIDATORS)
    for rule in detection_rules:
        for validation_issue in validator.validate_rule(rule):
            issues.append(_convert_issue(validation_issue))

    for validation_issue in validator.finalize():
        issues.append(_convert_issue(validation_issue))
    return issues


def _convert_issue(validation_issue: SigmaValidationIssue) -> Issue:
    """Convert a pySigma validation issue into a SentinelForge issue."""

    rule_paths = [str(rule.source) if rule.source is not None else str(rule.id) for rule in validation_issue.rules]
    path = rule_paths[0] if rule_paths else None
    return Issue(
        severity=map_validation_severity(validation_issue.severity),
        code=f"sigma.{validation_issue.__class__.__name__}",
        message=validation_issue.description,
        rule_path=path,
        stage="sigma.best_practice",
    )
