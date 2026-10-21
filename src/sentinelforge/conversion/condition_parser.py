"""Sigma condition compiler.

This module turns a pySigma rule into a small, platform neutral intermediate
representation (IR).  The IR is the single source of truth for the *semantics*
of a rule: both the Wazuh converter and the offline fixture matcher consume it,
which guarantees that the two never drift apart.

Supported Sigma subset
----------------------
The compiler accepts:

* detection definitions that are mappings, lists of mappings, plain keyword
  values and lists of keyword values;
* boolean conditions built from ``and`` / ``or`` / ``not``, detection
  identifiers, ``1 of them`` / ``all of them`` / ``1 of <pattern>`` selectors;
* the modifiers ``contains``, ``startswith``, ``endswith``, ``cased``, ``all``,
  ``exists`` and ``neq``;
* string, integer and boolean values.

Everything else is rejected with a :class:`~sentinelforge.errors.UnsupportedFeatureError`
that names the offending construct.  In particular regular expressions, CIDR
ranges, wildcards inside values, numeric comparisons, base64 encodings, field
references and value references are *not* converted: emitting a Wazuh rule that
matched a different set of events would silently weaken the detection.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, cast

from sigma.conditions import (
    ConditionAND,
    ConditionIdentifier,
    ConditionNOT,
    ConditionOR,
    ConditionSelector,
    SigmaCondition,
)
from sigma.modifiers import (  # type: ignore[attr-defined]
    SigmaAllModifier,
    SigmaCaseSensitiveModifier,
    SigmaCompareModifier,
    SigmaContainsModifier,
    SigmaEndswithModifier,
    SigmaExists,
    SigmaExistsModifier,
    SigmaNegateModifier,
    SigmaRegularExpressionModifier,
    SigmaStartswithModifier,
)
from sigma.rule import SigmaRule
from sigma.rule.detection import SigmaDetection, SigmaDetectionItem
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaNull,
    SigmaNumber,
    SigmaString,
)

from ..errors import UnsupportedFeatureError
from ..models import LogSource
from .field_mapping import UNKNOWN_FIELD_MESSAGE, MappingRegistry

__all__ = [
    "ClauseKind",
    "Clause",
    "BoolNode",
    "NotNode",
    "Node",
    "ConditionCompiler",
    "SUPPORTED_MODIFIERS",
]

#: Sigma modifiers that the compiler understands.
SUPPORTED_MODIFIERS: frozenset[str] = frozenset(
    {
        "contains",
        "startswith",
        "endswith",
        "cased",
        "all",
        "exists",
        "neq",
    }
)


class ClauseKind(str, Enum):
    """The kind of match a single clause performs."""

    KEYWORD = "keyword"
    EQUALS = "equals"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    EXISTS = "exists"


@dataclass(frozen=True)
class Clause:
    """A single atomic match condition."""

    kind: ClauseKind
    field: str | None = None
    value: str | None = None
    case_sensitive: bool = False
    negated: bool = False

    def describe(self) -> str:
        """Return a short human readable description of the clause."""

        if self.kind is ClauseKind.KEYWORD:
            return f"keyword '{self.value}'"
        if self.kind is ClauseKind.EXISTS:
            state = "present" if self.value == "true" else "absent"
            return f"field '{self.field}' {state}"
        operator = {
            ClauseKind.EQUALS: "==",
            ClauseKind.CONTAINS: "contains",
            ClauseKind.STARTSWITH: "starts with",
            ClauseKind.ENDSWITH: "ends with",
        }[self.kind]
        return f"field '{self.field}' {operator} '{self.value}'"


@dataclass(frozen=True)
class BoolNode:
    """A conjunction or disjunction of child nodes."""

    operator: str
    children: tuple[Node, ...]

    def describe(self) -> str:
        joiner = " and " if self.operator == "and" else " or "
        return f"({joiner.join(child.describe() for child in self.children)})"


@dataclass(frozen=True)
class NotNode:
    """A negation of a child node."""

    child: Node

    def describe(self) -> str:
        return f"NOT {self.child.describe()}"


Node = Clause | BoolNode | NotNode


class ConditionCompiler:
    """Compile a pySigma rule into the SentinelForge intermediate representation."""

    def __init__(self, mapping: MappingRegistry) -> None:
        self._mapping = mapping

    # ------------------------------------------------------------------ public

    def compile_rule(
        self,
        rule: SigmaRule,
        *,
        logsource: LogSource,
        rule_path: str | None = None,
        rule_id: str | None = None,
    ) -> Node:
        """Compile *rule* into an IR tree.

        Raises
        ------
        UnsupportedFeatureError
            When the rule uses a construct outside the documented supported
            subset.
        """

        detections = rule.detection
        if not detections.condition:
            raise UnsupportedFeatureError(
                "Rule does not define a condition.",
                rule_path=rule_path,
                rule_id=rule_id,
                feature="condition.missing",
                limitation="Every converted rule must define a boolean condition.",
            )

        branches: list[Node] = []
        for condition_text in detections.condition:
            condition = SigmaCondition(condition_text, detections, rule.source)
            try:
                tree = condition.parse(postprocess=False)
            except Exception as exc:  # pysigma raises SigmaConditionError subclasses
                raise UnsupportedFeatureError(
                    f"Condition '{condition_text}' could not be parsed: {exc}",
                    rule_path=rule_path,
                    rule_id=rule_id,
                    feature="condition.unparsable",
                    limitation=("Only boolean conditions over detection identifiers are supported."),
                ) from exc
            if tree is None:
                raise UnsupportedFeatureError(
                    f"Condition '{condition_text}' is empty.",
                    rule_path=rule_path,
                    rule_id=rule_id,
                    feature="condition.empty",
                    limitation="Only boolean conditions over detection identifiers are supported.",
                )
            branches.append(self._node_from_condition(tree, detections, logsource, rule_path, rule_id))

        if len(branches) == 1:
            return branches[0]
        return BoolNode("or", tuple(branches))

    # ----------------------------------------------------------------- private

    def _node_from_condition(
        self,
        item: Any,
        detections: Any,
        logsource: LogSource,
        rule_path: str | None,
        rule_id: str | None,
    ) -> Node:
        if isinstance(item, ConditionIdentifier):
            try:
                detection = detections[item.identifier]
            except KeyError as exc:
                raise UnsupportedFeatureError(
                    f"Detection '{item.identifier}' referenced by the condition is not defined.",
                    rule_path=rule_path,
                    rule_id=rule_id,
                    feature="condition.dangling_detection",
                    limitation="Every identifier used in a condition must be defined.",
                ) from exc
            return self._node_from_detection(detection, logsource, rule_path, rule_id)

        if isinstance(item, ConditionSelector):
            identifiers = item.resolve_referenced_detections(detections)
            if not identifiers:
                raise UnsupportedFeatureError(
                    f"Selector '{' '.join(item.args)}' does not match any detection.",
                    rule_path=rule_path,
                    rule_id=rule_id,
                    feature="condition.empty_selector",
                    limitation="Selectors must match at least one detection definition.",
                )
            children = tuple(
                self._node_from_detection(detections[identifier.identifier], logsource, rule_path, rule_id)
                for identifier in identifiers
            )
            operator = "or" if item.cond_class is ConditionOR else "and"
            return BoolNode(operator, children)

        if isinstance(item, ConditionAND):
            children = tuple(
                self._node_from_condition(child, detections, logsource, rule_path, rule_id) for child in item.args
            )
            if not children:
                raise UnsupportedFeatureError(
                    "Empty 'and' expression in condition.",
                    rule_path=rule_path,
                    rule_id=rule_id,
                    feature="condition.empty",
                    limitation="Boolean conditions must contain at least one operand.",
                )
            if len(children) == 1:
                return children[0]
            return BoolNode("and", children)

        if isinstance(item, ConditionOR):
            children = tuple(
                self._node_from_condition(child, detections, logsource, rule_path, rule_id) for child in item.args
            )
            if not children:
                raise UnsupportedFeatureError(
                    "Empty 'or' expression in condition.",
                    rule_path=rule_path,
                    rule_id=rule_id,
                    feature="condition.empty",
                    limitation="Boolean conditions must contain at least one operand.",
                )
            if len(children) == 1:
                return children[0]
            return BoolNode("or", children)

        if isinstance(item, ConditionNOT):
            child = self._node_from_condition(item.args[0], detections, logsource, rule_path, rule_id)
            return NotNode(child)

        raise UnsupportedFeatureError(
            f"Unsupported condition construct '{type(item).__name__}'.",
            rule_path=rule_path,
            rule_id=rule_id,
            feature="condition.unsupported",
            limitation="Only and/or/not over detection identifiers and selectors are supported.",
        )

    def _node_from_detection(
        self,
        detection: SigmaDetection,
        logsource: LogSource,
        rule_path: str | None,
        rule_id: str | None,
    ) -> Node:
        items = detection.detection_items
        if not items:
            raise UnsupportedFeatureError(
                "Detection definition is empty.",
                rule_path=rule_path,
                rule_id=rule_id,
                feature="detection.empty",
                limitation="Every detection must define at least one value.",
            )

        if all(isinstance(item, SigmaDetectionItem) for item in items):
            linking = detection.item_linking
            operator = "and" if linking is ConditionAND else "or"
            children = tuple(
                self._node_from_item(cast(SigmaDetectionItem, item), logsource, rule_path, rule_id) for item in items
            )
            if len(children) == 1:
                return children[0]
            return BoolNode(operator, children)

        children = tuple(
            self._node_from_detection(item, logsource, rule_path, rule_id)
            for item in items
            if isinstance(item, SigmaDetection)
        )
        if not children:
            raise UnsupportedFeatureError(
                "Detection definition contains only unsupported item types.",
                rule_path=rule_path,
                rule_id=rule_id,
                feature="detection.unsupported",
                limitation="Only detection items and nested detections are supported.",
            )
        if len(children) == 1:
            return children[0]
        return BoolNode("or", children)

    def _node_from_item(
        self,
        item: SigmaDetectionItem,
        logsource: LogSource,
        rule_path: str | None,
        rule_id: str | None,
    ) -> Node:
        self._check_modifiers(item, rule_path, rule_id)

        if item.field is not None:
            self._require_field_mapping(logsource, item.field, rule_path, rule_id)

        kind = self._clause_kind(item, rule_path, rule_id)
        negated = bool(item.negated)
        case_sensitive = SigmaCaseSensitiveModifier in item.modifiers

        values = item.original_value if item.original_value else item.value
        if not values:
            raise UnsupportedFeatureError(
                f"Detection item for field '{item.field}' has no value.",
                rule_path=rule_path,
                rule_id=rule_id,
                feature="detection.empty_value",
                limitation="Every detection item must define at least one value.",
            )

        clauses: list[Node] = []
        for index in range(len(values)):
            literal = self._literal(values[index], item, rule_path, rule_id)
            clauses.append(
                Clause(
                    kind=kind,
                    field=item.field,
                    value=literal,
                    case_sensitive=case_sensitive,
                    negated=negated,
                )
            )

        if len(clauses) == 1:
            return clauses[0]
        linking = item.value_linking
        operator = "and" if linking is ConditionAND else "or"
        return BoolNode(operator, tuple(clauses))

    def _check_modifiers(self, item: SigmaDetectionItem, rule_path: str | None, rule_id: str | None) -> None:
        for modifier in item.modifiers:
            name = modifier.__name__
            if name in {
                SigmaContainsModifier.__name__,
                SigmaStartswithModifier.__name__,
                SigmaEndswithModifier.__name__,
                SigmaCaseSensitiveModifier.__name__,
                SigmaAllModifier.__name__,
                SigmaExistsModifier.__name__,
                SigmaNegateModifier.__name__,
            }:
                continue
            if name == SigmaRegularExpressionModifier.__name__:
                raise UnsupportedFeatureError(
                    "The 're' modifier is not supported.",
                    rule_path=rule_path,
                    rule_id=rule_id,
                    feature="modifier.re",
                    limitation=(
                        "Sigma regular expressions are evaluated with Python's 're' module while "
                        "Wazuh uses PCRE. The two dialects differ in edge cases, so the rule is "
                        "rejected instead of being converted into a pattern with different "
                        "semantics."
                    ),
                )
            if issubclass(modifier, SigmaCompareModifier):
                raise UnsupportedFeatureError(
                    f"The '{name.removeprefix('Sigma').removesuffix('Modifier').lower()}' "
                    "numeric comparison modifier is not supported.",
                    rule_path=rule_path,
                    rule_id=rule_id,
                    feature=f"modifier.{name}",
                    limitation=(
                        "Numeric comparison modifiers cannot be expressed as a Wazuh field "
                        "match without changing the semantics of the rule."
                    ),
                )
            raise UnsupportedFeatureError(
                f"The modifier '{name}' is not supported.",
                rule_path=rule_path,
                rule_id=rule_id,
                feature=f"modifier.{name}",
                limitation=(
                    "Only contains, startswith, endswith, cased, all, exists and neq are part "
                    "of the supported conversion subset."
                ),
            )

    def _clause_kind(self, item: SigmaDetectionItem, rule_path: str | None, rule_id: str | None) -> ClauseKind:
        if SigmaExistsModifier in item.modifiers:
            return ClauseKind.EXISTS
        if SigmaContainsModifier in item.modifiers:
            return ClauseKind.CONTAINS
        if SigmaStartswithModifier in item.modifiers:
            return ClauseKind.STARTSWITH
        if SigmaEndswithModifier in item.modifiers:
            return ClauseKind.ENDSWITH
        return ClauseKind.EQUALS

    def _literal(
        self,
        value: Any,
        item: SigmaDetectionItem,
        rule_path: str | None,
        rule_id: str | None,
    ) -> str:
        if isinstance(value, SigmaExists):
            return "true" if value.boolean else "false"  # type: ignore[attr-defined]
        if isinstance(value, SigmaCasedString):
            text = str(value)
        elif isinstance(value, SigmaString):
            text = str(value)
        elif isinstance(value, SigmaNumber):
            text = str(value.number)
        elif isinstance(value, SigmaBool):
            text = "true" if value.boolean else "false"
        elif isinstance(value, SigmaNull):
            raise UnsupportedFeatureError(
                "Null values are not supported.",
                rule_path=rule_path,
                rule_id=rule_id,
                feature="value.null",
                limitation=(
                    "A Wazuh rule cannot assert that a decoded field is null without changing "
                    "the meaning of the detection."
                ),
            )
        else:
            raise UnsupportedFeatureError(
                f"Value of type '{type(value).__name__}' is not supported.",
                rule_path=rule_path,
                rule_id=rule_id,
                feature=f"value.{type(value).__name__}",
                limitation=(
                    "Only plain string, integer and boolean values are part of the supported " "conversion subset."
                ),
            )

        if "*" in text:
            raise UnsupportedFeatureError(
                f"Wildcards inside the value {text!r} are not supported.",
                rule_path=rule_path,
                rule_id=rule_id,
                feature="value.wildcard",
                limitation=(
                    "Sigma wildcards expand to arbitrary content and cannot be translated into a "
                    "Wazuh field match without changing the semantics of the rule. Use the "
                    "'contains' modifier instead."
                ),
            )
        return text

    def _require_field_mapping(
        self, logsource: LogSource, field_name: str, rule_path: str | None, rule_id: str | None
    ) -> None:
        if self._mapping.pattern(logsource, field_name) is None:
            raise UnsupportedFeatureError(
                UNKNOWN_FIELD_MESSAGE.format(field=field_name, logsource=logsource.key),
                rule_path=rule_path,
                rule_id=rule_id,
                feature=f"field_mapping.{logsource.key}.{field_name}",
                limitation=(
                    "A field without a mapping would have to be matched as a plain keyword, "
                    "which would match unrelated events and weaken the detection."
                ),
            )
