"""Sigma rule loading utilities.

This module bridges the gap between the validated :class:`~sentinelforge.models.DetectionRule`
model and the pySigma objects needed by the condition compiler and the converter.
"""

from __future__ import annotations

from sigma.rule import SigmaRule

from ..models import DetectionRule, LogSource
from .condition_parser import ConditionCompiler, Node
from .field_mapping import MappingRegistry

__all__ = ["LoadedRule", "SigmaLoader"]


class LoadedRule:
    """A Sigma rule loaded into pySigma together with its compiled IR."""

    def __init__(
        self,
        rule: DetectionRule,
        sigma_rule: SigmaRule,
        ir: Node,
        logsource: LogSource,
    ) -> None:
        self.rule = rule
        self.sigma_rule = sigma_rule
        self.ir = ir
        self.logsource = logsource

    @property
    def title(self) -> str:
        return self.rule.title

    @property
    def rule_id(self) -> str:
        return self.rule.rule_id


class SigmaLoader:
    """Load validated rules into pySigma and compile their conditions."""

    def __init__(self, mapping: MappingRegistry) -> None:
        self._mapping = mapping
        self._compiler = ConditionCompiler(mapping)

    def load(self, rule: DetectionRule) -> LoadedRule:
        """Parse *rule* with pySigma and compile its condition to IR."""

        if rule.kind.value != "detection":
            raise ValueError(f"Rule {rule.rule_id} is not a detection rule")

        sigma_rule = SigmaRule.from_dict(rule.raw, collect_errors=True)
        if sigma_rule.errors:
            raise ValueError(f"pySigma parse errors: {sigma_rule.errors}")

        ir = self._compiler.compile_rule(
            sigma_rule,
            logsource=rule.logsource,
            rule_path=rule.path,
            rule_id=rule.rule_id,
        )

        return LoadedRule(
            rule=rule,
            sigma_rule=sigma_rule,
            ir=ir,
            logsource=rule.logsource,
        )

    def load_many(self, rules: list[DetectionRule]) -> list[LoadedRule]:
        """Load multiple rules, skipping those that fail to parse."""

        loaded: list[LoadedRule] = []
        for rule in rules:
            try:
                loaded.append(self.load(rule))
            except Exception as exc:  # pragma: no cover - defensive
                raise ValueError(f"Failed to load rule {rule.rule_id}: {exc}") from exc
        return loaded
