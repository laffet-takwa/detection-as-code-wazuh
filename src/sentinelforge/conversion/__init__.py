"""Conversion layer: Sigma to Wazuh translation."""

from __future__ import annotations

from .base import Backend, Converter, ConverterContext
from .condition_parser import (
    SUPPORTED_MODIFIERS,
    BoolNode,
    Clause,
    ClauseKind,
    ConditionCompiler,
    Node,
    NotNode,
)
from .conversion_report import render_conversion_report, render_conversion_summary
from .field_mapping import (
    DEFAULT_MAPPINGS,
    UNKNOWN_FIELD_MESSAGE,
    FieldPattern,
    FieldTemplate,
    LogSourceMapping,
    MappingRegistry,
    build_default_registry,
)
from .sigma_loader import LoadedRule, SigmaLoader
from .wazuh_converter import (
    RULE_GROUP_MAP,
    WazuhConverter,
    WazuhRuleBuilder,
    build_rule_xml,
)

__all__ = [
    "Backend",
    "Converter",
    "ConverterContext",
    "Clause",
    "ClauseKind",
    "Node",
    "BoolNode",
    "NotNode",
    "ConditionCompiler",
    "SUPPORTED_MODIFIERS",
    "LoadedRule",
    "SigmaLoader",
    "WazuhConverter",
    "WazuhRuleBuilder",
    "RULE_GROUP_MAP",
    "build_rule_xml",
    "FieldTemplate",
    "FieldPattern",
    "LogSourceMapping",
    "MappingRegistry",
    "DEFAULT_MAPPINGS",
    "build_default_registry",
    "UNKNOWN_FIELD_MESSAGE",
    "render_conversion_report",
    "render_conversion_summary",
]
