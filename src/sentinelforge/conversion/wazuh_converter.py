"""Wazuh custom rule converter.

This module translates the SentinelForge intermediate representation (IR) into
syntactically valid Wazuh custom XML rules.  Only the subset of Sigma that has a
faithful Wazuh equivalent is converted; every other construct raises
:class:`~sentinelforge.errors.UnsupportedFeatureError`.

Supported Sigma subset (mirrors :mod:`sentinelforge.conversion.condition_parser`):
- Field equality, contains, startswith, endswith with explicit field mappings
- Keyword searches (field-less values)
- Field existence checks
- Boolean combinations (and / or / not)
- 1 of them / all of them / 1 of <pattern> selectors

Unsupported (rejected with explanation):
- Regular expressions (re modifier) - Python vs PCRE dialect differences
- Numeric comparisons (lt, gt, lte, gte) - no Wazuh equivalent
- Wildcards inside values (*) - would change semantics
- Base64 encodings, CIDR, field references, value references
- Correlation rules (multi-event, time windows) - requires separate engine
- Null values - no Wazuh equivalent
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..config import Settings
from ..errors import UnsupportedFeatureError
from ..models import (
    AttackReference,
    ConversionOutcome,
    LogSource,
)
from ..utils.identifiers import allocate_rule_id, slugify
from .base import Converter, ConverterContext
from .condition_parser import BoolNode, Clause, ClauseKind, Node, NotNode
from .field_mapping import UNKNOWN_FIELD_MESSAGE, LogSourceMapping, MappingRegistry
from .sigma_loader import LoadedRule

__all__ = ["WazuhConverter", "WazuhRuleBuilder", "RULE_GROUP_MAP", "build_rule_xml"]


#: Mapping from SentinelForge platform/group to Wazuh rule <group> values.
RULE_GROUP_MAP: dict[str, str] = {
    "linux": "syslog,authentication",
    "windows": "windows,authentication",
    "common": "syslog",
    "sshd": "syslog,sshd,authentication",
    "auditd": "syslog,auditd,audit",
    "cron": "syslog,cron,persistence",
    "security": "windows,security,authentication",
    "system": "windows,system,persistence",
    "powershell": "windows,powershell,execution",
}


@dataclass
class WazuhRuleBuilder:
    """Assemble a single Wazuh custom rule XML element."""

    rule_id: int
    level: int
    description: str
    groups: list[str] = field(default_factory=list)
    decoded_as: str | None = None
    match_fields: list[tuple[str, str]] = field(default_factory=list)
    regex_fields: list[tuple[str, str]] = field(default_factory=list)
    pcre2: bool = True
    mitre: list[AttackReference] = field(default_factory=list)
    parent_rule_id: int | None = None
    if_sid: int | None = None
    if_group: str | None = None
    options: list[str] = field(default_factory=list)

    def to_xml(self) -> ET.Element:
        """Return the rule as an :class:`xml.etree.ElementTree.Element`."""

        rule = ET.Element("rule")
        rule.set("id", str(self.rule_id))
        rule.set("level", str(self.level))

        if self.groups:
            group_elem = ET.SubElement(rule, "group")
            group_elem.text = ",".join(self.groups)

        if self.decoded_as:
            decoded = ET.SubElement(rule, "decoded_as")
            decoded.text = self.decoded_as

        if self.parent_rule_id:
            rule.set("parent_rule_id", str(self.parent_rule_id))

        if self.if_sid:
            if_sid = ET.SubElement(rule, "if_sid")
            if_sid.text = str(self.if_sid)

        if self.if_group:
            if_group = ET.SubElement(rule, "if_group")
            if_group.text = self.if_group

        for field_name, pattern in self.match_fields:
            field_elem = ET.SubElement(rule, "field")
            field_elem.set("name", field_name)
            field_elem.text = pattern

        for field_name, pattern in self.regex_fields:
            field_elem = ET.SubElement(rule, "field")
            field_elem.set("name", field_name)
            field_elem.set("type", "pcre2" if self.pcre2 else "regex")
            field_elem.text = pattern

        for opt in self.options:
            option_elem = ET.SubElement(rule, "option")
            option_elem.text = opt

        desc = ET.SubElement(rule, "description")
        desc.text = self.description

        for ref in self.mitre:
            mitre_elem = ET.SubElement(rule, "mitre")
            mitre_elem.set("id", ref.id)
            if ref.tactic:
                mitre_elem.set("tactic", ref.tactic)
            if ref.technique:
                mitre_elem.set("technique", ref.technique)

        return rule


class WazuhConverter(Converter):
    """Convert supported Sigma rules into Wazuh custom XML."""

    backend_name = "wazuh"

    def __init__(
        self,
        settings: Settings,
        mapping: MappingRegistry,
    ) -> None:
        self._settings = settings
        self._mapping = mapping
        self._used_ids: set[int] = set()

    def convert(self, context: ConverterContext) -> ConversionOutcome:
        rule = context.rule
        logsource = context.logsource

        mapping = self._mapping.for_logsource(logsource)
        if mapping is None:
            return ConversionOutcome(
                rule_path=rule.path,
                rule_id=rule.rule_id,
                title=rule.title,
                status="rejected",
                converted=False,
                feature=f"logsource.unsupported.{logsource.key}",
                limitation=(
                    f"No Wazuh decoder mapping for log source '{logsource.key}'. "
                    "Add a mapping in the SentinelForge configuration."
                ),
                message=f"Unsupported log source: {logsource.key}",
            )

        try:
            from .sigma_loader import SigmaLoader

            loader = SigmaLoader(self._mapping)
            loaded = loader.load(rule)
        except Exception as exc:
            return ConversionOutcome(
                rule_path=rule.path,
                rule_id=rule.rule_id,
                title=rule.title,
                status="rejected",
                converted=False,
                feature="sigma.load_failed",
                limitation=f"Rule could not be loaded by pySigma: {exc}",
                message=str(exc),
            )

        try:
            builder = self._build_wazuh_rule(loaded, mapping)
        except UnsupportedFeatureError as exc:
            return ConversionOutcome(
                rule_path=rule.path,
                rule_id=rule.rule_id,
                title=rule.title,
                status="rejected",
                converted=False,
                wazuh_rule_id=None,
                output_path=None,
                feature=exc.feature,
                limitation=exc.limitation,
                message=str(exc),
            )
        except Exception as exc:  # pragma: no cover - defensive
            return ConversionOutcome(
                rule_path=rule.path,
                rule_id=rule.rule_id,
                title=rule.title,
                status="rejected",
                converted=False,
                feature="conversion.error",
                limitation=f"Unexpected conversion error: {exc}",
                message=str(exc),
            )

        output_dir = context.output_directory
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{slugify(rule.title)}-{rule.rule_id[:8]}.xml"
        output_path = output_dir / filename

        xml_root = ET.Element("group")
        xml_root.set("name", f"sentinelforge,{slugify(rule.title)}")
        xml_root.append(builder.to_xml())

        ET.indent(xml_root, space="  ")
        xml_text = ET.tostring(xml_root, encoding="unicode", xml_declaration=True)

        from ..utils.filesystem import write_text

        write_text(output_path, xml_text)

        self._used_ids.add(builder.rule_id)

        return ConversionOutcome(
            rule_path=rule.path,
            rule_id=rule.rule_id,
            title=rule.title,
            status="converted",
            converted=True,
            wazuh_rule_id=builder.rule_id,
            output_path=str(output_path),
            message="Successfully converted to Wazuh custom rule",
        )

    def _build_wazuh_rule(self, loaded: LoadedRule, mapping: LogSourceMapping) -> WazuhRuleBuilder:
        rule = loaded.rule
        ir = loaded.ir
        logsource = loaded.logsource

        wazuh_rule_id = allocate_rule_id(
            rule.rule_id,
            base=self._settings.wazuh.rule_id_base,
            span=self._settings.wazuh.rule_id_span,
            taken=self._used_ids,
        )

        level = self._settings.wazuh.level_for(rule.level)

        groups = list(mapping.groups)
        if rule.platform:
            platform_group = RULE_GROUP_MAP.get(rule.platform.value)
            if platform_group and platform_group not in groups:
                groups.append(platform_group)

        decoded_as = mapping.decoders[0] if mapping.decoders else None

        mitre_refs = list(rule.attack)

        builder = WazuhRuleBuilder(
            rule_id=wazuh_rule_id,
            level=level,
            description=rule.title,
            groups=groups,
            decoded_as=decoded_as,
            mitre=mitre_refs,
        )

        self._compile_ir(ir, builder, logsource, mapping)

        return builder

    def _compile_ir(
        self,
        node: Node,
        builder: WazuhRuleBuilder,
        logsource: LogSource,
        mapping: LogSourceMapping,
    ) -> None:
        if isinstance(node, Clause):
            self._compile_clause(node, builder, logsource, mapping)
        elif isinstance(node, BoolNode):
            self._compile_bool_node(node, builder, logsource, mapping)
        elif isinstance(node, NotNode):
            self._compile_not_node(node, builder, logsource, mapping)
        else:  # pragma: no cover - defensive
            raise ValueError(f"Unknown IR node type: {type(node)}")

    def _compile_clause(
        self,
        clause: Clause,
        builder: WazuhRuleBuilder,
        logsource: LogSource,
        mapping: LogSourceMapping,
    ) -> None:
        if clause.kind is ClauseKind.KEYWORD:
            pattern = self._escape_regex(clause.value or "")
            builder.regex_fields.append(("message", pattern))
            return

        if clause.kind is ClauseKind.EXISTS:
            field_name = clause.field
            if not field_name:
                raise UnsupportedFeatureError(
                    "EXISTS clause without field",
                    rule_path=None,
                    rule_id=None,
                    feature="clause.exists_no_field",
                    limitation="Field existence checks require a field name.",
                )
            if clause.value == "true":
                builder.options.append("field_exists")
                builder.match_fields.append((field_name, ".+"))
            else:
                builder.options.append("field_missing")
            return

        field_name = clause.field
        if not field_name:
            raise UnsupportedFeatureError(
                f"Clause kind {clause.kind} requires a field",
                rule_path=None,
                rule_id=None,
                feature="clause.missing_field",
                limitation="Field-based matches require a Sigma field with a Wazuh mapping.",
            )

        field_pattern = self._build_field_pattern(clause, logsource, mapping)
        if field_pattern is None:
            raise UnsupportedFeatureError(
                UNKNOWN_FIELD_MESSAGE.format(field=field_name, logsource=logsource.key),
                rule_path=None,
                rule_id=None,
                feature=f"field_mapping.{logsource.key}.{field_name}",
                limitation="A field without a mapping would have to be matched as a plain keyword, "
                "which would match unrelated events and weaken the detection.",
            )

        if clause.kind in (ClauseKind.EQUALS, ClauseKind.CONTAINS, ClauseKind.STARTSWITH, ClauseKind.ENDSWITH):
            builder.match_fields.append((field_name, field_pattern))
        else:
            builder.regex_fields.append((field_name, field_pattern))

    def _compile_bool_node(
        self,
        node: BoolNode,
        builder: WazuhRuleBuilder,
        logsource: LogSource,
        mapping: LogSourceMapping,
    ) -> None:
        for child in node.children:
            self._compile_ir(child, builder, logsource, mapping)

    def _compile_not_node(
        self,
        node: NotNode,
        builder: WazuhRuleBuilder,
        logsource: LogSource,
        mapping: LogSourceMapping,
    ) -> None:
        if isinstance(node.child, Clause):
            child = node.child
            if child.kind is ClauseKind.EQUALS:
                child = Clause(
                    kind=ClauseKind.EQUALS,
                    field=child.field,
                    value=child.value,
                    case_sensitive=child.case_sensitive,
                    negated=not child.negated,
                )
                self._compile_clause(child, builder, logsource, mapping)
            elif child.kind is ClauseKind.EXISTS:
                child = Clause(
                    kind=ClauseKind.EXISTS,
                    field=child.field,
                    value="false" if child.value == "true" else "true",
                    negated=not child.negated,
                )
                self._compile_clause(child, builder, logsource, mapping)
            else:
                raise UnsupportedFeatureError(
                    f"Negation of {child.kind.value} is not supported",
                    rule_path=None,
                    rule_id=None,
                    feature=f"negation.{child.kind.value}",
                    limitation="Wazuh rules only support negation of exact matches and field existence.",
                )
        else:
            raise UnsupportedFeatureError(
                "Negation of complex boolean expressions is not supported",
                rule_path=None,
                rule_id=None,
                feature="negation.complex",
                limitation="Wazuh rules cannot express NOT over AND/OR combinations. "
                "Restructure the rule using De Morgan's laws if possible.",
            )

    def _build_field_pattern(
        self,
        clause: Clause,
        logsource: LogSource,
        mapping: LogSourceMapping,
    ) -> str | None:
        if clause.field is None:
            return None
        pattern = self._mapping.pattern(logsource, clause.field)
        if pattern is None:
            return None

        value = clause.value or ""
        escaped = self._escape_regex(value)

        if clause.kind is ClauseKind.EQUALS:
            return f"^{escaped}$"
        elif clause.kind is ClauseKind.CONTAINS:
            return escaped
        elif clause.kind is ClauseKind.STARTSWITH:
            return f"^{escaped}"
        elif clause.kind is ClauseKind.ENDSWITH:
            return f"{escaped}$"
        return escaped

    @staticmethod
    def _escape_regex(text: str) -> str:
        return re.escape(text)


def build_rule_xml(
    rule_id: int,
    level: int,
    description: str,
    groups: list[str],
    match_fields: list[tuple[str, str]],
    regex_fields: list[tuple[str, str]] | None = None,
    decoded_as: str | None = None,
    mitre: list[AttackReference] | None = None,
) -> str:
    """Convenience function to build a rule XML string (for tests)."""

    builder = WazuhRuleBuilder(
        rule_id=rule_id,
        level=level,
        description=description,
        groups=groups,
        decoded_as=decoded_as,
        match_fields=match_fields,
        regex_fields=regex_fields or [],
        mitre=mitre or [],
    )
    xml_root = ET.Element("group")
    xml_root.set("name", f"sentinelforge,{slugify(description)}")
    xml_root.append(builder.to_xml())
    ET.indent(xml_root, space="  ")
    return ET.tostring(xml_root, encoding="unicode", xml_declaration=True)
