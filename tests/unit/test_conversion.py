"""Unit tests for conversion module."""

import pytest
from sentinelforge.conversion import (
    WazuhRuleBuilder,
    build_default_registry,
    build_rule_xml,
)
from sentinelforge.models import (
    AttackReference,
    LogSource,
)


class TestWazuhRuleBuilder:
    """Tests for WazuhRuleBuilder."""

    def test_basic_rule_xml(self):
        """Test basic rule XML generation."""
        builder = WazuhRuleBuilder(
            rule_id=100001,
            level=5,
            description="Test Rule",
            groups=["linux", "sshd"],
            match_fields=[("field1", "value1")],
        )
        xml_elem = builder.to_xml()
        assert xml_elem.get("id") == "100001"
        assert xml_elem.get("level") == "5"
        desc = xml_elem.find("description")
        assert desc is not None
        assert desc.text == "Test Rule"

    def test_rule_with_mitre(self):
        """Test rule with MITRE ATT&CK metadata."""
        mitre = [AttackReference(id="T1110", tactic="Credential Access", technique="Brute Force")]
        builder = WazuhRuleBuilder(
            rule_id=100001,
            level=5,
            description="Test Rule",
            groups=["linux"],
            mitre=mitre,
        )
        xml_elem = builder.to_xml()
        mitre_elem = xml_elem.find("mitre")
        assert mitre_elem is not None
        assert mitre_elem.get("id") == "T1110"
        assert mitre_elem.get("tactic") == "Credential Access"

    def test_build_rule_xml_function(self):
        """Test build_rule_xml convenience function."""
        xml_str = build_rule_xml(
            rule_id=100001,
            level=5,
            description="Test Rule",
            groups=["linux"],
            match_fields=[("field1", "value1")],
        )
        assert 'id="100001"' in xml_str
        assert 'level="5"' in xml_str
        assert "Test Rule" in xml_str


class TestFieldMapping:
    """Tests for field mapping registry."""

    def test_default_registry_has_sshd(self):
        """Test that default registry has sshd mapping."""
        registry = build_default_registry()
        mapping = registry.for_logsource(LogSource(product="linux", service="sshd"))
        assert mapping is not None
        assert mapping.key == "linux/sshd"

    def test_default_registry_has_auditd(self):
        """Test that default registry has auditd mapping."""
        registry = build_default_registry()
        mapping = registry.for_logsource(LogSource(product="linux", service="auditd"))
        assert mapping is not None
        assert mapping.key == "linux/auditd"

    def test_field_pattern_lookup(self):
        """Test field pattern lookup."""
        registry = build_default_registry()
        pattern = registry.pattern(LogSource(product="linux", service="sshd"), "SourceIP")
        assert pattern is not None
        assert pattern.field == "SourceIP"
        assert len(pattern.templates) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
