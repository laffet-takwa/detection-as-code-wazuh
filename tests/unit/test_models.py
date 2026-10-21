"""Unit tests for models module."""

from uuid import UUID

import pytest
from sentinelforge.models import (
    AttackReference,
    DetectionRule,
    FixtureResult,
    Issue,
    IssueSeverity,
    LogSource,
    Platform,
    RuleKind,
    RuleStatus,
    Severity,
    TestReport,
    ValidationReport,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_from_sigma_level(self):
        assert Severity.from_sigma_level("low") == Severity.LOW
        assert Severity.from_sigma_level("HIGH") == Severity.HIGH
        assert Severity.from_sigma_level(None) == Severity.MEDIUM
        assert Severity.from_sigma_level("informational") == Severity.INFORMATIONAL

    def test_invalid_level(self):
        with pytest.raises(ValueError):
            Severity.from_sigma_level("invalid")


class TestRuleStatus:
    """Tests for RuleStatus enum."""

    def test_values(self):
        assert RuleStatus.STABLE == "stable"
        assert RuleStatus.TEST == "test"
        assert RuleStatus.EXPERIMENTAL == "experimental"
        assert RuleStatus.DEPRECATED == "deprecated"
        assert RuleStatus.UNSUPPORTED == "unsupported"


class TestPlatform:
    """Tests for Platform enum."""

    def test_values(self):
        assert Platform.LINUX == "linux"
        assert Platform.WINDOWS == "windows"
        assert Platform.COMMON == "common"


class TestLogSource:
    """Tests for LogSource model."""

    def test_key_property(self):
        ls = LogSource(product="linux", service="sshd")
        assert ls.key == "linux/sshd"

    def test_key_with_category_only(self):
        ls = LogSource(category="authentication")
        assert ls.key == "/authentication"

    def test_platform_inference(self):
        ls = LogSource(product="linux", service="sshd")
        assert ls.platform == Platform.LINUX

        ls = LogSource(product="windows", service="security")
        assert ls.platform == Platform.WINDOWS

        ls = LogSource(category="authentication")
        assert ls.platform is None


class TestAttackReference:
    """Tests for AttackReference model."""

    def test_id_normalization(self):
        ref = AttackReference(id="t1110")
        assert ref.id == "T1110"

        ref = AttackReference(id="  T1110.001  ")
        assert ref.id == "T1110.001"


class TestDetectionRule:
    """Tests for DetectionRule model."""

    def test_creation(self):
        rule = DetectionRule(
            path="rules/linux/test.yml",
            title="Test Rule",
            id=UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            logsource=LogSource(product="linux", service="sshd"),
        )
        assert rule.rule_id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert rule.title == "Test Rule"

    def test_defaults(self):
        rule = DetectionRule(
            path="rules/linux/test.yml",
            title="Test Rule",
            id=UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            logsource=LogSource(product="linux", service="sshd"),
        )
        assert rule.level == Severity.MEDIUM
        assert rule.status == RuleStatus.EXPERIMENTAL
        assert rule.kind == RuleKind.DETECTION
        assert rule.falsepositives == []
        assert rule.references == []
        assert rule.tags == []
        assert rule.attack == []


class TestValidationReport:
    """Tests for ValidationReport model."""

    def test_passed_property(self):
        report = ValidationReport(rules_discovered=1, rules_valid=1, rules_invalid=0)
        assert report.passed

        report = ValidationReport(
            rules_discovered=1,
            rules_valid=0,
            rules_invalid=1,
            issues=[Issue(severity=IssueSeverity.ERROR, code="test", message="Error", rule_path="test.yml")]
        )
        assert not report.passed

    def test_errors_warnings_properties(self):
        issues = [
            Issue(severity=IssueSeverity.ERROR, code="err1", message="Error"),
            Issue(severity=IssueSeverity.WARNING, code="warn1", message="Warning"),
            Issue(severity=IssueSeverity.INFO, code="info1", message="Info"),
        ]
        report = ValidationReport(issues=issues)
        assert len(report.errors) == 1
        assert len(report.warnings) == 1


class TestFixtureResult:
    """Tests for FixtureResult model."""

    def test_creation(self):
        result = FixtureResult(
            fixture="test.log",
            rule_path="rules/linux/test.yml",
            rule_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            expectation="match",
            structured="matched",
            raw="log text",
            passed=True,
        )
        assert result.passed
        assert result.expectation == "match"


class TestTestReport:
    """Tests for TestReport model."""

    def test_passed_property(self):
        report = TestReport(fixtures_discovered=2, fixtures_passed=2, fixtures_failed=0)
        assert report.passed

        report = TestReport(fixtures_discovered=2, fixtures_passed=1, fixtures_failed=1)
        assert not report.passed

    def test_wazuh_integration_default(self):
        report = TestReport()
        assert report.wazuh_integration == "NOT RUN"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
