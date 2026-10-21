"""Unit tests for testing module."""

import tempfile
from pathlib import Path

import pytest
from sentinelforge.conversion.condition_parser import BoolNode, Clause, ClauseKind
from sentinelforge.models import LogSource
from sentinelforge.testing import FixtureMatcher, load_fixtures


class TestFixtureMatcher:
    """Tests for FixtureMatcher."""

    def test_keyword_match(self):
        """Test keyword matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause = Clause(kind=ClauseKind.KEYWORD, value="authentication_failure")
        assert matcher.match(clause, "type=authentication_failure")
        assert not matcher.match(clause, "type=authentication_success")

    def test_keyword_case_insensitive(self):
        """Test case-insensitive keyword matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause = Clause(kind=ClauseKind.KEYWORD, value="FAILURE", case_sensitive=False)
        assert matcher.match(clause, "type=authentication_failure")
        assert not matcher.match(clause, "type=authentication_success")

    def test_keyword_case_sensitive(self):
        """Test case-sensitive keyword matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause = Clause(kind=ClauseKind.KEYWORD, value="FAILURE", case_sensitive=True)
        assert not matcher.match(clause, "type=authentication_failure")
        assert matcher.match(clause, "type=authentication_FAILURE")

    def test_field_equals_match(self):
        """Test field equality matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause = Clause(kind=ClauseKind.EQUALS, field="type", value="authentication_failure")
        assert matcher.match(clause, "type=authentication_failure")
        assert not matcher.match(clause, "type=authentication_success")

    def test_field_contains_match(self):
        """Test field contains matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause = Clause(kind=ClauseKind.CONTAINS, field="type", value="auth")
        assert matcher.match(clause, "type=authentication_failure")
        assert not matcher.match(clause, "type=connection")

    def test_field_startswith_match(self):
        """Test field startswith matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause = Clause(kind=ClauseKind.STARTSWITH, field="type", value="auth")
        assert matcher.match(clause, "type=authentication_failure")
        assert not matcher.match(clause, "type=connection_auth")

    def test_field_endswith_match(self):
        """Test field endswith matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause = Clause(kind=ClauseKind.ENDSWITH, field="type", value="failure")
        assert matcher.match(clause, "type=authentication_failure")
        assert not matcher.match(clause, "type=failure_authentication")

    def test_field_exists_match(self):
        """Test field existence matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause = Clause(kind=ClauseKind.EXISTS, field="type", value="true")
        assert matcher.match(clause, "type=authentication_failure")
        assert not matcher.match(clause, "message=test")

        clause = Clause(kind=ClauseKind.EXISTS, field="type", value="false")
        assert matcher.match(clause, "message=test")
        assert not matcher.match(clause, "type=authentication_failure")

    def test_negated_match(self):
        """Test negated matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause = Clause(kind=ClauseKind.EQUALS, field="type", value="authentication_failure", negated=True)
        assert not matcher.match(clause, "type=authentication_failure")
        assert matcher.match(clause, "type=authentication_success")

    def test_bool_and(self):
        """Test boolean AND matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause1 = Clause(kind=ClauseKind.EQUALS, field="type", value="authentication_failure")
        clause2 = Clause(kind=ClauseKind.EQUALS, field="user", value="root")
        bool_node = BoolNode(operator="and", children=(clause1, clause2))

        assert matcher.match(bool_node, "type=authentication_failure user=root")
        assert not matcher.match(bool_node, "type=authentication_failure user=admin")
        assert not matcher.match(bool_node, "type=authentication_success user=root")

    def test_bool_or(self):
        """Test boolean OR matching."""
        logsource = LogSource(product="linux", service="sshd")
        matcher = FixtureMatcher(logsource)

        clause1 = Clause(kind=ClauseKind.EQUALS, field="type", value="authentication_failure")
        clause2 = Clause(kind=ClauseKind.EQUALS, field="type", value="authentication_success")
        bool_node = BoolNode(operator="or", children=(clause1, clause2))

        assert matcher.match(bool_node, "type=authentication_failure")
        assert matcher.match(bool_node, "type=authentication_success")
        assert not matcher.match(bool_node, "type=connection")


class TestLoadFixtures:
    """Tests for load_fixtures function."""

    def test_load_fixtures(self):
        """Test loading fixtures from directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            linux_dir = fixtures_dir / "linux"
            rule_dir = linux_dir / "test-rule-a1b2c3d4"
            rule_dir.mkdir(parents=True)

            (rule_dir / "positive-01.log").write_text("type=authentication_failure")
            (rule_dir / "negative-01.log").write_text("type=authentication_success")

            fixtures = load_fixtures(fixtures_dir)
            assert len(fixtures) == 2

            pos = [f for f in fixtures if f.expectation == "match"]
            neg = [f for f in fixtures if f.expectation == "no-match"]
            assert len(pos) == 1
            assert len(neg) == 1

    def test_fixture_rule_path(self):
        """Test fixture rule path construction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fixtures_dir = Path(tmpdir)
            linux_dir = fixtures_dir / "linux"
            rule_dir = linux_dir / "test-rule-a1b2c3d4"
            rule_dir.mkdir(parents=True)

            (rule_dir / "positive-01.log").write_text("test")

            fixtures = load_fixtures(fixtures_dir)
            assert fixtures[0].rule_path == "rules/linux/test-rule.yml"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
