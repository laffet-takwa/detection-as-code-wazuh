"""Offline fixture runner and match engine.

This module executes synthetic log fixtures against the compiled IR of a rule.
It provides the primary CI testing path that does not require a Wazuh instance.

The matcher implements exactly the supported Sigma subset documented in
:mod:`sentinelforge.conversion.condition_parser`.  It does not claim to be a
complete Sigma runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..conversion.condition_parser import BoolNode, Clause, ClauseKind, Node, NotNode
from ..models import DetectionRule, FixtureResult, LogSource, TestReport
from ..utils.filesystem import iter_files, read_text

__all__ = [
    "FixtureCase",
    "FixtureMatcher",
    "run_fixture_tests",
    "load_fixtures",
]


@dataclass(frozen=True)
class FixtureCase:
    """A single synthetic log event with its expected match outcome."""

    name: str
    rule_path: str
    rule_id: str
    log_text: str
    expectation: str  # "match" or "no-match"
    description: str = ""


def load_fixtures(fixtures_dir: Path) -> list[FixtureCase]:
    """Load all fixture cases from *fixtures_dir*.

    Expected layout:
        fixtures_dir/
            linux/
                rule-name/
                    positive-01.log
                    positive-02.log
                    negative-01.log
            windows/
                ...

    The expectation is inferred from the filename prefix: ``positive-`` means
    the event SHOULD match, ``negative-`` means it SHOULD NOT match.
    """

    cases: list[FixtureCase] = []
    for path in iter_files(fixtures_dir, (".log", ".txt", ".json")):
        relative = path.relative_to(fixtures_dir)
        parts = relative.parts
        if len(parts) < 2:
            continue
        platform = parts[0]
        rule_dir = parts[1]
        filename = path.name.lower()

        if filename.startswith("positive-"):
            expectation = "match"
        elif filename.startswith("negative-"):
            expectation = "no-match"
        else:
            continue

        # Extract rule info from directory name: "rule-title-uuid8"
        # Rule files don't have UUID suffix, so strip it for rule_path
        rule_title = rule_dir
        rule_id = ""
        rule_file_stem = rule_dir
        if "-" in rule_dir:
            # Try to extract UUID suffix (8 hex chars after last dash)
            parts = rule_dir.rsplit("-", 1)
            if len(parts[1]) == 8 and all(c in "0123456789abcdef" for c in parts[1]):
                rule_title = parts[0]
                rule_id = parts[1]
                rule_file_stem = parts[0]

        cases.append(
            FixtureCase(
                name=f"{platform}/{rule_dir}/{filename}",
                rule_path=f"rules/{platform}/{rule_file_stem}.yml",
                rule_id=rule_id,
                log_text=read_text(path),
                expectation=expectation,
                description=f"{platform} fixture for {rule_title}",
            )
        )
    return cases


class FixtureMatcher:
    """Match synthetic log events against a compiled rule IR."""

    def __init__(self, logsource: LogSource) -> None:
        self._logsource = logsource
        self._field_patterns = self._compile_field_patterns(logsource)

    def _compile_field_patterns(self, logsource: LogSource) -> dict[str, list[re.Pattern]]:
        patterns: dict[str, list[re.Pattern]] = {}
        # Use a simple fallback: match field=value or "field=value"
        # In practice the conversion layer uses the mapping registry
        return patterns

    def match(self, node: Node, log_text: str) -> bool:
        """Evaluate *node* against *log_text*."""

        if isinstance(node, Clause):
            return self._match_clause(node, log_text)
        elif isinstance(node, BoolNode):
            return self._match_bool(node, log_text)
        elif isinstance(node, NotNode):
            return not self.match(node.child, log_text)
        return False

    def _match_clause(self, clause: Clause, log_text: str) -> bool:
        if clause.kind is ClauseKind.KEYWORD:
            pattern = re.escape(clause.value or "")
            flags = 0 if clause.case_sensitive else re.IGNORECASE
            matched = bool(re.search(pattern, log_text, flags))
            return not matched if clause.negated else matched

        if clause.kind is ClauseKind.EXISTS:
            field_name = clause.field or ""
            # Check if field appears in log
            pattern = rf"{re.escape(field_name)}[=:]\s*\S+"
            matched = bool(re.search(pattern, log_text, re.IGNORECASE))
            expected = clause.value == "true"
            result = matched == expected
            return not result if clause.negated else result

        field_name = clause.field or ""
        value = clause.value or ""
        escaped = re.escape(value)
        flags = 0 if clause.case_sensitive else re.IGNORECASE

        if clause.kind is ClauseKind.EQUALS:
            pattern = rf"{re.escape(field_name)}[=:]\s*\"?{escaped}\"?(?:\s|$)"
        elif clause.kind is ClauseKind.CONTAINS:
            pattern = rf"{re.escape(field_name)}[=:]\s*\"?.*{escaped}.*\"?"
        elif clause.kind is ClauseKind.STARTSWITH:
            pattern = rf"{re.escape(field_name)}[=:]\s*\"?{escaped}"
        elif clause.kind is ClauseKind.ENDSWITH:
            pattern = rf"{re.escape(field_name)}[=:]\s*\"?.*{escaped}\"?(?:\s|$)"
        else:
            return False

        matched = bool(re.search(pattern, log_text, flags))
        return not matched if clause.negated else matched

    def _match_bool(self, node: BoolNode, log_text: str) -> bool:
        if node.operator == "and":
            return all(self.match(child, log_text) for child in node.children)
        elif node.operator == "or":
            return any(self.match(child, log_text) for child in node.children)
        return False


def run_fixture_tests(
    rules: list[DetectionRule],
    fixtures: list[FixtureCase],
    compiled_irs: dict[str, Node],
    log_sources: dict[str, LogSource],
    wazuh_integration: str = "NOT RUN",
    wazuh_detail: str | None = None,
) -> TestReport:
    """Run all fixture cases against their corresponding rules."""

    results: list[FixtureResult] = []
    passed = 0
    failed = 0
    not_evaluated = 0

    for fixture in fixtures:
        ir = compiled_irs.get(fixture.rule_path)
        logsource = log_sources.get(fixture.rule_path)

        if ir is None or logsource is None:
            results.append(
                FixtureResult(
                    fixture=fixture.name,
                    rule_path=fixture.rule_path,
                    rule_id=fixture.rule_id,
                    expectation=fixture.expectation,
                    structured="",
                    raw=fixture.log_text,
                    passed=False,
                    detail="No compiled IR or log source for rule",
                    events=0,
                )
            )
            not_evaluated += 1
            continue

        matcher = FixtureMatcher(logsource)
        matched = matcher.match(ir, fixture.log_text)

        expected_match = fixture.expectation == "match"
        passed_fixture = matched == expected_match

        if passed_fixture:
            passed += 1
        else:
            failed += 1

        results.append(
            FixtureResult(
                fixture=fixture.name,
                rule_path=fixture.rule_path,
                rule_id=fixture.rule_id,
                expectation=fixture.expectation,
                structured="matched" if matched else "no-match",
                raw=fixture.log_text,
                passed=passed_fixture,
                detail=(
                    None
                    if passed_fixture
                    else f"Expected {fixture.expectation}, got {'match' if matched else 'no-match'}"
                ),
                events=1,
            )
        )

    return TestReport(
        fixtures_discovered=len(fixtures),
        fixtures_passed=passed,
        fixtures_failed=failed,
        fixtures_not_evaluated=not_evaluated,
        results=results,
        wazuh_integration=wazuh_integration,
        wazuh_detail=wazuh_detail,
    )
