"""Coverage metrics over the detection catalogue."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import CoverageReport, DetectionRule, TestReport, ValidationReport

__all__ = ["CoverageAnalyzer", "compute_coverage"]


@dataclass
class CoverageAnalyzer:
    """Analyse detection coverage from validation, conversion and test reports."""

    validation: ValidationReport | None = None
    conversion_rules: list[DetectionRule] = field(default_factory=list)
    test_report: TestReport | None = None

    def analyze(self) -> CoverageReport:
        rules_total = len(self.conversion_rules)
        rules_with_positive = 0
        rules_with_negative = 0
        rules_covered = 0
        techniques: dict[str, list[str]] = {}
        platform_counts: dict[str, int] = {}
        uncovered_rules: list[str] = []

        positive_rules: set[str] = set()
        negative_rules: set[str] = set()

        if self.test_report:
            for result in self.test_report.results:
                if result.expectation == "match" and result.passed:
                    positive_rules.add(result.rule_path)
                elif result.expectation == "no-match" and result.passed:
                    negative_rules.add(result.rule_path)

        for rule in self.conversion_rules:
            platform = rule.platform.value if rule.platform else "unknown"
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

            for attack in rule.attack:
                techniques.setdefault(attack.id, []).append(rule.rule_id)

            has_positive = rule.path in positive_rules
            has_negative = rule.path in negative_rules

            if has_positive:
                rules_with_positive += 1
            if has_negative:
                rules_with_negative += 1
            if has_positive or has_negative:
                rules_covered += 1
            else:
                uncovered_rules.append(rule.path)

        return CoverageReport(
            rules_total=rules_total,
            rules_with_positive_fixture=rules_with_positive,
            rules_with_negative_fixture=rules_with_negative,
            rules_covered=rules_covered,
            rules_converted=rules_total,
            rules_rejected=0,
            techniques=techniques,
            platform_counts=platform_counts,
            uncovered_rules=uncovered_rules,
        )


def compute_coverage(
    validation: ValidationReport | None,
    rules: list[DetectionRule],
    test_report: TestReport | None,
) -> CoverageReport:
    analyzer = CoverageAnalyzer(
        validation=validation,
        conversion_rules=rules,
        test_report=test_report,
    )
    return analyzer.analyze()
