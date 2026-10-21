#!/usr/bin/env python
"""Run detection tests against synthetic fixtures."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sentinelforge.config import load_settings
from sentinelforge.conversion import SigmaLoader, build_default_registry
from sentinelforge.testing import load_fixtures, run_fixture_tests, run_wazuh_integration_tests
from sentinelforge.validation import RepositoryValidator


def main() -> int:
    settings = load_settings()
    validator = RepositoryValidator(settings)
    validation_result = validator.validate()
    rules = validation_result.rules

    # Load fixtures
    fixtures = load_fixtures(settings.fixtures_directory)
    print(f"Loaded {len(fixtures)} fixture cases")

    # Compile IRs
    mapping = build_default_registry(settings.mapping_overrides)
    loader = SigmaLoader(mapping)
    compiled_irs = {}
    log_sources = {}

    for rule in rules:
        if rule.kind.value != "detection":
            continue
        try:
            loaded = loader.load(rule)
            compiled_irs[rule.path] = loaded.ir
            log_sources[rule.path] = loaded.logsource
        except Exception as exc:
            print(f"Warning: Could not compile IR for {rule.path}: {exc}")

    # Run fixture tests
    test_report = run_fixture_tests(rules, fixtures, compiled_irs, log_sources)

    # Wazuh integration
    wazuh_status = "NOT RUN"
    wazuh_detail = None
    generated_rules = list(settings.output_directory.glob("*.xml"))
    if generated_rules:
        fixture_dicts = [
            {
                "rule_file": f.rule_path,
                "rule_id": f.rule_id,
                "log_text": f.log_text,
                "expectation": f.expectation,
            }
            for f in fixtures
        ]
        wazuh_status, wazuh_detail = run_wazuh_integration_tests(settings, generated_rules, fixture_dicts)
    else:
        wazuh_detail = "No generated rules found. Run 'convert' first."

    # Re-run fixture tests with wazuh integration status
    test_report = run_fixture_tests(
        rules, fixtures, compiled_irs, log_sources, wazuh_integration=wazuh_status, wazuh_detail=wazuh_detail
    )

    print(f"\nFixtures discovered: {test_report.fixtures_discovered}")
    print(f"Fixtures passed: {test_report.fixtures_passed}")
    print(f"Fixtures failed: {test_report.fixtures_failed}")
    print(f"Fixtures not evaluated: {test_report.fixtures_not_evaluated}")
    print(f"Wazuh integration: {test_report.wazuh_integration}")
    if test_report.wazuh_detail:
        print(f"Wazuh detail: {test_report.wazuh_detail}")

    for result in test_report.results:
        if not result.passed:
            print(f"FAIL: {result.fixture} - {result.detail}")

    return 0 if test_report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
