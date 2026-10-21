#!/usr/bin/env python
"""Generate JSON and Markdown reports from validation, conversion, and test results."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from datetime import UTC, datetime

from sentinelforge.config import load_settings
from sentinelforge.conversion import (
    ConverterContext,
    SigmaLoader,
    WazuhConverter,
    build_default_registry,
)
from sentinelforge.models import ConversionReport
from sentinelforge.reporting import write_all_reports
from sentinelforge.testing import (
    compute_coverage,
    load_fixtures,
    run_fixture_tests,
    run_wazuh_integration_tests,
)
from sentinelforge.validation import RepositoryValidator


def main() -> int:
    settings = load_settings()

    # Validation
    print("Running validation...")
    validator = RepositoryValidator(settings)
    validation_result = validator.validate()
    rules = validation_result.rules

    # Conversion
    print("Running conversion...")
    mapping = build_default_registry(settings.mapping_overrides)
    converter = WazuhConverter(settings, mapping)

    outcomes = []
    for rule in rules:
        if rule.kind.value != "detection":
            continue
        context = ConverterContext(
            rule=rule,
            logsource=rule.logsource,
            output_directory=settings.output_directory,
            mapping_overrides=settings.mapping_overrides,
        )
        outcome = converter.convert(context)
        outcomes.append(outcome)

    conversion_report = ConversionReport(
        backend="wazuh",
        outcomes=outcomes,
        output_directory=str(settings.output_directory),
        generated_at=datetime.now(UTC),
        tool_versions={"pysigma": "1.5.1", "sentinelforge": "0.1.0"},
    )

    # Testing
    print("Running tests...")
    fixtures = load_fixtures(settings.fixtures_directory)
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
        except Exception:
            pass

    test_report = run_fixture_tests(rules, fixtures, compiled_irs, log_sources)

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
        wazuh_status, wazuh_detail = "NOT RUN", "No generated rules found. Run 'convert' first."

    # Re-run fixture tests with wazuh integration status
    test_report = run_fixture_tests(
        rules, fixtures, compiled_irs, log_sources, wazuh_integration=wazuh_status, wazuh_detail=wazuh_detail
    )

    # Coverage
    print("Computing coverage...")
    coverage_report = compute_coverage(validation_result.report, rules, test_report)

    # Reports
    print("Generating reports...")
    json_path, md_path = write_all_reports(
        settings.reports_directory,
        validation=validation_result.report,
        conversion=conversion_report,
        test=test_report,
        coverage=coverage_report,
    )

    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
