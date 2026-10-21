"""SentinelForge command-line interface."""

from __future__ import annotations

import logging
import sys
from datetime import UTC
from pathlib import Path
from typing import Any

import click

from . import __version__
from .config import Settings, load_settings
from .conversion import (
    ConverterContext,
    Node,
    WazuhConverter,
    build_default_registry,
)
from .logging_config import configure_logging, get_logger
from .models import LogSource
from .reporting import write_all_reports
from .testing import load_fixtures, run_fixture_tests, run_wazuh_integration_tests
from .validation import RepositoryValidator
from .validation.repository import ValidationResult

__all__ = ["main"]

logger = get_logger(__name__)


def _load_rules(settings: Settings) -> ValidationResult:
    """Load and validate all rules, returning the validation result."""
    validator = RepositoryValidator(settings)
    return validator.validate()


@click.group()
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=True, path_type=Path),
    help="Path to YAML configuration file.",
)
@click.option(
    "--rules-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Override the rules directory.",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    help="Override the output directory for generated rules.",
)
@click.option(
    "--reports-dir",
    type=click.Path(path_type=Path),
    help="Override the reports directory.",
)
@click.option(
    "--fixtures-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Override the fixtures directory.",
)
@click.option(
    "--strict/--no-strict",
    default=False,
    help="Treat warnings as errors.",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    help="Set the logging level.",
)
@click.version_option(__version__, prog_name="sentinelforge")
@click.pass_context
def cli(
    ctx: click.Context,
    config_file: Path | None,
    rules_dir: Path | None,
    output_dir: Path | None,
    reports_dir: Path | None,
    fixtures_dir: Path | None,
    strict: bool,
    log_level: str,
) -> None:
    """SentinelForge - Detection-as-Code Engineering Platform for Wazuh."""

    configure_logging(log_level)

    overrides: dict[str, Any] = {"strict": strict}
    if rules_dir:
        overrides["rules_directory"] = rules_dir
    if output_dir:
        overrides["output_directory"] = output_dir
    if reports_dir:
        overrides["reports_directory"] = reports_dir
    if fixtures_dir:
        overrides["fixtures_directory"] = fixtures_dir

    settings = load_settings(config_file=config_file, overrides=overrides)
    ctx.ensure_object(dict)
    ctx.obj["settings"] = settings


@cli.command()
@click.pass_context
def validate(ctx: click.Context) -> None:
    """Validate all Sigma rules in the repository."""

    settings: Settings = ctx.obj["settings"]
    logger.info("Starting validation", extra={"rules_dir": str(settings.rules_directory)})

    result = _load_rules(settings)

    for issue in result.report.issues:
        logger.log(
            logging.ERROR if issue.severity.value == "error" else logging.WARNING,
            issue.format(),
        )

    logger.info(
        "Validation complete",
        extra={
            "discovered": result.report.rules_discovered,
            "valid": result.report.rules_valid,
            "invalid": result.report.rules_invalid,
        },
    )

    if not result.report.passed:
        sys.exit(1)


@cli.command()
@click.option(
    "--backend",
    type=click.Choice(["wazuh"]),
    default="wazuh",
    help="Target backend for conversion.",
)
@click.pass_context
def convert(ctx: click.Context, backend: str) -> None:
    """Convert validated Sigma rules to the target backend format."""

    settings: Settings = ctx.obj["settings"]
    logger.info("Starting conversion", extra={"backend": backend})

    validation_result = _load_rules(settings)
    rules = validation_result.rules

    if not rules:
        logger.warning("No valid rules to convert")
        return

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

        if outcome.converted:
            logger.info(f"Converted: {outcome.title} -> {outcome.wazuh_rule_id}")
        else:
            logger.warning(f"Rejected: {outcome.title} - {outcome.message}")

    from datetime import datetime

    from .models import ConversionReport

    report = ConversionReport(
        backend=backend,
        outcomes=outcomes,
        output_directory=str(settings.output_directory),
        generated_at=datetime.now(UTC),
        tool_versions={"pysigma": "1.5.1", "sentinelforge": __version__},
    )

    logger.info(
        "Conversion complete",
        extra={
            "converted": len(report.converted),
            "rejected": len(report.rejected),
        },
    )

    if report.rejected and settings.strict:
        sys.exit(1)


@cli.command()
@click.option(
    "--fixtures",
    "fixtures_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Directory containing synthetic fixture logs.",
)
@click.option(
    "--wazuh/--no-wazuh",
    default=False,
    help="Run Wazuh logtest integration (requires wazuh-logtest).",
)
@click.pass_context
def test(ctx: click.Context, fixtures_dir: Path | None, wazuh: bool) -> None:
    """Run detection tests against synthetic fixtures and optionally Wazuh."""

    settings: Settings = ctx.obj["settings"]
    if fixtures_dir:
        settings = Settings.build(
            settings.project_root,
            config_file=settings.config_file,
            overrides={"fixtures_directory": fixtures_dir, "strict": settings.strict},
        )

    logger.info("Starting tests", extra={"fixtures_dir": str(settings.fixtures_directory)})

    validation_result = _load_rules(settings)
    rules = validation_result.rules

    # Load fixtures
    fixtures = load_fixtures(settings.fixtures_directory)
    logger.info(f"Loaded {len(fixtures)} fixture cases")

    # Compile IRs for all rules
    mapping = build_default_registry(settings.mapping_overrides)
    from .conversion import SigmaLoader

    loader = SigmaLoader(mapping)
    compiled_irs: dict[str, Node] = {}
    log_sources: dict[str, LogSource] = {}

    for rule in rules:
        if rule.kind.value != "detection":
            continue
        try:
            loaded = loader.load(rule)
            compiled_irs[rule.path] = loaded.ir
            log_sources[rule.path] = loaded.logsource
        except Exception as exc:
            logger.warning(f"Could not compile IR for {rule.path}: {exc}")

    # Run fixture tests
    test_report = run_fixture_tests(rules, fixtures, compiled_irs, log_sources)

    # Wazuh integration
    wazuh_status = "NOT RUN"
    wazuh_detail = None
    if wazuh:
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

    # Report
    logger.info(
        "Testing complete",
        extra={
            "passed": test_report.fixtures_passed,
            "failed": test_report.fixtures_failed,
            "not_evaluated": test_report.fixtures_not_evaluated,
            "wazuh": wazuh_status,
        },
    )

    for result in test_report.results:
        if not result.passed:
            logger.error(f"FAIL: {result.fixture} - {result.detail}")

    if not test_report.passed:
        sys.exit(1)


@cli.command()
@click.pass_context
def report(ctx: click.Context) -> None:
    """Generate JSON and Markdown reports from the last run."""

    settings: Settings = ctx.obj["settings"]
    logger.info("Generating reports", extra={"reports_dir": str(settings.reports_directory)})

    validation_result = _load_rules(settings)

    # We need to re-run conversion and testing to get fresh reports
    # In practice, the reports would be loaded from persisted artifacts
    # For now, generate a report with validation data only
    write_all_reports(
        settings.reports_directory,
        validation=validation_result.report,
    )

    logger.info("Reports written", extra={"dir": str(settings.reports_directory)})


@cli.command()
@click.pass_context
def coverage(ctx: click.Context) -> None:
    """Compute and display detection coverage metrics."""

    settings: Settings = ctx.obj["settings"]
    logger.info("Computing coverage")

    validation_result = _load_rules(settings)
    rules = validation_result.rules

    # Load fixtures to compute coverage
    fixtures = load_fixtures(settings.fixtures_directory)
    mapping = build_default_registry(settings.mapping_overrides)
    from .conversion import SigmaLoader

    loader = SigmaLoader(mapping)
    compiled_irs: dict[str, Node] = {}
    log_sources: dict[str, LogSource] = {}

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

    from .testing import compute_coverage

    coverage_report = compute_coverage(validation_result.report, rules, test_report)

    print(f"Total rules: {coverage_report.rules_total}")
    print(f"Rules with positive fixture: {coverage_report.rules_with_positive_fixture}")
    print(f"Rules with negative fixture: {coverage_report.rules_with_negative_fixture}")
    print(f"Rules covered: {coverage_report.rules_covered}")
    print(f"Platform distribution: {coverage_report.platform_counts}")
    print(f"ATT&CK techniques: {len(coverage_report.techniques)}")
    for tech_id, rule_ids in sorted(coverage_report.techniques.items()):
        print(f"  {tech_id}: {len(rule_ids)} rule(s)")
    if coverage_report.uncovered_rules:
        print(f"Uncovered rules ({len(coverage_report.uncovered_rules)}):")
        for rule_path in coverage_report.uncovered_rules:
            print(f"  {rule_path}")


def main() -> None:
    """Entry point for the sentinelforge CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
