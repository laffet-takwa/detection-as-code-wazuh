"""Testing layer: synthetic fixtures, match engine, optional Wazuh integration."""

from __future__ import annotations

from .coverage import CoverageAnalyzer, compute_coverage
from .fixture_runner import FixtureCase, FixtureMatcher, load_fixtures, run_fixture_tests
from .wazuh_logtest import WazuhLogtestRunner, run_wazuh_integration_tests

__all__ = [
    "FixtureCase",
    "FixtureMatcher",
    "load_fixtures",
    "run_fixture_tests",
    "WazuhLogtestRunner",
    "run_wazuh_integration_tests",
    "CoverageAnalyzer",
    "compute_coverage",
]
