"""Optional Wazuh logtest integration.

This module provides a thin wrapper around the ``wazuh-logtest`` binary for
end-to-end validation of generated rules against a real Wazuh manager.

The integration is entirely optional: if the binary is not available or the
Wazuh manager is not configured, the test is skipped and reported as
``NOT RUN`` rather than failing the build.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import Settings

__all__ = ["WazuhLogtestRunner", "run_wazuh_integration_tests"]


@dataclass
class LogtestResult:
    """Result of a single wazuh-logtest invocation."""

    rule_file: str
    log_text: str
    matched_rules: list[int]
    alerted: bool
    raw_output: str
    error: str | None = None


class WazuhLogtestRunner:
    """Execute ``wazuh-logtest`` against generated rules."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._binary = self._resolve_binary()

    def _resolve_binary(self) -> str | None:
        if self._settings.wazuh.logtest_binary:
            return self._settings.wazuh.logtest_binary
        candidates = (
            "wazuh-logtest",
            "/var/ossec/bin/wazuh-logtest",
            r"C:\Program Files (x86)\ossec-agent\wazuh-logtest.exe",
        )
        for candidate in candidates:
            if Path(candidate).exists() or self._which(candidate):
                return candidate
        return None

    @staticmethod
    def _which(cmd: str) -> bool:
        try:
            subprocess.run([cmd, "--version"], capture_output=True, check=False)
            return True
        except FileNotFoundError:
            return False

    def is_available(self) -> bool:
        return self._binary is not None

    def test_log(self, rule_file: Path, log_text: str) -> LogtestResult:
        """Run a single log through wazuh-logtest with *rule_file*."""

        if not self.is_available():
            return LogtestResult(
                rule_file=str(rule_file),
                log_text=log_text,
                matched_rules=[],
                alerted=False,
                raw_output="",
                error="wazuh-logtest not available",
            )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as tf:
            tf.write(log_text)
            log_path = tf.name

        try:
            cmd = [self._binary, "-c", str(rule_file), log_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            raw = result.stdout + result.stderr
            matched_rules = self._parse_matched_rules(raw)
            alerted = len(matched_rules) > 0
            return LogtestResult(
                rule_file=str(rule_file),
                log_text=log_text,
                matched_rules=matched_rules,
                alerted=alerted,
                raw_output=raw,
            )
        except subprocess.TimeoutExpired:
            return LogtestResult(
                rule_file=str(rule_file),
                log_text=log_text,
                matched_rules=[],
                alerted=False,
                raw_output="",
                error="wazuh-logtest timeout",
            )
        except Exception as exc:
            return LogtestResult(
                rule_file=str(rule_file),
                log_text=log_text,
                matched_rules=[],
                alerted=False,
                raw_output="",
                error=str(exc),
            )
        finally:
            Path(log_path).unlink(missing_ok=True)

    def _parse_matched_rules(self, output: str) -> list[int]:
        rules: list[int] = []
        for line in output.splitlines():
            line = line.strip()
            if "Rule:" in line and "level" in line.lower():
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        rules.append(int(part))
                        break
        return rules


def run_wazuh_integration_tests(
    settings: Settings,
    generated_rules: list[Path],
    fixtures: list[dict[str, Any]],
) -> tuple[str, str | None]:
    """Run Wazuh integration tests and return status and detail."""

    runner = WazuhLogtestRunner(settings)
    if not runner.is_available():
        return "NOT RUN", "wazuh-logtest binary not found. Set SENTINELFORGE_WAZUH_LOGTEST or install Wazuh."

    if not generated_rules:
        return "NOT RUN", "No generated rules to test."

    results: list[LogtestResult] = []
    for rule_file in generated_rules:
        for fixture in fixtures:
            if fixture.get("rule_file") == str(rule_file) or fixture.get("rule_id") in str(rule_file):
                result = runner.test_log(rule_file, fixture["log_text"])
                results.append(result)

    if not results:
        return "NOT RUN", "No matching fixtures for generated rules."

    passed = sum(1 for r in results if r.alerted == fixture_expects_alert(r, fixtures))
    total = len(results)

    detail = f"{passed}/{total} integration tests passed"
    status = "PASS" if passed == total else "FAIL"
    return status, detail


def fixture_expects_alert(result: LogtestResult, fixtures: list[dict[str, Any]]) -> bool:
    for fixture in fixtures:
        if fixture["log_text"] == result.log_text:
            return fixture.get("expectation") == "match"
    return False
