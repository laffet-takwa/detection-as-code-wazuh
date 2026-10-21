"""Centralised runtime configuration.

All filesystem locations, thresholds and Wazuh specific tunables are resolved in
this module so that no other part of the package has to guess a path or read an
environment variable.  Values can be overridden by (in order of increasing
precedence):

1. the built-in defaults,
2. a YAML configuration file (``SENTINELFORGE_CONFIG`` or ``--config``),
3. environment variables,
4. explicit CLI arguments.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import ConfigurationError
from .models import Severity

__all__ = [
    "Settings",
    "WazuhSettings",
    "load_settings",
    "discover_project_root",
    "WAZUH_LEVEL_MAP",
    "DEFAULT_RULE_ID_BASE",
    "DEFAULT_RULE_ID_SPAN",
]

#: Wazuh custom rules live in the 100000-199999 range.  SentinelForge allocates
#: identifiers from the lower bound of that range.
DEFAULT_RULE_ID_BASE = 100_000
DEFAULT_RULE_ID_SPAN = 90_000

#: Mapping of Sigma severities onto Wazuh alert levels.
WAZUH_LEVEL_MAP: dict[Severity, int] = {
    Severity.INFORMATIONAL: 3,
    Severity.LOW: 5,
    Severity.MEDIUM: 7,
    Severity.HIGH: 10,
    Severity.CRITICAL: 12,
}

_ROOT_MARKERS = ("pyproject.toml", "rules")


def discover_project_root(start: Path | None = None) -> Path:
    """Locate the SentinelForge repository root.

    The lookup order is: ``SENTINELFORGE_ROOT`` environment variable, the closest
    ancestor of *start* that contains both ``pyproject.toml`` and ``rules``, and
    finally the directory that contains this package when the project is used from
    a source checkout.
    """

    env_root = os.environ.get("SENTINELFORGE_ROOT")
    if env_root:
        root = Path(env_root).expanduser().resolve()
        if not root.is_dir():
            raise ConfigurationError(f"SENTINELFORGE_ROOT does not exist: {root}")
        return root

    origin = (start or Path.cwd()).resolve()
    for candidate in [origin, *origin.parents]:
        if all((candidate / marker).exists() for marker in _ROOT_MARKERS):
            return candidate

    package_root = Path(__file__).resolve().parents[2]
    if (package_root / "rules").is_dir():
        return package_root
    return origin


class WazuhSettings(BaseModel):
    """Wazuh specific configuration."""

    model_config = ConfigDict(frozen=True)

    rule_id_base: int = DEFAULT_RULE_ID_BASE
    rule_id_span: int = DEFAULT_RULE_ID_SPAN
    level_map: dict[str, int] = Field(
        default_factory=lambda: {severity.value: level for severity, level in WAZUH_LEVEL_MAP.items()}
    )
    logtest_binary: str | None = None
    rules_directory: str | None = None
    decoder_groups: list[str] = Field(default_factory=list)

    @field_validator("rule_id_base")
    @classmethod
    def _validate_base(cls, value: int) -> int:
        if not 100_000 <= value <= 199_999:
            raise ValueError("Wazuh custom rule identifiers must be within 100000-199999")
        return value

    @field_validator("rule_id_span")
    @classmethod
    def _validate_span(cls, value: int) -> int:
        if not 1 <= value <= 100_000:
            raise ValueError("rule_id_span must be between 1 and 100000")
        return value

    def level_for(self, severity: Severity) -> int:
        """Return the Wazuh alert level for a Sigma severity."""

        return self.level_map.get(severity.value, 7)


class Settings(BaseModel):
    """Runtime settings for a SentinelForge invocation."""

    model_config = ConfigDict(frozen=True)

    project_root: Path
    rules_directory: Path
    output_directory: Path
    reports_directory: Path
    fixtures_directory: Path
    schema_path: Path
    strict: bool = False
    wazuh: WazuhSettings = Field(default_factory=WazuhSettings)
    config_file: Path | None = None
    mapping_overrides: dict[str, Any] = Field(default_factory=dict)
    log_level: str = "INFO"

    @classmethod
    def build(
        cls,
        project_root: Path,
        *,
        config_file: Path | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> Settings:
        """Create settings for *project_root* applying *overrides*."""

        data: dict[str, Any] = {
            "project_root": project_root,
            "rules_directory": project_root / "rules",
            "output_directory": project_root / "wazuh" / "rules",
            "reports_directory": project_root / "reports",
            "fixtures_directory": project_root / "tests" / "fixtures",
            "schema_path": project_root / "schemas" / "detection-rule.schema.json",
            "config_file": config_file,
        }
        if config_file is not None:
            data.update(_read_config_file(config_file))
        if overrides:
            data.update(overrides)
        return cls(**data)

    def relative(self, path: Path) -> str:
        """Return *path* relative to the project root when possible."""

        try:
            return path.resolve().relative_to(self.project_root).as_posix()
        except ValueError:
            return path.as_posix()


def _read_config_file(config_file: Path) -> dict[str, Any]:
    """Read and flatten a YAML configuration file into settings overrides."""

    if not config_file.is_file():
        raise ConfigurationError(f"Configuration file not found: {config_file}")
    try:
        raw = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in configuration file {config_file}: {exc}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigurationError(f"Configuration file {config_file} must contain a mapping")

    overrides: dict[str, Any] = {}
    rules = raw.get("rules") or {}
    if isinstance(rules, dict):
        if "directory" in rules:
            overrides["rules_directory"] = _resolve(config_file, rules["directory"])
    output = raw.get("output") or {}
    if isinstance(output, dict):
        if "wazuh_rules_directory" in output:
            overrides["output_directory"] = _resolve(config_file, output["wazuh_rules_directory"])
        if "reports_directory" in output:
            overrides["reports_directory"] = _resolve(config_file, output["reports_directory"])
    testing = raw.get("testing") or {}
    if isinstance(testing, dict):
        if "fixtures_directory" in testing:
            overrides["fixtures_directory"] = _resolve(config_file, testing["fixtures_directory"])
        if "strict" in testing:
            overrides["strict"] = bool(testing["strict"])
    wazuh = raw.get("wazuh") or {}
    if isinstance(wazuh, dict):
        overrides["wazuh"] = wazuh
    mapping = raw.get("mapping") or {}
    if isinstance(mapping, dict):
        overrides["mapping_overrides"] = mapping.get("overrides", {})
    return overrides


def _resolve(base: Path, value: Any) -> Any:
    """Resolve a configuration value that may be a relative path."""

    if isinstance(value, str) and ("/" in value or "\\" in value):
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = (base.parent / candidate).resolve()
        return candidate
    return value


def load_settings(
    config_file: Path | None = None,
    *,
    project_root: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> Settings:
    """Build the effective settings for a run.

    Environment variables are applied on top of the configuration file so that CI
    jobs and lab operators can adjust behaviour without editing tracked files.
    """

    root = project_root or discover_project_root()
    env_config = os.environ.get("SENTINELFORGE_CONFIG")
    selected = config_file or (Path(env_config).expanduser() if env_config else None)
    if selected is not None and not selected.is_absolute():
        selected = (root / selected).resolve()

    effective_overrides: dict[str, Any] = dict(overrides or {})
    env_overrides = _environment_overrides(root)
    for key, value in env_overrides.items():
        if key == "wazuh":
            merged = dict(effective_overrides.get("wazuh", {}))
            merged.update(value)
            effective_overrides["wazuh"] = merged
        else:
            effective_overrides.setdefault(key, value)

    settings = Settings.build(root, config_file=selected, overrides=effective_overrides)
    return settings


def _environment_overrides(root: Path) -> dict[str, Any]:
    """Translate ``SENTINELFORGE_*`` environment variables into overrides."""

    overrides: dict[str, Any] = {}
    mapping = {
        "SENTINELFORGE_RULES_DIR": "rules_directory",
        "SENTINELFORGE_OUTPUT_DIR": "output_directory",
        "SENTINELFORGE_REPORTS_DIR": "reports_directory",
        "SENTINELFORGE_FIXTURES_DIR": "fixtures_directory",
    }
    for variable, key in mapping.items():
        value = os.environ.get(variable)
        if value:
            candidate = Path(value).expanduser()
            overrides[key] = candidate if candidate.is_absolute() else (root / candidate)
    strict = os.environ.get("SENTINELFORGE_STRICT")
    if strict:
        overrides["strict"] = strict.strip().lower() in {"1", "true", "yes", "on"}
    log_level = os.environ.get("SENTINELFORGE_LOG_LEVEL")
    if log_level:
        overrides["log_level"] = log_level.upper()

    wazuh: dict[str, Any] = {}
    logtest = os.environ.get("SENTINELFORGE_WAZUH_LOGTEST")
    if logtest:
        wazuh["logtest_binary"] = logtest
    rules_dir = os.environ.get("SENTINELFORGE_WAZUH_RULES_DIR")
    if rules_dir:
        wazuh["rules_directory"] = rules_dir
    base = os.environ.get("SENTINELFORGE_RULE_ID_BASE")
    if base:
        try:
            wazuh["rule_id_base"] = int(base)
        except ValueError as exc:
            raise ConfigurationError("SENTINELFORGE_RULE_ID_BASE must be an integer") from exc
    if wazuh:
        overrides["wazuh"] = wazuh
    return overrides
