"""Validation stages for the SentinelForge rule catalogue.

The stages are intentionally separated so that a failure can be attributed to a
concrete concern:

``yaml_validator``
    File level YAML well-formedness (safe parsing, single document, no duplicate
    keys, non-empty mapping).
``sigma_validator``
    Sigma semantics, implemented on top of pySigma's own parser and best practice
    validator suite.
``metadata_validator``
    SentinelForge metadata conventions (required fields, UUIDs, severities,
    descriptions, log source completeness, file organisation).
``attack_validator``
    MITRE ATT&CK technique identifier syntax and registry lookups.
``repository``
    Deterministic traversal and cross-file checks (duplicate identifiers).
"""

from __future__ import annotations

from .attack_validator import (
    ATTACK_TECHNIQUES,
    TechniqueInfo,
    extract_attack_tags,
    is_valid_technique_id,
    lookup_technique,
    technique_url,
    validate_attack_tags,
)
from .metadata_validator import MetadataResult, RuleMetadata, validate_metadata
from .repository import RepositoryValidator, ValidationResult
from .sigma_validator import (
    BEST_PRACTICE_VALIDATORS,
    ParsedRule,
    parse_rule_document,
    run_best_practice_validators,
    validate_sigma_semantics,
)
from .yaml_validator import YamlValidationResult, validate_yaml_file, validate_yaml_text

__all__ = [
    "ATTACK_TECHNIQUES",
    "TechniqueInfo",
    "extract_attack_tags",
    "is_valid_technique_id",
    "lookup_technique",
    "technique_url",
    "validate_attack_tags",
    "MetadataResult",
    "RuleMetadata",
    "validate_metadata",
    "RepositoryValidator",
    "ValidationResult",
    "BEST_PRACTICE_VALIDATORS",
    "ParsedRule",
    "parse_rule_document",
    "run_best_practice_validators",
    "validate_sigma_semantics",
    "YamlValidationResult",
    "validate_yaml_file",
    "validate_yaml_text",
]
