"""Utility helpers shared across the SentinelForge package."""

from __future__ import annotations

from .filesystem import (
    SIGMA_SUFFIXES,
    ensure_directory,
    file_sha256,
    iter_files,
    iter_sigma_files,
    read_text,
    relative_posix,
    write_text,
)
from .identifiers import (
    UUID_PATTERN,
    allocate_rule_id,
    is_valid_uuid,
    normalise_identifier,
    parse_uuid,
    slugify,
)

__all__ = [
    "SIGMA_SUFFIXES",
    "ensure_directory",
    "file_sha256",
    "iter_files",
    "iter_sigma_files",
    "read_text",
    "relative_posix",
    "write_text",
    "UUID_PATTERN",
    "allocate_rule_id",
    "is_valid_uuid",
    "normalise_identifier",
    "parse_uuid",
    "slugify",
]
