"""Identifier helpers: UUID validation and deterministic Wazuh rule ID allocation."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable
from uuid import UUID

__all__ = [
    "UUID_PATTERN",
    "parse_uuid",
    "is_valid_uuid",
    "allocate_rule_id",
    "slugify",
    "normalise_identifier",
]

#: Canonical textual representation of a UUID used by the Sigma specification.
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


def parse_uuid(value: str) -> UUID:
    """Parse *value* into a :class:`~uuid.UUID`, raising ``ValueError`` on failure."""

    return UUID(value.strip())


def is_valid_uuid(value: str) -> bool:
    """Return ``True`` when *value* is a syntactically valid UUID."""

    return bool(UUID_PATTERN.match(value.strip()))


def allocate_rule_id(
    rule_uuid: str | UUID,
    *,
    base: int,
    span: int,
    taken: Iterable[int] = (),
) -> int:
    """Deterministically allocate a Wazuh custom rule identifier.

    The identifier is derived from the SHA-256 digest of the rule UUID, which
    makes the allocation:

    * stable - re-running the converter never changes an identifier,
    * order independent - adding or removing rules does not renumber the rest,
    * collision checked - a candidate that is already in use is skipped in a
      deterministic, reproducible way.

    Parameters
    ----------
    rule_uuid:
        The UUID of the source rule.
    base:
        Lower bound of the Wazuh custom rule range.
    span:
        Size of the range; identifiers are allocated in ``[base, base + span)``.
    taken:
        Identifiers that are already in use.
    """

    if span < 1:
        raise ValueError("span must be positive")
    uuid_text = str(rule_uuid).strip().lower()
    digest = hashlib.sha256(uuid_text.encode("utf-8")).digest()
    offset = int.from_bytes(digest[:8], "big") % span
    used = set(taken)
    for step in range(span):
        candidate = base + ((offset + step) % span)
        if candidate not in used:
            return candidate
    raise ValueError("no free Wazuh rule identifier available in the configured range")


def slugify(value: str, *, max_length: int = 64) -> str:
    """Return a lowercase, hyphen separated slug for *value*."""

    normalised = unicodedata.normalize("NFKD", value)
    ascii_only = normalised.encode("ascii", "ignore").decode("ascii")
    slug = _SLUG_STRIP.sub("-", ascii_only.lower()).strip("-")
    if not slug:
        return "rule"
    if len(slug) > max_length:
        slug = slug[:max_length].rstrip("-")
    return slug


def normalise_identifier(value: str) -> str:
    """Normalise a Sigma ``name`` identifier to its canonical lowercase form."""

    return value.strip().lower().replace(" ", "_")
