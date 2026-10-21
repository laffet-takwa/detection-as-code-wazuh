#!/usr/bin/env python
"""Validate all Sigma rules in the repository."""

import sys
from pathlib import Path

# Add src to path for direct execution
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sentinelforge.config import load_settings
from sentinelforge.validation import RepositoryValidator


def main() -> int:
    settings = load_settings()
    validator = RepositoryValidator(settings)
    result = validator.validate()

    for issue in result.report.issues:
        print(issue.format())

    print(f"\nDiscovered: {result.report.rules_discovered}")
    print(f"Valid: {result.report.rules_valid}")
    print(f"Invalid: {result.report.rules_invalid}")

    return 0 if result.report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
