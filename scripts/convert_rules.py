#!/usr/bin/env python
"""Convert validated Sigma rules to Wazuh custom rules."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sentinelforge.config import load_settings
from sentinelforge.conversion import ConverterContext, WazuhConverter, build_default_registry
from sentinelforge.validation import RepositoryValidator


def main() -> int:
    settings = load_settings()
    validator = RepositoryValidator(settings)
    validation_result = validator.validate()
    rules = validation_result.rules

    if not rules:
        print("No valid rules to convert")
        return 0

    mapping = build_default_registry(settings.mapping_overrides)
    converter = WazuhConverter(settings, mapping)

    converted_count = 0
    rejected_count = 0

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

        if outcome.converted:
            print(f"[OK] Converted: {outcome.title} -> {outcome.wazuh_rule_id} ({outcome.output_path})")
            converted_count += 1
        else:
            print(f"[FAIL] Rejected: {outcome.title} - {outcome.message}")
            if outcome.limitation:
                print(f"  Limitation: {outcome.limitation}")
            rejected_count += 1

    print(f"\nConverted: {converted_count}")
    print(f"Rejected: {rejected_count}")

    return 0 if rejected_count == 0 or not settings.strict else 1


if __name__ == "__main__":
    sys.exit(main())
