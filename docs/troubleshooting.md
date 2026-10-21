# Troubleshooting Guide

## Common Issues

### Validation Failures

#### "File contains multiple YAML documents"
**Cause**: Rule file contains `---` document separators or multiple root mappings.
**Fix**: Ensure each rule file contains exactly one YAML document (one root mapping).

#### "Top level YAML structure must be a mapping"
**Cause**: File starts with a list (`- item`) instead of a mapping (`key: value`).
**Fix**: Rule files must be YAML mappings (dictionaries).

#### "Required field 'X' is missing"
**Cause**: Rule is missing one of the mandatory fields: title, id, status, description, author, date, logsource, detection, falsepositives, level.
**Fix**: Add the missing field with appropriate value.

#### "Field 'id' must be a canonical UUID"
**Cause**: ID is not a valid UUID v4 format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
**Fix**: Generate a new UUID: `uuidgen` or `python -c "import uuid; print(uuid.uuid4())"`.

#### "Field 'level' must be one of..."
**Cause**: Severity value not in: informational, low, medium, high, critical.
**Fix**: Use one of the valid severity values (lowercase).

#### "Rule does not reference a MITRE ATT&CK technique"
**Cause**: No `attack.tXXXX` tag in the rule's tags list.
**Fix**: Add at least one ATT&CK tag, e.g., `attack.t1110`.

#### "Technique TXXXX is not part of the curated technique registry"
**Cause**: ATT&CK technique ID is valid but not in SentinelForge's curated registry.
**Fix**: Either add the technique to `attack_validator.py` registry or verify the mapping is correct and use a registered technique.

#### "Rule declares product 'windows' but is stored in the 'linux' directory"
**Cause**: Rule's logsource product doesn't match its parent directory.
**Fix**: Move rule to correct directory (`rules/windows/`) or update logsource product.

#### "UUID X is already used by 'rules/.../other-rule.yml'"
**Cause**: Duplicate UUID across rules.
**Fix**: Generate a new unique UUID for one of the rules.

### Conversion Failures

#### "No Wazuh field mapping is defined for field 'X' in log source 'Y'"
**Cause**: Sigma field has no entry in the Field Mapping Registry.
**Fix**: 
1. Add mapping to `conversion/field_mapping.py` in `DEFAULT_MAPPINGS`
2. Or add override in configuration file under `mapping.overrides`

#### "The 're' modifier is not supported"
**Cause**: Rule uses regex modifier (`field|re: pattern`).
**Fix**: Rewrite using `contains`, `startswith`, `endswith` modifiers instead.

#### "Numeric comparison modifier is not supported"
**Cause**: Rule uses `lt`, `lte`, `gt`, `gte` modifiers.
**Fix**: Enrich logs at ingestion to add categorical fields, or implement correlation in a separate engine.

#### "Wildcards inside the value are not supported"
**Cause**: Rule value contains `*` (e.g., `user*admin`).
**Fix**: Use `contains` modifier: `field|contains: "admin"`.

#### "Negation of complex boolean expressions is not supported"
**Cause**: Rule uses `not (a and b)` or similar complex negation.
**Fix**: Restructure using De Morgan's laws: `not a or not b`, or split into multiple rules.

#### "Correlation rules are not supported"
**Cause**: Rule uses `correlation` block or requires multi-event time-window counting.
**Fix**: 
- For time-window correlation: Use Wazuh's correlation engine or a separate detection layer
- Mark rule as `kind: correlation` and `status: unsupported` for documentation

### Test Failures

#### "Expected match, got no-match" / "Expected no-match, got match"
**Cause**: Fixture doesn't match the rule's detection logic.
**Fix**: 
1. Check fixture log format matches the expected log source
2. Verify field names and values in fixture
3. Check if field mapping matches the log format
4. Review rule condition logic

#### "No compiled IR or log source for rule"
**Cause**: Rule failed to compile to IR (unsupported construct) but fixtures exist.
**Fix**: Either fix the rule to use supported constructs, or remove fixtures for unsupported rules.

#### "wazuh-logtest binary not found"
**Cause**: Wazuh not installed or binary not in PATH.
**Fix**: 
1. Install Wazuh Manager/Agent
2. Set `SENTINELFORGE_WAZUH_LOGTEST` environment variable
3. Or run without `--wazuh` flag for offline testing only

### XML Validation Errors

#### "Generated XML is not well-formed"
**Cause**: Converter produced invalid XML (should not happen with ElementTree).
**Fix**: Check for special characters in rule title/description that need escaping.

#### "Duplicate rule ID in Wazuh"
**Cause**: Two rules allocated the same Wazuh rule ID (collision).
**Fix**: The allocator should prevent this. Check if `rule_id_span` is too small.

### Performance Issues

#### "Validation takes too long"
**Cause**: Large rule set or complex rules.
**Fix**: 
- Enable parallel validation (not yet implemented)
- Profile with `python -m cProfile scripts/validate_rules.py`

#### "Conversion produces many rejections"
**Cause**: Rules use many unsupported constructs.
**Fix**: 
- Review rejected rules' limitations
- Consider rewriting rules using supported subset
- Document why certain rules cannot be converted

## Debugging Tips

### Enable Debug Logging
```bash
SENTINELFORGE_LOG_LEVEL=DEBUG sentinelforge validate
```

### Inspect Compiled IR
```python
from sentinelforge.validation import RepositoryValidator
from sentinelforge.conversion import build_default_registry, SigmaLoader
from sentinelforge.config import load_settings

settings = load_settings()
validator = RepositoryValidator(settings)
result = validator.validate()

mapping = build_default_registry(settings.mapping_overrides)
loader = SigmaLoader(mapping)

for rule in result.rules:
    if rule.kind.value == "detection":
        loaded = loader.load(rule)
        print(f"Rule: {rule.title}")
        print(f"IR: {loaded.ir.describe()}")
        print()
```

### Test Single Fixture
```python
from sentinelforge.testing import FixtureMatcher
from sentinelforge.config import load_settings

settings = load_settings()
# ... load rule and compile IR ...

matcher = FixtureMatcher(logsource)
matched = matcher.match(ir, log_text)
print(f"Matched: {matched}")
```

### Validate Generated XML
```bash
# Check XML syntax
xmllint --noout wazuh/rules/*.xml

# Or with Python
python -c "import xml.etree.ElementTree as ET; [ET.parse(f) for f in __import__('glob').glob('wazuh/rules/*.xml')]"
```

### Test with wazuh-logtest Manually
```bash
/var/ossec/bin/wazuh-logtest -c wazuh/rules/ssh-authentication-failure-a1b2c3d4.xml
# Paste test log:
# type=authentication_failure srcip=192.168.1.100 user=root from=192.168.1.100 port=22
```

## Configuration Issues

### Settings Not Loading
**Cause**: Config file not found or invalid YAML.
**Fix**: 
1. Check `SENTINELFORGE_CONFIG` environment variable
2. Verify config file exists and is valid YAML
3. Use `--config` CLI argument explicitly

### Path Resolution Errors
**Cause**: Relative paths resolved incorrectly.
**Fix**: Use absolute paths in config, or set `SENTINELFORGE_ROOT`.

### Rule ID Range Exhausted
**Cause**: Too many rules for the configured `rule_id_span`.
**Fix**: Increase `rule_id_span` in config (max 100000).

## Getting Help

1. **Check logs** with `SENTINELFORGE_LOG_LEVEL=DEBUG`
2. **Run validation first** - most issues caught early
3. **Review conversion report** for rejected rules and limitations
4. **Check fixture format** against rule's log source
5. **Consult documentation**: 
   - `docs/architecture.md` - System overview
   - `docs/sigma-to-wazuh.md` - Supported/unsupported constructs
   - `docs/testing-strategy.md` - Testing methodology

## Reporting Bugs

When reporting issues, include:
1. Command that failed
2. Full error output (with debug logging if possible)
3. Relevant rule file(s)
4. Fixture file(s) if test-related
5. Python version and dependency versions (`pip freeze`)
6. OS and Wazuh version (if integration-related)