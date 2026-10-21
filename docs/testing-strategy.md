# Testing Strategy

## Overview

SentinelForge employs a multi-layered testing approach that validates detection
rules at different levels of fidelity, from static analysis to live SIEM
integration.

## Testing Layers

### Layer 1: Static Validation (CI Gate)
**Tool**: `sentinelforge validate` / `scripts/validate_rules.py`
**Runs on**: Every commit, PR

Checks:
- YAML well-formedness (safe parsing, single document, no duplicate keys)
- Sigma semantic validity (pySigma parser, condition parsing)
- Best-practice validators (pySigma's built-in suite)
- Metadata completeness (required fields, UUID format, severity, descriptions)
- MITRE ATT&CK tag syntax and registry lookup
- Repository-level uniqueness (UUID, title, name)
- File organization consistency (platform directory matches log source)

**Exit code**: Non-zero on any ERROR-level issue

### Layer 2: Unit Tests (CI Gate)
**Tool**: `pytest tests/unit/`
**Runs on**: Every commit, PR

Tests:
- Individual validator functions
- Condition compiler IR generation
- Field mapping lookups
- Rule ID allocation determinism
- XML generation validity
- Report rendering

### Layer 3: Conversion Tests (CI Gate)
**Tool**: `sentinelforge convert` / `scripts/convert_rules.py`
**Runs on**: Every commit, PR

Verifies:
- Supported rules convert to valid XML
- Unsupported rules are rejected with clear errors
- Generated XML is well-formed
- Rule IDs are stable across runs
- MITRE metadata preserved in output

### Layer 4: Synthetic Fixture Tests (CI Gate)
**Tool**: `sentinelforge test` / `scripts/run_tests.py`
**Runs on**: Every commit, PR

**Positive Fixtures**: Synthetic log events that SHOULD match the rule
- At least 1 per rule (target: 2+)
- Cover typical attack patterns
- Use realistic field values

**Negative Fixtures**: Synthetic log events that should NOT match
- At least 1 per rule (target: 1+)
- Cover common false positive scenarios
- Test boundary conditions (missing fields, similar values)

**Boundary Fixtures**: Edge cases
- Missing fields
- Empty strings
- Case sensitivity
- Special characters in values
- Malformed timestamps

**Execution**: Fixtures evaluated against compiled IR (offline, no Wazuh needed)

### Layer 5: Wazuh Integration Tests (Optional/Lab)
**Tool**: `sentinelforge test --wazuh` / `scripts/run_tests.py` with `--wazuh`
**Runs on**: Manual trigger, dedicated lab environment

Requires:
- Wazuh Manager installed and running
- `wazuh-logtest` binary available
- Proper decoder configuration

Validates:
- Generated rules load without errors in Wazuh
- Positive fixtures trigger alerts in real Wazuh
- Negative fixtures do not trigger alerts
- Rule IDs don't conflict with built-in rules

**Status reporting**: `NOT RUN` if Wazuh unavailable (never PASS by default)

### Layer 6: Atomic Red Team Simulation (Optional/Lab)
**Tool**: Manual execution in isolated lab
**Runs on**: Periodic validation, pre-release

Process:
1. Deploy detection rules to lab Wazuh
2. Execute Atomic Red Team test cases for mapped ATT&CK techniques
3. Verify alerts fire as expected
4. Document any gaps or false positives

**Safety**: Only in isolated lab environments, never production

## Fixture Design Principles

1. **Realistic but synthetic** - No real production logs, but structurally accurate
2. **Minimal** - Only fields relevant to the detection
3. **Deterministic** - Same input always produces same result
4. **Documented** - Each fixture has a clear purpose in its filename
5. **Version controlled** - Fixtures are committed alongside rules

## Fixture Naming Convention

```
tests/fixtures/{platform}/{rule-slug}/
  positive-01.log    # Should match
  positive-02.log    # Should match (variant)
  negative-01.log    # Should NOT match
  negative-02.log    # Should NOT match (variant)
  boundary-01.log    # Edge case
```

## Coverage Metrics

The coverage report tracks:
- Rules with ≥1 positive fixture
- Rules with ≥1 negative fixture
- Rules covered by any fixture
- MITRE ATT&CK technique coverage
- Platform distribution
- Uncovered rules (no fixtures)

**Target**: 100% of convertible rules have both positive and negative fixtures

## Test Data Management

- Fixtures are **committed to the repository** (not generated)
- No external downloads during tests
- No secrets or real credentials in fixtures
- Fixtures are small (< 1KB each)

## Continuous Integration

GitHub Actions workflow (`.github/workflows/detection-ci.yml`):
1. Lint (Ruff)
2. Type check (mypy)
3. Validate all rules
4. Convert to Wazuh
5. Run fixture tests
6. Generate reports
7. Upload artifacts

Integration tests run separately on manual dispatch.

## Local Development

```bash
# Full test cycle
make test

# Or step by step:
python scripts/validate_rules.py
python scripts/convert_rules.py
python scripts/run_tests.py
python scripts/generate_report.py

# View reports
cat reports/report.md
```