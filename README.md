# SentinelForge

**Detection-as-Code Engineering Platform for Wazuh**

[![CI](https://github.com/example/sentinelforge/actions/workflows/detection-ci.yml/badge.svg)](https://github.com/example/sentinelforge/actions/workflows/detection-ci.yml)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

SentinelForge transforms portable **Sigma detection rules** into **Wazuh custom rules** with comprehensive validation, testing, and reporting. It enforces a disciplined detection engineering workflow suitable for production SOC environments.

## Features

- **Sigma-Native**: Store detections in portable Sigma YAML format
- **Multi-Stage Validation**: YAML → Sigma semantics → Metadata → Repository checks
- **MITRE ATT&CK Mapping**: Structured technique references with curated registry
- **Safe Conversion**: Only converts Sigma constructs with faithful Wazuh equivalents; rejects the rest explicitly
- **Synthetic Fixture Testing**: Positive/negative/boundary test cases without a SIEM
- **Wazuh Integration**: Optional `wazuh-logtest` validation in lab environments
- **Comprehensive Reporting**: JSON and Markdown reports with coverage metrics
- **CI/CD Ready**: GitHub Actions workflow with pinned dependencies
- **Deterministic**: Stable rule IDs, reproducible builds, no hidden state

## Quick Start

### Prerequisites

- Python 3.12+
- Wazuh Manager (optional, for integration testing)

### Installation

```bash
# Clone the repository
git clone https://github.com/example/sentinelforge.git
cd sentinelforge

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Basic Usage

```bash
# Validate all rules
sentinelforge validate

# Convert to Wazuh custom rules
sentinelforge convert --backend wazuh

# Run synthetic fixture tests
sentinelforge test --fixtures tests/fixtures

# Generate reports
sentinelforge report

# Compute coverage
sentinelforge coverage
```

Or use the scripts directly:
```bash
python scripts/validate_rules.py
python scripts/convert_rules.py
python scripts/run_tests.py
python scripts/generate_report.py
```

## Repository Structure

```
SentinelForge/
├── .github/workflows/     # CI/CD pipelines
├── rules/                 # Source Sigma rules
│   ├── linux/            # Linux detections
│   ├── windows/          # Windows detections
│   └── common/           # Cross-platform detections
├── src/sentinelforge/     # Core package
│   ├── validation/       # 4-stage validation pipeline
│   ├── conversion/       # Sigma → Wazuh converter
│   ├── testing/          # Fixture runner & Wazuh integration
│   └── reporting/        # JSON/Markdown reports
├── tests/
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   └── fixtures/         # Synthetic log fixtures
├── wazuh/rules/          # Generated Wazuh XML (artifacts)
├── reports/              # Generated reports (artifacts)
├── docs/                 # Documentation
├── examples/             # Example configuration
├── scripts/              # Standalone CLI scripts
└── schemas/              # JSON schemas
```

## Detection Rule Catalog

| Rule | Platform | ATT&CK | Conversion |
|------|----------|--------|------------|
| SSH Authentication Failure | Linux | T1110, T1110.001 | ✅ |
| Repeated SSH Auth Failures | Linux | T1110, T1110.001 | ❌ (correlation) |
| SSH Success After Failures | Linux | T1110, T1078 | ❌ (correlation) |
| Cron Persistence Modification | Linux | T1053.003 | ✅ |
| SSH Authorized Keys Modification | Linux | T1098.004 | ✅ |
| Sudoers Configuration Modification | Linux | T1548.003 | ✅ |
| Suspicious Download Activity | Linux | T1105 | ✅ |
| Suspicious PowerShell Execution | Windows | T1059.001 | ✅ |
| Encoded PowerShell Command | Windows | T1059.001, T1027 | ✅ |
| Local User Account Creation | Windows | T1136.001 | ✅ |
| User Added to Administrators | Windows | T1098, T1078 | ✅ |
| Scheduled Task Creation | Windows | T1053.005 | ✅ |
| Suspicious Service Installation | Windows | T1543.003 | ✅ |

**11/13 rules convertible** (2 correlation rules require separate engine)

## Supported Sigma Subset

The converter **only** accepts Sigma constructs with faithful Wazuh equivalents:

| Category | Supported |
|----------|-----------|
| Field equality/contains/startswith/endswith | ✅ |
| Keyword search (no field) | ✅ |
| Field existence (`exists`) | ✅ |
| Boolean logic (and/or/not) | ✅ |
| Selectors (1 of them, all of them) | ✅ |
| Modifiers: contains, startswith, endswith, cased, all, exists, neq | ✅ |
| Regular expressions (`re`) | ❌ |
| Numeric comparisons (lt/gt/lte/gte) | ❌ |
| Wildcards inside values (`*`) | ❌ |
| Correlation/time-window rules | ❌ |
| Null values | ❌ |

See [docs/sigma-to-wazuh.md](docs/sigma-to-wazuh.md) for the complete matrix.

## Configuration

Copy `examples/configuration.example.yaml` to `configuration.local.yaml` (gitignored) and adjust:

```yaml
rules:
  directory: "rules"

output:
  wazuh_rules_directory: "wazuh/rules"
  reports_directory: "reports"

testing:
  fixtures_directory: "tests/fixtures"
  strict: false

wazuh:
  rule_id_base: 100000
  rule_id_span: 90000
  logtest_binary: null  # Set for integration tests
```

Environment variables (higher precedence):
- `SENTINELFORGE_ROOT` - Project root
- `SENTINELFORGE_RULES_DIR` - Rules directory
- `SENTINELFORGE_OUTPUT_DIR` - Output directory
- `SENTINELFORGE_WAZUH_LOGTEST` - Path to wazuh-logtest
- `SENTINELFORGE_STRICT` - Treat warnings as errors

## Documentation

- [Architecture](docs/architecture.md) - System design and data flow
- [Detection Catalog](docs/detection-catalog.md) - All rules with metadata
- [Sigma-to-Wazuh Conversion](docs/sigma-to-wazuh.md) - Supported/unsupported matrix
- [Testing Strategy](docs/testing-strategy.md) - Multi-layered testing approach
- [MITRE ATT&CK Coverage](docs/mitre-coverage.md) - Technique mapping details
- [Threat Model](docs/threat-model.md) - Security analysis
- [Troubleshooting](docs/troubleshooting.md) - Common issues and fixes

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/detection-ci.yml`) runs on every push/PR:

1. **Lint** - Ruff (format + lint)
2. **Type Check** - mypy (strict mode)
3. **Validate** - All 4 validation stages
4. **Convert** - Sigma → Wazuh XML
5. **Test** - Synthetic fixture evaluation
6. **Report** - JSON + Markdown artifacts

Integration tests with real Wazuh run on manual dispatch only.

## Adding New Rules

1. Create Sigma YAML in `rules/{linux,windows,common}/`
2. Include all required metadata fields
3. Add ATT&CK tags (`attack.tXXXX`)
4. Create fixtures in `tests/fixtures/{platform}/{rule-slug}/`
   - `positive-01.log`, `positive-02.log` (should match)
   - `negative-01.log` (should not match)
5. Run validation: `sentinelforge validate`
6. Run conversion: `sentinelforge convert`
7. Run tests: `sentinelforge test`

## Limitations

- **No correlation engine**: Multi-event time-window rules are rejected
- **No regex conversion**: Python `re` ≠ PCRE semantics
- **No numeric comparisons**: Wazuh fields are string-only
- **Decoder dependency**: Field mappings assume standard Wazuh decoders
- **Single-event only**: Each Wazuh rule matches one log event

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add rules with fixtures and documentation
4. Run full test suite: `make test` (or `python scripts/validate_rules.py && python scripts/convert_rules.py && python scripts/run_tests.py`)
5. Submit PR with description of detection logic and ATT&CK mapping rationale

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Sigma](https://github.com/SigmaHQ/sigma) - Generic signature format
- [pySigma](https://github.com/SigmaHQ/pySigma) - Python Sigma library
- [Wazuh](https://wazuh.com/) - Open source SIEM/XDR
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary behavior framework