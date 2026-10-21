# SentinelForge Architecture

## Overview

SentinelForge is a Detection-as-Code engineering platform that transforms portable
Sigma detection rules into Wazuh custom rules, with comprehensive validation,
testing, and reporting capabilities.

## High-Level Architecture

```mermaid
graph TB
    subgraph Source["Source Rules"]
        RULES[("Sigma YAML Rules\nrules/{linux,windows,common}/")]
    end

    subgraph Validation["Validation Pipeline"]
        YAML_VAL["Stage A: YAML Validation"]
        SIGMA_VAL["Stage B: Sigma Semantic Validation\n(pySigma parser + best practices)"]
        META_VAL["Stage C: Metadata Validation\n(required fields, UUIDs, ATT&CK)"]
        REPO_VAL["Stage D: Repository Validation\n(duplicates, ordering)"]
    end

    subgraph Conversion["Conversion Engine"]
        LOADER["Sigma Loader\n(pySigma -> IR)"]
        COMPILER["Condition Compiler\n(Supported Subset Only)"]
        CONVERTER["Wazuh Converter\n(IR -> XML)"]
        MAPPING["Field Mapping Registry"]
    end

    subgraph Testing["Testing Framework"]
        FIXTURES[("Synthetic Fixtures\ntests/fixtures/")]
        MATCHER["Fixture Matcher\n(IR Evaluation)"]
        WAZUH_TEST["Wazuh Logtest Integration\n(Optional)"]
    end

    subgraph Reporting["Reporting"]
        JSON_REPORT["JSON Report"]
        MD_REPORT["Markdown Report"]
        COVERAGE["Coverage Analysis"]
    end

    RULES --> YAML_VAL
    YAML_VAL --> SIGMA_VAL
    SIGMA_VAL --> META_VAL
    META_VAL --> REPO_VAL

    REPO_VAL --> LOADER
    LOADER --> COMPILER
    COMPILER --> CONVERTER
    MAPPING --> CONVERTER
    CONVERTER --> WAZUH_RULES[("Generated Wazuh XML\nwazuh/rules/")]

    REPO_VAL --> MATCHER
    FIXTURES --> MATCHER
    COMPILER --> MATCHER
    MATCHER --> WAZUH_TEST
    WAZUH_TEST --> REPORTING
    MATCHER --> REPORTING
    CONVERTER --> REPORTING
    REPO_VAL --> REPORTING
</mermaid>

## Component Details

### Validation Pipeline (4 Stages)

1. **YAML Validation** - Safe parsing, single document, no duplicate keys
2. **Sigma Semantic Validation** - pySigma parser, condition parsing, best-practice validators
3. **Metadata Validation** - Required fields, UUID format, severity values, descriptions, log source completeness
4. **Repository Validation** - Deterministic traversal, duplicate UUID/title/name detection

### Conversion Engine

The conversion engine implements a **deliberately limited subset** of Sigma that
can be faithfully represented in Wazuh custom rules:

**Supported:**
- Field equality, contains, startswith, endswith (with explicit mappings)
- Keyword searches
- Field existence checks
- Boolean combinations (and/or/not)
- Selectors (1 of them, all of them, 1 of pattern)

**Unsupported (explicitly rejected):**
- Regular expressions (Python vs PCRE dialect differences)
- Numeric comparisons (lt, gt, etc.)
- Wildcards inside values
- Base64/CIDR/field references/value references
- Correlation rules (time windows, event counting)
- Null values

### Testing Framework

- **Offline mode** (default): Synthetic fixture evaluation against compiled IR
- **Wazuh integration mode**: Optional `wazuh-logtest` execution against generated rules

### Data Flow

```
Sigma YAML → YAML Validator → pySigma Parser → Condition Compiler → IR
                                                              ↓
                                                    Wazuh Converter → XML
                                                              ↓
                                                    Fixture Matcher → Test Results
                                                              ↓
                                                    Coverage Analyzer → Metrics
                                                              ↓
                                                    Report Renderer → JSON + Markdown
```

## Supported Sigma Subset

The converter only accepts Sigma constructs that have a **faithful semantic
equivalent** in Wazuh's rule language. This prevents silent weakening of
detections.

See [Sigma-to-Wazuh Conversion](sigma-to-wazuh.md) for the complete matrix.

## Extensibility Points

1. **Field Mapping Registry** - Add new log sources and field mappings via configuration
2. **Custom Validators** - Extend the validation pipeline with domain-specific checks
3. **Additional Backends** - Implement the `Converter` interface for other SIEM targets