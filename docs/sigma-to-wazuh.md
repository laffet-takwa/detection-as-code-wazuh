# Sigma to Wazuh Conversion Support Matrix

This document details which Sigma constructs are supported by the SentinelForge
converter and which are explicitly rejected.

## Design Principle

> **Never silently weaken a detection.** If a Sigma construct cannot be
> faithfully represented in Wazuh's rule language, the converter raises an
> `UnsupportedFeatureError` with a clear explanation.

## Supported Constructs

### Detection Items

| Sigma Construct | Wazuh Equivalent | Notes |
|-----------------|------------------|-------|
| `field: value` | `<field name="field">value</field>` | Exact match (anchored) |
| `field\|contains: value` | `<field name="field">value</field>` | Substring match |
| `field\|startswith: value` | `<field name="field">value</field>` | Prefix match (anchored start) |
| `field\|endswith: value` | `<field name="field">value</field>` | Suffix match (anchored end) |
| `field\|cased: value` | `<field name="field">value</field>` | Case-sensitive match |
| `field\|all: [a, b]` | Multiple `<field>` elements | All values must match (AND) |
| `field\|exists: true` | `<option>field_exists</option>` + match | Field presence check |
| `field\|exists: false` | `<option>field_missing</option>` | Field absence check |
| `field\|neq: value` | Negated exact match | Not equal (via negation) |
| `keyword` (no field) | `<field name="message">keyword</field>` | Full-message keyword search |

### Modifiers

| Modifier | Supported | Wazuh Mapping |
|----------|-----------|---------------|
| `contains` | ✅ | Substring regex |
| `startswith` | ✅ | Prefix regex (`^value`) |
| `endswith` | ✅ | Suffix regex (`value$`) |
| `cased` | ✅ | Case-sensitive regex |
| `all` | ✅ | Multiple field elements (AND) |
| `exists` | ✅ | `field_exists`/`field_missing` options |
| `neq` | ✅ | Negated equality |
| `re` | ❌ | Python `re` ≠ PCRE - rejected |
| `lt`/`lte`/`gt`/`gte` | ❌ | No numeric comparison in Wazuh fields |
| `cidr` | ❌ | No CIDR matching in Wazuh fields |
| `base64` | ❌ | No base64 decode in Wazuh fields |
| `utf16` | ❌ | Encoding not preserved |
| `fieldref` | ❌ | Field-to-field comparison not supported |
| `valueref` | ❌ | Value-to-value comparison not supported |

### Conditions

| Sigma Condition | Supported | Wazuh Mapping |
|-----------------|-----------|---------------|
| `selection1 and selection2` | ✅ | Multiple `<field>` elements (implicit AND) |
| `selection1 or selection2` | ✅ | Multiple rules or `<option>alert_new_rule</option>` |
| `not selection` | ✅ | Negated field match (exact/EXISTS only) |
| `1 of them` | ✅ | Multiple rules with same group/parent |
| `all of them` | ✅ | Single rule with multiple fields (AND) |
| `1 of selection*` | ✅ | Multiple rules for each selection |
| `(a or b) and c` | ✅ | Nested boolean logic |
| Complex nesting | ⚠️ | Limited by Wazuh's flat rule structure |

### Values

| Value Type | Supported | Notes |
|------------|-----------|-------|
| Plain string | ✅ | Regex-escaped |
| Integer | ✅ | Converted to string |
| Boolean | ✅ | `true`/`false` strings |
| List of values | ✅ | OR-ed within field (or AND with `all`) |
| String with `*` wildcard | ❌ | Rejected - use `contains` instead |
| Null | ❌ | No null representation in Wazuh |

## Unsupported Constructs (Explicitly Rejected)

### 1. Regular Expressions (`re` modifier)
**Reason**: Sigma uses Python's `re` module; Wazuh uses PCRE. The dialects differ
in edge cases (lookbehinds, recursion, etc.), so a converted regex would have
different semantics.

**Workaround**: Rewrite using `contains`/`startswith`/`endswith` or use a
post-processing enrichment pipeline.

### 2. Numeric Comparisons (`lt`, `lte`, `gt`, `gte`)
**Reason**: Wazuh field matches are string/regex only. Numeric comparison would
require parsing the field as a number, which Wazuh decoders don't guarantee.

**Workaround**: Enrich logs at ingestion to add categorical fields (e.g.,
`port_category: "privileged"` for ports < 1024).

### 3. Wildcards Inside Values (`*`)
**Reason**: Sigma wildcards expand to arbitrary content. Translating `user*admin`
to a regex would match `userXadmin` but also `user_anything_admin`, changing
semantics.

**Workaround**: Use `contains` modifier for substring matching.

### 4. Correlation Rules (Time Windows, Event Counting)
**Reason**: Wazuh custom rules are single-event matching. Multi-event correlation
with time windows requires the Wazuh correlation engine or a separate detection
layer.

**Workaround**: Implement correlation in a dedicated SIEM rule engine (Wazuh
Correlation, Elastic Detection Engine, etc.) rather than custom rules.

### 5. Field References and Value References
**Reason**: Cross-field and cross-value comparisons have no equivalent in
Wazuh's flat rule structure.

### 6. Null Values
**Reason**: Wazuh cannot assert "field is absent" vs "field is empty string"
reliably without decoder changes.

## Field Mapping Requirement

Every Sigma field used in a converted rule **must** have an entry in the
Field Mapping Registry (`conversion/field_mapping.py`). This maps Sigma field
names to Wazuh decoded event locations.

Example mapping for `linux/sshd`:
```python
"SourceIP": FieldPattern(
    field="SourceIP",
    templates=[
        FieldTemplate(prefix=r"from\s+"),           # Raw: "from 10.0.0.1"
        FieldTemplate(prefix=r"srcip:\s*"),         # Decoded: "srcip: 10.0.0.1"
        FieldTemplate(prefix=r"src_ip="),           # JSON: "src_ip=10.0.0.1"
    ]
)
```

Without a mapping, the converter rejects the rule with:
```
UnsupportedFeatureError: No Wazuh field mapping for field 'SourceIP' in log source 'linux/sshd'
```

## Rule ID Allocation

- **Range**: 100000-199999 (Wazuh custom rule range)
- **Algorithm**: SHA-256(UUID) → deterministic offset within range
- **Properties**: Stable, order-independent, collision-checked

## MITRE ATT&CK Metadata

Converted rules include MITRE metadata when present in the source rule:
```xml
<mitre id="T1110" tactic="Credential Access" technique="Brute Force"/>
```

The tactic and technique are looked up from the curated technique registry.

## Testing Converted Rules

### Offline (Fixture Matcher)
```bash
sentinelforge test --fixtures tests/fixtures
```

### With Wazuh logtest
```bash
sentinelforge test --fixtures tests/fixtures --wazuh
# Requires SENTINELFORGE_WAZUH_LOGTEST or wazuh-logtest in PATH
```

### Manual logtest
```bash
/var/ossec/bin/wazuh-logtest -c wazuh/rules/ssh-authentication-failure-a1b2c3d4.xml
# Paste test log event
```

## Extending the Supported Subset

To add support for a new Sigma construct:

1. Add handling in `condition_parser.py` (IR compilation)
2. Add field mapping in `field_mapping.py` (if new field)
3. Add Wazuh XML generation in `wazuh_converter.py`
4. Add tests in `tests/test_conversion.py`
5. Update this document

**Do not** add support if the semantic equivalence cannot be guaranteed.