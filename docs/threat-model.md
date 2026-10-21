# Threat Model

## Scope

SentinelForge is a **detection engineering platform**, not a runtime security
product. This threat model covers the development-time tooling and the
generated detection rules when deployed to a Wazuh SIEM.

## Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| Source Sigma Rules | Detection logic intellectual property | Medium |
| Generated Wazuh Rules | Deployed detection logic | Medium |
| Test Fixtures | Synthetic attack patterns | Low |
| Configuration | Paths, mappings, thresholds | Low |
| Reports | Detection coverage, gaps | Medium |
| MITRE ATT&CK Registry | Curated technique metadata | Low |

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    Developer Workstation                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Source Rules│→ │ SentinelForge│→ │ Generated Rules    │  │
│  │ (Git)       │  │ Pipeline     │  │ (wazuh/rules/)     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      CI/CD Pipeline                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Validation  │→ │ Conversion  │→ │ Fixture Tests      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Wazuh Manager (Prod)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Custom Rules│  │ Decoders    │  │ Alerts/Events      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Threat Actors

| Actor | Motivation | Capability |
|-------|------------|------------|
| Malicious Contributor | Inject weak/broken rules | Write access to repo (PR) |
| Compromised CI | Modify pipeline output | Write access to artifacts |
| Supply Chain Attack | Malicious dependency | PyPI/npm package compromise |
| Insider (SOC) | Disable/detect evasion | Wazuh Manager access |
| External Attacker | Evade detection | Knowledge of deployed rules |

## Threat Scenarios

### 1. Rule Injection (Development Time)
**Threat**: Malicious contributor submits a rule that:
- Intentionally misses an attack pattern
- Generates excessive false positives (alert fatigue)
- Contains logic that crashes the converter

**Mitigations**:
- Required PR reviews by trusted maintainers
- Automated validation catches malformed rules
- Conversion rejects unsupported constructs
- Fixture tests verify detection behavior
- Code owners for `rules/` directory

### 2. Supply Chain Compromise
**Threat**: Compromised dependency (pySigma, pydantic, etc.) injects malicious code

**Mitigations**:
- Pinned dependency versions in `requirements.txt`
- `pip-audit` or `safety` in CI (recommended)
- Minimal dependency set
- Virtual environment isolation

### 3. Generated Rule Tampering (CI/CD)
**Threat**: Compromised CI runner modifies generated Wazuh rules before deployment

**Mitigations**:
- GitHub Actions permissions: `contents: read` only
- Artifact uploads are read-only after creation
- Signed commits for release tags
- Verify rule checksums before deployment

### 4. Detection Evasion (Runtime)
**Threat**: Attacker knows deployed rules and crafts evasive payloads

**Mitigations**:
- Rules target behavioral patterns, not specific IOCs
- Multiple rules per technique (defense in depth)
- Regular rule updates via threat intelligence
- Correlation rules for multi-stage detection
- Tuning based on false positive analysis

### 5. Alert Fatigue / Rule Suppression
**Threat**: High false positive rate leads to rules being disabled

**Mitigations**:
- `falsepositives` field documents known benign triggers
- Severity levels guide prioritization
- Coverage reporting identifies gaps
- Regular rule review process

### 6. Configuration Drift
**Threat**: Field mappings become outdated as Wazuh decoders change

**Mitigations**:
- Version-pinned Wazuh decoder compatibility notes
- Integration tests catch decoder mismatches
- Mapping overrides via configuration file
- Documented upgrade procedure

## Data Flow Threats

### Source Rule → Validation
- **Tampering**: Malformed YAML → caught by YAML validator
- **Logic bypass**: Sigma constructs outside supported subset → rejected by converter

### Validation → Conversion
- **Information loss**: Unsupported features → explicit rejection (not silent weakening)
- **ID collision**: Deterministic allocation with collision checking

### Conversion → Deployment
- **XML injection**: Values are escaped in XML builder
- **ID conflict**: Custom range (100000-199999) avoids built-in rules

### Deployment → Runtime
- **Decoder mismatch**: Field mapping registry documents decoder assumptions
- **Rule override**: Wazuh rule precedence documented

## Security Controls Summary

| Control | Implementation |
|---------|----------------|
| Code Review | Required PR reviews, CODEOWNERS |
| Dependency Pinning | `requirements.txt` with exact versions |
| Static Analysis | Ruff, mypy in CI |
| Validation Gates | 4-stage validation pipeline |
| Conversion Safety | Explicit rejection of unsupported features |
| Fixture Testing | Positive/negative/boundary cases per rule |
| Integration Testing | Optional Wazuh logtest in lab |
| Artifact Integrity | GitHub Actions least privilege |
| Documentation | Architecture, conversion matrix, limitations |

## Residual Risks

1. **Correlation gap**: Multi-event correlation rules cannot be converted to Wazuh custom rules. Requires separate correlation engine.
2. **Decoder dependency**: Field mappings assume specific Wazuh decoder versions. Upgrades may break mappings.
3. **Regex dialect**: Python `re` vs PCRE prevents safe regex conversion.
4. **Numeric comparison**: No support for port ranges, size thresholds, etc.
5. **Human review**: ATT&CK mapping correctness relies on manual review.

## Incident Response

If a deployed rule is found to be malicious or dangerously flawed:

1. **Immediate**: Disable rule in Wazuh (`rule_id` in `ignore_rules` or delete XML)
2. **Investigate**: Check git history for rule origin
3. **Remediate**: Revert commit, rotate credentials if CI compromised
4. **Verify**: Re-run full validation and conversion pipeline
5. **Deploy**: Push corrected rules

## Assumptions

1. Developers are trusted (insider threat mitigated by review process)
2. CI/CD infrastructure is not persistently compromised
3. Wazuh Manager is properly hardened and monitored
4. Dependencies are not maliciously modified post-pinning
5. Synthetic fixtures adequately represent real attack patterns