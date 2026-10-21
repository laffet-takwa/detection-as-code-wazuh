# MITRE ATT&CK Coverage

This document maps each detection rule to its MITRE ATT&CK technique(s) and
provides a coverage overview.

## Technique Registry

SentinelForge maintains a curated subset of MITRE ATT&CK Enterprise techniques
in `src/sentinelforge/validation/attack_validator.py`. This registry enables:

- Technique ID syntax validation
- Canonical technique name and tactic lookup
- Stable URL generation for official ATT&CK pages
- Coverage reporting

**Note**: Registry membership does not validate that a rule correctly detects
the technique behavior. That judgement is recorded in each rule's rationale
and reviewed by a human.

## Rule-to-Technique Mapping

| Rule | UUID | Technique(s) | Tactic(s) | Rationale |
|------|------|--------------|-----------|-----------|
| SSH Authentication Failure | a1b2c3d4... | T1110, T1110.001 | Credential Access | Direct observation of failed password guessing attempts |
| Repeated SSH Auth Failures | b2c3d4e5... | T1110, T1110.001 | Credential Access | Aggregated view of brute force pattern |
| SSH Success After Failures | c3d4e5f6... | T1110, T1110.001, T1078 | Credential Access, Defense Evasion | Successful credential use after guessing |
| Cron Persistence Modification | d4e5f6a7... | T1053, T1053.003 | Execution, Persistence | Cron job creation/modification for persistence |
| SSH Authorized Keys Modification | e5f6a7b8... | T1098, T1098.004 | Persistence, Privilege Escalation | Adding attacker keys for persistent access |
| Sudoers Configuration Modification | f6a7b8c9... | T1548, T1548.003 | Privilege Escalation | Modifying sudo to enable passwordless elevation |
| Suspicious Download Activity | a7b8c9d0... | T1105 | Command and Control | Downloading payloads/tools via CLI utilities |
| Suspicious PowerShell Execution | b8c9d0e1... | T1059, T1059.001 | Execution | Malicious PowerShell patterns (encoded, bypass, cradles) |
| Encoded PowerShell Command | c9d0e1f2... | T1059.001, T1027 | Execution, Defense Evasion | Base64-encoded command obfuscation |
| Local User Account Creation | d0e1f2a3... | T1136, T1136.001 | Persistence | Creating local accounts for persistent access |
| User Added to Administrators | e1f2a3b4... | T1098, T1078 | Persistence, Privilege Escalation, Defense Evasion | Adding compromised account to admin group |
| Scheduled Task Creation | f2a3b4c5... | T1053, T1053.005 | Execution, Persistence | Task Scheduler abuse for persistence/execution |
| Suspicious Service Installation | a3b4c5d6... | T1543, T1543.003 | Persistence | Windows service installation for persistence |

## Coverage Matrix

### By Tactic

| Tactic | Techniques Covered | Rules |
|--------|-------------------|-------|
| Credential Access | T1110, T1110.001 | 3 |
| Persistence | T1053.003, T1098.004, T1136.001, T1053.005, T1543.003 | 6 |
| Privilege Escalation | T1548.003, T1098.004, T1098 | 3 |
| Defense Evasion | T1027, T1078, T1098 | 3 |
| Execution | T1059.001, T1053, T1053.003, T1053.005 | 4 |
| Command and Control | T1105 | 1 |

### By Platform

| Platform | Techniques | Rules |
|----------|------------|-------|
| Linux | T1110, T1110.001, T1053.003, T1098.004, T1548.003, T1105, T1078 | 7 |
| Windows | T1059.001, T1027, T1136.001, T1098, T1078, T1053.005, T1543.003 | 6 |

### Technique Coverage Count

| Technique ID | Name | Rule Count |
|--------------|------|------------|
| T1110 | Brute Force | 3 |
| T1110.001 | Password Guessing | 3 |
| T1053.003 | Cron | 1 |
| T1098.004 | SSH Authorized Keys | 1 |
| T1548.003 | Sudo and Sudo Caching | 1 |
| T1105 | Ingress Tool Transfer | 1 |
| T1059.001 | PowerShell | 2 |
| T1027 | Obfuscated Files or Information | 1 |
| T1136.001 | Local Account | 1 |
| T1098 | Account Manipulation | 2 |
| T1078 | Valid Accounts | 3 |
| T1053.005 | Scheduled Task | 1 |
| T1543.003 | Windows Service | 1 |

## Coverage Gaps

### Tactics Not Covered
- Initial Access (T1190, T1566, etc.)
- Discovery (T1083, T1018, etc.)
- Lateral Movement (T1021, T1550, etc.)
- Collection (T1005, T1560, etc.)
- Exfiltration (T1041, T1048, etc.)
- Impact (T1486, T1490, etc.)

### Techniques Mapped But Not Implemented
- T1059.004 (Unix Shell) - Could extend download detection
- T1546.004 (Unix Shell Config) - Could detect .bashrc/.profile modifications
- T1053 (Scheduled Task/Job generic) - Platform-specific subtechniques used

## Validation of Mappings

Each rule's ATT&CK mapping should be reviewed against:
1. **Official technique definition** - Does the rule detect the core behavior?
2. **Procedure examples** - Does the rule catch known adversary procedures?
3. **Detection coverage** - Are there significant blind spots?

The `rationale` field in each rule's `attack` metadata should document this review.

## Updating the Registry

To add a new technique to the curated registry:

1. Add entry to `ATTACK_TECHNIQUES` in `attack_validator.py`
2. Include: ID, name, tactics tuple, summary
3. Run validation to confirm syntax
4. Update this document

The registry is intentionally curated (not auto-imported from STIX) to ensure
only relevant, reviewed techniques are available for tagging.