# Detection Rule Catalog

This document lists all detection rules in the SentinelForge repository with their
metadata, MITRE ATT&CK mappings, and conversion status.

## Linux Rules

### 1. SSH Authentication Failure
- **File**: `rules/linux/ssh-auth-failure.yml`
- **UUID**: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
- **Status**: stable
- **Severity**: medium
- **Log Source**: linux/sshd
- **ATT&CK**: T1110 (Brute Force), T1110.001 (Password Guessing)
- **Description**: Detects failed SSH authentication attempts including invalid users, wrong passwords, and protocol mismatches.
- **Conversion**: ✅ Supported

### 2. Repeated SSH Authentication Failures from Same Source
- **File**: `rules/linux/ssh-repeated-auth-failures.yml`
- **UUID**: `b2c3d4e5-f6a7-8901-bcde-f23456789012`
- **Status**: stable
- **Severity**: high
- **Log Source**: linux/sshd
- **ATT&CK**: T1110 (Brute Force), T1110.001 (Password Guessing)
- **Description**: Detects repeated SSH authentication failures from the same source IP. Requires correlation/time-window aggregation.
- **Conversion**: ❌ Unsupported (correlation rule)

### 3. Successful SSH Login After Repeated Failures
- **File**: `rules/linux/ssh-success-after-failures.yml`
- **UUID**: `c3d4e5f6-a7b8-9012-cdef-345678901234`
- **Status**: test
- **Severity**: critical
- **Log Source**: linux/sshd
- **ATT&CK**: T1110 (Brute Force), T1110.001 (Password Guessing), T1078 (Valid Accounts)
- **Description**: Detects successful SSH login following multiple failed attempts from the same source. Requires stateful correlation.
- **Conversion**: ❌ Unsupported (correlation rule)

### 4. Cron Persistence Modification
- **File**: `rules/linux/cron-persistence-modification.yml`
- **UUID**: `d4e5f6a7-b8c9-0123-def0-456789012345`
- **Status**: stable
- **Severity**: high
- **Log Source**: linux/cron
- **ATT&CK**: T1053 (Scheduled Task/Job), T1053.003 (Cron)
- **Description**: Detects modifications to system crontab files and user crontab entries.
- **Conversion**: ✅ Supported

### 5. SSH Authorized Keys Modification
- **File**: `rules/linux/ssh-authorized-keys-modification.yml`
- **UUID**: `e5f6a7b8-c9d0-1234-ef01-567890123456`
- **Status**: stable
- **Severity**: high
- **Log Source**: linux/auditd
- **ATT&CK**: T1098 (Account Manipulation), T1098.004 (SSH Authorized Keys)
- **Description**: Detects modifications to SSH authorized_keys files in user home directories and root.
- **Conversion**: ✅ Supported

### 6. Sudoers Configuration Modification
- **File**: `rules/linux/sudoers-modification.yml`
- **UUID**: `f6a7b8c9-d0e1-2345-f012-678901234567`
- **Status**: stable
- **Severity**: high
- **Log Source**: linux/auditd
- **ATT&CK**: T1548 (Abuse Elevation Control Mechanism), T1548.003 (Sudo and Sudo Caching)
- **Description**: Detects modifications to sudoers configuration files (/etc/sudoers and /etc/sudoers.d/).
- **Conversion**: ✅ Supported

### 7. Suspicious Command Line Download Activity
- **File**: `rules/linux/suspicious-download-activity.yml`
- **UUID**: `a7b8c9d0-e1f2-3456-0123-789012345678`
- **Status**: stable
- **Severity**: medium
- **Log Source**: linux/auditd
- **ATT&CK**: T1105 (Ingress Tool Transfer)
- **Description**: Detects suspicious file downloads via curl, wget, fetch, and execution of downloaded content.
- **Conversion**: ✅ Supported

## Windows Rules

### 8. Suspicious PowerShell Execution
- **File**: `rules/windows/suspicious-powershell-execution.yml`
- **UUID**: `b8c9d0e1-f2a3-4567-1234-890123456789`
- **Status**: stable
- **Severity**: high
- **Log Source**: windows/powershell
- **ATT&CK**: T1059 (Command and Scripting Interpreter), T1059.001 (PowerShell)
- **Description**: Detects suspicious PowerShell execution patterns including encoded commands, execution policy bypass, download cradles, and obfuscation.
- **Conversion**: ✅ Supported

### 9. Encoded PowerShell Command Execution
- **File**: `rules/windows/encoded-powershell-command.yml`
- **UUID**: `c9d0e1f2-a3b4-5678-2345-901234567890`
- **Status**: stable
- **Severity**: high
- **Log Source**: windows/powershell
- **ATT&CK**: T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)
- **Description**: Detects PowerShell execution with base64-encoded commands via -EncodedCommand, -enc, or -e parameters.
- **Conversion**: ✅ Supported

### 10. Local User Account Creation
- **File**: `rules/windows/local-user-creation.yml`
- **UUID**: `d0e1f2a3-b4c5-6789-3456-012345678901`
- **Status**: stable
- **Severity**: medium
- **Log Source**: windows/security
- **ATT&CK**: T1136 (Create Account), T1136.001 (Local Account)
- **Description**: Detects creation of local user accounts (Event ID 4720).
- **Conversion**: ✅ Supported

### 11. User Added to Local Administrators Group
- **File**: `rules/windows/user-added-to-administrators.yml`
- **UUID**: `e1f2a3b4-c5d6-7890-4567-123456789012`
- **Status**: stable
- **Severity**: high
- **Log Source**: windows/security
- **ATT&CK**: T1098 (Account Manipulation), T1078 (Valid Accounts)
- **Description**: Detects addition of users to the local Administrators group (Event ID 4732, Target: Administrators).
- **Conversion**: ✅ Supported

### 12. Scheduled Task Creation
- **File**: `rules/windows/scheduled-task-creation.yml`
- **UUID**: `f2a3b4c5-d6e7-8901-5678-234567890123`
- **Status**: stable
- **Severity**: medium
- **Log Source**: windows/security
- **ATT&CK**: T1053 (Scheduled Task/Job), T1053.005 (Scheduled Task)
- **Description**: Detects creation and modification of scheduled tasks (Event IDs 4698, 4702).
- **Conversion**: ✅ Supported

### 13. Suspicious Windows Service Installation
- **File**: `rules/windows/suspicious-service-installation.yml`
- **UUID**: `a3b4c5d6-e7f8-9012-6789-345678901234`
- **Status**: stable
- **Severity**: medium
- **Log Source**: windows/system
- **ATT&CK**: T1543 (Create or Modify System Process), T1543.003 (Windows Service)
- **Description**: Detects installation of new Windows services (Event ID 7045).
- **Conversion**: ✅ Supported

## Summary

| Category | Count | Convertible | Correlation-Only |
|----------|-------|-------------|------------------|
| Linux    | 7     | 5           | 2                |
| Windows  | 6     | 6           | 0                |
| **Total** | **13** | **11**      | **2**            |

## Conversion Status Legend

- ✅ **Supported**: Rule converts to valid Wazuh XML with faithful semantics
- ❌ **Unsupported**: Rule uses Sigma constructs outside the supported subset (correlation, regex, etc.)