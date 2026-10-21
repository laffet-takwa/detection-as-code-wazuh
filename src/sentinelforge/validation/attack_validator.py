"""Stage C (part) - MITRE ATT&CK metadata validation.

The registry below is a *curated subset* of the MITRE ATT&CK Enterprise matrix
that covers the techniques referenced by the SentinelForge rule catalogue.  It
exists so that the tooling can check identifier syntax, look up the canonical
technique name and tactic, and produce a stable link to the official technique
page.

The registry is **not** a substitute for the official ATT&CK STIX bundle: a
successful validation proves that an identifier is well formed and known to this
repository, it does not prove that a rule observes the behaviour the technique
describes.  That judgement is recorded manually in each rule's ``attack``
rationale and is reviewed by a human.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from ..models import AttackReference, Issue, IssueSeverity

__all__ = [
    "TechniqueInfo",
    "ATTACK_TECHNIQUES",
    "TECHNIQUE_ID_PATTERN",
    "is_valid_technique_id",
    "technique_url",
    "lookup_technique",
    "validate_attack_tags",
    "extract_attack_tags",
]

TECHNIQUE_ID_PATTERN: Final = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_SIGMA_ATTACK_TAG: Final = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


@dataclass(frozen=True)
class TechniqueInfo:
    """Static metadata about a single ATT&CK technique."""

    id: str
    name: str
    tactics: tuple[str, ...]
    summary: str = ""

    @property
    def url(self) -> str:
        return technique_url(self.id)

    @property
    def primary_tactic(self) -> str:
        return self.tactics[0] if self.tactics else ""


def technique_url(technique_id: str) -> str:
    """Return the official ATT&CK URL for *technique_id*."""

    if "." in technique_id:
        parent, _, child = technique_id.partition(".")
        return f"https://attack.mitre.org/techniques/{parent}/{child}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def _t(technique_id: str, name: str, tactics: tuple[str, ...], summary: str = "") -> TechniqueInfo:
    return TechniqueInfo(id=technique_id, name=name, tactics=tactics, summary=summary)


#: Curated subset of ATT&CK Enterprise techniques used by this repository.
ATTACK_TECHNIQUES: Final[dict[str, TechniqueInfo]] = {
    info.id: info
    for info in (
        _t(
            "T1027",
            "Obfuscated Files or Information",
            ("Defense Evasion",),
            "Adversaries obfuscate data to impede detection and analysis.",
        ),
        _t(
            "T1053",
            "Scheduled Task/Job",
            ("Execution", "Persistence"),
            "Adversaries schedule commands to run on a recurring basis.",
        ),
        _t(
            "T1053.003",
            "Scheduled Task/Job: Cron",
            ("Execution", "Persistence"),
            "Adversaries abuse cron to schedule commands on Linux hosts.",
        ),
        _t(
            "T1053.005",
            "Scheduled Task/Job: Scheduled Task",
            ("Execution", "Persistence"),
            "Adversaries abuse the Windows Task Scheduler for persistence.",
        ),
        _t(
            "T1059",
            "Command and Scripting Interpreter",
            ("Execution",),
            "Adversaries abuse command interpreters to execute instructions.",
        ),
        _t(
            "T1059.001",
            "Command and Scripting Interpreter: PowerShell",
            ("Execution",),
            "Adversaries abuse PowerShell to execute malicious commands.",
        ),
        _t(
            "T1059.004",
            "Command and Scripting Interpreter: Unix Shell",
            ("Execution",),
            "Adversaries abuse Unix shells to execute commands.",
        ),
        _t(
            "T1078",
            "Valid Accounts",
            ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"),
            "Adversaries use legitimate credentials to access and persist.",
        ),
        _t(
            "T1098",
            "Account Manipulation",
            ("Persistence", "Privilege Escalation"),
            "Adversaries modify accounts to maintain or elevate access.",
        ),
        _t(
            "T1098.004",
            "Account Manipulation: SSH Authorized Keys",
            ("Persistence", "Privilege Escalation"),
            "Adversaries modify SSH authorized_keys to establish persistence.",
        ),
        _t(
            "T1105",
            "Ingress Tool Transfer",
            ("Command and Control",),
            "Adversaries transfer tools or payloads into a compromised network.",
        ),
        _t(
            "T1110",
            "Brute Force",
            ("Credential Access",),
            "Adversaries guess passwords to obtain valid credentials.",
        ),
        _t(
            "T1110.001",
            "Brute Force: Password Guessing",
            ("Credential Access",),
            "Adversaries guess passwords against exposed authentication services.",
        ),
        _t(
            "T1136",
            "Create Account",
            ("Persistence",),
            "Adversaries create accounts to maintain access to a system.",
        ),
        _t(
            "T1136.001",
            "Create Account: Local Account",
            ("Persistence",),
            "Adversaries create local accounts to maintain access.",
        ),
        _t(
            "T1543",
            "Create or Modify System Process",
            ("Persistence",),
            "Adversaries create or modify system processes for persistence.",
        ),
        _t(
            "T1543.003",
            "Create or Modify System Process: Windows Service",
            ("Persistence",),
            "Adversaries install Windows services to persist and execute payloads.",
        ),
        _t(
            "T1546",
            "Event Triggered Execution",
            ("Persistence", "Privilege Escalation"),
            "Adversaries bind malicious code to a trigger such as a config file.",
        ),
        _t(
            "T1546.004",
            "Event Triggered Execution: Unix Shell Config Modification",
            ("Persistence", "Privilege Escalation"),
            "Adversaries modify shell configuration files for persistence.",
        ),
        _t(
            "T1548",
            "Abuse Elevation Control Mechanism",
            ("Privilege Escalation",),
            "Adversaries abuse mechanisms to elevate privileges.",
        ),
        _t(
            "T1548.003",
            "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
            ("Privilege Escalation",),
            "Adversaries abuse sudo configuration or caching to gain root.",
        ),
    )
}


def is_valid_technique_id(value: str) -> bool:
    """Return ``True`` when *value* is a syntactically valid ATT&CK technique ID."""

    return bool(TECHNIQUE_ID_PATTERN.match(value.strip()))


def lookup_technique(technique_id: str) -> TechniqueInfo | None:
    """Return the registry entry for *technique_id* when known."""

    return ATTACK_TECHNIQUES.get(technique_id.strip().upper())


def extract_attack_tags(tags: list[str]) -> list[str]:
    """Return the ATT&CK technique IDs referenced by Sigma ``attack.*`` tags."""

    found: list[str] = []
    for tag in tags:
        match = _SIGMA_ATTACK_TAG.match(tag.strip().lower())
        if match:
            identifier = match.group(1).upper()
            if identifier not in found:
                found.append(identifier)
    return found


def validate_attack_tags(
    tags: list[str],
    *,
    rule_path: str | None = None,
    rule_id: str | None = None,
    require_attack: bool = True,
) -> tuple[list[AttackReference], list[Issue]]:
    """Validate the ATT&CK metadata of a rule.

    Returns the resolved :class:`~sentinelforge.models.AttackReference` objects
    together with the issues that were found.
    """

    issues: list[Issue] = []
    references: list[AttackReference] = []
    technique_ids = extract_attack_tags(tags)

    if not technique_ids:
        if require_attack:
            issues.append(
                Issue(
                    severity=IssueSeverity.ERROR,
                    code="attack.missing",
                    message=(
                        "Rule does not reference a MITRE ATT&CK technique. Add at least one " "'attack.tXXXX' tag."
                    ),
                    rule_path=rule_path,
                    rule_id=rule_id,
                    field="tags",
                    stage="attack",
                )
            )
        return references, issues

    for technique_id in technique_ids:
        if not is_valid_technique_id(technique_id):
            issues.append(
                Issue(
                    severity=IssueSeverity.ERROR,
                    code="attack.invalid_id",
                    message=(
                        f"'{technique_id}' is not a valid ATT&CK technique identifier " "(expected T#### or T####.###)."
                    ),
                    rule_path=rule_path,
                    rule_id=rule_id,
                    field="tags",
                    stage="attack",
                )
            )
            continue
        info = lookup_technique(technique_id)
        if info is None:
            issues.append(
                Issue(
                    severity=IssueSeverity.WARNING,
                    code="attack.unknown_technique",
                    message=(
                        f"Technique {technique_id} is syntactically valid but is not part of the "
                        "curated technique registry of this repository. Verify the mapping "
                        "manually against the official ATT&CK matrix."
                    ),
                    rule_path=rule_path,
                    rule_id=rule_id,
                    field="tags",
                    stage="attack",
                )
            )
            references.append(AttackReference(id=technique_id, url=technique_url(technique_id)))
            continue
        references.append(
            AttackReference(
                id=info.id,
                tactic=info.primary_tactic,
                technique=info.name,
                url=info.url,
            )
        )

    return references, issues
