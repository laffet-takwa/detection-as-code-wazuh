"""Field and event-source mapping between Sigma and Wazuh.

A Wazuh custom rule cannot reference arbitrary log fields the way a Sigma rule
can.  Wazuh rules match against a *decoded event* using a small set of
primitives, so every Sigma field that SentinelForge converts needs an explicit
mapping onto the regular expression fragment that identifies the field inside
the decoded event.

The mapping is data, not code: it lives in :data:`DEFAULT_MAPPINGS` and can be
extended or overridden from a YAML configuration file (see
``examples/configuration.example.yaml``).

Semantics of a mapped field
---------------------------
Each :class:`FieldTemplate` describes where the field lives inside the decoded
event:

``prefix``
    Regular expression that must appear directly before the field value.
``suffix``
    Regular expression that must appear directly after the field value.
``quoted``
    When ``True`` the value may optionally be surrounded by double quotes, which
    covers both the ``name="/etc/sudoers"`` and ``name=/etc/sudoers`` shapes used
    by auditd.
``span``
    Upper bound for the "any characters in between" wildcard that is used for
    ``contains``/``endswith`` style matches.

The templates intentionally accept both the *raw* log shape (``from 10.0.0.5
port 22``) and the *Wazuh decoded* shape (``srcip: 10.0.0.5``) so that a rule
keeps working regardless of whether the Wazuh decoder rewrote the message.  The
authoritative check for a specific Wazuh version remains ``wazuh-logtest`` in a
lab; the offline test-suite only verifies the conversion logic.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ..models import LogSource

__all__ = [
    "FieldTemplate",
    "FieldPattern",
    "LogSourceMapping",
    "MappingRegistry",
    "DEFAULT_MAPPINGS",
    "build_default_registry",
    "UNKNOWN_FIELD_MESSAGE",
]

#: Message used when a Sigma field has no mapping for its log source.
UNKNOWN_FIELD_MESSAGE = (
    "No Wazuh field mapping is defined for field '{field}' in log source '{logsource}'. "
    "Add a mapping in the SentinelForge configuration before converting this rule."
)

_BOUNDARY = r"(?=\s|$)"
_SSH_BOUNDARY = r"(?:\s|$)"


@dataclass(frozen=True)
class FieldTemplate:
    """One candidate location of a field inside the decoded event."""

    prefix: str
    suffix: str = _BOUNDARY
    quoted: bool = False
    span: int = 512
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "prefix": self.prefix,
            "suffix": self.suffix,
            "quoted": self.quoted,
            "span": self.span,
        }


@dataclass(frozen=True)
class FieldPattern:
    """All known locations of a single Sigma field for one log source."""

    field: str
    templates: tuple[FieldTemplate, ...]
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "templates": [template.to_dict() for template in self.templates],
            "description": self.description,
        }


@dataclass(frozen=True)
class LogSourceMapping:
    """Mapping of a Sigma log source onto Wazuh decoders and fields."""

    key: str
    decoders: tuple[str, ...]
    fields: Mapping[str, FieldPattern] = field(default_factory=dict)
    groups: tuple[str, ...] = ()
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "decoders": list(self.decoders),
            "groups": list(self.groups),
            "fields": {name: pattern.to_dict() for name, pattern in self.fields.items()},
            "description": self.description,
        }


def _template(prefix: str, suffix: str = _BOUNDARY, *, quoted: bool = False, span: int = 512) -> FieldTemplate:
    return FieldTemplate(prefix=prefix, suffix=suffix, quoted=quoted, span=span)


def _pattern(name: str, templates: Iterable[FieldTemplate], description: str = "") -> FieldPattern:
    return FieldPattern(field=name, templates=tuple(templates), description=description)


# --------------------------------------------------------------------------- #
# Linux                                                                       #
# --------------------------------------------------------------------------- #

_SSHD_FIELDS: dict[str, FieldPattern] = {
    "SourceIP": _pattern(
        "SourceIP",
        [
            _template(r"from\s+", _SSH_BOUNDARY),
            _template(r"srcip:\s*", _SSH_BOUNDARY),
            _template(r"src_ip=", _SSH_BOUNDARY),
        ],
        "Client address of the SSH connection.",
    ),
    "SourcePort": _pattern(
        "SourcePort",
        [
            _template(r"port\s+", _SSH_BOUNDARY),
            _template(r"srcport:\s*", _SSH_BOUNDARY),
        ],
        "Client port of the SSH connection.",
    ),
    "User": _pattern(
        "User",
        [
            _template(r"for\s+invalid user\s+", _SSH_BOUNDARY),
            _template(r"for\s+", r"\s+from\b"),
            _template(r"(?:srcuser|dstuser|user):\s*", _SSH_BOUNDARY),
        ],
        "Account the SSH daemon attempted to authenticate.",
    ),
    "AuthenticationMethod": _pattern(
        "AuthenticationMethod",
        [
            _template(r"authentication method\s+", _SSH_BOUNDARY),
            _template(r"authmethod:\s*", _SSH_BOUNDARY),
        ],
        "Authentication method reported by the SSH daemon.",
    ),
    "type": _pattern(
        "type",
        [
            _template(r"type=", _SSH_BOUNDARY),
            _template(r"type\s+", _SSH_BOUNDARY),
        ],
        "SSH message type (authentication_failure, authentication_success, etc.).",
    ),
}

_AUDITD_FIELDS: dict[str, FieldPattern] = {
    "type": _pattern(
        "type",
        [_template(r"type=", _BOUNDARY)],
        "auditd record type (SYSCALL, PATH, USER_CMD, ...).",
    ),
    "exe": _pattern(
        "exe",
        [_template(r"exe=", _BOUNDARY, quoted=True)],
        "Executable path recorded by auditd.",
    ),
    "comm": _pattern(
        "comm",
        [_template(r"comm=", _BOUNDARY, quoted=True)],
        "Command name recorded by auditd.",
    ),
    "name": _pattern(
        "name",
        [_template(r"name=", _BOUNDARY, quoted=True)],
        "Object name (file path) recorded by auditd.",
    ),
    "success": _pattern(
        "success",
        [_template(r"success=", _BOUNDARY)],
        "Whether the audited syscall succeeded.",
    ),
    "uid": _pattern(
        "uid",
        [_template(r"uid=", _BOUNDARY)],
        "Effective user id of the audit record.",
    ),
    "a0": _pattern("a0", [_template(r"a0=", _BOUNDARY, quoted=True)], "First syscall argument."),
    "a1": _pattern("a1", [_template(r"a1=", _BOUNDARY, quoted=True)], "Second syscall argument."),
    "a2": _pattern("a2", [_template(r"a2=", _BOUNDARY, quoted=True)], "Third syscall argument."),
    "a3": _pattern("a3", [_template(r"a3=", _BOUNDARY, quoted=True)], "Fourth syscall argument."),
}

# --------------------------------------------------------------------------- #
# Windows                                                                     #
# --------------------------------------------------------------------------- #

_WINDOWS_FIELDS: dict[str, FieldPattern] = {
    "EventID": _pattern(
        "EventID",
        [_template(r"EventID\s*:?\s*", _BOUNDARY)],
        "Windows event identifier.",
    ),
    "ProviderName": _pattern(
        "ProviderName",
        [_template(r"Provider\s*Name\s*:?\s*", _BOUNDARY)],
        "Event provider name.",
    ),
    "TargetUserName": _pattern(
        "TargetUserName",
        [_template(r"Target\s*User\s*Name\s*:?\s*", _BOUNDARY, quoted=True)],
        "Account that is the target of the operation.",
    ),
    "SubjectUserName": _pattern(
        "SubjectUserName",
        [_template(r"Subject\s*User\s*Name\s*:?\s*", _BOUNDARY, quoted=True)],
        "Account that performed the operation.",
    ),
    "TargetDomain": _pattern(
        "TargetDomain",
        [_template(r"Target\s*Domain\s*:?\s*", _BOUNDARY, quoted=True)],
        "Domain of the target account.",
    ),
    "MemberName": _pattern(
        "MemberName",
        [
            _template(r"Member\s*Name\s*:?\s*", _BOUNDARY, quoted=True),
            _template(r"MemberName\s*:?\s*", _BOUNDARY, quoted=True),
        ],
        "Member of a group (group membership events).",
    ),
    "MemberSid": _pattern(
        "MemberSid",
        [_template(r"Member\s*SID\s*:?\s*", _BOUNDARY)],
        "Security identifier of the group member.",
    ),
    "IpAddress": _pattern(
        "IpAddress",
        [
            _template(r"Ip\s*Address\s*:?\s*", _BOUNDARY),
            _template(r"(?:src_ip|ip_address)=", _BOUNDARY),
        ],
        "Client address of the logon event.",
    ),
    "IpPort": _pattern(
        "IpPort",
        [_template(r"Ip\s*Port\s*:?\s*", _BOUNDARY)],
        "Client port of the logon event.",
    ),
    "LogonType": _pattern(
        "LogonType",
        [_template(r"Logon\s*Type\s*:?\s*", _BOUNDARY)],
        "Logon type of the authentication event.",
    ),
    "WorkstationName": _pattern(
        "WorkstationName",
        [_template(r"Workstation\s*Name\s*:?\s*", _BOUNDARY, quoted=True)],
        "Workstation of the logon event.",
    ),
    "Status": _pattern(
        "Status",
        [_template(r"Status\s*:?\s*", _BOUNDARY)],
        "Status code of the event.",
    ),
    "SubStatus": _pattern(
        "SubStatus",
        [_template(r"Sub\s*Status\s*:?\s*", _BOUNDARY)],
        "Sub status code of the event.",
    ),
    "ProcessName": _pattern(
        "ProcessName",
        [_template(r"Process\s*Name\s*:?\s*", _BOUNDARY, quoted=True)],
        "Process that produced the event.",
    ),
    "CommandLine": _pattern(
        "CommandLine",
        [_template(r"Command\s*Line\s*:?\s*", _BOUNDARY)],
        "Command line of the process that produced the event.",
    ),
    "ParentCommandLine": _pattern(
        "ParentCommandLine",
        [_template(r"Parent\s*Command\s*Line\s*:?\s*", _BOUNDARY)],
        "Command line of the parent process.",
    ),
    "ServiceName": _pattern(
        "ServiceName",
        [
            _template(r"Service\s*Name\s*:?\s*", _BOUNDARY, quoted=True),
            _template(r"ServiceName\s*:?\s*", _BOUNDARY, quoted=True),
        ],
        "Name of the installed Windows service.",
    ),
    "ImagePath": _pattern(
        "ImagePath",
        [
            _template(r"Image\s*Path\s*:?\s*", _BOUNDARY, quoted=True),
            _template(r"ImagePath\s*:?\s*", _BOUNDARY, quoted=True),
        ],
        "Path of the service binary.",
    ),
    "TaskName": _pattern(
        "TaskName",
        [
            _template(r"TaskName\s*:?\s*", _BOUNDARY, quoted=True),
            _template(r"Task\s*Name\s*:?\s*", _BOUNDARY, quoted=True),
        ],
        "Name of the registered scheduled task.",
    ),
    "TaskContent": _pattern(
        "TaskContent",
        [_template(r"Task\s*Content\s*:?\s*", _BOUNDARY)],
        "XML body of the registered scheduled task.",
    ),
    "ScriptBlockText": _pattern(
        "ScriptBlockText",
        [_template(r"Script\s*Block\s*Text\s*:?\s*", _BOUNDARY)],
        "PowerShell script block content (event 4104).",
    ),
    "ScriptBlockId": _pattern(
        "ScriptBlockId",
        [_template(r"Script\s*Block\s*ID\s*:?\s*", _BOUNDARY)],
        "Identifier of the logged script block.",
    ),
}

#: Built-in event source and field mappings.
DEFAULT_MAPPINGS: dict[str, LogSourceMapping] = {
    "linux/sshd": LogSourceMapping(
        key="linux/sshd",
        decoders=("sshd",),
        fields=_SSHD_FIELDS,
        groups=("linux", "sshd", "authentication"),
        description="OpenSSH daemon messages.",
    ),
    "linux/auditd": LogSourceMapping(
        key="linux/auditd",
        decoders=("auditd",),
        fields=_AUDITD_FIELDS,
        groups=("linux", "auditd", "audit"),
        description="Linux audit daemon records.",
    ),
    "linux/cron": LogSourceMapping(
        key="linux/cron",
        decoders=("crond",),
        fields={
            "type": _pattern(
                "type",
                [
                    _template(r"type=", _BOUNDARY),
                    _template(r"type\s+", _BOUNDARY),
                ],
                "Cron message type (cron, anacron, etc.).",
            ),
            "name": _pattern(
                "name",
                [
                    _template(r"name=", _BOUNDARY, quoted=True),
                ],
                "Object name (file path) recorded by auditd/cron.",
            ),
            "User": _pattern(
                "User",
                [
                    _template(r"\(root\)\s+CMD\s+", _BOUNDARY),
                    _template(r"CMD\s+", _BOUNDARY),
                    _template(r"user:\s*", _BOUNDARY),
                ],
                "Account the cron daemon executed the job for.",
            ),
            "Command": _pattern(
                "Command",
                [_template(r"CMD\s+\(", r"\)\s*$")],
                "Command line executed by cron.",
            ),
            "comm": _pattern(
                "comm",
                [_template(r"comm=", _BOUNDARY, quoted=True)],
                "Command name recorded by auditd.",
            ),
            "a0": _pattern("a0", [_template(r"a0=", _BOUNDARY, quoted=True)], "First syscall argument."),
        },
        groups=("linux", "cron", "persistence"),
        description="cron daemon messages.",
    ),
    "windows/security": LogSourceMapping(
        key="windows/security",
        decoders=("windows",),
        fields=_WINDOWS_FIELDS,
        groups=("windows", "security", "authentication"),
        description="Windows Security event log.",
    ),
    "windows/system": LogSourceMapping(
        key="windows/system",
        decoders=("windows",),
        fields=_WINDOWS_FIELDS,
        groups=("windows", "system", "persistence"),
        description="Windows System event log.",
    ),
    "windows/powershell": LogSourceMapping(
        key="windows/powershell",
        decoders=("windows",),
        fields=_WINDOWS_FIELDS,
        groups=("windows", "powershell", "execution"),
        description="Windows PowerShell operational log.",
    ),
}


class MappingRegistry:
    """Lookup structure for log source and field mappings."""

    def __init__(self, mappings: Mapping[str, LogSourceMapping]) -> None:
        self._mappings = dict(mappings)

    @property
    def mappings(self) -> Mapping[str, LogSourceMapping]:
        return dict(self._mappings)

    def keys(self) -> list[str]:
        return sorted(self._mappings)

    def for_logsource(self, logsource: LogSource) -> LogSourceMapping | None:
        """Return the mapping for *logsource* when one is known."""

        return self._mappings.get(logsource.key)

    def pattern(self, logsource: LogSource, field_name: str) -> FieldPattern | None:
        """Return the field pattern for *field_name* within *logsource*."""

        mapping = self.for_logsource(logsource)
        if mapping is None:
            return None
        return mapping.fields.get(field_name)

    def with_overrides(self, overrides: Mapping[str, Any]) -> MappingRegistry:
        """Return a new registry with *overrides* applied.

        The override format mirrors :meth:`LogSourceMapping.to_dict`::

            mapping:
              overrides:
                linux/sshd:
                  decoders: [sshd]
                  fields:
                    SourceIP:
                      templates:
                        - prefix: "from\\s+"
                          suffix: "(?:\\s|$)"
        """

        if not overrides:
            return self
        merged = dict(self._mappings)
        for key, raw in overrides.items():
            if not isinstance(raw, dict):
                continue
            base = merged.get(key)
            decoders = tuple(raw.get("decoders", base.decoders if base else ()))
            groups = tuple(raw.get("groups", base.groups if base else ()))
            fields: dict[str, FieldPattern] = dict(base.fields if base else {})
            for name, definition in (raw.get("fields") or {}).items():
                if not isinstance(definition, dict):
                    continue
                templates = tuple(
                    FieldTemplate(
                        prefix=str(template.get("prefix", "")),
                        suffix=str(template.get("suffix", _BOUNDARY)),
                        quoted=bool(template.get("quoted", False)),
                        span=int(template.get("span", 512)),
                    )
                    for template in definition.get("templates", [])
                    if isinstance(template, dict)
                )
                fields[name] = FieldPattern(
                    field=name,
                    templates=templates,
                    description=str(definition.get("description", "")),
                )
            merged[key] = LogSourceMapping(
                key=key,
                decoders=decoders,
                fields=fields,
                groups=groups,
                description=str(raw.get("description", base.description if base else "")),
            )
        return MappingRegistry(merged)


def build_default_registry(overrides: Mapping[str, Any] | None = None) -> MappingRegistry:
    """Build the mapping registry, applying optional configuration overrides."""

    registry = MappingRegistry(DEFAULT_MAPPINGS)
    if overrides:
        registry = registry.with_overrides(overrides)
    return registry
