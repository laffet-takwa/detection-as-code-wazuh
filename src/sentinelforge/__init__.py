"""SentinelForge - a Detection-as-Code engineering platform for Wazuh.

The package is intentionally small and layered:

``models``/``config``/``logging_config``
    Foundation: typed data models, centralised settings and logging.
``validation``
    Static quality gates for the Sigma rule catalogue (YAML, Sigma, metadata, ATT&CK).
``conversion``
    Translation of the supported Sigma subset into Wazuh custom rules.
``testing``
    Synthetic fixture execution, correlation engine and optional Wazuh integration.
``reporting``
    Machine-readable (JSON) and human-readable (Markdown) report rendering.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
