"""Structured logging configuration for SentinelForge.

The package uses the standard library :mod:`logging` module.  A single
configuration entry point keeps the console output consistent between the CLI,
the library scripts and the test-suite.
"""

from __future__ import annotations

import logging
import sys
from typing import Final

__all__ = ["configure_logging", "get_logger", "LOGGER_NAME"]

LOGGER_NAME: Final = "sentinelforge"

_CONSOLE_FORMAT: Final = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATE_FORMAT: Final = "%Y-%m-%dT%H:%M:%S%z"


def configure_logging(level: str = "INFO", *, stream: object | None = None) -> logging.Logger:
    """Configure and return the root SentinelForge logger.

    The handler is replaced on every call so that repeated invocations inside a
    single process (for example the test-suite) never duplicate log output.
    """

    logger = logging.getLogger(LOGGER_NAME)
    numeric_level = getattr(logging, str(level).upper(), logging.INFO)
    logger.setLevel(numeric_level)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(logging.Formatter(_CONSOLE_FORMAT, datefmt=_DATE_FORMAT))
    handler.setLevel(numeric_level)
    logger.addHandler(handler)
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger of the SentinelForge logger."""

    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(f"{LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
