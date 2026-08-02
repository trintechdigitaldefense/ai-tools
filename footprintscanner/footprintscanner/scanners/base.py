"""Abstract base class for all scanners."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from footprintscanner.models import Finding, ScannerCategory, Target

if TYPE_CHECKING:
    from footprintscanner.config import Config

logger = logging.getLogger("footprintscanner.scanners")


class BaseScanner(ABC):
    """All scanners inherit from this base class."""

    category: ScannerCategory = ScannerCategory.DOMAIN
    name: str = "Unknown"

    def __init__(self, config: Config):
        self.config = config

    @abstractmethod
    def scan(self, target: Target) -> list[Finding]:
        """Run the scanner against the target and return findings."""
        ...

    def log(self, message: str, level: str = "info"):
        getattr(logger, level)("[%s] %s", self.name, message)
