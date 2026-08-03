"""
TrinTech Digital Defense
TI-Corr: Threat Intelligence Correlator — Base Feed Abstraction

Provides a common interface for all threat intelligence feeds.
Each feed implements the FeedBase interface.
"""

import abc
import logging
import time
from datetime import datetime, timedelta
from typing import Any

log = logging.getLogger("ticorr.feeds.base")


class FeedBase(abc.ABC):
    """Abstract base class for threat intelligence feeds."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable feed name."""

    @property
    @abc.abstractmethod
    def endpoint(self) -> str:
        """API endpoint URL."""

    @property
    def enabled(self) -> bool:
        """Override to disable specific feeds."""
        return True

    @property
    def rate_limit(self) -> int:
        """Requests per minute limit (default: 60)."""
        return 60

    @abc.abstractmethod
    def fetch(self, query: str, **kwargs) -> list[dict[str, Any]]:
        """
        Fetch intelligence data for a given query.

        Args:
            query: Search term (IP, domain, hash, etc.)
            **kwargs: Feed-specific parameters

        Returns:
            List of intelligence dicts with common keys:
                - source: str (feed name)
                - type: str (ip, domain, hash, url, etc.)
                - value: str (the queried value)
                - confidence: int (0-100)
                - tags: list[str]
                - first_seen: str|None
                - last_seen: str|None
                - description: str
                - raw: dict  (original response, stripped)
        """

    def _backoff(self):
        """Simple rate-limit backoff (1 second between requests)."""
        time.sleep(1.0 / self.rate_limit)

    def validate_api_key(self) -> bool:
        """Check if required API keys are set. Override per-feed."""
        return True

    def get_status(self) -> dict:
        """Return feed operational status."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "last_fetch": None,
            "records_fetched": 0,
        }
