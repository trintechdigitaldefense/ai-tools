"""Scanner configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml


CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


class Config:
    """Global scanner configuration."""

    # How long to wait between HTTP requests (seconds)
    request_delay: float = 1.0

    # Max retries per request
    max_retries: int = 3

    # Timeout for HTTP requests (seconds)
    timeout: int = 15

    # HaveIBeenPwned API key (optional, v2 requires subscription)
    hibp_api_key: Optional[str] = None

    # User-Agent header for HTTP requests
    user_agent: str = (
        "Mozilla/5.0 (compatible; FootprintScanner/0.1; "
        "+https://github.com/footprintscanner)"
    )

    # Number of concurrent scanner workers
    max_concurrency: int = 6

    # Output directory for reports
    output_dir: Path = Path("footprint_reports")

    @classmethod
    def load(cls, path: Path | str | None = None) -> Config:
        """Load config from YAML file or use defaults."""
        config_file = Path(path) if path else CONFIG_PATH
        if config_file.exists():
            with open(config_file) as f:
                data = yaml.safe_load(f) or {}
            instance = cls()
            for key, value in data.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)
            return instance
        return cls()

    @classmethod
    def example(cls) -> str:
        """Return an example config YAML."""
        return """# FootprintScanner Configuration
# Copy this to config.yaml and customize

# Seconds to wait between HTTP requests (avoid rate limits)
request_delay: 1.0

# Maximum retries for failed requests
max_retries: 3

# HTTP timeout in seconds
timeout: 15

# HaveIBeenPwned API key (optional — free tier available)
hibp_api_key: null

# User-Agent string sent with requests
user_agent: "Mozilla/5.0 (compatible; FootprintScanner/0.1)"

# How many scanners run concurrently
max_concurrency: 6

# Where to save PDF reports
output_dir: "footprint_reports"
"""
