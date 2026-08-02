"""Core models for FootprintScanner findings, targets, and reports."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, model_validator


class Severity(str, enum.Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def priority(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(self.value, 99)

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
        }.get(self.value, "⚪")


class ScannerCategory(str, enum.Enum):
    """Categories of scanning modules."""

    DOMAIN = "Domain & DNS"
    IP_INFRASTRUCTURE = "IP & Network"
    EMAIL = "Email"
    SOCIAL_MEDIA = "Social Media"
    SECURITY_HEADERS = "Security Headers"
    BREACH = "Breach Data"
    SEARCH_ENGINE = "Search Engine"
    CERTIFICATE = "SSL/TLS Certificate"


class Finding(BaseModel):
    """A single finding from a scan."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    category: ScannerCategory
    title: str
    description: str
    severity: Severity
    details: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scanner: str = ""

    def __lt__(self, other: "Finding") -> bool:
        return self.severity.priority < other.severity.priority


class Vulnerability(Finding):
    """A finding that represents a vulnerability or misconfiguration."""

    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)


class Exposure(Finding):
    """A finding that reveals public information about the target."""

    exposed_data_type: str = ""
    estimated_data_volume: str = ""


class Positive(Finding):
    """A finding that indicates a security best practice is in place."""

    pass


class Target(BaseModel):
    """A target being scanned (domain, IP, email, etc.)."""

    domain: str = ""
    ip: str = ""
    email: str = ""
    social_username: str = ""
    name: str = ""  # human-friendly name for reports

    @model_validator(mode="after")
    def _validate_at_least_one(self):
        if not any([self.domain, self.ip, self.email, self.social_username]):
            raise ValueError("Target must have at least one identifier")
        return self


class ScanResult(BaseModel):
    """Aggregate results from a full scan."""

    target: Target
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    findings: list[Finding] = Field(default_factory=list)
    scanner_errors: list[str] = Field(default_factory=list)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_error(self, error: str):
        self.scanner_errors.append(error)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def risk_score(self) -> float:
        """Calculate overall risk score 0-100. Higher = worse."""
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        total = 0.0
        for f in self.findings:
            total += weights.get(f.severity.value, 0)
        return min(round(total, 1), 100.0)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        if score >= 10:
            return "LOW"
        return "MINIMAL"

    def time_to_complete(self) -> str:
        if self.completed_at is None:
            return "In progress"
        delta = self.completed_at - self.started_at
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return f"{seconds}s"
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes}m {secs}s"
