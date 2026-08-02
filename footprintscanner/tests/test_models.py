"""Tests for models."""

import pytest
from pydantic import ValidationError

from footprintscanner.models import (
    Exposure, Finding, Positive, ScanResult, Severity, ScannerCategory, Target,
    Vulnerability,
)


class TestSeverity:
    def test_severity_priority_order(self):
        assert Severity.CRITICAL.priority < Severity.HIGH.priority
        assert Severity.HIGH.priority < Severity.MEDIUM.priority
        assert Severity.MEDIUM.priority < Severity.LOW.priority
        assert Severity.LOW.priority < Severity.INFO.priority

    def test_severity_colors(self):
        assert Severity.CRITICAL.color == "🔴"
        assert Severity.HIGH.color == "🟠"
        assert Severity.MEDIUM.color == "🟡"
        assert Severity.LOW.color == "🔵"
        assert Severity.INFO.color == "⚪"


class TestTarget:
    def test_target_with_domain(self):
        t = Target(domain="example.com")
        assert t.domain == "example.com"

    def test_target_with_email(self):
        t = Target(email="test@example.com")
        assert t.email == "test@example.com"

    def test_target_without_identifier_raises(self):
        with pytest.raises(ValidationError):
            Target()

    def test_target_with_name(self):
        t = Target(domain="example.com", name="Example Corp")
        assert t.name == "Example Corp"


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            category=ScannerCategory.DOMAIN,
            title="Test Finding",
            description="A test",
            severity=Severity.HIGH,
        )
        assert f.title == "Test Finding"
        assert f.severity == Severity.HIGH
        assert f.id  # auto-generated

    def test_finding_sorting(self):
        f1 = Finding(
            category=ScannerCategory.DOMAIN, title="A", description="", severity=Severity.HIGH,
        )
        f2 = Finding(
            category=ScannerCategory.DOMAIN, title="B", description="", severity=Severity.LOW,
        )
        assert f1 < f2


class TestVulnerability:
    def test_vulnerability_has_remediation(self):
        v = Vulnerability(
            category="Security Headers",
            title="Missing HSTS",
            description="HSTS not set",
            severity=Severity.HIGH,
            remediation="Add HSTS header",
        )
        assert v.remediation == "Add HSTS header"


class TestScanResult:
    def test_add_finding(self):
        r = ScanResult(target=Target(domain="example.com"))
        f = Finding(
            category=ScannerCategory.DOMAIN, title="Test", description="", severity=Severity.HIGH,
        )
        r.add_finding(f)
        assert len(r.findings) == 1

    def test_counts(self):
        r = ScanResult(target=Target(domain="example.com"))
        r.add_finding(Finding(category=ScannerCategory.DOMAIN, title="A", description="", severity=Severity.CRITICAL))
        r.add_finding(Finding(category=ScannerCategory.DOMAIN, title="B", description="", severity=Severity.HIGH))
        r.add_finding(Finding(category=ScannerCategory.DOMAIN, title="C", description="", severity=Severity.MEDIUM))
        r.add_finding(Finding(category=ScannerCategory.DOMAIN, title="D", description="", severity=Severity.LOW))
        r.add_finding(Finding(category=ScannerCategory.DOMAIN, title="E", description="", severity=Severity.INFO))
        assert r.critical_count == 1
        assert r.high_count == 1
        assert r.medium_count == 1
        assert r.low_count == 1
        assert r.info_count == 1

    def test_risk_score(self):
        r = ScanResult(target=Target(domain="example.com"))
        r.add_finding(Finding(category=ScannerCategory.DOMAIN, title="A", description="", severity=Severity.CRITICAL))
        score = r.risk_score
        assert score >= 25  # CRITICAL adds 25

    def test_risk_level(self):
        r = ScanResult(target=Target(domain="example.com"))
        assert r.risk_level == "MINIMAL"

        # Add a critical finding to push it above 75
        for _ in range(4):
            r.add_finding(Finding(category=ScannerCategory.DOMAIN, title="A", description="", severity=Severity.CRITICAL))
        assert r.risk_level == "CRITICAL"

    def test_add_error(self):
        r = ScanResult(target=Target(domain="example.com"))
        r.add_error("DNS lookup failed")
        assert len(r.scanner_errors) == 1
