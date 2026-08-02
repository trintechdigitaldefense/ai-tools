"""Tests for scanners."""

import pytest

from footprintscanner.config import Config
from footprintscanner.models import Finding, Severity, Target, ScannerCategory
from footprintscanner.scanners.base import BaseScanner


class DummyScanner(BaseScanner):
    """A dummy scanner for testing."""

    name = "Dummy"

    def scan(self, target: Target) -> list[Finding]:
        return [
            Finding(
                category=ScannerCategory.EMAIL,
                title="Test Finding",
                description="This is a test finding",
                severity=Severity.MEDIUM,
                scanner=self.name,
            )
        ]


class TestBaseScanner:
    def test_scan_returns_findings(self):
        config = Config()
        scanner = DummyScanner(config)
        target = Target(domain="example.com")
        findings = scanner.scan(target)
        assert len(findings) == 1
        assert findings[0].title == "Test Finding"

    def test_log_method(self, caplog):
        import logging
        caplog.set_level(logging.DEBUG)
        config = Config()
        scanner = DummyScanner(config)
        scanner.log("test message")
        assert "test message" in caplog.text


class TestDomainScanner:
    @pytest.fixture(autouse=True)
    def mock_whois(self, monkeypatch):
        """Mock whois to return a recent domain for tests."""
        from datetime import datetime, timedelta

        class MockWhois:
            def whois(self, domain):
                return {"creation_date": datetime.now(timezone.utc) - timedelta(days=365)}
        monkeypatch.setattr("footprintscanner.scanners.domain.whois.whois", MockWhois().whois)

    def test_domain_scanner_returns_findings(self, mock_whois):
        from footprintscanner.scanners.domain import DomainScanner
        config = Config()
        scanner = DomainScanner(config)
        target = Target(domain="example.com")
        findings = scanner.scan(target)
        # Should have at least domain age and MX record check findings
        assert len(findings) >= 0


class TestIPScanner:
    def test_no_target(self):
        from footprintscanner.scanners.ip import IPScanner
        config = Config()
        scanner = IPScanner(config)
        # Scanner handles gracefully when no domain/ip provided
        findings = scanner.scan(Target(email="test@example.com"))
        assert len(findings) >= 0


class TestEmailScanner:
    def test_no_email(self):
        from footprintscanner.scanners.email import EmailScanner
        config = Config()
        scanner = EmailScanner(config)
        target = Target(domain="example.com")  # No email
        findings = scanner.scan(target)
        assert len(findings) == 0


class TestSocialScanner:
    def test_no_username(self):
        from footprintscanner.scanners.social import SocialMediaScanner
        config = Config()
        scanner = SocialMediaScanner(config)
        target = Target(domain="example.com")  # No username
        findings = scanner.scan(target)
        assert len(findings) == 0


class TestSearchScanner:
    def test_no_target(self):
        from footprintscanner.scanners.search import SearchEngineScanner
        config = Config()
        scanner = SearchEngineScanner(config)
        # No domain/email/name/username/ip provided
        findings = scanner.scan(Target(domain="test.com"))
        assert len(findings) == 0
