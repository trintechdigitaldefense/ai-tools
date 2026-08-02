"""Tests for remediation engine."""

import pytest

from footprintscanner.models import Finding, Severity, ScannerCategory
from footprintscanner.remediation import RemediationEngine


class TestRemediationEngine:
    def test_generate_report_empty(self):
        report = RemediationEngine.generate_report([])
        assert len(report) == 0

    def test_generate_report_critical(self):
        findings = [
            Finding(
                category=ScannerCategory.EMAIL,
                title="Email in Data Breaches",
                description="Email found in breach",
                severity=Severity.CRITICAL,
                remediation="Change passwords immediately.",
            ),
        ]
        report = RemediationEngine.generate_report(findings)
        assert len(report) == 1
        assert report[0]["severity"] == "CRITICAL"
        assert report[0]["count"] == 1

    def test_generate_report_multiple_severities(self):
        findings = [
            Finding(category=ScannerCategory.EMAIL, title="A", description="", severity=Severity.CRITICAL),
            Finding(category=ScannerCategory.EMAIL, title="B", description="", severity=Severity.HIGH),
            Finding(category=ScannerCategory.EMAIL, title="C", description="", severity=Severity.MEDIUM),
            Finding(category=ScannerCategory.EMAIL, title="D", description="", severity=Severity.LOW),
        ]
        report = RemediationEngine.generate_report(findings)
        severities = [r["severity"] for r in report]
        assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_executive_actions(self):
        report = [
            {"severity": "CRITICAL", "specific_actions": ["Fix breach"]},
            {"severity": "HIGH", "specific_actions": []},
        ]
        actions = RemediationEngine.generate_executive_actions(report)
        assert "Priority Remediation Actions:" in actions[0]
        assert "Fix breach" in actions[1]

    def test_next_steps(self):
        report = [
            {"severity": "CRITICAL", "count": 2},
            {"severity": "HIGH", "count": 1},
        ]
        steps = RemediationEngine.generate_next_steps(report, "test.com")
        assert "test.com" in steps[0]
        assert "critical" in steps[1].lower()
        assert "follow-up" in steps[-1].lower()
