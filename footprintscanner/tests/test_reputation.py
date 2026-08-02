"""Tests for reputation scoring."""

import pytest

from footprintscanner.models import Finding, ScanResult, Severity, ScannerCategory, Target
from footprintscanner.reputation import PriorityList, RiskScorer


class TestRiskScorer:
    def test_no_findings(self):
        assert RiskScorer.calculate_risk_score([]) == 0.0

    def test_critical_finding(self):
        findings = [
            Finding(category=ScannerCategory.EMAIL, title="Breach", description="", severity=Severity.CRITICAL),
        ]
        score = RiskScorer.calculate_risk_score(findings)
        assert score >= 25  # Critical base weight

    def test_multiple_findings(self):
        findings = [
            Finding(category=ScannerCategory.DOMAIN, title="A", description="", severity=Severity.HIGH),
            Finding(category="Email", title="B", description="", severity=Severity.MEDIUM),
            Finding(category="Security Headers", title="C", description="", severity=Severity.LOW),
        ]
        score = RiskScorer.calculate_risk_score(findings)
        assert score > 0
        assert score <= 100

    def test_classify_risk(self):
        assert RiskScorer.classify_risk(90) == "CRITICAL"
        assert RiskScorer.classify_risk(60) == "HIGH"
        assert RiskScorer.classify_risk(40) == "MEDIUM"
        assert RiskScorer.classify_risk(15) == "LOW"
        assert RiskScorer.classify_risk(3) == "MINIMAL"

    def test_generate_summary(self):
        r = ScanResult(target=Target(domain="example.com"))
        r.add_finding(Finding(category=ScannerCategory.EMAIL, title="A", description="", severity=Severity.CRITICAL))
        r.add_finding(Finding(category=ScannerCategory.EMAIL, title="B", description="", severity=Severity.HIGH))
        summary = RiskScorer.generate_summary(r)
        assert summary["risk_score"] > 0
        assert summary["total_findings"] == 2
        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["has_critical"] is True


class TestPriorityList:
    def test_high_priority(self):
        findings = [
            Finding(category=ScannerCategory.EMAIL, title="A", description="", severity=Severity.CRITICAL),
            Finding(category=ScannerCategory.EMAIL, title="B", description="", severity=Severity.INFO),
            Finding(category=ScannerCategory.EMAIL, title="C", description="", severity=Severity.HIGH),
        ]
        high = PriorityList.high_priority(findings)
        assert len(high) == 2
        assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in high)

    def test_sort_by_severity(self):
        findings = [
            Finding(category=ScannerCategory.EMAIL, title="A", description="", severity=Severity.LOW),
            Finding(category=ScannerCategory.EMAIL, title="B", description="", severity=Severity.CRITICAL),
            Finding(category=ScannerCategory.EMAIL, title="C", description="", severity=Severity.MEDIUM),
        ]
        sorted_f = PriorityList.sort_by_severity(findings)
        assert sorted_f[0].severity == Severity.CRITICAL
        assert sorted_f[1].severity == Severity.MEDIUM
        assert sorted_f[2].severity == Severity.LOW
