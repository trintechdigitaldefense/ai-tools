"""Risk scoring engine — classifies findings by severity and calculates aggregate risk."""

from __future__ import annotations

from footprintscanner.models import Finding, Severity, ScanResult


class RiskScorer:
    """Calculate risk scores and classify threat levels."""

    # Base weights for each severity
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0,
    }

    # Category multipliers (certain categories are more critical)
    CATEGORY_MULTIPLIERS = {
        "Breaches": 1.5,
        "Security Headers": 1.3,
        "Domain & DNS": 1.2,
        "Email": 1.4,
        "IP & Network": 1.1,
        "SSL/TLS Certificate": 1.3,
        "Social Media": 0.8,
        "Search Engine": 0.6,
    }

    # Thresholds
    THRESHOLDS = {
        "CRITICAL": 75,
        "HIGH": 50,
        "MEDIUM": 25,
        "LOW": 10,
        "MINIMAL": 0,
    }

    @classmethod
    def calculate_risk_score(cls, findings: list[Finding]) -> float:
        """Calculate overall risk score (0-100)."""
        score = 0.0

        # Group by category
        by_category: dict[str, list[Finding]] = {}
        for f in findings:
            cat = f.category.value
            by_category.setdefault(cat, []).append(f)

        for category, category_findings in by_category.items():
            category_score = 0.0
            for f in category_findings:
                severity_score = cls.SEVERITY_WEIGHTS.get(f.severity, 0)
                # Diminishing returns: duplicate findings of same severity
                category_score += severity_score / max(1, category_findings.count(
                    f for f in category_findings if f.severity == f.severity
                ))

            multiplier = cls.CATEGORY_MULTIPLIERS.get(category, 1.0)
            score += category_score * multiplier

        return min(round(score, 1), 100.0)

    @classmethod
    def classify_risk(cls, score: float) -> str:
        """Convert a numeric score to a risk level."""
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
            if score >= cls.THRESHOLDS[level]:
                return level
        return "MINIMAL"

    @classmethod
    def generate_summary(cls, result: ScanResult) -> dict:
        """Generate a risk summary for the report."""
        score = cls.calculate_risk_score(result.findings)
        level = cls.classify_risk(score)

        # Count by severity
        counts = {s.value: 0 for s in Severity}
        for f in result.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        # Group by category
        by_category: dict[str, int] = {}
        for f in result.findings:
            cat = f.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        return {
            "risk_score": score,
            "risk_level": level,
            "total_findings": len(result.findings),
            "by_severity": counts,
            "by_category": by_category,
            "has_critical": counts.get("CRITICAL", 0) > 0,
            "has_high": counts.get("HIGH", 0) > 0,
            "scanner_errors": len(result.scanner_errors),
        }


class PriorityList:
    """Organize findings by priority for the executive summary."""

    @staticmethod
    def high_priority(findings: list[Finding]) -> list[Finding]:
        """Get findings that need immediate attention."""
        return [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

    @staticmethod
    def medium_priority(findings: list[Finding]) -> list[Finding]:
        """Get findings that should be addressed soon."""
        return [f for f in findings if f.severity == Severity.MEDIUM]

    @staticmethod
    def low_priority(findings: list[Finding]) -> list[Finding]:
        """Get findings for gradual improvement."""
        return [f for f in findings if f.severity in (Severity.LOW, Severity.INFO)]

    @staticmethod
    def sort_by_severity(findings: list[Finding]) -> list[Finding]:
        """Sort findings by severity (most severe first)."""
        return sorted(findings, key=lambda f: f.severity.priority)
