"""Remediation recommendations engine."""

from __future__ import annotations

from footprintscanner.models import Finding, Severity


# Remediation templates for common findings
REMEDIATION_TEMPLATES = {
    "CRITICAL": {
        "header": "🔴 CRITICAL — Immediate Action Required",
        "urgency": "These issues must be resolved immediately to prevent active exploitation.",
        "actions": [
            "Isolate affected systems if active compromise is suspected.",
            "Change all passwords and API keys that may be exposed.",
            "Enable multi-factor authentication (MFA) on all accounts.",
            "Contact your security team or incident response provider.",
            "Document all affected systems and begin investigation.",
        ],
    },
    "HIGH": {
        "header": "🟠 HIGH — Address Within 24-48 Hours",
        "urgency": "These issues create significant risk and should be addressed promptly.",
        "actions": [
            "Prioritize remediation in your next sprint.",
            "Assign ownership to specific team members.",
            "Monitor affected systems for signs of exploitation.",
            "Review access logs for unauthorized activity.",
        ],
    },
    "MEDIUM": {
        "header": "🟡 MEDIUM — Address Within 1 Week",
        "urgency": "These issues weaken your security posture and should be fixed soon.",
        "actions": [
            "Add to your security improvement backlog.",
            "Plan remediation in the next development cycle.",
            "Monitor for changes that could elevate risk.",
        ],
    },
    "LOW": {
        "header": "🔵 LOW — Address Within 30 Days",
        "urgency": "These are minor issues that improve security when addressed.",
        "actions": [
            "Include in regular maintenance tasks.",
            "Address during routine security reviews.",
            "Consider as part of ongoing security hygiene.",
        ],
    },
}

# Specific remediation guidance for common finding titles
SPECIFIC_REMEDIATIONS = {
    "No SPF Record": "Add SPF record: v=spf1 include:_yourprovider.com ~all",
    "No DMARC Record": "Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
    "No DKIM": "Contact your email provider to enable DKIM signing.",
    "Domain Expired": "Renew domain immediately. Enable auto-renewal and registrar MFA.",
    "Certificate Expired": "Renew TLS certificate. Set up auto-renewal with Let's Encrypt.",
    "WHOIS Information Exposed": "Enable WHOIS privacy through your domain registrar.",
    "DNSSEC Not Configured": "Enable DNSSEC at your domain registrar.",
}


class RemediationEngine:
    """Generate prioritized remediation recommendations."""

    @classmethod
    def generate_report(cls, findings: list[Finding]) -> list[dict]:
        """Generate a prioritized remediation report."""
        by_severity: dict[str, list[Finding]] = {}
        for f in findings:
            by_severity.setdefault(f.severity.value, []).append(f)

        report = []

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            template = REMEDIATION_TEMPLATES.get(severity, {})
            if severity not in by_severity:
                continue

            severity_findings = by_severity[severity]

            # Get specific remediations for top issues
            specific_actions = []
            for f in severity_findings[:5]:  # Top 5 per severity
                specific = cls._get_specific_remediation(f)
                if specific and specific not in specific_actions:
                    specific_actions.append(specific)

            report.append({
                "severity": severity,
                "header": template.get("header", severity),
                "urgency": template.get("urgency", ""),
                "actions": template.get("actions", []),
                "specific_actions": specific_actions,
                "count": len(severity_findings),
                "findings": [
                    {
                        "title": f.title,
                        "description": f.description,
                        "remediation": getattr(f, "remediation", "") or "",
                    }
                    for f in severity_findings
                ],
            })

        return report

    @staticmethod
    def _get_specific_remediation(finding: Finding) -> str | None:
        """Get specific remediation guidance for a finding."""
        title_lower = finding.title.lower()

        for key, value in SPECIFIC_REMEDIATIONS.items():
            if key.lower() in title_lower:
                return value

        return getattr(finding, "remediation", None)

    @classmethod
    def generate_executive_actions(cls, report: list[dict]) -> list[str]:
        """Generate top-level executive actions."""
        actions = []

        # Find all unique specific remediations
        all_specific = []
        for section in report:
            all_specific.extend(section.get("specific_actions", []))

        if all_specific:
            actions.append("Priority Remediation Actions:")
            for i, action in enumerate(all_specific, 1):
                actions.append(f"  {i}. {action}")

        # General recommendations
        general = [
            "Implement a vulnerability management program.",
            "Conduct regular security assessments (quarterly minimum).",
            "Train employees on security awareness.",
            "Maintain an incident response plan.",
            "Monitor for new exposures regularly.",
        ]

        if any(s["severity"] in ("CRITICAL", "HIGH") for s in report):
            actions.append("\nGeneral Security Recommendations:")
            actions.extend(general)

        return actions

    @classmethod
    def generate_next_steps(cls, report: list[dict], target_name: str) -> list[str]:
        """Generate actionable next steps for the target."""
        steps = [
            f"Review and address all {len(report)} remediation categories for {target_name}.",
        ]

        critical_count = sum(s["count"] for s in report if s["severity"] == "CRITICAL")
        high_count = sum(s["count"] for s in report if s["severity"] == "HIGH")

        if critical_count > 0:
            steps.append(
                f"\n  🔴 IMMEDIATE: Address {critical_count} critical issue(s) within 24 hours."
            )
        if high_count > 0:
            steps.append(
                f"  🟠 URGENT: Address {high_count} high-priority issue(s) within 48 hours."
            )

        medium_count = sum(s["count"] for s in report if s["severity"] == "MEDIUM")
        if medium_count > 0:
            steps.append(
                f"  🟡 PLAN: Address {medium_count} medium-priority issue(s) within 1 week."
            )

        steps.append(
            "  Schedule a follow-up scan after remediation to verify fixes."
        )

        return steps
