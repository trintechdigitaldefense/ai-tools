"""PDF report generator with executive summary and remediation guidance."""

from __future__ import annotations

import io
import textwrap
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.doctemplate import NextPageTemplate

from footprintscanner.models import Finding, ScanResult, Severity
from footprintscanner.reputation import RiskScorer, PriorityList
from footprintscanner.remediation import RemediationEngine


# Custom color palette — professional, accessible
COLORS = {
    "CRITICAL": (1.0, 0.2, 0.2),       # Red
    "HIGH": (1.0, 0.55, 0.0),           # Orange
    "MEDIUM": (1.0, 0.85, 0.0),         # Yellow
    "LOW": (0.2, 0.6, 1.0),             # Blue
    "INFO": (0.5, 0.5, 0.55),           # Gray
    "DARK": (0.08, 0.12, 0.18),         # Dark navy
    "LIGHT_BG": (0.97, 0.97, 0.98),     # Light gray
    "WHITE": (1.0, 1.0, 1.0),
    "BORDER": (0.85, 0.85, 0.87),
}

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 0.75 * inch
LEFT_MARGIN = MARGIN
RIGHT_MARGIN = MARGIN
TOP_MARGIN = MARGIN
BOTTOM_MARGIN = MARGIN


class PDFGenerator:
    """Generate professional security audit PDF reports."""

    def __init__(self, result: ScanResult):
        self.result = result
        self.risk_summary = RiskScorer.generate_summary(result)
        self.remediation_report = RemediationEngine.generate_report(result.findings)
        self.styles = getSampleStyleSheet()
        self.pages: list = []

    def generate(self) -> bytes:
        """Generate the full PDF and return as bytes."""
        import io
        buffer = io.BytesIO()

        doc = BaseDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=LEFT_MARGIN,
            rightMargin=RIGHT_MARGIN,
            topMargin=TOP_MARGIN,
            bottomMargin=BOTTOM_MARGIN,
        )

        # Define pages with different header styles
        cover_frame = Frame(
            LEFT_MARGIN, TOP_MARGIN,
            PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN,
            PAGE_HEIGHT - TOP_MARGIN - BOTTOM_MARGIN,
            id="cover",
        )

        content_frame = Frame(
            LEFT_MARGIN, BOTTOM_MARGIN + 0.5 * inch,
            PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN,
            PAGE_HEIGHT - TOP_MARGIN - BOTTOM_MARGIN - 0.5 * inch,
            id="content",
        )

        doc.addPageTemplates([
            PageTemplate(id="cover", frames=cover_frame, onPage=lambda c, d: self._canvas_decorator(c, d) or self._cover_page_header(c, d)),
            PageTemplate(id="content", frames=content_frame, onPage=lambda c, d: self._canvas_decorator(c, d) or self._content_page_header(c, d)),
        ])

        # Build story
        story: list = []

        # Cover page
        story.extend(self._build_cover_page())
        story.append(NextPageTemplate("content"))

        # Table of contents
        story.extend(self._build_table_of_contents())

        # Executive Summary
        story.extend(self._build_executive_summary())

        # Detailed Findings
        story.extend(self._build_detailed_findings())

        # Remediation Plan
        story.extend(self._build_remediation_plan())

        # Build the document
        doc.build(story)

        return buffer.getvalue()

    def _canvas_decorator(self, canvas, doc):
        """Canvas decorator for page numbers and header decorations."""
        canvas.saveState()
        # Page number at bottom center
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.Color(0.5, 0.5, 0.55, alpha=0.6))
        canvas.drawCentredString(PAGE_WIDTH / 2, 0.4 * inch,
                                 f"Page {doc.page} — FootprintScanner Audit Report")
        # Thin line at bottom
        canvas.setStrokeColor(COLORS["BORDER"])
        canvas.setLineWidth(0.5)
        canvas.line(LEFT_MARGIN, 0.5 * inch, PAGE_WIDTH - RIGHT_MARGIN, 0.5 * inch)
        canvas.restoreState()

    def _cover_page_header(self, canvas, doc):
        canvas.saveState()
        canvas.restoreState()

    def _content_page_header(self, canvas, doc):
        canvas.saveState()
        # Branding bar at top
        canvas.setFillColor(COLORS["DARK"])
        canvas.rect(0, PAGE_HEIGHT - 0.5 * inch, PAGE_WIDTH, 0.5 * inch, fill=1, stroke=0)

        # Title
        canvas.setFillColor(colors.Color(1, 1, 1))
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(LEFT_MARGIN, PAGE_HEIGHT - 0.32 * inch,
                          "FootprintScanner — Digital Footprint Audit Report")

        # Page number
        canvas.drawRightString(PAGE_WIDTH - RIGHT_MARGIN, PAGE_HEIGHT - 0.32 * inch,
                               f"Page {doc.page}")
        canvas.restoreState()

    def _build_cover_page(self) -> list:
        """Build the cover page."""
        story = []

        # Spacer to push title down
        story.append(Spacer(1, 2.5 * inch))

        # Title
        story.append(Paragraph(
            "Digital Footprint<br/>Audit Report",
            ParagraphStyle(
                "CoverTitle",
                parent=self.styles["Title"],
                fontSize=36,
                textColor=COLORS["DARK"],
                spaceAfter=12,
                fontName="Helvetica-Bold",
            ),
        ))

        story.append(Spacer(1, 12))

        # Subtitle
        target_name = self.result.target.name or self.result.target.domain or "Unknown Target"
        story.append(Paragraph(
            f"Target: {target_name}",
            ParagraphStyle(
                "CoverSubtitle",
                parent=self.styles["Normal"],
                fontSize=18,
                textColor=colors.Color(0.4, 0.4, 0.5),
                spaceAfter=24,
            ),
        ))

        story.append(Spacer(1, 20))

        # Risk level badge
        risk_level = self.risk_summary["risk_level"]
        risk_score = self.risk_summary["risk_score"]
        color_map = {
            "CRITICAL": (1.0, 0.2, 0.2),
            "HIGH": (1.0, 0.55, 0.0),
            "MEDIUM": (1.0, 0.85, 0.0),
            "LOW": (0.2, 0.6, 1.0),
            "MINIMAL": (0.2, 0.7, 0.3),
        }

        story.append(Paragraph(
            f"<b>Risk Score:</b> {risk_score}/100  |  <b>Level:</b> "
            f"<font color='{self._hex_color(color_map.get(risk_level, (0.5, 0.5, 0.5)))}'>"
            f"{' '.join(risk_level.lower().capitalize() for _ in [1]) or risk_level.lower().capitalize()}"
            f"</font>",
            ParagraphStyle("CoverRisk", parent=self.styles["Normal"], fontSize=14),
        ))

        story.append(Spacer(1, 30))

        # Scan details
        report_date = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
        scan_info = [
            ("Report Date:", report_date),
            ("Scanner Version:", "0.1.0"),
            ("Scan Duration:", self.result.time_to_complete()),
            ("Total Findings:", str(self.risk_summary["total_findings"])),
        ]

        info_data = [
            [
                Paragraph(f"<b>{label}</b>", self.styles["Normal"]),
                Paragraph(value, self.styles["Normal"]),
            ]
            for label, value in scan_info
        ]
        info_table = Table(info_data, colWidths=[150, 300])
        info_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(info_table)

        story.append(Spacer(1, 60))

        # Confidentiality notice
        story.append(Paragraph(
            "CONFIDENTIAL — This report contains sensitive security information. "
            "Handle according to your organization's data protection policies.",
            ParagraphStyle(
                "Confidential",
                parent=self.styles["Normal"],
                fontSize=9,
                textColor=colors.Color(0.6, 0.2, 0.2),
                fontName="Helvetica-Oblique",
            ),
        ))

        return story

    def _hex_color(self, color) -> str:
        if isinstance(color, str):
            return color
        r, g, b = color
        return f"#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}"

    def _build_table_of_contents(self) -> list:
        """Build table of contents."""
        story = []

        story.append(Paragraph(
            "Table of Contents",
            ParagraphStyle("TOC_Title", parent=self.styles["Heading1"],
                           fontSize=22, textColor=COLORS["DARK"], spaceAfter=20),
        ))

        toc_items = [
            ("Executive Summary", "Overview of security posture"),
            ("Detailed Findings", "All findings organized by severity"),
            ("Remediation Plan", "Actionable steps to address issues"),
            ("Appendix", "Technical details and references"),
        ]

        for title, desc in toc_items:
            story.append(Paragraph(
                f"<b>{title}</b> — {desc}",
                ParagraphStyle("TOC_Item", parent=self.styles["Normal"],
                               fontSize=12, spaceAfter=8),
            ))

        story.append(NextPageTemplate("content"))
        story.append(Spacer(1, 0.5 * inch))
        return story

    def _build_executive_summary(self) -> list:
        """Build the executive summary section."""
        story = []

        story.append(Paragraph(
            "Executive Summary",
            ParagraphStyle("SectionTitle", parent=self.styles["Heading1"],
                           fontSize=22, textColor=COLORS["DARK"], spaceAfter=16),
        ))

        story.append(Spacer(1, 0.1 * inch))

        # Risk score bar
        score = self.risk_summary["risk_score"]
        max_bar_width = 4 * inch

        # Color gradient based on score
        from reportlab.lib.colors import Color
        if score < 25:
            bar_color = colors.Color(0.2, 0.7, 0.3)
        elif score < 50:
            bar_color = colors.Color(0.6, 0.85, 0.2)
        elif score < 75:
            bar_color = colors.Color(1.0, 0.85, 0.0)
        else:
            bar_color = colors.Color(1.0, 0.2, 0.2)

        story.append(Paragraph(
            f"Overall Risk Score",
            ParagraphStyle("BarLabel", parent=self.styles["Normal"],
                           fontSize=13, textColor=COLORS["DARK"],
                           spaceAfter=6),
        ))

        bar_table = Table(
            [[Paragraph("", ParagraphStyle(
                "Bar", fontSize=1, leading=20, spaceBefore=0, spaceAfter=0,
                textColor=bar_color,
            ))]],
            colWidths=[max_bar_width],
        )
        bar_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bar_color),
            ("LINEBELOW", (0, 0), (-1, -1), 0, colors.white),
        ]))
        story.append(bar_table)

        story.append(Paragraph(
            f"<b>{score}</b> / 100",
            ParagraphStyle("BarScore", parent=self.styles["Normal"],
                           fontSize=14, spaceAfter=24),
        ))

        # Key stats table
        findings = self.risk_summary["by_severity"]
        stats_data = [
            ["Finding Type", "Count", "Status"],
            ["Critical", str(findings.get("CRITICAL", 0)),
             "🔴 Immediate Action"],
            ["High", str(findings.get("HIGH", 0)),
             "🟠 Urgent"],
            ["Medium", str(findings.get("MEDIUM", 0)),
             "🟡 Important"],
            ["Low", str(findings.get("LOW", 0)),
             "🔵 Minor"],
            ["Informational", str(findings.get("INFO", 0)),
             "ℹ️ FYI"],
        ]

        stats_table = Table(stats_data, colWidths=[120, 60, 200])
        stats_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLORS["DARK"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 11),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), COLORS["LIGHT_BG"]),
            ("GRID", (0, 0), (-1, -1), 0.5, COLORS["BORDER"]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 16))

        # Key insight paragraph
        target_name = self.result.target.name or self.result.target.domain or "this target"
        insight = f"""\
<b>Assessment for {target_name}:</b> This digital footprint audit has identified
{self.risk_summary['total_findings']} findings across {len(self.risk_summary['by_category'])}
categories. With a risk score of <b>{score}/100</b> (Level: <b>{self.risk_summary['risk_level']}</b>),
this{' requires' if self.risk_summary['has_critical'] else ' presents'}{' immediate attention' if self.risk_summary['has_critical'] else ' opportunities for improvement'}.
The findings below provide specific, actionable recommendations to address each issue.
"""

        story.append(Paragraph(insight, ParagraphStyle(
            "ExecutiveText", parent=self.styles["Normal"],
            fontSize=11, leading=16, spaceAfter=16,
        )))

        # Most important findings
        if self.risk_summary["has_critical"] or self.risk_summary["has_high"]:
            priority_findings = PriorityList.high_priority(self.result.findings)[:5]
            if priority_findings:
                story.append(Paragraph(
                    "<b>Most Critical Findings</b>",
                    ParagraphStyle("SubSection", parent=self.styles["Heading2"],
                                   fontSize=16, spaceAfter=10),
                ))

                for f in priority_findings:
                    story.append(Paragraph(
                        f"{f.severity.color} <b>{f.title}</b>",
                        ParagraphStyle("PriorityItem", parent=self.styles["Normal"],
                                       fontSize=11, spaceAfter=4),
                    ))
                    story.append(Paragraph(
                        textwrap.shorten(f.description, 500, placeholder="..."),
                        ParagraphStyle("PriorityDesc", parent=self.styles["Normal"],
                                       fontSize=10, textColor=colors.Color(0.3, 0.3, 0.35),
                                       spaceAfter=8, leftIndent=12),
                    ))

        return story

    def _build_detailed_findings(self) -> list:
        """Build the detailed findings section."""
        story = []

        story.append(Paragraph(
            "Detailed Findings",
            ParagraphStyle("SectionTitle", parent=self.styles["Heading1"],
                           fontSize=22, textColor=COLORS["DARK"], spaceAfter=16),
        ))

        # Group by severity
        by_severity: dict[str, list[Finding]] = {}
        for f in self.result.findings:
            by_severity.setdefault(f.severity.value, []).append(f)

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        for severity in severity_order:
            if severity not in by_severity:
                continue

            severity_findings = by_severity[severity]
            color = COLORS.get(severity, COLORS["INFO"])

            story.append(Paragraph(
                f"{severity_findings[0].severity.color} {severity} Findings ({len(severity_findings)})",
                ParagraphStyle("SeverityHeader", parent=self.styles["Heading2"],
                               fontSize=16, textColor=color, spaceAfter=12),
            ))

            for f in severity_findings:
                # Finding card
                card_data = [
                    [Paragraph(f"<b>{f.title}</b>", ParagraphStyle(
                        "FindingTitle", parent=self.styles["Normal"],
                        fontSize=12, spaceAfter=4))],
                    [Paragraph(f"<b>Category:</b> {f.category.value}  "
                               f"<b>Severity:</b> {f.severity.value}", ParagraphStyle(
                        "FindingMeta", parent=self.styles["Normal"],
                        fontSize=9, textColor=colors.Color(0.4, 0.4, 0.5)))],
                    [Paragraph(f.description, ParagraphStyle(
                        "FindingDesc", parent=self.styles["Normal"],
                        fontSize=10, leading=14))],
                ]

                if getattr(f, "remediation", None):
                    card_data.append([Paragraph(
                        f"<b>Recommended Action:</b> {getattr(f, "remediation", "")}",
                        ParagraphStyle("FindingRem", parent=self.styles["Normal"],
                                       fontSize=10, textColor=colors.Color(0.1, 0.45, 0.15),
                                       backColor=colors.Color(0.95, 1.0, 0.95)),
                    )])

                card_table = Table(card_data, colWidths=[PAGE_WIDTH - 2 * LEFT_MARGIN])
                card_table.setStyle(TableStyle([
                    ("BOX", (0, 0), (-1, -1), 0.5, COLORS["BORDER"]),
                    ("BACKGROUND", (0, 0), (-1, 0), COLORS["LIGHT_BG"]),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
                    ("TOPPADDING", (0, 1), (-1, 1), 2),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 4),
                    ("TOPPADDING", (0, 2), (-1, 2), 4),
                    ("BOTTOMPADDING", (0, 2), (-1, 2), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))

                story.append(card_table)
                story.append(Spacer(1, 8))

        return story

    def _build_remediation_plan(self) -> list:
        """Build the remediation plan section."""
        story = []

        story.append(Paragraph(
            "Remediation Plan",
            ParagraphStyle("SectionTitle", parent=self.styles["Heading1"],
                           fontSize=22, textColor=COLORS["DARK"], spaceAfter=16),
        ))

        next_steps = RemediationEngine.generate_next_steps(
            self.remediation_report,
            self.result.target.name or self.result.target.domain or "this target"
        )

        for step in next_steps:
            story.append(Paragraph(
                step,
                ParagraphStyle("Step", parent=self.styles["Normal"],
                               fontSize=11, spaceAfter=6, bulletIndent=10),
            ))

        story.append(Spacer(1, 16))

        for section in self.remediation_report:
            if section["severity"] in ("INFO",):
                continue

            story.append(Paragraph(
                section["header"],
                ParagraphStyle("RemediationHeader", parent=self.styles["Heading3"],
                               fontSize=14, spaceAfter=6),
            ))

            story.append(Paragraph(
                section["urgency"],
                ParagraphStyle("RemediationUrgency", parent=self.styles["Normal"],
                               fontSize=10, textColor=colors.Color(0.3, 0.3, 0.4),
                               spaceAfter=8, fontName="Helvetica-Oblique"),
            ))

            # Specific actions
            if section.get("specific_actions"):
                for action in section["specific_actions"]:
                    story.append(Paragraph(
                        f"• {action}",
                        ParagraphStyle("SpecificAction", parent=self.styles["Normal"],
                                       fontSize=10, leftIndent=20, spaceAfter=3),
                    ))

            # Check all actions
            for action in section.get("actions", []):
                story.append(Paragraph(
                    f"☐ {action}",
                    ParagraphStyle("CheckAction", parent=self.styles["Normal"],
                                   fontSize=10, leftIndent=20, spaceAfter=2),
                ))

            story.append(Spacer(1, 8))

        # Appendix
        story.append(Spacer(1, 24))
        story.append(Paragraph(
            "Appendix — Scanner Error Log",
            ParagraphStyle("SectionTitle", parent=self.styles["Heading1"],
                           fontSize=22, textColor=COLORS["DARK"], spaceAfter=16),
        ))

        if self.result.scanner_errors:
            for error in self.result.scanner_errors:
                story.append(Paragraph(
                    f"⚠️ {error}",
                    ParagraphStyle("Error", parent=self.styles["Normal"],
                                   fontSize=10, textColor=colors.Color(0.6, 0.3, 0.3),
                                   spaceAfter=4),
                ))
        else:
            story.append(Paragraph(
                "No scanner errors occurred during this audit.",
                ParagraphStyle("NoErrors", parent=self.styles["Normal"],
                               fontSize=11, spaceAfter=8),
            ))

        # Footer note
        story.append(Spacer(1, 24))
        story.append(Paragraph(
            "This report was generated by FootprintScanner v0.1.0.\n"
            "For questions or additional analysis, consult your security team.",
            ParagraphStyle("Footer", parent=self.styles["Normal"],
                           fontSize=9, textColor=colors.Color(0.5, 0.5, 0.55),
                           fontName="Helvetica-Oblique", alignment=2),
        ))

        return story
