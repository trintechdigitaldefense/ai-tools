"""FootprintScanner CLI — Digital footprint scanning and PDF report generation."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from colorama import Fore, Style, init as colorama_init
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .config import Config
from .models import Severity, Target
from .scanner import FootprintScanner

console = Console()
colorama_init()


def cli():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="footprintscanner",
        description="Digital Footprint Scanner — Scan the clearnet for your digital footprint and generate actionable PDF audit reports",
        epilog="Examples:\n"
               "  footprintscanner --domain example.com\n"
               "  footprintscanner --domain example.com --email admin@example.com\n"
               "  footprintscanner --email john@example.com --name \"John Doe\"\n"
               "  footprintscanner --help\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--domain", "-d", help="Domain to scan (e.g., example.com)")
    parser.add_argument("--email", "-e", help="Email address to scan")
    parser.add_argument("--name", "-n", help="Person's name to search for")
    parser.add_argument("--username", "-u", help="Social media username to check")
    parser.add_argument("--ip", help="IP address to analyze")
    parser.add_argument("--output", "-o", default="footprint_reports", help="Output directory for reports (default: footprint_reports)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--quick", action="store_true", help="Quick scan (fewer checks, faster)")

    args = parser.parse_args()

    # Validate input
    if not any([args.domain, args.email, args.name, args.username, args.ip]):
        console.print(f"{Fore.RED}Error: Provide at least one target (--domain, --email, --name, --username, or --ip){Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    config = Config.load()
    config.output_dir = Path(args.output)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    # Create target
    target = Target(
        domain=args.domain or "",
        email=args.email or "",
        name=args.name or args.domain or args.email or "Target",
        social_username=args.username or "",
        ip=args.ip or "",
    )

    # Run scan
    scanner = FootprintScanner(config)

    if args.quick:
        result = asyncio.run(scanner.scan_quick(target.domain))
    else:
        result = asyncio.run(scanner.scan(target))

    if args.json:
        _print_json_result(result)
    else:
        _print_cli_result(result, args.verbose)

    # Generate PDF
    pdf_path = _save_report(result, args.output)
    console.print(f"\n{Fore.GREEN}✓ PDF report saved to: {pdf_path}{Style.RESET_ALL}")

    # Exit code based on severity
    if result.critical_count > 0:
        sys.exit(2)
    elif result.high_count > 0:
        sys.exit(1)


def _print_cli_result(result: "ScanResult", verbose: bool):
    """Print results to the CLI with rich formatting."""
    from .reputation import RiskScorer

    summary = RiskScorer.generate_summary(result)

    # Header
    console.print()
    console.print(f"[bold magenta]╔══════════════════════════════════════════╗")
    console.print(f"[bold magenta]║       Digital Footprint Scan Results      ║")
    console.print(f"[bold magenta]╚══════════════════════════════════════════╝[/bold magenta]")
    console.print()

    target_str = result.target.name or result.target.domain or result.target.email or "Target"
    console.print(f"  [bold]Target:[/bold] {target_str}")
    console.print(f"  [bold]Started:[/bold] {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if result.completed_at:
        console.print(f"  [bold]Completed:[/bold] {result.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    console.print(f"  [bold]Duration:[/bold] {result.time_to_complete()}")
    console.print()

    # Risk score
    risk_level = summary["risk_level"]
    risk_color = {
        "CRITICAL": "red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "MINIMAL": "green",
    }.get(risk_level, "white")

    console.print(
        f"  [bold]Risk Score:[/bold] {summary['risk_score']}/100  "
        f"[bold]{risk_level}[/bold]  "
        f"[dim]({summary['total_findings']} findings)[/dim]"
    )
    console.print()

    # Severity breakdown
    if verbose:
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Severity", style="dim", width=12)
        table.add_column("Count", style="bold", width=6)
        table.add_column("Details", width=50)

        by_sev = summary["by_severity"]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = by_sev.get(sev, 0)
            color_map = {
                "CRITICAL": "red", "HIGH": "red",
                "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim",
            }
            if count > 0:
                table.add_row(
                    f"[{color_map.get(sev, 'white')}]{'.' * count}{sev[:4]}[/]",
                    str(count),
                    sev,
                )

        console.print(table)
        console.print()

    # Category breakdown
    if verbose:
        console.print(f"  [bold]By Category:[/bold]")
        for cat, count in summary.get("by_category", {}).items():
            console.print(f"    • {cat}: {count}")
        console.print()

    # Top findings
    priority = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if priority:
        console.print(f"  [bold red]⚠  Top Priority Findings ({len(priority)})[/]")
        for f in priority[:5]:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(f.severity.value, "⚠")
            console.print(f"    {icon} [bold]{f.title}[/] [dim]({f.category.value})[/dim]")
            # Shorten description for display
            desc = f.description[:200].replace("\n", " ")
            console.print(f"      {desc}")
            if getattr(f, "remediation", None):
                rem = getattr(f, "remediation", "")[:150].replace("\n", " ")
                console.print(f"      [green]→ {rem}[/]")
            console.print()

    # Errors
    if result.scanner_errors:
        console.print(f"  [bold yellow]⚠ Scanner Errors ({len(result.scanner_errors)})[/]")
        for err in result.scanner_errors[:5]:
            console.print(f"    [yellow]• {err}[/]")
        console.print()


def _print_json_result(result: "ScanResult"):
    """Print results as JSON."""
    from .reputation import RiskScorer

    summary = RiskScorer.generate_summary(result)
    output = {
        "target": {
            "domain": result.target.domain,
            "email": result.target.email,
            "name": result.target.name,
        },
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "risk_score": summary["risk_score"],
        "risk_level": summary["risk_level"],
        "total_findings": summary["total_findings"],
        "by_severity": summary["by_severity"],
        "by_category": summary.get("by_category", {}),
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in sorted(result.findings, key=lambda x: x.severity.priority)
        ],
        "scanner_errors": result.scanner_errors,
    }
    console.print(json.dumps(output, indent=2))


def _save_report(result: "ScanResult", output_dir: str) -> str:
    """Generate and save the PDF report."""
    from .reports.pdf_generator import PDFGenerator

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    target_str = (result.target.name or result.target.domain or "target").replace("/", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    pdf_file = out_path / f"audit_{target_str}_{timestamp}.pdf"

    pdf_bytes = PDFGenerator(result).generate()
    pdf_file.write_bytes(pdf_bytes)

    return str(pdf_file)


if __name__ == "__main__":
    cli()
