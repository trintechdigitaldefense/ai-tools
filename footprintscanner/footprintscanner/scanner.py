"""Scanner orchestrator — runs all scanners in parallel."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from footprintscanner.config import Config
from footprintscanner.models import Finding, ScanResult, Target
from footprintscanner.reports.pdf_generator import PDFGenerator
from footprintscanner.scanners.domain import DomainScanner
from footprintscanner.scanners.email import EmailScanner
from footprintscanner.scanners.dns import DNSAnalyzer
from footprintscanner.scanners.security_headers import SecurityHeadersScanner
from footprintscanner.scanners.social import SocialMediaScanner
from footprintscanner.scanners.search import SearchEngineScanner
from footprintscanner.scanners.ip import IPScanner
from footprintscanner.scanners.certificate import CertificateScanner

logger = logging.getLogger("footprintscanner.scanner")

# Map which scanners apply to which target types
SCANNER_MAP = {
    "domain": [DomainScanner, DNSAnalyzer, CertificateScanner, SecurityHeadersScanner, SearchEngineScanner, IPScanner],
    "email": [EmailScanner, SearchEngineScanner],
    "social_username": [SocialMediaScanner],
    "name": [SearchEngineScanner],
    "ip": [IPScanner, CertificateScanner, SecurityHeadersScanner],
}


class FootprintScanner:
    """Main orchestrator — runs all scanners against a target."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()

    async def scan(self, target: Target) -> ScanResult:
        """Run a full scan against a target."""
        result = ScanResult(target=target)
        logger.info("Starting scan for %s", target.domain or target.email or target.social_username or target.ip)

        # Determine which scanners to run
        scanners_to_run: list[type] = []
        for scanner_type, scanner_list in SCANNER_MAP.items():
            value = getattr(target, scanner_type)
            if value:
                scanners_to_run.extend(scanner_list)

        # Remove duplicates while preserving order
        seen = set()
        unique_scanners = []
        for s in scanners_to_run:
            if s not in seen:
                seen.add(s)
                unique_scanners.append(s)

        # Initialize scanner instances
        scanner_instances: list = []
        for scanner_cls in unique_scanners:
            instance = scanner_cls(self.config)
            scanner_instances.append(instance)

        logger.info("Running %d scanners", len(scanner_instances))

        # Run all scanners concurrently
        async def _run_scanner(cls_instance):
            try:
                findings = await asyncio.to_thread(cls_instance.scan, target)
                return findings, None
            except Exception as e:
                return [], f"Scanner '{cls_instance.name}' failed: {e}"

        tasks = [_run_scanner(s) for s in scanner_instances]
        results = await asyncio.gather(*tasks)

        # Aggregate results
        for findings, error in results:
            if error:
                result.add_error(error)
                logger.warning(error)
            for finding in findings:
                result.add_finding(finding)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            "Scan complete: %d findings, %d errors",
            len(result.findings),
            len(result.scanner_errors),
        )

        return result

    def generate_report(self, result: ScanResult) -> bytes:
        """Generate a PDF report from scan results."""
        return PDFGenerator(result).generate()

    async def scan_quick(self, domain: str) -> ScanResult:
        """Quick scan focusing on the most impactful checks."""
        target = Target(domain=domain)
        return await self.scan(target)
