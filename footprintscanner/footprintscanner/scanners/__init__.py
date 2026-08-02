"""Scanners package — all scanning modules."""

from .base import BaseScanner

__all__ = [
    "BaseScanner",
    "DomainScanner",
    "EmailScanner",
    "DNSAnalyzer",
    "SecurityHeadersScanner",
    "SocialMediaScanner",
    "SearchEngineScanner",
    "IPScanner",
    "CertificateScanner",
]


def get_scanner(cls_name: str):
    """Dynamically import and return a scanner class."""
    module = __import__(f".{cls_name.lower()}", fromlist=[cls_name])
    return getattr(module, cls_name)
