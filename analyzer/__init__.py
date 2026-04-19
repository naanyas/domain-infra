"""
Vendored SDAT domain analyzer.

Source: github.com/jenna43008/testing-breaks (at time of vendoring).
Used as the engine behind domain_scans within a submission.

Do not modify the vendored modules directly — re-vendor from the source of truth.
The only local change is converting absolute imports to relative imports so the
analyzer works as a Python package.
"""
from .analyzer import (
    analyze_domain,
    DomainApprovalResult,
    ANALYZER_VERSION,
    calculate_score,
)
from .config import DEFAULT_CONFIG, load_config

__all__ = [
    "analyze_domain",
    "DomainApprovalResult",
    "ANALYZER_VERSION",
    "calculate_score",
    "DEFAULT_CONFIG",
    "load_config",
]
