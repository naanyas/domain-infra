"""
Canonical catalog of signals + operators that can be referenced in risk-profile rules.

Exposed to the UI via GET /api/v1/signal-catalog so rule builders can offer
typed dropdowns instead of free-form strings. Every signal name the rules
engine understands MUST appear here — new signals added to the pipeline
need corresponding catalog entries.

Signal naming convention: dotted path matching the signals dict structure
built by apps.api.services._build_signals().
"""
from __future__ import annotations

# ----------------------------------------------------------------------
# Operators
# ----------------------------------------------------------------------

OPERATORS: dict[str, dict] = {
    "eq":       {"label": "equals",              "arity": 2},
    "ne":       {"label": "not equals",          "arity": 2},
    "lt":       {"label": "less than",           "arity": 2},
    "le":       {"label": "less than or equal",  "arity": 2},
    "gt":       {"label": "greater than",        "arity": 2},
    "ge":       {"label": "greater than or equal","arity": 2},
    "in":       {"label": "in list",             "arity": 2},
    "contains": {"label": "contains",            "arity": 2},
    "exists":   {"label": "exists / non-empty",  "arity": 1},
}

# Which operators are valid for which signal type. UI uses this to constrain choices.
OPERATORS_BY_TYPE: dict[str, list[str]] = {
    "number":  ["eq", "ne", "lt", "le", "gt", "ge", "exists"],
    "boolean": ["eq", "ne", "exists"],
    "string":  ["eq", "ne", "in", "contains", "exists"],
}


# ----------------------------------------------------------------------
# Signal catalog
# ----------------------------------------------------------------------
# Each entry:
#   path:        dotted signal path (used in rules as `signal`)
#   type:        number | boolean | string
#   category:    UI grouping
#   description: human-readable
#   values:      (optional) enumerated valid string values
#   phase:       which Phase populates this signal — "phase1" live today; "phase2-ip" needs IP enrichment; etc.

SIGNALS: list[dict] = [
    # ========== Domain scan (from SDAT analyzer) ==========
    {"path": "domain_scan.risk_score", "type": "number", "category": "domain",
     "description": "Analyzer risk score (0-100)", "phase": "phase1"},
    {"path": "domain_scan.risk_level", "type": "string", "category": "domain",
     "description": "Analyzer risk band", "values": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "phase": "phase1"},
    {"path": "domain_scan.recommendation", "type": "string", "category": "domain",
     "description": "Analyzer verdict string", "phase": "phase1"},
    {"path": "domain_scan.spf_exists", "type": "boolean", "category": "domain",
     "description": "SPF record present", "phase": "phase1"},
    {"path": "domain_scan.dmarc_policy", "type": "string", "category": "domain",
     "description": "DMARC policy", "values": ["reject", "quarantine", "none", ""], "phase": "phase1"},
    {"path": "domain_scan.dkim_exists", "type": "boolean", "category": "domain",
     "description": "DKIM selector found", "phase": "phase1"},
    {"path": "domain_scan.https_valid", "type": "boolean", "category": "domain",
     "description": "HTTPS cert valid", "phase": "phase1"},
    {"path": "domain_scan.cdn_provider", "type": "string", "category": "domain",
     "description": "Detected CDN (Cloudflare, Akamai, etc. or empty)", "phase": "phase1"},
    {"path": "domain_scan.mx_exists", "type": "boolean", "category": "domain",
     "description": "MX record present", "phase": "phase1"},
    {"path": "domain_scan.resolved", "type": "boolean", "category": "domain",
     "description": "Domain resolved to an IP", "phase": "phase1"},

    # ========== Contact email ==========
    {"path": "contact_email.domain", "type": "string", "category": "contact",
     "description": "Email domain (after @)", "phase": "phase1"},
    {"path": "contact_email.is_disposable", "type": "boolean", "category": "contact",
     "description": "Disposable/throwaway email provider", "phase": "phase2-email"},
    {"path": "contact_email.is_role_account", "type": "boolean", "category": "contact",
     "description": "Role account (admin@, support@, etc.)", "phase": "phase2-email"},
    {"path": "contact_email.breach_count", "type": "number", "category": "contact",
     "description": "Breach sightings (HaveIBeenPwned)", "phase": "phase2-email"},
    {"path": "contact_email.mx_reachable", "type": "boolean", "category": "contact",
     "description": "Email domain has reachable MX", "phase": "phase2-email"},

    # ========== Contact phone ==========
    {"path": "contact_phone.country_code", "type": "string", "category": "contact",
     "description": "Phone country code (e.g. +1, +44)", "phase": "phase1"},
    {"path": "contact_phone.line_type", "type": "string", "category": "contact",
     "description": "Phone line type",
     "values": ["mobile", "voip", "landline", ""], "phase": "phase2-phone"},

    # ========== Submitter IP ==========
    {"path": "submitter_ip.country", "type": "string", "category": "submitter_ip",
     "description": "Country of submitter IP", "phase": "phase2-ip"},
    {"path": "submitter_ip.is_vpn", "type": "boolean", "category": "submitter_ip",
     "description": "Submitter IP is a known VPN", "phase": "phase2-ip"},
    {"path": "submitter_ip.is_proxy", "type": "boolean", "category": "submitter_ip",
     "description": "Submitter IP is a known proxy", "phase": "phase2-ip"},
    {"path": "submitter_ip.is_tor", "type": "boolean", "category": "submitter_ip",
     "description": "Submitter IP is a Tor exit node", "phase": "phase2-ip"},
    {"path": "submitter_ip.is_datacenter", "type": "boolean", "category": "submitter_ip",
     "description": "Submitter IP is hosted in a datacenter (not residential)", "phase": "phase2-ip"},

    # ========== Network reputation (from fingerprint matches) ==========
    {"path": "network.infrastructure.reputation_score", "type": "number", "category": "network",
     "description": "Infrastructure fingerprint reputation (-1 bad .. +1 good)", "phase": "phase1"},
    {"path": "network.infrastructure.exact_match_count", "type": "number", "category": "network",
     "description": "Prior submissions with identical infrastructure fingerprint", "phase": "phase1"},
    {"path": "network.infrastructure.flagged_count", "type": "number", "category": "network",
     "description": "Network-wide flagged count for this infrastructure fingerprint", "phase": "phase1"},
    {"path": "network.actor.reputation_score", "type": "number", "category": "network",
     "description": "Actor fingerprint reputation (-1 bad .. +1 good)", "phase": "phase1"},
    {"path": "network.actor.exact_match_count", "type": "number", "category": "network",
     "description": "Prior submissions with identical actor fingerprint", "phase": "phase1"},
    {"path": "network.actor.flagged_count", "type": "number", "category": "network",
     "description": "Network-wide flagged count for this actor fingerprint", "phase": "phase1"},

    # ========== Submission metadata ==========
    {"path": "submission.has_domain", "type": "boolean", "category": "submission",
     "description": "A domain was supplied", "phase": "phase1"},
    {"path": "submission.has_contact_email", "type": "boolean", "category": "submission",
     "description": "A contact email was supplied", "phase": "phase1"},
    {"path": "submission.has_submitter_ip", "type": "boolean", "category": "submission",
     "description": "A submitter IP was supplied", "phase": "phase1"},
]


def build_catalog_response() -> dict:
    """Shape for GET /api/v1/signal-catalog. Read-only to API consumers."""
    return {
        "operators": OPERATORS,
        "operators_by_type": OPERATORS_BY_TYPE,
        "signals": SIGNALS,
    }


SIGNAL_PATHS = {s["path"] for s in SIGNALS}


def is_known_signal(path: str) -> bool:
    return path in SIGNAL_PATHS
