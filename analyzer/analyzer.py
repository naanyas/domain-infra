from __future__ import annotations
"""
Domain Analysis Engine for Sender Approval — v7.5.1
Evaluates domain infrastructure signals for email sender approval decisions.
"""

# Full changelog: see CHANGELOG.md or git history
# v7.5.1: Parking page FP fix, new domain age gating, hacklink campaign profile,
#   UK variant dark, e-commerce/financial site defense, SPA legitimacy check,
#   security tooling bonus, cert-but-TLS-dead, GDPR ccTLD handling, typosquat
#   context check, phishing paths split, CT renewal suppression, zero auth floor,
#   TLD variant .com removal, root domain fallback, socket/HTTP WHOIS fallback,
#   transfer lock reduction for fully-authenticated domains.
# v7.5: Autofail override, phishing kit composite, CT apex fix.
# v7.2: Multi-signal malicious script detection, CDN whitelist.
# v7.1: Malicious script/hidden injection/cPanel/transfer lock/CT signals.
# v7.0: VirusTotal + hacklink/SEO spam integration.
# v6.x: WHOIS fallback, DNSBL fix, brand+keyword detection.
# v4.x: TLD variant, hosting detection, app store, TLS, e-commerce.

ANALYZER_VERSION = "8.0.0"

import re
import json
import os
import socket
import ssl
import hashlib
import difflib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, fields, asdict
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Set
from urllib.parse import urlparse, urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

from .config import DEFAULT_CONFIG, get_weight

try:
    from .app_store_detection import check_app_store_presence
    APP_STORE_DETECTION_AVAILABLE = True
except Exception:
    APP_STORE_DETECTION_AVAILABLE = False

try:
    from .virustotal_checker import VirusTotalChecker
    VT_CHECKER_AVAILABLE = True
except Exception:
    VT_CHECKER_AVAILABLE = False

try:
    from .hacklink_keyword_scanner import HacklinkKeywordScanner
    HACKLINK_SCANNER_AVAILABLE = True
except Exception:
    HACKLINK_SCANNER_AVAILABLE = False

try:
    from .content_checks import check_content_identity
    CONTENT_CHECKS_AVAILABLE = True
except Exception:
    CONTENT_CHECKS_AVAILABLE = False


# ============================================================================
# DATA CLASS
# ============================================================================

@dataclass
class DomainApprovalResult:
    # === PRIMARY FIELDS ===
    domain: str = ""
    risk_score: int = 0
    recommendation: str = ""
    summary: str = ""
    
    # === METADATA ===
    scan_timestamp: str = ""
    risk_level: str = ""
    
    # === DNS / NETWORK ===
    resolved: bool = False
    ip_address: str = ""
    
    # === REVERSE DNS (PTR) ===
    ptr_record: str = ""
    ptr_exists: bool = False
    ptr_matches_forward: bool = False
    
    # === EMAIL: SPF ===
    spf_record: str = ""
    spf_exists: bool = False
    spf_mechanism: str = ""
    spf_includes: str = ""
    spf_lookup_count: int = 0
    spf_syntax_valid: bool = True
    spf_too_permissive: bool = False
    
    # === EMAIL: DKIM ===
    dkim_exists: bool = False
    dkim_selectors_found: str = ""
    
    # === EMAIL: DMARC ===
    dmarc_record: str = ""
    dmarc_exists: bool = False
    dmarc_policy: str = ""
    dmarc_pct: int = 100
    dmarc_rua: str = ""
    dmarc_syntax_valid: bool = True
    
    # === EMAIL: MX ===
    mx_exists: bool = False
    mx_records: str = ""
    mx_is_null: bool = False
    mx_uses_free_provider: bool = False
    mx_primary: str = ""
    mx_provider_type: str = ""  # "enterprise", "standard", "disposable", "selfhosted", "unknown"
    mx_is_mail_prefix: bool = False  # MX is exactly mail.{domain} — phishing template fingerprint
    
    # === EMAIL: SPF PROVIDER ANALYSIS ===
    spf_has_external_includes: bool = False  # SPF includes a real email provider (Google, Microsoft, etc.)
    
    # === EMAIL: BIMI ===
    bimi_exists: bool = False
    bimi_record: str = ""
    
    # === EMAIL: MTA-STS ===
    mta_sts_exists: bool = False
    mta_sts_record: str = ""
    
    # === BLACKLISTS ===
    domain_blacklists_hit: str = ""
    domain_blacklist_count: int = 0
    domain_blacklist_inconclusive: int = 0    # v6.2: queries that timed out / errored
    ip_blacklists_hit: str = ""
    ip_blacklist_count: int = 0
    ip_blacklist_inconclusive: int = 0        # v6.2: queries that timed out / errored
    
    # === DOMAIN INFO ===
    rdap_created: str = ""
    whois_created: str = ""
    domain_age_days: int = -1
    domain_age_source: str = ""                  # "rdap" or "whois"
    domain_created_today: bool = False            # True if 0-1 days old
    is_suspicious_tld: bool = False
    is_free_email_domain: bool = False
    is_free_hosting: bool = False
    is_url_shortener: bool = False
    is_disposable_email: bool = False
    typosquat_target: str = ""
    typosquat_similarity: float = 0.0
    
    # === DOMAIN NAME PATTERN DETECTION (Tech Support Scams) ===
    has_suspicious_prefix: bool = False
    suspicious_prefix_found: str = ""
    has_suspicious_suffix: bool = False
    suspicious_suffix_found: str = ""
    is_tech_support_tld: bool = False
    is_hyphenated_sld: bool = False            # SLD contains a hyphen (pay-pal.com, hive-flow.com) — overrepresented in phishing
    domain_impersonates_brand: str = ""  # Brand found in domain name
    domain_pattern_risk: str = ""  # Summary of suspicious patterns
    brand_spoofing_keyword: str = ""     # Spoofing keyword found with brand (e.g., "connect" in easyjetconnect)
    brand_plus_keyword_domain: bool = False  # True when brand + spoofing keyword detected
    
    # === WEB: TLS/CERT ===
    https_valid: bool = False
    tls_error: str = ""
    tls_handshake_failed: bool = False       # v4.4: True when SSL handshake itself fails
    tls_connection_failed: bool = False       # v4.4: True when TCP connect to 443 fails
    cert_self_signed: bool = False
    cert_expired: bool = False
    cert_wrong_host: bool = False
    
    # === WEB: HTTP ===
    http_reachable: bool = False
    http_status: int = 0
    https_reachable: bool = False
    https_status: int = 0
    
    # === WEB: REDIRECTS ===
    redirect_count: int = 0
    redirect_chain: str = ""
    redirect_domains: str = ""
    redirect_cross_domain: bool = False
    redirect_uses_temp: bool = False
    final_url: str = ""
    
    # === WEB: STATUS CODES ===
    status_codes_seen: str = ""
    has_403: bool = False
    has_429: bool = False
    has_503: bool = False
    has_5xx: bool = False
    
    # === WEB: CONTENT ===
    content_length: int = -1
    content_hash: str = ""
    is_minimal_shell: bool = False
    has_js_redirect: bool = False
    has_meta_refresh: bool = False
    has_external_js: bool = False
    has_obfuscation: bool = False
    
    # === PHISHING/MALWARE ===
    phishing_paths_found: str = ""
    has_credential_form: bool = False
    has_sensitive_fields: bool = False
    brands_detected: str = ""
    form_posts_external: bool = False
    malware_links_found: str = ""
    has_suspicious_iframe: bool = False
    is_parking_page: bool = False
    
    # === PHISHING KIT DETECTION (v7.3) ===
    has_phishing_kit_filename: bool = False    # Kit entry-point filename in URL path
    phishing_kit_filename: str = ""            # Which filename matched (e.g., "gate.php")
    phishing_kit_filename_strong: bool = False # True if strong-signal filename
    has_exfil_drop_script: bool = False        # Telegram/Discord/exfil patterns in source
    exfil_drop_signals: str = ""               # Semicolon-separated signal names that fired
    exfil_drop_details: str = ""               # Human-readable descriptions
    phishing_kit_detected: bool = False        # Composite: multiple kit signals confirm a kit
    phishing_kit_reason: str = ""              # Human-readable explanation of kit detection
    
    # === CLIENT-SIDE HARVEST DETECTION (v7.5) ===
    has_harvest_signals: bool = False           # Any client-side harvest pattern matched
    harvest_signals: str = ""                  # Semicolon-separated harvest signal names
    harvest_details: str = ""                  # Human-readable descriptions with extracted values
    has_harvest_combo: bool = False             # Combo: harvest + corroborating signal
    harvest_combo_reason: str = ""             # What harvest + what corroborating signal(s)
    has_form_action_kit: bool = False           # <form action="gate.php"> targets kit filename
    form_action_kit_target: str = ""           # Which kit filename the form posts to
    form_action_kit_strong: bool = False        # True if form targets strong kit filename
    has_suspicious_page_title: bool = False     # <title> matches phishing lure pattern
    page_title: str = ""                       # Extracted page title
    page_title_match: str = ""                 # Which suspicious pattern matched
    whois_privacy: bool = False                # WHOIS registrant uses privacy/proxy service
    whois_privacy_service: str = ""            # Which privacy service detected
    
    # === HIJACKED DOMAIN / STEPPING STONE INDICATORS ===
    has_hijack_path_pattern: bool = False
    hijack_path_found: str = ""
    has_doc_sharing_lure: bool = False
    doc_lure_found: str = ""
    has_phishing_js_behavior: bool = False
    phishing_js_patterns: str = ""
    redirects_to_phishing_infra: bool = False
    phishing_infra_domain: str = ""
    has_email_in_url: bool = False
    url_email_tracking: str = ""
    
    # === ACCESS ANOMALY DETECTION ===
    has_401: bool = False                    # 401 Unauthorized seen
    is_access_restricted: bool = False       # 401 on public-facing domain (403 excluded — WAF FP)
    access_restriction_note: str = ""        # Details about access restriction
    
    # === CORPORATE TRUST SIGNALS ===
    missing_trust_signals: bool = False      # No about/contact/privacy pages
    trust_pages_checked: str = ""            # Which pages were checked
    trust_pages_found: str = ""              # Which trust pages exist
    is_opaque_entity: bool = False           # Access restricted + no trust signals
    
    # === E-COMMERCE / RETAIL SCAM DETECTION ===
    is_retail_scam_tld: bool = False         # .shop, .store, .sale, etc.
    is_ecommerce_site: bool = False          # Detected product listings/cart
    has_cross_domain_brand_link: bool = False # Links to same-brand different TLD
    cross_domain_brand_links: str = ""       # e.g., "gabyandbeauty.com" from gabyandbeauty.shop
    missing_business_identity: bool = False  # No legal name, address, registration
    business_identity_signals: str = ""      # What was found/missing
    
    # === APP STORE PRESENCE (Legitimacy Signal) ===
    app_store_has_presence: bool = False       # Any verified app store presence found
    app_store_confidence: str = ""             # none, low, medium, high
    app_store_ios_verified: bool = False       # Apple AASA deep link config found
    app_store_android_verified: bool = False   # Android Asset Links found
    app_store_page_links: bool = False         # App store links in page content
    app_store_itunes_match: bool = False       # iTunes API match found
    app_store_ios_app_ids: str = ""            # Semicolon-separated iOS app IDs
    app_store_android_packages: str = ""       # Semicolon-separated Android packages
    app_store_methods_found: str = ""          # Which detection methods found apps
    app_store_summary: str = ""                # Human-readable summary
    
    # === TLD VARIANT SPOOFING DETECTION ===
    tld_variant_detected: bool = False           # A TLD variant with established presence was found
    tld_variant_domain: str = ""                 # The established variant domain (e.g., "gordondown.co.uk")
    tld_variant_has_content: bool = False         # Variant has substantive website content
    tld_variant_has_email_infra: bool = False     # Variant has email auth configured (SPF/DKIM/MX)
    tld_variant_domain_age_days: int = -1         # Variant domain age in days
    tld_variant_content_words: int = 0            # Word count on variant's page
    tld_variant_signup_content_words: int = 0     # Word count on signup domain's page
    tld_variant_summary: str = ""                 # Human-readable summary of the comparison
    tld_variant_uk_no_dns: bool = False          # v7.5.1: UK TLD variant (.co.uk) has no DNS
    tld_variant_uk_no_dns_domain: str = ""       # The dark UK variant (e.g., "example.co.uk")
    
    # === HACKLINK CAMPAIGN PROFILE (v7.5.1) ===
    hacklink_campaign_profile: bool = False       # Composite: domain matches hacklink target fingerprint
    hacklink_campaign_profile_confidence: str = "" # MODERATE or HIGH
    hacklink_campaign_profile_signals: str = ""   # Semicolon-separated component signals
    
    # === HOSTING PROVIDER DETECTION ===
    hosting_provider: str = ""                  # Detected provider name (e.g., "Hostinger", "GoDaddy")
    hosting_provider_type: str = ""             # budget_shared, free, suspect, premium, unknown
    hosting_detected_via: str = ""              # ns, asn, ptr, or combination
    hosting_asn: str = ""                       # ASN number if resolved
    hosting_asn_org: str = ""                   # ASN organization name
    blocked_asn_org_match: str = ""             # Matched blocked ASN org pattern (if any)
    
    # === NAMESERVER RISK DETECTION ===
    ns_records: str = ""                         # Semicolon-separated NS records
    ns_count: int = -1                           # Number of NS records (-1 = not checked)
    ns_is_parking: bool = False                  # NS delegated to parking/placeholder service
    ns_parking_match: str = ""                   # Which parking NS pattern matched
    ns_is_dynamic_dns: bool = False              # NS delegated to dynamic DNS provider
    ns_dynamic_dns_match: str = ""               # Which dynamic DNS NS pattern matched
    ns_is_free_dns: bool = False                 # NS using free/anonymous authoritative DNS
    ns_free_dns_match: str = ""                  # Which free DNS NS pattern matched
    ns_is_lame_delegation: bool = False          # Zero NS records (broken/abandoned)
    ns_is_single_ns: bool = False                # Only 1 NS record (fragile/temporary)
    
    # === HIGH-RISK COMPOSITE INDICATORS ===
    high_risk_phish_infra: bool = False          # Render ASN + self-hosted MX + both phish rules fired
    high_risk_phish_infra_reason: str = ""       # Human-readable explanation
    pattern_match: str = ""                      # Known attack pattern identifier (e.g. "Swedish Invoice Phish", "Hacklink/SEO Spam")
    autofail_reason: str = ""                     # Non-empty when a deterministic override forced DENY (e.g. confirmed phishing kit)
    all_issues_text: str = ""                     # Full semicolon-separated list of all issues found
    asn_display: str = ""                        # Formatted "AS{number} ({org})" for results display
    
    # === SCORING DETAILS ===
    signals_triggered: str = ""
    combos_triggered: str = ""
    rules_triggered: str = ""                    # Custom rules that fired (name:score pairs)
    rules_labels: str = ""                       # Human-readable labels for triggered rules
    score_breakdown: str = ""                    # JSON: {signal_or_rule: points} for every scored item
    
    # === VIRUSTOTAL REPUTATION ===
    vt_available: bool = False                   # True if VT API key was configured and query succeeded
    vt_malicious_count: int = 0                  # Vendors flagging domain as malicious
    vt_suspicious_count: int = 0                 # Vendors flagging domain as suspicious
    vt_total_vendors: int = 0                    # Total vendors that analyzed the domain
    vt_detection_rate: float = 0.0               # (malicious+suspicious) / total_vendors
    vt_community_score: int = 0                  # VT community votes (harmless - malicious)
    vt_reputation: int = 0                       # VT reputation score
    vt_threat_names: str = ""                    # Semicolon-separated threat family names
    vt_malicious_vendors: str = ""               # Semicolon-separated vendor names flagging malicious
    vt_categories: str = ""                      # JSON of vendor->category mappings
    vt_last_analysis: str = ""                   # Last VT analysis date
    
    # === HACKLINK / SEO SPAM DETECTION ===
    hacklink_detected: bool = False              # True if hacklink SEO spam injection detected
    hacklink_score: int = 0                      # Hacklink module risk score (0-30)
    hacklink_keywords: str = ""                  # Semicolon-separated hacklink keywords found
    hacklink_injection_patterns: str = ""        # Semicolon-separated injection patterns detected
    hacklink_is_wordpress: bool = False           # WordPress CMS detected
    hacklink_wp_compromised: bool = False         # WordPress compromise indicators found
    hacklink_vulnerable_plugins: str = ""         # Semicolon-separated vulnerable WP plugins
    hacklink_spam_link_count: int = 0            # Number of spam links found in content
    hacklink_spam_links_found: str = ""          # Semicolon-separated spam/phishing URLs found in content
    hacklink_malicious_script: bool = False       # SocGholish/FakeUpdates/obfuscated script injection
    hacklink_malicious_script_confidence: str = "" # HIGH, MEDIUM, or NONE — multi-signal confidence level
    hacklink_malicious_script_signals: str = ""    # Semicolon-separated signal names that fired
    hacklink_malicious_script_score: int = 0       # Accumulated multi-signal score
    hacklink_hidden_injection: bool = False       # CSS hidden content injection (display:none, font-size:0)
    hacklink_hidden_injection_confidence: str = "" # HIGH = hidden+links, LOW = CSS-only (legit pattern)
    hacklink_is_cpanel: bool = False              # cPanel hosting environment detected
    hacklink_suspicious_scripts: str = ""         # Semicolon-separated suspicious external script URLs
    
    # === CONTENT IDENTITY VERIFICATION ===
    content_title_body_mismatch: bool = False      # <title> claims one business, body shows another
    content_title_body_detail: str = ""             # Human-readable mismatch explanation
    content_cross_domain_emails: str = ""           # Semicolon-sep emails from different domain found on page
    content_cross_domain_email_domains: str = ""    # Which foreign domains those emails belong to
    content_page_privacy_emails: str = ""           # Privacy provider emails found on page (proton, tutanota)
    content_page_freemail_contacts: str = ""        # Freemail used as business contact on page
    content_is_broker_page: bool = False             # Domain broker / parking / for-sale page detected
    content_broker_indicators: str = ""              # Which broker phrases matched
    content_is_placeholder: bool = False             # Placeholder content (lorem ipsum, coming soon)
    content_page_emails: str = ""                    # All emails found on page
    content_page_phones: str = ""                    # All phone numbers found on page
    content_identity_hash: str = ""                  # Normalized content hash (for clone detection)
    content_structure_hash: str = ""                 # DOM structure hash (for layout clone detection)
    content_is_facade: bool = False                  # SPA shell: title present but <30 visible words + external JS
    content_facade_detail: str = ""                  # Explanation of why facade was flagged
    content_spa_framework_detected: bool = False     # Known SPA framework fingerprint found (Next.js/Vue/Angular/etc.) — facade suppressed
    content_spa_framework_name: str = ""             # Framework name (e.g. "Next.js", "Angular")
    content_external_script_domains: str = ""        # Non-CDN external script domains (semicolon-sep)
    content_external_link_domains: str = ""          # All external domains linked via <a href> (semicolon-sep, with paths)
    contact_reuse_results: str = ""                   # JSON: contact info found on other domains (OSINT cross-reference)
    content_visible_word_count: int = -1             # Number of visible words on page (-1 = not checked)
    content_security_signals: str = ""               # v7.5.1: Security tooling detected (recaptcha, cloudflare_bot_management, etc.)
    registration_opaque: bool = False                # Both RDAP and WHOIS failed — cannot determine domain age/registrar
    domain_reregistered: bool = False                # RDAP shows a reregistration event (domain was dropped + re-bought)
    domain_reregistered_date: str = ""               # When the domain was re-registered
    domain_reregistered_days: int = -1               # Days since reregistration
    
    # === WHOIS ENRICHMENT / TRANSFER LOCK ===
    whois_registrar: str = ""                    # Registrar name from WHOIS
    whois_updated: str = ""                      # WHOIS last-updated date (ISO)
    whois_statuses: str = ""                     # Semicolon-separated domain statuses
    domain_transfer_locked: bool = True          # clientTransferProhibited present (default True = safe)
    domain_transfer_lock_recent: bool = False    # Lock recently added on old domain (post-compromise lockdown signal)
    whois_recently_updated: bool = False         # WHOIS updated in last 30 days
    whois_recently_updated_days: int = -1        # Days since last WHOIS update
    
    # === MX HIJACK FINGERPRINT (v7.3.1) ===
    # Detects enterprise provider ghosts in DNS: SPF/DKIM still references
    # Google/Microsoft/etc but MX has been changed to different infrastructure.
    mx_provider_mismatch: bool = False           # SPF/DKIM ghosts enterprise but MX doesn't match
    mx_ghost_provider: str = ""                  # Which enterprise provider the ghost references
    mx_ghost_evidence: str = ""                  # Semicolon-separated evidence strings
    mx_hijack_confidence: str = ""               # HIGH, MEDIUM, LOW
    
    # === EMPTY PAGE DETECTION ===
    is_empty_page: bool = False                  # Page returns empty or near-empty content (<50 chars)
    
    # === CERTIFICATE TRANSPARENCY ===
    ct_log_count: int = -1                       # Number of certs found in CT logs (-1 = not checked)
    ct_recent_issuance: bool = False             # Cert issued within last 7 days
    ct_issuers: str = ""                         # Semicolon-separated unique issuers
    ct_first_seen: str = ""                      # Earliest cert date in CT logs
    ct_last_seen: str = ""                       # Most recent cert date in CT logs
    ct_gap_months: int = -1                      # v7.3.1: Largest gap in cert history (months)
    ct_reactivated: bool = False                 # v7.3.1: Aged domain with long CT gap + recent cert (expired domain purchase)
    ct_gap_evidence: str = ""                    # v7.3.1: Evidence string for CT gap
    ct_last_cert_issuer: str = ""                # v7.5.1: Issuer CN of the most recent certificate
    ct_days_since_last_cert: int = -1            # v7.5.1: Days since most recent cert was issued
    ct_cert_tls_dead: bool = False               # v7.5.1: Cert issued recently but TLS is dead/refusing
    ct_cert_tls_dead_detail: str = ""            # v7.5.1: Human-readable detail
    analyzed_root_note: str = ""                 # v7.5.1: Note when subdomain didn't resolve and root was analyzed instead

    # === MAIL-ONLY DOMAIN DETECTION ===
    is_mail_only_domain: bool = False              # Domain has no A record but has valid MX records
    mail_only_mx_records: str = ""                 # MX records found for mail-only domain
    mail_only_mx_provider_type: str = ""           # MX provider classification for mail-only domain
    mail_only_note: str = ""                       # Human-readable note about mail-only detection
    mail_only_dns_score: int = -1                  # Composite DNS-based score for mail-only domains (-1 = not evaluated)
    mail_only_dns_signals: str = ""                # Semicolon-separated DNS signals evaluated
    mail_only_dns_breakdown: str = ""              # JSON breakdown of mail-only DNS scoring

    # === NO-RESOLVE DOMAIN (v8.1) ===
    is_no_resolve_domain: bool = False             # Domain has no A record AND no valid MX records
    cannot_receive_mail: bool = False              # Domain has no valid MX — cannot receive email
    no_resolve_note: str = ""                      # Human-readable note about no-resolve detection
    no_resolve_dns_score: int = -1                 # Composite DNS-based score for no-resolve domains (-1 = not evaluated)
    no_resolve_dns_signals: str = ""               # Semicolon-separated DNS signals evaluated
    no_resolve_dns_breakdown: str = ""             # JSON breakdown of no-resolve DNS scoring

    # === NS PROVIDER QUALITY (v8.1) ===
    ns_is_enterprise: bool = False               # NS uses enterprise/premium DNS provider
    ns_enterprise_match: str = ""                # Which enterprise NS pattern matched

    # === SOA FRESHNESS (v8.1) ===
    soa_exists: bool = False                     # SOA record found
    soa_serial: int = 0                          # SOA serial number
    soa_serial_is_date: bool = False             # Serial follows YYYYMMDDNN convention
    soa_serial_date: str = ""                    # Parsed date from serial (ISO format)
    soa_days_since_serial: int = -1              # Days since serial date (-1 = unknown)

    # === DNSSEC (v8.1) ===
    dnssec_enabled: bool = False                 # DNSKEY or DS record found

    # === TLD REGISTRATION COST (v8.1) ===
    is_free_registration_tld: bool = False       # TLD has free registration (.tk, .ml, .ga, .cf, .gq)

    # === DOMAIN NAME ENTROPY (v8.1) ===
    sld_entropy: float = 0.0                     # Shannon entropy of second-level domain label

    # === SUBDOMAIN DELEGATION ABUSE (v7.3.1) ===
    is_subdomain: bool = False                   # Submitted domain is a subdomain (not registrable root)
    is_staging_subdomain: bool = False           # Subdomain prefix indicates SDLC env (stg, staging, dev, test, uat, qa, sandbox)
    parent_domain: str = ""                      # The registrable parent domain
    parent_ip: str = ""                          # Parent domain's resolved IP
    parent_asn: str = ""                         # Parent domain's ASN
    parent_asn_org: str = ""                     # Parent domain's ASN org
    parent_mx_provider_type: str = ""            # Parent domain's MX provider type
    subdomain_infra_divergent: bool = False      # Subdomain points to different infrastructure than parent
    subdomain_divergence_evidence: str = ""      # Evidence of divergence
    subdomain_divergence_confidence: str = ""    # HIGH, MEDIUM, LOW
    
    # === OAUTH CONSENT PHISHING (v7.3.1) ===
    has_oauth_phish: bool = False                # Page contains OAuth consent phishing patterns
    oauth_phish_evidence: str = ""               # Semicolon-separated evidence strings
    
    # === HOMOGLYPH / IDN SPOOFING (v7.3.1) ===
    is_homoglyph_domain: bool = False            # Domain uses IDN homoglyphs mimicking a brand
    homoglyph_target: str = ""                   # The brand being spoofed
    homoglyph_decoded: str = ""                  # Unicode-decoded domain display
    
    # === QUISHING PROFILE (v7.3.1) ===
    quishing_profile: bool = False               # Domain matches QR code phishing profile
    quishing_evidence: str = ""                  # Evidence strings
    
    # === CDN TUNNEL ABUSE (v7.3.1) ===
    is_cdn_hosted: bool = False                  # Domain resolves to CDN provider IPs
    cdn_provider: str = ""                       # Which CDN (Cloudflare, Fastly, etc.)
    cdn_tunnel_suspect: bool = False             # CDN-hosted with no organic web presence
    cdn_tunnel_evidence: str = ""                # Evidence strings


# ============================================================================
# CONSTANTS
# ============================================================================

DNS_TIMEOUT = 5.0
WEB_TIMEOUT = 8.0
MAX_REDIRECTS = 10

# DNSBL Rate Limit Protection (v6.2)
DNSBL_TIMEOUT = 5.0            # Timeout per DNSBL query (longer than general DNS)
DNSBL_RETRIES = 2              # Retries on timeout/SERVFAIL before marking inconclusive
DNSBL_RETRY_DELAY = 1.5        # Seconds between retries (backoff)
DNSBL_INTER_QUERY_DELAY = 0.3  # Seconds between consecutive DNSBL queries (rate limit)
DNSBL_CACHE_TTL = 300          # Cache results for 5 minutes

# In-memory DNSBL result cache: { "query:zone" -> (result, timestamp) }
# result: True = listed, False = clean, None = inconclusive
import time as _time
_dnsbl_cache: Dict[str, tuple] = {}

TEMP_REDIRECT_CODES = {302, 307}
PERM_REDIRECT_CODES = {301, 308, 303}
ALL_REDIRECT_CODES = TEMP_REDIRECT_CODES | PERM_REDIRECT_CODES

FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'aol.com', 'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com',
]

FREE_HOSTING_PATTERNS = [
    'github.io', 'gitlab.io', 'pages.dev', 'netlify.app', 'vercel.app',
    'herokuapp.com', 'firebaseapp.com', 'azurewebsites.net',
    '000webhostapp.com', 'wixsite.com', 'weebly.com', 'blogspot.com',
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'j.mp', 'rb.gy', 'shorturl.at', 'cutt.ly',
]

PHISHING_PATHS = [
    # === HIGH-CONFIDENCE: Genuinely suspicious — rarely seen on legitimate sites ===
    '/banking', '/webscr', '/paypal', '/amazon',
    '/account/verification', '/secure/login', '/admin/verify',
    '/wp-admin/update/', '/verification/',
    # v7.3.1: HTML credential-harvesting kit directory patterns
    '/tunnel/', '/tunel/',
]

# Standard authentication paths — these are NORMAL on web applications.
# /signin, /login, /auth/, /portal/ exist on every SaaS, mobile app backend,
# and Firebase/Auth0/Supabase deployment.  These should NOT count as phishing
# kit evidence by themselves — only when combined with brand impersonation
# or other non-auth signals.
STANDARD_AUTH_PATHS = [
    '/signin', '/login', '/secure', '/verify', '/update', '/confirm',
    '/account', '/auth/', '/portal/', '/invoice/', '/doc/', '/share/',
]

# ============================================================================
# PHISHING KIT DETECTION (v7.3)
# ============================================================================
# Kit filenames — if the final URL path ends with one of these, the domain
# is serving a phishing kit entry point.
# STRONG: score directly (almost never legitimate)
# WEAK:   score 0 alone — only fire via combo rules needing a second signal
PHISHING_KIT_FILENAMES_STRONG = [
    'gate.php', 'post.php', 'next.php', 'submit.php', 'process.php',
    'validate.php', 'secure.php', 'auth.php',
    'index2.php',                    # Classic kit duplicate-index pattern
    'well.php', 'ok.php',            # Common kit result pages
    'log.php', 'logs.php',           # Kit logging endpoints
    'rezult.php', 'result.php',
    'chk.php', 'check.php',
    # v7.3.1: HTML credential-harvesting kits (Feb 2025 observed paths)
    # These filenames are near-zero legitimate use.  No real site serves
    # a page called "email-template.html" — it's a kit builder artifact
    # where the author's internal name leaked into production.
    'email-template.html',           # 29/121 observed kit paths — dominant
    'project-template.html',         # 2/121 — same kit family, project lure
]

PHISHING_KIT_FILENAMES_WEAK = [
    # Common on legitimate CMS — only flag in combination with other signals
    'login.php', 'verify.php', 'signin.php', 'update.php', 'confirm.php',
    'recover.php', 'reset.php', 'access.php',
    # v7.3.1: HTML kit filenames that COULD appear on legitimate sites
    # (e.g. a security tool page named "scan.html").  Only score via combos.
    'scan.html',                     # 2/121 — common but not definitive alone
]

# Exfiltration / drop script patterns detectable in HTML source.
# Each tuple: (compiled_regex, signal_name, description)
import re as _re
EXFIL_DROP_PATTERNS = [
    # Telegram Bot API tokens — format: bot{8-10 digits}:{35 alphanumeric+_-}
    # Capture group: full bot token
    (_re.compile(rb'(bot\d{8,12}:[A-Za-z0-9_\-]{35})', _re.IGNORECASE),
     'telegram_bot_token', 'Telegram bot token (credential exfiltration)'),
    # Telegram API sendMessage endpoint
    # Capture group: full API URL
    (_re.compile(rb'(https?://api\.telegram\.org/bot[A-Za-z0-9_:/-]+)', _re.IGNORECASE),
     'telegram_api', 'Telegram API call (credential exfiltration)'),
    # Discord webhook URLs — format: discord.com/api/webhooks/{id}/{token}
    # Capture group: full webhook URL
    (_re.compile(rb'(https?://(?:discord(?:app)?\.com|canary\.discord\.com)/api/webhooks/\d+/[A-Za-z0-9_\-]+)', _re.IGNORECASE),
     'discord_webhook', 'Discord webhook URL (credential exfiltration)'),
    # Suspicious base64-encoded blocks near network calls
    # Capture group: the base64 payload string
    (_re.compile(rb'(?:atob|btoa|base64)\s*\(\s*["\']([A-Za-z0-9+/=]{40,})["\']', _re.IGNORECASE),
     'base64_exfil', 'Base64-encoded exfiltration payload'),
    # Hardcoded email recipient in JS string context (kit exfil target)
    # Capture group: the email address
    (_re.compile(rb'''["'](?:to|email|recipient|receiver)["']\s*[:=]\s*["']([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']''', _re.IGNORECASE),
     'js_email_exfil', 'Hardcoded email in JavaScript (kit exfiltration target)'),
    # JavaScript cross-domain POST — fetch() sending data to external domain
    # Capture group: the target URL
    (_re.compile(rb'''fetch\s*\(\s*["'](https?://[^"']+)["']\s*,\s*\{[^}]*method\s*:\s*["']POST["']''', _re.IGNORECASE | _re.DOTALL),
     'js_fetch_external_post', 'JavaScript fetch() POST to external domain'),
    # XMLHttpRequest POST to external domain
    # Capture group: the target URL
    (_re.compile(rb'''\.open\s*\(\s*["']POST["']\s*,\s*["'](https?://[^"']+)["']''', _re.IGNORECASE),
     'js_xhr_external_post', 'XMLHttpRequest POST to external domain'),
]

# Client-side credential harvesting patterns (v7.5).
# These are NEVER scored alone — too common on legitimate sites.
# They only fire as part of the client_side_harvest_combo signal when paired
# with a corroborating lower-confidence phishing signal.
# Each tuple: (compiled_regex, signal_name, description)
CLIENT_SIDE_HARVEST_PATTERNS = [
    # Input value harvesting on password / email / SSN / card fields
    #   Matches: document.getElementById('password').value
    #            document.querySelector('[name="email"]').value
    #            $('#pass').val()
    (_re.compile(
        rb'''(?:getElementById|querySelector|getElementsByName|querySelectorAll|\$)\s*\('''
        rb'''[^)]{0,80}(?:pass|pwd|email|user|login|ssn|card|cvv|pin|otp|token|credential|secret)'''
        rb'''[^)]{0,40}\)'''
        rb'''[^;]{0,60}\.(?:value|val\s*\(\s*\))''',
        _re.IGNORECASE),
     'harvest_input_value', 'Input value harvesting on sensitive field'),

    # Keylogger: keydown/keypress/keyup event listener with data capture
    #   Matches: addEventListener('keydown', function(e) { ... e.key ... })
    (_re.compile(
        rb'''addEventListener\s*\(\s*["'](?:keydown|keypress|keyup)["']\s*,\s*function'''
        rb'''[^}]{0,300}(?:\.key|\.which|\.keyCode|\.charCode|String\.fromCharCode)''',
        _re.IGNORECASE | _re.DOTALL),
     'harvest_keylogger', 'Keylogger event listener capturing keystrokes'),

    # navigator.sendBeacon() to external URL — stealthier than fetch
    # Capture group: the external URL
    (_re.compile(
        rb'''navigator\s*\.\s*sendBeacon\s*\(\s*["'](https?://[^"']+)["']''',
        _re.IGNORECASE),
     'harvest_sendbeacon', 'navigator.sendBeacon() to external URL'),

    # Image pixel exfiltration: new Image().src = url + stolen_data
    # Capture group: the target URL
    (_re.compile(
        rb'''new\s+Image\s*\(\s*\)\s*\.\s*src\s*=\s*["']?(https?://[^"'\s;]+)["']?\s*\+''',
        _re.IGNORECASE),
     'harvest_img_pixel', 'Image pixel exfiltration (data appended to URL)'),

    # document.cookie read in suspicious context (near exfil-like patterns)
    (_re.compile(
        rb'''document\s*\.\s*cookie.{0,300}(?:fetch|XMLHttpRequest|\.open|sendBeacon|new\s+Image|\.src\s*=|\.send\s*\()''',
        _re.IGNORECASE | _re.DOTALL),
     'harvest_cookie_theft', 'document.cookie read near exfiltration call'),

    # FormData constructed from a form and sent cross-origin
    (_re.compile(
        rb'''new\s+FormData\s*\([^)]*\).{0,300}(?:fetch|\.send|sendBeacon)\s*\(''',
        _re.IGNORECASE | _re.DOTALL),
     'harvest_formdata_exfil', 'FormData constructed and sent externally'),
]

# Corroborating signals for harvest combo evaluation.
# The combo fires when: ≥1 harvest pattern + ≥1 corroborating signal.
# These are lower-confidence phishing signals that, alone, aren't conclusive
# but become high-confidence when combined with active credential harvesting code.
HARVEST_CORROBORATING_SIGNALS = {
    "phishing_kit_filename_weak",     # login.php, verify.php, etc.
    "has_suspicious_page_title",      # Phishing lure page title
    "has_credential_form",            # <form> with password/email inputs
    "form_posts_external",            # <form action="https://other-domain/...">
    "brands_detected",                # Brand impersonation (Microsoft, PayPal, etc.)
    "phishing_paths_found",           # /verify, /secure, /login in URL path
    "has_sensitive_fields",           # SSN, card number, etc. in form
    "doc_sharing_lure",               # Fake OneDrive/Google Docs lure
    "has_suspicious_iframe",          # Hidden or off-screen iframe
}

# Suspicious page titles — common in phishing kit landing pages.
# These are matched against <title> tag content (case-insensitive).
SUSPICIOUS_PAGE_TITLES = [
    # Document lure titles
    'secure document portal', 'document verification', 'verify your identity',
    'account verification required', 'verify your account', 'confirm your identity',
    'security verification', 'identity verification', 'email verification required',
    # Login clone titles
    'sign in to your account', 'login to continue', 'sign in required',
    'session expired', 'session timeout', 'your session has expired',
    # Brand-generic lure titles
    'update your information', 'update your payment', 'update billing information',
    'confirm your payment', 'payment verification', 'secure payment portal',
    # Access/sharing lures
    'shared with you', 'file shared with you', 'access your document',
    'view shared file', 'document shared', 'secure file access',
    # Urgency titles
    'action required', 'immediate action required', 'urgent action needed',
    'account suspended', 'account locked', 'account restricted',
    'unauthorized login attempt', 'suspicious activity detected',
]

# ============================================================================
# PHISHING DOMAIN NAME PATTERNS (Tech Support Scam / Brand Impersonation)
# ============================================================================

# Suspicious prefixes commonly used in tech support scams
# Note: Some prefixes work with OR without hyphen (app-, app both suspicious)
SUSPICIOUS_PREFIXES_HYPHEN = [
    'app-', 'my-', 'get-', 'www-', 'login-', 'secure-', 'support-', 'help-',
    'account-', 'portal-', 'online-', 'web-', 'customer-', 'service-',
    'official-', 'verify-', 'update-', 'billing-', 'payment-',
    'i-download', 'download-', 'install-',
]

# These prefixes are suspicious even WITHOUT hyphen when followed by other text
# e.g., "appbelezia", "myaccount", "gethelp"
SUSPICIOUS_PREFIXES_NO_HYPHEN = [
    'app', 'my', 'get', 'login', 'secure', 'support', 'help',
    'account', 'portal', 'online', 'web', 'customer', 'service',
    'official', 'verify', 'update', 'billing', 'payment',
    'download', 'install', 'easy', 'howto', 'free', 'fast', 
    'quick', 'best', 'top',
]

# Legitimate words that start with suspicious prefixes - exclude from detection
# These should NOT trigger the prefix detection
LEGITIMATE_PREFIX_WORDS = [
    # Words starting with 'app'
    'apple', 'application', 'applications', 'appliance', 'appliances',
    'appetite', 'apparel', 'apparatus', 'appeal', 'appear', 'appearance',
    'appendix', 'applies', 'apply', 'appointment', 'appreciate', 'approach',
    'appropriate', 'approval', 'approve', 'approximate',
    # Words starting with 'my' - most are legitimate as "my" is a common word
    'myth', 'mystery', 'mysterious', 'myself', 'myriad',
    # Words starting with 'get'
    'getaway', 'getaways',
    # Words starting with 'top'
    'topic', 'topics', 'topical', 'topology', 'topography',
    # Words starting with 'best'
    'bestow', 'bestseller', 'bestsellers',
    # Words starting with 'free'
    'freedom', 'freelance', 'freelancer', 'freeway', 'freeze', 'freight',
    # Words starting with 'fast'
    'fasten', 'fastener', 'faster', 'fastest',
    # Words starting with 'quick'
    'quickly', 'quicken',
    # Words starting with 'easy'
    'easily', 'easier', 'easiest',
    # Words starting with 'web'
    'website', 'websites', 'webinar', 'webmaster',
    # Words starting with 'online'
    # (online + something is usually suspicious, keep it)
    # Words starting with 'secure'
    'security', 'securities', 'secured', 'securely',
    # Words starting with 'support'
    'supporter', 'supporters', 'supported', 'supporting', 'supportive',
    # Words starting with 'service'
    'services', 'serviced', 'servicer',
    # Words starting with 'account' (account is also a prefix we check)
    'accountant', 'accountants', 'accounting', 'accountable', 'accountability',
    # Words starting with 'customer'
    'customers', 'customary', 'customize', 'customized',
]

# Suspicious suffixes commonly used in tech support scams  
SUSPICIOUS_SUFFIXES = [
    'account', 'accounts', 'login', 'signin', 'support', 'help', 'helpdesk',
    'setup', 'install', 'download', 'update', 'upgrade', 'cancellation',
    'cancel', 'billing', 'payment', 'verify', 'verification', 'secure',
    'activate', 'activation', 'renew', 'renewal', 'subscription',
    'customer', 'service', 'official', 'online', 'portal', 'center',
    'assistant', 'desk', 'tech', 'fix', 'repair', 'cleaner', 'optimizer',
]

# Legitimate words that end with suspicious suffixes - exclude from detection
LEGITIMATE_SUFFIX_WORDS = [
    # Words ending with 'account'
    'accountant', 'accountancy', 'unaccountable', 'accountability',
    # Words ending with 'support'
    'supportive', 'unsupportive',
    # Words ending with 'service'
    'services', 'disservice',
    # Words ending with 'portal'
    # (most portal words are portal + modifier, keep detection)
    # Words ending with 'center'
    'epicenter', 'hypercenter',
    # Words ending with 'tech'
    'biotech', 'nanotech', 'hightech', 'lowtech', 'infotech',
    # Words ending with 'secure'
    'insecure',
    # Words ending with 'online'
    # (most are compound words like bankonline, keep detection)
]

# TLDs heavily abused for tech support scams
TECH_SUPPORT_SCAM_TLDS = [
    '.support', '.tech', '.help', '.services', '.solutions', '.center',
    '.expert', '.guru', '.pro', '.care', '.repair', '.fix',
]

# TLDs heavily abused for e-commerce/retail scams (fake stores, dropshipping scams)
RETAIL_SCAM_TLDS = [
    '.shop', '.store', '.sale', '.deals', '.bargains', '.discount', '.cheap',
    '.buy', '.shopping', '.market', '.boutique', '.fashion', '.shoes',
    '.jewelry', '.watch', '.gifts', '.flowers', '.furniture', '.toys',
]

# European ccTLDs where WHOIS/RDAP data is restricted by GDPR or registry policy.
# registration_opaque should NOT be penalized on these TLDs — the registries
# suppress creation dates and registrant info by default, not because the
# domain owner is hiding anything.
GDPR_RESTRICTED_TLDS = {
    '.de',    # DENIC — no WHOIS creation date, minimal RDAP
    '.eu',    # EURid — GDPR redacted
    '.fr',    # AFNIC — GDPR redacted
    '.nl',    # SIDN — GDPR redacted
    '.be',    # DNS Belgium — GDPR redacted
    '.at',    # nic.at — GDPR redacted
    '.ch',    # SWITCH — Swiss privacy law
    '.it',    # NIC.it — GDPR redacted
    '.es',    # Red.es — GDPR redacted
    '.pt',    # .PT — GDPR redacted
    '.se',    # IIS — GDPR redacted
    '.no',    # Norid — GDPR redacted
    '.dk',    # Punktum dk — GDPR redacted
    '.fi',    # FICORA — GDPR redacted
    '.pl',    # NASK — GDPR redacted
    '.cz',    # CZ.NIC — GDPR redacted
    '.ie',    # IEDR — GDPR redacted
    '.lu',    # RESTENA — GDPR redacted
    '.sk',    # SK-NIC — GDPR redacted
    '.hr',    # CARNet — GDPR redacted
    '.ro',    # ROTLD — GDPR redacted
    '.bg',    # REGISTER.BG — GDPR redacted
    '.hu',    # ISZT — GDPR redacted
    '.si',    # ARNES — GDPR redacted
    '.lt',    # DOMREG — GDPR redacted
    '.lv',    # NIC.LV — GDPR redacted
    '.ee',    # EIS — GDPR redacted
    '.li',    # SWITCH — Swiss/Liechtenstein privacy
}

# E-commerce indicators in page content
ECOMMERCE_INDICATORS = [
    'add to cart', 'add to bag', 'buy now', 'shop now', 'checkout',
    'shopping cart', 'your cart', 'view cart', 'price', 'order now',
    'free shipping', 'fast delivery', 'product description', 'quantity',
    'in stock', 'out of stock', 'add to wishlist', 'save for later',
]

# Business identity indicators (what legitimate businesses show)
BUSINESS_IDENTITY_PATTERNS = [
    # Legal entity identifiers
    r'\b(inc|llc|ltd|corp|corporation|gmbh|sarl|bv|ag|co\.)\b',
    # Registration numbers
    r'\b(registration|reg\.?\s*no|business\s*number|company\s*number|ein|vat|abn)\s*[:.\s]*[\w\d-]+',
    # Physical address indicators
    r'\b\d+\s+\w+\s+(street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln)\b',
    r'\b(suite|ste|floor|unit|building)\s*[#\d]+',
    # Contact legitimacy
    r'\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}',  # Phone numbers
]

# Expanded brand list for domain-name impersonation detection
# Includes: ISPs, security software, streaming, tech companies, utilities,
# airlines, travel, shipping, financial services, e-commerce
IMPERSONATED_BRANDS = [
    # Major tech companies (already in content check)
    'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix',
    
    # ISPs / Email providers (common tech support scam targets)
    'aol', 'att', 'bellsouth', 'centurylink', 'charter', 'comcast', 'cox',
    'earthlink', 'frontier', 'hughesnet', 'juno', 'mediacom', 'optimum',
    'roadrunner', 'spectrum', 'suddenlink', 'verizon', 'windstream', 'xfinity',
    'yahoo', 'gmail', 'outlook', 'hotmail', 'protonmail', 'startmail',
    'duckduckgo', 'prontoemail', 'prontomail',
    
    # Security software (huge tech support scam target)
    'norton', 'mcafee', 'avast', 'avg', 'bitdefender', 'kaspersky', 'malwarebytes',
    'webroot', 'trendmicro', 'sophos', 'eset', 'avira', 'pcmatic', 'totalav',
    'scanguard', 'stopzilla', 'hitmanpro', 'spyhunter', 'fixmestick',
    'cleanmymac', 'macpaw', 'ccleaner', 'iolo', 'systemcare',
    
    # Streaming services
    'hulu', 'disney', 'hbomax', 'peacock', 'paramount', 'fubo', 'fubotv',
    'sling', 'vudu', 'roku', 'appletv', 'primevideo', 'spotify', 'pandora',
    
    # Hardware / Printers (tech support scam targets)
    'hp', 'canon', 'epson', 'brother', 'lexmark', 'dymo', 'xerox', 'dell',
    'lenovo', 'asus', 'acer', 'toshiba', 'samsung', 'logitech',
    
    # Software
    'quickbooks', 'turbotax', 'quicken', 'sage', 'adobe', 'autodesk',
    'dropbox', 'carbonite', 'idrive', 'backblaze', 'crashplan',
    
    # Gaming / Entertainment
    'pogo', 'steam', 'epic', 'origin', 'ubisoft', 'blizzard', 'roblox',
    
    # Other commonly impersonated
    'geeksquad', 'bestbuy', 'costco', 'walmart', 'target',
    
    # === Airlines (high-value phishing targets — booking/payment data) ===
    'easyjet', 'ryanair', 'british airways', 'britishairways', 'emirates',
    'lufthansa', 'airfrance', 'klm', 'southwest', 'southwestairlines',
    'delta', 'united', 'american airlines', 'americanairlines',
    'jetblue', 'spirit', 'frontier airlines', 'allegiant', 'alaska airlines',
    'wizzair', 'vueling', 'eurowings', 'norwegian', 'tui', 'jet2',
    'qantas', 'virgin atlantic', 'virginatlantic', 'aer lingus', 'aerlingus',
    'turkish airlines', 'turkishairlines', 'cathay pacific', 'cathaypacific',
    'singapore airlines', 'singaporeairlines', 'etihad', 'qatar airways',
    'qatarairways', 'airindia',
    
    # === Travel / Booking (phishing targets — payment/personal data) ===
    'booking', 'expedia', 'airbnb', 'tripadvisor', 'hotels', 'trivago',
    'kayak', 'skyscanner', 'priceline', 'orbitz', 'travelocity',
    'lastminute', 'trainline', 'eurostar', 'flixbus',
    
    # === Shipping / Logistics (delivery phishing — customs fees, tracking) ===
    'fedex', 'usps', 'ups', 'dhl', 'royalmail', 'hermes', 'evri',
    'yodel', 'dpd', 'parcelforce', 'postnl', 'laposte', 'correos',
    'deutschepost', 'aramex', 'maersk',
    
    # === Banks / Financial (high-value: account access, payments) ===
    'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'hsbc',
    'barclays', 'lloyds', 'natwest', 'santander', 'halifax',
    'nationwide', 'tsb', 'monzo', 'revolut', 'starling',
    'capitalone', 'americanexpress', 'amex', 'discover',
    'goldmansachs', 'morganstanley', 'schwab', 'fidelity', 'vanguard',
    'robinhood', 'coinbase', 'binance', 'kraken', 'blockchain', 'metamask',
    
    # === Payment / Fintech ===
    'stripe', 'square', 'venmo', 'zelle', 'cashapp', 'wise', 'transferwise',
    'klarna', 'afterpay', 'affirm', 'clearpay',
    
    # === E-commerce / Retail ===
    'ebay', 'alibaba', 'aliexpress', 'etsy', 'shopify', 'wish',
    'wayfair', 'asos', 'zara', 'shein', 'temu',
    
    # === Telecoms ===
    'vodafone', 'tmobile', 'sprint', 'three', 'orange', 'telefonica',
    'bt', 'ee', 'o2', 'giffgaff', 'sky', 'virgin media', 'virginmedia',
    
    # === Government / Tax (seasonal phishing spikes) ===
    'hmrc', 'irs', 'dvla', 'govuk',
]

# ============================================================================
# BRAND SPOOFING KEYWORDS
# ============================================================================
# When a known brand name appears in a domain COMBINED with one of these
# keywords, the risk is significantly higher. These keywords mimic legitimate
# brand services/portals (easyjetconnect.com, amazonverify.com, etc.)
#
# Scored as a separate signal on top of domain_brand_impersonation.
# ============================================================================

BRAND_SPOOFING_KEYWORDS = [
    # Connection / Access
    'connect', 'connected', 'connection', 'linking', 'link',
    # Authentication / Verification
    'login', 'logon', 'signin', 'signup', 'signon',
    'verify', 'verification', 'validate', 'confirm', 'auth',
    # Account / Portal
    'account', 'accounts', 'myaccount', 'portal', 'dashboard',
    'member', 'members', 'membership', 'profile', 'user',
    # Security / Trust
    'secure', 'security', 'safe', 'protect', 'protection', 'shield',
    'trust', 'trusted', 'official', 'verified',
    # Support / Service
    'support', 'helpdesk', 'help', 'service', 'services', 'care',
    'customer', 'contact', 'assist', 'center', 'centre',
    # Updates / Billing
    'update', 'upgrade', 'renew', 'renewal', 'billing', 'payment',
    'pay', 'invoice', 'refund', 'claim', 'reward', 'rewards',
    # Tracking / Delivery (shipping brand phishing)
    'track', 'tracking', 'deliver', 'delivery', 'parcel', 'package',
    'shipment', 'shipping', 'dispatch', 'customs', 'collect',
    # Booking / Travel (airline/travel brand phishing)
    'book', 'booking', 'bookings', 'reserve', 'reservation',
    'flight', 'flights', 'checkin', 'boardingpass', 'itinerary',
    # Notifications / Communication
    'notify', 'notification', 'notifications', 'alert', 'alerts',
    'message', 'messages', 'inbox', 'mail', 'email',
    # Management / Admin
    'manage', 'manager', 'admin', 'panel', 'control',
    # App / Digital
    'app', 'apps', 'online', 'web', 'digital', 'cloud',
    # Action / Download
    'download', 'install', 'setup', 'activate', 'activation',
    # Status
    'status', 'info', 'information', 'notice', 'advisory',
]

# Content-based brand detection (for page content scanning)
# NOTE: 'apple' removed — triggers on every site with apple-touch-icon/
# apple-mobile-web-app-capable meta tags. Apple phishing is caught by
# typosquatting, domain name patterns, credential forms, and phishing paths.
BRAND_KEYWORDS = [
    b'paypal', b'amazon', b'microsoft', b'google', b'facebook',
    b'instagram', b'netflix', b'bank of america', b'chase', b'wells fargo',
    b'usps', b'fedex', b'dropbox', b'docusign',
]

# Short keywords that need word boundary matching (to avoid false positives like "first" matching "irs")
BRAND_KEYWORDS_SHORT = [b'irs', b'ups', b'dhl']

# Shipping/logistics brands that are EXPECTED on e-commerce sites.
# When detected on a confirmed WooCommerce/Shopify/e-commerce domain, these
# should NOT count as brand impersonation evidence in the phishing kit composite.
ECOMMERCE_SHIPPING_BRANDS = {'ups', 'fedex', 'usps', 'dhl', 'dpd', 'hermes', 'royal mail'}

# === KNOWN PARKING / DOMAIN-SALE PROVIDERS (v7.5) ===
# When the page is a parking page AND external resources/forms point to these
# domains, suppress brand detection, form_posts_external, and malicious script
# signals to prevent false positives.  Parking pages include payment processor
# references (Chase, PayPal, Stripe) from the domain purchase flow and cookie
# consent / analytics scripts that trigger SocGholish false positives.
KNOWN_PARKING_DOMAINS = {
    "hugedomains.com", "www.hugedomains.com", "static.hugedomains.com",
    "hugedomainsdns.com", "forsale.hugedomainsdns.com",
    "domain-for-sale.hugedomainsdns.com",
    "sedoparking.com", "www.sedoparking.com", "sedo.com",
    "godaddy.com", "www.godaddy.com", "domaincontrol.com",
    "afternic.com", "www.afternic.com",
    "dan.com", "www.dan.com",
    "undeveloped.com", "www.undeveloped.com",
    "namebright.com", "www.namebright.com",
    "bodis.com", "www.bodis.com",
    "parkingcrew.net", "www.parkingcrew.net",
    "domainmarket.com", "www.domainmarket.com",
    "buydomains.com", "www.buydomains.com",
    "porkbun.com", "www.porkbun.com",
}

# Benign external script domains commonly loaded on parking pages.
# These should NOT trigger UNKNOWN_EXTERNAL_SCRIPT / malicious script
# when the page is identified as a parking page.
KNOWN_PARKING_SCRIPT_DOMAINS = {
    "cdn-cookieyes.com",
    "static.hugedomains.com",
    "www.hugedomains.com",
    "www.google.com",
    "www.google-analytics.com",
    "www.googletagmanager.com",
    "cdn.sedoparking.com",
    "pagead2.googlesyndication.com",
    "www.googleadservices.com",
    "cdn.bodis.com",
}

# === OAUTH CONSENT PHISHING PATTERNS (v7.3.1) ===
# OAuth authorization endpoint patterns that indicate consent phishing.
# Attackers redirect to real Microsoft/Google OAuth pages with malicious
# app permissions — no password fields on the phishing domain itself.
OAUTH_AUTH_ENDPOINTS = [
    b'login.microsoftonline.com/common/oauth2/authorize',
    b'login.microsoftonline.com/common/oauth2/v2.0/authorize',
    b'login.microsoftonline.com/organizations/oauth2',
    b'accounts.google.com/o/oauth2/auth',
    b'accounts.google.com/o/oauth2/v2/auth',
    b'login.windows.net/common/oauth2',
]
OAUTH_PARAM_PATTERNS = [
    rb'response_type\s*=\s*["\']?code',
    rb'redirect_uri\s*=\s*["\']?https?://',
    rb'client_id\s*=\s*[0-9a-f-]{20,}',
    rb'scope\s*=.*(?:mail|files|contacts|user)\.read',
]

# === HOMOGLYPH MAP (v7.3.1) ===
# Cyrillic/Greek/other Unicode chars that visually resemble Latin letters.
# Used to detect IDN homoglyph attacks (xn-- punycode domains).
HOMOGLYPH_MAP = {
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0443': 'y',  # Cyrillic у
    '\u0445': 'x',  # Cyrillic х
    '\u0456': 'i',  # Cyrillic і
    '\u0458': 'j',  # Cyrillic ј
    '\u04bb': 'h',  # Cyrillic һ
    '\u0501': 'd',  # Cyrillic ԁ
    '\u051b': 'q',  # Cyrillic ԛ
    '\u0261': 'g',  # Latin small script g (IPA)
    '\u0251': 'a',  # Latin alpha
    '\u03b1': 'a',  # Greek α
    '\u03bf': 'o',  # Greek ο
    '\u03c1': 'p',  # Greek ρ
    '\u03b5': 'e',  # Greek ε
    '\u0432': 'b',  # Cyrillic в (looks like b in some fonts)
    '\u043a': 'k',  # Cyrillic к
    '\u043c': 'm',  # Cyrillic м
    '\u043d': 'h',  # Cyrillic н (looks like H)
    '\u0442': 't',  # Cyrillic т
    '\u0448': 'w',  # Cyrillic ш (sometimes confusable)
    '\u0131': 'i',  # Turkish dotless ı
    '\u1d00': 'a',  # Latin small cap A
    '\u1d04': 'c',  # Latin small cap C
    '\u1d07': 'e',  # Latin small cap E
    '\u1d0f': 'o',  # Latin small cap O
}

# === CONFUSABLE TLD PAIRS (v7.3.1) ===
# TLD pairs that look similar in certain fonts or at small sizes
CONFUSABLE_TLD_PAIRS = {
    '.corn': '.com',   # rn → m in sans-serif
    '.cam': '.com',    # vowel swap
    '.con': '.com',    # trailing char swap
    '.corn': '.com',
    '.orn': '.om',
}

# === QUISHING TLDs (v7.3.1) ===
# TLDs disproportionately used for QR code phishing landing pages
QUISHING_TLDS = {'.page', '.link', '.click', '.qr', '.to', '.me', '.one', '.zip', '.mov'}

# === CDN PROVIDER ASN MAP (v7.3.1) ===
# ASNs belonging to major CDN/proxy providers. When a domain resolves to these,
# the actual origin server is hidden — could be legitimate or attacker-controlled.
CDN_ASN_MAP = {
    '13335': 'Cloudflare',   # CLOUDFLARENET
    '209242': 'Cloudflare',  # Cloudflare secondary
    '54113': 'Fastly',
    '16625': 'Akamai',
    '20940': 'Akamai',
    '16509': 'AWS CloudFront',  # AMAZON-02
    '15169': 'Google Cloud CDN',
    '396982': 'Google Cloud',
    '8075': 'Microsoft Azure CDN',
    '13414': 'Twitter/X CDN',
}

CREDENTIAL_PATTERNS = [b'type="password"', b"type='password'", b'name="password"']
SENSITIVE_PATTERNS = [b'name="ssn"', b'name="card_number"', b'name="cvv"']
JS_REDIRECT_PATTERNS = [b'location.href', b'location.replace', b'window.location']
MALWARE_EXTENSIONS = ['.exe', '.scr', '.bat', '.cmd', '.msi', '.jar', '.vbs', '.apk']

# ============================================================================
# HIJACKED DOMAIN / STEPPING STONE DETECTION PATTERNS
# Based on research: https://keepaware.com/blog/over-100-domains-hijacked
# ============================================================================

# Suspicious URL path segments (phishing pages hidden in subdirectories)
HIJACK_PATH_KEYWORDS = [
    'tunnel', 'bid', 'invite', 'secure', 'memo', 'document', 'fileshare',
    'agreement', 'policy', 'scan', 'rfp', 'proposal', 'submission',
    'sharedsuccess', 'teamwork', 'workers-team', 'team-work', 'team-admin',
    'autodocs', 'onlstorage', 'tunelstorage', 'cstorefile', 'archiev',
    'proceed', 'record', 'source', 'incoming-bid', 'drive', 'zoom',
    'invitation', 'offers', 'master', 'project', 'realestate', 'legal',
]

# Suspicious filename patterns in URLs
HIJACK_FILE_PATTERNS = [
    'email-template.html', 'proposal.html', 'policy.html', 'home.html',
    'index.html', 'scan.html', 'agreement.html', 'project.html',
    'compliance.html', 'secure.html', 'form.html', 'preview-form.html',
]

# Known phishing infrastructure domains (redirects to these = bad)
PHISHING_INFRASTRUCTURE = [
    'workers.dev',           # Cloudflare workers - heavily abused
    'pages.dev',             # Cloudflare pages
    'netlify.app',           # Netlify - abused for phishing
    'vercel.app',            # Vercel - abused
    'herokuapp.com',         # Heroku
    'glitch.me',             # Glitch
    'replit.dev',            # Replit
    'web.app',               # Firebase
    'firebaseapp.com',       # Firebase
    'azurewebsites.net',     # Azure (often abused)
    'blob.core.windows.net', # Azure blob storage
    'googleapis.com',        # Google APIs (sometimes abused)
    'ipfs.io',               # IPFS - decentralized, hard to takedown
    'dweb.link',             # IPFS gateway
    'fleek.co',              # IPFS hosting
    'arweave.net',           # Permanent storage - abused
]

# Document sharing lure patterns (in page content)
DOC_SHARING_LURES = [
    b'secure document sharing',
    b'business document shared',
    b'shared document',
    b'view document',
    b'access document',
    b'download document',
    b'open document',
    b'document preview',
    b'file shared with you',
    b'has shared a file',
    b'sent you a document',
    b'review document',
    b'sign document',
    b'confidential document',
    b'important document',
    b'urgent document',
    b'invoice attached',
    b'payment document',
    b'enter your email to view',
    b'verify your email to access',
    b'enter email to continue',
]

# JavaScript patterns indicating phishing kit behavior
PHISHING_JS_PATTERNS = [
    b'atob(',                          # Base64 decoding (URL obfuscation)
    b'window.location.hash',           # Email extraction from URL hash
    b'getEmailFromHash',               # Function name from known kits
    b'decodeBase64',                   # Base64 decoding function
    b'loadingOverlay',                 # Fake loading screen
    b'loadingSpinner',                 # Fake loading spinner
    b"btoa(",                          # Base64 encoding
    b'.workers.dev',                   # Cloudflare workers redirect
    b'captchaResponse',                # Fake captcha
    b'validate-captcha.php',           # Fake captcha validation
    b'redirectUrl',                    # Redirect configuration
    b'emailFromHash',                  # Email from URL hash
]


# ============================================================================
# DNS FUNCTIONS
# ============================================================================

def dns_query(domain: str, record_type: str) -> List[str]:
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        return [str(rdata) for rdata in resolver.resolve(domain, record_type)]
    except Exception:
        return []


def check_soa_freshness(domain: str) -> dict:
    """
    Query SOA record and assess freshness from serial number.
    SOA serials often use YYYYMMDDNN format (10 digits, leading 20XX).
    """
    result = {
        "soa_exists": False,
        "soa_serial": 0,
        "soa_serial_is_date": False,
        "soa_serial_date": "",
        "soa_days_since_serial": -1,
    }
    if not DNS_AVAILABLE:
        return result
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, 'SOA')
        if not answers:
            return result
        soa = answers[0]
        result["soa_exists"] = True
        serial = soa.serial
        result["soa_serial"] = serial
        serial_str = str(serial)
        if len(serial_str) == 10 and serial_str[:2] == '20':
            try:
                year = int(serial_str[0:4])
                month = int(serial_str[4:6])
                day = int(serial_str[6:8])
                from datetime import date
                serial_date = date(year, month, day)
                result["soa_serial_is_date"] = True
                result["soa_serial_date"] = serial_date.isoformat()
                result["soa_days_since_serial"] = (date.today() - serial_date).days
            except (ValueError, OverflowError):
                pass
    except Exception:
        pass
    return result


def check_dnssec(domain: str) -> bool:
    """Check if domain has DNSSEC enabled by querying for DNSKEY, fallback to DS."""
    if not DNS_AVAILABLE:
        return False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, 'DNSKEY')
        if answers:
            return True
    except Exception:
        pass
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, 'DS')
        if answers:
            return True
    except Exception:
        pass
    return False


def calculate_domain_entropy(domain: str) -> float:
    """
    Calculate Shannon entropy of the second-level domain label.
    Legitimate SLDs: ~2.0-3.2 bits/char (dictionary words, brand names)
    DGA-generated:   ~3.5-5.0+ bits/char (random character sequences)
    """
    import math
    parts = domain.lower().split('.')
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    if not sld or len(sld) < 3:
        return 0.0
    freq = {}
    for c in sld:
        freq[c] = freq.get(c, 0) + 1
    length = len(sld)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def get_ptr_record(ip: str) -> Tuple[bool, str, bool]:
    if not DNS_AVAILABLE or not ip:
        return False, "", False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, 'PTR')
        if not answers:
            return False, "", False
        ptr_hostname = str(answers[0]).rstrip('.')
        try:
            forward_ips = [str(r) for r in resolver.resolve(ptr_hostname, 'A')]
            matches = ip in forward_ips
        except Exception:
            matches = False
        return True, ptr_hostname, matches
    except Exception:
        return False, "", False


def get_spf(domain: str) -> Tuple[str, bool, Dict]:
    for record in dns_query(domain, 'TXT'):
        record = record.strip('"').strip("'")
        if record.lower().startswith('v=spf1'):
            return record, True, parse_spf(record)
    return "", False, {}


def parse_spf(spf: str) -> Dict:
    result = {"mechanism": "", "includes": [], "lookups": 0, "valid": True, "permissive": False}
    spf_lower = spf.lower()
    all_match = re.search(r'([+\-~?]?)all\b', spf_lower)
    if all_match:
        q = all_match.group(1) or '+'
        result["mechanism"] = f"{q}all"
        if q in ['+', '?']:
            result["permissive"] = True
    for m in ['include:', 'a:', 'mx:', 'ptr:', 'exists:', 'redirect=']:
        result["lookups"] += spf_lower.count(m)
    result["includes"] = re.findall(r'include:([^\s]+)', spf_lower)
    if not spf_lower.startswith('v=spf1'):
        result["valid"] = False
    return result


def get_dmarc(domain: str) -> Tuple[str, bool, Dict]:
    for record in dns_query(f"_dmarc.{domain}", 'TXT'):
        record = record.strip('"').strip("'")
        if record.lower().startswith('v=dmarc1'):
            return record, True, parse_dmarc(record)
    return "", False, {}


def parse_dmarc(dmarc: str) -> Dict:
    result = {"policy": "", "pct": 100, "rua": "", "valid": True}
    dmarc_lower = dmarc.lower()
    p = re.search(r'\bp=(\w+)', dmarc_lower)
    if p:
        result["policy"] = p.group(1)
    pct = re.search(r'\bpct=(\d+)', dmarc_lower)
    if pct:
        result["pct"] = int(pct.group(1))
    rua = re.search(r'\brua=([^;\s]+)', dmarc_lower)
    if rua:
        result["rua"] = rua.group(1)
    if not result["policy"]:
        result["valid"] = False
    return result


def check_dkim(domain: str) -> Tuple[bool, List[str]]:
    selectors = ['default', 'dkim', 'selector1', 'selector2', 'google', 'k1', 's1', 's2', 
                 'mandrill', 'everlytickey1', 'everlytickey2', 'dkim1', 'dkim2', 'mail',
                 'smtp', 'email', 'key1', 'key2', 'selector', 'sendgrid', 'amazonses']
    found = []
    for sel in selectors:
        records = dns_query(f"{sel}._domainkey.{domain}", 'TXT')
        for r in records:
            if 'v=dkim1' in r.lower() or 'p=' in r.lower():
                found.append(sel)
                break
        if len(found) >= 3:
            break
    return len(found) > 0, found


def get_mx(domain: str) -> Tuple[bool, List[Tuple[int, str]], bool]:
    if not DNS_AVAILABLE:
        return False, [], False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, 'MX')
        mx = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
        is_null = len(mx) == 1 and mx[0][0] == 0 and mx[0][1] in ['', '.']
        return True, mx, is_null
    except Exception:
        return False, [], False


def classify_mx_provider(mx_records: List[Tuple[int, str]], domain: str, config: dict) -> str:
    """Classify MX provider type based on MX hostnames.
    
    Returns: 'enterprise', 'standard', 'disposable', 'selfhosted', or 'unknown'
    """
    if not mx_records:
        return "unknown"
    
    mx_providers = config.get('mx_providers', {})
    
    # Check all MX hostnames (primary first, but check all)
    all_mx_hosts = [h.lower() for _, h in mx_records]
    
    # --- HARDCODED ENTERPRISE SAFETY NET ---
    # These patterns are so fundamental that they must match regardless of config.
    # Prevents misclassification if config fails to load or is incomplete.
    # Example: hriscloudlk-com.mail.protection.outlook.com → Microsoft 365
    _ENTERPRISE_ALWAYS = [
        "mail.protection.outlook.com",   # Microsoft 365 / Exchange Online
        "google.com",                     # Google Workspace
        "googlemail.com",                 # Google Workspace (legacy)
        "pphosted.com",                   # Proofpoint Protection
        "ppe-hosted.com",                 # Proofpoint Protection Essentials (PPE)
        "mimecast.com",                   # Mimecast
        "barracudanetworks.com",          # Barracuda
        "messagelabs.com",               # Broadcom/Symantec Email Security
        "iphmx.com",                     # Cisco IronPort / Email Security
        "fireeyecloud.com",             # Trellix / FireEye Email Security
    ]
    for mx_host in all_mx_hosts:
        for pattern in _ENTERPRISE_ALWAYS:
            if pattern in mx_host:
                return "enterprise"
    
    # Check enterprise patterns from config (highest priority)
    enterprise_patterns = mx_providers.get('enterprise', {}).get('patterns', [])
    for mx_host in all_mx_hosts:
        for pattern in enterprise_patterns:
            if pattern.lower() in mx_host:
                return "enterprise"
    
    # Check standard patterns
    standard_patterns = mx_providers.get('standard', {}).get('patterns', [])
    for mx_host in all_mx_hosts:
        for pattern in standard_patterns:
            if pattern.lower() in mx_host:
                return "standard"
    
    # Check disposable patterns
    disposable_patterns = mx_providers.get('disposable', {}).get('patterns', [])
    for mx_host in all_mx_hosts:
        for pattern in disposable_patterns:
            if pattern.lower() in mx_host:
                return "disposable"
    
    # Check if self-hosted (MX points to same domain or subdomain)
    domain_lower = domain.lower()
    for mx_host in all_mx_hosts:
        if mx_host == domain_lower or mx_host.endswith('.' + domain_lower):
            return "selfhosted"
    
    return "unknown"


def detect_mx_provider_mismatch(
    spf_includes: List[str],
    dkim_selectors: List[str],
    mx_provider_type: str,
    mx_primary: str,
    domain_age_days: int,
    whois_recently_updated: bool,
) -> Dict:
    """Detect enterprise provider ghosts in DNS — MX hijack fingerprint.
    
    When a domain's SPF record still references an enterprise email provider
    (Google Workspace, Microsoft 365, etc.) but the MX records have been
    changed to self-hosted, budget, or unknown infrastructure, it's a strong
    indicator of domain hijack. Attackers change MX to route mail through
    their own infra but rarely clean up SPF/DKIM.
    
    Returns dict with: mismatch (bool), ghost_provider, evidence (list), confidence
    """
    result = {
        "mismatch": False,
        "ghost_provider": "",
        "evidence": [],
        "confidence": "",
    }
    
    # Only flag if current MX is NOT enterprise — if they moved from Google
    # to Microsoft, that's a migration, not a hijack.
    if mx_provider_type == "enterprise":
        return result
    
    # Only meaningful on established domains — new domains with messy DNS
    # are just misconfigured, not hijacked.
    if domain_age_days >= 0 and domain_age_days < 180:
        return result
    
    # === SPF → MX provider mapping ===
    # Maps: SPF include substring → (provider_name, MX substring that should match)
    _SPF_TO_PROVIDER = [
        # Google Workspace
        ('_spf.google.com',             'Google Workspace', 'google.com'),
        ('google.com',                   'Google Workspace', 'google.com'),
        ('googlemail.com',               'Google Workspace', 'googlemail.com'),
        # Microsoft 365
        ('spf.protection.outlook.com',   'Microsoft 365',   'mail.protection.outlook.com'),
        ('outlook.com',                  'Microsoft 365',   'outlook.com'),
        # Proofpoint
        ('pphosted.com',                 'Proofpoint',      'pphosted.com'),
        ('ppe-hosted.com',               'Proofpoint',      'ppe-hosted.com'),
        # Mimecast
        ('mimecast.com',                 'Mimecast',        'mimecast.com'),
    ]
    
    # === DKIM selector → provider mapping ===
    # Only high-confidence selectors that are near-exclusive to one provider.
    _DKIM_TO_PROVIDER = {
        'google':    'Google Workspace',
        'selector1': 'Microsoft 365',
        'selector2': 'Microsoft 365',
    }
    
    mx_lower = mx_primary.lower() if mx_primary else ""
    spf_lower = [inc.lower() for inc in spf_includes]
    
    ghost_providers = {}  # provider_name → list of evidence strings
    
    # Check SPF includes for enterprise ghosts
    for spf_pattern, provider_name, mx_pattern in _SPF_TO_PROVIDER:
        # Does SPF reference this provider?
        spf_match = any(spf_pattern in inc for inc in spf_lower)
        if not spf_match:
            continue
        # Does current MX match this provider?
        mx_match = mx_pattern in mx_lower
        if mx_match:
            continue  # MX still matches — no ghost
        # Ghost found: SPF references provider but MX doesn't match
        if provider_name not in ghost_providers:
            ghost_providers[provider_name] = []
        ghost_providers[provider_name].append(f"SPF includes {spf_pattern}")
    
    # Check DKIM selectors for enterprise ghosts
    for sel in dkim_selectors:
        sel_lower = sel.lower()
        if sel_lower in _DKIM_TO_PROVIDER:
            provider_name = _DKIM_TO_PROVIDER[sel_lower]
            # Check if MX matches this provider
            mx_patterns_for_provider = [
                p[2] for p in _SPF_TO_PROVIDER if p[1] == provider_name
            ]
            mx_match = any(pat in mx_lower for pat in mx_patterns_for_provider)
            if not mx_match:
                if provider_name not in ghost_providers:
                    ghost_providers[provider_name] = []
                ghost_providers[provider_name].append(f"DKIM selector '{sel}' present")
    
    if not ghost_providers:
        return result
    
    # Pick the provider with the most evidence
    best_provider = max(ghost_providers, key=lambda p: len(ghost_providers[p]))
    evidence = ghost_providers[best_provider]
    
    # Add MX context to evidence
    if mx_provider_type == "selfhosted":
        evidence.append(f"MX now self-hosted ({mx_primary})")
    elif mx_provider_type == "disposable":
        evidence.append(f"MX now disposable ({mx_primary})")
    elif mx_provider_type == "budget_shared":
        evidence.append(f"MX now budget shared ({mx_primary})")
    else:
        evidence.append(f"MX now {mx_provider_type} ({mx_primary})")
    
    # Determine confidence
    has_spf_ghost = any("SPF" in e for e in evidence)
    has_dkim_ghost = any("DKIM" in e for e in evidence)
    
    if has_spf_ghost and has_dkim_ghost and whois_recently_updated:
        confidence = "HIGH"
    elif has_spf_ghost and (whois_recently_updated or mx_provider_type in ("selfhosted", "disposable")):
        confidence = "HIGH"
    elif has_spf_ghost:
        confidence = "MEDIUM"
    else:
        # DKIM ghost alone — could be residual from legitimate migration
        confidence = "LOW"
    
    result["mismatch"] = True
    result["ghost_provider"] = best_provider
    result["evidence"] = evidence
    result["confidence"] = confidence
    
    return result


def get_registrable_domain(hostname: str) -> str:
    """Extract the registrable domain from a hostname.
    
    Uses same compound TLD logic as _extract_base_and_tld.
    Examples:
        mail.example.com → example.com
        portal.sub.example.co.uk → example.co.uk
        example.com → example.com
    """
    hostname = hostname.lower().strip().rstrip('.')
    SLD_INDICATORS = {'com', 'co', 'org', 'net', 'ac', 'gov', 'edu', 'me', 'gen', 'mil'}
    parts = hostname.split('.')
    
    if len(parts) >= 3:
        sld = parts[-2]
        cctld = parts[-1]
        if sld in SLD_INDICATORS and len(cctld) <= 3:
            # Compound TLD: need at least 3 parts for registrable
            return '.'.join(parts[-3:])
    
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    
    return hostname


def is_subdomain_of(domain: str, parent: str) -> bool:
    """Check if domain is a subdomain of parent (not the parent itself)."""
    d = domain.lower().rstrip('.')
    p = parent.lower().rstrip('.')
    return d != p and d.endswith('.' + p)


def detect_subdomain_delegation_abuse(
    submitted_domain: str,
    submitted_ip: str,
    submitted_asn: str,
    submitted_mx_provider_type: str,
    config: dict,
) -> Dict:
    """Detect subdomain delegation abuse — subdomain points to different infra than parent.
    
    Attackers who gain DNS access to a legitimate company can create subdomains
    (mail.legit.com, portal.legit.com) pointing to their own infrastructure.
    The parent domain passes all trust checks (aged, enterprise MX, DMARC).
    
    This function resolves the parent domain and compares infrastructure signals.
    
    Returns dict with: is_subdomain, parent_domain, parent_ip, parent_asn, parent_asn_org,
                       parent_mx_provider_type, divergent (bool), evidence (list), confidence
    """
    result = {
        "is_subdomain": False,
        "parent_domain": "",
        "parent_ip": "",
        "parent_asn": "",
        "parent_asn_org": "",
        "parent_mx_provider_type": "",
        "divergent": False,
        "evidence": [],
        "confidence": "",
    }
    
    parent = get_registrable_domain(submitted_domain)
    if not parent or parent == submitted_domain.lower().rstrip('.'):
        return result  # Not a subdomain
    
    # www.example.com pointing to different infra than example.com is completely normal.
    # Many legitimate sites use CDN for www while apex is on origin, or vice versa.
    # Never flag www subdomains as delegation abuse.
    subdomain_part = submitted_domain.lower().rstrip('.').replace(parent, '').rstrip('.')
    if subdomain_part == 'www':
        return result
    
    result["is_subdomain"] = True
    result["parent_domain"] = parent
    
    # Resolve parent IP
    try:
        parent_ip = socket.gethostbyname(parent)
        result["parent_ip"] = parent_ip
    except Exception:
        # Parent doesn't resolve — could be parked or expired.
        # Not enough info to call delegation abuse.
        return result
    
    # Get parent ASN
    parent_asn, parent_asn_org = get_asn_info(parent_ip)
    result["parent_asn"] = parent_asn
    result["parent_asn_org"] = parent_asn_org
    
    # Get parent MX provider
    try:
        parent_mx_exists, parent_mx_records, _ = get_mx(parent)
        if parent_mx_records:
            result["parent_mx_provider_type"] = classify_mx_provider(
                parent_mx_records, parent, config
            )
    except Exception:
        pass
    
    evidence = []
    
    # --- Infrastructure comparison ---
    
    # 1. IP comparison: same /24 subnet?
    same_subnet = False
    if submitted_ip and parent_ip:
        sub_parts = submitted_ip.split('.')
        par_parts = parent_ip.split('.')
        if len(sub_parts) == 4 and len(par_parts) == 4:
            same_subnet = sub_parts[:3] == par_parts[:3]
            if not same_subnet and submitted_ip != parent_ip:
                evidence.append(f"Different IP: subdomain={submitted_ip}, parent={parent_ip}")
    
    # 2. ASN comparison: same network?
    same_asn = (submitted_asn == parent_asn) if submitted_asn and parent_asn else True
    if not same_asn:
        evidence.append(
            f"Different ASN: subdomain=AS{submitted_asn} ({submitted_asn}), "
            f"parent=AS{parent_asn} ({parent_asn_org})"
        )
    
    # 3. MX provider divergence: parent has enterprise, subdomain has self-hosted/disposable?
    parent_mx = result["parent_mx_provider_type"]
    mx_divergent = False
    if parent_mx == "enterprise" and submitted_mx_provider_type in ("selfhosted", "disposable", "unknown"):
        mx_divergent = True
        evidence.append(
            f"MX divergence: parent={parent_mx}, subdomain={submitted_mx_provider_type}"
        )
    
    if not evidence:
        return result  # Infrastructure matches — no divergence
    
    # Determine confidence
    result["divergent"] = True
    
    if not same_asn and mx_divergent:
        result["confidence"] = "HIGH"
    elif not same_asn and not same_subnet:
        result["confidence"] = "HIGH"
    elif not same_asn:
        result["confidence"] = "MEDIUM"
    elif mx_divergent:
        result["confidence"] = "MEDIUM"
    elif not same_subnet:
        result["confidence"] = "LOW"
    else:
        result["confidence"] = "LOW"
    
    result["evidence"] = evidence
    return result


def detect_ct_gap(
    ct_dates: List[datetime],
    domain_age_days: int,
    ct_recent_issuance: bool,
    whois_recently_updated: bool,
) -> Dict:
    """Detect aged domain purchase via Certificate Transparency gap analysis.
    
    When attackers buy expired-but-aged domains from auction sites, the CT logs
    show a characteristic gap: active certs for years, then a long silence
    (6+ months), then a sudden new cert. The domain_age_days is high (passes
    age checks) but the cert history reveals the domain was dead.
    
    Args:
        ct_dates: Sorted list of cert not_before datetimes from CT logs
        domain_age_days: Domain age in days
        ct_recent_issuance: Whether most recent cert is within 7 days
        whois_recently_updated: Whether WHOIS was updated recently
    
    Returns dict with: gap_months, reactivated (bool), evidence (str)
    """
    result = {
        "gap_months": -1,
        "reactivated": False,
        "evidence": "",
    }
    
    if len(ct_dates) < 2:
        return result
    
    # Only relevant for established domains — new domains can't have gaps
    if domain_age_days >= 0 and domain_age_days < 365:
        return result
    
    # Find the largest gap between consecutive cert issuances
    max_gap_days = 0
    gap_start = None
    gap_end = None
    
    for i in range(1, len(ct_dates)):
        gap = (ct_dates[i] - ct_dates[i-1]).days
        if gap > max_gap_days:
            max_gap_days = gap
            gap_start = ct_dates[i-1]
            gap_end = ct_dates[i]
    
    gap_months = max_gap_days // 30
    result["gap_months"] = gap_months
    
    if gap_months < 6:
        return result  # Normal cert renewal gap
    
    # We have a significant gap (6+ months). Now check if it looks like reactivation.
    now = datetime.now(timezone.utc)
    
    # How recent is the cert after the gap?
    if gap_end:
        days_since_reactivation = (now - gap_end).days
    else:
        return result
    
    evidence_parts = []
    evidence_parts.append(
        f"{gap_months}mo gap in CT logs ({gap_start.strftime('%Y-%m') if gap_start else '?'} "
        f"→ {gap_end.strftime('%Y-%m') if gap_end else '?'})"
    )
    
    # Reactivation = gap ended recently (within 90 days) on an aged domain
    if days_since_reactivation <= 90 and domain_age_days > 365:
        result["reactivated"] = True
        evidence_parts.append(
            f"Domain is {domain_age_days}d old but cert activity resumed {days_since_reactivation}d ago"
        )
        if whois_recently_updated:
            evidence_parts.append("WHOIS also recently updated — likely domain purchase/transfer")
        if ct_recent_issuance:
            evidence_parts.append("New cert issued in last 7 days")
    
    result["evidence"] = "; ".join(evidence_parts)
    return result


def detect_cdn_hosted(asn: str) -> Tuple[bool, str]:
    """Check if the domain's IP belongs to a CDN/proxy provider.
    
    When a domain resolves to a CDN, the actual origin server is hidden.
    This is normal for legitimate sites, but attackers use Cloudflare Tunnels
    and similar services to hide phishing kit origins behind reputable CDN IPs.
    
    Returns: (is_cdn, provider_name)
    """
    if asn and asn in CDN_ASN_MAP:
        return True, CDN_ASN_MAP[asn]
    return False, ""


def detect_cdn_tunnel_abuse(
    is_cdn: bool,
    cdn_provider: str,
    domain_age_days: int,
    ct_log_count: int,
    ct_recent_issuance: bool,
    has_credential_form: bool,
    has_oauth_phish: bool,
    is_minimal_shell: bool,
    has_parking: bool,
    has_js_redirect: bool,
    hosting_provider_type: str,
) -> Dict:
    """Detect CDN tunnel abuse — phishing kit hidden behind CDN proxy.
    
    The domain resolves to Cloudflare/CDN IPs (looks reputable), has valid
    universal SSL certs, but serves a phishing kit from a hidden origin.
    
    Suspicious combo: CDN-hosted + (new domain OR no CT history) + 
                      (minimal content OR credential form OR OAuth phish)
    
    Returns dict with: suspect (bool), evidence (list)
    """
    result = {"suspect": False, "evidence": []}
    
    if not is_cdn:
        return result
    
    evidence = []
    risk_signals = 0
    
    # Domain youth / freshness signals
    if domain_age_days >= 0 and domain_age_days < 90:
        evidence.append(f"New domain ({domain_age_days}d old) on {cdn_provider}")
        risk_signals += 1
    if ct_log_count == 0:
        evidence.append(f"No CT history — zero organic cert presence")
        risk_signals += 1
    if ct_recent_issuance and domain_age_days > 180:
        evidence.append(f"Fresh cert on established domain behind {cdn_provider}")
        risk_signals += 1
    
    # Content signals — what's the CDN serving?
    if has_credential_form:
        evidence.append("Credential form behind CDN proxy")
        risk_signals += 1
    if has_oauth_phish:
        evidence.append("OAuth consent phishing behind CDN proxy")
        risk_signals += 1
    if is_minimal_shell or has_js_redirect:
        evidence.append("Minimal shell / JS redirect behind CDN — classic tunnel abuse")
        risk_signals += 1
    if has_parking:
        evidence.append("Parked page behind CDN — domain not actively used")
        risk_signals += 1
    
    # Need at least 2 risk signals to flag (CDN + one youth + one content indicator)
    if risk_signals >= 2:
        result["suspect"] = True
        result["evidence"] = evidence
    
    return result


def detect_quishing_profile(
    domain: str,
    domain_age_days: int,
    ct_log_count: int,
    is_minimal_shell: bool,
    has_js_redirect: bool,
    has_credential_form: bool,
    has_oauth_phish: bool,
    tld: str,
) -> Dict:
    """Detect QR code phishing (quishing) landing page profile.
    
    Quishing domains are registered purely as QR-to-phish destinations:
    - Extremely minimal pages (redirect or single form)
    - Very new domains or no CT history
    - Frequently use .page, .link, .click, .qr TLDs
    - Zero organic web presence
    
    Returns dict with: profile (bool), evidence (list)
    """
    result = {"profile": False, "evidence": []}
    
    evidence = []
    score = 0
    
    # TLD signal
    tld_with_dot = '.' + tld if not tld.startswith('.') else tld
    if tld_with_dot.lower() in QUISHING_TLDS:
        evidence.append(f"Quishing-associated TLD ({tld_with_dot})")
        score += 2
    
    # Domain freshness
    if domain_age_days >= 0 and domain_age_days < 30:
        evidence.append(f"Very new domain ({domain_age_days}d)")
        score += 2
    elif domain_age_days >= 0 and domain_age_days < 90:
        evidence.append(f"New domain ({domain_age_days}d)")
        score += 1
    
    # No organic presence
    if ct_log_count == 0:
        evidence.append("No CT history — zero prior web presence")
        score += 1
    
    # Minimal content
    if is_minimal_shell:
        evidence.append("Minimal page shell — classic QR redirect target")
        score += 2
    if has_js_redirect:
        evidence.append("JS redirect — QR → redirect → phish")
        score += 1
    
    # Payload
    if has_credential_form:
        evidence.append("Credential form — phishing endpoint")
        score += 1
    if has_oauth_phish:
        evidence.append("OAuth consent phish — QR → OAuth flow")
        score += 1
    
    # Short domain name (QR domains are often short for easy encoding)
    base = domain.split('.')[0] if '.' in domain else domain
    if len(base) <= 6:
        evidence.append(f"Short domain name ({base}) — optimized for QR encoding")
        score += 1
    
    # Need quishing TLD + at least 1 other signal, or 4+ non-TLD signals
    if (tld_with_dot.lower() in QUISHING_TLDS and score >= 4) or score >= 5:
        result["profile"] = True
        result["evidence"] = evidence
    
    return result


def get_bimi(domain: str) -> Tuple[bool, str]:
    for record in dns_query(f"default._bimi.{domain}", 'TXT'):
        record = record.strip('"').strip("'")
        if record.lower().startswith('v=bimi1'):
            return True, record[:200]
    return False, ""


def get_mta_sts(domain: str) -> Tuple[bool, str]:
    for record in dns_query(f"_mta-sts.{domain}", 'TXT'):
        record = record.strip('"').strip("'")
        if 'v=sts' in record.lower():
            return True, record[:200]
    return False, ""


def check_blacklist(query: str, zone: str) -> Optional[bool]:
    """
    Check if query is listed in a DNSBL zone.
    
    v6.2: Now distinguishes between "not listed" and "check failed".
    
    Returns:
        True  = listed (DNSBL returned a result)
        False = NOT listed (NXDOMAIN — definitive clean)
        None  = INCONCLUSIVE (timeout, SERVFAIL, rate limited — we don't know)
    """
    if not DNS_AVAILABLE:
        return None  # Can't check = inconclusive, NOT clean
    
    cache_key = f"{query}:{zone}"
    
    # Check cache first (v6.2)
    if cache_key in _dnsbl_cache:
        cached_result, cached_time = _dnsbl_cache[cache_key]
        if _time.time() - cached_time < DNSBL_CACHE_TTL:
            return cached_result
        else:
            del _dnsbl_cache[cache_key]  # Expired
    
    result = None  # Default: inconclusive
    
    for attempt in range(1 + DNSBL_RETRIES):
        if attempt > 0:
            _time.sleep(DNSBL_RETRY_DELAY)  # Backoff between retries
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNSBL_TIMEOUT
            resolver.lifetime = DNSBL_TIMEOUT
            resolver.resolve(f"{query}.{zone}", 'A')
            result = True  # Listed
            break
            
        except dns.resolver.NXDOMAIN:
            # Definitive: domain is NOT on this blacklist
            result = False
            break
            
        except dns.resolver.NoAnswer:
            # Zone exists but no A record — treat as not listed
            result = False
            break
            
        except dns.resolver.NoNameservers:
            # SERVFAIL / all nameservers failed — likely rate limited
            continue  # Retry
            
        except dns.exception.Timeout:
            # Timeout — likely rate limited or network issue
            continue  # Retry
            
        except Exception:
            # Other DNS errors — inconclusive
            continue  # Retry
    
    # Cache the result (even inconclusive, to avoid hammering a broken zone)
    _dnsbl_cache[cache_key] = (result, _time.time())
    
    return result


def check_domain_blacklists(domain: str, blacklists: List[str]) -> Tuple[List[str], int, int]:
    """
    Check domain against all configured DNSBL zones.
    
    v6.2: Now returns inconclusive count as third element.
    
    Returns: (hits, hit_count, inconclusive_count)
    """
    hits = []
    inconclusive = 0
    
    for bl in blacklists:
        result = check_blacklist(domain, bl)
        if result is True:
            hits.append(bl)
        elif result is None:
            inconclusive += 1
        # False = clean, nothing to track
        
        # Rate limit: pause between queries to avoid triggering DNSBL limits
        if bl != blacklists[-1]:  # Don't sleep after last query
            _time.sleep(DNSBL_INTER_QUERY_DELAY)
    
    return hits, len(hits), inconclusive


def check_ip_blacklists(ip: str, blacklists: List[str]) -> Tuple[List[str], int, int]:
    """
    Check IP against all configured RBL zones.
    
    v6.2: Now returns inconclusive count as third element.
    
    Returns: (hits, hit_count, inconclusive_count)
    """
    if not ip:
        return [], 0, 0
    reversed_ip = '.'.join(reversed(ip.split('.')))
    hits = []
    inconclusive = 0
    
    for bl in blacklists:
        result = check_blacklist(reversed_ip, bl)
        if result is True:
            hits.append(bl)
        elif result is None:
            inconclusive += 1
        
        if bl != blacklists[-1]:
            _time.sleep(DNSBL_INTER_QUERY_DELAY)
    
    return hits, len(hits), inconclusive


# ============================================================================
# HOSTING PROVIDER DETECTION
# ============================================================================

def get_asn_info(ip: str) -> Tuple[str, str]:
    """
    Look up ASN number and organization for an IP via Team Cymru DNS.
    
    Query: reversed_ip.origin.asn.cymru.com → TXT record
    Response format: "ASN | IP/CIDR | CC | Registry | Date"
    Then: AS<number>.asn.cymru.com → TXT record for org name
    
    Returns: (asn_number, asn_org_name) or ("", "") on failure
    """
    if not DNS_AVAILABLE or not ip:
        return "", ""
    
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        
        # Step 1: Get ASN number from IP
        answers = resolver.resolve(f"{reversed_ip}.origin.asn.cymru.com", 'TXT')
        if not answers:
            return "", ""
        
        txt = str(answers[0]).strip('"').strip("'")
        parts = [p.strip() for p in txt.split('|')]
        if not parts:
            return "", ""
        
        asn_number = parts[0].strip()
        if not asn_number:
            return "", ""
        
        # Step 2: Get org name from ASN
        try:
            org_answers = resolver.resolve(f"AS{asn_number}.asn.cymru.com", 'TXT')
            if org_answers:
                org_txt = str(org_answers[0]).strip('"').strip("'")
                org_parts = [p.strip() for p in org_txt.split('|')]
                # Org name is the last field
                asn_org = org_parts[-1].strip() if len(org_parts) >= 5 else ""
                return asn_number, asn_org
        except Exception:
            pass
        
        return asn_number, ""
    except Exception:
        return "", ""


def check_hosting_provider(domain: str, ip: str, ns_records: List[str] = None, 
                           ptr_record: str = "", hosting_config: dict = None) -> Dict:
    """
    Detect hosting provider using multiple signals:
    1. Nameserver patterns (most hosts use branded NS)
    2. ASN lookup (network owner identification)
    3. PTR record patterns (reverse DNS often shows host)
    
    Returns dict with provider info and risk tier.
    """
    result = {
        "provider": "",
        "provider_type": "",      # budget_shared, free, suspect, premium, unknown
        "detected_via": "",       # ns, asn, ptr
        "asn": "",
        "asn_org": "",
        "match_details": [],      # What matched and how
    }
    
    if not hosting_config:
        hosting_config = {}
    
    providers = hosting_config.get("hosting_providers", {})
    if not providers:
        return result
    
    # Collect NS records if not provided
    if ns_records is None:
        ns_records = dns_query(domain, 'NS')
    
    ns_lower = [ns.lower().rstrip('.') for ns in ns_records]
    ptr_lower = ptr_record.lower() if ptr_record else ""
    
    # Get ASN info
    asn_number, asn_org = get_asn_info(ip)
    result["asn"] = asn_number
    result["asn_org"] = asn_org
    asn_org_lower = asn_org.lower()
    
    best_match = None
    best_priority = 999  # Lower = better match
    
    for provider_key, provider_def in providers.items():
        matched = False
        match_method = ""
        
        # Check NS patterns (priority 1 - most reliable)
        ns_patterns = provider_def.get("ns_patterns", [])
        for pattern in ns_patterns:
            pattern_lower = pattern.lower()
            for ns in ns_lower:
                if pattern_lower in ns:
                    matched = True
                    match_method = "ns"
                    break
            if matched:
                break
        
        # Check ASN numbers (priority 2 - very reliable)
        if not matched:
            asn_numbers = provider_def.get("asn_numbers", [])
            if asn_number and asn_number in [str(a) for a in asn_numbers]:
                matched = True
                match_method = "asn"
        
        # Check ASN org name patterns (priority 3 - reliable)
        if not matched:
            asn_patterns = provider_def.get("asn_org_patterns", [])
            for pattern in asn_patterns:
                if pattern.lower() in asn_org_lower:
                    matched = True
                    match_method = "asn_org"
                    break
        
        # Check PTR patterns (priority 4 - good but can be changed)
        if not matched and ptr_lower:
            ptr_patterns = provider_def.get("ptr_patterns", [])
            for pattern in ptr_patterns:
                if pattern.lower() in ptr_lower:
                    matched = True
                    match_method = "ptr"
                    break
        
        if matched:
            # Determine priority (ns > asn > ptr)
            priority_map = {"ns": 1, "asn": 2, "asn_org": 3, "ptr": 4}
            priority = priority_map.get(match_method, 5)
            
            if priority < best_priority:
                best_priority = priority
                best_match = {
                    "provider": provider_def.get("name", provider_key),
                    "provider_type": provider_def.get("type", "unknown"),
                    "detected_via": match_method,
                    "key": provider_key,
                }
    
    if best_match:
        result["provider"] = best_match["provider"]
        result["provider_type"] = best_match["provider_type"]
        result["detected_via"] = best_match["detected_via"]
    
    return result


# ============================================================================
# NAMESERVER RISK DETECTION
# ============================================================================

def check_ns_risk(ns_records: List[str], ns_risk_config: dict) -> Dict:
    """
    Analyse NS records for risk indicators independent of hosting provider.
    
    Detects:
      - Parking / placeholder nameservers (domain unused / for-sale)
      - Dynamic DNS providers (rapid IP rotation, phishing infra)
      - Free / anonymous authoritative DNS (minimal investment)
      - Lame delegation (zero NS records — broken / abandoned)
      - Single NS (fragile / hastily-set-up)
    
    Returns dict with boolean flags and the matched pattern strings.
    """
    result = {
        "ns_count": len(ns_records),
        "is_parking": False,
        "parking_match": "",
        "is_dynamic_dns": False,
        "dynamic_dns_match": "",
        "is_free_dns": False,
        "free_dns_match": "",
        "is_enterprise_ns": False,
        "enterprise_ns_match": "",
        "is_lame_delegation": False,
        "is_single_ns": False,
    }
    
    # Lame delegation: domain resolved (we have an IP) but zero NS records
    if len(ns_records) == 0:
        result["is_lame_delegation"] = True
        return result
    
    if len(ns_records) == 1:
        result["is_single_ns"] = True
    
    ns_lower = [ns.lower().rstrip('.') for ns in ns_records]
    
    # Known false-positive NS patterns — these LOOK like parking services but are
    # actually legitimate hosting provider nameservers.
    # dns-parking.com = Hostinger's standard NS (ns1/ns2.dns-parking.com) used by
    #                   millions of active sites.  The name is misleading.
    _PARKING_NS_WHITELIST = [
        "dns-parking.com",   # Hostinger default NS
    ]
    
    def _is_whitelisted(ns_value: str) -> bool:
        return any(wl in ns_value for wl in _PARKING_NS_WHITELIST)
    
    # Check parking NS patterns (skip whitelisted entries)
    parking_patterns = ns_risk_config.get("parking_ns", [])
    for pattern in parking_patterns:
        pattern_lower = pattern.lower()
        for ns in ns_lower:
            if pattern_lower in ns and not _is_whitelisted(ns):
                result["is_parking"] = True
                result["parking_match"] = pattern
                break
        if result["is_parking"]:
            break
    
    # Check dynamic DNS NS patterns
    dynamic_patterns = ns_risk_config.get("dynamic_dns_ns", [])
    for pattern in dynamic_patterns:
        pattern_lower = pattern.lower()
        for ns in ns_lower:
            if pattern_lower in ns:
                result["is_dynamic_dns"] = True
                result["dynamic_dns_match"] = pattern
                break
        if result["is_dynamic_dns"]:
            break
    
    # Check free DNS NS patterns (skip if already flagged as parking or dynamic)
    if not result["is_parking"] and not result["is_dynamic_dns"]:
        free_patterns = ns_risk_config.get("free_dns_ns", [])
        for pattern in free_patterns:
            pattern_lower = pattern.lower()
            for ns in ns_lower:
                if pattern_lower in ns:
                    result["is_free_dns"] = True
                    result["free_dns_match"] = pattern
                    break
            if result["is_free_dns"]:
                break

    # Check enterprise NS patterns (skip if already flagged as risk)
    if not result["is_parking"] and not result["is_dynamic_dns"] and not result["is_free_dns"]:
        enterprise_patterns = ns_risk_config.get("enterprise_ns", [])
        for pattern in enterprise_patterns:
            pattern_lower = pattern.lower()
            for ns in ns_lower:
                if pattern_lower in ns:
                    result["is_enterprise_ns"] = True
                    result["enterprise_ns_match"] = pattern
                    break
            if result["is_enterprise_ns"]:
                break

    return result


# ============================================================================
# TYPOSQUATTING DETECTION
# ============================================================================

def check_typosquatting(domain: str, protected_brands: List[str]) -> Tuple[str, float]:
    domain_lower = domain.lower()
    parts = domain_lower.split('.')
    tld = parts[-1] if parts else ""
    brand_like_tlds = {'app', 'shop', 'store', 'bank', 'pay', 'mail', 'cloud', 'tech'}
    
    if len(parts) >= 2:
        main_part = parts[-2]
    else:
        main_part = parts[0]
    
    if len(main_part) < 4:
        return "", 0.0
    
    def normalize(s: str) -> str:
        s = s.replace('-', '').replace('_', '')
        s = s.replace('0', 'o').replace('1', 'l').replace('3', 'e')
        s = s.replace('4', 'a').replace('5', 's').replace('@', 'a')
        return s
    
    normalized_main = normalize(main_part)
    best_match = ""
    best_score = 0.0
    
    for brand in protected_brands:
        if domain_lower == f"{brand}.com" or domain_lower == f"{brand}.net" or domain_lower == f"{brand}.org":
            continue
        if tld in brand_like_tlds:
            tld_brand_similarity = difflib.SequenceMatcher(None, tld, brand).ratio()
            if tld_brand_similarity >= 0.6:
                continue
        if len(brand) <= 3:
            continue
        
        scores = []
        base_ratio = difflib.SequenceMatcher(None, main_part, brand).ratio()
        normalized_ratio = difflib.SequenceMatcher(None, normalized_main, brand).ratio()
        
        if base_ratio >= 0.75:
            scores.append(base_ratio)
        if normalized_ratio >= 0.75:
            scores.append(normalized_ratio)
        
        if brand in main_part and main_part != brand and len(main_part) >= len(brand) + 2:
            scores.append(0.85)
        if brand in normalized_main and normalized_main != brand and len(normalized_main) >= len(brand) + 2:
            scores.append(0.80)
        
        if len(brand) >= 5:
            for i in range(len(brand)):
                truncated = brand[:i] + brand[i+1:]
                if main_part == truncated or normalized_main == truncated:
                    scores.append(0.90)
        
        if len(main_part) == len(brand) + 1 and len(brand) >= 4:
            for i in range(len(main_part)):
                reduced = main_part[:i] + main_part[i+1:]
                if reduced == brand:
                    scores.append(0.88)
        
        if len(main_part) == len(brand) and len(brand) >= 5:
            diffs = sum(1 for a, b in zip(main_part, brand) if a != b)
            if diffs == 2:
                scores.append(0.85)
        
        max_score = max(scores) if scores else 0.0
        if max_score > best_score and max_score >= 0.78:
            best_score = max_score
            best_match = brand
    
    return best_match, best_score


def is_disposable_email(domain: str, disposable_list: List[str]) -> bool:
    domain_lower = domain.lower()
    if domain_lower in disposable_list:
        return True
    for disp in disposable_list:
        if domain_lower.endswith('.' + disp):
            return True
    disposable_patterns = [
        r'^temp.*mail', r'^fake.*mail', r'^trash.*mail', r'^throw.*mail',
        r'^disposable', r'^temporary.*email', r'^10minute', r'^guerrilla',
    ]
    for pattern in disposable_patterns:
        if re.search(pattern, domain_lower):
            return True
    return False


def check_homoglyph_domain(domain: str, protected_brands: List[str]) -> Dict:
    """Detect IDN homoglyph attacks — domains using Unicode lookalike characters.
    
    Attackers register domains like xn--pypal-4ve.com (paуpal.com with Cyrillic у)
    that look identical to legitimate brands in browsers and email clients.
    
    Detection approach:
    1. If domain is punycode (xn--), decode to Unicode
    2. Map each Unicode char through HOMOGLYPH_MAP to find Latin equivalents
    3. Compare the Latin-mapped result against protected brands
    4. Also check confusable TLD pairs (.corn → .com visual confusion)
    
    Returns dict with: is_homoglyph, target_brand, decoded_display, evidence
    """
    result = {
        "is_homoglyph": False,
        "target_brand": "",
        "decoded_display": "",
        "evidence": "",
    }
    
    domain_lower = domain.lower().strip().rstrip('.')
    parts = domain_lower.split('.')
    
    # Check for punycode labels (xn--)
    has_punycode = any(label.startswith('xn--') for label in parts)
    
    # Decode punycode to Unicode
    decoded_domain = domain_lower
    if has_punycode:
        try:
            decoded_domain = domain_lower.encode('ascii').decode('idna')
        except (UnicodeError, UnicodeDecodeError):
            try:
                # Try label-by-label decoding
                decoded_parts = []
                for part in parts:
                    if part.startswith('xn--'):
                        decoded_parts.append(part.encode('ascii').decode('idna'))
                    else:
                        decoded_parts.append(part)
                decoded_domain = '.'.join(decoded_parts)
            except Exception:
                return result  # Can't decode — skip
    
    result["decoded_display"] = decoded_domain
    
    # Check if decoded domain has any non-ASCII characters
    has_non_ascii = any(ord(c) > 127 for c in decoded_domain)
    
    if not has_non_ascii and not has_punycode:
        # Not an IDN domain — check confusable TLD pairs only
        tld = '.' + parts[-1] if parts else ''
        for confusable, legitimate in CONFUSABLE_TLD_PAIRS.items():
            if tld == confusable:
                # Reconstruct with legitimate TLD and check against brands
                base = '.'.join(parts[:-1])
                legit_domain = base + legitimate
                legit_main = legit_domain.split('.')[-2] if '.' in legit_domain else legit_domain
                for brand in protected_brands:
                    if len(brand) > 3 and legit_main == brand:
                        result["is_homoglyph"] = True
                        result["target_brand"] = brand
                        result["evidence"] = f"Confusable TLD: {tld} looks like {legitimate} → {brand}{legitimate}"
                        return result
        return result
    
    # Map Unicode homoglyphs to Latin equivalents
    # Extract the main domain part (before TLD)
    if len(parts) >= 2:
        main_label = parts[-2] if len(parts[-1]) <= 3 else parts[-1]
    else:
        main_label = parts[0]
    
    # Convert using homoglyph map
    latin_mapped = []
    mixed_script = False
    has_homoglyph = False
    for char in main_label:
        if char in HOMOGLYPH_MAP:
            latin_mapped.append(HOMOGLYPH_MAP[char])
            has_homoglyph = True
        elif ord(char) > 127:
            # Non-ASCII char not in our map — keep as-is
            latin_mapped.append(char)
        else:
            latin_mapped.append(char)
            if has_homoglyph:
                mixed_script = True  # Mix of Latin + non-Latin = suspicious
    
    if not has_homoglyph:
        return result
    
    latin_equivalent = ''.join(latin_mapped)
    
    # Compare against protected brands
    for brand in protected_brands:
        if len(brand) <= 3:
            continue
        # Direct match
        if latin_equivalent == brand:
            result["is_homoglyph"] = True
            result["target_brand"] = brand
            result["evidence"] = (
                f"IDN homoglyph: {decoded_domain} (punycode: {domain_lower}) "
                f"→ Latin equivalent '{latin_equivalent}' matches brand '{brand}'"
            )
            return result
        # High similarity (accounts for partial homoglyph + typo combos)
        ratio = difflib.SequenceMatcher(None, latin_equivalent, brand).ratio()
        if ratio >= 0.85 and has_homoglyph:
            result["is_homoglyph"] = True
            result["target_brand"] = brand
            result["evidence"] = (
                f"IDN homoglyph (similarity {ratio:.0%}): {decoded_domain} "
                f"→ Latin equivalent '{latin_equivalent}' ≈ brand '{brand}'"
            )
            return result
    
    return result


def check_domain_name_patterns(domain: str, config: dict = None) -> Dict:
    """
    Detect tech support scam / brand impersonation patterns in domain name.
    
    Patterns detected:
    1. Suspicious prefixes: app-, my-, get-, support-, login-, etc.
    2. Suspicious suffixes: account, setup, cancellation, support, etc.
    3. Tech support scam TLDs: .support, .tech, .help, etc.
    4. Brand names embedded in domain: spectrum, verizon, norton, etc.
    5. Brand + spoofing keyword: easyjetconnect, amazonverify, etc. (v5.2)
    
    Returns dict with detection results.
    """
    result = {
        "has_suspicious_prefix": False,
        "suspicious_prefix": "",
        "has_suspicious_suffix": False, 
        "suspicious_suffix": "",
        "is_tech_support_tld": False,
        "domain_impersonates_brand": "",
        "brand_spoofing_keyword": "",
        "brand_plus_keyword": False,
        "patterns_found": [],
        "risk_score_addition": 0,
    }
    
    domain_lower = domain.lower().strip()
    
    # Extract main part (without TLD)
    parts = domain_lower.rsplit('.', 1)
    if len(parts) == 2:
        main_part = parts[0]
        tld = '.' + parts[1]
    else:
        main_part = domain_lower
        tld = ""
    
    # Check for multi-part TLDs like .co.uk
    full_tld = ""
    for tst in TECH_SUPPORT_SCAM_TLDS:
        if domain_lower.endswith(tst):
            full_tld = tst
            main_part = domain_lower[:-len(tst)]
            break
    
    # Normalize: remove hyphens for brand matching
    normalized = main_part.replace('-', '').replace('_', '')
    
    # === CHECK 1: Suspicious prefixes ===
    # First check hyphenated prefixes (e.g., "app-spectrum")
    for prefix in SUSPICIOUS_PREFIXES_HYPHEN:
        if main_part.startswith(prefix):
            result["has_suspicious_prefix"] = True
            result["suspicious_prefix"] = prefix
            result["patterns_found"].append(f"prefix:{prefix}")
            result["risk_score_addition"] += 12
            break
    
    # Then check non-hyphenated prefixes (e.g., "appbelezia", "myaccount")
    # Only if we haven't already found a hyphenated prefix
    if not result["has_suspicious_prefix"]:
        for prefix in SUSPICIOUS_PREFIXES_NO_HYPHEN:
            # Must start with prefix AND have more characters after
            if main_part.startswith(prefix) and len(main_part) > len(prefix):
                # Avoid false positives: check if this is a legitimate word
                if main_part in LEGITIMATE_PREFIX_WORDS:
                    continue
                    
                # Avoid false positives: make sure it's not just the prefix as the whole name
                # e.g., "app.com" alone shouldn't flag, but "appbelezia.com" should
                remaining = main_part[len(prefix):]
                # The remaining part should look like it could be a word/brand
                if len(remaining) >= 3 and remaining[0].isalpha():
                    result["has_suspicious_prefix"] = True
                    result["suspicious_prefix"] = prefix
                    result["patterns_found"].append(f"prefix:{prefix}")
                    result["risk_score_addition"] += 12
                    break
    
    # === CHECK 2: Suspicious suffixes ===
    for suffix in SUSPICIOUS_SUFFIXES:
        # Check if domain ends with suffix (e.g., "spectrumaccount" ends with "account")
        if normalized.endswith(suffix) and len(normalized) > len(suffix):
            # Avoid false positives: check if this is a legitimate word
            if normalized in LEGITIMATE_SUFFIX_WORDS:
                continue
            result["has_suspicious_suffix"] = True
            result["suspicious_suffix"] = suffix
            result["patterns_found"].append(f"suffix:{suffix}")
            result["risk_score_addition"] += 12
            break
    
    # === CHECK 3: Tech support scam TLDs ===
    if full_tld:
        result["is_tech_support_tld"] = True
        result["patterns_found"].append(f"tld:{full_tld}")
        result["risk_score_addition"] += 15
    else:
        for scam_tld in TECH_SUPPORT_SCAM_TLDS:
            if domain_lower.endswith(scam_tld):
                result["is_tech_support_tld"] = True
                result["patterns_found"].append(f"tld:{scam_tld}")
                result["risk_score_addition"] += 15
                break
    
    # === CHECK 4: Brand impersonation in domain name ===
    # This catches domains like "app-spectrum.com", "nortonaccount.com"
    # 
    # v5.x improvements:
    #   - Word-boundary matching for short brands (avoids "first" → "irs")
    #   - Minimum brand-to-domain ratio (avoids tiny brand in long domain)
    #   - Allowlist of common English words that contain brand substrings
    matched_brand = ""
    matched_brand_normalized = ""
    
    # Load brand impersonation tuning from config (with sensible defaults)
    brand_config = config.get("brand_impersonation", {}) if config else {}
    short_brand_max_len = brand_config.get("short_brand_max_len", 5)
    brand_min_domain_ratio = brand_config.get("brand_min_domain_ratio", 0.25)
    brand_allowlist_words = [w.lower() for w in brand_config.get("brand_allowlist_words", [])]
    
    for brand in IMPERSONATED_BRANDS:
        brand_normalized = brand.replace(' ', '').lower()
        
        # Skip very short brands that cause false positives (2-char: hp, bt, ee, o2)
        if len(brand_normalized) < 3:
            continue
            
        # Check if brand is in the domain (but domain is not the exact brand)
        if brand_normalized in normalized:
            # Make sure it's not the legitimate domain
            legitimate = [f"{brand_normalized}.com", f"{brand_normalized}.net", 
                         f"{brand_normalized}.org", f"{brand_normalized}.co",
                         f"{brand_normalized}.co.uk", f"{brand_normalized}.com.au",
                         f"{brand_normalized}.eu", f"{brand_normalized}.de",
                         f"{brand_normalized}.fr", f"{brand_normalized}.io"]
            if domain_lower not in legitimate:
                # Make sure the domain isn't just a longer legit name
                # e.g., "spectrum.net" vs "spectrumaccount.com"
                if normalized != brand_normalized:
                    
                    brand_pos = normalized.find(brand_normalized)
                    brand_end = brand_pos + len(brand_normalized)
                    at_start = (brand_pos == 0)
                    at_end = (brand_end == len(normalized))
                    
                    # Check if brand appears at a hyphen boundary in the original domain
                    at_hyphen_boundary = False
                    segments = main_part.split('-')
                    for seg in segments:
                        seg_clean = seg.replace('_', '')
                        if seg_clean == brand_normalized:
                            at_hyphen_boundary = True
                            break
                        if seg_clean.startswith(brand_normalized) or seg_clean.endswith(brand_normalized):
                            if len(seg_clean) == len(brand_normalized):
                                at_hyphen_boundary = True
                                break
                    
                    is_at_boundary = at_start or at_end or at_hyphen_boundary
                    
                    # --- NEW: Word-boundary check for short brands ---
                    # Short brands (≤ short_brand_max_len chars) must appear at a
                    # word boundary: start/end of domain part, or adjacent to a
                    # hyphen in the original (un-normalized) domain.
                    # This prevents "first" → "irs", "birdsong" → "irs", etc.
                    if len(brand_normalized) <= short_brand_max_len:
                        if not is_at_boundary:
                            continue
                    
                    # --- NEW: Percentage/ratio check ---
                    # Only applied when brand is NOT at a clear boundary.
                    # If the brand is embedded in the middle of a long domain
                    # and is a tiny fraction of it, it's likely coincidental.
                    # e.g., "sage" (4 chars) in "massagetherapy" (14 chars) = 29% → skip
                    # But "sage" at start of "sageconsulting" → skip ratio (at boundary)
                    if not is_at_boundary and brand_min_domain_ratio > 0 and len(normalized) > 0:
                        ratio = len(brand_normalized) / len(normalized)
                        if ratio < brand_min_domain_ratio:
                            continue
                    
                    # --- NEW: Allowlist check ---
                    # If any allowlisted word appears in the normalized domain and
                    # spans the position where the brand was found, suppress the match.
                    # e.g., "first" is allowlisted, and "irs" is found inside "first"
                    #        within "godfirstdigital" → suppress
                    allowlisted = False
                    for allowed_word in brand_allowlist_words:
                        if allowed_word in normalized:
                            # Check if the allowed word overlaps with the brand match
                            aw_pos = normalized.find(allowed_word)
                            aw_end = aw_pos + len(allowed_word)
                            # Overlap check: brand is within or overlaps the allowed word
                            if aw_pos <= brand_pos and aw_end >= brand_end:
                                allowlisted = True
                                break
                    
                    if allowlisted:
                        continue
                    
                    matched_brand = brand
                    matched_brand_normalized = brand_normalized
                    result["domain_impersonates_brand"] = brand
                    result["patterns_found"].append(f"brand:{brand}")
                    result["risk_score_addition"] += 20
                    break
    
    # === CHECK 5: Brand + Spoofing Keyword Detection (v5.2) ===
    # If a brand was found, check if the remaining text is a spoofing keyword.
    # This catches easyjetconnect.com, amazonverify.net, chaselogin.com, etc.
    # These are MUCH higher risk than a brand name alone because they specifically
    # mimic legitimate brand service names/subdomains.
    if matched_brand_normalized:
        # Extract the non-brand portion of the domain name
        brand_pos = normalized.find(matched_brand_normalized)
        if brand_pos >= 0:
            before_brand = normalized[:brand_pos]
            after_brand = normalized[brand_pos + len(matched_brand_normalized):]
            
            # Check both portions for spoofing keywords
            for keyword in BRAND_SPOOFING_KEYWORDS:
                keyword_lower = keyword.lower()
                # Check after the brand: easyjet[connect], amazon[verify]
                if after_brand and (after_brand == keyword_lower or after_brand.startswith(keyword_lower)):
                    result["brand_spoofing_keyword"] = keyword
                    result["brand_plus_keyword"] = True
                    result["patterns_found"].append(f"brand_keyword:{matched_brand}+{keyword}")
                    result["risk_score_addition"] += 15  # Additional on top of brand impersonation
                    break
                # Check before the brand: [my]paypal, [secure]chase
                if before_brand and (before_brand == keyword_lower or before_brand.endswith(keyword_lower)):
                    result["brand_spoofing_keyword"] = keyword
                    result["brand_plus_keyword"] = True
                    result["patterns_found"].append(f"brand_keyword:{keyword}+{matched_brand}")
                    result["risk_score_addition"] += 15
                    break
    
    return result


# ============================================================================
# TLD VARIANT SPOOFING DETECTION
# ============================================================================
# Detects when a signup domain is a TLD variant of an established business.
# Example: gordondown.uk spoofing gordondown.co.uk
# The .uk/.co.uk pair is the most common UK spoofing vector, but we also
# check .com and other high-value TLD pairs.
# ============================================================================

# TLD variant pairs to check — order matters: (signup_suffix, variant_suffix)
# We generate variants by stripping the signup TLD and appending the variant TLD.
# These are checked bidirectionally via the generation logic below.
UK_TLD_VARIANTS = [
    ('.uk', '.co.uk'),
    ('.co.uk', '.uk'),
    ('.uk', '.org.uk'),
    ('.org.uk', '.uk'),
]

# Always-check TLD variants (appended to base name regardless of signup TLD)
# v7.5.1: Removed '.com' — too generic. Almost every short domain name has a
# .com variant owned by a different entity.  This was generating massive false
# positives (e.g., tele.store flagged for tele.com, vetfo.us for vetfo.com).
# The UK pairs (.uk ↔ .co.uk) are the only proven spoofing detection pattern.
UNIVERSAL_TLD_VARIANTS = []

# Additional pairs for non-UK domains
# v7.5.1: Removed all .com targets — same reason as above.
# Keep only pairs between similar ccTLD extensions where spoofing is plausible.
EXTRA_TLD_VARIANTS = [
    # Intentionally empty — only UK pairs are proven to detect real spoofing.
    # Re-add specific pairs here if a new spoofing pattern emerges.
]

# Minimum word count for a page to be considered "substantive"
VARIANT_CONTENT_THRESHOLD = 80
# Minimum word count disparity ratio (variant must have N× more words)
VARIANT_CONTENT_RATIO = 4
# Minimum email auth signals on variant for asymmetry flag
VARIANT_EMAIL_AUTH_MIN = 2  # e.g., SPF + MX, or SPF + DKIM


def _extract_base_and_tld(domain: str) -> Tuple[str, str]:
    """
    Extract the registrable base name and its effective TLD.
    
    Uses dynamic detection: any two-letter SLD indicator (com, co, org, net, 
    ac, gov, edu, etc.) followed by a two-letter ccTLD is treated as a compound
    TLD. This handles .com.pk, .co.id, .org.za, etc. without hardcoding.
    
    Examples:
        gordondown.uk       → ("gordondown", ".uk")
        gordondown.co.uk    → ("gordondown", ".co.uk")
        example.com         → ("example", ".com")
        mysite.org.uk       → ("mysite", ".org.uk")
        taleem.com.pk       → ("taleem", ".com.pk")
        web.gr8asia.in      → ("gr8asia", ".in")
    """
    domain = domain.lower().strip().rstrip('.')
    
    # Known SLD indicators that form compound TLDs when followed by a ccTLD
    # e.g., "com" in .com.pk, "co" in .co.uk, "org" in .org.za
    SLD_INDICATORS = {'com', 'co', 'org', 'net', 'ac', 'gov', 'edu', 'me', 'gen', 'mil'}
    
    parts = domain.split('.')
    
    if len(parts) >= 3:
        # Check if last two labels form a compound TLD
        # e.g., parts = ['taleem', 'com', 'pk'] → sld='com', cctld='pk'
        sld = parts[-2]   # e.g., 'com'
        cctld = parts[-1] # e.g., 'pk'
        
        # Compound TLD: SLD indicator + 2-3 letter ccTLD
        if sld in SLD_INDICATORS and len(cctld) <= 3:
            compound = f'.{sld}.{cctld}'
            base = parts[-3]  # The registrable name
            return base, compound
    
    if len(parts) >= 2:
        # Simple TLD: example.com, gordondown.uk
        base = parts[-2]
        tld = '.' + parts[-1]
        return base, tld
    
    return domain, ""


def _generate_tld_variants(domain: str) -> List[str]:
    """
    Generate TLD variant domains to check for the given signup domain.
    
    For gordondown.uk → ["gordondown.co.uk", "gordondown.com"]
    For gordondown.co.uk → ["gordondown.uk", "gordondown.com"]
    For example.com → ["example.co.uk", "example.net", "example.org"] (if .com)
    """
    base, tld = _extract_base_and_tld(domain)
    if not base or not tld:
        return []
    
    variants = set()
    
    # Check UK-specific TLD pairs
    for signup_tld, variant_tld in UK_TLD_VARIANTS:
        if tld == signup_tld:
            candidate = base + variant_tld
            if candidate != domain.lower():
                variants.add(candidate)
    
    # Check other TLD pairs (currently empty — only UK pairs active)
    for signup_tld, variant_tld in EXTRA_TLD_VARIANTS:
        if tld == signup_tld:
            candidate = base + variant_tld
            if candidate != domain.lower():
                variants.add(candidate)
    
    # v7.5.1: Removed universal .com check and .com→.co.uk check.
    # The .com TLD is too generic to serve as spoofing evidence.
    
    return list(variants)


def _count_page_words(content: bytes) -> int:
    """Count words in HTML content (strip tags first)."""
    if not content:
        return 0
    try:
        text = content.decode('utf-8', errors='ignore')
    except Exception:
        text = str(content)
    
    # Remove script/style blocks
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', text, flags=re.DOTALL | re.IGNORECASE)
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Remove HTML entities
    text = re.sub(r'&[a-zA-Z]+;', ' ', text)
    text = re.sub(r'&#?\w+;', ' ', text)
    # Collapse whitespace and count
    words = text.split()
    # Filter out very short tokens (likely artifacts)
    words = [w for w in words if len(w) >= 2]
    return len(words)


def _check_variant_email_infra(variant_domain: str) -> Dict:
    """Quick email infrastructure check on a variant domain."""
    result = {
        "spf_exists": False,
        "dkim_exists": False,
        "mx_exists": False,
        "dmarc_exists": False,
        "auth_count": 0,
        "mx_selfhosted": False,
        "mx_external": False,       # True if MX points to known provider (not self-hosted)
        "mx_hosts": [],             # Raw MX hostnames for diagnostics
    }
    
    # SPF
    _, spf_exists, _ = get_spf(variant_domain)
    result["spf_exists"] = spf_exists
    
    # MX
    mx_exists, mx_records, _ = get_mx(variant_domain)
    result["mx_exists"] = mx_exists
    
    if mx_exists and mx_records:
        all_mx_hosts = [h.lower() for _, h in mx_records]
        result["mx_hosts"] = all_mx_hosts
        
        domain_lower = variant_domain.lower()
        
        # Check self-hosted: MX points to own domain or subdomain
        is_selfhosted = any(
            h == domain_lower or h.endswith('.' + domain_lower) 
            for h in all_mx_hosts
        )
        result["mx_selfhosted"] = is_selfhosted
        
        # Check external provider (enterprise or standard patterns)
        # These are common hosted email providers — if MX points here, it's external
        EXTERNAL_MX_PATTERNS = [
            # Enterprise
            'google.com', 'googlemail.com', 'outlook.com', 'microsoft.com',
            'protection.outlook.com', 'ppe-hosted.com',
            # Standard  
            'mxroute.com', 'zoho.com', 'fastmail.com', 'protonmail.ch',
            'messagingengine.com', 'migadu.com', 'tutanota.de',
            'emailsrvr.com', 'secureserver.net', 'icloud.com',
            'registrar-servers.com', 'hostinger.com', 'ionos.com',
            'dreamhost.com', 'bluehost.com', 'siteground.net',
            'ovh.net', 'gandi.net', 'namecheap.com',
        ]
        result["mx_external"] = not is_selfhosted and any(
            any(pattern in h for pattern in EXTERNAL_MX_PATTERNS)
            for h in all_mx_hosts
        )
    
    # DMARC
    _, dmarc_exists, _ = get_dmarc(variant_domain)
    result["dmarc_exists"] = dmarc_exists
    
    # DKIM (quick check — just try a few common selectors)
    dkim_exists, _ = check_dkim(variant_domain)
    result["dkim_exists"] = dkim_exists
    
    result["auth_count"] = sum([
        result["spf_exists"],
        result["dkim_exists"],
        result["mx_exists"],
        result["dmarc_exists"],
    ])
    
    return result


def _check_variant_content_indicators(content: bytes) -> Dict:
    """Check for business legitimacy indicators in variant page content."""
    result = {
        "has_navigation": False,
        "has_contact_info": False,
        "has_company_number": False,
        "has_vat_number": False,
        "has_professional_membership": False,
        "has_multiple_pages": False,
        "indicator_count": 0,
    }
    
    if not content:
        return result
    
    text = content.decode('utf-8', errors='ignore').lower()
    
    # Navigation links (suggests multi-page site)
    nav_patterns = [
        r'<nav\b', r'class="nav', r'class="menu', r'id="menu',
        r'<ul[^>]*class="[^"]*nav', r'role="navigation"',
    ]
    result["has_navigation"] = any(re.search(p, text) for p in nav_patterns)
    
    # Multiple internal links (more than just a placeholder)
    internal_links = re.findall(r'<a\s+[^>]*href=["\'](?!/|#|http|mailto|tel)[^"\']+["\']', text)
    relative_links = re.findall(r'<a\s+[^>]*href=["\']/[^"\']+["\']', text)
    result["has_multiple_pages"] = (len(internal_links) + len(relative_links)) >= 3
    
    # Contact information
    contact_patterns = [
        r'\b\d{3,5}\s?\d{3,4}\s?\d{3,4}\b',  # Phone numbers
        r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b',  # Email addresses
        r'\bcontact\s*us\b', r'\bget\s*in\s*touch\b',
    ]
    result["has_contact_info"] = any(re.search(p, text) for p in contact_patterns)
    
    # Company registration number (UK Companies House format, or generic)
    company_patterns = [
        r'company\s*(?:number|no\.?|registration|reg\.?)\s*[:.]?\s*\d{6,8}',
        r'registered\s*(?:in\s+)?(?:england|wales|scotland)\b',
        r'companies\s*house\b',
    ]
    result["has_company_number"] = any(re.search(p, text) for p in company_patterns)
    
    # VAT number
    vat_patterns = [
        r'vat\s*(?:number|no\.?|reg\.?)\s*[:.]?\s*(?:gb)?\s*\d{9}',
        r'vat\s*[:.]?\s*(?:gb)?\s*\d{3}\s*\d{4}\s*\d{2}',
    ]
    result["has_vat_number"] = any(re.search(p, text) for p in vat_patterns)
    
    # Professional memberships (accounting, legal, etc.)
    membership_patterns = [
        r'\bicaew\b', r'\bacca\b', r'\bciot\b', r'\bcima\b',  # Accounting
        r'\bsra\b', r'\blaw\s*society\b',  # Legal
        r'\brics\b', r'\briba\b',  # Property/Architecture
        r'\bfca\b', r'\bcertified\s+accountant', r'\bchartered\b',
    ]
    result["has_professional_membership"] = any(re.search(p, text) for p in membership_patterns)
    
    result["indicator_count"] = sum([
        result["has_navigation"],
        result["has_contact_info"],
        result["has_company_number"],
        result["has_vat_number"],
        result["has_professional_membership"],
        result["has_multiple_pages"],
    ])
    
    return result


def check_tld_variant_spoofing(domain: str, signup_content: bytes = None, 
                                 timeout: float = 8.0) -> Dict:
    """
    Check if the signup domain is a TLD variant of an established business domain.
    
    This catches the gordondown.uk-spoofing-gordondown.co.uk pattern:
    - Generate TLD variants of the signup domain
    - Check if any variant resolves to an established business
    - Compare content and email infrastructure asymmetry
    
    Returns dict with detection results.
    """
    result = {
        "tld_variant_detected": False,
        "variant_domain": "",
        "variant_has_content": False,
        "variant_has_email_infra": False,
        "variant_domain_age_days": -1,
        "variant_content_words": 0,
        "signup_content_words": 0,
        "summary": "",
    }
    
    # Count words on signup domain's page
    signup_words = _count_page_words(signup_content) if signup_content else 0
    result["signup_content_words"] = signup_words
    
    # Check signup domain's own email infrastructure (for disparity comparison)
    signup_email = _check_variant_email_infra(domain)
    
    # Generate TLD variants
    variants = _generate_tld_variants(domain)
    if not variants:
        return result
    
    best_variant = None
    best_score = 0  # Track the "most established" variant
    diagnostics = []  # Track what we found for debug output
    
    for variant_domain in variants:
        # Step 1: DNS resolution — does the variant exist?
        try:
            socket.gethostbyname(variant_domain)
        except Exception:
            diagnostics.append(f"{variant_domain}: no DNS")
            continue  # Variant doesn't resolve — skip
        
        # Step 2: Fetch variant's page content
        variant_content = None
        if REQUESTS_AVAILABLE:
            variant_http = follow_redirects(f"https://{variant_domain}", timeout, fetch_content=True)
            if variant_http["ok"]:
                variant_content = variant_http["content"]
            else:
                # Try HTTP if HTTPS fails
                variant_http = follow_redirects(f"http://{variant_domain}", timeout, fetch_content=True)
                if variant_http["ok"]:
                    variant_content = variant_http["content"]
        
        variant_words = _count_page_words(variant_content)
        
        # Step 3: Check email infrastructure on variant
        variant_email = _check_variant_email_infra(variant_domain)
        
        # Step 4: Check content legitimacy indicators
        variant_indicators = _check_variant_content_indicators(variant_content)
        
        # Step 5: Calculate asymmetry score
        # Higher = more likely the variant is the real business and signup is the spoof
        asymmetry_score = 0
        score_reasons = []
        
        # --- SIGNUP HOLLOWNESS (independent signal) ---
        # A near-empty signup page is suspicious on its own when a variant exists
        if signup_words < 30:
            asymmetry_score += 2
            score_reasons.append(f"signup hollow ({signup_words}w)")
            # Variant has ANY meaningful content (even SPA shell with meta/titles)
            if variant_words >= 30:
                asymmetry_score += 1
                score_reasons.append(f"variant has content ({variant_words}w)")
        
        # --- CONTENT VOLUME ASYMMETRY ---
        if variant_words >= VARIANT_CONTENT_THRESHOLD:
            asymmetry_score += 1
            score_reasons.append(f"variant substantive ({variant_words}w)")
            if signup_words < 50:
                asymmetry_score += 1  # Big disparity
                score_reasons.append("content disparity")
        
        # --- EMAIL INFRASTRUCTURE ON VARIANT ---
        if variant_email["auth_count"] >= VARIANT_EMAIL_AUTH_MIN:
            asymmetry_score += 2
            score_reasons.append(f"variant email auth ({variant_email['auth_count']}/4)")
            if variant_email["auth_count"] >= 3:
                asymmetry_score += 1
                score_reasons.append("variant strong email")
        
        # --- EMAIL AUTH DISPARITY (variant vs signup) ---
        # If variant has significantly better email auth than signup, strong signal
        email_gap = variant_email["auth_count"] - signup_email["auth_count"]
        if email_gap >= 2:
            asymmetry_score += 2
            score_reasons.append(f"email disparity (variant {variant_email['auth_count']} vs signup {signup_email['auth_count']})")
        elif email_gap >= 1:
            asymmetry_score += 1
            score_reasons.append(f"email gap +{email_gap}")
        
        # --- MX TYPE DISPARITY ---
        # Signup has self-hosted MX (mail.domain.uk) while variant has external provider
        # This is a strong spoof signal: real businesses use hosted email, spoofs point MX at themselves
        if signup_email["mx_selfhosted"] and variant_email["mx_external"]:
            asymmetry_score += 2
            score_reasons.append(f"MX disparity (signup selfhosted vs variant external)")
        elif signup_email["mx_selfhosted"] and not variant_email["mx_selfhosted"]:
            # Variant at least isn't selfhosted, even if we can't confirm provider
            asymmetry_score += 1
            score_reasons.append(f"signup MX selfhosted")
        
        # --- BUSINESS LEGITIMACY INDICATORS ---
        if variant_indicators["indicator_count"] >= 2:
            asymmetry_score += 2
            score_reasons.append(f"biz indicators ({variant_indicators['indicator_count']})")
        if variant_indicators["indicator_count"] >= 4:
            asymmetry_score += 1
        
        # Company registration is a very strong signal
        if variant_indicators["has_company_number"]:
            asymmetry_score += 2
            score_reasons.append("company reg found")
        
        diag = f"{variant_domain}: score={asymmetry_score} [{', '.join(score_reasons)}] words={variant_words} email={variant_email['auth_count']}/4 mx_ext={variant_email['mx_external']}"
        diagnostics.append(diag)
        
        # Track best variant
        if asymmetry_score > best_score:
            best_score = asymmetry_score
            best_variant = {
                "domain": variant_domain,
                "words": variant_words,
                "email": variant_email,
                "indicators": variant_indicators,
                "score": asymmetry_score,
                "content": variant_content,
                "score_reasons": score_reasons,
            }
    
    # Decision: flag if asymmetry score is high enough
    # Threshold: score >= 5 means clear asymmetry (established variant vs hollow signup)
    DETECTION_THRESHOLD = 5
    
    if best_variant and best_variant["score"] >= DETECTION_THRESHOLD:
        v = best_variant
        result["tld_variant_detected"] = True
        result["variant_domain"] = v["domain"]
        result["variant_has_content"] = v["words"] >= VARIANT_CONTENT_THRESHOLD
        result["variant_has_email_infra"] = v["email"]["auth_count"] >= VARIANT_EMAIL_AUTH_MIN
        result["variant_content_words"] = v["words"]
        
        # Build human-readable summary
        summary_parts = []
        summary_parts.append(f"TLD VARIANT: {v['domain']}")
        
        # Content comparison
        summary_parts.append(f"variant has {v['words']} words vs signup has {signup_words} words")
        
        # Email infra
        email_signals = []
        if v["email"]["spf_exists"]:
            email_signals.append("SPF")
        if v["email"]["dkim_exists"]:
            email_signals.append("DKIM")
        if v["email"]["mx_exists"]:
            email_signals.append("MX")
        if v["email"]["dmarc_exists"]:
            email_signals.append("DMARC")
        if email_signals:
            summary_parts.append(f"variant email auth: {'+'.join(email_signals)}")
        
        # Signup email weakness
        signup_signals = []
        if signup_email["spf_exists"]:
            signup_signals.append("SPF")
        if signup_email["dkim_exists"]:
            signup_signals.append("DKIM")
        if signup_email["mx_exists"]:
            if signup_email["mx_selfhosted"]:
                signup_signals.append("MX(selfhosted)")
            else:
                signup_signals.append("MX")
        if signup_email["dmarc_exists"]:
            signup_signals.append("DMARC")
        summary_parts.append(f"signup email auth: {'+'.join(signup_signals) if signup_signals else 'none'}")
        
        # Business indicators
        biz_signals = []
        if v["indicators"]["has_company_number"]:
            biz_signals.append("company reg")
        if v["indicators"]["has_vat_number"]:
            biz_signals.append("VAT")
        if v["indicators"]["has_professional_membership"]:
            biz_signals.append("professional body")
        if v["indicators"]["has_navigation"]:
            biz_signals.append("full site")
        if v["indicators"]["has_contact_info"]:
            biz_signals.append("contact info")
        if biz_signals:
            summary_parts.append(f"variant signals: {', '.join(biz_signals)}")
        
        summary_parts.append(f"asymmetry: {v['score']}")
        result["summary"] = " → ".join(summary_parts)
    
    else:
        # Always provide diagnostic output so we can see what happened
        mx_type = "selfhosted" if signup_email["mx_selfhosted"] else ("external" if signup_email["mx_external"] else "unknown")
        diag_summary = f"TLD VARIANT CHECK: signup={signup_words}w, signup_email={signup_email['auth_count']}/4, signup_mx={mx_type}"
        if diagnostics:
            diag_summary += " | " + " | ".join(diagnostics)
        else:
            diag_summary += " | no variants resolved"
        if best_variant:
            diag_summary += f" | best={best_variant['domain']} score={best_variant['score']} (threshold={DETECTION_THRESHOLD})"
        result["summary"] = diag_summary
    
    return result


# ============================================================================
# WEB FUNCTIONS
# ============================================================================

def check_tls(domain: str, timeout: float) -> Dict:
    """
    Probe TLS on port 443 and classify the failure mode.
    
    v4.4: Now explicitly catches ssl.SSLError for handshake failures
    (cipher mismatch, protocol version, SSLV3_ALERT_HANDSHAKE_FAILURE, etc.)
    instead of letting them fall through to a generic except.
    
    Returns:
        ok                – handshake + cert verification succeeded
        error             – human-readable error (empty on success)
        handshake_failed  – SSL negotiation itself failed
        connection_failed – TCP layer failed (refused, timeout, unreachable)
        self_signed       – certificate is self-signed
        expired           – certificate is expired
        wrong_host        – certificate CN/SAN doesn't match domain
    """
    result = {
        "ok": False,
        "error": "",
        "handshake_failed": False,
        "connection_failed": False,
        "self_signed": False,
        "expired": False,
        "wrong_host": False,
    }
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
                result["ok"] = True

    # Certificate exists but fails validation
    except ssl.SSLCertVerificationError as e:
        err = str(e).lower()
        result["error"] = str(e)[:200]
        result["self_signed"] = "self signed" in err or "self-signed" in err
        result["expired"] = "expired" in err
        result["wrong_host"] = "hostname" in err or "match" in err

    # v4.4 FIX: Handshake-level failures — previously fell through to generic except
    # Fires for: SSLV3_ALERT_HANDSHAKE_FAILURE, TLSV1_ALERT_PROTOCOL_VERSION,
    # EOF occurred in violation of protocol, cipher mismatch, connection reset during handshake
    except ssl.SSLError as e:
        result["error"] = str(e)[:200]
        result["handshake_failed"] = True

    # DNS resolution failure or TCP timeout
    except (socket.timeout, socket.gaierror) as e:
        result["error"] = str(e)[:200]
        result["connection_failed"] = True

    # Port 443 is closed / nothing listening
    except ConnectionRefusedError as e:
        result["error"] = f"Connection refused on port 443: {e}"[:200]
        result["connection_failed"] = True

    # Network unreachable, host unreachable, etc.
    except OSError as e:
        result["error"] = str(e)[:200]
        result["connection_failed"] = True

    return result


def follow_redirects(url: str, timeout: float, fetch_content: bool = False) -> Dict:
    """
    Follow HTTP redirect chain and optionally fetch final content.
    
    v4.4: Replaced bare `except:` with typed exception handling so SSL errors,
    connection errors, and timeouts are captured in separate result fields
    instead of being silently swallowed.
    """
    if not REQUESTS_AVAILABLE:
        return {"ok": False, "initial_status": 0, "hops": 0, "chain": [], "domains": [], 
                "cross_domain": False, "uses_temp": False, "final_url": url, 
                "all_statuses": set(), "content": b"", "content_length": -1,
                "ssl_error": "", "connection_error": "", "timeout_error": "", "error": ""}
    
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})
    
    result = {
        "ok": False, "initial_status": 0, "hops": 0,
        "chain": [], "domains": [], "cross_domain": False,
        "uses_temp": False, "final_url": url, "all_statuses": set(),
        "content": b"", "content_length": -1,
        # v4.4: typed error fields (was bare except that discarded all info)
        "ssl_error": "",
        "connection_error": "",
        "timeout_error": "",
        "error": "",
    }
    
    start_host = urlparse(url).netloc.lower()
    current = url
    seen = set()
    
    # Helper: extract registrable domain to avoid false cross-domain on
    # www-normalization (tandem.co.uk → www.tandem.co.uk) or subdomain
    # redirects (app.example.com → api.example.com).
    _CCTLD_2ND = {"co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "go"}
    def _registrable(host: str) -> str:
        h = host.lower()
        if h.startswith("www."):
            h = h[4:]
        parts = h.split(".")
        if len(parts) >= 3 and parts[-2] in _CCTLD_2ND:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else h
    
    start_registrable = _registrable(start_host)
    
    for i in range(MAX_REDIRECTS + 1):
        if current in seen:
            break
        seen.add(current)
        host = urlparse(current).netloc.lower()
        if host and host not in result["domains"]:
            result["domains"].append(host)
        
        try:
            # Use HEAD for redirect chasing (fast), GET only when we need content
            resp = session.head(current, allow_redirects=False, timeout=timeout, verify=True)
            status = resp.status_code
            
            if status in (405, 501):
                resp = session.get(current, allow_redirects=False, timeout=timeout, verify=True)
                status = resp.status_code
            
            if i == 0:
                result["initial_status"] = status
            result["all_statuses"].add(status)
            
            if status in ALL_REDIRECT_CODES and "Location" in resp.headers:
                result["chain"].append(status)
                if status in TEMP_REDIRECT_CODES:
                    result["uses_temp"] = True
                next_url = urljoin(current, resp.headers["Location"])
                next_host = urlparse(next_url).netloc.lower()
                if next_host and _registrable(next_host) != start_registrable:
                    result["cross_domain"] = True
                current = next_url
                result["hops"] += 1
                continue
            
            result["ok"] = True
            result["final_url"] = current
            result["chain"].append(status)
            
            # Non-redirect final response — fetch body with GET if caller wants content
            if fetch_content:
                try:
                    # Use allow_redirects=True so auth pages that redirect to login get captured.
                    # Many 401/403 pages serve full HTML with footer links (privacy policy etc.)
                    get_resp = session.get(current, allow_redirects=True, timeout=timeout, verify=True)
                    result["content"] = get_resp.content[:50000]
                    result["content_length"] = len(result["content"])
                except Exception as e:
                    result["error"] = f"content_read_failed: {str(e)[:150]}"
            return result

        # v4.4 FIX: typed exception handling (was bare `except:` that silently returned)
        except requests.exceptions.SSLError as e:
            result["ssl_error"] = str(e)[:200]
            result["ok"] = False
            return result

        except requests.exceptions.ConnectionError as e:
            result["connection_error"] = str(e)[:200]
            result["ok"] = False
            return result

        except requests.exceptions.Timeout as e:
            result["timeout_error"] = str(e)[:200]
            result["ok"] = False
            return result

        except Exception as e:
            result["error"] = str(e)[:200]
            result["ok"] = False
            return result
    
    result["ok"] = True
    return result


def analyze_content(content: bytes, final_url: str, domain: str) -> Dict:
    result = {
        "minimal_shell": False, "js_redirect": False, "meta_refresh": False,
        "external_js": False, "obfuscation": False, "credential_form": False,
        "sensitive_fields": False, "brands": [], "form_external": False,
        "malware": [], "suspicious_iframe": False, "parking": False, "phishing_paths": [],
        "auth_paths": [],  # v7.5.1: Standard auth paths found (tracked separately)
        # Phishing kit detection (v7.3)
        "kit_filename": "", "kit_filename_strong": False,
        "exfil_signals": [], "exfil_details": [],
        "form_action_kit": "", "form_action_kit_strong": False,
        "page_title": "", "suspicious_title_match": "",
        # Client-side harvest detection (v7.5)
        "harvest_signals": [], "harvest_details": [],
        "harvest_combo": False, "harvest_combo_reason": "",
        # OAuth consent phishing (v7.3.1)
        "oauth_phish": False, "oauth_evidence": [],
        # Security tooling detection (v7.5.1)
        "security_signals": [],  # e.g., ["recaptcha", "cloudflare_turnstile", "hcaptcha"]
    }
    
    if not content:
        return result
    
    content_lower = content.lower()
    content_len = len(content.strip())
    
    has_script = b'<script' in content_lower
    body = re.sub(rb'<script[^>]*>.*?</script>', b'', content_lower, flags=re.DOTALL)
    if content_len < 1000 and has_script and len(body.strip()) < 300:
        result["minimal_shell"] = True
    
    for p in JS_REDIRECT_PATTERNS:
        if p in content_lower:
            result["js_redirect"] = True
            break
    
    if re.search(rb'<meta[^>]+http-equiv=["\']?refresh', content_lower):
        result["meta_refresh"] = True
    
    if content_len < 2000 and re.search(rb'<script[^>]+src=', content_lower):
        result["external_js"] = True
    
    obf = [rb'fromCharCode', rb'eval\s*\(', rb'atob\s*\(', rb'\\x[0-9a-f]{2}']
    if sum(1 for p in obf if re.search(p, content_lower)) >= 2:
        result["obfuscation"] = True
    
    for p in CREDENTIAL_PATTERNS:
        if p in content_lower:
            result["credential_form"] = True
            break
    
    for p in SENSITIVE_PATTERNS:
        if p in content_lower:
            result["sensitive_fields"] = True
            break
    
    final_domain = urlparse(final_url).netloc.lower()
    
    # Check for brand keywords in VISIBLE page text only.
    # We must exclude: HTML tags/attributes, scripts, styles, URLs (href/src),
    # social media links, app store references, meta tags, Open Graph tags,
    # Facebook/Google SDKs, tracking pixels, and share buttons.
    # Only flag brands that appear in actual page copy (titles, headings, body text).
    
    # Step 1: Remove script, style, noscript, head blocks entirely
    visible = re.sub(rb'<script[^>]*>.*?</script>', b' ', content_lower, flags=re.DOTALL)
    visible = re.sub(rb'<style[^>]*>.*?</style>', b' ', visible, flags=re.DOTALL)
    visible = re.sub(rb'<noscript[^>]*>.*?</noscript>', b' ', visible, flags=re.DOTALL)
    visible = re.sub(rb'<head[^>]*>.*?</head>', b' ', visible, flags=re.DOTALL)
    
    # Step 2: Remove all HTML comments
    visible = re.sub(rb'<!--.*?-->', b' ', visible, flags=re.DOTALL)
    
    # Step 3: Remove all HTML tags (and their attributes — this strips href, src, alt, etc.)
    visible = re.sub(rb'<[^>]+>', b' ', visible)
    
    # Step 4: Remove any remaining URLs
    visible = re.sub(rb'https?://\S+', b' ', visible)
    
    # Step 5: Decode to string for brand matching
    visible_text = visible.decode('utf-8', errors='ignore').lower()
    
    # Step 6: Remove common non-impersonation phrases (social links, app stores, SDKs)
    _SAFE_BRAND_CONTEXTS = [
        # Social media references
        r'follow\s+us\s+on\s+\w+', r'like\s+us\s+on\s+\w+', r'find\s+us\s+on\s+\w+',
        r'connect\s+with\s+us\s+on\s+\w+', r'join\s+us\s+on\s+\w+',
        r'share\s+on\s+\w+', r'share\s+to\s+\w+', r'share\s+via\s+\w+',
        r'sign\s+in\s+with\s+\w+', r'log\s*in\s+with\s+\w+', r'continue\s+with\s+\w+',
        r'powered\s+by\s+\w+',
        # App store references
        r'download\s+on\s+the\s+app\s+store', r'get\s+it\s+on\s+google\s+play',
        r'available\s+on\s+the\s+app\s+store', r'available\s+on\s+google\s+play',
        r'download\s+from\s+\w+\s+store', r'app\s+store', r'google\s+play',
        r'apple\s+store',
        # Copyright / footer boilerplate
        r'©\s*\d{4}\s+\w+', r'copyright\s+\d{4}\s+\w+',
        r'all\s+rights\s+reserved',
        # Platform references
        r'facebook\s+pixel', r'facebook\s+sdk', r'facebook\s+page',
        r'google\s+analytics', r'google\s+tag\s+manager', r'google\s+maps',
        r'google\s+fonts', r'google\s+recaptcha', r'google\s+adsense',
        r'instagram\s+feed', r'instagram\s+widget',
        r'microsoft\s+365', r'microsoft\s+office', r'microsoft\s+teams',
        r'apple\s+pay', r'apple\s+music', r'apple\s+tv', r'apple\s+watch',
        r'amazon\s+pay', r'amazon\s+web\s+services', r'amazon\s+aws',
        r'paypal\s+checkout', r'pay\s+with\s+paypal',
    ]
    visible_cleaned = visible_text
    for ctx_pattern in _SAFE_BRAND_CONTEXTS:
        visible_cleaned = re.sub(ctx_pattern, ' ', visible_cleaned, flags=re.IGNORECASE)
    
    # Ubiquitous brands: appear on virtually every website as social links,
    # login buttons, analytics, share widgets, app store links, etc.
    # These should NOT be flagged from content alone — only the domain-name
    # check (IMPERSONATED_BRANDS) should catch impersonation of these.
    _UBIQUITOUS_BRANDS = {b'facebook', b'instagram', b'google', b'microsoft', b'amazon', b'apple', b'netflix'}
    
    # Step 7: Check standard brand keywords in cleaned visible text
    # Only flag non-ubiquitous brands from content (financial, shipping, etc.)
    for brand in BRAND_KEYWORDS:
        if brand in _UBIQUITOUS_BRANDS:
            continue  # Skip — too common in legitimate page content
        brand_str = brand.decode('utf-8', errors='ignore').replace(' ', '')
        brand_display = brand.decode('utf-8', errors='ignore')
        if brand_str not in final_domain and brand_str not in domain:
            if brand_str in visible_cleaned:
                result["brands"].append(brand_display)
    
    # Step 8: Check short brand keywords with word boundary matching
    for brand in BRAND_KEYWORDS_SHORT:
        brand_str = brand.decode('utf-8', errors='ignore')
        if brand_str not in final_domain and brand_str not in domain:
            pattern = r'\b' + re.escape(brand_str) + r'\b'
            if re.search(pattern, visible_cleaned, re.IGNORECASE):
                result["brands"].append(brand_str)
    
    result["brands"] = list(set(result["brands"]))[:5]  # Dedupe and limit
    
    forms = re.findall(rb'<form[^>]+action=["\']([^"\']+)["\']', content_lower)
    for action in forms:
        try:
            action_url = action.decode('utf-8', errors='ignore')
            if action_url.startswith(('http://', 'https://')):
                action_host = urlparse(action_url).netloc.lower()
                if action_host and action_host != final_domain:
                    result["form_external"] = True
                    break
            # === FORM ACTION → KIT FILENAME CHECK (v7.4) ===
            # Check if form posts to a known kit filename — even on same domain.
            # <form action="next.php"> is the #1 phishing kit signature.
            action_basename = action_url.rsplit('/', 1)[-1].lower().strip() if action_url else ""
            if action_basename and not result["form_action_kit"]:
                for fn in PHISHING_KIT_FILENAMES_STRONG:
                    if action_basename == fn:
                        result["form_action_kit"] = fn
                        result["form_action_kit_strong"] = True
                        break
                if not result["form_action_kit"]:
                    for fn in PHISHING_KIT_FILENAMES_WEAK:
                        if action_basename == fn:
                            result["form_action_kit"] = fn
                            result["form_action_kit_strong"] = False
                            break
        except:
            pass
    
    # === PAGE TITLE EXTRACTION + SUSPICIOUS TITLE DETECTION (v7.4) ===
    title_match = re.search(rb'<title[^>]*>([^<]{1,200})</title>', content_lower)
    if title_match:
        raw_title = title_match.group(1).decode('utf-8', errors='ignore').strip()
        result["page_title"] = raw_title[:200]
        title_lower = raw_title.lower()
        for pattern in SUSPICIOUS_PAGE_TITLES:
            if pattern in title_lower:
                result["suspicious_title_match"] = pattern
                break
    
    links = re.findall(rb'(?:href|src)=["\']([^"\']+)["\']', content_lower)
    for link in links:
        try:
            link_str = link.decode('utf-8', errors='ignore').lower()
            for ext in MALWARE_EXTENSIONS:
                if link_str.endswith(ext):
                    result["malware"].append(ext)
                    break
        except:
            pass
    result["malware"] = list(set(result["malware"]))[:5]
    
    if re.search(rb'<iframe[^>]*(?:display:\s*none|width=["\']?[01])', content_lower):
        result["suspicious_iframe"] = True
    
    # Parking page detection — use full phrases for long strings, word-boundary
    # regex for short words to avoid false positives (e.g. "parked" inside CSS
    # classes, JS vars, or unrelated page content like "double-parked").
    #
    # Split into DEFINITIVE signals (always fire) and AMBIGUOUS signals (only
    # fire on thin pages).  A full landing page that says "Coming Soon" for one
    # feature or "under construction" for a section is a product label, not a
    # parking indicator.  Definitive signals like "buy this domain" or
    # "sedoparking" are never legitimate feature labels.
    _PARKING_DEFINITIVE = [
        b'domain for sale', b'buy this domain', b'domain parking',
        b'this domain is parked', b'parked free', b'parked by',
        b'parked domain', b'sedoparking',
        b'hugedomains', b'afternic', b'dan.com/buy-domain',
    ]
    _PARKING_AMBIGUOUS = [
        b'under construction',
    ]
    for phrase in _PARKING_DEFINITIVE:
        if phrase in content_lower:
            result["parking"] = True
            break
    if not result["parking"]:
        for phrase in _PARKING_AMBIGUOUS:
            if phrase in content_lower:
                # Only fire on thin pages — strip tags and measure visible text
                _visible = re.sub(rb'<[^>]+>', b' ', content)
                _visible = re.sub(rb'\s+', b' ', _visible).strip()
                if len(_visible) < 1000:
                    result["parking"] = True
                break
    if not result["parking"]:
        # Decode once for regex checks — catches "coming soon" and standalone
        # "parked" while avoiding substring collisions
        _content_str = content_lower.decode('utf-8', errors='ignore')
        _PARKING_REGEX_DEFINITIVE = [
            r'(?<!-)\bparked\b(?!-)',  # standalone "parked" — excludes hyphenated (double-parked, header-parked-section)
        ]
        _PARKING_REGEX_AMBIGUOUS = [
            r'\bcoming\s+soon\b',       # "coming soon" as whole phrase
        ]
        for pat in _PARKING_REGEX_DEFINITIVE:
            if re.search(pat, _content_str):
                result["parking"] = True
                break
        if not result["parking"]:
            for pat in _PARKING_REGEX_AMBIGUOUS:
                if re.search(pat, _content_str):
                    # Only fire on thin pages
                    _visible = re.sub(rb'<[^>]+>', b' ', content)
                    _visible = re.sub(rb'\s+', b' ', _visible).strip()
                    if len(_visible) < 1000:
                        result["parking"] = True
                    break
    
    path = urlparse(final_url).path.lower()
    for p in PHISHING_PATHS:
        if p in path:
            result["phishing_paths"].append(p)
    # v7.5.1: Also check standard auth paths — tracked separately so the
    # phishing kit composite can distinguish "has /signin" (normal for apps)
    # from "has /tunnel/" (genuinely suspicious).
    _auth_paths_found = []
    for p in STANDARD_AUTH_PATHS:
        if p in path:
            _auth_paths_found.append(p)
    # Only add auth paths to phishing_paths if brand impersonation is also present
    # (a login page impersonating Chase IS phishing; a login page for nextphoto.app is not)
    if _auth_paths_found and result.get("brands"):
        result["phishing_paths"].extend(_auth_paths_found)
    # Track auth paths separately for transparency even when not scored
    result["auth_paths"] = _auth_paths_found
    
    # === PHISHING KIT FILENAME DETECTION (v7.3) ===
    # Check if the URL path ends with a known kit entry-point filename.
    path_basename = path.rsplit('/', 1)[-1] if '/' in path else path
    
    for fn in PHISHING_KIT_FILENAMES_STRONG:
        if path_basename == fn:
            result["kit_filename"] = fn
            result["kit_filename_strong"] = True
            break
    
    if not result["kit_filename"]:
        for fn in PHISHING_KIT_FILENAMES_WEAK:
            if path_basename == fn:
                result["kit_filename"] = fn
                result["kit_filename_strong"] = False
                break
    
    # === EXFILTRATION / DROP SCRIPT DETECTION (v7.3, updated v7.5) ===
    # Scan raw HTML source for credential exfiltration patterns.
    # Telegram bot tokens, Discord webhooks, base64-encoded exfil payloads
    # in page source are near-certain indicators of a live phishing kit.
    # v7.5: Extract matched values (emails, tokens, URLs) for analyst visibility.
    # v7.5.1: Same-domain exclusion for js_email_exfil — a site's own contact
    #         email hardcoded in JS (e.g. "contato@example.com.br" on example.com.br)
    #         is a contact form, not credential exfiltration.
    _analyzed_domain_lower = domain.lower().strip('.')
    for pattern_re, signal_name, description in EXFIL_DROP_PATTERNS:
        match = pattern_re.search(content)
        if match:
            # Same-domain suppression for hardcoded email signals
            if signal_name == 'js_email_exfil' and match.lastindex and match.lastindex >= 1:
                try:
                    email_addr = match.group(1).decode('utf-8', errors='replace').lower()
                    email_domain = email_addr.split('@', 1)[1].strip('.')
                    # Suppress if email domain matches or is parent of the analyzed domain
                    # e.g. email=info@example.com on domain=example.com → suppress
                    # e.g. email=contact@example.com on domain=shop.example.com → suppress
                    if (email_domain == _analyzed_domain_lower
                            or _analyzed_domain_lower.endswith('.' + email_domain)):
                        continue  # Same-domain contact email — not exfil
                except Exception:
                    pass  # If we can't parse, let it fire as normal
            
            result["exfil_signals"].append(signal_name)
            detail = description
            # If regex has a capture group, extract and append the value
            if match.lastindex and match.lastindex >= 1:
                try:
                    extracted = match.group(1).decode('utf-8', errors='replace')
                    # Truncate very long values (e.g. base64 blobs) for readability
                    if len(extracted) > 120:
                        extracted = extracted[:60] + "..." + extracted[-20:]
                    detail += f" → {extracted}"
                except Exception:
                    pass  # Fall back to description-only if decode fails
            result["exfil_details"].append(detail)
    
    # === CLIENT-SIDE HARVEST DETECTION (v7.5) ===
    # Detect credential harvesting code (input value reads, keyloggers,
    # sendBeacon, image pixel exfil, cookie theft, FormData send).
    # These are NEVER scored alone — only flagged for combo evaluation.
    for pattern_re, signal_name, description in CLIENT_SIDE_HARVEST_PATTERNS:
        match = pattern_re.search(content)
        if match:
            result["harvest_signals"].append(signal_name)
            detail = description
            if match.lastindex and match.lastindex >= 1:
                try:
                    extracted = match.group(1).decode('utf-8', errors='replace')
                    if len(extracted) > 120:
                        extracted = extracted[:60] + "..." + extracted[-20:]
                    detail += f" → {extracted}"
                except Exception:
                    pass
            result["harvest_details"].append(detail)
    
    # === HARVEST COMBO EVALUATION (v7.5) ===
    # Check if any harvest signal is corroborated by other phishing indicators.
    # Must run AFTER all content analysis (cred forms, brands, paths, titles).
    if result["harvest_signals"]:
        corroborating_found = []
        # Map result dict keys to corroborating signal names
        _harvest_corroboration_map = {
            "credential_form": "has_credential_form",
            "form_external": "form_posts_external",
            "sensitive_fields": "has_sensitive_fields",
            "suspicious_iframe": "has_suspicious_iframe",
        }
        # Check boolean flags from the result dict
        for result_key, signal_label in _harvest_corroboration_map.items():
            if result.get(result_key):
                corroborating_found.append(signal_label)
        # Check string/list fields that indicate presence when non-empty
        if result.get("brands"):
            corroborating_found.append("brands_detected")
        if result.get("phishing_paths"):
            corroborating_found.append("phishing_paths_found")
        if result.get("suspicious_title_match"):
            corroborating_found.append("has_suspicious_page_title")
        # Kit filename (weak only — strong is already high-confidence on its own)
        if result.get("kit_filename") and not result.get("kit_filename_strong"):
            corroborating_found.append("phishing_kit_filename_weak")
        
        if corroborating_found:
            result["harvest_combo"] = True
            harvest_names = "; ".join(result["harvest_signals"])
            corr_names = "; ".join(corroborating_found)
            result["harvest_combo_reason"] = (
                f"Client-side harvest [{harvest_names}] + "
                f"corroborating [{corr_names}]"
            )
    
    # === OAUTH CONSENT PHISHING DETECTION (v7.3.1) ===
    # Attackers set up pages that redirect to real Microsoft/Google OAuth
    # authorization endpoints with malicious app permissions. The phishing
    # domain itself has NO password fields (bypasses credential form detection).
    # Look for: OAuth auth endpoints in links/redirects, response_type=code,
    # redirect_uri pointing back to the domain, excessive scope requests.
    oauth_evidence = []
    
    # Check for OAuth authorization endpoints in all href/src links
    all_links = re.findall(rb'(?:href|src|action|url)\s*=\s*["\']([^"\']{10,500})["\']', content, re.IGNORECASE)
    all_links_lower = [l.lower() for l in all_links]
    for link in all_links_lower:
        for endpoint in OAUTH_AUTH_ENDPOINTS:
            if endpoint in link:
                oauth_evidence.append(f"OAuth endpoint in link: {endpoint.decode()}")
                break
    
    # Check for OAuth parameters in page source (could be in JS, forms, or meta redirects)
    for pattern in OAUTH_PARAM_PATTERNS:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            param_str = match.group(0).decode('utf-8', errors='ignore')[:80]
            oauth_evidence.append(f"OAuth param: {param_str}")
    
    # Also check for inline JS that builds OAuth URLs
    if re.search(rb'(?:oauth|authorize|consent).*(?:response_type|redirect_uri|client_id)', content, re.IGNORECASE):
        if not oauth_evidence:  # Only if we haven't already found direct evidence
            oauth_evidence.append("JS references to OAuth authorization flow")
    
    if oauth_evidence:
        result["oauth_phish"] = True
        result["oauth_evidence"] = oauth_evidence
    
    # === SECURITY TOOLING DETECTION (v7.5.1) ===
    # Legitimate sites invest in bot management, CAPTCHA, and security tooling.
    # These are positive trust signals — phishing kits and spam operations almost
    # never implement real security tooling (it costs money and blocks their targets).
    _security_signals = []
    
    # Google reCAPTCHA (v2, v3, Enterprise)
    if (b'google.com/recaptcha' in content_lower or
        b'gstatic.com/recaptcha' in content_lower or
        b'grecaptcha' in content_lower or
        b'g-recaptcha' in content_lower or
        b'recaptcha/api' in content_lower):
        _security_signals.append("recaptcha")
    
    # Cloudflare Turnstile / Bot Management
    if (b'challenges.cloudflare.com' in content_lower or
        b'cf-turnstile' in content_lower or
        b'cloudflare.com/turnstile' in content_lower or
        b'cf_challenge' in content_lower or
        b'__cf_bm' in content_lower or
        b'cf-challenge-response' in content_lower):
        _security_signals.append("cloudflare_bot_management")
    
    # hCaptcha
    if (b'hcaptcha.com' in content_lower or
        b'h-captcha' in content_lower):
        _security_signals.append("hcaptcha")
    
    # Akamai Bot Manager
    if b'akamai.com/akam' in content_lower or b'_abck' in content_lower:
        _security_signals.append("akamai_bot_manager")
    
    # DataDome
    if b'datadome.co' in content_lower:
        _security_signals.append("datadome")
    
    # PerimeterX / HUMAN Security
    if b'perimeterx.net' in content_lower or b'px-captcha' in content_lower:
        _security_signals.append("perimeterx")
    
    result["security_signals"] = _security_signals
    
    return result


def analyze_ecommerce_indicators(content: bytes, domain: str) -> Dict:
    """
    Detect e-commerce site indicators and business legitimacy signals.
    
    Helps identify:
    1. Whether site is an e-commerce store
    2. Whether it has proper business identity disclosure
    3. Cross-domain brand links (fragmentation indicator)
    """
    result = {
        "is_ecommerce": False,
        "ecommerce_signals": [],
        "has_business_identity": False,
        "business_identity_signals": [],
        "missing_identity_signals": [],
        "cross_domain_brand_links": [],
    }
    
    if not content:
        return result
    
    content_str = content.decode('utf-8', errors='ignore').lower()
    
    # === E-COMMERCE DETECTION ===
    ecom_count = 0
    for indicator in ECOMMERCE_INDICATORS:
        if indicator in content_str:
            result["ecommerce_signals"].append(indicator)
            ecom_count += 1
    
    # Consider it e-commerce if 3+ indicators present
    if ecom_count >= 3:
        result["is_ecommerce"] = True
    
    # === BUSINESS IDENTITY DETECTION ===
    identity_signals = []
    
    # Check for legal entity patterns
    if re.search(r'\b(inc|llc|ltd|corp|corporation|gmbh|sarl|pty|co\.)\b', content_str, re.IGNORECASE):
        identity_signals.append("legal_entity")
    
    # Check for registration numbers
    if re.search(r'(registration|reg\.?\s*no|business\s*number|company\s*number|ein|vat|abn|tax\s*id)\s*[:.\s#]*[\w\d-]{5,}', content_str, re.IGNORECASE):
        identity_signals.append("registration_number")
    
    # Check for physical address
    if re.search(r'\d+\s+\w+\s+(street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|way|court|ct|place|pl)', content_str, re.IGNORECASE):
        identity_signals.append("physical_address")
    
    # Check for "About Us" with substantial content
    if re.search(r'about\s*(us|our\s*company|the\s*company|who\s*we\s*are)', content_str, re.IGNORECASE):
        identity_signals.append("about_page")
    
    # Check for contact information
    if re.search(r'contact\s*(us|info|information)', content_str, re.IGNORECASE):
        identity_signals.append("contact_info")
    
    # Check for terms/privacy
    if re.search(r'(terms\s*(of|and)\s*(service|use)|privacy\s*policy|refund\s*policy|return\s*policy)', content_str, re.IGNORECASE):
        identity_signals.append("legal_policies")
    
    result["business_identity_signals"] = identity_signals
    result["has_business_identity"] = len(identity_signals) >= 3
    
    # What's missing (important for e-commerce sites)
    if result["is_ecommerce"]:
        expected = ["legal_entity", "physical_address", "legal_policies"]
        missing = [s for s in expected if s not in identity_signals]
        result["missing_identity_signals"] = missing
    
    # === CROSS-DOMAIN BRAND LINK DETECTION ===
    # Extract the registrable domain (brand + effective TLD) for comparison.
    # Must handle ccTLDs like .co.uk, .com.au, .com.br, .co.ke, .or.ke, etc.
    # Without this, "tandem.co.uk" is parsed as brand="tandem.co" tld=".uk",
    # causing www.tandem.co.uk to fuzzy-match as a "different brand."
    
    _CCTLD_SECOND_LEVELS = {"co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "go"}
    
    def _split_brand_tld(hostname: str):
        """Split a hostname into (brand, effective_tld), stripping subdomains.
        
        Examples:
            tandem.co.uk     → ("tandem", ".co.uk")
            www.tandem.co.uk → ("tandem", ".co.uk")
            cs.tandem.co.uk  → ("tandem", ".co.uk")
            gabyandbeauty.shop → ("gabyandbeauty", ".shop")
            sub.example.com.au → ("example", ".com.au")
        """
        parts = hostname.lower().strip(".").split(".")
        # Remove www prefix — it's never part of the brand
        if parts and parts[0] == "www":
            parts = parts[1:]
        if len(parts) < 2:
            return (hostname.lower(), "")
        # Detect ccTLD: if second-to-last part is a known second-level (co, com, org, etc.)
        if len(parts) >= 3 and parts[-2] in _CCTLD_SECOND_LEVELS:
            tld = "." + ".".join(parts[-2:])
            brand = parts[-3] if len(parts) >= 3 else parts[0]
        else:
            tld = "." + parts[-1]
            brand = parts[-2] if len(parts) >= 2 else parts[0]
        return (brand, tld)
    
    brand_name, current_tld = _split_brand_tld(domain)
    
    if brand_name and current_tld:
        # Build the registrable domain for same-domain checks
        registrable_domain = brand_name + current_tld
        
        # Find all links in content
        links = re.findall(r'href=["\']([^"\']+)["\']', content_str, re.IGNORECASE)
        
        for link in links:
            try:
                if link.startswith('http'):
                    parsed = urlparse(link)
                    link_host = parsed.netloc.lower()
                    if not link_host or link_host == domain:
                        continue
                    
                    link_brand, link_tld = _split_brand_tld(link_host)
                    if not link_brand or not link_tld:
                        continue
                    
                    link_registrable = link_brand + link_tld
                    
                    # Skip subdomains of the SAME registrable domain
                    # e.g. www.tandem.co.uk, cs.tandem.co.uk are same as tandem.co.uk
                    if link_registrable == registrable_domain:
                        continue
                    
                    # Same brand, different TLD = suspicious
                    if link_brand == brand_name and link_tld != current_tld:
                        result["cross_domain_brand_links"].append(link_host)
                    
                    # Similar brand (80%+ match) on different registrable domain
                    elif link_registrable != registrable_domain:
                        if difflib.SequenceMatcher(None, brand_name, link_brand).ratio() > 0.8:
                            result["cross_domain_brand_links"].append(link_host)
            except:
                pass
        
        result["cross_domain_brand_links"] = list(set(result["cross_domain_brand_links"]))[:5]
    
    return result


def check_hijacked_domain_indicators(content: bytes, final_url: str, redirect_chain: List[str] = None) -> Dict:
    """
    Detect indicators of hijacked/compromised domains being used as phishing stepping stones.
    
    Based on research: https://keepaware.com/blog/over-100-domains-hijacked
    
    Key indicators:
    1. Suspicious URL path patterns (e.g., /tunnel/, /bid/, /invite/)
    2. Document sharing lure content
    3. Phishing kit JavaScript behaviors (atob, hash extraction, etc.)
    4. Redirects to known phishing infrastructure (workers.dev, etc.)
    5. Email tracking in URL hash
    """
    result = {
        "has_hijack_path": False,
        "hijack_path": "",
        "has_doc_lure": False,
        "doc_lure": "",
        "has_phishing_js": False,
        "phishing_js_found": [],
        "redirects_to_phishing_infra": False,
        "phishing_infra": "",
        "has_email_in_url": False,
        "email_tracking": "",
        "risk_score_addition": 0,
    }
    
    if not content and not final_url:
        return result
    
    # === CHECK 1: Suspicious URL path patterns ===
    # Hijacked sites often have phishing pages in paths like /tunnel/, /bid/, /secure/
    if final_url:
        parsed = urlparse(final_url)
        path_lower = parsed.path.lower()
        
        for keyword in HIJACK_PATH_KEYWORDS:
            if f'/{keyword}/' in path_lower or f'/{keyword}' == path_lower or path_lower.startswith(f'/{keyword}'):
                result["has_hijack_path"] = True
                result["hijack_path"] = keyword
                result["risk_score_addition"] += 12
                break
        
        # Check for suspicious filename patterns
        if not result["has_hijack_path"]:
            for pattern in HIJACK_FILE_PATTERNS:
                if pattern in path_lower:
                    result["has_hijack_path"] = True
                    result["hijack_path"] = pattern
                    result["risk_score_addition"] += 8
                    break
        
        # === CHECK 5: Email tracking in URL ===
        # Phishers embed victim email in URL hash: example.com/page#john@company.com
        full_url = final_url
        if '#' in full_url:
            hash_part = full_url.split('#', 1)[1]
            # Check for plain email
            if '@' in hash_part and '.' in hash_part.split('@')[-1]:
                result["has_email_in_url"] = True
                result["email_tracking"] = "plain_email_in_hash"
                result["risk_score_addition"] += 15
            # Check for base64 encoded email (common pattern)
            elif len(hash_part) > 10 and hash_part.replace('=', '').replace('+', '').replace('/', '').isalnum():
                try:
                    import base64
                    decoded = base64.b64decode(hash_part).decode('utf-8', errors='ignore')
                    if '@' in decoded and '.' in decoded:
                        result["has_email_in_url"] = True
                        result["email_tracking"] = "base64_email_in_hash"
                        result["risk_score_addition"] += 18
                except:
                    pass
    
    # === CHECK 4: Redirects to known phishing infrastructure ===
    urls_to_check = [final_url] if final_url else []
    if redirect_chain:
        urls_to_check.extend(redirect_chain)
    
    for url in urls_to_check:
        if url:
            url_lower = url.lower()
            for infra in PHISHING_INFRASTRUCTURE:
                if infra in url_lower:
                    result["redirects_to_phishing_infra"] = True
                    result["phishing_infra"] = infra
                    result["risk_score_addition"] += 20
                    break
        if result["redirects_to_phishing_infra"]:
            break
    
    if not content:
        return result
    
    content_lower = content.lower()
    
    # === CHECK 2: Document sharing lure content ===
    for lure in DOC_SHARING_LURES:
        if lure in content_lower:
            result["has_doc_lure"] = True
            result["doc_lure"] = lure.decode('utf-8', errors='ignore')
            result["risk_score_addition"] += 12
            break
    
    # === CHECK 3: Phishing kit JavaScript behaviors ===
    js_patterns_found = []
    for pattern in PHISHING_JS_PATTERNS:
        if pattern in content_lower:
            js_patterns_found.append(pattern.decode('utf-8', errors='ignore'))
    
    if len(js_patterns_found) >= 2:  # Need 2+ patterns to flag
        result["has_phishing_js"] = True
        result["phishing_js_found"] = js_patterns_found[:5]
        result["risk_score_addition"] += 15
    
    return result


def check_corporate_trust_signals(domain: str, timeout: float = 3.0) -> Dict:
    """
    Check for corporate legitimacy signals by probing common trust pages.
    A legitimate business typically has: /about, /contact, /privacy, /terms, etc.
    
    This is a lightweight check - we just see if these pages return 200 OK.
    """
    result = {
        "pages_checked": [],
        "pages_found": [],
        "missing_trust_signals": False,
        "trust_score": 0,  # Higher = more trustworthy
    }
    
    if not REQUESTS_AVAILABLE:
        return result
    
    # Common corporate trust pages
    TRUST_PAGES = [
        '/about', '/about-us', '/company', '/team',      # Company info
        '/contact', '/contact-us', '/support',            # Contact info
        '/privacy', '/privacy-policy',                    # Legal
        '/terms', '/terms-of-service', '/tos',           # Legal
        '/careers', '/jobs',                              # Established company signal
    ]
    
    base_url = f"https://{domain}"
    
    try:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        for page in TRUST_PAGES[:8]:  # Check up to 8 pages to limit requests
            result["pages_checked"].append(page)
            try:
                r = session.head(base_url + page, timeout=timeout, allow_redirects=True)
                # Accept 200, 301/302 (redirect to actual page), but not 404/403/401
                if r.status_code in [200, 301, 302]:
                    # For redirects, check if it redirects to a real page (not homepage)
                    if r.status_code in [301, 302]:
                        redirect_to = r.headers.get('Location', '')
                        # If redirect goes back to homepage, don't count it
                        if redirect_to.rstrip('/') == base_url or redirect_to == '/':
                            continue
                    result["pages_found"].append(page)
                    result["trust_score"] += 1
            except:
                continue
        
        session.close()
    except:
        pass
    
    # Missing trust signals if we found 0-1 trust pages out of what we checked
    if len(result["pages_found"]) <= 1 and len(result["pages_checked"]) >= 4:
        result["missing_trust_signals"] = True
    
    return result


def rdap_lookup(domain: str, timeout: float) -> Tuple[str, int, bool, str]:
    """Returns: (effective_date_iso, age_days, is_reregistered, rereg_date_iso)"""
    if not REQUESTS_AVAILABLE:
        return "", -1, False, ""
    try:
        parts = domain.split('.')
        base = '.'.join(parts[-3:]) if len(parts) > 2 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil'] else '.'.join(parts[-2:])
        tld = parts[-1].lower() if parts else ""
        
        # Direct registry endpoints for known TLDs — more reliable than rdap.org
        # which rate-limits (10 req/10s) and may omit reregistration events.
        _DIRECT_RDAP = {
            "app": "https://pubapi.registry.google/rdap/domain/",
            "dev": "https://pubapi.registry.google/rdap/domain/",
            "page": "https://pubapi.registry.google/rdap/domain/",
            "new": "https://pubapi.registry.google/rdap/domain/",
            "google": "https://pubapi.registry.google/rdap/domain/",
            "com": "https://rdap.verisign.com/com/v1/domain/",
            "net": "https://rdap.verisign.com/net/v1/domain/",
            "org": "https://rdap.org/domain/",
            "io": "https://rdap.identitydigital.services/rdap/domain/",
            "me": "https://rdap.identitydigital.services/rdap/domain/",
            "ai": "https://rdap.identitydigital.services/rdap/domain/",
        }
        
        urls_to_try = []
        # Try direct registry endpoint FIRST for known TLDs — more reliable,
        # includes reregistration events that rdap.org may omit.
        if tld in _DIRECT_RDAP:
            urls_to_try.append(f"{_DIRECT_RDAP[tld]}{base}")
        # Fallback to rdap.org bootstrap (handles all TLDs but rate-limits)
        urls_to_try.append(f"https://rdap.org/domain/{base}")
        
        _headers = {"User-Agent": "ConfigChecker-RDAP/1.0 (domain-verification-tool)", "Accept": "application/rdap+json, application/json"}
        
        data = None
        for url in urls_to_try:
            try:
                r = requests.get(url, timeout=timeout, headers=_headers, allow_redirects=True)
                if r.status_code == 200:
                    data = r.json()
                    break
            except Exception:
                continue
        
        if not data:
            return "", -1, False, ""
        
        # Parse events — look for registration, reregistration, and last changed
        created = None
        reregistered = None
        for ev in data.get("events", []):
            action = ev.get("eventAction", "").lower()
            date_str = ev.get("eventDate", "")
            if not date_str:
                continue
            if action == "registration" and not created:
                created = date_str
            elif action == "reregistration":
                reregistered = date_str
        
        # Use reregistration date if present (domain was dropped and re-registered)
        # — this gives a more accurate "effective age" than original registration
        use_date = reregistered or created
        is_rereg = bool(reregistered)
        rereg_iso = ""
        if reregistered:
            try:
                rereg_iso = datetime.fromisoformat(reregistered.replace("Z", "+00:00")).isoformat()
            except Exception:
                pass
        if use_date:
            dt = datetime.fromisoformat(use_date.replace("Z", "+00:00"))
            return dt.isoformat(), (datetime.now(timezone.utc) - dt).days, is_rereg, rereg_iso
        return "", -1, False, ""
    except:
        return "", -1, False, ""


def whois_lookup(domain: str) -> Tuple[str, int]:
    """Fallback domain age lookup via python-whois when RDAP fails."""
    if not WHOIS_AVAILABLE:
        return "", -1
    try:
        parts = domain.split('.')
        base = '.'.join(parts[-3:]) if len(parts) > 2 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil'] else '.'.join(parts[-2:])
        w = python_whois.whois(base)
        created = w.creation_date
        if created is None:
            return "", -1
        # Some registrars return a list of dates
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime):
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            return created.isoformat(), age_days
        return "", -1
    except Exception:
        return "", -1


# === DIRECT SOCKET WHOIS FALLBACK (v7.5.1) ===
# For TLDs where RDAP and python-whois both fail, query the WHOIS server
# directly over TCP port 43.  This handles ccTLDs with non-standard WHOIS
# formats (e.g., .ng, .ke, .gh, .tz, .pk, .bd).
WHOIS_SERVERS = {
    'ng': 'whois.nic.ng',
    'ke': 'whois.kenic.or.ke',
    'gh': 'whois.nic.gh',
    'tz': 'whois.tznic.or.tz',
    'pk': 'whois.pknic.net.pk',
    'bd': 'whois.btcl.net.bd',
    'za': 'whois.registry.net.za',
    'eg': 'whois.ripe.net',
    'ug': 'whois.co.ug',
    'rw': 'whois.ricta.org.rw',
    'et': 'whois.ethiotelecom.et',
    'lk': 'whois.nic.lk',
    'mm': 'whois.registry.gov.mm',
    'kh': 'whois.nic.kh',
    'np': 'whois.mos.com.np',
    'ua': 'whois.ua',
    'by': 'whois.cctld.by',
    'ge': 'whois.registration.ge',
    'am': 'whois.amnic.net',
    'az': 'whois.az',
    'kz': 'whois.nic.kz',
    'uz': 'whois.cctld.uz',
}

def whois_socket_lookup(domain: str, timeout: float = 8.0) -> Tuple[str, int]:
    """
    Direct socket WHOIS query for TLDs not covered by RDAP or python-whois.
    Returns: (creation_date_iso, age_days)
    """
    import socket as _socket
    
    parts = domain.lower().split('.')
    # Extract the TLD (last part) for server lookup
    tld = parts[-1] if parts else ""
    if tld not in WHOIS_SERVERS:
        return "", -1
    
    # Build the registrable base domain
    _sld_indicators = {'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil'}
    if len(parts) > 2 and parts[-2] in _sld_indicators:
        base = '.'.join(parts[-3:])
    else:
        base = '.'.join(parts[-2:])
    
    server = WHOIS_SERVERS[tld]
    
    try:
        sock = _socket.create_connection((server, 43), timeout=timeout)
        sock.sendall((base + "\r\n").encode("utf-8"))
        
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except _socket.timeout:
                break
        sock.close()
        
        if not response:
            return "", -1
        
        text = response.decode("utf-8", errors="replace")
        
        # Parse creation date from various WHOIS formats
        # Common patterns:
        #   Creation Date: 2020-01-15T00:00:00Z
        #   Registration Date: 15-Jan-2020
        #   created: 2020-01-15
        #   Registered: 15 Jan 2020
        #   Created On: 2020-01-15
        import re as _re_w
        
        _DATE_PATTERNS = [
            _re_w.compile(r'(?:Creation Date|Registration Date|Created|Registered|Created On|created)\s*[:=]\s*(.+)', _re_w.IGNORECASE),
        ]
        
        for pattern in _DATE_PATTERNS:
            m = pattern.search(text)
            if m:
                date_str = m.group(1).strip().rstrip('.')
                # Try parsing multiple date formats
                for fmt in [
                    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d", "%d-%b-%Y", "%d %b %Y", "%d/%m/%Y",
                    "%Y.%m.%d", "%B %d, %Y", "%d-%m-%Y", "%Y-%m-%d %H:%M:%S",
                ]:
                    try:
                        dt = datetime.strptime(date_str[:30], fmt)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        age_days = (datetime.now(timezone.utc) - dt).days
                        return dt.isoformat(), age_days
                    except (ValueError, TypeError):
                        continue
                
                # Last resort: try fromisoformat
                try:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - dt).days
                    return dt.isoformat(), age_days
                except (ValueError, TypeError):
                    pass
        
        return "", -1
    except Exception:
        return "", -1


# === HTTP WHOIS FALLBACK (v7.5.1) ===
# When socket WHOIS fails (e.g., Streamlit Cloud blocks port 43), query
# web-based WHOIS services over HTTPS.  This is the final fallback in the
# registration lookup chain: RDAP → python-whois → socket WHOIS → HTTP WHOIS.
def whois_http_lookup(domain: str, timeout: float = 8.0) -> Tuple[str, int]:
    """
    Query web-based WHOIS services over HTTPS for domains where RDAP,
    python-whois, and socket WHOIS all fail.
    Returns: (creation_date_iso, age_days)
    """
    if not REQUESTS_AVAILABLE:
        return "", -1
    
    import re as _re_http
    
    parts = domain.lower().split('.')
    _sld_indicators = {'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil'}
    if len(parts) > 2 and parts[-2] in _sld_indicators:
        base = '.'.join(parts[-3:])
    else:
        base = '.'.join(parts[-2:])
    
    _DATE_PATTERNS = [
        _re_http.compile(
            r'(?:Creation Date|Registration Date|Created|Registered|Created On|created|'
            r'Registration Time|Domain Registration Date)\s*[:=]\s*(.+)',
            _re_http.IGNORECASE
        ),
    ]
    
    _DATE_FORMATS = [
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d", "%d-%b-%Y", "%d %b %Y", "%d/%m/%Y",
        "%Y.%m.%d", "%B %d, %Y", "%d-%m-%Y", "%Y-%m-%d %H:%M:%S",
        "%a %b %d %H:%M:%S %Z %Y",  # Ruby-style: Tue Jan 10 00:00:00 UTC 2023
    ]
    
    def _parse_date(date_str: str):
        """Try to parse a date string in multiple formats."""
        date_str = date_str.strip().rstrip('.')
        # Strip trailing comments/notes after the date
        # e.g., "2020-01-15 (some note)" → "2020-01-15"
        date_str = _re_http.split(r'\s*[\(\[]', date_str)[0].strip()
        
        for fmt in _DATE_FORMATS:
            try:
                dt = datetime.strptime(date_str[:40], fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - dt).days
                if 0 <= age_days <= 36500:  # Sanity: 0-100 years
                    return dt.isoformat(), age_days
            except (ValueError, TypeError):
                continue
        # Last resort: fromisoformat
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - dt).days
            if 0 <= age_days <= 36500:
                return dt.isoformat(), age_days
        except (ValueError, TypeError):
            pass
        return "", -1
    
    # Service 1: who.is (HTML scraping)
    try:
        r = requests.get(
            f"https://who.is/whois/{base}",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 DomainVerification/1.0"},
            allow_redirects=True,
        )
        if r.status_code == 200:
            text = r.text
            for pattern in _DATE_PATTERNS:
                m = pattern.search(text)
                if m:
                    iso, age = _parse_date(m.group(1))
                    if age >= 0:
                        return iso, age
    except Exception:
        pass
    
    # Service 2: IANA RDAP bootstrap (sometimes works for ccTLDs that
    # have RDAP but aren't in rdap.org's bootstrap file)
    try:
        # Get the RDAP server from IANA bootstrap
        tld = parts[-1]
        bootstrap_r = requests.get(
            "https://data.iana.org/rdap/dns.json",
            timeout=5,
            headers={"User-Agent": "DomainVerification/1.0"},
        )
        if bootstrap_r.status_code == 200:
            bootstrap_data = bootstrap_r.json()
            rdap_url = None
            for entry in bootstrap_data.get("services", []):
                tld_list, urls = entry[0], entry[1]
                if tld in tld_list:
                    rdap_url = urls[0].rstrip('/')
                    break
            
            if rdap_url:
                rdap_r = requests.get(
                    f"{rdap_url}/domain/{base}",
                    timeout=timeout,
                    headers={"Accept": "application/rdap+json, application/json"},
                    allow_redirects=True,
                )
                if rdap_r.status_code == 200:
                    data = rdap_r.json()
                    for ev in data.get("events", []):
                        if ev.get("eventAction", "").lower() == "registration":
                            date_str = ev.get("eventDate", "")
                            if date_str:
                                iso, age = _parse_date(date_str)
                                if age >= 0:
                                    return iso, age
    except Exception:
        pass
    
    return "", -1


def whois_enrich(domain: str) -> dict:
    """
    Extract registrar, statuses, and updated date from WHOIS.
    Used for transfer lock detection and domain takeover signals.
    """
    result = {
        "registrar": "",
        "statuses": [],
        "updated_date": "",
        "updated_days_ago": -1,
        "transfer_locked": True,  # Default safe — only flag if we confirm lock is missing
        "privacy": False,         # v7.4: WHOIS privacy/proxy service detected
        "privacy_service": "",    # v7.4: Which privacy service matched
    }
    
    # Known WHOIS privacy/proxy service indicators
    PRIVACY_KEYWORDS = [
        ('domains by proxy', 'Domains By Proxy (GoDaddy)'),
        ('domainsbyproxy', 'Domains By Proxy (GoDaddy)'),
        ('whoisguard', 'WhoisGuard (Namecheap)'),
        ('whois guard', 'WhoisGuard (Namecheap)'),
        ('contactprivacy', 'Contact Privacy (Tucows)'),
        ('contact privacy', 'Contact Privacy (Tucows)'),
        ('privacy protect', 'Privacy Protection Service'),
        ('privacyprotect', 'Privacy Protection Service'),
        ('withheldforprivacy', 'Withheld for Privacy'),
        ('withheld for privacy', 'Withheld for Privacy'),
        ('redacted for privacy', 'ICANN Redacted'),
        ('data protected', 'Data Protected'),
        ('identity protection', 'Identity Protection Service'),
        ('id shield', 'ID Shield'),
        ('perfect privacy', 'Perfect Privacy'),
        ('whois privacy', 'WHOIS Privacy Service'),
        ('whoisprivacy', 'WHOIS Privacy Service'),
        ('privacy service', 'Privacy Service'),
        ('proxy service', 'Proxy Registration Service'),
        ('domain privacy', 'Domain Privacy Service'),
        ('registrant not identified', 'Registrant Not Identified'),
    ]
    
    if not WHOIS_AVAILABLE:
        return result
    try:
        parts = domain.split('.')
        base = '.'.join(parts[-3:]) if len(parts) > 2 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil'] else '.'.join(parts[-2:])
        w = python_whois.whois(base)
        
        # Registrar
        result["registrar"] = (w.registrar or "")[:200]
        
        # === WHOIS PRIVACY DETECTION (v7.4) ===
        # Check org, name, and registrar fields for privacy service indicators.
        # Build a single string from all available registrant info.
        privacy_haystack_parts = []
        for attr in ['org', 'name', 'registrar', 'emails']:
            val = getattr(w, attr, None)
            if val:
                if isinstance(val, list):
                    privacy_haystack_parts.extend(str(v) for v in val)
                else:
                    privacy_haystack_parts.append(str(val))
        # Also check raw text if available (some TLDs only have raw text)
        if hasattr(w, 'text') and w.text:
            raw = w.text if isinstance(w.text, str) else str(w.text)
            # Only check first 2000 chars of raw text for efficiency
            privacy_haystack_parts.append(raw[:2000])
        
        privacy_haystack = ' '.join(privacy_haystack_parts).lower()
        
        for keyword, service_name in PRIVACY_KEYWORDS:
            if keyword in privacy_haystack:
                result["privacy"] = True
                result["privacy_service"] = service_name
                break
        
        # Statuses
        raw_status = w.status
        if raw_status:
            if isinstance(raw_status, str):
                raw_status = [raw_status]
            # Normalize: "clientTransferProhibited https://..." → "clientTransferProhibited"
            statuses = []
            for s in raw_status:
                clean = s.split()[0].strip() if s else ""
                if clean:
                    statuses.append(clean)
            result["statuses"] = statuses
            
            # Transfer lock check
            lock_statuses = {'clienttransferprohibited', 'servertransferprohibited'}
            has_lock = any(s.lower() in lock_statuses for s in statuses)
            result["transfer_locked"] = has_lock
        
        # Updated date
        updated = w.updated_date
        if updated:
            if isinstance(updated, list):
                updated = updated[0]
            if isinstance(updated, datetime):
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
                result["updated_date"] = updated.isoformat()
                result["updated_days_ago"] = (datetime.now(timezone.utc) - updated).days
    except Exception:
        pass
    return result


def check_cert_transparency(domain: str, timeout: float = 8.0) -> dict:
    """
    Query crt.sh (Certificate Transparency logs) for domain certificates.
    Reveals certificate issuance history — useful for detecting:
    - Brand-new domains (first cert = recent)
    - Domain takeovers (new cert on old domain)
    - Let's Encrypt churn (mass phishing infra)
    """
    result = {
        "ct_count": -1,
        "recent_issuance": False,
        "issuers": [],
        "first_seen": "",
        "last_seen": "",
        "dates": [],  # v7.3.1: sorted list of cert datetimes for gap analysis
        "last_cert_issuer": "",    # v7.5.1: Issuer of the most recent certificate
        "days_since_last_cert": -1,  # v7.5.1: Days since most recent cert issued
    }
    if not REQUESTS_AVAILABLE:
        return result
    try:
        # v7.5: Query both subdomain wildcard AND exact apex to catch apex-only certs.
        # The %.domain query only matches subdomain certs; an apex-only cert
        # (e.g., E8 cert for gthrr.com with no subdomain SANs) requires a
        # separate exact query.
        entries = []
        ua = {"User-Agent": "DomainApproval/7.1"}

        # Query 1: subdomain wildcard (%.domain.com)
        try:
            r1 = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=timeout, headers=ua
            )
            if r1.status_code == 200:
                sub_entries = r1.json()
                if isinstance(sub_entries, list):
                    entries.extend(sub_entries)
        except Exception:
            pass

        # Query 2: exact apex domain — catches apex-only certs
        try:
            r2 = requests.get(
                f"https://crt.sh/?q={domain}&output=json",
                timeout=timeout, headers=ua
            )
            if r2.status_code == 200:
                apex_entries = r2.json()
                if isinstance(apex_entries, list):
                    entries.extend(apex_entries)
        except Exception:
            pass

        if not entries:
            return result

        # Deduplicate by crt.sh entry ID
        seen_ids = set()
        deduped = []
        for entry in entries:
            entry_id = entry.get("id") or entry.get("min_cert_id")
            if entry_id and entry_id in seen_ids:
                continue
            if entry_id:
                seen_ids.add(entry_id)
            deduped.append(entry)
        entries = deduped
        
        result["ct_count"] = len(entries)
        
        if not entries:
            return result
        
        # Parse dates and issuers
        issuers = set()
        dates = []
        now = datetime.now(timezone.utc)
        
        for entry in entries[:200]:  # Cap processing at 200 certs
            issuer = entry.get("issuer_name", "")
            if issuer:
                # Extract CN or O from issuer DN
                for part in issuer.split(","):
                    part = part.strip()
                    if part.startswith("CN=") or part.startswith("O="):
                        issuers.add(part.split("=", 1)[1].strip())
                        break
            
            not_before = entry.get("not_before", "")
            if not_before:
                try:
                    dt = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                    # Ensure timezone-aware (crt.sh may omit timezone)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    dates.append(dt)
                except (ValueError, TypeError):
                    pass
        
        if dates:
            dates.sort()
            result["first_seen"] = dates[0].isoformat()
            result["last_seen"] = dates[-1].isoformat()
            
            # Check if most recent cert was issued within 7 days
            days_since_last = (now - dates[-1]).days
            result["days_since_last_cert"] = days_since_last
            if days_since_last <= 7:
                result["recent_issuance"] = True
        
        result["issuers"] = sorted(issuers)[:10]  # Cap at 10 unique issuers
        result["dates"] = dates  # v7.3.1: sorted dates for gap analysis
        
        # v7.5.1: Find the issuer of the most recent certificate specifically
        # We need to match the most recent not_before to its issuer
        if dates:
            most_recent_dt = dates[-1]
            for entry in entries[:200]:
                not_before = entry.get("not_before", "")
                if not_before:
                    try:
                        dt = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        if dt == most_recent_dt:
                            issuer_dn = entry.get("issuer_name", "")
                            for part in issuer_dn.split(","):
                                part = part.strip()
                                if part.startswith("CN=") or part.startswith("O="):
                                    result["last_cert_issuer"] = part.split("=", 1)[1].strip()
                                    break
                            break
                    except (ValueError, TypeError):
                        pass
        
    except Exception:
        pass
    return result


# ============================================================================
# SCORING & SUMMARY
# ============================================================================

def generate_summary(res: DomainApprovalResult, signals: Set[str], rdap_enabled: bool, weights: dict = None) -> str:
    """Generate comprehensive summary showing ALL triggered signals and their email impacts."""
    
    if weights is None:
        weights = {}
    
    all_issues = []  # Format: "ISSUE → IMPACT"
    positives = []
    
    # === HIGH-RISK PHISHING INFRASTRUCTURE (composite indicator) ===
    if res.high_risk_phish_infra:
        all_issues.append(f"🚨 HIGH-RISK PHISHING INFRA → {res.high_risk_phish_infra_reason}")
    
    # === CRITICAL ISSUES ===
    if res.domain_blacklist_count > 0:
        bl_names = res.domain_blacklists_hit.replace(";", ", ")
        all_issues.append(f"BLACKLISTED DOMAIN on {bl_names} ({res.domain_blacklist_count} lists) → Emails BLOCKED by Gmail/Outlook/Yahoo")
    
    if res.ip_blacklist_count > 0:
        ip_bl_names = res.ip_blacklists_hit.replace(";", ", ")
        all_issues.append(f"BLACKLISTED IP on {ip_bl_names} ({res.ip_blacklist_count} lists) → Emails BLOCKED by major providers")
    
    # v6.2: Warn when blacklist checks were inconclusive (timeout/rate limit)
    total_inconclusive = res.domain_blacklist_inconclusive + res.ip_blacklist_inconclusive
    if total_inconclusive > 0:
        parts = []
        if res.domain_blacklist_inconclusive > 0:
            parts.append(f"{res.domain_blacklist_inconclusive} domain")
        if res.ip_blacklist_inconclusive > 0:
            parts.append(f"{res.ip_blacklist_inconclusive} IP")
        all_issues.append(f"⚠️ BLACKLIST CHECK INCONCLUSIVE ({', '.join(parts)} list(s) timed out) → May be rate-limited; result is NOT confirmed clean")
    
    if res.spf_mechanism == "+all":
        all_issues.append("SPF +all → Domain SPOOFABLE; anyone can forge emails as this sender")
    
    if rdap_enabled and res.domain_age_days >= 0 and res.domain_age_days <= 1:
        src = f" ({res.domain_age_source.upper()})" if res.domain_age_source else ""
        all_issues.append(f"⚠ DOMAIN CREATED TODAY/YESTERDAY{src} → Registered {res.domain_age_days}d ago")
    elif rdap_enabled and res.domain_age_days >= 0 and res.domain_age_days < 7:
        all_issues.append(f"DOMAIN ONLY {res.domain_age_days} DAYS OLD → Very new domain")
    elif rdap_enabled and res.domain_age_days >= 7 and res.domain_age_days < 30:
        all_issues.append(f"DOMAIN {res.domain_age_days} DAYS OLD → Young domain")
    elif rdap_enabled and res.domain_age_days >= 30 and res.domain_age_days < 90:
        all_issues.append(f"DOMAIN {res.domain_age_days} DAYS OLD → Relatively new domain")
    
    if not res.spf_exists and not res.dmarc_exists and not res.dkim_exists:
        all_issues.append("ZERO EMAIL AUTH → Gmail/Yahoo REQUIRE authentication; emails will fail")
    
    if res.is_disposable_email:
        all_issues.append("DISPOSABLE EMAIL DOMAIN → Cannot build sender reputation; inherently untrusted")
    
    if res.typosquat_target:
        all_issues.append(f"TYPOSQUAT of '{res.typosquat_target}' → Triggers phishing/fraud filters automatically")
    
    # === DOMAIN NAME PATTERN DETECTION (Tech Support Scams) ===
    if res.domain_impersonates_brand:
        if res.brand_plus_keyword_domain:
            all_issues.append(
                f"BRAND + SPOOFING KEYWORD '{res.domain_impersonates_brand.upper()}' + '{res.brand_spoofing_keyword}' "
                f"→ Domain mimics legitimate brand service/portal (e.g., {res.domain_impersonates_brand}connect.com = phishing)")
        else:
            all_issues.append(f"DOMAIN IMPERSONATES '{res.domain_impersonates_brand.upper()}' → Brand name in domain; classic tech support scam pattern")
    
    # === TLD VARIANT SPOOFING ===
    if res.tld_variant_detected:
        all_issues.append(f"TLD VARIANT SPOOF ({res.tld_variant_domain}) → Established business exists at variant TLD")
    # v7.5.1: UK variant dark — .co.uk has no DNS
    if res.tld_variant_uk_no_dns and "tld_variant_uk_no_dns" in signals:
        all_issues.append(
            f"UK VARIANT DARK ({res.tld_variant_uk_no_dns_domain}) → "
            f"UK business TLD variant has no DNS; domain operating on alternate TLD"
        )
    # Diagnostic detail (TLD VARIANT CHECK / CHECK ERROR) is stored in res.tld_variant_summary
    # but NOT shown in issues — it was confusing users into thinking spoofing was detected
    
    if res.has_suspicious_prefix:
        all_issues.append(f"SUSPICIOUS PREFIX '{res.suspicious_prefix_found}' → Common phishing/scam domain pattern")
    
    if res.has_suspicious_suffix:
        all_issues.append(f"SUSPICIOUS SUFFIX '{res.suspicious_suffix_found}' → Tech support scam domain pattern (e.g., 'brandaccount.com')")
    
    if res.is_tech_support_tld:
        all_issues.append("TECH SUPPORT SCAM TLD (.support/.tech/.help) → Heavily abused for scams")
    
    # E-commerce / Retail scam indicators
    if res.is_retail_scam_tld:
        tld = '.' + res.domain.split('.')[-1] if '.' in res.domain else ''
        all_issues.append(f"RETAIL SCAM TLD ({tld}) → .shop/.store TLDs heavily abused for fake stores")
    
    if res.has_cross_domain_brand_link:
        all_issues.append(f"CROSS-DOMAIN BRAND LINKS ({res.cross_domain_brand_links}) → Links to same brand on different TLD; common in clone stores")
    
    if res.is_ecommerce_site and res.missing_business_identity:
        all_issues.append("E-COMMERCE WITHOUT BUSINESS IDENTITY → No legal name/address/registration; high scam risk")
    
    if res.brands_detected:
        all_issues.append(f"BRAND IMPERSONATION ({res.brands_detected}) → Triggers phishing filters")
    
    if res.malware_links_found:
        all_issues.append("MALWARE LINKS DETECTED → Domain will be blacklisted across providers")
    
    if res.has_credential_form and res.brands_detected:
        all_issues.append("CREDENTIAL FORM + BRAND IMPERSONATION → Classic phishing; will be blocked")
    
    # === PHISHING KIT / EXFIL DETECTION (v7.3) ===
    if res.phishing_kit_detected:
        all_issues.append(f"🎣 PHISHING KIT DETECTED → {res.phishing_kit_reason}")
    
    if res.has_phishing_kit_filename:
        severity = "HIGH" if res.phishing_kit_filename_strong else "MODERATE"
        all_issues.append(f"PHISHING KIT FILENAME ({res.phishing_kit_filename}, {severity}) → URL path ends with known phishing kit entry point")
    
    if res.has_exfil_drop_script:
        details = res.exfil_drop_details.replace(";", "; ")
        all_issues.append(f"EXFIL DROP SCRIPT ({details}) → Credential exfiltration infrastructure in page source")
    
    # v7.4: Form action kit filename
    if res.has_form_action_kit:
        severity = "STRONG" if res.form_action_kit_strong else "WEAK"
        all_issues.append(f"FORM ACTION → KIT FILENAME ({res.form_action_kit_target}, {severity}) → Form posts to known phishing kit entry point")
    
    # v7.4: Suspicious page title
    if res.has_suspicious_page_title:
        all_issues.append(f"SUSPICIOUS PAGE TITLE (\"{res.page_title[:60]}\") → Matches phishing lure pattern: \"{res.page_title_match}\"")
    
    # v7.5: Client-side harvest combo
    if res.has_harvest_combo:
        harvest_detail = res.harvest_details.replace(";", "; ")
        all_issues.append(f"CLIENT-SIDE HARVEST COMBO ({harvest_detail}) → {res.harvest_combo_reason}")
    elif res.has_harvest_signals:
        # Informational only — harvest detected but no corroboration (not scored)
        harvest_detail = res.harvest_details.replace(";", "; ")
        all_issues.append(f"CLIENT-SIDE HARVEST (uncorroborated, {harvest_detail}) → Credential harvesting code detected but no other phishing indicators")
    
    # v7.4: WHOIS privacy — only surface as issue when combined with other risk factors
    if res.whois_privacy and res.domain_age_days >= 0 and res.domain_age_days < 90:
        all_issues.append(f"WHOIS PRIVACY ({res.whois_privacy_service}) → Privacy-protected registrant on {res.domain_age_days}d-old domain")
    elif res.whois_privacy and res.domain_age_days >= 90:
        # Older domain with privacy is normal — note for context but not an issue
        pass
    
    # === VIRUSTOTAL REPUTATION ===
    if res.vt_available:
        if res.vt_malicious_count >= 5:
            vendors = res.vt_malicious_vendors.replace(";", ", ")[:100]
            all_issues.append(f"🛡️ VT MALICIOUS ({res.vt_malicious_count}/{res.vt_total_vendors} vendors: {vendors}) → Domain flagged as malicious by security vendors")
        elif res.vt_malicious_count >= 1:
            all_issues.append(f"🛡️ VT FLAGGED ({res.vt_malicious_count} malicious + {res.vt_suspicious_count} suspicious) → Some security vendors flag this domain")
        elif res.vt_suspicious_count >= 1:
            all_issues.append(f"VT SUSPICIOUS ({res.vt_suspicious_count} vendor(s)) → Domain under suspicion by some vendors")
        if res.vt_threat_names:
            names = res.vt_threat_names.replace(";", ", ")
            all_issues.append(f"VT THREAT NAMES: {names}")
        if res.vt_malicious_count == 0 and res.vt_suspicious_count == 0 and res.vt_total_vendors >= 50:
            positives.append(f"VT CLEAN → 0/{res.vt_total_vendors} security vendors flag this domain")
    
    # === HACKLINK / SEO SPAM ===
    if res.hacklink_detected:
        kw = res.hacklink_keywords.replace(";", ", ")[:80] if res.hacklink_keywords else "various"
        all_issues.append(f"🕷️ HACKLINK SEO SPAM DETECTED (keywords: {kw}) → Domain compromised with injected gambling/spam content")
    elif res.hacklink_keywords:
        kw = res.hacklink_keywords.replace(";", ", ")[:80]
        all_issues.append(f"HACKLINK KEYWORDS FOUND ({kw}) → Some hacklink-associated keywords present in page content")
    
    if res.hacklink_wp_compromised:
        all_issues.append("WORDPRESS COMPROMISED → WordPress files show signs of code injection/backdoor")
    
    if res.hacklink_vulnerable_plugins:
        plugins = res.hacklink_vulnerable_plugins.replace(";", ", ")[:80]
        # Check if there's actual compromise evidence alongside the vuln plugins
        has_compromise_evidence = (
            res.hacklink_keywords or res.hacklink_hidden_injection_confidence == "HIGH"
            or res.hacklink_wp_compromised or res.hacklink_spam_link_count >= 5
            or (res.hacklink_malicious_script and res.hacklink_malicious_script_confidence in ("HIGH", "MEDIUM"))
        )
        if has_compromise_evidence:
            all_issues.append(f"VULNERABLE WP PLUGINS ({plugins}) → Known exploitable plugins detected")
        else:
            all_issues.append(f"VULNERABLE WP PLUGINS ({plugins}) → Known exploitable plugins detected (⬇ no active compromise evidence — popular plugin on established site)")
    
    if res.hacklink_spam_link_count >= 5:
        all_issues.append(f"SPAM LINKS ({res.hacklink_spam_link_count} hidden links) → Hidden outbound spam links injected into page")
    
    # === MALICIOUS SCRIPT / HIDDEN INJECTION (HIGH-VALUE SIGNALS) ===
    # v7.5.1: Suppress on parking pages when all external scripts are from known
    # parking providers (CookieYes, HugeDomains, Google analytics).
    _suppress_ms_issue = False
    if res.hacklink_malicious_script and res.is_parking_page:
        _ext = [d.strip().lower() for d in
                (res.content_external_script_domains or "").split(";") if d.strip()]
        if _ext:
            _suppress_ms_issue = not any(d not in KNOWN_PARKING_SCRIPT_DOMAINS for d in _ext)
        else:
            _ms_sigs = set((res.hacklink_malicious_script_signals or "").split(";"))
            _suppress_ms_issue = _ms_sigs.issubset(
                {"UNKNOWN_EXTERNAL_SCRIPT", "HIGH_ENTROPY_PATH", "JQUERY_MASQUERADE", ""})
    
    if res.hacklink_malicious_script and not _suppress_ms_issue:
        conf = res.hacklink_malicious_script_confidence
        signals = res.hacklink_malicious_script_signals.replace(";", ", ")[:100] if res.hacklink_malicious_script_signals else "unknown"
        if conf == "HIGH":
            all_issues.append(f"🚨 MALICIOUS SCRIPT INJECTION (HIGH confidence) → SocGholish/FakeUpdates-style obfuscated script detected; signals: {signals}")
        else:
            all_issues.append(f"⚠️ SUSPICIOUS SCRIPT DETECTED (MEDIUM confidence) → Potentially malicious script patterns found; signals: {signals}")
    
    if res.hacklink_hidden_injection:
        if res.hacklink_hidden_injection_confidence == "HIGH":
            all_issues.append("🚨 HIDDEN CONTENT INJECTION → CSS-cloaked content (display:none, font-size:0) with embedded links; classic hacklink/SEO spam technique")
        elif res.hacklink_hidden_injection_confidence == "LOW":
            all_issues.append("CSS HIDING PATTERNS → CSS hiding techniques found (no hidden links detected — common in legitimate templates/dev sites)")
    
    if res.hacklink_is_cpanel:
        all_issues.append("CPANEL HOSTING → cPanel shared hosting detected; frequently targeted in hacklink campaigns")
    
    if res.hacklink_suspicious_scripts:
        scripts = res.hacklink_suspicious_scripts.replace(";", ", ")[:120]
        all_issues.append(f"SUSPICIOUS EXTERNAL SCRIPTS ({scripts}) → Third-party scripts from known-bad or suspicious domains")
    
    # v7.5.1: Hacklink campaign profile
    if res.hacklink_campaign_profile:
        _hcp_sigs = res.hacklink_campaign_profile_signals.replace(";", ", ")
        all_issues.append(
            f"🕸️ HACKLINK CAMPAIGN PROFILE ({res.hacklink_campaign_profile_confidence}) → "
            f"Domain matches hacklink target infrastructure fingerprint ({_hcp_sigs}); "
            f"injected content may be cloaked or cleaned up"
        )
    
    # === CONTENT IDENTITY VERIFICATION ===
    if res.content_is_facade:
        wc = res.content_visible_word_count
        all_issues.append(f"CONTENT FACADE → Page title present but only {wc} visible words; content loaded entirely via external JS (SPA shell)")
    if res.content_title_body_mismatch:
        all_issues.append(f"CONTENT TITLE/BODY MISMATCH → {res.content_title_body_detail[:120]}")
    if res.content_cross_domain_emails:
        domains = res.content_cross_domain_email_domains.replace(";", ", ")
        all_issues.append(f"CROSS-DOMAIN EMAILS ON PAGE → Page contains emails from: {domains}")
    if res.content_is_broker_page:
        all_issues.append(f"BROKER/PARKING PAGE → Domain broker or for-sale page detected: {res.content_broker_indicators[:100]}")
    if res.content_page_privacy_emails:
        all_issues.append(f"PRIVACY EMAIL ON PAGE → {res.content_page_privacy_emails.replace(';', ', ')}")
    if res.content_is_placeholder:
        all_issues.append("PLACEHOLDER CONTENT → Page contains template/placeholder text (lorem ipsum, coming soon)")
    if res.registration_opaque:
        all_issues.append("REGISTRATION OPAQUE → Both RDAP and WHOIS failed to return domain creation date/registrar — registration data hidden or unavailable")
    if res.domain_reregistered:
        _rereg_age = f"{res.domain_reregistered_days}d ago" if res.domain_reregistered_days >= 0 else "unknown date"
        _rereg_dt = res.domain_reregistered_date[:10] if res.domain_reregistered_date else "?"
        all_issues.append(f"DOMAIN RE-REGISTERED ({_rereg_dt}, {_rereg_age}) → Domain was dropped and re-registered — possible expired domain takeover for residual reputation")
    
    # === TRANSFER LOCK / DOMAIN TAKEOVER ===
    if res.domain_transfer_lock_recent:
        days = res.whois_recently_updated_days
        all_issues.append(f"RECENT TRANSFER LOCK → Lock added recently ({days}d ago) on established domain — possible post-compromise lockdown by owner/registrar")
    
    if res.whois_recently_updated:
        days = res.whois_recently_updated_days
        all_issues.append(f"WHOIS RECENTLY UPDATED ({days}d ago) → Possible recent transfer, ownership change, or DNS hijack")
    
    # === MX HIJACK FINGERPRINT (v7.3.1) ===
    if res.mx_provider_mismatch:
        evidence_str = res.mx_ghost_evidence.replace(";", ", ")
        if res.mx_hijack_confidence == "HIGH":
            all_issues.append(f"🚨 MX HIJACK FINGERPRINT ({res.mx_ghost_provider} ghost, HIGH confidence) → {evidence_str}")
        elif res.mx_hijack_confidence == "MEDIUM":
            all_issues.append(f"⚠️ MX PROVIDER MISMATCH ({res.mx_ghost_provider} ghost, MEDIUM) → {evidence_str}")
        else:
            all_issues.append(f"MX PROVIDER MISMATCH ({res.mx_ghost_provider} residual, LOW) → {evidence_str}")
    
    # === EMPTY PAGE ===
    if res.is_empty_page:
        all_issues.append("EMPTY PAGE → Reachable domain returns empty/near-empty content; possibly parked, abandoned, or stripped post-compromise")
    
    # === CERTIFICATE TRANSPARENCY ===
    if res.ct_log_count == 0:
        all_issues.append("NO CT HISTORY → Zero certificates found in CT logs; domain may never have been used for HTTPS")
    elif res.ct_recent_issuance and res.domain_age_days > 365:
        # v7.5.1: Only flag if this isn't a routine renewal (few certs = unusual)
        if res.ct_log_count < 5:
            all_issues.append(f"CT RECENT ISSUANCE ON OLD DOMAIN → New cert issued in last 7d on {res.domain_age_days}d-old domain; possible takeover/reactivation")
    elif res.ct_recent_issuance:
        # v7.5.1: Suppress issue text for routine renewals (5+ certs, established domain)
        _is_routine = res.ct_log_count >= 5 and (res.domain_age_days < 0 or res.domain_age_days >= 180)
        if not _is_routine:
            all_issues.append("CT RECENT CERT ISSUANCE → Certificate issued within last 7 days")
    
    if res.ct_issuers:
        issuers = res.ct_issuers.replace(";", ", ")
        positives.append(f"CT issuers: {issuers}")
    
    # v7.3.1: CT gap — aged domain purchase
    if res.ct_reactivated:
        all_issues.append(f"🚨 CT REACTIVATION ({res.ct_gap_months}mo gap) → {res.ct_gap_evidence}")
    elif res.ct_gap_months >= 12:
        all_issues.append(f"⚠️ CT GAP ({res.ct_gap_months}mo) → {res.ct_gap_evidence}")
    
    # v7.5.1: Cert issued but TLS dead
    if res.ct_cert_tls_dead:
        _issuer = res.ct_last_cert_issuer or "unknown"
        _days = res.ct_days_since_last_cert
        all_issues.append(
            f"🔒 CERT ISSUED BUT TLS DEAD → Certificate issued {_days}d ago by "
            f"{_issuer} but port 443 now {'refuses connections' if res.tls_connection_failed else 'fails handshake'}; "
            f"infrastructure disrupted since cert issuance"
        )
    
    # v7.3.1: Subdomain delegation abuse
    if res.subdomain_infra_divergent:
        evidence_str = res.subdomain_divergence_evidence.replace(";", ", ")
        conf = res.subdomain_divergence_confidence
        if conf == "HIGH":
            all_issues.append(
                f"🚨 SUBDOMAIN DELEGATION ABUSE ({res.parent_domain} → {res.domain}, HIGH confidence) → {evidence_str}"
            )
        elif conf == "MEDIUM":
            all_issues.append(
                f"⚠️ SUBDOMAIN INFRA DIVERGENCE ({res.parent_domain} → {res.domain}, MEDIUM) → {evidence_str}"
            )
        else:
            all_issues.append(
                f"SUBDOMAIN INFRA DIVERGENCE ({res.parent_domain} → {res.domain}, LOW) → {evidence_str}"
            )
    elif res.is_subdomain and res.parent_domain:
        if res.is_staging_subdomain:
            positives.append(f"Subdomain of {res.parent_domain} — SDLC/staging environment (email auth not expected)")
        else:
            positives.append(f"Subdomain of {res.parent_domain} — infrastructure matches parent")
    
    # v7.3.1: OAuth consent phishing
    if res.has_oauth_phish:
        evidence_str = res.oauth_phish_evidence.replace(";", ", ")
        all_issues.append(f"🚨 OAUTH CONSENT PHISH → {evidence_str}")
    
    # v7.3.1: Homoglyph / IDN spoofing
    if res.is_homoglyph_domain:
        decoded = f" (displays as: {res.homoglyph_decoded})" if res.homoglyph_decoded else ""
        all_issues.append(
            f"🚨 HOMOGLYPH DOMAIN → IDN lookalike targeting '{res.homoglyph_target}'{decoded}"
        )
    
    # v7.3.1: Quishing profile
    if res.quishing_profile:
        evidence_str = res.quishing_evidence.replace(";", ", ")
        all_issues.append(f"⚠️ QUISHING PROFILE → QR code phishing landing page: {evidence_str}")
    
    # v7.3.1: CDN tunnel abuse
    if res.cdn_tunnel_suspect:
        evidence_str = res.cdn_tunnel_evidence.replace(";", ", ")
        all_issues.append(f"⚠️ CDN TUNNEL ABUSE ({res.cdn_provider}) → {evidence_str}")
    elif res.is_cdn_hosted:
        positives.append(f"CDN-hosted ({res.cdn_provider}) — origin hidden but no abuse indicators")
    
    # === CONTACT CROSS-REFERENCE (OSINT) ===
    if res.contact_reuse_results:
        try:
            import json as _json
            _cr = _json.loads(res.contact_reuse_results)
            for _m in _cr.get("matches", []):
                _icon = "📧" if _m["type"] == "email" else "📞"
                _contact = _m["contact"]
                _doms = ", ".join(_m["found_on"][:5])
                all_issues.append(f"{_icon} SHARED CONTACT ({_contact}) → also found on: {_doms}")
        except Exception:
            pass
    
    # === EMAIL AUTHENTICATION ===
    if not res.dmarc_exists:
        all_issues.append("NO DMARC → Gmail/Yahoo now REQUIRE DMARC; expect 10-30% lower inbox placement")
    elif res.dmarc_policy == "none":
        all_issues.append("DMARC p=none → Zero spoofing protection; upgrade to p=quarantine or p=reject")
    
    if not res.dkim_exists:
        all_issues.append("NO DKIM → Missing cryptographic signature; 15-25% deliverability penalty")
    
    if not res.spf_exists:
        all_issues.append("NO SPF → Cannot verify authorized senders; emails may be rejected or spam-foldered")
    elif res.spf_mechanism == "~all":
        all_issues.append("SPF ~all (softfail) → Weak enforcement; upgrade to -all for strict rejection")
    elif res.spf_mechanism == "?all":
        all_issues.append("SPF ?all (neutral) → Provides zero protection; upgrade to -all")
    
    if res.dmarc_exists and not res.dmarc_rua:
        all_issues.append("DMARC NO REPORTING → Cannot monitor authentication failures; add rua= tag")
    
    # === INFRASTRUCTURE ===
    if not res.mx_exists:
        all_issues.append("NO MX RECORDS → Cannot receive bounces; some providers reject senders without MX")
    elif res.mx_is_null:
        all_issues.append("NULL MX RECORD → Domain explicitly cannot receive email")
    
    if res.mx_provider_type == "disposable":
        all_issues.append(f"DISPOSABLE MX PROVIDER ({res.mx_primary}) → Cheap/temporary email service commonly used for spam")
    elif res.mx_provider_type == "selfhosted":
        if res.mx_is_mail_prefix:
            all_issues.append(f"SELF-HOSTED MX ({res.mx_primary}) → mail.{{domain}} template pattern; common phishing infrastructure fingerprint")
        else:
            all_issues.append(f"SELF-HOSTED MX ({res.mx_primary}) → MX points to own domain; no external provider oversight")
    
    if not res.ptr_exists:
        all_issues.append("NO PTR RECORD → Corporate/enterprise email filters may reject")
    elif not res.ptr_matches_forward:
        all_issues.append("PTR MISMATCH → Forward/reverse DNS inconsistent; triggers spam filters")
    
    # v4.4: Specific TLS failure messages instead of generic "NO VALID HTTPS"
    if res.tls_handshake_failed:
        all_issues.append(f"TLS HANDSHAKE FAILED ({res.tls_error}) → Server rejects secure connections; broken SSL config or intentional evasion")
    elif res.tls_connection_failed:
        all_issues.append(f"TLS CONNECTION FAILED ({res.tls_error}) → Cannot reach port 443; no HTTPS service running")
    elif not res.https_valid:
        all_issues.append("NO VALID HTTPS → May indicate abandoned or suspicious domain")
    
    if res.is_suspicious_tld:
        all_issues.append("HIGH-ABUSE TLD → This domain extension faces extra spam scrutiny")
    
    if res.is_free_hosting:
        all_issues.append("FREE HOSTING PROVIDER → Associated with spam; limited reputation potential")
    
    if res.hosting_provider and res.hosting_provider_type in ("budget_shared", "free", "suspect", "platform"):
        type_labels = {
            "budget_shared": f"BUDGET SHARED HOST ({res.hosting_provider}) → Commonly used for spam/phishing; shared IP reputation risk",
            "free": f"FREE HOSTING ({res.hosting_provider}) → Associated with throwaway sites and spam campaigns",
            "suspect": f"SUSPECT HOST ({res.hosting_provider}) → Known bulletproof/abuse-tolerant hosting provider",
            "platform": f"DEV PLATFORM HOST ({res.hosting_provider}) → Developer platform with free tier; custom domains used for phishing infrastructure",
        }
        all_issues.append(type_labels.get(res.hosting_provider_type, f"HOSTING: {res.hosting_provider}"))
    
    if res.blocked_asn_org_match:
        all_issues.append(f"BLOCKED ASN ORG ({res.blocked_asn_org_match} / {res.hosting_asn_org}) → Domain hosted on blocked network; ASN {res.hosting_asn}")
    
    # === NAMESERVER RISK ISSUES ===
    if res.ns_is_dynamic_dns:
        all_issues.append(f"DYNAMIC DNS NAMESERVER ({res.ns_dynamic_dns_match}) → Domain delegated to dynamic DNS; almost exclusively phishing/malware infrastructure")
    
    if res.ns_is_parking:
        all_issues.append(f"PARKING NAMESERVER ({res.ns_parking_match}) → Domain parked/unused/for-sale; not a legitimate sender")
    
    if res.ns_is_lame_delegation:
        all_issues.append("LAME DELEGATION (0 NS RECORDS) → Broken or abandoned domain; no functioning DNS")
    
    if res.ns_is_free_dns:
        all_issues.append(f"FREE DNS PROVIDER ({res.ns_free_dns_match}) → Minimal infrastructure investment; unusual for business senders")
    
    if res.ns_is_single_ns:
        all_issues.append("SINGLE NAMESERVER → Only 1 NS record; fragile or hastily configured domain")
    
    if res.is_free_email_domain:
        all_issues.append("FREE EMAIL PROVIDER DOMAIN → Cannot send bulk from consumer email domains")
    
    # === WEB/REDIRECT ISSUES ===
    if res.redirect_count >= 2:
        all_issues.append(f"REDIRECT CHAIN ({res.redirect_count} hops) → May trigger phishing detection")
    
    if res.redirect_cross_domain:
        all_issues.append("CROSS-DOMAIN REDIRECT → Suspicious pattern common in phishing")
    
    if res.redirect_uses_temp:
        all_issues.append("TEMP REDIRECTS (302/307) → Suggests URL cloaking; triggers filters")
    
    # Check for strong email auth (used to annotate mitigated issues)
    _strong_email = (
        res.spf_exists and res.spf_mechanism == "-all"
        and res.dmarc_exists and res.dmarc_policy in ("reject", "quarantine")
    )

    if res.is_minimal_shell:
        if _strong_email:
            all_issues.append("MINIMAL/SHELL WEBSITE → Common phishing indicator (⬇ mitigated: strong email auth)")
        else:
            all_issues.append("MINIMAL/SHELL WEBSITE → Common phishing indicator")
    
    if res.has_js_redirect:
        if _strong_email:
            all_issues.append("JAVASCRIPT REDIRECT → Suspicious redirect technique (⬇ mitigated: strong email auth)")
        else:
            all_issues.append("JAVASCRIPT REDIRECT → Suspicious redirect technique")
    
    if res.has_meta_refresh:
        all_issues.append("META REFRESH REDIRECT → Often used for cloaking")
    
    if res.has_external_js:
        all_issues.append("EXTERNAL JS LOADER → Content loaded from external source")
    
    if res.has_suspicious_iframe:
        all_issues.append("HIDDEN IFRAME → Often used to load malicious content")
    
    if res.is_parking_page:
        all_issues.append("PARKING PAGE → Domain not actively used")
    
    if res.form_posts_external:
        all_issues.append("FORM POSTS EXTERNALLY → Credentials sent to different domain")
    
    if res.has_sensitive_fields:
        all_issues.append("SENSITIVE FORM FIELDS → Requests SSN/card numbers")
    
    # === STATUS CODE SIGNALS (infrastructure intent) ===
    if res.has_401:
        all_issues.append("401 UNAUTHORIZED → Public domain requires authentication - unusual")
    
    # 403 intentionally omitted — Cloudflare/WAF bot protection causes too many FPs
    # status_403_cloaking weight is already 0 in config.py

    if res.has_429:
        all_issues.append("429 RATE LIMITED → Throttling automated checks")
    
    if res.has_503:
        all_issues.append("503 UNAVAILABLE → Disposable/intermittent infrastructure")
    
    # === ACCESS RESTRICTION / TRUST SIGNALS (supplier fraud detection) ===
    if res.is_opaque_entity:
        all_issues.append("OPAQUE ENTITY → Access blocked AND no corporate pages found - high B2B fraud risk")
    elif res.is_access_restricted:
        all_issues.append(f"ACCESS RESTRICTED → {res.access_restriction_note}")
    
    if res.missing_trust_signals and not res.is_opaque_entity:
        all_issues.append("NO CORPORATE FOOTPRINT → Missing /about, /contact, /privacy pages")
    
    if res.has_credential_form and not res.brands_detected:
        all_issues.append("CREDENTIAL FORM DETECTED → Login form on landing page")
    
    # === HIJACKED DOMAIN / STEPPING STONE INDICATORS ===
    if res.redirects_to_phishing_infra:
        all_issues.append(f"REDIRECTS TO PHISHING INFRASTRUCTURE ({res.phishing_infra_domain}) → Known malicious hosting")
    
    if res.has_doc_sharing_lure:
        all_issues.append(f"DOCUMENT SHARING LURE → '{res.doc_lure_found}' - Common phishing tactic")
    
    if res.has_phishing_js_behavior:
        all_issues.append(f"PHISHING KIT JS PATTERNS → Suspicious JavaScript: {res.phishing_js_patterns}")
    
    if res.has_email_in_url:
        all_issues.append(f"EMAIL TRACKING IN URL → {res.url_email_tracking} - Victim tracking technique")
    
    if res.has_hijack_path_pattern:
        all_issues.append(f"SUSPICIOUS URL PATH '/{res.hijack_path_found}/' → Common hijacked domain pattern")
    
    # === CUSTOM RULE LABELS ===
    if res.rules_labels:
        for label in res.rules_labels.split(';'):
            if label.strip():
                all_issues.append(f"RULE: {label.strip()}")
    
    # === POSITIVE SIGNALS ===
    if res.spf_exists and res.spf_mechanism == "-all":
        positives.append("Strict SPF (-all)")
    
    if res.dmarc_exists and res.dmarc_policy == "reject":
        positives.append("DMARC p=reject")
    elif res.dmarc_exists and res.dmarc_policy == "quarantine":
        positives.append("DMARC p=quarantine")
    
    if res.dkim_exists:
        positives.append("DKIM configured")
    
    if rdap_enabled and res.domain_age_days >= 365:
        years = res.domain_age_days // 365
        positives.append(f"Established ({years}+ years)")
    
    if res.https_valid:
        positives.append("Valid HTTPS")
    
    if res.content_spa_framework_detected and res.content_spa_framework_name:
        positives.append(f"SPA framework detected ({res.content_spa_framework_name}) — facade suppressed")
    
    if res.bimi_exists:
        positives.append("BIMI verified")
    
    if res.mta_sts_exists:
        positives.append("MTA-STS enabled")
    
    # v7.5.1: Security tooling positive
    if res.content_security_signals:
        _sec_names = {
            "recaptcha": "reCAPTCHA",
            "cloudflare_bot_management": "Cloudflare Bot Management",
            "hcaptcha": "hCaptcha",
            "akamai_bot_manager": "Akamai Bot Manager",
            "datadome": "DataDome",
            "perimeterx": "PerimeterX/HUMAN",
        }
        _sec_display = [_sec_names.get(s.strip(), s.strip())
                        for s in res.content_security_signals.split(";") if s.strip()]
        if _sec_display:
            positives.append(f"Security: {', '.join(_sec_display)}")
    
    if res.app_store_has_presence:
        is_platform_fp = res.hosting_provider_type == "platform"
        if res.app_store_confidence == "high":
            if is_platform_fp:
                # Don't show as positive — it's the platform's AASA, not the domain's
                pass
            else:
                methods = []
                if res.app_store_ios_verified:
                    methods.append("iOS deep links")
                if res.app_store_android_verified:
                    methods.append("Android deep links")
                if res.app_store_page_links:
                    methods.append("store links")
                if res.app_store_itunes_match:
                    methods.append("iTunes match")
                positives.append(f"App Store verified ({', '.join(methods)})")
        elif res.app_store_confidence == "medium":
            if not is_platform_fp:
                positives.append("App Store presence detected")
    elif res.app_store_confidence == "low":
        positives.append("Possible app store presence")
    
    if res.mx_exists and not res.mx_is_null:
        if res.mx_provider_type == "enterprise":
            if res.content_is_facade:
                # v7.5.1: Check if facade has SPA trust signals
                _spa_t = 0
                if res.mx_provider_type == "enterprise": _spa_t += 2
                if res.app_store_has_presence and res.app_store_confidence in ("high", "medium"): _spa_t += 2
                if res.spf_exists and res.spf_mechanism == "-all": _spa_t += 1
                if res.dkim_exists or bool(res.dkim_selectors_found): _spa_t += 1
                if res.vt_malicious_count == 0 and res.vt_total_vendors >= 50: _spa_t += 1
                if res.domain_age_days >= 180: _spa_t += 1
                positives.append(
                    "Enterprise MX (Google/Microsoft/Proofpoint)" if _spa_t >= 4
                    else "Enterprise MX (suppressed — content facade)"
                )
            else:
                positives.append("Enterprise MX (Google/Microsoft/Proofpoint)")
        else:
            positives.append("MX configured")
    
    if res.ptr_exists and res.ptr_matches_forward:
        positives.append("PTR matches")
    
    if res.trust_pages_found and len(res.trust_pages_found.split(';')) >= 2:
        positives.append(f"Corporate pages found ({len(res.trust_pages_found.split(';'))})")
    
    # === BUILD SUMMARY ===
    # Score each issue by its config weight for filtering and sorting.
    # Issues whose corresponding signal has weight=0 (disabled) are excluded.
    # Remaining issues sort highest-weight-first so the top 3 are the most critical.
    
    def _issue_weight(text):
        """Map issue text to its config weight for sorting/filtering."""
        # Ordered by severity — first match wins
        # All weights.get() names MUST match config keys exactly
        _map = [
            ('HIGH-RISK PHISHING INFRA', 100),
            ('MALICIOUS SCRIPT INJECTION (HIGH', weights.get('malicious_script', 100)),
            ('SUSPICIOUS SCRIPT DETECTED (MEDIUM', weights.get('malicious_script_medium', 25)),
            ('VT MALICIOUS', weights.get('vt_malicious_high', 65)),
            ('HIDDEN CONTENT INJECTION', weights.get('hidden_injection', 55)),
            ('CSS HIDING PATTERNS', weights.get('hidden_injection_css_only', 5)),
            ('BLACKLISTED DOMAIN', weights.get('domain_blacklisted', 50)),
            ('HACKLINK SEO SPAM DETECTED', weights.get('hacklink_detected', 50)),
            ('HACKLINK CAMPAIGN PROFILE', weights.get('hacklink_campaign_profile_strong', 40)),
            ('WORDPRESS COMPROMISED', weights.get('hacklink_wp_compromised', 45)),
            ('BLACKLISTED IP', weights.get('ip_blacklisted', 40)),
            ('SPF +all', weights.get('spf_pass_all', 40)),
            ('DOMAIN CREATED TODAY + RISK', weights.get('new_domain_with_risk', 40)),
            ('SPAM LINKS', weights.get('hacklink_spam_links', 35)),
            ('DISPOSABLE EMAIL', weights.get('disposable_email', 30)),
            ('TYPOSQUAT', weights.get('typosquat_detected', 25)),
            ('BRAND + SPOOFING', weights.get('brand_spoofing_keyword', 20)),
            ('DOMAIN IMPERSONATES', weights.get('domain_brand_impersonation', 25)),
            ('MALWARE LINKS', weights.get('malware_links', 25)),
            ('EXFIL DROP SCRIPT', weights.get('exfil_drop_script', 30)),
            ('PHISHING KIT DETECTED', weights.get('phishing_kit_detected', 15)),
            ('PHISHING KIT FILENAME', weights.get('phishing_kit_filename_strong', 22)),
            ('FORM ACTION → KIT', weights.get('form_action_kit_strong', 25)),
            ('SUSPICIOUS TITLE', weights.get('suspicious_page_title', 5)),
            ('HARVEST COMBO', weights.get('client_side_harvest_combo', 25)),
            ('CREDENTIAL FORM + BRAND', weights.get('credential_form', 10)),
            ('VULNERABLE WP PLUGINS', weights.get('hacklink_vulnerable_plugins', 25)),
            ('YOUNG DOMAIN + RISK', weights.get('young_domain_with_risk_7d', 25)),
            ('REDIRECTS TO PHISHING', weights.get('phishing_infra_redirect', 25)),
            ('VT FLAGGED', weights.get('vt_malicious_medium', 40)),
            ('BLOCKED ASN', weights.get('blocked_asn_org_score', 20)),
            ('OPAQUE ENTITY', weights.get('opaque_entity', 20)),
            ('TLD VARIANT SPOOF', weights.get('tld_variant_spoofing', 30)),
            ('EMPTY PAGE', weights.get('empty_page', 20)),
            ('ZERO EMAIL AUTH', 20),
            ('HACKLINK KEYWORDS', weights.get('hacklink_keywords', 15)),
            ('SUSPICIOUS PREFIX', weights.get('suspicious_prefix', 15)),
            ('SUSPICIOUS SUFFIX', weights.get('suspicious_suffix', 15)),
            ('VT SUSPICIOUS', weights.get('vt_suspicious', 15)),
            ('FREE EMAIL PROVIDER', weights.get('free_email_domain', 15)),
            ('DOCUMENT SHARING LURE', weights.get('doc_sharing_lure', 15)),
            ('PHISHING KIT JS', weights.get('phishing_js_behavior', 18)),
            ('TRANSFER LOCK', weights.get('transfer_lock_recent', 15)),
            ('MX HIJACK FINGERPRINT', weights.get('mx_hijack_high', 30)),
            ('MX PROVIDER MISMATCH', weights.get('mx_hijack_medium', 15)),
            ('CT RECENT ISSUANCE ON OLD', weights.get('ct_recent_issuance', 8)),
            ('CT REACTIVATION', weights.get('ct_reactivated', 25)),
            ('CT GAP', weights.get('ct_gap_large', 10)),
            ('NO CT HISTORY', weights.get('ct_no_history', 12)),
            ('SUBDOMAIN DELEGATION ABUSE', weights.get('subdomain_delegation_high', 25)),
            ('SUBDOMAIN INFRA DIVERGENCE', weights.get('subdomain_delegation_medium', 12)),
            ('OAUTH CONSENT PHISH', weights.get('oauth_phish', 20)),
            ('HOMOGLYPH DOMAIN', weights.get('homoglyph_domain', 30)),
            ('QUISHING PROFILE', weights.get('quishing_profile', 15)),
            ('CDN TUNNEL ABUSE', weights.get('cdn_tunnel_suspect', 15)),
            ('SENSITIVE FORM', weights.get('sensitive_fields', 12)),
            ('TECH SUPPORT SCAM TLD', weights.get('tech_support_tld', 12)),
            ('DISPOSABLE MX', weights.get('mx_disposable', 10)),
            ('HIJACK', weights.get('hijack_path_pattern', 12)),
            ('RETAIL SCAM TLD', weights.get('retail_scam_tld', 10)),
            ('CROSS-DOMAIN BRAND', weights.get('cross_domain_brand_link', 12)),
            ('NO DMARC', weights.get('no_dmarc', 10)),
            ('WHOIS RECENTLY UPDATED', weights.get('whois_recently_updated', 10)),
            ('ACCESS RESTRICTED', weights.get('access_restricted', 10)),
            ('FREE HOSTING', weights.get('hosting_free', 10)),
            ('PARKING PAGE', weights.get('parking_page', 10)),
            ('CREDENTIAL FORM DETECTED', weights.get('credential_form', 10)),
            ('E-COMMERCE WITHOUT', weights.get('ecommerce_no_identity', 15)),
            ('EMAIL TRACKING', weights.get('email_tracking_url', 10)),
            ('TLS HANDSHAKE FAILED', weights.get('tls_handshake_failed', 10)),
            ('TLS CONNECTION FAILED', weights.get('tls_connection_failed', 10)),
            ('BRAND IMPERSONATION', weights.get('brand_impersonation', 15)),
            ('DOMAIN', weights.get('young_domain_with_risk_90d', 4)),  # domain age 30-90d fallback
            ('NO SPF', weights.get('no_spf', 8)),
            ('SELF-HOSTED MX', weights.get('mx_selfhosted', 8)),
            ('CROSS-DOMAIN REDIRECT', weights.get('redirect_cross_domain', 8)),
            ('MINIMAL/SHELL', weights.get('minimal_shell', 8)),
            ('JAVASCRIPT REDIRECT', weights.get('js_redirect', 8)),
            ('HIDDEN IFRAME', weights.get('suspicious_iframe', 8)),
            ('NO MX', weights.get('no_mx', 8)),
            ('CPANEL HOSTING', weights.get('cpanel_detected', 8)),
            ('BUDGET SHARED HOST', weights.get('hosting_budget_shared', 8)),
            ('SUSPECT HOST', weights.get('hosting_suspect', 8)),
            ('DEV PLATFORM HOST', weights.get('hosting_platform', 4)),
            ('DYNAMIC DNS NAMESERVER', weights.get('ns_dynamic_dns', 25)),
            ('PARKING NAMESERVER', weights.get('ns_parking', 15)),
            ('LAME DELEGATION', weights.get('ns_lame_delegation', 20)),
            ('FREE DNS PROVIDER', weights.get('ns_free_dns', 8)),
            ('SINGLE NAMESERVER', weights.get('ns_single_ns', 5)),
            ('NO VALID HTTPS', weights.get('no_https', 25)),
            ('HIGH-ABUSE TLD', weights.get('suspicious_tld', 6)),
            ('NO DKIM', weights.get('no_dkim', 6)),
            ('REDIRECT CHAIN', weights.get('redirect_chain_2plus', 5)),
            ('DMARC p=none', weights.get('dmarc_p_none', 5)),
            ('SPF ?all', weights.get('spf_neutral_all', 5)),
            ('TEMP REDIRECTS', weights.get('redirect_temp_302_307', 5)),
            ('META REFRESH', weights.get('meta_refresh', 5)),
            ('EXTERNAL JS LOADER', weights.get('external_js_loader', 5)),
            ('PTR MISMATCH', weights.get('ptr_mismatch', 5)),
            ('BLACKLIST CHECK INCONCLUSIVE', weights.get('blacklist_inconclusive', 5)),
            ('401 UNAUTHORIZED', weights.get('status_401_unauthorized', 5)),
            ('403 FORBIDDEN', weights.get('status_403_cloaking', 5)),
            ('429 RATE LIMITED', weights.get('status_429_throttling', 5)),
            ('503 UNAVAILABLE', weights.get('status_503_disposable', 5)),
            ('NO PTR', weights.get('no_ptr', 3)),
            ('SPF ~all', weights.get('spf_softfail_all', 2)),
            ('DMARC NO REPORTING', weights.get('dmarc_no_rua', 2)),
            ('NO CORPORATE FOOTPRINT', weights.get('missing_trust_signals', 8)),
            ('SUSPICIOUS EXTERNAL SCRIPTS', 0),  # Not a scored signal — informational only
            ('VT THREAT NAMES', 0),  # Informational detail, not a risk signal
            ('CT RECENT CERT ISSUANCE', weights.get('ct_recent_issuance', 3)),  # Minor standalone
            ('CONTENT FACADE', weights.get('content_facade', 25)),
            ('CONTENT TITLE/BODY MISMATCH', weights.get('content_title_mismatch', 25)),
            ('CROSS-DOMAIN EMAILS ON PAGE', weights.get('content_cross_domain_email', 35)),
            ('BROKER/PARKING PAGE', weights.get('content_broker_page', 20)),
            ('PRIVACY EMAIL ON PAGE', weights.get('content_privacy_email', 12)),
            ('PLACEHOLDER CONTENT', weights.get('content_placeholder', 10)),
            ('REGISTRATION OPAQUE', weights.get('registration_opaque', 15)),
            ('DOMAIN RE-REGISTERED', weights.get('domain_reregistered_recent', 10)),
        ]
        for prefix, w in _map:
            if prefix in text:
                return w
        return 5  # Default for RULE: labels and unmapped issues
    
    # Score, filter zeros, sort by weight descending
    scored_issues = [((_issue_weight(t), t)) for t in all_issues]
    
    # Look up ACTUAL scored points from the breakdown for each issue
    breakdown = {}
    if res.score_breakdown:
        try:
            breakdown = json.loads(res.score_breakdown)
        except (json.JSONDecodeError, TypeError):
            pass
    
    # Map issue text prefix → breakdown signal key(s)
    _ISSUE_TO_SIGNAL = [
        ('🚨 HIGH-RISK PHISHING INFRA', ['high_risk_phish_infra']),
        ('SPF +all', ['spf_pass_all']),
        ('ZERO EMAIL AUTH', ['no_spf', 'no_dkim', 'no_dmarc']),
        ('DISPOSABLE EMAIL', ['disposable_email']),
        ('TYPOSQUAT', ['typosquat_detected']),
        ('BRAND + SPOOFING KEYWORD', ['brand_spoofing_keyword']),
        ('DOMAIN IMPERSONATES', ['domain_brand_impersonation']),
        ('TLD VARIANT SPOOF', ['tld_variant_spoofing']),
        ('SUSPICIOUS PREFIX', ['suspicious_prefix']),
        ('SUSPICIOUS SUFFIX', ['suspicious_suffix']),
        ('TECH SUPPORT SCAM TLD', ['tech_support_tld']),
        ('RETAIL SCAM TLD', ['retail_scam_tld']),
        ('CROSS-DOMAIN BRAND', ['cross_domain_brand_link']),
        ('E-COMMERCE WITHOUT', ['ecommerce_no_identity']),
        ('NO VALID HTTPS', ['no_https']),
        ('NO HTTPS', ['no_https']),
        ('TLS HANDSHAKE FAILED', ['tls_handshake_failed']),
        ('TLS CONNECTION FAILED', ['tls_connection_failed']),
        ('REDIRECT CHAIN', ['redirect_chain_2plus']),
        ('CROSS-DOMAIN REDIRECT', ['redirect_cross_domain']),
        ('TEMP REDIRECTS', ['redirect_temp']),
        ('MINIMAL/SHELL', ['minimal_shell', 'minimal_shell_email_auth_mitigated']),
        ('JAVASCRIPT REDIRECT', ['js_redirect', 'js_redirect_email_auth_mitigated']),
        ('META REFRESH', ['meta_refresh']),
        ('EXTERNAL JS LOADER', ['external_js']),
        ('HIDDEN IFRAME', ['suspicious_iframe']),
        ('PARKING PAGE', ['parking_page']),
        ('FORM POSTS EXTERNALLY', ['form_posts_external']),
        ('SENSITIVE FORM', ['sensitive_fields']),
        ('CREDENTIAL FORM', ['credential_form']),
        ('PHISHING KIT FILENAME', ['phishing_kit_filename_strong', 'phishing_kit_filename_weak']),
        ('PHISHING KIT DETECTED', ['phishing_kit_detected']),
        ('EXFIL DROP SCRIPT', ['exfil_drop_script']),
        ('FORM ACTION KIT', ['form_action_kit_strong', 'form_action_kit_weak']),
        ('SUSPICIOUS TITLE', ['suspicious_page_title']),
        ('HARVEST COMBO', ['client_side_harvest_combo']),
        ('WHOIS PRIVACY', ['whois_privacy']),
        ('401 UNAUTHORIZED', ['access_restricted']),
        ('403 FORBIDDEN', ['access_restricted']),
        ('429 RATE LIMITED', ['status_429_throttling']),
        ('503 UNAVAILABLE', ['status_503_disposable']),
        ('OPAQUE ENTITY', ['opaque_entity']),
        ('ACCESS RESTRICTED', ['access_restricted']),
        ('NO CORPORATE FOOTPRINT', ['missing_trust_signals']),
        ('BRAND IMPERSONATION', ['brand_impersonation']),
        ('REDIRECTS TO PHISHING', ['phishing_infra_redirect']),
        ('DOCUMENT SHARING LURE', ['doc_lure']),
        ('PHISHING KIT JS', ['phishing_js']),
        ('EMAIL TRACKING', ['email_in_url']),
        ('SUSPICIOUS URL PATH', ['hijack_path_pattern']),
        ('DOMAIN CREATED TODAY + RISK', ['new_domain_with_risk']),
        ('DOMAIN CREATED TODAY', ['new_domain_with_risk']),
        ('DOMAIN ONLY', ['new_domain_with_risk']),
        ('BLACKLISTED DOMAIN', ['domain_blacklisted']),
        ('BLACKLISTED IP', ['ip_blacklisted']),
        ('BLACKLIST CHECK INCONCLUSIVE', ['blacklist_inconclusive']),
        ('VT MALICIOUS', ['vt_malicious', 'vt_malicious_medium']),
        ('VT SUSPICIOUS', ['vt_suspicious']),
        ('NO SPF', ['no_spf']),
        ('NO DKIM', ['no_dkim']),
        ('NO MX', ['no_mx']),
        ('NO DMARC', ['no_dmarc']),
        ('DMARC p=none', ['dmarc_p_none']),
        ('DMARC NO REPORTING', ['dmarc_no_rua']),
        ('SPF ~all', ['spf_softfail_all']),
        ('SPF ?all', ['spf_neutral_all']),
        ('NULL MX', ['null_mx']),
        ('SELF-HOSTED MX', ['mx_selfhosted']),
        ('DISPOSABLE MX', ['mx_disposable']),
        ('FREE EMAIL PROVIDER', ['free_email_domain']),
        ('HIGH-ABUSE TLD', ['suspicious_tld']),
        ('FREE HOSTING', ['hosting_free']),
        ('BUDGET SHARED HOST', ['hosting_budget_shared']),
        ('SUSPECT HOST', ['hosting_suspect']),
        ('DEV PLATFORM HOST', ['hosting_platform']),
        ('DYNAMIC DNS NAMESERVER', ['ns_dynamic_dns']),
        ('PARKING NAMESERVER', ['ns_parking']),
        ('LAME DELEGATION', ['ns_lame_delegation']),
        ('FREE DNS PROVIDER', ['ns_free_dns']),
        ('SINGLE NAMESERVER', ['ns_single_ns']),
        ('CPANEL HOSTING', ['cpanel_detected']),
        ('BLOCKED ASN', ['blocked_asn']),
        ('TRANSFER LOCK', ['transfer_lock_recent', 'transfer_lock_with_risk']),
        ('MX HIJACK FINGERPRINT', ['mx_hijack_high']),
        ('MX PROVIDER MISMATCH', ['mx_hijack_high', 'mx_hijack_medium', 'mx_hijack_low']),
        ('WHOIS RECENTLY UPDATED', ['whois_recently_updated', 'whois_updated_with_risk']),
        ('NO PTR', ['no_ptr']),
        ('PTR MISMATCH', ['ptr_mismatch']),
        ('CT RECENT ISSUANCE ON OLD', ['ct_recent_issuance']),
        ('CT RECENT CERT ISSUANCE', ['ct_recent_issuance']),
        ('CT REACTIVATION', ['ct_reactivated']),
        ('CT GAP', ['ct_gap_large']),
        ('NO CT HISTORY', ['ct_no_history']),
        ('SUBDOMAIN DELEGATION ABUSE', ['subdomain_delegation_high']),
        ('SUBDOMAIN INFRA DIVERGENCE', ['subdomain_delegation_high', 'subdomain_delegation_medium', 'subdomain_delegation_low']),
        ('OAUTH CONSENT PHISH', ['oauth_phish']),
        ('HOMOGLYPH DOMAIN', ['homoglyph_domain']),
        ('QUISHING PROFILE', ['quishing_profile']),
        ('CDN TUNNEL ABUSE', ['cdn_tunnel_suspect']),
        ('VULNERABLE WP PLUGINS', ['hacklink_vulnerable_plugins', 'vuln_plugins_no_compromise_mitigated']),
        ('HIDDEN CONTENT INJECTION', ['hidden_injection']),
        ('HACKLINK', ['hacklink_keywords']),
        ('HACKLINK CAMPAIGN PROFILE', ['hacklink_campaign_profile']),
        ('COMPROMISED WP', ['hacklink_wp_compromised']),
        ('SPAM LINKS', ['hacklink_spam_links']),
        ('MALICIOUS SCRIPT', ['malicious_script']),
        ('CSS HIDING PATTERNS', ['hidden_injection']),
        ('CONTENT FACADE', ['content_facade']),
        ('CONTENT TITLE/BODY MISMATCH', ['content_title_mismatch']),
        ('CROSS-DOMAIN EMAILS ON PAGE', ['content_cross_domain_email']),
        ('BROKER/PARKING PAGE', ['content_broker_page']),
        ('PRIVACY EMAIL ON PAGE', ['content_privacy_email']),
        ('PLACEHOLDER CONTENT', ['content_placeholder']),
        ('REGISTRATION OPAQUE', ['registration_opaque']),
        ('DOMAIN RE-REGISTERED', ['domain_reregistered_recent', 'domain_reregistered']),
        # Catch-all for domain age (must be LAST — "DOMAIN" matches broadly)
        ('DOMAIN', ['new_domain_with_risk']),
    ]
    
    def _lookup_pts(text):
        """Look up actual scored points from breakdown for an issue."""
        # Check RULE: issues first
        if text.startswith("RULE:"):
            rule_label = text[5:].strip()
            # Build label→name mapping from res
            if res.rules_triggered and res.rules_labels:
                names = res.rules_triggered.split(';')
                labels = res.rules_labels.split(';')
                for i, lbl in enumerate(labels):
                    if lbl.strip() == rule_label and i < len(names):
                        rule_key = f"rule:{names[i].strip()}"
                        return breakdown.get(rule_key, 0)
            return 0
        # Match by prefix
        for prefix, signal_keys in _ISSUE_TO_SIGNAL:
            if prefix in text:
                total = sum(breakdown.get(k, 0) for k in signal_keys)
                return total
        return 0
    
    # Store ALL issues on the result with actual points
    all_with_pts = []
    for w, t in sorted(scored_issues, key=lambda x: x[0], reverse=True):
        pts = _lookup_pts(t)
        if pts != 0:
            all_with_pts.append(f"[{pts:+d}] {t}")
        else:
            all_with_pts.append(f"[0] {t}")
    res.all_issues_text = ";".join(all_with_pts)
    
    # For summary, re-sort and filter by ACTUAL scored points from the breakdown.
    # Config weights (_issue_weight above) are approximations for initial ordering;
    # actual points reflect suppression, de-escalation, and combo adjustments.
    # This prevents suppressed signals (e.g. a fully de-escalated facade) from
    # appearing as top issues when they contributed 0 points to the score.
    scored_issues_actual = []
    for _w, _t in scored_issues:
        actual = _lookup_pts(_t)
        if actual > 0:
            scored_issues_actual.append((actual, _t))
    scored_issues = sorted(scored_issues_actual, key=lambda x: x[0], reverse=True)
    
    parts = []
    
    # High-risk phishing infra flag (most important — show first)
    if res.high_risk_phish_infra:
        parts.append(f"🚨 HIGH-RISK PHISHING INFRA → {res.high_risk_phish_infra_reason}")
    
    # Autofail override (v7.5) — show immediately after phishing infra flag
    if res.autofail_reason:
        parts.append(f"🚫 AUTOFAIL → {res.autofail_reason}")
    
    # Recommendation with score
    if res.recommendation == "DENY":
        parts.append(f"⛔ DENY (Score: {res.risk_score})")
    else:
        parts.append(f"✅ APPROVE (Score: {res.risk_score})")
    
    # === PATTERN MATCH INDICATORS ===
    # These help specialists instantly recognize known attack patterns.
    if res.pattern_match:
        parts.append("PATTERN: " + res.pattern_match)
    
    # Top issues only (limit to 3 most important by weight)
    if scored_issues:
        top_issues = [text for _, text in scored_issues[:3]]
        parts.append(" • ".join(top_issues))
        remaining = len(scored_issues) - 3
        if remaining > 0:
            parts.append(f"+{remaining} more issues")
    
    # Positive signals (compact)
    if positives:
        parts.append("✓ " + ", ".join(positives))
    
    return " | ".join(parts)


def calculate_mail_only_score(res: DomainApprovalResult, config: dict) -> dict:
    """
    Calculate a DNS-only composite score for mail-only domains.

    Mail-only domains have no A record (no website) but have valid MX records.
    This function evaluates only signals that can be determined from DNS, WHOIS,
    and API lookups — no HTTP/TLS/content checks.

    Runnable checks:
      - SPF, DKIM, DMARC, BIMI, MTA-STS  (already populated on res)
      - MX classification (enterprise provider bonus)
      - WHOIS/RDAP registration age        (already populated on res)
      - VirusTotal domain lookup            (already populated on res)
      - Typosquatting / homoglyph detection (already populated on res)
      - Domain name pattern checks          (already populated on res)
      - CT log checks                       (not applicable — no web cert)
      - DNSBL checks                        (already populated on res)

    Returns a dict with:
      score: int (0-100, lower = safer)
      signals: list of signal names that fired
      breakdown: dict of signal→points
    """
    mail_score = 0
    mail_signals = []
    mail_breakdown = {}
    weights = config.get('weights', DEFAULT_CONFIG['weights'])

    def _add(signal, points):
        nonlocal mail_score
        mail_signals.append(signal)
        if points != 0:
            mail_breakdown[signal] = points
            mail_score += points

    # --- EMAIL AUTHENTICATION (the core of mail-only evaluation) ---

    # SPF
    if not res.spf_exists:
        _add("mail_only_no_spf", 8)
    else:
        if res.spf_too_permissive:
            _add("mail_only_spf_permissive", 10)
        if not res.spf_syntax_valid:
            _add("mail_only_spf_syntax_error", 5)
        if res.spf_has_external_includes:
            _add("mail_only_spf_has_provider", -5)

    # DKIM
    if not res.dkim_exists:
        _add("mail_only_no_dkim", 8)
    else:
        _add("mail_only_dkim_present", -5)

    # DMARC
    if not res.dmarc_exists:
        _add("mail_only_no_dmarc", 8)
    else:
        if res.dmarc_policy == "reject":
            _add("mail_only_dmarc_reject", -10)
        elif res.dmarc_policy == "quarantine":
            _add("mail_only_dmarc_quarantine", -5)
        elif res.dmarc_policy == "none":
            _add("mail_only_dmarc_none", 3)
        if not res.dmarc_syntax_valid:
            _add("mail_only_dmarc_syntax_error", 5)

    # BIMI (advanced email auth — strong legitimacy signal)
    if res.bimi_exists:
        _add("mail_only_has_bimi", -15)

    # MTA-STS (transport security policy)
    if res.mta_sts_exists:
        _add("mail_only_has_mta_sts", -10)

    # --- MX CLASSIFICATION ---
    mx_type = res.mail_only_mx_provider_type or res.mx_provider_type
    if mx_type == "enterprise":
        _add("mail_only_mx_enterprise", -10)
    elif mx_type == "disposable":
        _add("mail_only_mx_disposable", 20)
    elif mx_type == "selfhosted":
        _add("mail_only_mx_selfhosted", 15)
    elif mx_type == "standard":
        _add("mail_only_mx_standard", 0)

    if res.mx_is_mail_prefix:
        _add("mail_only_mx_mail_prefix", 4)

    # --- WHOIS / REGISTRATION AGE ---
    if res.domain_age_days >= 0:
        if res.domain_age_days <= 1:
            _add("mail_only_domain_created_today", 35)
        elif res.domain_age_days <= 7:
            _add("mail_only_domain_lt_7d", 20)
        elif res.domain_age_days <= 30:
            _add("mail_only_domain_lt_30d", 10)
        elif res.domain_age_days <= 90:
            _add("mail_only_domain_lt_90d", 5)
        elif res.domain_age_days >= 365:
            _add("mail_only_domain_established", -8)

    if res.whois_privacy:
        _add("mail_only_whois_privacy", 5)

    if res.domain_reregistered:
        _add("mail_only_domain_reregistered", 10)

    # --- VIRUSTOTAL ---
    if res.vt_available:
        if res.vt_malicious_count >= 5:
            _add("mail_only_vt_malicious_high", 100)
        elif res.vt_malicious_count >= 3:
            _add("mail_only_vt_malicious_medium", 40)
        elif res.vt_malicious_count >= 1:
            _add("mail_only_vt_malicious_low", 20)
        elif res.vt_malicious_count == 0 and res.vt_total_vendors > 0:
            _add("mail_only_vt_clean", -5)

    # --- TYPOSQUATTING / HOMOGLYPH ---
    if res.typosquat_target:
        _add("mail_only_typosquat", 15)
    if res.is_homoglyph_domain:
        _add("mail_only_homoglyph", 20)

    # --- DOMAIN NAME PATTERNS ---
    if res.has_suspicious_prefix:
        _add("mail_only_suspicious_prefix", 10)
    if res.has_suspicious_suffix:
        _add("mail_only_suspicious_suffix", 10)
    if res.brand_plus_keyword_domain:
        _add("mail_only_brand_keyword", 15)
    if res.is_hyphenated_sld:
        _add("mail_only_hyphenated_sld", 5)

    # --- DNSBL ---
    if res.domain_blacklist_count > 0:
        _add("mail_only_domain_blacklisted", 45)

    # --- SUSPICIOUS TLD ---
    if res.is_suspicious_tld:
        _add("mail_only_suspicious_tld", 15)
    if res.is_free_email_domain:
        _add("mail_only_free_email_domain", 15)
    if res.is_disposable_email:
        _add("mail_only_disposable_email", 40)

    # --- NS RISK ---
    if res.ns_is_parking:
        _add("mail_only_ns_parking", 15)
    if res.ns_is_dynamic_dns:
        _add("mail_only_ns_dynamic_dns", 25)
    if res.ns_is_lame_delegation:
        _add("mail_only_ns_lame", 20)

    # --- FULL EMAIL AUTH BONUS ---
    # If domain has SPF + DKIM + DMARC with reject/quarantine = strong legitimacy
    if (res.spf_exists and res.dkim_exists and res.dmarc_exists
            and res.dmarc_policy in ("reject", "quarantine")):
        _add("mail_only_full_email_auth", -10)

    # Clamp score
    mail_score = max(0, min(mail_score, 100))

    return {
        "score": mail_score,
        "signals": mail_signals,
        "breakdown": mail_breakdown,
    }


def calculate_no_resolve_score(res, config: dict) -> dict:
    """
    Calculate a DNS-only composite score for domains with no web presence (v8.2).

    Used for BOTH mail-only domains (no A, has MX) and no-resolve domains
    (no A, no MX). Both lack a website, so they receive the same scrutiny.
    The only difference is which missing-record flags fire:
      - No A record: always fires (both paths)
      - No MX / cannot receive mail: only fires for no-resolve domains

    Runnable checks (all DNS-based, no HTTP needed):
      - WHOIS/RDAP registration age
      - VirusTotal domain lookup
      - Typosquatting / homoglyph detection
      - Domain name pattern checks (suspicious prefix/suffix)
      - DNSBL checks
      - Suspicious TLD checks
      - NS risk detection (parking, dynamic DNS, lame delegation)
      - NS provider quality (enterprise DNS bonus)
      - SOA record freshness (active management signal)
      - DNSSEC enabled (operational maturity signal)
      - CT log presence (historical web presence signal)
      - Free TLD registration cost (zero-investment signal)
      - Domain name entropy (DGA detection)
      - Email auth posture (SPF/DKIM/DMARC)
      - Registration opacity
    """
    nr_score = 0
    nr_signals = []
    nr_breakdown = {}
    weights = config.get('weights', DEFAULT_CONFIG['weights'])

    def _add(signal, points):
        nonlocal nr_score
        nr_signals.append(signal)
        if points != 0:
            nr_breakdown[signal] = points
            nr_score += points

    # --- BASE PENALTY: No A record (no web presence) ---
    _add("no_resolve_no_a_record", weights.get('no_resolve_no_a_record', 25))

    # --- NO MX / CANNOT RECEIVE MAIL (v8.2) ---
    # Only fires for no-resolve domains (no MX). Mail-only domains have MX
    # so this doesn't apply to them.
    if res.cannot_receive_mail:
        _add("no_resolve_cannot_receive_mail", weights.get('no_resolve_cannot_receive_mail', 10))

    # --- WHOIS / REGISTRATION AGE ---
    if res.domain_age_days >= 0:
        if res.domain_age_days <= 1:
            _add("no_resolve_domain_created_today", weights.get('no_resolve_domain_created_today', 35))
        elif res.domain_age_days <= 7:
            _add("no_resolve_domain_lt_7d", weights.get('no_resolve_domain_lt_7d', 20))
        elif res.domain_age_days <= 30:
            _add("no_resolve_domain_lt_30d", weights.get('no_resolve_domain_lt_30d', 10))
        elif res.domain_age_days <= 90:
            _add("no_resolve_domain_lt_90d", weights.get('no_resolve_domain_lt_90d', 5))
        elif res.domain_age_days >= 365:
            _add("no_resolve_domain_established", weights.get('no_resolve_domain_established', -10))

    if res.whois_privacy:
        _add("no_resolve_whois_privacy", weights.get('no_resolve_whois_privacy', 5))

    if res.domain_reregistered:
        _add("no_resolve_domain_reregistered", weights.get('no_resolve_domain_reregistered', 10))

    # --- EMAIL AUTH POSTURE (v8.1.1) ---
    # For normal domains, missing email auth is a deliverability issue (score 0).
    # For no-resolve domains, it's a risk signal: no website + no MX + no email
    # auth = zero operational investment. Legitimate pre-launch domains typically
    # set up SPF/DMARC before going live. Their absence here compounds the risk.
    _no_spf = not res.spf_exists
    _no_dkim = not res.dkim_exists
    _no_dmarc = not res.dmarc_exists

    if _no_spf and _no_dkim and _no_dmarc:
        # Complete email auth vacuum — strongest signal
        _add("no_resolve_no_email_auth", weights.get('no_resolve_no_email_auth', 15))
    else:
        if _no_spf:
            _add("no_resolve_no_spf", weights.get('no_resolve_no_spf', 5))
        if _no_dkim:
            _add("no_resolve_no_dkim", weights.get('no_resolve_no_dkim', 5))
        if _no_dmarc:
            _add("no_resolve_no_dmarc", weights.get('no_resolve_no_dmarc', 5))

    # SPF +all (pass everyone) on a no-resolve domain = likely spoofing setup
    if res.spf_exists and res.spf_mechanism == "+all":
        _add("no_resolve_spf_pass_all", weights.get('no_resolve_spf_pass_all', 10))

    # DMARC p=none on a no-resolve domain = no enforcement intent
    if res.dmarc_exists and res.dmarc_policy == "none":
        _add("no_resolve_dmarc_p_none", weights.get('no_resolve_dmarc_p_none', 5))

    # Bonus: Full email auth stack on a no-resolve domain = strong legitimacy signal
    if res.spf_exists and res.dkim_exists and res.dmarc_exists:
        if res.dmarc_policy in ("reject", "quarantine"):
            _add("no_resolve_full_email_auth", weights.get('no_resolve_full_email_auth', -10))

    # --- REGISTRATION OPAQUE (v8.1.1) ---
    # Both RDAP and WHOIS failed to return any data. On a normal domain this
    # could be GDPR (European ccTLDs). On a no-resolve domain with nothing
    # else to go on, it's an additional opacity signal.
    if res.registration_opaque:
        _add("no_resolve_registration_opaque", weights.get('no_resolve_registration_opaque', 10))

    # --- VIRUSTOTAL ---
    if res.vt_available:
        if res.vt_malicious_count >= 5:
            _add("no_resolve_vt_malicious_high", weights.get('no_resolve_vt_malicious_high', 100))
        elif res.vt_malicious_count >= 3:
            _add("no_resolve_vt_malicious_medium", weights.get('no_resolve_vt_malicious_medium', 40))
        elif res.vt_malicious_count >= 1:
            _add("no_resolve_vt_malicious_low", weights.get('no_resolve_vt_malicious_low', 20))
        elif res.vt_malicious_count == 0 and res.vt_total_vendors > 0:
            _add("no_resolve_vt_clean", weights.get('no_resolve_vt_clean', -5))

    # --- TYPOSQUATTING / HOMOGLYPH ---
    if res.typosquat_target:
        _add("no_resolve_typosquat", weights.get('no_resolve_typosquat', 15))
    if res.is_homoglyph_domain:
        _add("no_resolve_homoglyph", weights.get('no_resolve_homoglyph', 20))

    # --- DOMAIN NAME PATTERNS ---
    if res.has_suspicious_prefix:
        _add("no_resolve_suspicious_prefix", weights.get('no_resolve_suspicious_prefix', 10))
    if res.has_suspicious_suffix:
        _add("no_resolve_suspicious_suffix", weights.get('no_resolve_suspicious_suffix', 10))
    if res.brand_plus_keyword_domain:
        _add("no_resolve_brand_keyword", weights.get('no_resolve_brand_keyword', 15))
    if res.is_hyphenated_sld:
        _add("no_resolve_hyphenated_sld", weights.get('no_resolve_hyphenated_sld', 5))

    # --- DNSBL ---
    if res.domain_blacklist_count > 0:
        _add("no_resolve_domain_blacklisted", weights.get('no_resolve_domain_blacklisted', 45))

    # --- SUSPICIOUS TLD ---
    if res.is_suspicious_tld:
        _add("no_resolve_suspicious_tld", weights.get('no_resolve_suspicious_tld', 15))
    if res.is_free_email_domain:
        _add("no_resolve_free_email_domain", weights.get('no_resolve_free_email_domain', 15))
    if res.is_disposable_email:
        _add("no_resolve_disposable_email", weights.get('no_resolve_disposable_email', 40))

    # --- NS RISK ---
    if res.ns_is_parking:
        _add("no_resolve_ns_parking", weights.get('no_resolve_ns_parking', 15))
    if res.ns_is_dynamic_dns:
        _add("no_resolve_ns_dynamic_dns", weights.get('no_resolve_ns_dynamic_dns', 25))
    if res.ns_is_lame_delegation:
        _add("no_resolve_ns_lame", weights.get('no_resolve_ns_lame', 20))

    # --- NS PROVIDER QUALITY (v8.1) ---
    if res.ns_is_enterprise:
        _add("no_resolve_ns_enterprise", weights.get('no_resolve_ns_enterprise', -8))

    # --- SOA FRESHNESS (v8.1) ---
    if not res.soa_exists:
        _add("no_resolve_soa_missing", weights.get('no_resolve_soa_missing', 5))
    elif res.soa_serial_is_date and res.soa_days_since_serial >= 0:
        if res.soa_days_since_serial <= 90:
            _add("no_resolve_soa_fresh", weights.get('no_resolve_soa_fresh', -5))
        elif res.soa_days_since_serial > 365:
            _add("no_resolve_soa_stale", weights.get('no_resolve_soa_stale', 10))

    # --- DNSSEC (v8.1) ---
    if res.dnssec_enabled:
        _add("no_resolve_dnssec_enabled", weights.get('no_resolve_dnssec_enabled', -5))

    # --- CT LOG PRESENCE (v8.1) ---
    if res.ct_log_count >= 0:
        if res.ct_log_count > 0:
            _add("no_resolve_ct_has_history", weights.get('no_resolve_ct_has_history', -8))
        elif res.ct_log_count == 0:
            _add("no_resolve_ct_no_history", weights.get('no_resolve_ct_no_history', 5))

    # --- FREE TLD (v8.1) ---
    if res.is_free_registration_tld:
        _add("no_resolve_free_tld", weights.get('no_resolve_free_tld', 10))

    # --- DOMAIN NAME ENTROPY (v8.1) ---
    if res.sld_entropy > 4.2:
        _add("no_resolve_very_high_entropy_sld", weights.get('no_resolve_very_high_entropy_sld', 15))
    elif res.sld_entropy > 3.8:
        _add("no_resolve_high_entropy_sld", weights.get('no_resolve_high_entropy_sld', 10))

    # Clamp score
    nr_score = max(0, min(nr_score, 100))

    return {
        "score": nr_score,
        "signals": nr_signals,
        "breakdown": nr_breakdown,
    }


def calculate_score(res: DomainApprovalResult, config: dict) -> None:
    score = 0
    signals: Set[str] = set()
    breakdown: dict = {}  # signal_or_rule → points contributed
    weights = config.get('weights', DEFAULT_CONFIG['weights'])
    threshold = config.get('approve_threshold', 50)
    
    def add(signal: str, points: int):
        """Record a signal, its points, and accumulate score."""
        nonlocal score
        signals.add(signal)
        if points != 0:
            breakdown[signal] = breakdown.get(signal, 0) + points
            score += points
    
    # === NO WEB PRESENCE: UNIFIED DNS-ONLY SCORING PATH (v8.2) ===
    # Both mail-only (no A, has MX) and no-resolve (no A, no MX) domains
    # go through the same scoring function. Neither has a website, so they
    # get identical scrutiny. The only difference is which missing-record
    # indicators fire.
    if res.is_mail_only_domain or res.is_no_resolve_domain:
        nr = calculate_no_resolve_score(res, config)

        # Store in the appropriate result fields
        if res.is_mail_only_domain:
            res.mail_only_dns_score = nr["score"]
            res.mail_only_dns_signals = ";".join(nr["signals"])
            res.mail_only_dns_breakdown = json.dumps(nr["breakdown"])
        if res.is_no_resolve_domain:
            res.no_resolve_dns_score = nr["score"]
            res.no_resolve_dns_signals = ";".join(nr["signals"])
            res.no_resolve_dns_breakdown = json.dumps(nr["breakdown"])

        # Use the unified score as the risk score
        res.risk_score = nr["score"]
        bands = [(0, 19, "LOW"), (20, 39, "MEDIUM"), (40, 64, "HIGH"), (65, 84, "CRITICAL"), (85, 999, "SEVERE")]
        res.risk_level = next((l for lo, hi, l in bands if lo <= res.risk_score <= hi), "UNKNOWN")
        res.recommendation = "APPROVE" if res.risk_score < threshold else "DENY"
        res.signals_triggered = ";".join(sorted(nr["signals"]))
        res.score_breakdown = json.dumps(nr["breakdown"])

        # Build summary — label differs based on which path
        if res.is_no_resolve_domain:
            _label = f"🔇 NO-RESOLVE DOMAIN — no A, no MX (score: {nr['score']})"
        else:
            _mx_type = res.mail_only_mx_provider_type or res.mx_provider_type or ""
            _label = f"📧 MAIL-ONLY DOMAIN — no A, has MX{f' ({_mx_type})' if _mx_type else ''} (score: {nr['score']})"

        _summary_parts = [_label]
        if res.cannot_receive_mail:
            _summary_parts.append("📭 Cannot receive mail")
        if res.domain_age_days >= 0:
            _summary_parts.append(f"Age: {res.domain_age_days}d")
        if res.vt_available:
            if res.vt_malicious_count > 0:
                _summary_parts.append(f"VT: {res.vt_malicious_count} malicious")
            else:
                _summary_parts.append("VT: clean")
        if res.domain_blacklist_count > 0:
            _summary_parts.append(f"DNSBL: {res.domain_blacklist_count} hits")
        if res.ns_is_enterprise:
            _summary_parts.append("NS: enterprise")
        elif res.ns_is_parking:
            _summary_parts.append("NS: parking")
        elif res.ns_is_lame_delegation:
            _summary_parts.append("NS: lame")
        if res.dnssec_enabled:
            _summary_parts.append("DNSSEC")
        if res.ct_log_count > 0:
            _summary_parts.append(f"CT: {res.ct_log_count} certs")
        elif res.ct_log_count == 0:
            _summary_parts.append("CT: none")
        if res.soa_serial_is_date and res.soa_days_since_serial >= 0:
            if res.soa_days_since_serial <= 90:
                _summary_parts.append("SOA: fresh")
            elif res.soa_days_since_serial > 365:
                _summary_parts.append("SOA: stale")
        if res.sld_entropy > 3.8:
            _summary_parts.append(f"Entropy: {res.sld_entropy}")
        # Email auth summary
        if not res.spf_exists and not res.dkim_exists and not res.dmarc_exists:
            _summary_parts.append("Auth: none")
        else:
            _auth_parts = []
            if res.spf_exists: _auth_parts.append("SPF")
            if res.dkim_exists: _auth_parts.append("DKIM")
            if res.dmarc_exists: _auth_parts.append(f"DMARC:{res.dmarc_policy or '?'}")
            _summary_parts.append(f"Auth: {'+'.join(_auth_parts)}")
        if res.registration_opaque:
            _summary_parts.append("WHOIS: opaque")
        res.summary = f"{res.recommendation}: {' | '.join(_summary_parts)}"
        return

    # Email Auth - these are DELIVERABILITY concerns only, NOT fraud signals
    # A domain missing these should get warnings, not denial
    if not res.spf_exists:
        add("no_spf", weights.get('no_spf', 8))
    else:
        if res.spf_mechanism == "+all":
            add("spf_pass_all", weights.get('spf_pass_all', 40))  # This IS a security issue - allows spoofing
        elif res.spf_mechanism == "?all":
            add("spf_neutral_all", weights.get('spf_neutral_all', 5))
        elif res.spf_mechanism == "~all":
            add("spf_softfail_all", weights.get('spf_softfail_all', 2))  # Very minor - this is common and acceptable
    if not res.dkim_exists:
        add("no_dkim", weights.get('no_dkim', 6))
    
    if not res.dmarc_exists:
        add("no_dmarc", weights.get('no_dmarc', 10))
    else:
        if res.dmarc_policy == "none":
            add("dmarc_p_none", weights.get('dmarc_p_none', 5))
        if not res.dmarc_rua:
            add("dmarc_no_rua", weights.get('dmarc_no_rua', 2))
    
    if not res.mx_exists:
        add("no_mx", weights.get('no_mx', 8))
    elif res.mx_is_null:
        add("null_mx", weights.get('null_mx', 12))
    
    # MX provider type scoring (v4.7)
    # NOTE: mx_enterprise bonus is SUPPRESSED when content_facade is detected
    # AND no strong SPA trust signals are present.  If the SPA legitimacy check
    # already de-escalated the facade (trust score >= 3), restore the MX bonus.
    if res.mx_provider_type == "enterprise":
        if not res.content_is_facade:
            add("mx_enterprise", weights.get('mx_enterprise_bonus', -5))
        else:
            # Check if facade was de-escalated by SPA legitimacy check
            if "content_facade" not in signals:
                # Facade fully suppressed → SPA trust signals strong → give MX bonus
                add("mx_enterprise", weights.get('mx_enterprise_bonus', -5))
            # else: facade is still weighted → suppress MX bonus
    elif res.mx_provider_type == "disposable":
        add("mx_disposable", weights.get('mx_disposable', 10))
    elif res.mx_provider_type == "selfhosted":
        add("mx_selfhosted", weights.get('mx_selfhosted', 6))
    
    # mail.{domain} template fingerprint — stronger than generic selfhosted
    # This exact pattern is used by phishing infrastructure toolkits
    if res.mx_is_mail_prefix:
        add("mx_mail_prefix", weights.get('mx_mail_prefix', 4))
    
    # SPF exists but has NO external email provider includes
    # Legit businesses almost always include Google/Microsoft/SendGrid/etc.
    # Self-only SPF (just a/mx mechanisms) = no real email provider
    if res.spf_exists and not res.spf_has_external_includes:
        add("spf_no_external_includes", weights.get('spf_no_external_includes', 3))
    
    if not res.ptr_exists:
        add("no_ptr", weights.get('no_ptr', 4))
    elif not res.ptr_matches_forward:
        add("ptr_mismatch", weights.get('ptr_mismatch', 5))
    
    if res.bimi_exists:
        add("has_bimi", weights.get('has_bimi', -8))
    if res.mta_sts_exists:
        add("has_mta_sts", weights.get('has_mta_sts', -5))
    
    # === SECURITY TOOLING TRUST BONUS (v7.5.1) ===
    # Legitimate sites invest in bot management, CAPTCHA, and security tooling.
    # Phishing kits and spam operations almost never implement these (they cost
    # money, add friction, and block their targets).  Each detected security
    # service is a moderate trust signal; capped at -10 total to prevent gaming.
    if res.content_security_signals:
        _sec_sigs = res.content_security_signals.split(";")
        _sec_bonus = 0
        for _ss in _sec_sigs:
            _ss = _ss.strip().lower()
            if _ss in ("recaptcha", "cloudflare_bot_management", "hcaptcha",
                       "akamai_bot_manager", "datadome", "perimeterx"):
                _sec_bonus += weights.get(f'security_{_ss}', -15)
        # Cap total security bonus at -10
        _sec_bonus = max(_sec_bonus, -10)
        if _sec_bonus < 0:
            add("security_tooling", _sec_bonus)
    
    # === APP STORE PRESENCE BONUS (Legitimacy Signal) ===
    # Tiered by confidence: high (verified deep links) > medium (page links/API) > low (keyword only)
    # IMPORTANT: Platform hosting providers (Render, Netlify, Vercel, etc.) serve their OWN
    # AASA/asset-links files for ALL custom domains. A domain on Render getting "iOS deep links"
    # is detecting Render's app, not the domain owner's app. Suppress the bonus in this case.
    is_platform_hosted = res.hosting_provider_type == "platform"
    if res.app_store_has_presence:
        if res.app_store_confidence == "high":
            if is_platform_hosted:
                # Platform's AASA, not the domain's — don't give bonus
                add("app_store_platform_false_positive", 0)
            else:
                add("app_store_high", weights.get('app_store_high', -15))
        elif res.app_store_confidence == "medium":
            if not is_platform_hosted:
                add("app_store_medium", weights.get('app_store_medium', -10))
        elif res.app_store_confidence == "low":
            # v6.2: Fixed indentation — was incorrectly attached to outer if
            # Suppress when content_facade — an SPA shell shouldn't get app store credit
            # v7.5.1: Unless facade was de-escalated by SPA trust signals
            if not res.content_is_facade or "content_facade" not in signals:
                add("app_store_low", weights.get('app_store_low', -3))
    
    # Blacklists - HIGH weight, these are real fraud signals
    if res.domain_blacklist_count > 0:
        add("domain_blacklisted", weights.get('domain_blacklisted', 40) * min(res.domain_blacklist_count, 3))
    if res.ip_blacklist_count > 0:
        add("ip_blacklisted", weights.get('ip_blacklisted', 35) * min(res.ip_blacklist_count, 3))
    
    # v6.2: Inconclusive blacklist checks — "we don't know" ≠ "clean"
    # Apply a moderate penalty so these don't silently pass
    if res.domain_blacklist_inconclusive > 0:
        add("blacklist_inconclusive", weights.get('blacklist_inconclusive', 15))
    if res.ip_blacklist_inconclusive > 0:
        add("blacklist_inconclusive", weights.get('blacklist_inconclusive', 15))
    
    # Blocked ASN organizations - instant high score
    blocked_asn_orgs = config.get('blocked_asn_orgs', [])
    if res.hosting_asn_org and blocked_asn_orgs:
        asn_org_lower = res.hosting_asn_org.lower()
        matched_asn = next((org for org in blocked_asn_orgs if org.lower() in asn_org_lower), None)
        if matched_asn:
            asn_score = config.get('blocked_asn_org_score', 100)
            add("blocked_asn_org", asn_score)
            res.blocked_asn_org_match = matched_asn  # Store for display
    
    # Domain age — tracked as zero-point signals for rule engine only.
    # Age alone is not a risk — it only matters when combined with actual
    # content/infrastructure risk indicators (NOT email auth, which is weak).
    #
    # EXCEPTION: Day-0/1 domains get a small standalone score regardless of
    # content risk.  A domain registered today has zero track record.  For email
    # sending approval, that is itself a meaningful signal even if the surface
    # looks clean — phishing infrastructure is often stood up hours before use.
    if res.domain_age_days >= 0:
        if res.domain_age_days <= 1:
            res.domain_created_today = True
            add("domain_created_today", weights.get('domain_created_today_standalone', 15))
        elif res.domain_age_days < 7:
            add("domain_lt_7d", 0)
        elif res.domain_age_days < 30:
            add("domain_lt_30d", 0)
        elif res.domain_age_days < 90:
            add("domain_lt_90d", 0)
        # Track established domains (for rule detection)
        if res.domain_age_days >= 365:
            add("domain_gt_1yr", 0)

        # === AGE AMPLIFIER: only score age when real risk signals are present ===
        # Email auth (no_dkim, no_spf, dmarc_none, spf_pass_all) is excluded —
        # it's a weak signal that shouldn't activate age scoring on its own.
        _CONTENT_RISK_SIGNALS = {
            "hacklink_keywords", "hidden_injection", "hacklink_wp_compromised",
            "hacklink_spam_links", "hacklink_vulnerable_plugins", "malicious_script",
            "js_redirect", "minimal_shell", "empty_page", "suspicious_tld",
            "hosting_suspect", "hosting_free", "typosquat_detected",
            "disposable_email", "free_email_domain", "hosting_budget_shared",
            "redirect_cross_domain", "cross_domain_brand_link",
            "tld_variant_spoof", "domain_brand_impersonation",
            "opaque_entity", "sensitive_fields", "phishing_js", "doc_lure",
            "vt_malicious", "vt_malicious_medium", "vt_suspicious",
            "blocked_asn", "cpanel_detected",
            "content_title_mismatch", "content_cross_domain_email",
            "content_broker_page", "content_facade", "registration_opaque",
            "domain_reregistered_recent", "domain_reregistered",
        }
        has_content_risk = bool(signals & _CONTENT_RISK_SIGNALS)

        if has_content_risk:
            if res.domain_age_days <= 1:
                add("new_domain_with_risk", weights.get('new_domain_with_risk', 40))
            elif res.domain_age_days < 7:
                add("new_domain_with_risk", weights.get('young_domain_with_risk_7d', 25))
            elif res.domain_age_days < 30:
                add("new_domain_with_risk", weights.get('young_domain_with_risk_30d', 10))
            elif res.domain_age_days < 90:
                add("new_domain_with_risk", weights.get('young_domain_with_risk_90d', 4))
    
    # Domain type
    if res.is_suspicious_tld:
        # Don't stack with retail_scam_tld — if .shop is already flagged as a
        # retail scam TLD, don't also penalize it as a generic suspicious TLD
        if not res.is_retail_scam_tld:
            add("suspicious_tld", weights.get('suspicious_tld', 12))
    if res.is_free_email_domain:
        add("free_email_domain", weights.get('free_email_domain', 20))
    if res.is_disposable_email:
        add("disposable_email", weights.get('disposable_email', 30))
    if res.typosquat_target:
        add("typosquat_detected", weights.get('typosquat_detected', 25))
    if res.is_free_hosting:
        add("free_hosting", weights.get('free_hosting', 12))
    
    # === HOSTING PROVIDER DETECTION ===
    if res.hosting_provider_type == "budget_shared":
        add("hosting_budget_shared", weights.get('hosting_budget_shared', 8))
    elif res.hosting_provider_type == "free":
        add("hosting_free", weights.get('hosting_free', 12))
    elif res.hosting_provider_type == "suspect":
        add("hosting_suspect", weights.get('hosting_suspect', 18))
    elif res.hosting_provider_type == "platform":
        # Dev platforms (Render, Netlify, Vercel) aren't inherently bad,
        # but custom domains on free-tier platforms sending email is a red flag
        add("hosting_platform", weights.get('hosting_platform', 4))
    
    # === NAMESERVER RISK SIGNALS ===
    if res.ns_is_dynamic_dns:
        add("ns_dynamic_dns", weights.get('ns_dynamic_dns', 25))
    if res.ns_is_parking:
        add("ns_parking", weights.get('ns_parking', 15))
    # Subdomains never have their own NS records — they inherit from the parent zone.
    # Flagging a subdomain as "lame delegation" because it has 0 NS records of its own
    # is a structural FP (e.g. ntuacounseling.ntu.edu.tw, stg.example.com).
    if res.ns_is_lame_delegation and not res.is_subdomain:
        add("ns_lame_delegation", weights.get('ns_lame_delegation', 20))
    if res.ns_is_free_dns:
        add("ns_free_dns", weights.get('ns_free_dns', 8))
    if res.ns_is_single_ns:
        add("ns_single_ns", weights.get('ns_single_ns', 5))
    
    # === DOMAIN NAME PATTERN DETECTION (Tech Support Scams) ===
    if res.has_suspicious_prefix:
        add("suspicious_prefix", weights.get('suspicious_prefix', 15))
    if res.has_suspicious_suffix:
        add("suspicious_suffix", weights.get('suspicious_suffix', 15))
    if res.is_tech_support_tld:
        add("tech_support_tld", weights.get('tech_support_tld', 18))
    if res.domain_impersonates_brand:
        add("domain_brand_impersonation", weights.get('domain_brand_impersonation', 25))
    
    # v7.9: Hyphenated SLD — conditional scoring.
    # A hyphen in the registrable SLD is a low-confidence signal on its own
    # (many legitimate domains like co-op.com, e-bay.com use hyphens), but it
    # combines well with newness, youth, or opaque content.  Score only when at
    # least one other risk signal is present to avoid penalising established
    # legitimate hyphenated brands.
    if res.is_hyphenated_sld:
        add("hyphenated_sld", 0)  # Zero-point marker so combo rules can fire
        _hyphen_corroborated = bool(signals & {
            "domain_created_today", "domain_lt_7d", "domain_lt_30d",
            "content_facade", "content_placeholder", "minimal_shell",
            "registration_opaque", "hosting_suspect", "hosting_free",
            "typosquat_detected", "domain_brand_impersonation",
            "suspicious_prefix", "suspicious_suffix",
        })
        if _hyphen_corroborated:
            add("hyphenated_sld", weights.get('hyphenated_sld_with_risk', 8))
    
    # Brand + spoofing keyword: easyjetconnect, amazonverify, chaselogin, etc.
    # This is a much stronger signal than brand name alone — it specifically
    # mimics legitimate brand service names/subdomains
    if res.brand_plus_keyword_domain:
        add("brand_spoofing_keyword", weights.get('brand_spoofing_keyword', 20))
    
    # === TLD VARIANT SPOOFING DETECTION ===
    if res.tld_variant_detected:
        add("tld_variant_spoofing", weights.get('tld_variant_spoofing', 30))
    
    # v7.5.1: UK TLD variant dark — .co.uk has no DNS
    # On ESTABLISHED domains (90+ days): strong signal that the domain is operating
    # on an alternate TLD while the legitimate .co.uk is dead/unheld — common in
    # hacklink campaigns and domain takeovers.
    # On NEW domains (< 90 days): suppress entirely — the owner simply hasn't registered .co.uk.
    # Don't add to signals set on young domains to prevent combo rule cascading.
    if res.tld_variant_uk_no_dns:
        _ukv_age_ok = res.domain_age_days < 0 or res.domain_age_days >= 90
        if _ukv_age_ok:
            add("tld_variant_uk_no_dns", weights.get('tld_variant_uk_no_dns', 28))
        # else: young domain — don't score or track
    
    # E-commerce / Retail scam indicators
    if res.is_retail_scam_tld:
        add("retail_scam_tld", weights.get('retail_scam_tld', 12))
    if res.has_cross_domain_brand_link:
        add("cross_domain_brand_link", weights.get('cross_domain_brand_link', 18))
    if res.is_ecommerce_site and res.missing_business_identity:
        add("ecommerce_no_identity", weights.get('ecommerce_no_identity', 15))
    
    # Web/TLS
    if not res.https_valid:
        add("no_https", weights.get('no_https', 25))
    
    # v4.4: TLS failure markers — tracked for summary/rules but scored at 0.
    # These explain WHY HTTPS failed, they're not additional risk on top of no_https.
    if res.tls_handshake_failed:
        add("tls_handshake_failed", 0)
    if res.tls_connection_failed:
        add("tls_connection_failed", 0)
    
    if res.cert_expired:
        add("cert_expired", weights.get('cert_expired', 15))
    if res.cert_self_signed:
        add("cert_self_signed", weights.get('cert_self_signed', 12))
    
    # Redirects
    if res.redirect_count >= 2:
        add("redirect_chain_2plus", weights.get('redirect_chain_2plus', 12))
    if res.redirect_cross_domain:
        add("redirect_cross_domain", weights.get('redirect_cross_domain', 12))
    if res.redirect_uses_temp:
        add("redirect_temp_302_307", weights.get('redirect_temp_302_307', 10))
    
    # === STATUS CODE SIGNALS (per research: high-value early indicators) ===
    # 401 = unauthorized on public site - unusual
    if res.has_401:
        add("status_401_unauthorized", weights.get('status_401_unauthorized', 12))
    
    # NOTE: 403 (status_403_cloaking) intentionally not scored — see config.py comment.
    # Cloudflare/WAF bot protection returns 403 on too many legitimate domains.

    # 429 = throttling scanners - medium signal
    if res.has_429:
        add("status_429_throttling", weights.get('status_429_throttling', 8))
    
    # 503 = disposable infrastructure - medium signal  
    if res.has_503:
        add("status_503_disposable", weights.get('status_503_disposable', 8))
    
    # === ACCESS RESTRICTION / CORPORATE TRUST SIGNALS ===
    # Access restricted (401 or 403) on what should be a public domain
    if res.is_access_restricted:
        add("access_restricted", weights.get('access_restricted', 10))
    
    # Missing trust signals (no about/contact pages)
    # Don't flag on empty pages — obviously an empty page has no /about etc.
    # Don't flag when TLS failed — can't find /about if the server is unreachable;
    # that's already covered by no_https / tls_connection_failed.
    if res.missing_trust_signals and not res.is_empty_page and not res.tls_connection_failed and not res.tls_handshake_failed:
        add("missing_trust_signals", weights.get('missing_trust_signals', 8))
    
    # Opaque entity - access blocked AND no corporate footprint
    # This is a classic B2B fraud / supplier impersonation pattern
    if res.is_opaque_entity and not res.is_empty_page:
        add("opaque_entity", weights.get('opaque_entity', 20))
    
    # Content
    if res.is_minimal_shell and not res.is_empty_page:
        add("minimal_shell", weights.get('minimal_shell', 15))
    if res.has_js_redirect:
        # v7.5.1: Suppress on parking pages — parking providers (HugeDomains, Sedo)
        # use JS redirects for domain purchase flows and navigation.
        if not res.is_parking_page:
            add("js_redirect", weights.get('js_redirect', 12))
    if res.has_meta_refresh:
        add("meta_refresh", weights.get('meta_refresh', 5))
    if res.has_external_js:
        add("external_js_loader", weights.get('external_js_loader', 6))
    if res.has_suspicious_iframe:
        add("suspicious_iframe", weights.get('suspicious_iframe', 8))
    if res.is_parking_page:
        add("parking_page", weights.get('parking_page', 6))
    
    # === TRUSTED AUTHENTICATED SITE CHECK (v7.5.1) ===
    # Calculate ONCE, use everywhere.  Covers e-commerce, financial, SaaS, and any
    # established domain with strong email auth.  When True, credential_form,
    # form_posts_external, and weak harvest_input_value are all suppressed.
    _is_trusted_auth = False
    _trust_age_ok = res.domain_age_days < 0 or res.domain_age_days >= 90
    _trust_has_dkim = res.dkim_exists or bool(res.dkim_selectors_found)
    if _trust_age_ok:
        if res.is_ecommerce_site:
            _is_trusted_auth = True
        elif res.mx_provider_type == "enterprise" and _trust_has_dkim:
            _is_trusted_auth = True
        elif _trust_has_dkim and res.dmarc_policy in ("reject", "quarantine"):
            _is_trusted_auth = True
        elif res.mx_provider_type == "enterprise" and res.dmarc_policy in ("reject", "quarantine"):
            _is_trusted_auth = True
        elif res.app_store_has_presence and res.app_store_confidence in ("high", "medium") and _trust_has_dkim:
            _is_trusted_auth = True
    
    if res.has_credential_form and not _is_trusted_auth:
        add("credential_form", weights.get('credential_form', 20))
    if res.has_sensitive_fields:
        add("sensitive_fields", weights.get('sensitive_fields', 10))
    if res.form_posts_external and not _is_trusted_auth:
        add("form_posts_external", weights.get('form_posts_external', 10))
    if res.brands_detected:
        add("brand_impersonation", weights.get('brand_impersonation', 22))
    if res.phishing_paths_found:
        add("phishing_paths", weights.get('phishing_paths', 20))
    if res.malware_links_found:
        add("malware_links", weights.get('malware_links', 25))
    
    # === PHISHING KIT / EXFIL DETECTION (v7.3) ===
    if res.has_phishing_kit_filename:
        if res.phishing_kit_filename_strong:
            add("phishing_kit_filename_strong", weights.get('phishing_kit_filename_strong', 22))
        else:
            # Weak filenames score 0 alone — combo rules give them weight
            add("phishing_kit_filename_weak", 0)
    if res.has_exfil_drop_script:
        add("exfil_drop_script", weights.get('exfil_drop_script', 30))
    if res.phishing_kit_detected:
        add("phishing_kit_detected", weights.get('phishing_kit_detected', 15))
    
    # === v7.4: FORM ACTION → KIT FILENAME ===
    if res.has_form_action_kit:
        if res.form_action_kit_strong:
            add("form_action_kit_strong", weights.get('form_action_kit_strong', 25))
        else:
            # Weak form targets (login.php, verify.php) — combo fuel only
            add("form_action_kit_weak", 0)
    
    # === v7.4: SUSPICIOUS PAGE TITLE ===
    if res.has_suspicious_page_title:
        add("suspicious_page_title", weights.get('suspicious_page_title', 5))
    
    # === v7.5: CLIENT-SIDE HARVEST COMBO ===
    # Only scored when harvest patterns are corroborated by other phishing signals.
    # v7.5.1: On trusted auth sites (enterprise MX + DKIM, established), suppress
    # when the only harvest signal is harvest_input_value — every login form reads
    # input values as part of normal authentication.  Stronger signals (keylogger,
    # cookie theft, formdata exfil) still fire regardless.
    if res.has_harvest_combo:
        _suppress_harvest = False
        _harvest_sigs = set((res.harvest_signals or "").split(";"))
        _harvest_sigs.discard("")
        _weak_harvest_only = _harvest_sigs.issubset({"harvest_input_value"})
        
        # Use the SAME _is_trusted_auth flag calculated above
        if _weak_harvest_only and _is_trusted_auth:
            _suppress_harvest = True
        
        if not _suppress_harvest:
            add("client_side_harvest_combo", weights.get('client_side_harvest_combo', 25))
    
    # === v7.4: WHOIS PRIVACY ===
    # Standalone: very low weight (most legitimate domains use privacy too).
    # Value is as combo fuel with new_domain + credential_form + self-hosted MX.
    if res.whois_privacy:
        add("whois_privacy", weights.get('whois_privacy', 0))
    
    # === HIJACKED DOMAIN / STEPPING STONE INDICATORS ===
    if res.has_hijack_path_pattern:
        add("hijack_path_pattern", weights.get('hijack_path_pattern', 12))
    if res.has_doc_sharing_lure:
        add("doc_sharing_lure", weights.get('doc_sharing_lure', 15))
    if res.has_phishing_js_behavior:
        add("phishing_js_behavior", weights.get('phishing_js_behavior', 18))
    if res.redirects_to_phishing_infra:
        add("phishing_infra_redirect", weights.get('phishing_infra_redirect', 25))
    if res.has_email_in_url:
        add("email_tracking_url", weights.get('email_tracking_url', 20))
    
    # === VIRUSTOTAL REPUTATION SCORING ===
    if res.vt_available:
        mal = res.vt_malicious_count
        sus = res.vt_suspicious_count
        if mal >= 5:
            add("vt_malicious_high", weights.get('vt_malicious_high', 65))
        elif mal >= 3:
            add("vt_malicious_medium", weights.get('vt_malicious_medium', 40))
        elif mal >= 1:
            add("vt_malicious_low", weights.get('vt_malicious_low', 22))
        
        if sus >= 3:
            add("vt_suspicious", weights.get('vt_suspicious', 15))
        elif sus >= 1:
            add("vt_suspicious_low", weights.get('vt_suspicious_low', 5))
        
        if res.vt_community_score < -5:
            add("vt_negative_community", weights.get('vt_negative_community', 10))
        
        if mal == 0 and sus == 0 and res.vt_total_vendors >= 50:
            # Don't credit VT clean scan of a content facade (SPA shell with no real content)
            # v7.5.1: Unless facade was de-escalated by SPA trust signals
            if not res.content_is_facade or "content_facade" not in signals:
                add("vt_clean", weights.get('vt_clean', -5))
    
    # === HACKLINK / SEO SPAM SCORING ===
    if res.hacklink_detected:
        add("hacklink_detected", weights.get('hacklink_detected', 50))
    
    if res.hacklink_keywords and not res.hacklink_detected:
        # Keywords found but below threshold — still a warning signal
        kw_count = len(res.hacklink_keywords.split(";")) if res.hacklink_keywords else 0
        if kw_count >= 1:
            add("hacklink_keywords", weights.get('hacklink_keywords', 15))
    
    if res.hacklink_wp_compromised:
        add("hacklink_wp_compromised", weights.get('hacklink_wp_compromised', 45))
    
    if res.hacklink_vulnerable_plugins:
        add("hacklink_vulnerable_plugins", weights.get('hacklink_vulnerable_plugins', 25))
    
    if res.hacklink_spam_link_count >= 5:
        add("hacklink_spam_links", weights.get('hacklink_spam_links', 35))
    
    # === MALICIOUS SCRIPT INJECTION (SocGholish/FakeUpdates/obfuscated) ===
    # v7.2: Multi-signal confidence — HIGH gets full weight, MEDIUM gets reduced weight
    # v7.5: Suppress on parking pages when ALL external scripts are from known providers
    _suppress_malicious_script = False
    if res.hacklink_malicious_script and res.is_parking_page:
        # Check if all external script domains are known parking providers
        _ext_domains = [d.strip().lower() for d in
                        (res.content_external_script_domains or "").split(";") if d.strip()]
        if _ext_domains:
            _unknown = [d for d in _ext_domains if d not in KNOWN_PARKING_SCRIPT_DOMAINS]
            if not _unknown:
                _suppress_malicious_script = True
        else:
            # No external scripts tracked — check the signals themselves
            # If only UNKNOWN_EXTERNAL_SCRIPT + HIGH_ENTROPY_PATH + JQUERY_MASQUERADE
            # and parking page is confirmed, suppress (these are CookieYes/HugeDomains artifacts)
            _ms_sigs = set((res.hacklink_malicious_script_signals or "").split(";"))
            _parking_artifact_sigs = {"UNKNOWN_EXTERNAL_SCRIPT", "HIGH_ENTROPY_PATH",
                                      "JQUERY_MASQUERADE", ""}
            if _ms_sigs.issubset(_parking_artifact_sigs):
                _suppress_malicious_script = True
    
    if res.hacklink_malicious_script and not _suppress_malicious_script:
        if res.hacklink_malicious_script_confidence == "HIGH":
            add("malicious_script", weights.get('malicious_script', 100))
        elif res.hacklink_malicious_script_confidence == "MEDIUM":
            # v7.5.1: Established domains with VT clean get reduced weight —
            # MEDIUM confidence scripts on 19-year-old VT-clean sites are almost
            # certainly legitimate third-party tracking/analytics, not SocGholish.
            _ms_established = (
                (res.domain_age_days < 0 or res.domain_age_days >= 365) and
                res.vt_malicious_count == 0 and res.vt_total_vendors >= 50
            )
            if _ms_established:
                add("malicious_script", weights.get('malicious_script_medium_established', 10))
            else:
                add("malicious_script", weights.get('malicious_script_medium', 25))
    
    # === HIDDEN CONTENT INJECTION (CSS cloaking: display:none, font-size:0) ===
    # HIGH = hidden content WITH embedded links (near-certain hacklink/SEO spam)
    # LOW  = CSS hiding patterns only, no links (common in legit templates/dev sites)
    if res.hacklink_hidden_injection:
        if res.hacklink_hidden_injection_confidence == "HIGH":
            add("hidden_injection", weights.get('hidden_injection', 55))
        elif res.hacklink_hidden_injection_confidence == "LOW":
            add("hidden_injection_css_only", weights.get('hidden_injection_css_only', 5))
    
    # === CPANEL HOSTING DETECTED ===
    if res.hacklink_is_cpanel:
        add("cpanel_detected", weights.get('cpanel_detected', 8))
    
    # === CONTENT IDENTITY VERIFICATION ===
    if res.content_title_body_mismatch:
        add("content_title_mismatch", weights.get('content_title_mismatch', 25))
    
    if res.content_cross_domain_emails:
        add("content_cross_domain_email", weights.get('content_cross_domain_email', 35))
    
    if res.content_is_broker_page:
        add("content_broker_page", weights.get('content_broker_page', 20))
    
    if res.content_page_privacy_emails:
        add("content_privacy_email", weights.get('content_privacy_email', 12))
    
    if res.content_is_placeholder:
        add("content_placeholder", weights.get('content_placeholder', 10))
    
    if res.content_is_facade:
        # v7.5.1: SPA LEGITIMACY CHECK — Modern React/Vue/Next.js apps serve empty HTML
        # shells where JavaScript renders everything client-side.  This is indistinguishable
        # from a phishing shell on content alone.  However, phishing shells almost NEVER
        # have enterprise MX, app store presence, strict SPF, and clean VT — these signals
        # indicate a real SPA, not a phishing operation.
        #
        # Count strong legitimacy signals that are incompatible with phishing shells:
        _spa_trust = 0
        if res.mx_provider_type == "enterprise":
            _spa_trust += 2  # Enterprise MX (Google/Microsoft) — strongest signal
        if res.app_store_has_presence and res.app_store_confidence in ("high", "medium"):
            _spa_trust += 2  # Real app store listing
        if res.spf_exists and res.spf_mechanism == "-all":
            _spa_trust += 1  # Strict SPF — investment in email auth
        if res.dkim_exists or bool(res.dkim_selectors_found):
            _spa_trust += 1  # DKIM configured
        if res.vt_malicious_count == 0 and res.vt_total_vendors >= 50:
            _spa_trust += 1  # VT clean across 50+ vendors
        if res.domain_age_days >= 180:
            _spa_trust += 1  # Established domain (6+ months)
        
        # v7.9: SPA framework fingerprint — Next.js/__NEXT_DATA__, Angular ng-version,
        # Nuxt window.__NUXT__, etc. are structural markers that phishing shells
        # almost never replicate.  A confirmed framework adds meaningful trust.
        if res.content_spa_framework_detected:
            _spa_trust += 2
        
        # v7.9: ANTI-TRUST PENALTY — self-hosted MX on a facade site is an active
        # negative signal, not just the absence of enterprise MX.  A real SPA from
        # a legitimate company uses Google/Microsoft/Proofpoint for mail.  Running
        # your own mail server while hiding site content behind JS is a phishing
        # infrastructure pattern: you control delivery, the site stays opaque.
        if res.mx_provider_type == "selfhosted":
            _spa_trust -= 2
        
        # 4+ trust signals = almost certainly a real SPA → reduce facade to informational
        # 3 trust signals = probably a real SPA → halve the facade weight
        # 0-2 trust signals = could be phishing → full facade weight
        if _spa_trust >= 4:
            # Don't add to signals set — prevents combo rules from firing
            pass  # SPA with strong trust signals — completely suppress
        elif _spa_trust >= 3:
            _half = weights.get('content_facade', 25) // 2
            add("content_facade", _half)
        else:
            add("content_facade", weights.get('content_facade', 25))
    
    # === REGISTRATION OPACITY ===
    # Both RDAP and WHOIS failed to return domain creation date.
    # Legitimate domains almost always have accessible registration data.
    # Scored conditionally: standalone is mild, but combined with content
    # risk signals (facade, mismatch, broker) it becomes much more significant.
    #
    # EXCEPTION: Academic and government ccTLDs (.edu.*, .ac.*, .gov.*, .mil.*)
    # routinely restrict WHOIS/RDAP by policy — a subdomain of ntu.edu.tw or
    # ox.ac.uk will always return opaque registration data.  Scoring that as
    # a risk signal is a guaranteed FP for any institutional subdomain.
    _is_academic_subdomain = False
    if res.is_subdomain and res.parent_domain:
        _ACADEMIC_TLD_PATTERNS = (".edu.", ".ac.", ".gov.", ".mil.", ".gouv.", ".gob.")
        _parent_lower = res.parent_domain.lower()
        _is_academic_subdomain = any(_pat in _parent_lower for _pat in _ACADEMIC_TLD_PATTERNS)
    if res.registration_opaque and not _is_academic_subdomain:
        _content_risk_present = (
            res.content_is_facade or res.content_title_body_mismatch or
            res.content_cross_domain_emails or res.content_is_broker_page or
            res.content_is_placeholder
        )
        if _content_risk_present:
            add("registration_opaque", weights.get('registration_opaque_with_risk', 20))
        else:
            add("registration_opaque", weights.get('registration_opaque', 8))
    
    # === DOMAIN REREGISTRATION ===
    # Domain was dropped and re-registered (RDAP "reregistration" event).
    # Common tactic: buy an expired domain for residual reputation,
    # then use it for spam/phishing. Scored higher with content risk.
    if res.domain_reregistered and res.domain_reregistered_days >= 0:
        _content_risk_present = (
            res.content_is_facade or res.content_title_body_mismatch or
            res.content_cross_domain_emails or res.content_is_broker_page
        )
        if res.domain_reregistered_days <= 90 and _content_risk_present:
            add("domain_reregistered_recent", weights.get('domain_reregistered_recent_with_risk', 18))
        elif res.domain_reregistered_days <= 90:
            add("domain_reregistered_recent", weights.get('domain_reregistered_recent', 6))
        elif _content_risk_present:
            add("domain_reregistered", weights.get('domain_reregistered_with_risk', 10))
    
    # === TRANSFER LOCK / WHOIS ENRICHMENT ===
    # Transfer lock and WHOIS updates are tracked as zero-point markers.
    # Like domain age, they only add points when actual content/infrastructure
    # risk signals are present — a WHOIS update alone could be auto-renewal,
    # contact info change, privacy protection, registrar migration, etc.
    #
    # v7.5.1: Suppress entirely on parking pages — domain marketplaces
    # (HugeDomains, Sedo, Afternic) routinely add transfer locks to protect
    # domains listed for sale.  A recent lock on a parked domain is expected
    # marketplace behavior, not a post-compromise lockdown signal.
    if not res.is_parking_page:
        if res.domain_transfer_lock_recent:
            add("transfer_lock_recent", 0)
        elif res.whois_recently_updated:
            add("whois_recently_updated", 0)
        
        # Only score transfer lock / WHOIS update when content risk is present
        _TRANSFER_RISK_SIGNALS = {
            "hacklink_keywords", "hidden_injection", "hacklink_wp_compromised",
            "hacklink_spam_links", "hacklink_vulnerable_plugins", "malicious_script",
            "js_redirect", "minimal_shell", "empty_page",
            "hosting_suspect", "hosting_free", "typosquat_detected",
            "redirect_cross_domain", "cross_domain_brand_link",
            "tld_variant_spoof", "domain_brand_impersonation",
            "opaque_entity", "sensitive_fields", "phishing_js", "doc_lure",
            "vt_malicious", "vt_malicious_medium", "vt_suspicious",
            "blocked_asn", "mx_hijack_high", "mx_hijack_medium",
            "subdomain_delegation_high", "subdomain_delegation_medium",
            "ct_reactivated",
            "oauth_phish", "homoglyph_domain", "cdn_tunnel_suspect", "quishing_profile",
            "content_title_mismatch", "content_cross_domain_email", "content_broker_page", "content_facade", "registration_opaque",
            "domain_reregistered_recent", "domain_reregistered",
        }
        if (res.domain_transfer_lock_recent or res.whois_recently_updated):
            has_transfer_risk = bool(signals & _TRANSFER_RISK_SIGNALS)
            if has_transfer_risk:
                # v7.5.1: On fully-authenticated domains (enterprise MX + DKIM + SPF strict),
                # a recent transfer lock is more likely administrative than post-compromise.
                # Score at half weight when the only risk signals are "soft" indicators
                # (vulnerable plugins, ptr mismatch) that are common on legitimate sites.
                _HARD_TRANSFER_RISK = {
                    "hacklink_keywords", "hidden_injection", "hacklink_wp_compromised",
                    "hacklink_spam_links", "malicious_script", "empty_page",
                    "hosting_suspect", "hosting_free", "typosquat_detected",
                    "tld_variant_spoof", "domain_brand_impersonation",
                    "vt_malicious", "vt_malicious_medium", "vt_suspicious",
                    "blocked_asn", "mx_hijack_high",
                    "ct_reactivated", "oauth_phish", "homoglyph_domain",
                    "content_title_mismatch", "content_cross_domain_email",
                    "domain_reregistered_recent", "domain_reregistered",
                }
                _is_fully_authed = (
                    res.mx_provider_type == "enterprise" and
                    (res.dkim_exists or bool(res.dkim_selectors_found)) and
                    res.spf_exists and res.spf_mechanism == "-all"
                )
                _has_hard_risk = bool(signals & _HARD_TRANSFER_RISK)
                
                if res.domain_transfer_lock_recent:
                    if _is_fully_authed and not _has_hard_risk:
                        # Soft risk only on fully-authenticated domain → don't add to signals
                        pass  # Prevents combo rules from firing
                    else:
                        add("transfer_lock_with_risk", weights.get('transfer_lock_recent', 15))
                else:
                    add("whois_updated_with_risk", weights.get('whois_recently_updated', 10))
    
    # === MX HIJACK FINGERPRINT (v7.3.1) ===
    if res.mx_provider_mismatch:
        if res.mx_hijack_confidence == "HIGH":
            add("mx_hijack_high", weights.get('mx_hijack_high', 30))
        elif res.mx_hijack_confidence == "MEDIUM":
            add("mx_hijack_medium", weights.get('mx_hijack_medium', 15))
        else:
            add("mx_hijack_low", weights.get('mx_hijack_low', 0))  # informational only
    
    # === EMPTY PAGE ===
    # v7.5.1: Suppress on young domains (< 30 days) — a brand-new domain with an empty
    # page is expected behavior (site hasn't been built yet), not a compromise indicator.
    # On established domains, an empty page suggests stripped/gutted content post-compromise.
    # IMPORTANT: Don't add to signals set on young domains — this prevents combo rules
    # (e.g., combo_empty_page_uk_variant) from cascading into false denials.
    if res.is_empty_page:
        _empty_age_ok = res.domain_age_days < 0 or res.domain_age_days >= 30
        if _empty_age_ok:
            add("empty_page", weights.get('empty_page', 20))
        # else: young domain — don't score or track (prevents combo cascade)
    
    # === CERTIFICATE TRANSPARENCY ===
    # v7.5.1: Suppress ct_recent_issuance on routine LE/ACME renewals.
    # A domain with 5+ certs in CT logs and 180+ days of age is just auto-renewing
    # its Let's Encrypt cert every 60-90 days — that's not a risk signal.
    # Only score when it's a NEW cert on a domain that shouldn't need one:
    #   - Young domain (<180d) getting early certs
    #   - Domain with few certs (< 5) — limited history, could be reactivation
    #   - ct_reactivated already handles the gap-then-new-cert pattern separately
    if res.ct_recent_issuance:
        _routine_renewal = (
            res.ct_log_count >= 5 and
            (res.domain_age_days < 0 or res.domain_age_days >= 180) and
            not res.ct_reactivated
        )
        if not _routine_renewal:
            add("ct_recent_issuance", weights.get('ct_recent_issuance', 10))
    
    if res.ct_log_count == 0:
        add("ct_no_history", weights.get('ct_no_history', 15))
    
    # v7.3.1: CT gap — aged domain purchase detection
    if res.ct_reactivated:
        add("ct_reactivated", weights.get('ct_reactivated', 25))
    elif res.ct_gap_months >= 12:
        add("ct_gap_large", weights.get('ct_gap_large', 10))  # Large gap but not recent reactivation
    
    # v7.5.1: Cert issued but TLS dead — infrastructure disruption signal
    # A cert was issued within 90 days but TLS is now refusing/failing.
    # Weight scales by domain age: on established domains this is very suspicious,
    # on new domains it may just be setup in progress.
    if res.ct_cert_tls_dead:
        if res.domain_age_days >= 0 and res.domain_age_days < 30:
            add("ct_cert_tls_dead", 0)  # New domain — setup in progress
        elif res.domain_age_days >= 365:
            add("ct_cert_tls_dead", weights.get('ct_cert_tls_dead', 18))
        else:
            add("ct_cert_tls_dead", weights.get('ct_cert_tls_dead_young', 8))
    
    # v7.3.1: Subdomain delegation abuse
    if res.subdomain_infra_divergent:
        if res.subdomain_divergence_confidence == "HIGH":
            add("subdomain_delegation_high", weights.get('subdomain_delegation_high', 25))
        elif res.subdomain_divergence_confidence == "MEDIUM":
            add("subdomain_delegation_medium", weights.get('subdomain_delegation_medium', 12))
        else:
            # LOW divergence: only score if NOT a known SDLC subdomain prefix.
            # Staging/dev/uat/qa subdomains on different infra than parent are
            # completely normal — expected, in fact.  Scoring LOW divergence on
            # stg.example.com is a guaranteed FP.
            if not res.is_staging_subdomain:
                add("subdomain_delegation_low", weights.get('subdomain_delegation_low', 0))  # informational
    
    # Track staging subdomain as a zero-point signal so rules can gate on it
    if res.is_staging_subdomain:
        add("is_staging_subdomain", 0)
    
    # v7.3.1: OAuth consent phishing
    if res.has_oauth_phish:
        add("oauth_phish", weights.get('oauth_phish', 20))
    
    # v7.3.1: Homoglyph / IDN spoofing
    if res.is_homoglyph_domain:
        add("homoglyph_domain", weights.get('homoglyph_domain', 30))
    
    # v7.3.1: Quishing profile
    if res.quishing_profile:
        add("quishing_profile", weights.get('quishing_profile', 15))
    
    # v7.3.1: CDN tunnel abuse
    if res.cdn_tunnel_suspect:
        add("cdn_tunnel_suspect", weights.get('cdn_tunnel_suspect', 15))
    
    # === MITIGATIONS (strong counter-signals reduce risk from ambiguous indicators) ===
    # JS redirect + minimal shell is the classic phishing dropper fingerprint, but it's
    # also exactly what a legit "coming soon" page or storefront redirect looks like.
    # Phishing throwaways almost NEVER set up strict SPF + DMARC enforcement because
    # they don't care about long-term deliverability. When both are present, reduce
    # the weight of these ambiguous content signals.
    has_strong_email_auth = (
        res.spf_exists and res.spf_mechanism == "-all"
        and res.dmarc_exists and res.dmarc_policy in ("reject", "quarantine")
    )
    if has_strong_email_auth:
        if "js_redirect" in signals:
            add("js_redirect_email_auth_mitigated", weights.get('js_redirect_email_auth_mitigated', -8))
        if "minimal_shell" in signals:
            add("minimal_shell_email_auth_mitigated", weights.get('minimal_shell_email_auth_mitigated', -8))

    # === VULNERABLE PLUGINS WITHOUT COMPROMISE EVIDENCE ===
    # Contact Form 7, Elementor, etc. are on millions of legitimate WordPress sites.
    # Having them installed is theoretical risk, not evidence of actual compromise.
    # When there's NO evidence of exploitation AND the domain has strong legitimacy
    # signals, reduce the weight significantly — it's just a popular plugin, not a hack.
    if "hacklink_vulnerable_plugins" in signals:
        has_compromise_evidence = any(s in signals for s in [
            "hacklink_keywords", "hidden_injection", "hacklink_wp_compromised",
            "hacklink_spam_links", "malicious_script",
        ])
        if not has_compromise_evidence:
            # Domain has strong positive signals — theoretical vuln only
            is_established = res.domain_age_days and res.domain_age_days >= 365
            has_app_presence = res.app_store_has_presence
            has_enterprise_mx = res.mx_provider_type == "enterprise"
            legitimacy_signals = sum([
                bool(has_strong_email_auth),
                bool(is_established),
                bool(has_app_presence),
                bool(has_enterprise_mx),
                bool(res.dkim_exists),
            ])
            # 3+ legitimacy signals = clearly legitimate site with a popular plugin
            if legitimacy_signals >= 3:
                add("vuln_plugins_no_compromise_mitigated", weights.get('vuln_plugins_strong_mitigation', -18))
            # 2 legitimacy signals = likely legitimate, moderate reduction
            elif legitimacy_signals >= 2:
                add("vuln_plugins_no_compromise_mitigated", weights.get('vuln_plugins_moderate_mitigation', -10))

    # === UNIFIED RULES ENGINE ===
    # All scoring logic beyond base weights (former combos + custom rules)
    # Rules support if/then/else logic:
    #   if_all:  ALL listed signals must be present (AND)
    #   if_any:  AT LEAST ONE listed signal must be present (OR)
    #   if_not:  NONE of these signals may be present (exclusion)
    #   score:   points to add (positive = riskier, negative = safer)
    rules = config.get('rules', DEFAULT_CONFIG.get('rules', []))
    rules_hit = []
    rules_labels = []
    for rule in rules:
        rule_name = rule.get('name', 'unnamed_rule')
        
        # Skip disabled rules
        if not rule.get('enabled', True):
            continue
        
        # Check if_all: every signal in this list must be present
        if_all = rule.get('if_all', [])
        if if_all and not all(s in signals for s in if_all):
            continue
        
        # Check if_any: at least one signal in this list must be present
        if_any = rule.get('if_any', [])
        if if_any and not any(s in signals for s in if_any):
            continue
        
        # Check if_not: none of these signals may be present
        if_not = rule.get('if_not', [])
        if if_not and any(s in signals for s in if_not):
            continue
        
        # All conditions met — rule fires
        rule_score = rule.get('score', 0)
        rule_label = rule.get('label', '')
        if rule_score != 0:
            breakdown[f"rule:{rule_name}"] = rule_score
            score += rule_score
        rules_hit.append(rule_name)
        if rule_label:
            rules_labels.append(rule_label)
    
    res.risk_score = max(0, min(score, 100))
    
    bands = [(0, 19, "LOW"), (20, 39, "MEDIUM"), (40, 64, "HIGH"), (65, 84, "CRITICAL"), (85, 999, "SEVERE")]
    res.risk_level = next((l for lo, hi, l in bands if lo <= res.risk_score <= hi), "UNKNOWN")
    
    res.recommendation = "APPROVE" if res.risk_score < threshold else "DENY"
    res.signals_triggered = ";".join(sorted(signals))
    res.combos_triggered = ""  # Deprecated: combos are now unified rules
    res.rules_triggered = ";".join(rules_hit)
    res.rules_labels = ";".join(rules_labels)
    res.score_breakdown = json.dumps(breakdown)
    
    # === BUILD ASN DISPLAY STRING ===
    if res.hosting_asn and res.hosting_asn_org:
        res.asn_display = f"AS{res.hosting_asn} ({res.hosting_asn_org})"
    elif res.hosting_asn:
        res.asn_display = f"AS{res.hosting_asn}"
    elif res.hosting_asn_org:
        res.asn_display = res.hosting_asn_org
    
    # === HIGH-RISK PHISHING INFRASTRUCTURE COMPOSITE CHECK ===
    # Fires when ALL of these are true:
    #   1. Render ASN (or blocked ASN match for Render)
    #   2. Self-hosted MX
    #   3. phish_factory_template rule fired
    #   4. platform_phish_setup rule fired
    # This combination is the exact fingerprint of the Swedish invoice phish population.
    rules_hit_names = rules_hit
    is_render = (
        (res.hosting_provider and res.hosting_provider.lower() == "render")
        or (res.hosting_asn_org and "render" in res.hosting_asn_org.lower())
        or (res.blocked_asn_org_match and "render" in res.blocked_asn_org_match.lower())
    )
    has_selfhosted_mx = "mx_selfhosted" in signals
    has_phish_factory = "phish_factory_template" in rules_hit_names
    has_platform_phish = "platform_phish_setup" in rules_hit_names
    
    if is_render and has_selfhosted_mx and has_phish_factory and has_platform_phish:
        res.high_risk_phish_infra = True
        res.high_risk_phish_infra_reason = (
            "Render ASN + self-hosted MX + phishing factory template + platform phish setup — "
            "matches known Swedish invoice phishing infrastructure fingerprint"
        )
    elif is_render and has_selfhosted_mx and (has_phish_factory or has_platform_phish):
        # Partial match — still very suspicious
        res.high_risk_phish_infra = True
        matched = []
        if has_phish_factory:
            matched.append("phish_factory_template")
        if has_platform_phish:
            matched.append("platform_phish_setup")
        res.high_risk_phish_infra_reason = (
            f"Render ASN + self-hosted MX + {' + '.join(matched)} — "
            "partial match on known phishing infrastructure fingerprint"
        )
    
    # === PHISHING KIT COMPOSITE DETECTION (v7.3) ===
    # Fires when multiple phishing kit indicators combine to confirm a live kit.
    # This surfaces the conclusion "this domain is running a phishing kit"
    # as a clear banner, rather than just scattered individual issues.
    #
    # Criteria: 2+ signals from this set fires the composite.
    # Exception: exfil alone is strong enough (1 signal fires composite).
    kit_evidence = []
    if res.has_phishing_kit_filename:
        kit_evidence.append(f"kit filename: {res.phishing_kit_filename}")
    if res.has_form_action_kit:
        kit_evidence.append(f"form action: {res.form_action_kit_target}")
    if res.has_exfil_drop_script:
        kit_evidence.append(f"exfil: {res.exfil_drop_signals}")
    if res.has_credential_form:
        kit_evidence.append("credential form")
    if res.has_suspicious_page_title:
        kit_evidence.append(f"lure title: {res.page_title_match}")
    if res.phishing_paths_found:
        kit_evidence.append(f"phishing paths: {res.phishing_paths_found}")
    if res.brands_detected:
        kit_evidence.append(f"brand: {res.brands_detected}")
    if res.form_posts_external:
        kit_evidence.append("form posts to external domain")
    if res.has_obfuscation:
        kit_evidence.append("obfuscated JS")
    if res.has_harvest_combo:
        kit_evidence.append(f"harvest combo: {res.harvest_signals}")
    
    if len(kit_evidence) >= 2 or res.has_exfil_drop_script:
        # v7.5 defense-in-depth: On parking pages, brand + form_external are
        # artifacts of the domain purchase flow (suppressed upstream in v7.5).
        # As a safety net, if the only evidence is parking-attributable signals
        # and no exfil/kit-filename/credential-form is present, do NOT fire.
        if res.is_parking_page and not res.has_exfil_drop_script:
            _hard_evidence = [e for e in kit_evidence if not (
                e.startswith("brand:") or
                e == "form posts to external domain" or
                e == "obfuscated JS"
            )]
            if len(_hard_evidence) >= 2:
                res.phishing_kit_detected = True
                res.phishing_kit_reason = " + ".join(kit_evidence)
            # else: suppress — only soft/parking-artifact evidence on a parking page
        
        # v7.5.1 defense-in-depth: On confirmed e-commerce sites OR established
        # well-authenticated domains (enterprise MX + DKIM, or DMARC reject/quarantine
        # + DKIM), three signals are EXPECTED business behavior, not phishing:
        #   - credential_form = customer/user login
        #   - brand: ups/fedex/dhl/usps = shipping carriers (e-commerce only)
        #   - form_posts_external = payment/banking processor integration
        # Strip these as evidence; only fire if hard evidence remains.
        # Uses the shared _is_trusted_auth flag calculated in the scoring section above.
        elif not res.has_exfil_drop_script:
            if _is_trusted_auth:
                def _is_shipping_brand(evidence_str):
                    """Check if a brand evidence item only contains shipping brands."""
                    if not evidence_str.startswith("brand:"):
                        return False
                    brand_part = evidence_str.split(":", 1)[1].strip()
                    detected = [b.strip().lower() for b in brand_part.split(";")]
                    return all(b in ECOMMERCE_SHIPPING_BRANDS for b in detected if b)
                
                def _is_weak_harvest(evidence_str):
                    """Check if harvest combo only contains harvest_input_value."""
                    if not evidence_str.startswith("harvest combo:"):
                        return False
                    harvest_part = evidence_str.split(":", 1)[1].strip()
                    sigs = {s.strip() for s in harvest_part.split(";") if s.strip()}
                    return sigs.issubset({"harvest_input_value"})
                
                _trusted_evidence = [e for e in kit_evidence if not (
                    e == "credential form" or
                    e == "form posts to external domain" or
                    _is_weak_harvest(e) or
                    (res.is_ecommerce_site and _is_shipping_brand(e))
                )]
                if len(_trusted_evidence) >= 2:
                    res.phishing_kit_detected = True
                    res.phishing_kit_reason = " + ".join(kit_evidence)
                # else: suppress — only normal-business evidence on a trusted site
            else:
                res.phishing_kit_detected = True
                res.phishing_kit_reason = " + ".join(kit_evidence)
    
    # === HACKLINK CAMPAIGN PROFILE COMPOSITE (v7.5.1) ===
    # Identifies domains matching known hacklink target infrastructure fingerprints.
    # This is a PROFILE match, not confirmed hacklink — the domain's infrastructure
    # resembles domains commonly targeted or used in hacklink/SEO spam campaigns.
    #
    # Signals that contribute to the profile:
    #   - empty_page: site content stripped or never present
    #   - uk_variant_dark: .co.uk variant has no DNS (common in UK hacklink campaigns)
    #   - weak_email_auth: no DKIM + DMARC p=none + SPF softfail (low investment in auth)
    #   - hidden_injection: CSS-cloaked content detected
    #   - cpanel_detected: cPanel hosting (frequently targeted in mass exploitation)
    #
    # CRITICAL: Only fires on established domains (90+ days).
    # On new domains, empty pages and missing UK variants are normal setup behavior.
    _hcp_signals = []
    if res.is_empty_page:
        _hcp_signals.append("empty_page")
    if res.tld_variant_uk_no_dns:
        _hcp_signals.append("uk_variant_dark")
    if not (res.dkim_exists or bool(res.dkim_selectors_found)) and res.dmarc_policy == "none" and res.spf_mechanism == "~all":
        _hcp_signals.append("weak_email_auth")
    if res.hacklink_hidden_injection:
        _hcp_signals.append("hidden_injection")
    if res.hacklink_is_cpanel:
        _hcp_signals.append("cpanel")
    
    # 2+ signals = profile match, but ONLY on established domains
    _hcp_age_ok = res.domain_age_days < 0 or res.domain_age_days >= 90
    if len(_hcp_signals) >= 2 and _hcp_age_ok:
        # Confidence: 3+ signals = HIGH, 2 = MODERATE
        _hcp_conf = "HIGH" if len(_hcp_signals) >= 3 else "MODERATE"
        res.hacklink_campaign_profile = True
        res.hacklink_campaign_profile_confidence = _hcp_conf
        res.hacklink_campaign_profile_signals = ";".join(_hcp_signals)
        # v7.8 FIX: Use the strong weight for HIGH confidence (3+ signals).
        # Previously both HIGH and MODERATE used the same base weight.
        if _hcp_conf == "HIGH":
            _hcp_weight = weights.get('hacklink_campaign_profile_strong', 40)
        else:
            _hcp_weight = weights.get('hacklink_campaign_profile', 25)
        add("hacklink_campaign_profile", _hcp_weight)
        
        # Retroactively cancel the enterprise MX bonus when HCP fires.
        # Enterprise MX is a legitimacy signal, but a confirmed hacklink campaign
        # fingerprint overrides that credit — the attacker may have simply kept
        # the existing MX records after compromising the domain.
        # HCP detection runs after the MX bonus is awarded (line 5860), so we
        # must reverse it here to prevent it from offsetting the HCP risk score.
        if "mx_enterprise" in breakdown and breakdown["mx_enterprise"] < 0:
            _mx_hcp_reversal = -breakdown["mx_enterprise"]
            score += _mx_hcp_reversal
            del breakdown["mx_enterprise"]
            signals.discard("mx_enterprise")
        
        # Re-sync res.risk_score to include the HCP contribution.
        # ARCHITECTURE NOTE: The main scoring block computed res.risk_score at the
        # end of the rules loop (line 6668), BEFORE this post-scoring section runs.
        # Any add() calls in this section (HCP, MX reversal) update the local
        # `score` variable but do NOT automatically propagate to res.risk_score.
        # We must re-sync explicitly here so the displayed score reflects HCP points.
        
        # SPA TRUST / HCP MUTUAL AWARENESS:
        # The SPA trust calculation (lines ~6364-6410) may have fully suppressed the
        # facade score because the domain had enterprise MX + DKIM + VT clean.
        # But if HCP fires with `hidden_injection` as one of its signals, we have
        # direct evidence of malicious content — a "clean SPA" argument is undermined.
        # Retroactively add back half the facade weight to prevent full suppression
        # from masking confirmed injection activity.  Half-weight preserves the SPA
        # trust credit partially; it just prevents a total zero-out.
        if ("hidden_injection" in _hcp_signals
                and res.content_is_facade
                and "content_facade" not in signals):
            _facade_half = weights.get('content_facade', 25) // 2
            add("content_facade", _facade_half)
        
        res.risk_score = max(0, min(score, 100))
        _hcp_bands = [(0, 19, "LOW"), (20, 39, "MEDIUM"), (40, 64, "HIGH"), (65, 84, "CRITICAL"), (85, 999, "SEVERE")]
        res.risk_level = next((l for lo, hi, l in _hcp_bands if lo <= res.risk_score <= hi), "UNKNOWN")
        res.recommendation = "APPROVE" if res.risk_score < threshold else "DENY"
        res.signals_triggered = ";".join(sorted(signals))
        res.score_breakdown = json.dumps(breakdown)
    
    # === BUILD PATTERN MATCH INDICATOR ===
    # Identifies known attack patterns for specialist visibility.
    _patterns = []
    
    # Phishing Kit pattern (v7.3)
    if res.phishing_kit_detected:
        # Show up to 3 evidence items in the pattern string
        _patterns.append(f"🎣 Phishing Kit ({', '.join(kit_evidence[:3])})")
    
    # Swedish Invoice Phish pattern
    if res.high_risk_phish_infra:
        reason = res.high_risk_phish_infra_reason or ""
        if "swedish" in reason.lower() or "invoice" in reason.lower():
            _patterns.append("🇸🇪 Swedish Invoice Phish")
        elif "render" in reason.lower() and "phish" in reason.lower():
            _patterns.append("🇸🇪 Swedish Invoice Phish (partial match)")
    
    # Hacklink Campaign Profile (v7.5.1)
    if res.hacklink_campaign_profile:
        _patterns.append(
            f"🕸️ Hacklink Campaign Profile ({res.hacklink_campaign_profile_confidence}: "
            f"{res.hacklink_campaign_profile_signals.replace(';', ', ')})"
        )
    
    # Hacklink / SEO Spam pattern
    _hl_signals = []
    if res.hacklink_detected:
        _hl_signals.append("hacklink keywords")
    if res.hacklink_hidden_injection and res.hacklink_hidden_injection_confidence == "HIGH":
        _hl_signals.append("hidden content injection")
    if res.hacklink_wp_compromised:
        _hl_signals.append("WP compromised")
    # v7.5.1: Only show malicious script in pattern if it was actually scored
    # (not suppressed by parking page exclusion)
    if res.hacklink_malicious_script and "malicious_script" in signals:
        _hl_signals.append("malicious script")
    if res.hacklink_spam_link_count >= 5:
        _hl_signals.append(f"{res.hacklink_spam_link_count} spam links")
    if _hl_signals:
        _patterns.append(f"🕷️ Hacklink/SEO Spam ({', '.join(_hl_signals)})")
    
    res.pattern_match = " + ".join(_patterns) if _patterns else ""
    
    # === AUTOFAIL OVERRIDE (v7.5) ===
    # Deterministic deny for confirmed threats — score and bonuses cannot override.
    # These conditions represent HIGH-CONFIDENCE threat detections where approving
    # would be an operational error regardless of accumulated score or trust bonuses.
    #
    # Each condition:
    #   1. Forces recommendation → DENY
    #   2. Clamps risk_score to at least threshold + 1 (so score visually reflects denial)
    #   3. Records the reason in autofail_reason for audit trail
    #   4. Adds "autofail" signal to breakdown
    _autofail_reasons = []
    
    # Confirmed phishing kit (exfil script, or 2+ kit indicators)
    if res.phishing_kit_detected:
        _autofail_reasons.append(
            f"PHISHING KIT CONFIRMED ({res.phishing_kit_reason})"
        )
    
    # Confirmed hacklink / SEO spam injection
    if res.hacklink_detected:
        _autofail_reasons.append(
            f"HACKLINK/SEO SPAM CONFIRMED (score={res.hacklink_score}, "
            f"keywords={res.hacklink_keywords or 'none'})"
        )
    
    # Swedish invoice phishing infrastructure fingerprint
    if res.high_risk_phish_infra:
        _autofail_reasons.append(
            f"SWEDISH PHISH TREND CONFIRMED ({res.high_risk_phish_infra_reason})"
        )
    
    if _autofail_reasons:
        res.autofail_reason = " | ".join(_autofail_reasons)
        res.recommendation = "DENY"
        # Ensure score visually reflects the denial
        res.risk_score = max(res.risk_score, threshold + 1)
        # Re-derive risk_level since score may have changed
        bands = [(0, 19, "LOW"), (20, 39, "MEDIUM"), (40, 64, "HIGH"), (65, 84, "CRITICAL"), (85, 999, "SEVERE")]
        res.risk_level = next((l for lo, hi, l in bands if lo <= res.risk_score <= hi), "UNKNOWN")
        # Record in breakdown for transparency
        breakdown["autofail"] = 0  # No extra points — it's a policy override, not a score contribution
        signals.add("autofail")
        res.signals_triggered = ";".join(sorted(signals))
        res.score_breakdown = json.dumps(breakdown)
    
    # === ZERO EMAIL AUTH FLOOR (v7.5.1) ===
    # When a domain has NO SPF, NO DKIM, AND NO DMARC, emails will be rejected
    # by Gmail and Yahoo regardless of what we do.  There is no business value in
    # approving a domain that can't deliver email.  Set a minimum score that
    # ensures denial, with a clear reason for the operator.
    #
    # EXCEPTION: Staging / SDLC subdomains (stg., dev., uat., qa., sandbox., etc.)
    # never send email — they inherit auth from the parent domain or have none by
    # design.  Denying stg.example.com because it lacks SPF/DKIM/DMARC is a
    # guaranteed FP.  The floor is bypassed for confirmed staging prefixes.
    #
    # EXCEPTION: If NO other content or infrastructure risk signals fired at all,
    # the floor is also suppressed.  A clean domain that simply hasn't configured
    # email auth yet (e.g. a new consulting landing page) should not auto-DENY
    # on auth absence alone — the zero_email_auth rule already added 10pts to the
    # score.  The floor is reserved for domains where auth absence sits alongside
    # real risk signals, compounding the danger.
    _zero_auth_content_risk = bool(signals & {
        "content_facade", "content_title_mismatch", "content_cross_domain_email",
        "content_broker_page", "content_placeholder", "hacklink_keywords",
        "hidden_injection", "malicious_script", "js_redirect", "minimal_shell",
        "empty_page", "hosting_suspect", "hosting_free", "hosting_budget_shared",
        "typosquat_detected", "domain_brand_impersonation", "opaque_entity",
        "vt_malicious", "vt_suspicious", "blocked_asn", "redirect_cross_domain",
        "cpanel_detected", "registration_opaque", "domain_reregistered_recent",
        "suspicious_tld", "disposable_email",
    })
    if (not res.spf_exists and not res.dkim_exists and not res.dmarc_exists
            and not res.is_staging_subdomain
            and _zero_auth_content_risk):
        _zero_auth_floor = threshold + 5  # Minimum score = threshold + 5
        if res.risk_score < _zero_auth_floor:
            res.risk_score = _zero_auth_floor
            res.recommendation = "DENY"
            # Re-derive risk_level
            bands = [(0, 19, "LOW"), (20, 39, "MEDIUM"), (40, 64, "HIGH"), (65, 84, "CRITICAL"), (85, 999, "SEVERE")]
            res.risk_level = next((l for lo, hi, l in bands if lo <= res.risk_score <= hi), "UNKNOWN")
            breakdown["zero_email_auth_floor"] = 0  # Policy override marker
            signals.add("zero_email_auth_floor")
            res.signals_triggered = ";".join(sorted(signals))
            res.score_breakdown = json.dumps(breakdown)
    
    # === NEW DOMAIN + WHOIS PRIVACY FLOOR (v7.9) ===
    # A domain under 30 days old with WHOIS privacy enabled should never score 0.
    # Strong email auth is a legitimate trust signal, but it shouldn't completely
    # erase all concern about an unknown operator on a brand-new private domain.
    # This floor is intentionally modest (10pts) — it signals "we noticed this is
    # new and private" without overriding a genuinely strong trust stack.
    # The floor does NOT force a DENY (threshold is 50); it just prevents a 0.
    #
    # Exemptions:
    # - Domain age unknown (domain_age_days < 0) — can't confirm youth
    # - App store verified (high/medium) — operator identity confirmed via store
    # - VT clean with 50+ vendors — strong external vetting
    _new_private_floor = 10
    if (res.domain_age_days >= 0
            and res.domain_age_days < 30
            and res.whois_privacy
            and res.risk_score < _new_private_floor
            and not (res.app_store_has_presence and res.app_store_confidence == "high")
            and not (res.app_store_has_presence and res.app_store_confidence == "medium")):
        res.risk_score = _new_private_floor
        # Don't change recommendation — 10pts is well below DENY threshold.
        # Re-derive risk_level in case it changed.
        bands = [(0, 19, "LOW"), (20, 39, "MEDIUM"), (40, 64, "HIGH"), (65, 84, "CRITICAL"), (85, 999, "SEVERE")]
        res.risk_level = next((l for lo, hi, l in bands if lo <= res.risk_score <= hi), "UNKNOWN")
        breakdown["new_domain_whois_privacy_floor"] = 0  # Policy marker
        signals.add("new_domain_whois_privacy_floor")
        res.signals_triggered = ";".join(sorted(signals))
        res.score_breakdown = json.dumps(breakdown)

    res.summary = generate_summary(res, signals, res.domain_age_days >= 0, weights=weights)


# ============================================================================
# MAIN ANALYSIS FUNCTION
# ============================================================================

def analyze_domain(domain: str, timeout: float = 10.0, check_rdap: bool = True,
                   weights: dict = None, threshold: int = 50,
                   full_config: dict = None) -> dict:
    """
    Main entry point for domain analysis.
    Returns dict with all results.
    
    If full_config is provided, rules, allowlists, and other settings are
    taken from it.  Otherwise falls back to DEFAULT_CONFIG (all rules enabled).
    """
    src = full_config or {}
    config = {
        'weights': weights or src.get('weights', DEFAULT_CONFIG['weights']),
        'approve_threshold': threshold,
        'rules': src.get('rules', DEFAULT_CONFIG.get('rules', [])),
        'suspicious_tlds': src.get('suspicious_tlds', DEFAULT_CONFIG.get('suspicious_tlds', [])),
        'protected_brands': src.get('protected_brands', DEFAULT_CONFIG.get('protected_brands', [])),
        'disposable_domains': src.get('disposable_domains', DEFAULT_CONFIG.get('disposable_domains', [])),
        'domain_blacklists': src.get('domain_blacklists', DEFAULT_CONFIG.get('domain_blacklists', [])),
        'ip_blacklists': src.get('ip_blacklists', DEFAULT_CONFIG.get('ip_blacklists', [])),
        'hosting_providers': src.get('hosting_providers', DEFAULT_CONFIG.get('hosting_providers', {})),
        'ns_risk_patterns': src.get('ns_risk_patterns', DEFAULT_CONFIG.get('ns_risk_patterns', {})),
        'tld_variant_allowlist': src.get('tld_variant_allowlist', DEFAULT_CONFIG.get('tld_variant_allowlist', [])),
        'spoofing_allowlist': src.get('spoofing_allowlist', DEFAULT_CONFIG.get('spoofing_allowlist', [])),
        'blocked_asn_orgs': src.get('blocked_asn_orgs', DEFAULT_CONFIG.get('blocked_asn_orgs', [])),
        'blocked_asn_org_score': src.get('blocked_asn_org_score', DEFAULT_CONFIG.get('blocked_asn_org_score', 100)),
    }
    
    res = DomainApprovalResult(domain=domain)
    res.scan_timestamp = datetime.now(timezone.utc).isoformat()
    
    # DNS Resolution — with root domain fallback for subdomains
    try:
        res.ip_address = socket.gethostbyname(domain)
        res.resolved = True
    except:
        # v7.5.1: If a subdomain doesn't resolve, try the registrable root domain.
        # e.g., mailing.aeins.de → aeins.de, newsletter.example.com → example.com
        # This catches cases the app.py prefix stripper misses.
        _root = get_registrable_domain(domain)
        if _root and _root.lower() != domain.lower().rstrip('.'):
            try:
                _root_ip = socket.gethostbyname(_root)
                # Root resolves — analyze that instead
                _original_submitted = domain
                res.domain = _root
                res.ip_address = _root_ip
                res.resolved = True
                # Update the working domain variable for the rest of the function
                domain = _root
                # Note the fallback in summary so operators see what happened
                res.analyzed_root_note = f"📌 ANALYZED ROOT: {_root} (submitted: {_original_submitted} does not resolve)"
            except:
                pass
        
        if not res.resolved:
            # v8.0: Mail-only domain detection — before hard DENY, check if domain has valid MX records.
            # Email-only domains (no website, no A record) are legitimate for customers who only
            # need to send email. If valid MX exists, continue with DNS-only scoring instead of denying.
            _mail_only_mx_exists, _mail_only_mx_records, _mail_only_mx_is_null = get_mx(domain)
            if _mail_only_mx_exists and not _mail_only_mx_is_null:
                # Domain has valid MX — treat as mail-only domain
                res.is_mail_only_domain = True
                res.mail_only_mx_records = ";".join(f"{p}:{h}" for p, h in _mail_only_mx_records)
                res.mail_only_mx_provider_type = classify_mx_provider(_mail_only_mx_records, domain, config)
                res.mail_only_note = (
                    f"📧 MAIL-ONLY DOMAIN: {domain} has no A record but has valid MX "
                    f"({res.mail_only_mx_provider_type}). Running DNS-based evaluation."
                )
                # Set resolved=True conceptually so we continue, but ip_address stays empty
                # The rest of the function will detect is_mail_only_domain and skip HTTP checks
            else:
                # v8.1: No-resolve domain detection — domain has no A record AND no valid MX.
                # Instead of hard-denying, score using available DNS signals (WHOIS, VT,
                # typosquatting, DNSBL, NS risk, domain patterns). This lets established,
                # clean domains pass while still catching suspicious ones.
                res.is_no_resolve_domain = True
                res.cannot_receive_mail = True
                res.no_resolve_note = (
                    f"🔇 NO-RESOLVE DOMAIN: {domain} has no A record and no valid MX. "
                    f"Cannot receive mail. Running DNS-based evaluation."
                )
    
    # PTR (requires IP — skip for mail-only and no-resolve domains)
    if not res.is_mail_only_domain and not res.is_no_resolve_domain:
        res.ptr_exists, res.ptr_record, res.ptr_matches_forward = get_ptr_record(res.ip_address)
    
    # Domain characteristics
    domain_lower = domain.lower()
    res.is_suspicious_tld = any(domain_lower.endswith(t) for t in config['suspicious_tlds'])
    res.is_retail_scam_tld = any(domain_lower.endswith(t) for t in RETAIL_SCAM_TLDS)
    res.is_free_registration_tld = any(domain_lower.endswith(t) for t in config.get('free_registration_tlds', []))
    res.is_free_email_domain = domain_lower in FREE_EMAIL_PROVIDERS
    res.is_free_hosting = any(p in domain_lower for p in FREE_HOSTING_PATTERNS)
    res.is_url_shortener = domain_lower in URL_SHORTENERS
    res.is_disposable_email = is_disposable_email(domain_lower, config['disposable_domains'])
    res.typosquat_target, res.typosquat_similarity = check_typosquatting(domain, config['protected_brands'])
    res.sld_entropy = calculate_domain_entropy(domain)
    
    # v7.3.1: Homoglyph / IDN spoofing detection
    homoglyph = check_homoglyph_domain(domain, config['protected_brands'])
    res.is_homoglyph_domain = homoglyph["is_homoglyph"]
    res.homoglyph_target = homoglyph["target_brand"]
    res.homoglyph_decoded = homoglyph["decoded_display"]
    
    # Check domain name for tech support scam / brand impersonation patterns
    domain_patterns = check_domain_name_patterns(domain, config)
    res.has_suspicious_prefix = domain_patterns["has_suspicious_prefix"]
    res.suspicious_prefix_found = domain_patterns["suspicious_prefix"]
    res.has_suspicious_suffix = domain_patterns["has_suspicious_suffix"]
    res.suspicious_suffix_found = domain_patterns["suspicious_suffix"]
    res.is_tech_support_tld = domain_patterns["is_tech_support_tld"]
    res.domain_impersonates_brand = domain_patterns["domain_impersonates_brand"]
    res.brand_spoofing_keyword = domain_patterns["brand_spoofing_keyword"]
    res.brand_plus_keyword_domain = domain_patterns["brand_plus_keyword"]
    res.domain_pattern_risk = ";".join(domain_patterns["patterns_found"])
    
    # v7.9: Hyphenated SLD detection
    # Extract the second-level domain (e.g., "hive-flow" from "hive-flow.com") and
    # check for a hyphen.  Hyphens in the SLD are heavily overrepresented in phishing
    # and brand-split domains (pay-pal.com, apple-id-verify.com, hive-flow.com).
    # Subdomains are excluded — "mail.my-company.com" is normal; the check is on the
    # registrable SLD only.
    _registrable = get_registrable_domain(domain)
    if _registrable:
        _sld = _registrable.split('.')[0]  # leftmost label of the registrable domain
        if '-' in _sld:
            res.is_hyphenated_sld = True
    
    # Spoofing allowlist: suppress typosquat, brand impersonation, prefix/suffix
    # signals for domains explicitly cleared by admin review
    spoofing_allowlist = [d.lower().strip() for d in config.get('spoofing_allowlist', [])]
    if domain_lower in spoofing_allowlist or any(domain_lower.endswith('.' + a) for a in spoofing_allowlist):
        res.typosquat_target = ""
        res.typosquat_similarity = 0.0
        res.has_suspicious_prefix = False
        res.suspicious_prefix_found = ""
        res.has_suspicious_suffix = False
        res.suspicious_suffix_found = ""
        res.domain_impersonates_brand = ""
        res.brand_spoofing_keyword = ""
        res.brand_plus_keyword_domain = False
        res.domain_pattern_risk = ""
        res.is_homoglyph_domain = False
        res.homoglyph_target = ""

    # ----------------------------------------------------------------
    # PARALLEL LOOKUPS
    # The next 10+ network calls (email auth, DNSBL, NS, SOA, DNSSEC)
    # are mutually independent. Sequential they cost 5-8s; parallel
    # they're bounded by the slowest single call (~1-2s).
    # Each future is .result()'d at its original call site below, so
    # the rest of analyze_domain stays sequential and ordering-stable.
    # ----------------------------------------------------------------
    _pool = ThreadPoolExecutor(max_workers=14, thread_name_prefix="analyzer-lookups")
    _f_spf = _pool.submit(get_spf, domain)
    _f_dkim = _pool.submit(check_dkim, domain)
    _f_dmarc = _pool.submit(get_dmarc, domain)
    _f_mx = _pool.submit(get_mx, domain)
    _f_bimi = _pool.submit(get_bimi, domain)
    _f_mta_sts = _pool.submit(get_mta_sts, domain)
    _f_domain_bl = _pool.submit(check_domain_blacklists, domain, config['domain_blacklists'])
    _f_ns = _pool.submit(dns_query, domain, 'NS')
    _f_soa = _pool.submit(check_soa_freshness, domain)
    _f_dnssec = _pool.submit(check_dnssec, domain)
    # IP-blacklist check only when we actually resolved an IP and the
    # domain isn't a mail-only / no-resolve special case.
    _f_ip_bl = None
    if res.resolved and res.ip_address and not res.is_mail_only_domain and not res.is_no_resolve_domain:
        _f_ip_bl = _pool.submit(check_ip_blacklists, res.ip_address, config['ip_blacklists'])

    # HTTP/HTTPS probes — the single slowest network operations in the analyzer.
    # They were originally sequential, downstream of the DNS section. Now they
    # run alongside DNS, so the wall-clock cost of the web checks effectively
    # collapses into the DNS time. Read .result() at the original use sites.
    _f_http_head = None
    _f_https_fetch = None
    _f_tls = None
    if not res.is_mail_only_domain and not res.is_no_resolve_domain:
        if REQUESTS_AVAILABLE:
            def _http_head():
                try:
                    return requests.head(
                        f"http://{domain}",
                        timeout=timeout, allow_redirects=False, verify=False,
                    )
                except Exception:
                    return None
            _f_http_head = _pool.submit(_http_head)
        _f_https_fetch = _pool.submit(follow_redirects, f"https://{domain}", timeout, True)
        _f_tls = _pool.submit(check_tls, domain, timeout)

    # SPF
    spf_record, spf_exists, spf_parsed = _f_spf.result()
    res.spf_record = spf_record[:500]
    res.spf_exists = spf_exists
    if spf_exists:
        res.spf_mechanism = spf_parsed.get("mechanism", "")
        res.spf_includes = ";".join(spf_parsed.get("includes", []))
        res.spf_lookup_count = spf_parsed.get("lookups", 0)
        res.spf_syntax_valid = spf_parsed.get("valid", True)
        # Check if SPF includes any real external email provider
        KNOWN_SPF_PROVIDERS = [
            '_spf.google.com', 'google.com', 'googlemail.com',
            'spf.protection.outlook.com', 'outlook.com', 'microsoft.com',
            'amazonses.com', 'sendgrid.net', 'mailgun.org', 'mandrillapp.com',
            'mailchimp.com', 'postmarkapp.com', 'sparkpostmail.com',
            'zoho.com', 'zoho.eu', 'fastmail.com', 'messagingengine.com',
            'icloud.com', 'apple.com', 'protonmail.ch',
            'mimecast.com', 'pphosted.com', 'fireeyecloud.com',
            'secureserver.net', 'emailsrvr.com', 'hostinger.com',
            'ovh.net', 'gandi.net', 'ionos.com',
        ]
        includes_list = spf_parsed.get("includes", [])
        res.spf_has_external_includes = any(
            any(provider in inc.lower() for provider in KNOWN_SPF_PROVIDERS)
            for inc in includes_list
        )
    
    # DKIM
    res.dkim_exists, dkim_selectors = _f_dkim.result()
    res.dkim_selectors_found = ";".join(dkim_selectors)

    # DMARC
    dmarc_record, dmarc_exists, dmarc_parsed = _f_dmarc.result()
    res.dmarc_record = dmarc_record[:500]
    res.dmarc_exists = dmarc_exists
    if dmarc_exists:
        res.dmarc_policy = dmarc_parsed.get("policy", "")
        res.dmarc_pct = dmarc_parsed.get("pct", 100)
        res.dmarc_rua = dmarc_parsed.get("rua", "")
    
    # MX
    res.mx_exists, mx_records, res.mx_is_null = _f_mx.result()
    if mx_records:
        res.mx_records = ";".join([f"{p}:{h}" for p, h in mx_records])
        res.mx_primary = mx_records[0][1] if mx_records else ""
        free_mx = ['google.com', 'googlemail.com', 'yahoodns', 'outlook.com']
        res.mx_uses_free_provider = any(f in res.mx_primary.lower() for f in free_mx)
        res.mx_provider_type = classify_mx_provider(mx_records, domain, config)
        # Detect mail.{domain} template fingerprint — common in phishing infrastructure
        domain_lower = domain.lower()
        res.mx_is_mail_prefix = any(
            h.lower() == f"mail.{domain_lower}" for _, h in mx_records
        )
    
    # v7.3.1: MX hijack fingerprint — detect enterprise provider ghosts in DNS
    spf_inc_list = spf_parsed.get("includes", []) if spf_exists else []
    mx_hijack = detect_mx_provider_mismatch(
        spf_includes=spf_inc_list,
        dkim_selectors=dkim_selectors,
        mx_provider_type=res.mx_provider_type,
        mx_primary=res.mx_primary,
        domain_age_days=res.domain_age_days,
        whois_recently_updated=res.whois_recently_updated,
    )
    if mx_hijack["mismatch"]:
        res.mx_provider_mismatch = True
        res.mx_ghost_provider = mx_hijack["ghost_provider"]
        res.mx_ghost_evidence = ";".join(mx_hijack["evidence"])
        res.mx_hijack_confidence = mx_hijack["confidence"]
    
    # BIMI
    res.bimi_exists, res.bimi_record = _f_bimi.result()

    # MTA-STS
    res.mta_sts_exists, res.mta_sts_record = _f_mta_sts.result()

    # Blacklists (v6.2: now tracks inconclusive checks)
    bl_hits, bl_count, bl_inconclusive = _f_domain_bl.result()
    res.domain_blacklists_hit = ";".join(bl_hits)
    res.domain_blacklist_count = bl_count
    res.domain_blacklist_inconclusive = bl_inconclusive

    # IP blacklists and hosting detection require an IP address — skip for mail-only and no-resolve domains
    if not res.is_mail_only_domain and not res.is_no_resolve_domain and _f_ip_bl is not None:
        ip_bl_hits, ip_bl_count, ip_bl_inconclusive = _f_ip_bl.result()
        res.ip_blacklists_hit = ";".join(ip_bl_hits)
        res.ip_blacklist_count = ip_bl_count
        res.ip_blacklist_inconclusive = ip_bl_inconclusive

    # Hosting Provider Detection
    ns_records = _f_ns.result()
    if not res.is_mail_only_domain and not res.is_no_resolve_domain:
        hosting_result = check_hosting_provider(
            domain, res.ip_address,
            ns_records=ns_records,
            ptr_record=res.ptr_record,
            hosting_config=config
        )
        res.hosting_provider = hosting_result["provider"]
        res.hosting_provider_type = hosting_result["provider_type"]
        res.hosting_detected_via = hosting_result["detected_via"]
        res.hosting_asn = hosting_result["asn"]
        res.hosting_asn_org = hosting_result["asn_org"]
    
    # v7.3.1: CDN Provider Detection (requires IP/ASN — skip for mail-only and no-resolve)
    if not res.is_mail_only_domain and not res.is_no_resolve_domain:
        res.is_cdn_hosted, res.cdn_provider = detect_cdn_hosted(res.hosting_asn)

    # v7.3.1: Subdomain Delegation Abuse Detection (requires IP — skip for mail-only and no-resolve)
    if not res.is_mail_only_domain and not res.is_no_resolve_domain:
        sub_result = detect_subdomain_delegation_abuse(
            submitted_domain=domain,
            submitted_ip=res.ip_address,
            submitted_asn=res.hosting_asn,
            submitted_mx_provider_type=res.mx_provider_type,
            config=config,
        )
        res.is_subdomain = sub_result["is_subdomain"]
        res.parent_domain = sub_result["parent_domain"]
        res.parent_ip = sub_result["parent_ip"]
        res.parent_asn = sub_result["parent_asn"]
        res.parent_asn_org = sub_result["parent_asn_org"]
        res.parent_mx_provider_type = sub_result["parent_mx_provider_type"]
        if sub_result["divergent"]:
            res.subdomain_infra_divergent = True
            res.subdomain_divergence_evidence = ";".join(sub_result["evidence"])
            res.subdomain_divergence_confidence = sub_result["confidence"]
    
    # === STAGING / SDLC SUBDOMAIN DETECTION ===
    # Prefixes that unambiguously indicate a non-production environment:
    # stg/staging, dev/development, test/testing, uat, qa, sandbox, preview, demo, preprod.
    # These subdomains are expected to diverge from parent IP/ASN (different hosting),
    # have no email authentication (staging envs don't send email), and may have
    # placeholder content.  Scoring those signals as risk on a staging domain creates
    # FPs for every legitimate SaaS/enterprise that uses environment-specific subdomains.
    _STAGING_PREFIXES = {
        "stg", "staging", "stage",
        "dev", "develop", "development",
        "test", "testing",
        "uat", "qa",
        "sandbox",
        "preview",
        "demo",
        "preprod", "pre-prod", "pre-production",
        "local",
    }
    if res.is_subdomain and res.parent_domain:
        _subdomain_label = domain.lower().rstrip('.')
        # Remove parent suffix to get the leftmost label(s): stg.emersonhealth.com.br → stg
        _sub_prefix = _subdomain_label[:_subdomain_label.rfind('.' + res.parent_domain)].split('.')[0]
        if _sub_prefix in _STAGING_PREFIXES:
            res.is_staging_subdomain = True
    
    # Nameserver Risk Detection
    ns_risk_config = config.get("ns_risk_patterns", {})
    ns_risk = check_ns_risk(ns_records, ns_risk_config)
    res.ns_records = ";".join(ns_records)
    res.ns_count = ns_risk["ns_count"]
    res.ns_is_parking = ns_risk["is_parking"]
    res.ns_parking_match = ns_risk["parking_match"]
    res.ns_is_dynamic_dns = ns_risk["is_dynamic_dns"]
    res.ns_dynamic_dns_match = ns_risk["dynamic_dns_match"]
    res.ns_is_free_dns = ns_risk["is_free_dns"]
    res.ns_free_dns_match = ns_risk["free_dns_match"]
    res.ns_is_lame_delegation = ns_risk["is_lame_delegation"]
    res.ns_is_single_ns = ns_risk["is_single_ns"]
    res.ns_is_enterprise = ns_risk["is_enterprise_ns"]
    res.ns_enterprise_match = ns_risk.get("enterprise_ns_match", "")

    # v8.1: SOA freshness check (DNS-only, runs for all domains)
    soa = _f_soa.result()
    res.soa_exists = soa["soa_exists"]
    res.soa_serial = soa["soa_serial"]
    res.soa_serial_is_date = soa["soa_serial_is_date"]
    res.soa_serial_date = soa["soa_serial_date"]
    res.soa_days_since_serial = soa["soa_days_since_serial"]

    # v8.1: DNSSEC check (DNS-only, runs for all domains)
    res.dnssec_enabled = _f_dnssec.result()

    # All parallel lookups consumed — release the pool's threads.
    _pool.shutdown(wait=False)

    # === WEB CHECKS (TLS, HTTP, content, hacklink, etc.) ===
    # Mail-only and no-resolve domains have no A record / website — skip all web-dependent checks.
    # DNS-only checks (VT, RDAP/WHOIS) run separately after this block.
    content = None  # Initialize for mail-only/no-resolve path (used by later sections)
    if not res.is_mail_only_domain and not res.is_no_resolve_domain:
        # TLS — v4.4: now captures handshake_failed and connection_failed separately
        tls = _f_tls.result() if _f_tls is not None else check_tls(domain, timeout)
        res.https_valid = tls["ok"]
        res.tls_error = tls["error"]
        res.tls_handshake_failed = tls["handshake_failed"]       # v4.4
        res.tls_connection_failed = tls["connection_failed"]     # v4.4
        res.cert_self_signed = tls["self_signed"]
        res.cert_expired = tls["expired"]
        res.cert_wrong_host = tls["wrong_host"]
        
        # HTTP check (consumes the future submitted up-front)
        if REQUESTS_AVAILABLE and _f_http_head is not None:
            r = _f_http_head.result()
            if r is not None:
                res.http_reachable = r.status_code in [200, 301, 302, 307, 308]
                res.http_status = r.status_code

        # HTTPS with redirects + content (consumes the future submitted up-front)
        https_result = _f_https_fetch.result() if _f_https_fetch is not None else follow_redirects(f"https://{domain}", timeout, fetch_content=True)
        res.https_reachable = https_result["ok"]
        res.https_status = https_result["initial_status"]
        res.redirect_count = https_result["hops"]
        res.redirect_chain = "→".join(str(s) for s in https_result["chain"])
        res.redirect_domains = "→".join(https_result["domains"])
        res.redirect_cross_domain = https_result["cross_domain"]
        res.redirect_uses_temp = https_result["uses_temp"]
        res.final_url = https_result["final_url"]
        res.content_length = https_result["content_length"]
        
        all_statuses = https_result["all_statuses"]
        res.status_codes_seen = ";".join(str(s) for s in sorted(all_statuses) if s > 0)
        res.has_401 = 401 in all_statuses
        res.has_403 = 403 in all_statuses
        res.has_429 = 429 in all_statuses
        res.has_503 = 503 in all_statuses
        res.has_5xx = bool(all_statuses & {500, 502, 504})
        
        # Access restriction detection - 401 on what should be a public site is suspicious
        # NOTE: 403 is intentionally excluded — too many FPs from Cloudflare/WAF bot protection.
        # A legitimate domain like bahcemarket.com (21yr, VT clean, App Store) gets 403 from
        # Cloudflare when our scanner hits it; that's not a fraud signal.
        if res.has_401:
            res.is_access_restricted = True
            res.access_restriction_note = "401 Unauthorized - requires authentication for public site"
        
        # Content analysis
        content = https_result["content"]
        if not content and res.http_reachable:
            http_result = follow_redirects(f"http://{domain}", timeout, fetch_content=True)
            content = http_result["content"]
            res.content_length = http_result["content_length"]
        
        # === EMPTY PAGE DETECTION ===
        # A reachable domain that returns empty/near-empty content is suspicious
        # (parked, abandoned, or stripped after compromise)
        # But 403/5xx responses aren't "empty" — they're blocked/broken, different signal
        if res.https_reachable or res.http_reachable:
            if not (res.is_access_restricted or res.has_5xx or res.has_503):
                if not content or len(content.strip()) < 50:
                    res.is_empty_page = True
        
        if content:
            res.content_hash = hashlib.md5(content).hexdigest()[:12]
            ca = analyze_content(content, res.final_url, domain)
            res.is_minimal_shell = ca["minimal_shell"]
            res.has_js_redirect = ca["js_redirect"]
            res.has_meta_refresh = ca["meta_refresh"]
            res.has_external_js = ca["external_js"]
            res.has_obfuscation = ca["obfuscation"]
            res.has_credential_form = ca["credential_form"]
            res.has_sensitive_fields = ca["sensitive_fields"]
            res.brands_detected = ";".join(ca["brands"])
            res.form_posts_external = ca["form_external"]
            res.malware_links_found = ";".join(ca["malware"])
            res.has_suspicious_iframe = ca["suspicious_iframe"]
            res.is_parking_page = ca["parking"]
            res.phishing_paths_found = ";".join(ca["phishing_paths"])
            
            # === PARKING PAGE FALSE POSITIVE SUPPRESSION (v7.5) ===
            # Parking pages (HugeDomains, Sedo, GoDaddy, etc.) contain brand references
            # from payment processing (Chase, PayPal, Stripe) and purchase forms that
            # POST to the parking provider domain.  These trigger brand_impersonation +
            # form_posts_external, which fires the phishing kit composite = false autofail.
            #
            # When parking is confirmed, suppress:
            #   1. brands_detected — payment processor refs are not impersonation
            #   2. form_posts_external — only if form target is a known parking domain
            if res.is_parking_page:
                # Suppress brand detection entirely on parking pages
                if res.brands_detected:
                    res.brands_detected = ""
                
                # Suppress form_posts_external if the target is a known parking domain
                if res.form_posts_external:
                    _form_actions = re.findall(
                        rb'<form[^>]+action=["\']([^"\']+)["\']',
                        content.lower() if isinstance(content, bytes) else content.encode().lower()
                    )
                    _all_parking = True
                    for _fa in _form_actions:
                        try:
                            _fa_url = _fa.decode('utf-8', errors='ignore')
                            if _fa_url.startswith(('http://', 'https://')):
                                _fa_host = urlparse(_fa_url).netloc.lower()
                                if _fa_host and _fa_host != urlparse(res.final_url).netloc.lower():
                                    if _fa_host not in KNOWN_PARKING_DOMAINS:
                                        _all_parking = False
                                        break
                        except Exception:
                            pass
                    if _all_parking:
                        res.form_posts_external = False
            
            # Phishing kit detection (v7.3)
            if ca["kit_filename"]:
                res.has_phishing_kit_filename = True
                res.phishing_kit_filename = ca["kit_filename"]
                res.phishing_kit_filename_strong = ca["kit_filename_strong"]
            if ca["exfil_signals"]:
                res.has_exfil_drop_script = True
                res.exfil_drop_signals = ";".join(ca["exfil_signals"])
                res.exfil_drop_details = ";".join(ca["exfil_details"])
            
            # Client-side harvest detection (v7.5)
            if ca["harvest_signals"]:
                res.has_harvest_signals = True
                res.harvest_signals = ";".join(ca["harvest_signals"])
                res.harvest_details = ";".join(ca["harvest_details"])
            if ca["harvest_combo"]:
                res.has_harvest_combo = True
                res.harvest_combo_reason = ca["harvest_combo_reason"]
            
            # v7.4: Form action kit filename + suspicious page title
            if ca["form_action_kit"]:
                res.has_form_action_kit = True
                res.form_action_kit_target = ca["form_action_kit"]
                res.form_action_kit_strong = ca["form_action_kit_strong"]
            if ca["page_title"]:
                res.page_title = ca["page_title"]
            if ca["suspicious_title_match"]:
                res.has_suspicious_page_title = True
                res.page_title_match = ca["suspicious_title_match"]
            
            # v7.3.1: OAuth consent phishing
            if ca.get("oauth_phish"):
                res.has_oauth_phish = True
                res.oauth_phish_evidence = ";".join(ca["oauth_evidence"])
            
            # v7.5.1: Security tooling detection (reCAPTCHA, Cloudflare, hCaptcha, etc.)
            if ca.get("security_signals"):
                res.content_security_signals = ";".join(ca["security_signals"])
        
        # Check for hijacked domain / stepping stone indicators
        redirect_chain_urls = res.redirect_chain.split(' → ') if res.redirect_chain else []
        hijack = check_hijacked_domain_indicators(content, res.final_url, redirect_chain_urls)
        res.has_hijack_path_pattern = hijack["has_hijack_path"]
        res.hijack_path_found = hijack["hijack_path"]
        res.has_doc_sharing_lure = hijack["has_doc_lure"]
        res.doc_lure_found = hijack["doc_lure"]
        res.has_phishing_js_behavior = hijack["has_phishing_js"]
        res.phishing_js_patterns = ";".join(hijack["phishing_js_found"])
        res.redirects_to_phishing_infra = hijack["redirects_to_phishing_infra"]
        res.phishing_infra_domain = hijack["phishing_infra"]
        res.has_email_in_url = hijack["has_email_in_url"]
        res.url_email_tracking = hijack["email_tracking"]
        
        # E-commerce / retail scam detection
        if content:
            ecom = analyze_ecommerce_indicators(content, domain)
            res.is_ecommerce_site = ecom["is_ecommerce"]
            
            res.has_cross_domain_brand_link = len(ecom["cross_domain_brand_links"]) > 0
            res.cross_domain_brand_links = ";".join(ecom["cross_domain_brand_links"])
            
            # Check business identity - especially important for e-commerce
            if ecom["is_ecommerce"]:
                res.missing_business_identity = not ecom["has_business_identity"]
                found_signals = ecom["business_identity_signals"]
                missing_signals = ecom["missing_identity_signals"]
                res.business_identity_signals = f"found:{';'.join(found_signals)}|missing:{';'.join(missing_signals)}"
        
        # Corporate trust signal check - only if we got a 401/403 or couldn't reach the site
        # A domain that blocks access AND has no trust pages is highly suspicious
        if res.is_access_restricted or res.is_minimal_shell or not res.https_reachable:
            trust_signals = check_corporate_trust_signals(domain, timeout=3.0)
            res.trust_pages_checked = ";".join(trust_signals["pages_checked"])
            res.trust_pages_found = ";".join(trust_signals["pages_found"])
            res.missing_trust_signals = trust_signals["missing_trust_signals"]
            
            # If access is restricted AND no trust signals found, mark as opaque entity
            if res.is_access_restricted and res.missing_trust_signals:
                res.is_opaque_entity = True
        
        # App Store Presence Detection (legitimacy signal)
        if APP_STORE_DETECTION_AVAILABLE:
            try:
                app_result = check_app_store_presence(domain, content=content, timeout=5.0)
                res.app_store_has_presence = app_result.get("has_any_app_presence", False)
                res.app_store_confidence = app_result.get("confidence", "none")
                res.app_store_ios_verified = app_result.get("ios_aasa", {}).get("exists", False)
                res.app_store_android_verified = app_result.get("android_asset_links", {}).get("exists", False)
                res.app_store_page_links = app_result.get("has_app_store_links", False)
                res.app_store_itunes_match = app_result.get("has_itunes_match", False)
                res.app_store_ios_app_ids = app_result.get("app_store_ios_app_ids", "")
                res.app_store_android_packages = app_result.get("app_store_android_packages", "")
                res.app_store_methods_found = app_result.get("app_store_methods_found", "")
                res.app_store_summary = " | ".join(app_result.get("summary_lines", []))
            except Exception:
                pass  # Non-critical — don't break analysis if app store check fails
        
        # TLD Variant Spoofing Detection
        # Check if signup domain is a TLD variant of an established business
        # e.g., gordondown.uk spoofing gordondown.co.uk
        try:
            tld_variant = check_tld_variant_spoofing(domain, signup_content=content, timeout=timeout)
            res.tld_variant_detected = tld_variant["tld_variant_detected"]
            res.tld_variant_domain = tld_variant["variant_domain"]
            res.tld_variant_has_content = tld_variant["variant_has_content"]
            res.tld_variant_has_email_infra = tld_variant["variant_has_email_infra"]
            res.tld_variant_domain_age_days = tld_variant["variant_domain_age_days"]
            res.tld_variant_content_words = tld_variant["variant_content_words"]
            res.tld_variant_signup_content_words = tld_variant["signup_content_words"]
            res.tld_variant_summary = tld_variant["summary"]
            
            # TLD variant allowlist: suppress for domains explicitly cleared by admin review
            tld_variant_allowlist = [d.lower().strip() for d in config.get('tld_variant_allowlist', [])]
            if res.tld_variant_detected:
                if domain_lower in tld_variant_allowlist or any(domain_lower.endswith('.' + a) for a in tld_variant_allowlist):
                    res.tld_variant_detected = False
                    res.tld_variant_summary = f"ALLOWLISTED — {res.tld_variant_domain} variant suppressed by admin"
            
            # v7.5.1: UK TLD variant dark detection
            # When a .co.uk variant has NO DNS, this is an infrastructure signal:
            # - On ESTABLISHED domains: suggests domain takeover or shell domain where
            #   the .co.uk was abandoned/never held by the attacker
            # - On NEW domains: expected behavior (owner only registered .com)
            summary_lower = (res.tld_variant_summary or "").lower()
            if "co.uk: no dns" in summary_lower or ".co.uk: no dns" in summary_lower:
                # Extract the dark variant domain from the summary
                import re as _re_uk
                _uk_match = _re_uk.search(r'(\S+\.co\.uk):\s*no dns', summary_lower)
                if _uk_match:
                    res.tld_variant_uk_no_dns = True
                    res.tld_variant_uk_no_dns_domain = _uk_match.group(1)
        except Exception as e:
            # Surface error in results so it's visible during debugging
            res.tld_variant_summary = f"CHECK ERROR: {type(e).__name__}: {str(e)[:200]}"
        
        # === VIRUSTOTAL REPUTATION CHECK ===
        # Uses the VT API to check domain reputation across 70+ security vendors
        vt_api_key = src.get('vt_api_key', '') or os.environ.get('VT_API_KEY', '')
        if VT_CHECKER_AVAILABLE and vt_api_key:
            try:
                vt = VirusTotalChecker(api_key=vt_api_key)
                vt_result = vt.check_domain(domain)
                res.vt_available = vt_result.get("vt_available", False)
                res.vt_malicious_count = vt_result.get("malicious_count", 0)
                res.vt_suspicious_count = vt_result.get("suspicious_count", 0)
                res.vt_total_vendors = vt_result.get("total_vendors", 0)
                res.vt_detection_rate = vt_result.get("detection_rate", 0.0)
                res.vt_community_score = vt_result.get("community_score", 0)
                res.vt_reputation = vt_result.get("reputation", 0)
                res.vt_threat_names = ";".join(vt_result.get("threat_names", []))
                res.vt_malicious_vendors = ";".join(vt_result.get("malicious_vendors", []))
                res.vt_categories = json.dumps(vt_result.get("categories", {}))
                res.vt_last_analysis = vt_result.get("last_analysis_date", "") or ""
            except Exception:
                pass  # Non-critical — don't break analysis if VT check fails
        
        # === HACKLINK / SEO SPAM DETECTION ===
        # Scans page content for Turkish hacklink injection, gambling keywords, 
        # WordPress compromise indicators, and hidden SEO spam
        if HACKLINK_SCANNER_AVAILABLE:
            try:
                hl_scanner = HacklinkKeywordScanner(timeout=int(timeout))
                # Pass pre-fetched content to avoid double-fetching
                content_str = content.decode('utf-8', errors='replace') if isinstance(content, bytes) else content
                hl_result = hl_scanner.scan(domain, content=content_str)
                res.hacklink_detected = hl_result.get("hacklink_detected", False)
                res.hacklink_score = hl_result.get("score", 0)
                res.hacklink_keywords = ";".join(hl_result.get("keywords_found", []))
                res.hacklink_injection_patterns = ";".join(hl_result.get("injection_patterns", []))
                res.hacklink_is_wordpress = hl_result.get("is_wordpress", False)
                res.hacklink_wp_compromised = hl_result.get("wp_compromised", False)
                vuln_plugins = hl_result.get("vulnerable_plugins", [])
                if vuln_plugins:
                    res.hacklink_vulnerable_plugins = ";".join(
                        f"{p.get('plugin','')}({p.get('risk','')})" if isinstance(p, dict) else str(p)
                        for p in vuln_plugins
                    )
                res.hacklink_spam_link_count = hl_result.get("spam_link_count", 0)
                spam_urls = hl_result.get("spam_link_urls", [])
                if spam_urls:
                    res.hacklink_spam_links_found = ";".join(spam_urls[:20])
                
                # === Extract sub-signals for individual scoring ===
                res.hacklink_is_cpanel = hl_result.get("is_cpanel", False)
                
                # Parse injection_patterns for malicious_script and hidden_injection flags
                inj_patterns = hl_result.get("injection_patterns", [])
                # v7.2: Use multi-signal confidence instead of binary pattern matching
                ms_confidence = hl_result.get("malicious_script_confidence", "NONE")
                res.hacklink_malicious_script = ms_confidence in ("HIGH", "MEDIUM")
                res.hacklink_malicious_script_confidence = ms_confidence
                ms_signals = hl_result.get("malicious_script_signals", [])
                res.hacklink_malicious_script_signals = ";".join(ms_signals) if ms_signals else ""
                res.hacklink_malicious_script_score = hl_result.get("malicious_script_score", 0)
                res.hacklink_hidden_injection = any("hidden_content" in p for p in inj_patterns)
                res.hacklink_hidden_injection_confidence = hl_result.get("hidden_injection_confidence", "")
                
                # Suspicious external scripts
                sus_scripts = hl_result.get("suspicious_scripts", [])
                if sus_scripts:
                    res.hacklink_suspicious_scripts = ";".join(sus_scripts[:10])
            except Exception:
                pass  # Non-critical — don't break analysis if hacklink check fails
        
        # === ECOMMERCE DETECTION VIA WOOCOMMERCE PLUGIN (v7.5.1) ===
        # The hacklink scanner detects WP plugins (including WooCommerce) during its
        # scan.  If content-based ecommerce detection missed it (e.g., TLS failure
        # preventing full page render), WooCommerce in the plugin list confirms it.
        if not res.is_ecommerce_site and res.hacklink_vulnerable_plugins:
            if "woocommerce" in res.hacklink_vulnerable_plugins.lower():
                res.is_ecommerce_site = True
        
        # === ECOMMERCE SHIPPING BRAND SUPPRESSION (v7.5.1) ===
        # On confirmed e-commerce sites with established domains (90+ days),
        # shipping/logistics brand mentions (UPS, FedEx, DHL, USPS) are expected
        # business content, not brand impersonation.  Strip shipping-only brands
        # from brands_detected to prevent combo rules from cascading
        # (brand_imp + cred_form = 20pts, brand_imp + no_https = 20pts).
        # If non-shipping brands are also present (e.g., "paypal"), keep those.
        # MUST run after both ecommerce detection AND hacklink scanner (for WooCommerce).
        if res.is_ecommerce_site and res.brands_detected:
            _ecom_age_ok = res.domain_age_days < 0 or res.domain_age_days >= 90
            if _ecom_age_ok:
                _detected_brands = [b.strip().lower() for b in res.brands_detected.split(";") if b.strip()]
                _non_shipping = [b for b in _detected_brands if b not in ECOMMERCE_SHIPPING_BRANDS]
                if _non_shipping:
                    res.brands_detected = ";".join(_non_shipping)
                else:
                    res.brands_detected = ""
        
        # === PARKING PAGE SIGNAL SUPPRESSION (v7.5.1) ===
        # Parking pages (HugeDomains, Sedo, etc.) generate false signals from the parking
        # provider's template.  The scoring suppression in calculate_score() prevents points,
        # but the RAW BOOLEANS still leak into UI threat indicators and pattern displays.
        # Clear them here so the entire pipeline sees clean data.
        if res.is_parking_page:
            # Malicious script: CookieYes/HugeDomains analytics scripts → SocGholish FP
            if res.hacklink_malicious_script:
                _ext = [d.strip().lower() for d in
                        (res.content_external_script_domains or "").split(";") if d.strip()]
                if _ext:
                    _unknown = [d for d in _ext if d not in KNOWN_PARKING_SCRIPT_DOMAINS]
                    if not _unknown:
                        res.hacklink_malicious_script = False
                        res.hacklink_malicious_script_confidence = ""
                        res.hacklink_malicious_script_signals = ""
                        res.hacklink_malicious_script_score = 0
                else:
                    _ms_sigs = set((res.hacklink_malicious_script_signals or "").split(";"))
                    if _ms_sigs.issubset({"UNKNOWN_EXTERNAL_SCRIPT", "HIGH_ENTROPY_PATH",
                                          "JQUERY_MASQUERADE", ""}):
                        res.hacklink_malicious_script = False
                        res.hacklink_malicious_script_confidence = ""
                        res.hacklink_malicious_script_signals = ""
                        res.hacklink_malicious_script_score = 0
            
            # UK variant dark: parking domain is for sale — .co.uk is irrelevant
            if res.tld_variant_uk_no_dns:
                res.tld_variant_uk_no_dns = False
                res.tld_variant_uk_no_dns_domain = ""
            
            # Hidden injection: parking template CSS (display:none for menus/modals)
            # Only suppress LOW confidence (no hidden links = just CSS patterns)
            if res.hacklink_hidden_injection and res.hacklink_hidden_injection_confidence == "LOW":
                res.hacklink_hidden_injection = False
                res.hacklink_hidden_injection_confidence = ""
        
        # === CONTENT IDENTITY VERIFICATION ===
        # Scans page content for identity mismatches, cloned content, cross-domain
        # email references, domain broker facades, and placeholder pages.
        # Reuses pre-fetched content — no duplicate HTTP requests.
        if CONTENT_CHECKS_AVAILABLE:
            try:
                content_str = content.decode('utf-8', errors='replace') if isinstance(content, bytes) else content
                cc = check_content_identity(domain, content=content_str)
                res.content_title_body_mismatch = cc.get("title_body_mismatch", False)
                res.content_title_body_detail = cc.get("title_body_mismatch_detail", "")
                xd_emails = cc.get("cross_domain_emails", [])
                if xd_emails:
                    res.content_cross_domain_emails = ";".join(xd_emails[:10])
                xd_domains = cc.get("cross_domain_email_domains", [])
                if xd_domains:
                    res.content_cross_domain_email_domains = ";".join(xd_domains[:10])
                priv_emails = cc.get("page_privacy_emails", [])
                if priv_emails:
                    res.content_page_privacy_emails = ";".join(priv_emails[:10])
                free_emails = cc.get("page_freemail_contacts", [])
                if free_emails:
                    res.content_page_freemail_contacts = ";".join(free_emails[:10])
                res.content_is_broker_page = cc.get("is_broker_page", False)
                broker_ind = cc.get("broker_indicators", [])
                if broker_ind:
                    res.content_broker_indicators = ";".join(broker_ind[:10])
                res.content_is_placeholder = cc.get("is_placeholder", False)
                page_emails = cc.get("page_emails", [])
                if page_emails:
                    res.content_page_emails = ";".join(page_emails[:20])
                page_phones = cc.get("page_phones", [])
                if page_phones:
                    res.content_page_phones = ";".join(page_phones[:10])
                res.content_identity_hash = cc.get("content_hash", "")
                res.content_structure_hash = cc.get("structure_hash", "")
                res.content_is_facade = cc.get("is_content_facade", False)
                res.content_facade_detail = cc.get("facade_detail", "")
                res.content_spa_framework_detected = cc.get("spa_framework_detected", False)
                res.content_spa_framework_name = cc.get("spa_framework_name", "")
                ext_scripts = cc.get("external_script_domains", [])
                if ext_scripts:
                    res.content_external_script_domains = ";".join(ext_scripts[:10])
                ext_links = cc.get("external_link_domains", [])
                if ext_links:
                    res.content_external_link_domains = ";".join(ext_links[:20])
                res.content_visible_word_count = cc.get("visible_word_count", -1)
            except Exception:
                pass  # Non-critical — don't break analysis if content check fails
        
        # === CONTACT CROSS-REFERENCE (OSINT) ===
        # Search web for emails/phones found on the page appearing on other domains.
        # Informational only — helps analysts spot coordinated campaigns.
        try:
            from .contact_osint import search_contact_reuse
            import json as _json
            _emails = res.content_page_emails.split(";") if res.content_page_emails else []
            _phones = res.content_page_phones.split(";") if res.content_page_phones else []
            if _emails or _phones:
                _osint = search_contact_reuse(_emails, _phones, domain, timeout=8)
                if _osint.get("matches"):
                    res.contact_reuse_results = _json.dumps(_osint)
        except Exception:
            pass  # Non-critical — never break analysis for OSINT lookup failure
    
    # === VIRUSTOTAL FOR MAIL-ONLY AND NO-RESOLVE DOMAINS ===
    # VT is DNS-based (no HTTP needed) — run it for mail-only and no-resolve domains too
    if res.is_mail_only_domain or res.is_no_resolve_domain:
        vt_api_key = src.get('vt_api_key', '') or os.environ.get('VT_API_KEY', '')
        if VT_CHECKER_AVAILABLE and vt_api_key:
            try:
                vt = VirusTotalChecker(api_key=vt_api_key)
                vt_result = vt.check_domain(domain)
                res.vt_available = vt_result.get("vt_available", False)
                res.vt_malicious_count = vt_result.get("malicious_count", 0)
                res.vt_suspicious_count = vt_result.get("suspicious_count", 0)
                res.vt_total_vendors = vt_result.get("total_vendors", 0)
                res.vt_detection_rate = vt_result.get("detection_rate", 0.0)
                res.vt_community_score = vt_result.get("community_score", 0)
                res.vt_reputation = vt_result.get("reputation", 0)
                res.vt_threat_names = ";".join(vt_result.get("threat_names", []))
                res.vt_malicious_vendors = ";".join(vt_result.get("malicious_vendors", []))
                res.vt_categories = json.dumps(vt_result.get("categories", {}))
                res.vt_last_analysis = vt_result.get("last_analysis_date", "") or ""
            except Exception:
                pass

    # RDAP
    if check_rdap:
        res.rdap_created, res.domain_age_days, _is_rereg, _rereg_date = rdap_lookup(domain, timeout)
        if res.domain_age_days >= 0:
            res.domain_age_source = "rdap"
        if _is_rereg:
            res.domain_reregistered = True
            res.domain_reregistered_date = _rereg_date
            if _rereg_date:
                try:
                    _rd = datetime.fromisoformat(_rereg_date)
                    res.domain_reregistered_days = (datetime.now(timezone.utc) - _rd).days
                except Exception:
                    pass
    
    # WHOIS fallback if RDAP returned no creation date
    if check_rdap and res.domain_age_days < 0:
        res.whois_created, res.domain_age_days = whois_lookup(domain)
        if res.domain_age_days >= 0:
            res.domain_age_source = "whois"
    
    # v7.5.1: Direct socket WHOIS fallback for TLDs not covered by RDAP/python-whois
    # (e.g., .ng, .ke, .gh, .pk — many African and Asian ccTLDs)
    if check_rdap and res.domain_age_days < 0:
        _sock_created, _sock_age = whois_socket_lookup(domain)
        if _sock_age >= 0:
            res.domain_age_days = _sock_age
            res.whois_created = _sock_created
            res.domain_age_source = "whois_socket"
    
    # v7.5.1: HTTP WHOIS fallback — queries web-based WHOIS services over HTTPS.
    # This is the final fallback when port 43 is blocked (e.g., Streamlit Cloud).
    if check_rdap and res.domain_age_days < 0:
        _http_created, _http_age = whois_http_lookup(domain, timeout=min(timeout, 8.0))
        if _http_age >= 0:
            res.domain_age_days = _http_age
            res.whois_created = _http_created
            res.domain_age_source = "whois_http"
    
    # Both RDAP and WHOIS failed — cannot determine domain age/registrar
    # Legitimate domains almost always have accessible registration data.
    # EXCEPTION: European ccTLDs (.de, .eu, .fr, .nl, etc.) suppress registration
    # data by default under GDPR — this is registry policy, not owner obfuscation.
    if check_rdap and res.domain_age_days < 0 and not res.domain_age_source:
        _domain_tld = '.' + domain.lower().rsplit('.', 1)[-1] if '.' in domain else ''
        if _domain_tld not in GDPR_RESTRICTED_TLDS:
            res.registration_opaque = True
        # else: GDPR ccTLD — expected behavior, don't flag
    
    # === WHOIS ENRICHMENT (transfer lock, registrar, update recency) ===
    if check_rdap:
        try:
            we = whois_enrich(domain)
            res.whois_registrar = we["registrar"]
            res.whois_statuses = ";".join(we["statuses"])
            res.whois_updated = we["updated_date"]
            res.whois_recently_updated_days = we["updated_days_ago"]
            res.domain_transfer_locked = we["transfer_locked"]
            # v7.4: WHOIS privacy detection
            res.whois_privacy = we.get("privacy", False)
            res.whois_privacy_service = we.get("privacy_service", "")
            # Recently-added lock on established domain = post-compromise lockdown signal
            # Lock present + WHOIS updated ≤90 days + domain >1yr old
            if (we["transfer_locked"] and 
                we["updated_days_ago"] >= 0 and we["updated_days_ago"] <= 90 and
                res.domain_age_days >= 365):
                res.domain_transfer_lock_recent = True
            if (we["updated_days_ago"] >= 0 and we["updated_days_ago"] <= 30
                    and res.domain_age_days >= 365):
                res.whois_recently_updated = True
        except Exception:
            pass
    
    # === CERTIFICATE TRANSPARENCY LOG CHECK ===
    try:
        ct = check_cert_transparency(domain, timeout=min(timeout, 8.0))
        res.ct_log_count = ct["ct_count"]
        res.ct_recent_issuance = ct["recent_issuance"]
        res.ct_issuers = ";".join(ct["issuers"])
        res.ct_first_seen = ct["first_seen"]
        res.ct_last_seen = ct["last_seen"]
        res.ct_last_cert_issuer = ct.get("last_cert_issuer", "")
        res.ct_days_since_last_cert = ct.get("days_since_last_cert", -1)
        
        # v7.5.1: CERT ISSUED BUT TLS DEAD
        # A certificate was issued recently (within 90 days) but TLS is now
        # refusing connections or failing handshake.  On established domains this
        # strongly suggests infrastructure disruption: server compromise, hosting
        # migration gone wrong, or domain being stripped post-takeover.
        if res.ct_days_since_last_cert >= 0 and res.ct_days_since_last_cert <= 90:
            if res.tls_connection_failed or res.tls_handshake_failed:
                res.ct_cert_tls_dead = True
                _issuer = res.ct_last_cert_issuer or "unknown issuer"
                _days = res.ct_days_since_last_cert
                _tls_reason = "connection refused" if res.tls_connection_failed else "handshake failed"
                res.ct_cert_tls_dead_detail = (
                    f"Certificate issued {_days}d ago by {_issuer} but TLS {_tls_reason} — "
                    f"infrastructure disrupted since cert issuance"
                )
        
        # v7.3.1: CT gap analysis — detect aged domain purchases
        ct_dates = ct.get("dates", [])
        if ct_dates:
            ct_gap = detect_ct_gap(
                ct_dates=ct_dates,
                domain_age_days=res.domain_age_days,
                ct_recent_issuance=res.ct_recent_issuance,
                whois_recently_updated=res.whois_recently_updated,
            )
            res.ct_gap_months = ct_gap["gap_months"]
            res.ct_reactivated = ct_gap["reactivated"]
            res.ct_gap_evidence = ct_gap["evidence"]
    except Exception:
        pass
    
    # v7.3.1: CDN Tunnel Abuse Detection (needs CT + content analysis results)
    if res.is_cdn_hosted:
        cdn_tunnel = detect_cdn_tunnel_abuse(
            is_cdn=res.is_cdn_hosted,
            cdn_provider=res.cdn_provider,
            domain_age_days=res.domain_age_days,
            ct_log_count=res.ct_log_count,
            ct_recent_issuance=res.ct_recent_issuance,
            has_credential_form=res.has_credential_form,
            has_oauth_phish=res.has_oauth_phish,
            is_minimal_shell=res.is_minimal_shell,
            has_parking=res.is_parking_page,
            has_js_redirect=res.has_js_redirect,
            hosting_provider_type=res.hosting_provider_type,
        )
        if cdn_tunnel["suspect"]:
            res.cdn_tunnel_suspect = True
            res.cdn_tunnel_evidence = ";".join(cdn_tunnel["evidence"])
    
    # v7.3.1: Quishing Profile Detection
    tld = domain.split('.')[-1] if '.' in domain else ''
    quishing = detect_quishing_profile(
        domain=domain,
        domain_age_days=res.domain_age_days,
        ct_log_count=res.ct_log_count,
        is_minimal_shell=res.is_minimal_shell,
        has_js_redirect=res.has_js_redirect,
        has_credential_form=res.has_credential_form,
        has_oauth_phish=res.has_oauth_phish,
        tld=tld,
    )
    if quishing["profile"]:
        res.quishing_profile = True
        res.quishing_evidence = ";".join(quishing["evidence"])
    
    # === TYPOSQUAT CONTEXT CHECK (v7.5.1) ===
    # Suppress typosquat when page title/content clearly indicates the domain is
    # a real brand UNRELATED to the matched typosquat target.
    # e.g., vetfo.us matches "venmo" (0.85 similarity) but page title says
    # "VetFo - Your Pet's Health, Simplified" — clearly not a Venmo phishing site.
    #
    # Logic: If the domain's main name appears in the page title AND the matched
    # brand does NOT appear in the page title, suppress the typosquat.
    if res.typosquat_target and res.page_title:
        _domain_main = domain.lower().split('.')[0] if '.' in domain else domain.lower()
        _title_lower = res.page_title.lower()
        _brand_lower = res.typosquat_target.lower()
        
        # Domain's own brand name appears in the title (it's THEIR brand)
        _own_brand_in_title = _domain_main in _title_lower
        # Matched typosquat brand does NOT appear in title
        _target_brand_absent = _brand_lower not in _title_lower
        
        if _own_brand_in_title and _target_brand_absent:
            res.typosquat_target = ""
            res.typosquat_similarity = 0.0
    
    # Score
    calculate_score(res, config)
    
    # v7.5.1: Prepend root domain fallback note to summary if applicable
    if res.analyzed_root_note:
        res.summary = f"{res.analyzed_root_note} | {res.summary}"

    # v8.0: Prepend mail-only domain note to summary if applicable
    if res.mail_only_note:
        res.summary = f"{res.mail_only_note} | {res.summary}"

    # v8.1: Prepend no-resolve domain note to summary if applicable
    if res.no_resolve_note:
        res.summary = f"{res.no_resolve_note} | {res.summary}"

    return asdict(res)
