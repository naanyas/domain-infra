"""
Hacklink Keyword Scanner
========================
Scans domain page content for hacklink SEO poisoning indicators.

Hacklink campaigns (predominantly Turkish-origin) inject hidden keywords and links
into compromised websites. These include gambling, pharmaceutical, and adult content
keywords designed to boost attacker-controlled sites in search rankings.

IMPORTANT: HTTP errors (403, timeout, SSL failures) are treated as risk signals,
not benign outcomes. A legitimate business domain that blocks access, times out,
or has certificate issues is itself suspicious for a sending domain.

VERSION: 7.4 (Feb 2026)
- SEO POISONING ESCALATION: CSS hiding techniques now contribute to malicious
  script confidence scoring.  When CSS hiding patterns (display:none, visibility:hidden,
  font-size:0) co-occur with suspicious external scripts, a CSS_HIDING_PRESENT signal
  (+1 weight) is added to the script confidence score.  Additionally, any MEDIUM-confidence
  script detection that co-occurs with CSS hiding is escalated to HIGH confidence via a
  combined escalation rule.  This closes a gap where domains exhibiting the classic SEO
  poisoning pattern (unknown async scripts + high-entropy paths + CSS hiding) were only
  reaching MEDIUM confidence because CSS hiding was evaluated in a separate code path
  that didn't feed into the script confidence score.
  Discovered via ovalworkshopgh.com: score 4 (UNKNOWN_EXTERNAL_SCRIPT +1,
  HIGH_ENTROPY_PATH +2, ASYNC_UNKNOWN_DOMAIN +1) should have been HIGH but CSS hiding
  was scored independently.  With this fix, CSS_HIDING_PRESENT adds +1 → score 5 → HIGH,
  and the escalation rule provides a safety net for score-3 MEDIUM cases with CSS hiding.

VERSION: 7.3 (Feb 2026)
- GAMBLING SITE CONTEXT: Added _is_gambling_site() detection (domain name + title/H1/meta).
  When a site IS a legitimate gambling/gaming business, keyword scoring is suppressed for
  visible content — only keywords found inside CSS-hidden blocks will score.  This eliminates
  false positives on sites like locobingo.es where "bingo", "slot", "casino" are the site's
  own product vocabulary, not injected hacklink content.
- PLACEHOLDER DETECTION FIX: Ambiguous signals ("coming soon", "under construction") now
  only fire on thin pages (< 1000 chars visible text).  A full landing page that says
  "Coming Soon" for one feature is a product label, not a parking page.  Definitive parking
  signals ("parked domain", "buy this domain", "apache2 default page", etc.) still fire
  regardless of page size.
- New return field: is_gambling_site (bool) for transparency in results.
"""

import re
import math
import socket
import urllib.request
import urllib.error
import ssl
from typing import Dict, List, Optional
from urllib.parse import urlparse


# ================================================================
# Hacklink Keyword Families
# ================================================================

# Long/specific keywords — safe for substring matching (low false-positive risk)
# Multi-word Turkish phrases are highly specific and won't collide with legitimate content.
TURKISH_HACKLINK_KEYWORDS = [
    "hacklink", "hack link", "hacklink satın al", "hacklink al",
    "hacklink panel", "hacklink servisi", "hacklink fiyat",
    "bahis siteleri", "canlı bahis", "illegal bahis",
    "canlı casino", "online casino", "casino siteleri",
    "kumar", "kumar siteleri", "slot oyunları",
    "betist", "betpark", "bahsegel",
    "deneme bonusu", "bonus veren siteler", "free bonus",
    "kaçak iddaa", "spor bahis",
    "escort bayan",
    "oto çekici", "nakliyat",
]

# Short/ambiguous keywords — require word-boundary matching (\b) to avoid
# false positives on legitimate words (e.g. "bet" in "better", "slot" in
# "slotted", "sex" in "next", "hap" in "happen", "xxx" in CSS comments,
# "porno" in content-rating metadata or genre taxonomies on film/media sites,
# "poker"/"casino"/"blackjack" as film titles or legitimate card game
# references, "betting" in legitimate sports content, "viagra" in health
# articles, "bahis" in non-gambling Turkish text, "iddaa" standalone).
#
# The (?<!-) and (?!-) lookarounds prevent matching inside hyphenated
# CSS classes and compound words (e.g. "no-porno-filter", "pre-casino-era",
# "anti-escort-policy").
HACKLINK_EXACT_KEYWORDS = [
    r'(?<!-)\bbet\b(?!-)',    r'(?<!-)\bslot\b(?!-)',   r'(?<!-)\bslots\b(?!-)',
    r'(?<!-)\bescort\b(?!-)',
    r'(?<!-)\bsex\b(?!-)',    r'(?<!-)\bxxx\b(?!-)',
    r'(?<!-)\bhap\b(?!-)',
    r'(?<!-)\bcialis\b(?!-)',
    r'(?<!-)\bporno\b(?!-)',  r'(?<!-)\bviagra\b(?!-)',
    r'(?<!-)\bcasino\b(?!-)', r'(?<!-)\bpoker\b(?!-)',  r'(?<!-)\bblackjack\b(?!-)',
    r'(?<!-)\bbetting\b(?!-)',r'(?<!-)\bbahis\b(?!-)',  r'(?<!-)\brulet\b(?!-)',
    r'(?<!-)\bbakara\b(?!-)', r'(?<!-)\biddaa\b(?!-)',
]
HACKLINK_EXACT_COMPILED = [re.compile(p, re.IGNORECASE) for p in HACKLINK_EXACT_KEYWORDS]

# ================================================================
# SocGholish / FakeUpdate Multi-Signal Detection (v7.2)
# ================================================================
# Replaces the broad single-regex approach with weighted signals.
# Each signal has a name, weight, and detection logic.
# Signals accumulate; threshold of 3+ triggers detection.
#
# Why: The old pattern `<script[^>]*src=...\.js...>` matched ANY
# external JS file, causing false positives on React SPAs loading
# jQuery from CDN, Google Analytics, Stripe, etc.
# ================================================================

# CDN / known-good script domains — NEVER flag these as suspicious.
# Scripts served from these domains are legitimate third-party resources.
CDN_WHITELIST = {
    # Major CDNs
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "ajax.googleapis.com", "ajax.aspnetcdn.com",
    "cdn.bootcdn.net", "cdn.staticfile.org", "cdn.bootcss.com",
    
    # jQuery / Bootstrap / common libraries
    "code.jquery.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "cdn.datatables.net",
    
    # Google services
    "www.googletagmanager.com", "googletagmanager.com",
    "www.google-analytics.com", "google-analytics.com",
    "www.gstatic.com", "apis.google.com",
    "maps.googleapis.com", "www.google.com",
    "pagead2.googlesyndication.com", "adservice.google.com",
    "www.googleadservices.com",
    
    # Analytics / marketing (legitimate)
    "cdn.segment.com", "js.hs-scripts.com", "js.hsforms.net",
    "static.hotjar.com", "snap.licdn.com", "connect.facebook.net",
    "platform.twitter.com", "widgets.leadconnectorhq.com",
    "cdn.heapanalytics.com", "cdn.amplitude.com",
    "cdn.mxpnl.com", "cdn.optimizely.com",
    "js.intercomcdn.com", "widget.intercom.io",
    "js.driftt.com", "cdn.pendo.io",
    
    # Payment / e-commerce
    "js.stripe.com", "checkout.stripe.com",
    "www.paypal.com", "www.paypalobjects.com",
    "sdk.mercadopago.com",
    
    # Fonts / icons
    "fonts.googleapis.com", "use.fontawesome.com",
    "kit.fontawesome.com", "use.typekit.net",
    
    # Cloud / hosting platforms (serving legitimate app bundles)
    "cdn.shopify.com", "cdn.squarespace.com",
    "assets.squarespace.com", "static.wixstatic.com",
    "cdn.wix.com", "cdn.hubspot.com",
    "www.hostinger.com", "hpanel.hostinger.com",
    "hostinger.com",  # Base domain — catches ALL *.hostinger.com subdomains
    
    # Webflow (website builder platform)
    "website-files.com",  # Base domain — catches cdn.prod.website-files.com etc.
    "webflow.com",  # Base domain — catches assets.webflow.com, global-uploads.webflow.com etc.
    "assets-global.website-files.com",
    
    # Vercel / Next.js
    "vercel.com", "vercel.live", "va.vercel-scripts.com",
    
    # Netlify
    "netlify.com", "netlify.app",
    
    # reCAPTCHA / security
    "www.google.com", "www.recaptcha.net",
    "challenges.cloudflare.com", "js.hcaptcha.com",
    
    # Cloudflare analytics / insights
    "static.cloudflareinsights.com",
    
    # Microsoft Clarity / analytics
    "www.clarity.ms", "cdn.clarity.ms",
    
    # Cookie consent / compliance
    "cdn.cookielaw.org", "cdn.cookie-script.com",
    "cookiescript.com",
    
    # Push notifications
    "cdn.onesignal.com", "onesignal.com",
    
    # Pingdom RUM (used by Hostinger and many others)
    "rum-static.pingdom.net",
    
    # Microsoft
    "ajax.aspnetcdn.com", "appsforoffice.microsoft.com",
    
    # React / Vue / Angular CDN patterns
    "reactjs.org", "vuejs.org", "angular.io",
}

# Patterns that are CRITICAL (weight=3) — near-certain SocGholish
SOCGHOLISH_CRITICAL_PATTERNS = {
    # ndsw / ndsx variables — THE canonical SocGholish marker
    "NDSW_NDSX_VARIABLE": re.compile(
        r'(?:var|let|const)\s+(?:ndsw|ndsx|_ndsw|_ndsx)\s*=', re.IGNORECASE
    ),
    # s_code.js?cid= pattern — known SocGholish loader URL format
    "SCODE_CID_PATTERN": re.compile(
        r'src=["\'][^"\']*s_code\.js\?cid=["\']', re.IGNORECASE
    ),
}

# Patterns that are HIGH weight (weight=2)
SOCGHOLISH_HIGH_PATTERNS = {
    # eval(atob(...)) chain — decoding + executing Base64 payload
    "EVAL_ATOB_CHAIN": re.compile(
        r'eval\s*\(\s*(?:window\.)?\s*atob\s*\(', re.IGNORECASE
    ),
    # document.write(<script...) — injecting script tags dynamically
    "DOCUMENT_WRITE_SCRIPT": re.compile(
        r'document\.write\s*\(\s*(?:unescape\s*\(|["\']<\s*script)', re.IGNORECASE
    ),
    # Packed JavaScript: eval(function(p,a,c,k,e,d)...) — Dean Edwards packer
    "PACKED_JS": re.compile(
        r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)', re.IGNORECASE
    ),
    # var _0x[hex] = [...] — common JS obfuscator output
    "HEX_OBFUSCATED_ARRAY": re.compile(
        r'var\s+_0x[a-f0-9]{4,}\s*=\s*\[', re.IGNORECASE
    ),
    # jQuery masquerade: non-CDN script pretending to be jQuery
    # (actual jQuery is on CDN whitelist; non-CDN "jquery" is suspicious)
    "JQUERY_MASQUERADE": re.compile(
        r'src=["\'][^"\']*jquery[^"\']*\.js["\']', re.IGNORECASE
    ),
}

# Patterns that are MODERATE weight (weight=1)
SOCGHOLISH_MODERATE_PATTERNS = {
    # String.fromCharCode obfuscation
    "FROMCHARCODE_CHAIN": re.compile(
        r'String\.fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){5,}', re.IGNORECASE
    ),
    # User-agent conditional check in inline script (SocGholish fingerprints visitors)
    "CONDITIONAL_UA_CHECK": re.compile(
        r'navigator\s*\.\s*userAgent.*(?:Windows|MSIE|Trident|Chrome).*(?:document\.write|eval|window\.location)',
        re.IGNORECASE | re.DOTALL
    ),
    # Large Base64 payload (>100 chars) inside inline script
    "BASE64_PAYLOAD": re.compile(
        r'atob\s*\(\s*["\'][A-Za-z0-9+/=]{100,}["\']', re.IGNORECASE
    ),
}

HIDDEN_CONTENT_PATTERNS_HIGH = [
    # --- HIGH CONFIDENCE: Hidden content WITH embedded links ---
    # These require both a CSS hiding technique AND an <a href> inside the hidden
    # block.  Almost certainly injected hacklink/SEO spam.
    #
    # <div style="display:none">...<a href="...">casino</a>...</div>
    r'style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*>.{0,800}?<a\s+href',
    # <div style="visibility:hidden">...<a href="...">
    r'style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden[^"\']*["\'][^>]*>.{0,800}?<a\s+href',
    # <div style="position:absolute;left:-9999px">...<a href="...">
    r'style\s*=\s*["\'][^"\']*position\s*:\s*absolute[^"\']*left\s*:\s*-\d{3,}[^"\']*["\'][^>]*>.{0,800}?<a\s+href',
    # <div style="text-indent:-9999px">...<a href="...">
    r'style\s*=\s*["\'][^"\']*text-indent\s*:\s*-\d{3,}[^"\']*["\'][^>]*>.{0,800}?<a\s+href',
    # <div style="overflow:hidden;height:0">...<a href="...">
    r'style\s*=\s*["\'][^"\']*overflow\s*:\s*hidden[^"\']*height\s*:\s*[01]px[^"\']*["\'][^>]*>.{0,800}?<a\s+href',
    # <div style="opacity:0">...<a href="...">
    r'style\s*=\s*["\'][^"\']*opacity\s*:\s*0[;\s"\'"][^"\']*["\'][^>]*>.{0,800}?<a\s+href',
    # <span style="font-size:0">...<a href="...">
    r'style\s*=\s*["\'][^"\']*font-size\s*:\s*0[^1-9][^"\']*["\'][^>]*>.{0,800}?<a\s+href',
    # Hidden links inside <noscript> (search engines see these, users don't)
    r'<noscript>.{0,500}?<a\s+href\s*=\s*["\']https?://[^"\']+["\'].{0,500}?</noscript>',
    # HTML comment-wrapped links
    r'<!--.{0,300}?<a\s+href\s*=\s*["\']https?://.{0,300}?-->',
]

HIDDEN_CONTENT_PATTERNS_LOW = [
    # --- LOW CONFIDENCE: CSS patterns WITHOUT links ---
    # These fire on CSS hiding techniques alone. Common in legitimate sites
    # (screen-reader text, image replacement, inline-block gap fixes, collapsed
    # menus, React/SPA hidden components).  Only meaningful when COMBINED with
    # hacklink keywords or other compromise signals.
    #
    # CSS class-based hiding (injected <style> blocks)
    r'<style[^>]*>[^<]*\{[^}]*display\s*:\s*none[^}]*\}[^<]*</style>',
    # font-size:0 or 1px (screen-reader / gap fix in legit CSS)
    r'font-size\s*:\s*[01]px',
    # text-indent with large negative value (image replacement technique)
    r'text-indent\s*:\s*-\d{4,}',
    # position:absolute with large negative left (off-screen positioning)
    r'position\s*:\s*absolute[^;"\']*left\s*:\s*-\d{4,}',
]

SUSPICIOUS_SCRIPT_DOMAINS = [
    r'cdn\.jsdelivr\.net/npm/.*(?:analytics|tracker|pixel)',
    r'statcounter\.com',
    r'\.top/.*\.js',
    r'\.buzz/.*\.js',
    r'\.click/.*\.js',
    r'\.link/.*\.js',
    # Only flag googletagmanager URLs NOT from the real googletagmanager.com
    # e.g. googletagmanager.evil.com or fake-googletagmanager.net
    r'googletagmanager(?!\.com[/?\s"\'])',
    # Only flag google-analytics URLs NOT from the real google-analytics.com
    r'google-analytics(?!\.com[/?\s"\'])',
]

WP_COMPROMISE_PATTERNS = [
    # Plugin JS with eval/document.write — legitimate plugins don't need these
    r'wp-content/plugins/[^/]+/[^"\']+\.js\?ver=\d+\.\d+\.\d+.*(?:eval|document\.write)',
    # WP core files with eval/base64 — legit WP core never contains these
    r'wp-includes/.*(?:eval|base64_decode)',
    # Backdoor shell patterns in WP paths
    r'wp-content/(?:uploads|plugins|themes)/[^"\']*(?:shell|c99|r57|wso|b374k|alfa)',
    # PHP injection artifacts visible in HTML source
    r'wp-(?:content|includes)/[^"\']*\.php\?(?:[a-z]{1,3}=)',
    # Encoded PHP in WP directories (base64 payloads in URLs)
    r'wp-content/[^"\']*(?:base64_decode|str_rot13|gzinflate|eval\s*\()',
]


class HacklinkKeywordScanner:
    """Scans domains for hacklink SEO poisoning indicators."""

    # Known-legitimate external domains commonly found inside hidden page
    # elements (mobile nav footers, newsletter widgets, analytics noscript
    # fallbacks, CMS attribution, comment systems, social embeds, etc.).
    # These should NEVER count as hacklink injection evidence.
    _BENIGN_EXTERNAL_DOMAINS = {
        # Newsletter / email services
        "eepurl.com", "mailchimp.com", "list-manage.com",
        "mailchi.mp", "campaign-archive.com",
        "convertkit.com", "buttondown.email", "substack.com",
        "sendinblue.com", "brevo.com", "mailerlite.com",
        "constantcontact.com", "hubspot.com",
        # CMS / hosting platforms
        "ghost.org", "ghost.io", "wordpress.org", "wordpress.com",
        "squarespace.com", "wix.com", "webflow.com", "weebly.com",
        "shopify.com", "blogger.com", "medium.com", "tumblr.com",
        # Analytics / tracking
        "google.com", "google-analytics.com", "googletagmanager.com",
        "gstatic.com", "googleapis.com", "googlesyndication.com",
        "doubleclick.net", "facebook.com", "facebook.net",
        "twitter.com", "x.com", "linkedin.com", "instagram.com",
        "pinterest.com", "tiktok.com", "youtube.com",
        "hotjar.com", "clarity.ms", "segment.com",
        # Comment / engagement systems
        "disqus.com", "disquscdn.com", "gravatar.com",
        # CDN / infrastructure
        "cloudflare.com", "jsdelivr.net", "unpkg.com",
        "cdnjs.cloudflare.com", "bootstrapcdn.com",
        "fontawesome.com", "fonts.googleapis.com",
        # Payment / trust
        "stripe.com", "paypal.com",
        # Development / code
        "github.com", "github.io", "gitlab.com", "codepen.io",
        "jsfiddle.net", "stackblitz.com", "netlify.com",
        "vercel.com", "herokuapp.com",
        # Common web services
        "apple.com", "microsoft.com", "amazon.com", "amazonaws.com",
        "intercom.io", "intercomcdn.com", "drift.com",
        "recaptcha.net", "hcaptcha.com",
    }

    # Regex to extract href values from HTML
    _HREF_EXTRACTOR = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

    # TLDs overwhelmingly associated with hacklink/SEO spam campaigns
    _SUSPICIOUS_TLDS = {
        ".top", ".buzz", ".click", ".link", ".xyz", ".icu",
        ".cam", ".rest", ".surf", ".monster", ".cyou",
    }

    # Keywords that indicate a domain is part of a hacklink/SEO spam network
    _SUSPICIOUS_DOMAIN_KEYWORDS = {
        "bahis", "casino", "slot", "poker", "rulet", "kumar",
        "betting", "blackjack", "bakara", "jackpot", "roulette",
        "escort", "porno", "cialis", "viagra", "hacklink",
        "canlibahis", "canli-bahis", "bonus", "freespin",
    }

    def __init__(self, timeout: int = 10, max_content_size: int = 500_000):
        self.timeout = timeout
        self.max_content_size = max_content_size

    @staticmethod
    def _is_benign_external(host: str) -> bool:
        """Check if a hostname belongs to a known-legitimate service."""
        for benign in HacklinkKeywordScanner._BENIGN_EXTERNAL_DOMAINS:
            if host == benign or host.endswith("." + benign):
                return True
        return False

    @staticmethod
    def _is_suspicious_external(host: str) -> bool:
        """Check if a hostname has hacklink-associated indicators.
        
        Uses segment-based matching: the hostname is split into labels
        (by '.' and '-') and each label is checked against the keyword set.
        This prevents 'slot' matching 'timeslot.com' or 'bonus' matching
        'bonustage.de' while still catching 'casino-online.com'.
        """
        # Check suspicious TLDs
        for tld in HacklinkKeywordScanner._SUSPICIOUS_TLDS:
            if host.endswith(tld):
                return True
        # Split hostname into segments (domain labels and hyphenated parts)
        # e.g. "casino-online.example.com" → ["casino", "online", "example", "com"]
        host_lower = host.lower()
        segments = set(re.split(r'[.\-]', host_lower))
        return bool(segments & HacklinkKeywordScanner._SUSPICIOUS_DOMAIN_KEYWORDS)

    @staticmethod
    def _has_external_links(html_chunk: str, domain: str) -> tuple:
        """
        Check whether an HTML chunk contains links to SUSPICIOUS external domains.

        Returns (has_suspicious: bool, suspicious_domains: set).

        Logic:
          1. Extract all hrefs from the chunk.
          2. Skip relative/internal/anchor/javascript/mailto links.
          3. Skip known-legitimate external services (Mailchimp, Ghost, Google,
             social media, CDNs, etc.) — these appear in hidden elements on
             virtually every responsive website.
          4. For remaining external links, check if they're on suspicious TLDs
             or contain hacklink-associated keywords.
          5. Also flag if there are 3+ distinct non-benign external domains
             (mass link injection pattern), even without suspicious keywords.
        """
        hrefs = HacklinkKeywordScanner._HREF_EXTRACTOR.findall(html_chunk)
        suspicious_domains = set()
        non_benign_external = set()

        # Build the base registrable domain for comparison
        base_domain = domain.lower().split(":")[0]
        parts = base_domain.split(".")
        # Handle ccTLDs like .co.uk, .com.au
        if len(parts) > 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
            base = ".".join(parts[-3:])
        elif len(parts) >= 2:
            base = ".".join(parts[-2:])
        else:
            base = base_domain

        for href in hrefs:
            href = href.strip()
            # Skip relative URLs, anchors, javascript:, mailto:, tel:
            if (not href or href.startswith("/") or href.startswith("#")
                    or href.startswith("javascript:") or href.startswith("mailto:")
                    or href.startswith("tel:")):
                continue
            try:
                parsed = urlparse(href)
                host = (parsed.hostname or "").lower()
                if not host:
                    continue
                # Same-domain check
                if host == base or host.endswith("." + base):
                    continue
                # Known-legitimate service check
                if HacklinkKeywordScanner._is_benign_external(host):
                    continue
                # This is a non-benign external link
                non_benign_external.add(host)
                # Check if it's actively suspicious
                if HacklinkKeywordScanner._is_suspicious_external(host):
                    suspicious_domains.add(host)
            except Exception:
                continue

        # Flag as suspicious if:
        #   - Any link goes to a domain with hacklink keywords/TLDs, OR
        #   - 3+ distinct non-benign external domains (mass injection pattern)
        has_suspicious = (
            len(suspicious_domains) > 0
            or len(non_benign_external) >= 3
        )

        return (has_suspicious, suspicious_domains or non_benign_external)

    def scan(self, domain: str, content: Optional[str] = None) -> Dict:
        """
        Scan a domain for hacklink injection indicators.

        Args:
            domain: Domain name to scan
            content: Optional pre-fetched page content. If provided, skips
                     HTTP fetch (useful when caller already has the content).

        Returns:
            Dict with hacklink_detected, score (0-30), keywords, findings
        """
        findings = []
        keywords_found = []
        injection_patterns = []
        score = 0
        page_content = content  # Use pre-fetched content if provided
        fetch_status = 200 if content else None
        fetch_error = None
        fetch_error_type = None

        # Attempt to fetch page content (only if not pre-fetched)
        if page_content is None:
            for protocol in ["https", "http"]:
                url = f"{protocol}://{domain}"
                try:
                    page_content, fetch_status = self._fetch_content(url)
                    if page_content:
                        break
                except urllib.error.HTTPError as e:
                    fetch_status = e.code
                    fetch_error = f"HTTP {e.code} {e.reason}"
                    fetch_error_type = "http_error"
                    continue
                except urllib.error.URLError as e:
                    reason = str(e.reason)
                    fetch_error = f"Connection failed: {reason}"
                    if "timed out" in reason.lower() or "timeout" in reason.lower():
                        fetch_error_type = "timeout"
                    elif "ssl" in reason.lower() or "certificate" in reason.lower():
                        fetch_error_type = "ssl_error"
                    elif "refused" in reason.lower():
                        fetch_error_type = "connection_refused"
                    elif "name or service not known" in reason.lower() or "getaddrinfo" in reason.lower():
                        fetch_error_type = "dns_failure"
                    else:
                        fetch_error_type = "connection_error"
                    continue
                except socket.timeout:
                    fetch_error = "Connection timed out"
                    fetch_error_type = "timeout"
                    continue
                except Exception as e:
                    fetch_error = str(e)[:200]
                    fetch_error_type = "unknown"
                    continue

        # ================================================================
        # SCORE HTTP ERRORS AS RISK SIGNALS
        # A legitimate sending domain that can't serve a web page is suspicious
        # ================================================================
        if not page_content:
            score, findings = self._score_fetch_failure(
                domain, fetch_status, fetch_error, fetch_error_type, score, findings
            )

            # Even without page content, check if domain NAME contains keywords
            domain_name_keywords = self._check_domain_name(domain)
            if domain_name_keywords:
                score += 5
                findings.append({
                    "severity": "high",
                    "category": "domain_name_keywords",
                    "detail": f"Domain name contains hacklink-associated keywords: "
                              f"{', '.join(domain_name_keywords)}. Combined with HTTP "
                              f"errors, this is a strong compromise indicator."
                })

            return {
                "hacklink_detected": len(domain_name_keywords) >= 1,
                "score": min(score, 30),
                "keywords_found": domain_name_keywords,
                "injection_patterns": [],
                "suspicious_scripts": [],
                "wp_compromised": False,
                "is_wordpress": False,
                "is_cpanel": False,
                "wp_plugins": [],
                "vulnerable_plugins": [],
                "spam_link_count": 0,
                "malicious_script_confidence": "NONE",
                "malicious_script_signals": [],
                "malicious_script_score": 0,
                "hidden_injection_confidence": "",
                "is_gambling_site": False,
                "google_dorks": self._generate_google_dorks(domain, domain_name_keywords, [], False),
                "findings": findings,
                "fetch_error": fetch_error,
                "fetch_error_type": fetch_error_type,
                "fetch_status": fetch_status,
            }

        content_lower = page_content.lower()

        # hacklink_content_score tracks ONLY hacklink-specific content signals
        # (keywords, hidden injection with suspicious links, meta spam, spam
        # outbound links).  Infrastructure signals like malicious-script
        # detection, CMS fingerprinting, empty-page checks, and cPanel markers
        # feed into the general `score` but MUST NOT inflate the
        # hacklink_detected threshold — they represent separate threat classes.
        hacklink_content_score = 0

        # ----- 0. Domain Name Keyword Check -----
        # Check if the domain name itself contains hacklink keywords
        domain_name_keywords = self._check_domain_name(domain)
        if domain_name_keywords:
            keywords_found.extend(domain_name_keywords)
            score += 5
            hacklink_content_score += 5
            findings.append({
                "severity": "high",
                "category": "domain_name_keywords",
                "detail": f"Domain name contains hacklink-associated keywords: "
                          f"{', '.join(domain_name_keywords)}. The domain itself may be "
                          f"part of a hacklink/SEO spam network."
            })

        # ----- 0b. Gambling/Gaming Site Context Check -----
        # If the site IS a gambling business, its own product keywords (casino,
        # slot, bingo, bet) in visible content are expected — not evidence of
        # compromise.  We only score keywords found in hidden blocks.
        is_gambling_site = self._is_gambling_site(domain, page_content)
        if is_gambling_site:
            findings.append({
                "severity": "info",
                "category": "gambling_site_context",
                "detail": "Site identified as a legitimate gambling/gaming business "
                          "(domain name + page title/headings confirm gambling as "
                          "primary business). Gambling keywords in visible content "
                          "are suppressed — only hidden-block keywords will score."
            })

        # ----- 1. Turkish Hacklink Keyword Scan -----
        # Build a set of keywords that appear in the domain name itself.
        # If a business is literally named "acarlar nakliyat" (a Turkish moving
        # company), the word "nakliyat" appearing in their page content is
        # expected — it's their business name, not evidence of compromise.
        # We suppress these from page-content matching to avoid false positives.
        domain_name_kw_set = set(k.lower() for k in domain_name_keywords)
        _specific_keyword_count = 0  # v7.5.1: Count of Turkish/specific (non-ambiguous) keywords

        if is_gambling_site:
            # --- GAMBLING SITE MODE ---
            # Extract only keywords found inside CSS-hidden blocks.
            # Visible-content gambling terms are the site's own product vocabulary.
            hidden_blocks = []
            for pattern in HIDDEN_CONTENT_PATTERNS_HIGH + HIDDEN_CONTENT_PATTERNS_LOW:
                for m in re.finditer(pattern, page_content, re.IGNORECASE | re.DOTALL):
                    hidden_blocks.append(page_content[m.start():m.start() + 2000].lower())
            hidden_text = " ".join(hidden_blocks)

            if hidden_text:
                for keyword in TURKISH_HACKLINK_KEYWORDS:
                    kw_lower = keyword.lower()
                    if kw_lower in domain_name_kw_set:
                        continue
                    if kw_lower in hidden_text:
                        keywords_found.append(keyword)
                _specific_keyword_count = len(keywords_found)  # v7.5.1: Turkish keywords in hidden blocks
                for pattern in HACKLINK_EXACT_COMPILED:
                    m = pattern.search(hidden_text)
                    if m:
                        matched = m.group().lower()
                        if matched in domain_name_kw_set:
                            continue
                        keywords_found.append(matched)
            else:
                _specific_keyword_count = 0
            # If no hidden blocks or no keywords in hidden blocks → keywords_found stays empty
        else:
            # --- NORMAL MODE ---
            # Scan full page content (original behavior).
            # Substring match for long/specific keywords (low false-positive risk)
            for keyword in TURKISH_HACKLINK_KEYWORDS:
                kw_lower = keyword.lower()
                if kw_lower in domain_name_kw_set:
                    continue  # Skip — this is the business's own terminology
                if kw_lower in content_lower:
                    keywords_found.append(keyword)
            _specific_keyword_count = len(keywords_found)  # v7.5.1: Count before adding ambiguous
            # Word-boundary match for short/ambiguous keywords (high false-positive risk)
            for pattern in HACKLINK_EXACT_COMPILED:
                m = pattern.search(page_content)
                if m:
                    matched = m.group().lower()
                    if matched in domain_name_kw_set:
                        continue  # Skip — domain's own terminology
                    keywords_found.append(matched)

        if len(keywords_found) >= 5:
            score += 30
            hacklink_content_score += 30
            findings.append({
                "severity": "critical",
                "category": "hacklink_keywords",
                "detail": f"CRITICAL: {len(keywords_found)} hacklink keywords found in page source: "
                          f"{', '.join(keywords_found[:10])}{'...' if len(keywords_found) > 10 else ''}"
            })
        elif len(keywords_found) >= 2:
            # v7.5.1: If ALL keywords are from the ambiguous/exact list (bet, slot,
            # casino, betting, etc.), require 3+ for full score.  These words have
            # legitimate uses on finance, gaming, sports, and entertainment sites.
            # A trading signals site with "bet" + "betting" is NOT hacklink spam.
            # Turkish hacklink keywords ("bahis siteleri", "canlı casino") are highly
            # specific and remain at the 2-keyword threshold.
            _all_ambiguous = (_specific_keyword_count == 0)
            if _all_ambiguous and len(keywords_found) < 3:
                # Only ambiguous keywords and fewer than 3 — low confidence
                score += 8
                hacklink_content_score += 8
                findings.append({
                    "severity": "medium",
                    "category": "hacklink_keywords",
                    "detail": f"Ambiguous hacklink keywords ({len(keywords_found)}): "
                              f"{', '.join(keywords_found)}. May be legitimate site vocabulary."
                })
            else:
                score += 20
                hacklink_content_score += 20
                findings.append({
                    "severity": "high",
                    "category": "hacklink_keywords",
                    "detail": f"Multiple hacklink keywords detected: {', '.join(keywords_found)}"
                })
        elif len(keywords_found) == 1:
            score += 8
            hacklink_content_score += 8
            findings.append({
                "severity": "medium",
                "category": "hacklink_keywords",
                "detail": f"Single hacklink keyword detected: {keywords_found[0]}"
            })

        # ----- 2. Hidden Content Injection -----
        # Two-pass approach:
        #   Pass 1 — Check HIGH patterns (CSS hiding + embedded links).
        #            For each match, inspect whether links point to SUSPICIOUS
        #            external domains (hacklink/gambling/pharma keywords, spam
        #            TLDs, or mass injection of 3+ distinct external domains).
        #            Known-benign services (Mailchimp, Ghost, Google, social
        #            media, CDNs) are whitelisted and ignored.
        #   Pass 2 — If no suspicious external links found, check LOW patterns
        #            (CSS-only, no links at all).
        hidden_high_found = False
        hidden_low_found = False
        hidden_external_domains = set()
        high_pattern_matched_benign_only = False

        for pattern in HIDDEN_CONTENT_PATTERNS_HIGH:
            for m in re.finditer(pattern, page_content, re.IGNORECASE | re.DOTALL):
                # Grab up to 1500 chars from match start to capture full
                # hidden block including the link targets
                block = page_content[m.start():m.start() + 1500]
                has_suspicious, sus_doms = self._has_external_links(block, domain)

                if has_suspicious:
                    # Suspicious external links inside hidden content → real hacklink
                    hidden_high_found = True
                    hidden_external_domains.update(sus_doms)
                    injection_patterns.append(f"hidden_content_high: {pattern[:50]}")
                    if score < 25:
                        score += 10
                        hacklink_content_score += 10
                    ext_sample = ", ".join(sorted(sus_doms)[:5])
                    findings.append({
                        "severity": "critical",
                        "category": "hidden_injection",
                        "detail": f"Hidden content injection with SUSPICIOUS external links "
                                  f"(CSS hiding + links to: {ext_sample}). "
                                  f"Classic hacklink/SEO spam technique."
                    })
                    break  # One confirmed match is enough
                else:
                    # Hidden content with only internal/benign-external links →
                    # responsive nav, mobile menu, newsletter widget, CMS footer
                    high_pattern_matched_benign_only = True

            if hidden_high_found:
                break

        # If HIGH patterns matched but all links were internal or benign → demote to LOW
        if high_pattern_matched_benign_only and not hidden_high_found:
            hidden_low_found = True
            injection_patterns.append("hidden_content_low: benign_links_only")
            findings.append({
                "severity": "low",
                "category": "hidden_injection_css_only",
                "detail": "CSS-hidden elements contain only internal or known-benign links "
                          "(responsive navigation, mobile menus, newsletter widgets — normal pattern)."
            })

        # Low-confidence: CSS patterns only, no links at all
        if not hidden_high_found and not hidden_low_found:
            for pattern in HIDDEN_CONTENT_PATTERNS_LOW:
                matches = re.findall(pattern, page_content, re.IGNORECASE | re.DOTALL)
                if matches:
                    hidden_low_found = True
                    injection_patterns.append(f"hidden_content_low: {pattern[:50]}")
                    findings.append({
                        "severity": "low",
                        "category": "hidden_injection_css_only",
                        "detail": f"CSS hiding technique found (no hidden links detected — "
                                  f"common in legitimate templates/dev sites). "
                                  f"Pattern: {pattern[:60]}..."
                    })

        # ----- 3. SocGholish/Malicious Script Detection (Multi-Signal v7.2) -----
        # Accumulates weighted signals instead of matching a single broad regex.
        # CDN-hosted scripts are whitelisted. Threshold: 3+ = MEDIUM, 5+ = HIGH.
        soc_signals = []  # List of (signal_name, weight) tuples
        soc_score_val = 0
        page_domain = domain.lower().split(':')[0]  # strip port if present

        # --- 3a. Inline script analysis ---
        inline_scripts = re.findall(
            r'<script(?:\s[^>]*)?>(.+?)</script>',
            page_content, re.IGNORECASE | re.DOTALL
        )
        for script_content in inline_scripts:
            # CRITICAL patterns (weight=3 each)
            for sig_name, pattern in SOCGHOLISH_CRITICAL_PATTERNS.items():
                if pattern.search(script_content):
                    soc_signals.append((sig_name, 3))
            # HIGH patterns (weight=2 each)
            for sig_name, pattern in SOCGHOLISH_HIGH_PATTERNS.items():
                # Skip JQUERY_MASQUERADE for inline scripts (it's for src= attributes)
                if sig_name == "JQUERY_MASQUERADE":
                    continue
                if pattern.search(script_content):
                    soc_signals.append((sig_name, 2))
            # MODERATE patterns (weight=1 each)
            for sig_name, pattern in SOCGHOLISH_MODERATE_PATTERNS.items():
                if pattern.search(script_content):
                    soc_signals.append((sig_name, 1))

        # --- 3b. External script analysis ---
        script_srcs = re.findall(
            r'<script[^>]*src=["\']([^"\']+)["\']',
            page_content, re.IGNORECASE
        )
        for src in script_srcs:
            src_domain = self._extract_script_domain(src)
            if not src_domain:
                continue

            # Skip whitelisted CDN domains
            if self._is_whitelisted_cdn(src_domain):
                continue

            # Skip same-domain scripts (site's own JS bundles)
            if src_domain == page_domain or src_domain.endswith('.' + page_domain):
                continue

            # --- Signal: UNKNOWN_EXTERNAL_SCRIPT (+1) ---
            # External .js from non-CDN, non-same-domain source
            soc_signals.append(("UNKNOWN_EXTERNAL_SCRIPT", 1))

            # --- Signal: HIGH_ENTROPY_PATH (+2) ---
            # SocGholish URLs have randomized paths with entropy > 4.0 bits/char
            url_path = urlparse(src).path if '/' in src else src
            path_entropy = self._calculate_path_entropy(url_path)
            if path_entropy > 4.0 and len(url_path) > 25:
                soc_signals.append(("HIGH_ENTROPY_PATH", 2))

            # --- Signal: ASYNC_UNKNOWN_DOMAIN (+1) ---
            # Check if this script tag has async attribute
            # Re-find the full tag for this src
            async_pattern = re.compile(
                r'<script[^>]*\basync\b[^>]*src=["\']' + re.escape(src) + r'["\']|'
                r'<script[^>]*src=["\']' + re.escape(src) + r'["\'][^>]*\basync\b',
                re.IGNORECASE
            )
            if async_pattern.search(page_content):
                soc_signals.append(("ASYNC_UNKNOWN_DOMAIN", 1))

            # --- Signal: JQUERY_MASQUERADE (+2) ---
            # Non-CDN script with "jquery" in filename
            if SOCGHOLISH_HIGH_PATTERNS["JQUERY_MASQUERADE"].search(f'src="{src}"'):
                soc_signals.append(("JQUERY_MASQUERADE", 2))

            # --- Signal: SUSPICIOUS_TLD_SCRIPT (+1) ---
            # Script from high-abuse TLD (.top, .buzz, .click, .link, .xyz)
            if re.search(r'\.(top|buzz|click|link|xyz|gq|ml|cf|ga|tk)$', src_domain, re.IGNORECASE):
                soc_signals.append(("SUSPICIOUS_TLD_SCRIPT", 1))

        # --- 3c. Deduplicate signals (same signal name counts once) ---
        seen_signals = set()
        deduped_signals = []
        for sig_name, weight in soc_signals:
            if sig_name not in seen_signals:
                seen_signals.add(sig_name)
                deduped_signals.append((sig_name, weight))
        soc_signals = deduped_signals

        # --- 3c-2. CSS hiding as corroborating signal for script injection ---
        # CSS hiding techniques (display:none, visibility:hidden, font-size:0)
        # are benign on their own (responsive nav, mobile menus), but when
        # combined with suspicious external scripts they form the classic
        # SEO poisoning / hacklink injection pattern.
        # Only contributes if at least one script signal already exists —
        # CSS hiding alone should never start a malicious_script detection.
        # IMPORTANT: Only use hidden_HIGH (suspicious external links in hidden
        # content) as corroboration.  hidden_LOW (benign_links_only = responsive
        # menus, mobile navs) is NORMAL web design and must NOT escalate.
        if hidden_high_found and soc_signals:
            soc_signals.append(("CSS_HIDING_PRESENT", 1))

        soc_score_val = sum(w for _, w in soc_signals)

        # --- 3d. Determine confidence level ---
        if soc_score_val >= 5:
            malicious_script_confidence = "HIGH"
            injection_patterns.append("malicious_script: multi-signal HIGH confidence")
            score = min(score + 15, 30)
            findings.append({
                "severity": "critical",
                "category": "malicious_script",
                "detail": f"HIGH-confidence SocGholish/FakeUpdate detection. "
                          f"Score: {soc_score_val} (threshold: 5). "
                          f"Signals: {', '.join(s[0] for s in soc_signals)}"
            })
        elif soc_score_val >= 3:
            malicious_script_confidence = "MEDIUM"
            injection_patterns.append("malicious_script: multi-signal MEDIUM confidence")
            score = min(score + 10, 30)
            findings.append({
                "severity": "high",
                "category": "malicious_script",
                "detail": f"MEDIUM-confidence malicious script detection. "
                          f"Score: {soc_score_val} (threshold: 3). "
                          f"Signals: {', '.join(s[0] for s in soc_signals)}"
            })
        else:
            malicious_script_confidence = "NONE"
            # Log for diagnostics even if below threshold
            if soc_signals:
                findings.append({
                    "severity": "info",
                    "category": "malicious_script_below_threshold",
                    "detail": f"Script signals detected but below threshold. "
                              f"Score: {soc_score_val} (need 3). "
                              f"Signals: {', '.join(s[0] for s in soc_signals)}"
                })

        # --- 3e. Combined escalation: MEDIUM scripts + CSS hiding → HIGH ---
        # CSS hiding techniques combined with suspicious external scripts is
        # the definitive SEO poisoning pattern.  Even if individual script
        # signals don't reach the HIGH threshold on their own, CSS hiding
        # provides strong corroboration that the site is compromised.
        # IMPORTANT: Only hidden_HIGH (suspicious external links in hidden
        # content) justifies escalation.  hidden_LOW (benign_links_only =
        # responsive menus, mobile navs) is NORMAL and must NOT escalate.
        if malicious_script_confidence == "MEDIUM" and hidden_high_found:
            malicious_script_confidence = "HIGH"
            injection_patterns.append(
                "malicious_script: ESCALATED to HIGH "
                "(MEDIUM scripts + CSS hiding = SEO poisoning pattern)"
            )
            # Upgrade score contribution: MEDIUM already added +10, HIGH is +15,
            # so add the +5 difference
            score = min(score + 5, 30)
            findings.append({
                "severity": "critical",
                "category": "malicious_script",
                "detail": f"ESCALATED to HIGH confidence — MEDIUM script signals "
                          f"combined with CSS hiding techniques indicates "
                          f"SEO poisoning/hacklink injection. "
                          f"Script score: {soc_score_val}, "
                          f"Signals: {', '.join(s[0] for s in soc_signals)}"
            })

        # ----- 4. Suspicious External Scripts -----
        script_srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', page_content, re.IGNORECASE)
        suspicious_scripts = []
        for src in script_srcs:
            for pattern in SUSPICIOUS_SCRIPT_DOMAINS:
                if re.search(pattern, src, re.IGNORECASE):
                    suspicious_scripts.append(src)
                    break

        if suspicious_scripts:
            score = min(score + 8, 30)
            findings.append({
                "severity": "high",
                "category": "suspicious_scripts",
                "detail": f"Suspicious external scripts loaded: "
                          f"{', '.join(suspicious_scripts[:5])}"
            })

        # ----- 5. WordPress & cPanel Detection (Common Compromise Targets) -----
        wp_compromised = False
        is_wordpress = bool(re.search(r'wp-content|wp-includes|wordpress', content_lower))
        is_cpanel = bool(re.search(
            r'cpanel|whm\.autopkg|cpsess[a-f0-9]{10,}|'
            r'powered\s*by\s*cpanel|cpanel\s*login|'
            r'[:"]208[2367]\b',
            content_lower
        ))

        for pattern in WP_COMPROMISE_PATTERNS:
            if re.search(pattern, page_content, re.IGNORECASE):
                wp_compromised = True
                injection_patterns.append("wordpress_compromise")
                break

        if wp_compromised:
            score = min(score + 5, 30)
            findings.append({
                "severity": "high",
                "category": "cms_compromise",
                "detail": "WordPress compromise indicators detected. Poorly maintained CMS "
                          "sites are primary targets for hacklink injection campaigns."
            })
        elif is_wordpress:
            score = min(score + 3, 30)
            findings.append({
                "severity": "medium",
                "category": "cms_target",
                "detail": "WordPress CMS detected. WordPress is the #1 target for hacklink "
                          "injection campaigns due to plugin vulnerabilities and weak admin "
                          "credentials. Presence of WordPress elevates compromise risk."
            })

        if is_cpanel:
            score = min(score + 3, 30)
            findings.append({
                "severity": "medium",
                "category": "cpanel_target",
                "detail": "cPanel hosting detected. cPanel shared hosting environments are "
                          "frequently targeted in hacklink campaigns — a single compromised "
                          "account can expose all sites on the server."
            })

        # ----- 5b. WordPress Plugin Vulnerability Audit -----
        wp_plugins = []
        vulnerable_plugins = []
        if is_wordpress:
            wp_plugins = self._extract_wp_plugins(page_content)
            if wp_plugins:
                vulnerable_plugins = self._check_plugin_vulnerabilities(wp_plugins)
                if vulnerable_plugins:
                    vuln_names = [f"{v['plugin']} ({v['risk']})" for v in vulnerable_plugins]
                    score = min(score + 5, 30)
                    findings.append({
                        "severity": "high",
                        "category": "wp_vulnerable_plugins",
                        "detail": f"WordPress plugins with known vulnerabilities detected: "
                                  f"{', '.join(vuln_names[:8])}. These are common exploit paths "
                                  f"for hacklink injection campaigns."
                    })
                elif wp_plugins:
                    findings.append({
                        "severity": "info",
                        "category": "wp_plugins_detected",
                        "detail": f"WordPress plugins detected: {', '.join(wp_plugins[:10])}. "
                                  f"No known high-risk plugins identified."
                    })

        # ----- 6. Meta Tag Anomalies -----
        meta_anomalies = self._check_meta_anomalies(page_content)
        if meta_anomalies:
            score = min(score + 5, 30)
            hacklink_content_score += 5
            findings.extend(meta_anomalies)

        # ----- 7. Excessive Outbound Links to Gambling/Pharma -----
        spam_links, spam_link_urls = self._count_spam_outbound_links(page_content)
        if spam_links > 10:
            score = min(score + 10, 30)
            hacklink_content_score += 10
            findings.append({
                "severity": "critical",
                "category": "spam_links",
                "detail": f"{spam_links} outbound links to gambling/pharma/adult domains detected."
            })
        elif spam_links > 3:
            score = min(score + 5, 30)
            hacklink_content_score += 5
            findings.append({
                "severity": "high",
                "category": "spam_links",
                "detail": f"{spam_links} suspicious outbound links to known spam categories."
            })

        # ----- 8. Page content anomalies -----
        # Strip HTML tags to measure VISIBLE text (not raw HTML size)
        visible_text = re.sub(r'<[^>]+>', ' ', page_content)
        visible_text = re.sub(r'\s+', ' ', visible_text).strip()
        visible_text_len = len(visible_text)
        raw_html_size = len(page_content)

        # Empty or near-empty page (200 OK but no real content)
        if visible_text_len < 50:
            score = min(score + 15, 30)
            findings.append({
                "severity": "critical",
                "category": "empty_page",
                "detail": f"EMPTY PAGE — Server returned 200 OK but page has virtually no "
                          f"visible text ({visible_text_len} chars). HTML size: {raw_html_size} bytes. "
                          f"A legitimate business domain should have actual web content. "
                          f"Empty pages indicate compromised, gutted, or abandoned infrastructure."
            })
        elif visible_text_len < 200:
            score = min(score + 10, 30)
            findings.append({
                "severity": "high",
                "category": "near_empty_page",
                "detail": f"NEAR-EMPTY PAGE — Only {visible_text_len} characters of visible text. "
                          f"Minimal content on a sending domain is suspicious — may be a "
                          f"shell of a previously compromised site."
            })
        elif raw_html_size < 500:
            score = min(score + 3, 30)
            findings.append({
                "severity": "medium",
                "category": "thin_content",
                "detail": f"Extremely small page ({raw_html_size} bytes). Possible parked, "
                          f"hijacked, or stub domain."
            })

        # WordPress shell without content (WP markers but empty/gutted)
        if is_wordpress and visible_text_len < 300:
            score = min(score + 8, 30)
            findings.append({
                "severity": "critical",
                "category": "wp_empty_shell",
                "detail": f"GUTTED WORDPRESS SITE — WordPress CMS markers present but page "
                          f"has only {visible_text_len} chars of content. Classic indicator of a "
                          f"compromised WordPress site that was cleaned/wiped but not restored. "
                          f"Attackers often leave broken WP installations behind."
            })

        # Check for default/placeholder pages.
        # IMPORTANT: Only check on thin pages (< 1000 chars visible text).
        # A full landing page with navigation, features, and footer that says
        # "Coming Soon" for one feature is NOT a parking page — it's a product
        # label.  Parking pages are characterised by minimal content + a
        # placeholder phrase being the DOMINANT message on the page.
        placeholder_signals = [
            "coming soon", "under construction", "parked domain",
            "this domain is for sale", "buy this domain",
            "default web page", "apache2 default page",
            "welcome to nginx", "it works!",
        ]
        # Definitive parking signals — always fire regardless of page size
        # (no legitimate site says "this domain is for sale" as a feature label)
        always_fire_signals = {
            "parked domain", "this domain is for sale", "buy this domain",
            "default web page", "apache2 default page",
            "welcome to nginx", "it works!",
        }
        for signal in placeholder_signals:
            if signal in content_lower:
                # For ambiguous signals ("coming soon", "under construction"),
                # only fire on thin pages where the signal is the dominant content
                if signal not in always_fire_signals and visible_text_len >= 1000:
                    continue  # Skip — this is likely a feature label on a real site
                score = min(score + 5, 30)
                findings.append({
                    "severity": "high",
                    "category": "placeholder_page",
                    "detail": f"Placeholder/default page detected ('{signal}'). Domain may be "
                              f"parked, abandoned, or recently hijacked."
                })
                break

        # hacklink_detected uses ONLY content-specific signals (keywords, hidden
        # injection with suspicious links, meta spam, spam outbound links).
        # Infrastructure signals (malicious scripts, CMS fingerprints, empty
        # pages) are separate threat classes and must NOT inflate this flag.
        #
        # v7.5.1: Score-based only.  The old `len(keywords_found) >= 2` fallback
        # caused false positives when 2 ambiguous keywords (bet + betting on a
        # trading site) scored only 8 but still triggered hacklink_detected.
        # Now: ambiguous-only 2-keyword matches score 8 (< 15, no detection),
        # while specific Turkish keywords or 3+ ambiguous keywords score 20+ (detection).
        hacklink_detected = hacklink_content_score >= 15

        # Determine hidden injection confidence
        if hidden_high_found:
            hidden_injection_confidence = "HIGH"
        elif hidden_low_found:
            hidden_injection_confidence = "LOW"
        else:
            hidden_injection_confidence = ""

        # ----- Generate Google Dork Queries -----
        google_dorks = self._generate_google_dorks(
            domain, keywords_found, injection_patterns, is_wordpress
        )

        return {
            "hacklink_detected": hacklink_detected,
            "score": min(score, 30),
            "keywords_found": keywords_found,
            "injection_patterns": injection_patterns,
            "suspicious_scripts": suspicious_scripts if suspicious_scripts else [],
            "wp_compromised": wp_compromised,
            "is_wordpress": is_wordpress,
            "is_cpanel": is_cpanel,
            "wp_plugins": wp_plugins,
            "vulnerable_plugins": vulnerable_plugins,
            "spam_link_count": spam_links,
            "spam_link_urls": spam_link_urls,
            "malicious_script_confidence": malicious_script_confidence,
            "malicious_script_signals": [s[0] for s in soc_signals],
            "malicious_script_score": soc_score_val,
            "hidden_injection_confidence": hidden_injection_confidence,
            "is_gambling_site": is_gambling_site,
            "google_dorks": google_dorks,
            "findings": findings,
            "fetch_status": fetch_status,
        }

    # ================================================================
    # Multi-Signal Detection Helpers (v7.2)
    # ================================================================

    @staticmethod
    def _calculate_path_entropy(path: str) -> float:
        """
        Calculate Shannon entropy of a URL path.
        Legitimate paths: 2.5-3.5 bits/char (readable words, predictable structure)
        SocGholish paths: 4.0-5.0+ bits/char (random alphanumeric gibberish)
        
        Examples:
            /wp-content/themes/flavor/main.js     → ~3.2 (legitimate)
            /f8a3c9d1e4b7/x2k9m4n7/tracker.js     → ~4.3 (suspicious)
        """
        if not path or len(path) < 5:
            return 0.0
        # Strip leading slashes and file extension for cleaner measurement
        clean = path.lstrip('/').rsplit('.', 1)[0] if '.' in path else path.lstrip('/')
        if not clean:
            return 0.0
        freq = {}
        for c in clean:
            freq[c] = freq.get(c, 0) + 1
        length = len(clean)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    @staticmethod
    def _is_whitelisted_cdn(domain: str) -> bool:
        """Check if a script domain is on the known-good CDN whitelist."""
        domain = domain.lower().strip('.')
        # Exact match
        if domain in CDN_WHITELIST:
            return True
        # Subdomain match (e.g., cdn.example.com matches if example.com is whitelisted)
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in CDN_WHITELIST:
                return True
        return False

    @staticmethod
    def _extract_script_domain(src: str) -> Optional[str]:
        """Extract the domain from a script src attribute value."""
        try:
            if src.startswith('//'):
                src = 'https:' + src
            elif not src.startswith(('http://', 'https://')):
                return None  # Relative path = same-domain, skip
            parsed = urlparse(src)
            return parsed.hostname.lower() if parsed.hostname else None
        except Exception:
            return None

    def _score_fetch_failure(self, domain, status, error, error_type, score, findings):
        """
        Score HTTP fetch failures as risk signals.
        A legitimate business domain that can't serve a web page is itself suspicious.
        """
        if status == 403:
            score += 8
            findings.append({
                "severity": "high",
                "category": "http_403",
                "detail": f"403 FORBIDDEN — {domain} blocks web access. Legitimate business "
                          f"sites don't typically block browsers. May indicate compromised "
                          f"infrastructure with attacker-configured access controls, or "
                          f"a domain that exists only for email-based attacks."
            })
        elif status == 401:
            score += 8
            findings.append({
                "severity": "high",
                "category": "http_401",
                "detail": f"401 UNAUTHORIZED — {domain} requires authentication. Very unusual "
                          f"for a domain being used as an email sending domain."
            })
        elif status == 404:
            score += 5
            findings.append({
                "severity": "medium",
                "category": "http_404",
                "detail": f"404 NOT FOUND — {domain} returns 404 at root. Domain exists in "
                          f"DNS but has no web content. Suspicious for an active sending domain."
            })
        elif status in (500, 502, 503, 504):
            score += 6
            findings.append({
                "severity": "high",
                "category": "http_server_error",
                "detail": f"SERVER ERROR ({status}) — {domain} is broken/down. A sending domain "
                          f"with failing web infrastructure is a signal of compromised or "
                          f"abandoned infrastructure being abused."
            })
        elif error_type == "timeout":
            score += 7
            findings.append({
                "severity": "high",
                "category": "http_timeout",
                "detail": f"CONNECTION TIMEOUT — {domain} did not respond. Sending domain with "
                          f"unreachable web server is suspicious. May indicate overwhelmed "
                          f"compromised infrastructure or intentionally non-web-facing setup."
            })
        elif error_type == "ssl_error":
            score += 8
            findings.append({
                "severity": "high",
                "category": "ssl_error",
                "detail": f"SSL/TLS ERROR — {domain} has certificate problems. Compromised "
                          f"domains often have expired, self-signed, or mismatched certificates "
                          f"when the attacker doesn't maintain the original SSL setup."
            })
        elif error_type == "connection_refused":
            score += 7
            findings.append({
                "severity": "high",
                "category": "connection_refused",
                "detail": f"CONNECTION REFUSED — {domain} actively refused connection. No web "
                          f"server running. Suspicious for a domain used for email sending."
            })
        elif error_type == "dns_failure":
            score += 10
            findings.append({
                "severity": "critical",
                "category": "dns_failure",
                "detail": f"DNS RESOLUTION FAILED — {domain} does not resolve. Domain may be "
                          f"expired, suspended, or using DNS that only resolves for email. "
                          f"Critical risk signal."
            })
        else:
            score += 5
            findings.append({
                "severity": "medium",
                "category": "fetch_failed",
                "detail": f"FETCH FAILED — {domain}: {error or 'unknown error'}. Unable to "
                          f"verify web presence of this sending domain."
            })

        return score, findings

    @staticmethod
    def _is_gambling_site(domain: str, page_content: str) -> bool:
        """Determine if the site is a LEGITIMATE gambling/gaming/casino business.

        A gambling site's own visible content will naturally contain keywords
        like "casino", "slot", "bingo", "bet" — these are their product, not
        evidence of compromise.  When this returns True the keyword scanner
        suppresses scoring for gambling terms found in *visible* content and
        only scores keywords found inside hidden (CSS-cloaked) blocks.

        Detection signals (need 2+ to confirm):
          - Domain name contains gambling terms (locobingo, casinorange, etc.)
          - <title> contains gambling terms
          - <h1> contains gambling terms
          - <meta description> contains gambling terms
        """
        GAMBLING_SIGNALS = {
            "casino", "bingo", "poker", "slot", "slots", "betting",
            "bet", "bahis", "blackjack", "roulette", "rulet", "lottery",
            "lotto", "jackpot", "gamble", "gambling", "wager", "sportsbook",
        }
        hits = 0

        # 1. Domain name — substring match within each segment
        #    "locobingo" contains "bingo", "casinorange" contains "casino", etc.
        segments = set(re.split(r'[.\-]', domain.lower()))
        segments -= {"com", "net", "org", "co", "io", "es", "uk", "de", "fr"}
        for seg in segments:
            if any(g in seg for g in GAMBLING_SIGNALS):
                hits += 1
                break

        content_lower = page_content.lower() if page_content else ""

        # 2. <title>
        title_m = re.search(r'<title[^>]*>([^<]{0,300})</title>', content_lower)
        if title_m and any(g in title_m.group(1) for g in GAMBLING_SIGNALS):
            hits += 1

        # 3. <h1>
        h1_m = re.search(r'<h1[^>]*>(.{0,300}?)</h1>', content_lower, re.DOTALL)
        if h1_m and any(g in h1_m.group(1) for g in GAMBLING_SIGNALS):
            hits += 1

        # 4. <meta description>
        meta_m = re.search(
            r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']{0,500})["\']',
            content_lower,
        )
        if meta_m and any(g in meta_m.group(1) for g in GAMBLING_SIGNALS):
            hits += 1

        return hits >= 2

    def _check_domain_name(self, domain: str) -> List[str]:
        """Check if the domain name itself contains hacklink-associated keywords.
        
        Uses segment-based matching: the domain is split into labels (by '.'
        and '-') and each label is checked against the keyword set.  This
        prevents 'slot' matching 'timeslot.com' or 'bonus' matching
        'bonushour.com' while still catching 'casino-online.com' and
        'bahisplus.com'.
        """
        domain_name_keywords = {
            "hacklink", "bahis", "casino", "kumar", "slot", "betting",
            "escort", "cialis", "viagra", "nakliyat", "cekici",
            "porno", "bonus", "iddaa", "rulet", "poker",
        }
        # Split into segments: "bahis-siteleri.example.com" → {"bahis","siteleri","example","com"}
        segments = set(re.split(r'[.\-]', domain.lower()))
        # Remove common TLD/SLD segments that could collide
        segments.discard("com")
        segments.discard("net")
        segments.discard("org")
        segments.discard("co")
        segments.discard("io")
        return sorted(segments & domain_name_keywords)

    def _fetch_content(self, url: str):
        """Fetch page content with safety limits. Returns (content, status_code)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
        })

        resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
        content = resp.read(self.max_content_size)
        status = resp.status if hasattr(resp, 'status') else 200
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            text = content.decode("latin-1", errors="replace")
        return text, status

    def _check_meta_anomalies(self, content: str) -> List[Dict]:
        """Check for suspicious meta tag patterns indicating compromise."""
        findings = []

        meta_kw = re.search(
            r'<meta[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\']+)["\']',
            content, re.IGNORECASE
        )
        if meta_kw:
            kw_content = meta_kw.group(1).lower()
            # Check long phrases (substring)
            spam_kws = [k for k in TURKISH_HACKLINK_KEYWORDS if k in kw_content]
            # Check short keywords (word-boundary) — meta keywords are
            # comma-separated tags so \b works well here
            for pattern in HACKLINK_EXACT_COMPILED:
                m = pattern.search(kw_content)
                if m:
                    spam_kws.append(m.group())
            if spam_kws:
                findings.append({
                    "severity": "critical",
                    "category": "meta_injection",
                    "detail": f"Meta keywords contain hacklink/spam terms: {', '.join(spam_kws[:5])}"
                })

        lang_tag = re.search(r'<html[^>]*lang=["\']([^"\']+)["\']', content, re.IGNORECASE)
        if lang_tag:
            page_lang = lang_tag.group(1).lower()[:2]
            has_turkish_kws = any(k in content.lower() for k in ["hacklink", "bahis", "canlı"])
            if has_turkish_kws and page_lang not in ["tr", "az"]:
                findings.append({
                    "severity": "high",
                    "category": "language_mismatch",
                    "detail": f"Turkish hacklink keywords on a '{page_lang}' language page. "
                              f"Strong indicator of injection/compromise."
                })

        return findings

    def _count_spam_outbound_links(self, content: str) -> tuple:
        """Count outbound links to known spam categories and return matching URLs.
        
        Uses URL-segment-aware matching: short keywords must appear as
        standalone domain labels or path segments (delimited by . / - _)
        to avoid false positives like 'bet' matching 'alphabet.com' or
        'sex' matching 'essex.gov.uk'.
        
        Returns:
            tuple: (count: int, urls: list[str]) — count and list of matching URLs
        """
        # Extract all outbound hrefs first
        hrefs = re.findall(
            r'href=["\']https?://([^"\']+)["\']', content, re.IGNORECASE
        )
        if not hrefs:
            return 0, []

        # Long/specific terms — safe for substring matching in URLs
        _SPAM_URL_PHRASES = [
            "casino", "bahis", "kumar", "escort", "porno",
            "viagra", "cialis", "pharma", "hacklink",
            "weight-loss", "weightloss", "weight_loss",
            "seo-link", "seolink", "backlink-service",
            "backlinkservice",
        ]

        # Short terms — require URL segment boundaries (. / - _ or start/end)
        # This prevents "bet" matching "alphabet", "sex" matching "essex", etc.
        _SPAM_URL_SEGMENT_RE = re.compile(
            r'(?:^|[./_-])'           # segment start: beginning or delimiter
            r'(?:bet|slot|slots|poker|xxx|sex|pill|drug)'
            r'(?:$|[./_\-?#])',       # segment end: end or delimiter or query
            re.IGNORECASE
        )

        count = 0
        matched_urls = []
        for href in hrefs:
            href_lower = href.lower()
            # Check long phrases (substring OK)
            if any(phrase in href_lower for phrase in _SPAM_URL_PHRASES):
                count += 1
                matched_urls.append(href)
                continue
            # Check short terms (segment-boundary match)
            if _SPAM_URL_SEGMENT_RE.search(href_lower):
                count += 1
                matched_urls.append(href)
        return count, matched_urls[:20]  # Cap at 20 to avoid bloat

    def _extract_wp_plugins(self, content: str) -> List[str]:
        """Extract WordPress plugin slugs from page source HTML."""
        plugin_pattern = r'wp-content/plugins/([a-zA-Z0-9_-]+)/'
        matches = re.findall(plugin_pattern, content, re.IGNORECASE)
        # Deduplicate preserving order
        seen = set()
        plugins = []
        for p in matches:
            slug = p.lower()
            if slug not in seen:
                seen.add(slug)
                plugins.append(slug)
        return plugins

    def _check_plugin_vulnerabilities(self, plugins: List[str]) -> List[Dict]:
        """
        Check extracted WordPress plugins against known vulnerable plugins
        frequently exploited in hacklink campaigns.
        Returns list of {plugin, risk, cve_ref, detail} dicts.
        """
        # Plugins commonly exploited in hacklink/SEO spam campaigns
        # Sources: WPScan, Wordfence, Sucuri reports
        KNOWN_VULNERABLE = {
            "revslider": {
                "risk": "CRITICAL",
                "cve": "CVE-2014-9734",
                "detail": "Revolution Slider — arbitrary file download/upload, "
                          "one of the most exploited WP plugins in hacklink campaigns.",
            },
            "developer-flavor-developer": {
                "risk": "CRITICAL",
                "cve": "CVE-2021-24990",
                "detail": "Developer Flavor — arbitrary file upload, hacklink injection vector.",
            },
            "contact-form-7": {
                "risk": "HIGH",
                "cve": "CVE-2020-35489",
                "detail": "Contact Form 7 — unrestricted file upload in older versions.",
            },
            "wp-file-manager": {
                "risk": "CRITICAL",
                "cve": "CVE-2020-25213",
                "detail": "WP File Manager — unauthenticated arbitrary file upload.",
            },
            "elementor": {
                "risk": "HIGH",
                "cve": "CVE-2022-29455",
                "detail": "Elementor — DOM XSS and privilege escalation in various versions.",
            },
            "wpgateway": {
                "risk": "CRITICAL",
                "cve": "CVE-2022-3180",
                "detail": "WP Gateway — unauthenticated privilege escalation.",
            },
            "tatsu": {
                "risk": "CRITICAL",
                "cve": "CVE-2021-25094",
                "detail": "Tatsu Builder — unauthenticated RCE via file upload.",
            },
            "wp-statistics": {
                "risk": "HIGH",
                "cve": "CVE-2022-25148",
                "detail": "WP Statistics — SQL injection in older versions.",
            },
            "essential-addons-for-elementor-lite": {
                "risk": "CRITICAL",
                "cve": "CVE-2023-32243",
                "detail": "Essential Addons for Elementor — privilege escalation.",
            },
            "woocommerce": {
                "risk": "MEDIUM",
                "cve": "CVE-2023-28121",
                "detail": "WooCommerce — authentication bypass in various versions.",
            },
            "yoast-seo": {
                "risk": "MEDIUM",
                "cve": "Multiple",
                "detail": "Yoast SEO — various XSS and SQL injection in older versions.",
            },
            "duplicator": {
                "risk": "CRITICAL",
                "cve": "CVE-2020-11738",
                "detail": "Duplicator — arbitrary file download and path traversal.",
            },
            "jetstyle": {
                "risk": "HIGH",
                "cve": "CVE-2021-24390",
                "detail": "JetStyle — arbitrary file upload vulnerability.",
            },
            "brizy": {
                "risk": "HIGH",
                "cve": "CVE-2021-38314",
                "detail": "Brizy Builder — information disclosure and file upload.",
            },
            "gravityforms": {
                "risk": "HIGH",
                "cve": "CVE-2023-28782",
                "detail": "Gravity Forms — object injection vulnerability.",
            },
            "formidable": {
                "risk": "HIGH",
                "cve": "CVE-2021-24836",
                "detail": "Formidable Forms — multiple injection vulnerabilities.",
            },
            "easy-wp-smtp": {
                "risk": "HIGH",
                "cve": "CVE-2019-8942",
                "detail": "Easy WP SMTP — debug log exposure, credential theft.",
            },
            "coming-soon": {
                "risk": "MEDIUM",
                "cve": "CVE-2021-24917",
                "detail": "SeedProd Coming Soon — subscriber data exposure.",
            },
            "jetstyle-developer": {
                "risk": "HIGH",
                "cve": "Multiple",
                "detail": "JetStyle Developer — common hacklink injection vector.",
            },
            "all-in-one-seo-pack": {
                "risk": "HIGH",
                "cve": "CVE-2021-25036",
                "detail": "All in One SEO — privilege escalation and SQL injection.",
            },
        }

        vulnerabilities = []
        for plugin in plugins:
            slug = plugin.lower().strip()
            if slug in KNOWN_VULNERABLE:
                vuln = KNOWN_VULNERABLE[slug]
                vulnerabilities.append({
                    "plugin": slug,
                    "risk": vuln["risk"],
                    "cve": vuln["cve"],
                    "detail": vuln["detail"],
                })
        return vulnerabilities

    def _generate_google_dorks(self, domain: str, keywords: List[str],
                                patterns: List[str], is_wordpress: bool) -> List[Dict]:
        """
        Generate Google dork queries to find other sites compromised with
        the same patterns, or to discover additional injected content.
        """
        dorks = []

        # 1. Find other sites with same injected keywords
        if keywords:
            kw_sample = " ".join(keywords[:3])
            dorks.append({
                "category": "find_other_victims",
                "query": f'intext:"{kw_sample}" -site:{domain}',
                "description": f"Find other sites injected with the same keywords: {kw_sample}",
            })

        # 2. Find cached/indexed hacklink content on this domain
        dorks.append({
            "category": "cached_content",
            "query": f'site:{domain} intext:"hacklink" OR intext:"bahis" OR intext:"casino"',
            "description": "Find indexed hacklink/gambling content on this domain",
        })

        # 3. Find hidden pages/directories
        dorks.append({
            "category": "hidden_pages",
            "query": f'site:{domain} inurl:wp-content OR inurl:wp-admin OR inurl:wp-includes',
            "description": "Find exposed WordPress paths that may contain injected content",
        })

        # 4. WordPress-specific dorks
        if is_wordpress:
            dorks.append({
                "category": "wp_exposed_files",
                "query": f'site:{domain} filetype:sql OR filetype:log OR filetype:bak',
                "description": "Find exposed database dumps, logs, or backups",
            })
            dorks.append({
                "category": "wp_login",
                "query": f'site:{domain} inurl:wp-login.php OR inurl:xmlrpc.php',
                "description": "Find WordPress login and XML-RPC endpoints",
            })

        # 5. Find injection patterns across the web
        if patterns:
            for pat in patterns[:2]:
                dorks.append({
                    "category": "injection_pattern",
                    "query": f'intext:"{pat}" -site:{domain}',
                    "description": f"Find other sites with same injection pattern: {pat}",
                })

        # 6. Link-based dork to find who links to this domain
        dorks.append({
            "category": "backlink_discovery",
            "query": f'intext:"{domain}" -site:{domain}',
            "description": f"Find sites that reference or link to {domain}",
        })

        # 7. Turkish hacklink-specific campaign dorks
        dorks.append({
            "category": "hacklink_campaign",
            "query": f'intext:"hacklink satın al" OR intext:"hacklink paneli" site:{domain}',
            "description": "Find Turkish hacklink marketplace content on this domain",
        })

        return dorks
