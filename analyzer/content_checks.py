"""
Content Identity Verification
==============================
Detects domains that pass DNS/email infrastructure checks but have
suspicious web content: cloned pages, identity mismatches, domain
broker facades, cross-domain email references, SPA shell facades.

Plugs into analyzer.py alongside VirusTotal and hacklink checks.
Reuses pre-fetched page content (no duplicate HTTP requests).

VERSION: 1.1 (Feb 2026)
- Title vs body identity mismatch
- Cross-domain email detection (kigs.app showing @topdot.com emails)
- Privacy/freemail/disposable email on business page
- Domain broker / parking / for-sale detection
- Placeholder / template content detection
- Content + structure hashing for cross-domain clone detection
- SPA shell / content facade detection (title but no body content)
- External script domain extraction
"""

import re
import hashlib
import logging
from typing import Dict, List, Set
from urllib.parse import urlparse

log = logging.getLogger("content_checks")


# ─────────────────────────────────────────────
# REFERENCE DATA
# ─────────────────────────────────────────────

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "icloud.com", "zoho.com", "yandex.com", "gmx.com",
    "live.com", "msn.com", "yahoo.co.uk", "googlemail.com",
}

PRIVACY_EMAIL_DOMAINS = {
    "protonmail.com", "proton.me", "pm.me",
    "tutanota.com", "tuta.io", "tutanota.de",
    "hushmail.com", "mailfence.com",
    "disroot.org", "riseup.net", "cock.li", "airmail.cc",
}

DISPOSABLE_EMAIL_DOMAINS = {
    "tempmail.com", "guerrillamail.com", "throwaway.email",
    "mailinator.com", "sharklasers.com", "yopmail.com",
    "trashmail.com", "10minutemail.com", "temp-mail.org",
}

BROKER_PARKING_PHRASES = [
    "domain brokerage", "domain broker", "domain for sale",
    "buy this domain", "purchase this domain", "make an offer",
    "domain acquisition", "premium domain", "domain portfolio",
    "submit inquiry", "domain monetization", "domain search",
    "parked domain", "this domain is for sale", "inquire about",
    "domain transfer", "domain escrow", "domain appraisal",
    "brokerage services", "domain services", "domain marketplace",
    "featured domains", "find your perfect domain",
    "domain provider", "portfolio management",
]

PLACEHOLDER_PHRASES = [
    "lorem ipsum", "coming soon", "under construction",
    "website coming soon", "page under construction",
    "sample page", "hello world", "default page", "test page",
]

IGNORE_EMAIL_DOMAINS = {
    "cloudflare.com", "google.com", "wordpress.com", "gravatar.com",
    "w3.org", "schema.org", "sentry.io", "googleapis.com",
    "gstatic.com", "facebook.com", "twitter.com", "github.com",
    # Placeholder / example / documentation domains (RFC 2606 + common form placeholders)
    "example.com", "example.org", "example.net", "test.com",
    "email.com", "domain.com", "yourdomain.com", "yourcompany.com",
    "yoursite.com", "youremail.com", "company.com", "website.com",
    "mysite.com", "mydomain.com", "mail.example.com", "placeholder.com",
    "sample.com", "address.com", "business.com",
}

# Common placeholder email local parts — if the local part matches one of these
# AND the domain is generic, the email is almost certainly a form placeholder
# like "your@email.com", "name@domain.com", "user@example.com"
PLACEHOLDER_EMAIL_PATTERNS = {
    "your", "you", "user", "name", "email", "info", "example",
    "username", "test", "sample", "placeholder", "me", "address",
    "john", "jane", "yourname", "youremail", "myemail",
}

# Known-good CDN/framework script hosts — don't flag these as suspicious external scripts
KNOWN_SCRIPT_HOSTS = {
    "cdnjs.cloudflare.com", "cdn.cloudflare.com", "ajax.cloudflare.com",
    "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com",
    "fonts.googleapis.com", "maps.googleapis.com", "www.googleapis.com",
    "www.google-analytics.com", "www.googletagmanager.com",
    "connect.facebook.net", "platform.twitter.com",
    "js.stripe.com", "checkout.stripe.com",
    "cdn.shopify.com", "assets.squarespace.com",
    "static.cloudflareinsights.com", "challenges.cloudflare.com",
    "www.recaptcha.net", "www.gstatic.com",
    "code.jquery.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "cdn.bootcss.com",
    "use.fontawesome.com", "kit.fontawesome.com",
    "polyfill.io", "cdn.polyfill.io",
    "d3js.org", "cdn.plot.ly",
    "hm.baidu.com", "s.yimg.com",
    # Push notification / messaging SDKs
    "cdn.onesignal.com", "onesignal.com",
    "js.pusher.com", "js.pusherapp.com",
    "www.pushwoosh.com",
    "sdk.pushcrew.com",
}


# ─────────────────────────────────────────────
# EXTRACTION HELPERS
# ─────────────────────────────────────────────

def _extract_emails(html: str) -> List[str]:
    return list(set(re.findall(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html
    )))

def _extract_phones(text: str) -> List[str]:
    patterns = [
        r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
    ]
    phones = []
    for p in patterns:
        phones.extend(re.findall(p, text))
    return list(set(phones))

def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.DOTALL)
    return match.group(1).strip() if match else ""


def _detect_spa_framework(html: str) -> tuple:
    """Detect known SPA framework fingerprints in raw (pre-JS) HTML.

    Legitimate React/Next.js/Vue/Angular/Nuxt apps leave characteristic markers
    in their server-sent HTML that phishing shells almost never replicate:
    mount points, hydration data blobs, framework version attributes, etc.

    Returns (detected: bool, framework_name: str).

    IMPORTANT: Only include patterns that are (a) specific to the framework and
    (b) extremely unlikely to appear in a phishing shell.  Generic patterns like
    a bare <div id="root"> are NOT included because they can be trivially copied.
    We require at least one *structural* or *data* fingerprint.
    """
    # Next.js: server-side __NEXT_DATA__ JSON blob injected into every page
    if re.search(r'<script[^>]*id=["\']__NEXT_DATA__["\']', html, re.I):
        return True, "Next.js"

    # Next.js: __next_f or self.__next_f push pattern (app router streaming)
    if re.search(r'self\.__next_f\s*=\s*\[|self\.__next_f\.push', html, re.I):
        return True, "Next.js (App Router)"

    # Nuxt.js: window.__NUXT__ hydration payload or <div id="__nuxt"> mount point
    if re.search(r'window\.__NUXT__\s*=', html, re.I):
        return True, "Nuxt.js"
    if re.search(r'<div[^>]+id=["\']__nuxt["\']', html, re.I):
        return True, "Nuxt.js"

    # Angular Universal (SSR): ng-version attribute or TransferState blob
    if re.search(r'ng-version=["\'][\d.]+["\']', html, re.I):
        return True, "Angular"
    if re.search(r'<script[^>]*id=["\']ng-state["\']', html, re.I):
        return True, "Angular"

    # Gatsby
    if re.search(r'window\.___gatsby|<script[^>]*id=["\']gatsby-chunk-mapping["\']', html, re.I):
        return True, "Gatsby"

    # Remix
    if re.search(r'window\.__remixContext\s*=', html, re.I):
        return True, "Remix"

    # React 18 SSR streaming markers
    if re.search(r'<!--\$-->|<!--\$\?-->|<!--\$!-->', html):
        return True, "React (SSR)"

    # SvelteKit
    if re.search(r'__sveltekit_[a-z0-9]+\s*=', html, re.I):
        return True, "SvelteKit"

    # Astro
    if re.search(r'<astro-island|data-astro-cid-', html, re.I):
        return True, "Astro"

    # Vite production build (client-side React/Vue/Svelte):
    # type="module" script loading from a local /assets/index-HASH.js path.
    # The hashed filename under /assets/ is Vite's content-hashing output.
    # Phishing shells load from external domains, not local /assets/.
    _vite_srcs = re.findall(
        r'<script[^>]+type=["\']module["\'][^>]+src=["\']([^"\']+)["\']',
        html, re.I
    )
    if any(re.search(r'^/assets/[^/]+-[A-Za-z0-9_-]{6,}\.js$', s) for s in _vite_srcs):
        return True, "Vite (React/Vue/Svelte)"

    # Schema.org Organization/LocalBusiness structured data.
    # Legitimate sites add JSON-LD for SEO; phishing shells essentially never do.
    if re.search(r'<script[^>]+type=["\']application/ld\+json["\']', html, re.I):
        if re.search(
            r'"@type"\s*:\s*"(Organization|LocalBusiness|Corporation|WebSite|SoftwareApplication)"',
            html, re.I
        ):
            return True, "Schema.org structured data (Organization)"

    return False, ""

def _visible_text(html: str) -> str:
    text = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.I)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.I)
    text = re.sub(r"<noscript[^>]*>.*?</noscript>", "", text, flags=re.DOTALL | re.I)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    # Remove URLs
    text = re.sub(r"https?://\S+", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def _content_hash(text: str) -> str:
    normalized = re.sub(r"\d+", "", text.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return hashlib.sha256(normalized.encode()).hexdigest()

def _structure_hash(html: str) -> str:
    tags = re.findall(r"<(/?\w+)", html)
    return hashlib.sha256(" ".join(tags[:500]).encode()).hexdigest()

def _extract_external_script_domains(html: str, page_domain: str) -> List[str]:
    """Extract domains of external <script src="..."> that aren't known CDNs."""
    src_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    domains = set()
    page_base = page_domain.lower().split(".")[-2] if "." in page_domain else page_domain.lower()

    for url in src_urls:
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower() or ""
            if not host and url.startswith("//"):
                host = url.split("//")[1].split("/")[0].lower()
            if not host:
                continue
            # Skip if it's the page's own domain
            if page_domain.lower() in host or page_base in host:
                continue
            # Skip known CDN/framework hosts
            if host in KNOWN_SCRIPT_HOSTS:
                continue
            domains.add(host)
        except Exception:
            continue
    return sorted(domains)

def _extract_all_script_domains(html: str, page_domain: str) -> List[str]:
    """Extract ALL external script domains (including CDNs) for visibility."""
    src_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    domains = set()
    page_base = page_domain.lower().split(".")[-2] if "." in page_domain else page_domain.lower()

    for url in src_urls:
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower() or ""
            if not host and url.startswith("//"):
                host = url.split("//")[1].split("/")[0].lower()
            if not host:
                continue
            if page_domain.lower() in host or page_base in host:
                continue
            domains.add(host)
        except Exception:
            continue
    return sorted(domains)

def _extract_external_link_domains(html: str, page_domain: str) -> List[str]:
    """Extract all unique external domains linked via <a href=\"...\"> on the page.
    
    Returns sorted list of (domain, sample_path) tuples as strings like
    "www.iubenda.com → /privacy-policy/219337" for analyst visibility.
    Excludes same-domain links and common infrastructure (CDNs, fonts, analytics).
    """
    href_urls = re.findall(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I)
    page_base = page_domain.lower().split(".")[-2] if "." in page_domain else page_domain.lower()
    
    # Infrastructure domains that aren't interesting for analysts
    _INFRA_DOMAINS = {
        "fonts.googleapis.com", "fonts.gstatic.com", "www.google.com",
        "www.googletagmanager.com", "www.google-analytics.com",
        "ajax.googleapis.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
        "unpkg.com", "maxcdn.bootstrapcdn.com", "use.fontawesome.com",
        "kit.fontawesome.com", "www.facebook.com", "twitter.com",
        "x.com", "www.instagram.com", "www.linkedin.com", "www.youtube.com",
        "t.me", "wa.me", "api.whatsapp.com",
    }
    
    seen = {}  # domain -> first path seen
    for url in href_urls:
        try:
            if not url.startswith("http"):
                continue
            parsed = urlparse(url)
            host = parsed.netloc.lower().strip(".")
            if not host:
                continue
            # Skip same-domain
            if page_domain.lower() in host or host in page_domain.lower():
                continue
            if page_base in host.split("."):
                continue
            # Skip infrastructure
            if host in _INFRA_DOMAINS:
                continue
            # Skip anchor/javascript links
            if parsed.scheme not in ("http", "https"):
                continue
            if host not in seen:
                path = parsed.path[:60] if parsed.path and parsed.path != "/" else ""
                seen[host] = path
        except Exception:
            continue
    
    # Format as "domain → /path" for readability
    results = []
    for domain, path in sorted(seen.items()):
        if path:
            results.append(f"{domain} → {path}")
        else:
            results.append(domain)
    return results[:20]  # Cap at 20 to avoid noise


def _word_count(text: str) -> int:
    """Count meaningful words (3+ chars, alpha only)."""
    words = re.findall(r"\b[a-zA-Z]{3,}\b", text)
    return len(words)


# ─────────────────────────────────────────────
# MAIN CHECK FUNCTION
# ─────────────────────────────────────────────

def check_content_identity(domain: str, content: str = "") -> Dict:
    """
    Run content identity checks on pre-fetched page content.

    Args:
        domain: The domain being checked (e.g., "kigs.app")
        content: Pre-fetched HTML string (from analyzer's existing fetch)

    Returns:
        Dict with all findings — stored on DomainApprovalResult fields
    """
    result = {
        "title_body_mismatch": False,
        "title_body_mismatch_detail": "",
        "cross_domain_emails": [],
        "cross_domain_email_domains": [],
        "page_privacy_emails": [],
        "page_freemail_contacts": [],
        "page_disposable_emails": [],
        "is_broker_page": False,
        "broker_indicators": [],
        "is_placeholder": False,
        "placeholder_phrases": [],
        "page_emails": [],
        "page_phones": [],
        "content_hash": "",
        "structure_hash": "",
        "title": "",
        # SPA shell / content facade
        "is_content_facade": False,
        "facade_detail": "",
        "spa_framework_detected": False,     # True when HTML contains known React/Vue/Next/Angular fingerprints
        "spa_framework_name": "",            # e.g. "Next.js", "React", "Vue", "Angular"
        "external_script_domains": [],
        "all_script_domains": [],
        "external_link_domains": [],       # All external domains linked via <a href>
        "visible_word_count": 0,
    }

    if not content or len(content) < 50:
        return result

    html = content
    title = _extract_title(html)
    visible = _visible_text(html)
    emails = _extract_emails(html)
    phones = _extract_phones(visible)
    word_count = _word_count(visible)
    ext_script_domains = _extract_external_script_domains(html, domain)
    all_script_domains = _extract_all_script_domains(html, domain)
    ext_link_domains = _extract_external_link_domains(html, domain)

    result["title"] = title
    result["page_emails"] = emails
    result["page_phones"] = phones
    result["content_hash"] = _content_hash(visible)
    result["structure_hash"] = _structure_hash(html)
    result["external_script_domains"] = ext_script_domains
    result["all_script_domains"] = all_script_domains
    result["external_link_domains"] = ext_link_domains
    result["visible_word_count"] = word_count

    domain_lower = domain.lower()
    domain_base = domain_lower.split(".")[0]

    # ── SPA FRAMEWORK FINGERPRINTING ──
    # Detect known React/Next.js/Vue/Angular/Nuxt patterns BEFORE facade check.
    # A confirmed framework fingerprint means the low visible word count is
    # explained by client-side rendering, not content hiding.
    _spa_fw_detected, _spa_fw_name = _detect_spa_framework(html)
    result["spa_framework_detected"] = _spa_fw_detected
    result["spa_framework_name"] = _spa_fw_name

    # ── CHECK 1: SPA Shell / Content Facade ──
    # Page has a title but virtually no visible body text.
    # Combined with external script loading, this is suspicious:
    # the domain claims to be something (via title) but serves
    # no actual content — everything is loaded via JS from elsewhere.
    #
    # SUPPRESSION: If a known SPA framework fingerprint is present, the low
    # word count is explained by legitimate client-side rendering.  Don't flag
    # as a facade — it's a real app that requires JS to display content.
    # The framework_detected flag is returned so the caller can still apply
    # reduced trust (it's still an opaque surface), but it won't be treated
    # as a phishing shell.
    has_title = bool(title and len(title.strip()) > 3)
    has_scripts = bool(re.search(r'<script', html, re.I))
    has_external_scripts = bool(re.search(r'<script[^>]+src=', html, re.I))

    if has_title and word_count < 30 and not _spa_fw_detected:
        # Very few visible words — this is a shell page
        if has_external_scripts:
            result["is_content_facade"] = True
            parts = [
                f"Title claims '{title}' but page body has only {word_count} visible words",
                f"Content loaded entirely via external JavaScript",
            ]
            if ext_script_domains:
                parts.append(f"Non-CDN scripts from: {', '.join(ext_script_domains[:5])}")
            elif all_script_domains:
                parts.append(f"Scripts from: {', '.join(all_script_domains[:5])}")
            result["facade_detail"] = " — ".join(parts)
        elif has_scripts and word_count < 10:
            # Inline scripts only but still almost empty
            result["is_content_facade"] = True
            result["facade_detail"] = (
                f"Title claims '{title}' but page body has only {word_count} "
                f"visible words — likely SPA shell or redirect page"
            )

    # ── CHECK 2: Title vs Body mismatch ──
    # Only check if there's enough body content to compare against
    if title and word_count > 50:
        title_words = set(re.findall(r"\b[a-z]{4,}\b", title.lower()))
        stopwords = {"this", "that", "with", "from", "your", "have", "been",
                     "will", "about", "more", "what", "when", "which", "their",
                     "other", "some", "than", "into", "over", "just", "also",
                     "home", "page", "site", "welcome"}
        title_words -= stopwords

        if title_words:
            matches = sum(1 for w in title_words if w in visible.lower())
            ratio = matches / len(title_words)
            if ratio < 0.25:
                result["title_body_mismatch"] = True
                result["title_body_mismatch_detail"] = (
                    f"Title '{title}' — {matches}/{len(title_words)} "
                    f"keywords found in body ({ratio:.0%} match)"
                )

    # ── CHECK 3: Cross-domain emails ──
    for email in emails:
        if "@" not in email:
            continue
        local_part, email_domain = email.split("@", 1)
        email_domain = email_domain.lower()
        local_lower = local_part.lower()
        if email_domain in IGNORE_EMAIL_DOMAINS:
            continue
        # Skip common form placeholder emails (e.g. your@email.com, name@domain.com)
        if local_lower in PLACEHOLDER_EMAIL_PATTERNS:
            continue
        if email_domain == domain_lower:
            continue
        if domain_base in email_domain or email_domain.split(".")[0] in domain_lower:
            continue
        result["cross_domain_emails"].append(email)
        if email_domain not in result["cross_domain_email_domains"]:
            result["cross_domain_email_domains"].append(email_domain)

    # ── CHECK 4: Privacy / freemail / disposable on page ──
    for email in emails:
        if "@" not in email:
            continue
        local_part = email.split("@", 1)[0].lower()
        email_domain = email.split("@")[1].lower()
        # Skip form placeholders (e.g. your@gmail.com in a placeholder attr)
        if local_part in PLACEHOLDER_EMAIL_PATTERNS:
            continue
        if email_domain in IGNORE_EMAIL_DOMAINS:
            continue
        if email_domain in PRIVACY_EMAIL_DOMAINS:
            result["page_privacy_emails"].append(email)
        elif email_domain in DISPOSABLE_EMAIL_DOMAINS:
            result["page_disposable_emails"].append(email)
        elif email_domain in FREEMAIL_DOMAINS:
            result["page_freemail_contacts"].append(email)

    # ── CHECK 5: Domain broker / parking / for-sale page ──
    text_lower = visible.lower()
    matched_phrases = [p for p in BROKER_PARKING_PHRASES if p in text_lower]
    result["broker_indicators"] = matched_phrases
    if len(matched_phrases) >= 3:
        result["is_broker_page"] = True

    # ── CHECK 6: Placeholder / template content ──
    matched_placeholders = [p for p in PLACEHOLDER_PHRASES if p in text_lower]
    result["placeholder_phrases"] = matched_placeholders
    if matched_placeholders:
        result["is_placeholder"] = True

    return result
