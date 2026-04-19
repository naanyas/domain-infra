"""
Contact Cross-Reference OSINT Module
=====================================
During domain analysis, searches the web for emails and phone numbers
found on the page to discover if the same contact info appears on
other unrelated domains.

Use case: Catch coordinated phishing campaigns, domain networks run
by the same operator, or shared infrastructure patterns.

Currently informational — displayed in domain detail view but not scored.
"""

import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Emails to skip — generic/functional addresses that appear everywhere
SKIP_EMAIL_PATTERNS = {
    "noreply", "no-reply", "do-not-reply", "donotreply",
    "postmaster", "hostmaster", "webmaster", "abuse",
    "mailer-daemon", "root", "nobody",
}

# Domains to exclude from results (search engines, social media, directories)
NOISE_DOMAINS = {
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
    "facebook.com", "twitter.com", "linkedin.com", "instagram.com",
    "youtube.com", "reddit.com", "pinterest.com", "tiktok.com",
    "wikipedia.org", "github.com", "stackoverflow.com",
    "trustpilot.com", "yelp.com", "bbb.org",
    "whois.com", "whois.net", "who.is", "lookup.icann.org",
    "domaintools.com", "viewdns.info", "dnschecker.org",
    "hunter.io", "emailhippo.com", "verify-email.org",
    "phonenumbervalidator.com", "whitepages.com", "truecaller.com",
    "opencorporates.com", "companieshouse.gov.uk",
}


def _normalize_domain(hostname: str) -> str:
    """Strip www. and lowercase a hostname."""
    d = hostname.lower().strip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def _is_noise_domain(domain: str) -> bool:
    """Check if domain is a search engine, social media, or directory site."""
    d = _normalize_domain(domain)
    if d in NOISE_DOMAINS:
        return True
    # Check parent domain (e.g., m.facebook.com, uk.trustpilot.com)
    parts = d.split(".")
    if len(parts) > 2:
        parent = ".".join(parts[-2:])
        if parent in NOISE_DOMAINS:
            return True
    return False


def _is_same_org_domain(domain: str, current_domain: str) -> bool:
    """Check if a domain likely belongs to the same organization.
    e.g., tandem.co.uk and tandem.bank are likely the same org.
    """
    d = _normalize_domain(domain)
    c = _normalize_domain(current_domain)

    if d == c or d.endswith(f".{c}") or c.endswith(f".{d}"):
        return True

    # Extract brand name (first meaningful part before TLD)
    # This is a rough heuristic — tandem.co.uk → "tandem", tandem.bank → "tandem"
    def brand(dom):
        parts = dom.split(".")
        # Handle SLDs like .co.uk, .com.au
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
            return parts[-3] if len(parts) >= 3 else parts[0]
        return parts[-2] if len(parts) >= 2 else parts[0]

    return brand(d) == brand(c)


def _filter_emails(emails: List[str], current_domain: str) -> List[str]:
    """Filter emails worth searching — skip generic/functional and same-domain."""
    filtered = []
    c_domain = _normalize_domain(current_domain)

    for email in emails:
        email = email.lower().strip()
        local_part = email.split("@")[0] if "@" in email else ""
        email_domain = email.split("@")[1] if "@" in email else ""

        # Skip generic functional addresses
        if local_part in SKIP_EMAIL_PATTERNS:
            continue

        # Skip image filenames that look like emails (common in HTML)
        if any(email.endswith(ext) for ext in (".png", ".jpg", ".svg", ".gif", ".webp")):
            continue

        # Skip emails at the current domain (expected, not interesting)
        if _normalize_domain(email_domain) == c_domain:
            continue

        # Skip common redacted WHOIS contact patterns
        if "cloudflareregistrar" in email or "whoisproxy" in email or "privacyguard" in email:
            continue

        filtered.append(email)

    return filtered[:3]  # Max 3 to limit search volume


def _filter_phones(phones: List[str]) -> List[str]:
    """Filter phone numbers worth searching — need enough digits to be meaningful."""
    filtered = []
    for phone in phones:
        # Only search phones with 10+ digits (international or full national)
        digits = re.sub(r"\D", "", phone)
        if len(digits) >= 10:
            filtered.append(phone)
    return filtered[:2]  # Max 2


def _search_ddg_raw(query: str, timeout: int = 8) -> List[str]:
    """Fallback: search DuckDuckGo HTML endpoint directly with requests."""
    import requests as _req
    from urllib.parse import unquote as _unquote
    try:
        resp = _req.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html",
            },
            timeout=timeout,
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return []
        html = resp.text
        domains = []
        # Extract from uddg= redirect URLs
        for encoded in re.findall(r'uddg=([^&"\']+)', html):
            try:
                url = _unquote(encoded)
                parsed = urlparse(url)
                if parsed.hostname:
                    d = _normalize_domain(parsed.hostname)
                    if d:
                        domains.append(d)
            except Exception:
                continue
        # Extract from result__url display spans
        for url_text in re.findall(r'class="result__url"[^>]*>([^<]+)', html):
            url_text = url_text.strip().split("/")[0].strip()
            if "." in url_text:
                d = _normalize_domain(url_text)
                if d:
                    domains.append(d)
        return domains
    except Exception:
        return []


def search_contact_reuse(
    emails: List[str],
    phones: List[str],
    current_domain: str,
    timeout: int = 8,
) -> Dict:
    """
    Search the web for contact info appearing on other domains.

    Args:
        emails: Email addresses found on the page
        phones: Phone numbers found on the page
        current_domain: The domain being analyzed (to exclude from results)
        timeout: Timeout per search query in seconds

    Returns:
        dict with:
            - matches: list of {contact, type, found_on: [domains]}
            - searched: number of queries executed
            - error: error message if search failed
    """
    import time as _time
    result = {"matches": [], "searched": 0, "error": ""}

    # Filter to only interesting contacts
    search_emails = _filter_emails(emails, current_domain)
    search_phones = _filter_phones(phones)

    if not search_emails and not search_phones:
        return result

    # Try duckduckgo_search library first (more reliable parsing)
    ddgs = None
    try:
        from duckduckgo_search import DDGS
        ddgs = DDGS(timeout=timeout)
    except Exception:
        ddgs = None  # Will use raw HTTP fallback

    c_domain = _normalize_domain(current_domain)

    # Search each contact
    for contact, contact_type in (
        *((e, "email") for e in search_emails),
        *((p, "phone") for p in search_phones),
    ):
        try:
            query = f'"{contact}"'
            other_domains = set()

            if ddgs is not None:
                # Use duckduckgo_search library
                try:
                    search_results = list(ddgs.text(query, max_results=10))
                    result["searched"] += 1
                    for sr in search_results:
                        url = sr.get("href", "") or sr.get("link", "")
                        if not url:
                            continue
                        try:
                            parsed = urlparse(url)
                            if parsed.hostname:
                                d = _normalize_domain(parsed.hostname)
                                if d and d != c_domain and not d.endswith(f".{c_domain}"):
                                    if not _is_same_org_domain(d, current_domain):
                                        if not _is_noise_domain(d):
                                            other_domains.add(d)
                        except Exception:
                            continue
                except Exception:
                    # Library call failed — try raw fallback for this query
                    ddgs = None  # Disable library for remaining queries too

            if ddgs is None:
                # Raw HTTP fallback
                raw_domains = _search_ddg_raw(query, timeout=timeout)
                result["searched"] += 1
                for d in raw_domains:
                    if d and d != c_domain and not d.endswith(f".{c_domain}"):
                        if not _is_same_org_domain(d, current_domain):
                            if not _is_noise_domain(d):
                                other_domains.add(d)

            if other_domains:
                result["matches"].append({
                    "contact": contact,
                    "type": contact_type,
                    "found_on": sorted(other_domains)[:10],
                })
        except Exception as e:
            logger.debug(f"Contact search failed for {contact}: {e}")
            continue

        # Brief delay between searches
        _time.sleep(0.5)

    return result
