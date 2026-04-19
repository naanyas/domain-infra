"""
ccTLD Registration Fallback
============================
Fallback for ccTLDs where:
  1. RDAP (direct + rdap.org bootstrap) returns nothing
  2. python-whois doesn't have the WHOIS server in its map

This module provides two fallback strategies:
  A) Direct WHOIS socket query to known ccTLD WHOIS servers
  B) ICANN RDAP proxy (rdap.org) — kept as secondary attempt

The direct socket approach is the primary fix. Many ccTLD registries
(e.g. .ng, .ke, .tz, .gh, .za) operate WHOIS servers that python-whois
doesn't know about and that aren't in the IANA RDAP bootstrap.
ICANN Lookup (lookup.icann.org) succeeds on these because it maintains
its own registry relationships — we replicate that by querying the
known WHOIS servers directly via port 43.

Integration:
  Called from analyzer.py when both rdap_lookup() and whois_lookup()
  fail to return a creation date.
"""

import re
import socket
import logging
from datetime import datetime, timezone
from typing import Dict

logger = logging.getLogger(__name__)

# Attempt requests import (should always be available in the Config Checker)
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ====================================================================
# KNOWN ccTLD WHOIS SERVERS
# ====================================================================
# These are registries that operate WHOIS on port 43 but are missing
# from python-whois's server map and/or the IANA RDAP bootstrap.
# Source: IANA root zone database + manual verification.
#
# Format: TLD -> WHOIS server hostname
# Only include TLDs where python-whois is confirmed to fail.

CCTLD_WHOIS_SERVERS = {
    # Africa
    "ng": "whois.nic.net.ng",
    "ke": "whois.kenic.or.ke",
    "gh": "whois.nic.gh",
    "tz": "whois.tznic.or.tz",
    "za": "whois.registry.net.za",
    "ci": "whois.nic.ci",
    "sn": "whois.nic.sn",
    "mg": "whois.nic.mg",
    "mu": "whois.nic.mu",
    "rw": "whois.ricta.org.rw",
    "ug": "whois.co.ug",
    "bw": "whois.nic.net.bw",
    "na": "whois.na-nic.com.na",
    "cm": "whois.netcom.cm",
    # Asia / Pacific
    "bd": "whois.registry.bd",
    "pk": "whois.pknic.net.pk",
    "lk": "whois.nic.lk",
    "np": "whois.nic.np",
    "mm": "whois.registry.gov.mm",
    "kh": "whois.nic.kh",
    "mn": "whois.nic.mn",
    "ge": "whois.registration.ge",
    "uz": "whois.cctld.uz",
    "az": "whois.az",
    # Caribbean / Latin America
    "tt": "whois.nic.tt",
    "do": "whois.nic.do",
    "ht": "whois.nic.ht",
    "bo": "whois.nic.bo",
    "sv": "whois.svnet.org.sv",
    "gt": "whois.gt",
    "hn": "whois.nic.hn",
    "ni": "whois.nic.ni",
    "py": "whois.nic.py",
    "cu": "whois.nic.cu",
    # Middle East
    "iq": "whois.cmc.iq",
    "jo": "whois.dns.jo",
    "lb": "whois.lbdr.org.lb",
    "ps": "whois.pnina.ps",
    # Europe (less common)
    "al": "whois.ripe.net",
    "ba": "whois.nic.ba",
    "mk": "whois.marnet.mk",
    "md": "whois.nic.md",
    "mt": "whois.nic.org.mt",
    "by": "whois.cctld.by",
    "rs": "whois.rnids.rs",
}


# ====================================================================
# WHOIS RESPONSE PARSERS
# ====================================================================
# WHOIS responses are unstructured text — each registry uses different
# field names. We look for common patterns.

# Patterns for creation date fields
_CREATED_PATTERNS = [
    r"(?:creation date|created|registered|registration date|domain registered)[:\s]+(\d{4}[-/.]\d{2}[-/.]\d{2})",
    r"(?:created)[:\s]+(\d{2}[-/.]\d{2}[-/.]\d{4})",  # DD/MM/YYYY format
    r"(?:registration date)[:\s]+(\d{4}-\d{2}-\d{2}T[\d:]+Z?)",  # ISO format
]

# Patterns for updated date fields
_UPDATED_PATTERNS = [
    r"(?:updated date|last modified|last updated|modified)[:\s]+(\d{4}[-/.]\d{2}[-/.]\d{2})",
    r"(?:updated date)[:\s]+(\d{4}-\d{2}-\d{2}T[\d:]+Z?)",
]

# Patterns for registrar
_REGISTRAR_PATTERNS = [
    r"(?:registrar|sponsoring registrar)[:\s]+(.+?)(?:\n|$)",
]

# Patterns for expiration
_EXPIRY_PATTERNS = [
    r"(?:expir(?:y|ation) date|expires|renewal date)[:\s]+(\d{4}[-/.]\d{2}[-/.]\d{2})",
]


def _parse_whois_date(date_str: str) -> datetime:
    """Parse date string from WHOIS response into datetime."""
    date_str = date_str.strip().rstrip(".")

    # ISO format: 2024-06-15T12:00:00Z
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass

    # YYYY-MM-DD or YYYY/MM/DD or YYYY.MM.DD
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d"):
        try:
            dt = datetime.strptime(date_str[:10], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    # DD/MM/YYYY or DD-MM-YYYY
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y"):
        try:
            dt = datetime.strptime(date_str[:10], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    raise ValueError(f"Cannot parse date: {date_str}")


def _extract_from_whois(text: str, patterns: list) -> str:
    """Extract first matching value from WHOIS text using pattern list."""
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()
    return ""


def _query_whois_socket(domain: str, server: str, timeout: float = 10.0) -> str:
    """
    Query a WHOIS server directly via TCP port 43.
    Returns raw WHOIS response text.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 43))
        sock.sendall((domain + "\r\n").encode("utf-8"))

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        sock.close()

        # Try UTF-8 first, fall back to latin-1
        try:
            return response.decode("utf-8")
        except UnicodeDecodeError:
            return response.decode("latin-1", errors="replace")

    except socket.timeout:
        logger.info(f"ccTLD fallback: WHOIS socket timeout for {domain} via {server}")
        return ""
    except socket.gaierror:
        logger.info(f"ccTLD fallback: WHOIS server DNS resolution failed: {server}")
        return ""
    except ConnectionRefusedError:
        logger.info(f"ccTLD fallback: WHOIS server refused connection: {server}")
        return ""
    except Exception as e:
        logger.info(f"ccTLD fallback: WHOIS socket error for {domain} via {server}: {e}")
        return ""


# ====================================================================
# PUBLIC API
# ====================================================================

def cctld_whois_fallback(domain: str, timeout: float = 10.0) -> Dict:
    """
    Fallback registration data lookup for ccTLDs via direct WHOIS socket.

    Tries:
      1. Direct WHOIS socket query to known ccTLD WHOIS server
      2. ICANN RDAP proxy (rdap.org) if socket fails

    Returns dict with:
        - creation_date: ISO string or ""
        - creation_days_ago: int (-1 if unavailable)
        - updated_date: ISO string or ""
        - updated_days_ago: int (-1 if unavailable)
        - expiration_date: ISO string or ""
        - registrar: str
        - source: "cctld_whois_socket" | "icann_rdap_proxy" | ""
    """
    result = {
        "creation_date": "",
        "creation_days_ago": -1,
        "updated_date": "",
        "updated_days_ago": -1,
        "expiration_date": "",
        "registrar": "",
        "source": "",
    }

    # Extract base domain and TLD
    parts = domain.lower().strip().split(".")
    compound_slds = {"co", "com", "org", "net", "ac", "gov", "edu"}
    if len(parts) > 2 and parts[-2] in compound_slds:
        base = ".".join(parts[-3:])
        tld = parts[-1]
    elif len(parts) >= 2:
        base = ".".join(parts[-2:])
        tld = parts[-1]
    else:
        logger.info(f"ccTLD fallback: cannot parse domain '{domain}'")
        return result

    # ── Strategy 1: Direct WHOIS socket ──────────────────────────
    whois_server = CCTLD_WHOIS_SERVERS.get(tld)
    if whois_server:
        logger.info(f"ccTLD fallback: trying WHOIS socket {whois_server} for {base}")
        raw = _query_whois_socket(base, whois_server, timeout=timeout)

        if raw:
            logger.info(f"ccTLD fallback: got {len(raw)} bytes from {whois_server}")
            now = datetime.now(timezone.utc)

            # Parse creation date
            created_str = _extract_from_whois(raw, _CREATED_PATTERNS)
            if created_str:
                try:
                    dt = _parse_whois_date(created_str)
                    result["creation_date"] = dt.isoformat()
                    result["creation_days_ago"] = (now - dt).days
                    result["source"] = "cctld_whois_socket"
                    logger.info(f"ccTLD fallback: {base} created {created_str} ({result['creation_days_ago']}d ago) via {whois_server}")
                except (ValueError, TypeError) as e:
                    logger.info(f"ccTLD fallback: failed to parse creation date '{created_str}': {e}")

            # Parse updated date
            updated_str = _extract_from_whois(raw, _UPDATED_PATTERNS)
            if updated_str:
                try:
                    dt = _parse_whois_date(updated_str)
                    result["updated_date"] = dt.isoformat()
                    result["updated_days_ago"] = (now - dt).days
                except (ValueError, TypeError):
                    pass

            # Parse expiration
            expiry_str = _extract_from_whois(raw, _EXPIRY_PATTERNS)
            if expiry_str:
                try:
                    dt = _parse_whois_date(expiry_str)
                    result["expiration_date"] = dt.isoformat()
                except (ValueError, TypeError):
                    pass

            # Parse registrar
            registrar_str = _extract_from_whois(raw, _REGISTRAR_PATTERNS)
            if registrar_str:
                result["registrar"] = registrar_str[:200]

            # If we got creation date, we're done
            if result["creation_days_ago"] >= 0:
                return result
            else:
                logger.info(f"ccTLD fallback: WHOIS response from {whois_server} but no creation date parsed")
        else:
            logger.info(f"ccTLD fallback: no response from {whois_server} for {base}")
    else:
        logger.info(f"ccTLD fallback: no known WHOIS server for .{tld}")

    # ── Strategy 2: ICANN RDAP proxy (rdap.org) ─────────────────
    # Secondary attempt — may have broader coverage than our socket map,
    # or may succeed where socket failed.
    if not REQUESTS_AVAILABLE:
        logger.info("ccTLD fallback: requests not available, skipping RDAP proxy")
        return result

    rdap_url = f"https://rdap.org/domain/{base}"
    logger.info(f"ccTLD fallback: trying RDAP proxy {rdap_url}")

    try:
        resp = requests.get(
            rdap_url,
            timeout=timeout,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "DomainApproval/7.8 (OneSignal Trust & Safety)",
            },
            allow_redirects=True,
        )

        if resp.status_code != 200:
            logger.info(f"ccTLD fallback: RDAP proxy returned {resp.status_code} for {base}")
            return result

        data = resp.json()
        events = data.get("events", [])
        now = datetime.now(timezone.utc)

        for event in events:
            action = event.get("eventAction", "").lower()
            date_str = event.get("eventDate", "")
            if not date_str:
                continue

            try:
                dt = _parse_whois_date(date_str)
            except (ValueError, TypeError):
                continue

            if action == "registration" and result["creation_days_ago"] < 0:
                result["creation_date"] = dt.isoformat()
                result["creation_days_ago"] = (now - dt).days
                result["source"] = "icann_rdap_proxy"

            elif action == "last changed" and result["updated_days_ago"] < 0:
                result["updated_date"] = dt.isoformat()
                result["updated_days_ago"] = (now - dt).days

            elif action == "expiration" and not result["expiration_date"]:
                result["expiration_date"] = dt.isoformat()

        # Registrar from entities
        for entity in data.get("entities", []):
            roles = [r.lower() for r in entity.get("roles", [])]
            if "registrar" in roles and not result["registrar"]:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            result["registrar"] = str(field[3])[:200]
                            break
                if not result["registrar"]:
                    result["registrar"] = entity.get("handle", "")[:200]
                break

        if result["creation_days_ago"] >= 0:
            logger.info(f"ccTLD fallback: {base} created {result['creation_date'][:10]} via RDAP proxy")
        else:
            logger.info(f"ccTLD fallback: RDAP proxy returned data but no creation date for {base}")

    except requests.exceptions.Timeout:
        logger.info(f"ccTLD fallback: RDAP proxy timeout for {base}")
    except requests.exceptions.ConnectionError:
        logger.info(f"ccTLD fallback: RDAP proxy connection error for {base}")
    except (ValueError, KeyError) as e:
        logger.info(f"ccTLD fallback: RDAP proxy parse error for {base}: {e}")
    except Exception as e:
        logger.info(f"ccTLD fallback: RDAP proxy unexpected error for {base}: {e}")

    return result


# Legacy alias — existing import in analyzer.py works unchanged
icann_rdap_fallback = cctld_whois_fallback
