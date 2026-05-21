"""
Threat-intel feed fetchers — one parser per external feed format.

Each parser is a function that takes the fetched raw response bytes and a
ThreatIntelFeed config, and yields dicts shaped like:

    {
      "domain": "evil.example.com",          # or "ip": "1.2.3.4" / "url": "https://..."
      "category": "phishing",                # optional — defaults to feed.default_category
      "subcategory": "brand_impersonation",  # optional
      "confidence": "high",                  # optional
      "notes": "…",                          # optional
    }

`fetch_feed(feed)` runs the right parser + upserts into ThreatIntelDomain.

Scheduling: wire `refresh_threat_intel` to cron or a systemd timer. No Celery /
Redis dependency — a simple `*/30 * * * * python manage.py refresh_threat_intel`
is enough for MVP; when load grows, swap in a queue.
"""
from __future__ import annotations

import csv
import datetime as _dt
import io
import ipaddress
import json
import logging
import os
import re
import time
from typing import Iterable, Iterator
from urllib.parse import urlparse

import requests
from django.db import transaction
from django.utils import timezone

from apps.iocs.models import ThreatIntelDomain, ThreatIntelFeed

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 30
USER_AGENT = "domain-infra-ti-fetcher/1.0 (+https://github.com/jenna43008)"


# ======================================================================
# Parsers — one per feed format
# ======================================================================


def _clean_host(s: str) -> str:
    """Strip http(s)://, port, path, trailing dot, lowercase."""
    s = (s or "").strip().lower()
    if not s or s.startswith("#") or s.startswith(";"):
        return ""
    if "://" in s:
        try:
            s = urlparse(s).hostname or s
        except Exception:
            pass
    s = s.split("/", 1)[0].split(":", 1)[0].strip(". ")
    # Skip 0.0.0.0 / 127.0.0.1 hosts-file prefixes
    if s in ("0.0.0.0", "127.0.0.1", "localhost"):
        return ""
    return s


def parse_plaintext_hosts(body: bytes, feed: ThreatIntelFeed) -> Iterator[dict]:
    """Line-delimited hostnames. Supports '# comment' lines and '0.0.0.0 host' hosts-file rows."""
    for raw in body.decode("utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # hosts-file format: "0.0.0.0 example.com"
        parts = line.split()
        candidate = parts[1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0]
        host = _clean_host(candidate)
        if host and "." in host:
            yield {"domain": host}


def parse_github_raw_text(body: bytes, feed: ThreatIntelFeed) -> Iterator[dict]:
    """GitHub-hosted plain-text blocklist. Same format as plaintext_hosts."""
    yield from parse_plaintext_hosts(body, feed)


def parse_csv_hosts(body: bytes, feed: ThreatIntelFeed) -> Iterator[dict]:
    """CSV with at least a `domain` column — other known columns absorbed."""
    text = body.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        host = _clean_host(row.get("domain") or row.get("url") or row.get("host") or "")
        if not host or "." not in host:
            continue
        yield {
            "domain": host,
            "category":    (row.get("category") or "").strip() or feed.default_category,
            "subcategory": (row.get("subcategory") or "").strip(),
            "confidence":  (row.get("confidence") or "").strip() or feed.default_confidence,
            "notes":       (row.get("description") or row.get("notes") or "")[:500],
        }


_SPAMHAUS_CIDR_RE = re.compile(r"^\s*([\d./:a-fA-F]+)\s*;")


def parse_spamhaus_drop(body: bytes, feed: ThreatIntelFeed) -> Iterator[dict]:
    """
    Spamhaus DROP / EDROP — semicolon-delimited format:
        1.10.16.0/20 ; SBL233488
    Treat each /CIDR as one indicator (stored as ip= "cidr").
    """
    for raw in body.decode("utf-8", errors="ignore").splitlines():
        m = _SPAMHAUS_CIDR_RE.match(raw)
        if not m:
            continue
        cidr = m.group(1).strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        yield {"domain": cidr, "subcategory": "spamhaus_drop"}


def parse_firehol_ips(body: bytes, feed: ThreatIntelFeed) -> Iterator[dict]:
    """FireHOL ip-blocklists — lines of CIDR or bare IPs; '#' comments."""
    for raw in body.decode("utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cidr = line.split()[0]
        try:
            ipaddress.ip_network(cidr if "/" in cidr else f"{cidr}/32", strict=False)
        except ValueError:
            continue
        yield {"domain": cidr, "subcategory": "firehol"}


def parse_openphish(body: bytes, feed: ThreatIntelFeed) -> Iterator[dict]:
    """OpenPhish free feed — one URL per line."""
    for raw in body.decode("utf-8", errors="ignore").splitlines():
        url = raw.strip()
        if not url or url.startswith("#"):
            continue
        host = _clean_host(url)
        if host and "." in host:
            yield {"domain": host, "category": "phishing", "subcategory": "openphish"}


def parse_abuseipdb_blacklist(body: bytes, feed: ThreatIntelFeed) -> Iterator[dict]:
    """
    AbuseIPDB /api/v2/blacklist JSON response. Requires api_key_env on the feed.
    Each item: {ipAddress, abuseConfidenceScore, lastReportedAt, countryCode}
    """
    try:
        doc = json.loads(body.decode("utf-8"))
    except Exception:
        return
    for item in doc.get("data", []):
        ip = (item.get("ipAddress") or "").strip()
        if not ip:
            continue
        conf_pct = int(item.get("abuseConfidenceScore") or 0)
        conf = "high" if conf_pct >= 90 else ("medium" if conf_pct >= 50 else "low")
        yield {
            "domain": ip,
            "category": "scan",
            "subcategory": "abuseipdb",
            "confidence": conf,
            "notes": f"AbuseIPDB confidence {conf_pct}% · last-reported {item.get('lastReportedAt')} · {item.get('countryCode', '?')}",
        }


PARSERS = {
    "plaintext_hosts":    parse_plaintext_hosts,
    "github_raw_text":    parse_github_raw_text,
    "csv_hosts":          parse_csv_hosts,
    "spamhaus_drop":      parse_spamhaus_drop,
    "firehol_ips":        parse_firehol_ips,
    "openphish":          parse_openphish,
    "abuseipdb_blacklist": parse_abuseipdb_blacklist,
}


# ======================================================================
# Fetch + upsert
# ======================================================================


def fetch_feed(feed: ThreatIntelFeed, limit: int | None = None) -> dict:
    """
    Pull the feed, parse, upsert into ThreatIntelDomain, stamp the feed with
    stats. Returns the stats dict.
    """
    started = time.time()
    parser = PARSERS.get(feed.parser)
    if parser is None:
        feed.last_status = "error"
        feed.last_error = f"Unknown parser: {feed.parser}"
        feed.last_fetched_at = timezone.now()
        feed.save()
        return {"status": "error", "reason": feed.last_error}

    headers = {"User-Agent": USER_AGENT, "Accept": "text/plain, application/json, text/csv, */*"}
    if feed.api_key_env:
        api_key = os.environ.get(feed.api_key_env, "")
        if not api_key:
            feed.last_status = "error"
            feed.last_error = f"Missing env var {feed.api_key_env}"
            feed.last_fetched_at = timezone.now()
            feed.save()
            return {"status": "error", "reason": feed.last_error}
        headers["Key"] = api_key
        headers["Authorization"] = f"Bearer {api_key}"
    if feed.extra_headers:
        headers.update({str(k): str(v) for k, v in feed.extra_headers.items()})

    try:
        resp = requests.get(feed.url, headers=headers, timeout=HTTP_TIMEOUT, stream=False)
        resp.raise_for_status()
    except Exception as exc:
        logger.exception("Feed fetch failed: %s", feed.name)
        feed.last_status = "error"
        feed.last_error = f"{type(exc).__name__}: {exc}"[:500]
        feed.last_fetched_at = timezone.now()
        feed.last_duration_seconds = round(time.time() - started, 2)
        feed.save()
        return {"status": "error", "reason": feed.last_error}

    created = updated = skipped = 0
    source_label = feed.source_label or feed.name
    today = _dt.date.today()

    with transaction.atomic():
        for i, row in enumerate(parser(resp.content, feed)):
            if limit and (created + updated) >= limit:
                break
            domain = row.get("domain", "").strip().lower().rstrip(".")
            if not domain:
                skipped += 1
                continue
            defaults = {
                "category":    row.get("category") or feed.default_category or "scam",
                "confidence":  row.get("confidence") or feed.default_confidence or "medium",
                "subcategory": row.get("subcategory") or feed.default_subcategory or "",
                "brand_target": "",
                "source": source_label,
                "reported_date": today,
                "notes": (row.get("notes") or "")[:500],
            }
            _, was_created = ThreatIntelDomain.objects.update_or_create(
                domain=domain, defaults=defaults,
            )
            if was_created:
                created += 1
            else:
                updated += 1

    feed.last_fetched_at = timezone.now()
    feed.last_status = "ok"
    feed.last_error = ""
    feed.last_items_created = created
    feed.last_items_updated = updated
    feed.last_items_skipped = skipped
    feed.last_duration_seconds = round(time.time() - started, 2)
    feed.save()

    return {
        "status": "ok", "created": created, "updated": updated, "skipped": skipped,
        "duration_seconds": feed.last_duration_seconds,
    }


def refresh_due_feeds(force: bool = False) -> list[dict]:
    """Iterate all enabled feeds and fetch those whose refresh interval has elapsed."""
    results = []
    for feed in ThreatIntelFeed.objects.filter(enabled=True).order_by("id"):
        if not force and not feed.is_due():
            continue
        res = fetch_feed(feed)
        res["feed"] = feed.name
        results.append(res)
    return results


# ======================================================================
# Default feed roster — seeded by `load_default_threat_intel_feeds`
# ======================================================================


DEFAULT_FEEDS = [
    {
        "name": "phishing.database New-today",
        "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-today.txt",
        "parser": "github_raw_text",
        "default_category": "phishing",
        "default_subcategory": "phishing_database",
        "default_confidence": "medium",
        "source_label": "Phishing.Database",
        "refresh_interval_hours": 6,
    },
    {
        "name": "spmedia crypto-scam detected_urls",
        "url": "https://raw.githubusercontent.com/spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed/main/detected_urls.txt",
        "parser": "github_raw_text",
        "default_category": "scam",
        "default_subcategory": "crypto_scam",
        "default_confidence": "medium",
        "source_label": "spmedia/Crypto-Scam-Feed",
        "refresh_interval_hours": 12,
    },
    {
        "name": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "parser": "spamhaus_drop",
        "kind": "ip",
        "default_category": "scam",
        "default_subcategory": "spamhaus_drop",
        "default_confidence": "high",
        "source_label": "Spamhaus DROP",
        "refresh_interval_hours": 24,
    },
    {
        "name": "FireHOL Level 1",
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "parser": "firehol_ips",
        "kind": "ip",
        "default_category": "scan",
        "default_subcategory": "firehol_level1",
        "default_confidence": "medium",
        "source_label": "FireHOL Level 1",
        "refresh_interval_hours": 24,
    },
    {
        "name": "OpenPhish feed",
        "url": "https://openphish.com/feed.txt",
        "parser": "openphish",
        "default_category": "phishing",
        "default_subcategory": "openphish",
        "default_confidence": "medium",
        "source_label": "OpenPhish",
        "refresh_interval_hours": 6,
    },
    {
        "name": "AbuseIPDB blacklist (requires API key)",
        "url": "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=75",
        "parser": "abuseipdb_blacklist",
        "kind": "ip",
        "default_category": "scan",
        "default_subcategory": "abuseipdb",
        "default_confidence": "medium",
        "source_label": "AbuseIPDB",
        "api_key_env": "ABUSEIPDB_API_KEY",
        "refresh_interval_hours": 24,
        "extra_headers": {"Accept": "application/json"},
    },
]
