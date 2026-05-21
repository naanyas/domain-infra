"""
Threat-intel detector — match a hostname (plus any cross-link / resolving hostnames
from the SDAT scan) against the ThreatIntelDomain table. Returns score-ready rows
for the pipeline + UI.
"""
from __future__ import annotations

from typing import Iterable

from apps.iocs.models import ThreatIntelDomain


def _norm(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def _host_chain(host: str) -> list[str]:
    """Given 'a.b.pages.dev' return ['a.b.pages.dev', 'b.pages.dev', 'pages.dev']."""
    host = _norm(host)
    if not host:
        return []
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def match_domain(host: str) -> list[dict]:
    """
    Match a single hostname against the threat-intel table. Returns a list of
    {domain, category, subcategory, brand, confidence, score, source, kind, notes}
    dicts (0 or more — an apex might also match as a subdomain of a shared host).
    """
    chain = _host_chain(host)
    if not chain:
        return []

    # Exact matches (not apex-only)
    hits: list[dict] = []
    seen: set[str] = set()

    exact = ThreatIntelDomain.objects.filter(
        domain__in=chain, is_meta_cluster=False, apex_subdomain_only=False,
    )
    for ti in exact:
        if ti.domain in seen:
            continue
        seen.add(ti.domain)
        kind = "exact" if ti.domain == chain[0] else "parent_match"
        hits.append(_pack(ti, kind, matched_host=chain[0]))

    # Shared-abusable-host apex entries — only match if hostname has a subdomain
    # prefix (never match the apex itself).
    apex_rows = ThreatIntelDomain.objects.filter(
        domain__in=chain[1:],  # parents only
        apex_subdomain_only=True,
        is_meta_cluster=False,
    )
    for ti in apex_rows:
        if ti.domain in seen:
            continue
        seen.add(ti.domain)
        hits.append(_pack(ti, "shared_host_subdomain", matched_host=chain[0]))

    return hits


def match_many(hosts: Iterable[str]) -> list[dict]:
    """Match a list of hostnames (primary + cross-links + resolving)."""
    all_hits: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for h in hosts:
        for hit in match_domain(h):
            key = (hit["domain"], hit["matched_host"])
            if key in seen:
                continue
            seen.add(key)
            all_hits.append(hit)
    return all_hits


def _pack(ti: ThreatIntelDomain, kind: str, matched_host: str) -> dict:
    return {
        "domain": ti.domain,
        "matched_host": matched_host,
        "category": ti.category,
        "subcategory": ti.subcategory,
        "brand": ti.brand_target,
        "confidence": ti.confidence,
        "score": ti.score_weight,
        "source": ti.source,
        "kind": kind,
        "notes": ti.notes,
        "reported_date": ti.reported_date.isoformat() if ti.reported_date else "",
    }
