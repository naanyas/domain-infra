"""
IPQualityScore enricher — IP reputation (VPN/proxy/Tor/datacenter/geo/ASN).

API docs: https://www.ipqualityscore.com/documentation/proxy-detection-api/overview

Failure is always swallowed: the submission pipeline must not hard-fail when
an external enrichment vendor is slow or down. Entities just keep their default
values and the verdict falls back to signal presence.
"""
from __future__ import annotations

import logging
import os

import requests

from apps.entities.models import ASN, IPAddress, SubmitterIP

logger = logging.getLogger(__name__)

IPQS_BASE = "https://ipqualityscore.com/api/json/ip"
IPQS_TIMEOUT_SEC = 6  # Budget that leaves room within a synchronous submission


def _api_key() -> str:
    return os.environ.get("IPQS_API_KEY", "")


# ----------------------------------------------------------------------
# Low-level API
# ----------------------------------------------------------------------


def lookup(address: str, strictness: int = 1) -> dict | None:
    """
    Call the IPQS Proxy Detection API. Returns the parsed JSON body on success,
    or None if the key is missing, request fails, or IPQS reports success=False.
    """
    key = _api_key()
    if not key:
        return None
    url = f"{IPQS_BASE}/{key}/{address}"
    params = {"strictness": strictness, "allow_public_access_points": "true"}
    try:
        resp = requests.get(url, params=params, timeout=IPQS_TIMEOUT_SEC)
    except requests.RequestException:
        logger.exception("IPQS request failed for %s", address)
        return None
    if resp.status_code != 200:
        logger.warning("IPQS non-200 for %s: status=%s body=%s", address, resp.status_code, resp.text[:200])
        return None
    data = resp.json()
    if not data.get("success"):
        logger.warning("IPQS reported failure for %s: %s", address, data.get("message"))
        return None
    return data


# ----------------------------------------------------------------------
# Field mapping (IPQS JSON → our models)
# ----------------------------------------------------------------------


def _is_datacenter(data: dict) -> bool:
    """IPQS signals datacenter via `connection_type` = 'Data Center' or the `hosting` boolean."""
    ct = (data.get("connection_type") or "").lower()
    return ct == "data center" or ct == "datacenter" or bool(data.get("hosting"))


def _upsert_asn(data: dict) -> ASN | None:
    """Create or update the ASN row from IPQS response. Returns None if no ASN."""
    number = data.get("ASN")
    if not number:
        return None
    try:
        number = int(number)
    except (TypeError, ValueError):
        return None
    asn, _ = ASN.objects.get_or_create(number=number)
    changed: list[str] = []
    org = (data.get("organization") or data.get("ISP") or "").strip()
    if org and not asn.name:
        asn.name = org[:200]
        changed.append("name")
    cc = (data.get("country_code") or "").strip()[:2]
    if cc and not asn.country:
        asn.country = cc
        changed.append("country")
    if changed:
        asn.save(update_fields=changed)
    return asn


# ----------------------------------------------------------------------
# Entity-typed appliers
# ----------------------------------------------------------------------


def _extract_risk_signals(data: dict) -> dict:
    """IPQS risk scoring fields (available on the free tier for most of these)."""
    fraud_score = data.get("fraud_score")
    try:
        fraud_score = int(fraud_score) if fraud_score is not None else None
    except (TypeError, ValueError):
        fraud_score = None
    # IPQS returns True/False booleans for these; null = not included in response
    ra = data.get("recent_abuse")
    bs = data.get("bot_status")
    return {
        "fraud_score": fraud_score,
        "recent_abuse": bool(ra) if isinstance(ra, bool) else None,
        "bot_status": bool(bs) if isinstance(bs, bool) else None,
    }


def apply_to_submitter_ip(sip: SubmitterIP, data: dict) -> None:
    asn = _upsert_asn(data)
    sip.country = (data.get("country_code") or "")[:2]
    sip.region = (data.get("region") or "")[:100]
    sip.city = (data.get("city") or "")[:100]
    lat, lng = data.get("latitude"), data.get("longitude")
    sip.latitude = float(lat) if isinstance(lat, (int, float)) else None
    sip.longitude = float(lng) if isinstance(lng, (int, float)) else None
    sip.is_vpn = bool(data.get("vpn"))
    sip.is_proxy = bool(data.get("proxy"))
    sip.is_tor = bool(data.get("tor"))
    sip.is_datacenter = _is_datacenter(data)
    sip.asn = asn
    risk = _extract_risk_signals(data)
    sip.fraud_score = risk["fraud_score"]
    sip.recent_abuse = risk["recent_abuse"]
    sip.bot_status = risk["bot_status"]
    sip.timezone = (data.get("timezone") or "")[:64]
    sip.save(
        update_fields=[
            "country", "region", "city", "latitude", "longitude",
            "is_vpn", "is_proxy", "is_tor", "is_datacenter", "asn",
            "fraud_score", "recent_abuse", "bot_status", "timezone",
        ]
    )


def apply_to_ip_address(ip: IPAddress, data: dict) -> None:
    asn = _upsert_asn(data)
    ip.country = (data.get("country_code") or "")[:2]
    ip.hosting_provider = (data.get("ISP") or data.get("organization") or "")[:200]
    ip.is_vpn = bool(data.get("vpn"))
    ip.is_proxy = bool(data.get("proxy"))
    ip.is_tor = bool(data.get("tor"))
    ip.is_datacenter = _is_datacenter(data)
    ip.asn = asn
    risk = _extract_risk_signals(data)
    ip.fraud_score = risk["fraud_score"]
    ip.recent_abuse = risk["recent_abuse"]
    ip.bot_status = risk["bot_status"]
    ip.timezone = (data.get("timezone") or "")[:64]
    ip.save(
        update_fields=[
            "country", "hosting_provider", "is_vpn", "is_proxy", "is_tor",
            "is_datacenter", "asn", "fraud_score", "recent_abuse", "bot_status", "timezone",
        ]
    )


# ----------------------------------------------------------------------
# Public one-shot helpers (swallow all errors — submission pipeline is sync)
# ----------------------------------------------------------------------


def enrich_submitter_ip(sip: SubmitterIP) -> None:
    try:
        data = lookup(sip.address)
        if data:
            apply_to_submitter_ip(sip, data)
    except Exception:
        logger.exception("enrich_submitter_ip failed for %s", sip.address)


def enrich_ip_address(ip: IPAddress) -> None:
    try:
        data = lookup(ip.address)
        if data:
            apply_to_ip_address(ip, data)
    except Exception:
        logger.exception("enrich_ip_address failed for %s", ip.address)
