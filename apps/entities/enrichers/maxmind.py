"""
MaxMind GeoLite2 enricher — country / city / ASN from local MMDB files.

Lookups are microseconds (reads a memory-mapped DB, no network call). Run
`python manage.py update_geoip` weekly to refresh the MMDB files.

We run MaxMind BEFORE IPQS in the enrichment pipeline:
 * MaxMind is authoritative + fast for geo + ASN.
 * IPQS adds VPN/proxy/Tor flags on top (which MaxMind's free tier doesn't provide).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import geoip2.database
import geoip2.errors
from django.conf import settings

from apps.entities.models import ASN, IPAddress, SubmitterIP

logger = logging.getLogger(__name__)

_READERS: dict[str, geoip2.database.Reader] = {}


def _db_dir() -> Path:
    override = os.environ.get("MAXMIND_DB_DIR")
    if override:
        return Path(override)
    return Path(settings.BASE_DIR) / "geoip"


def _reader(filename: str) -> geoip2.database.Reader | None:
    """Cached MMDB reader. Returns None if the file is missing."""
    if filename not in _READERS:
        path = _db_dir() / filename
        if not path.exists():
            logger.warning("MaxMind DB missing: %s (run: python manage.py update_geoip)", path)
            return None
        _READERS[filename] = geoip2.database.Reader(str(path))
    return _READERS[filename]


# ----------------------------------------------------------------------
# Low-level lookups
# ----------------------------------------------------------------------


def _lookup_city(address: str) -> dict:
    reader = _reader("GeoLite2-City.mmdb")
    if reader is None:
        return {}
    try:
        r = reader.city(address)
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return {}
    return {
        "country_code": (r.country.iso_code or "")[:2] if r.country else "",
        "region": (r.subdivisions.most_specific.name or "")[:100] if r.subdivisions else "",
        "city": (r.city.name or "")[:100] if r.city else "",
        "latitude": r.location.latitude if r.location else None,
        "longitude": r.location.longitude if r.location else None,
    }


def _lookup_asn(address: str) -> dict:
    reader = _reader("GeoLite2-ASN.mmdb")
    if reader is None:
        return {}
    try:
        r = reader.asn(address)
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return {}
    return {
        "asn_number": r.autonomous_system_number,
        "asn_name": (r.autonomous_system_organization or "")[:200],
    }


def _upsert_asn(data: dict, country_hint: str = "") -> ASN | None:
    number = data.get("asn_number")
    if not number:
        return None
    asn, _ = ASN.objects.get_or_create(number=int(number))
    changed: list[str] = []
    if data.get("asn_name") and not asn.name:
        asn.name = data["asn_name"]
        changed.append("name")
    if country_hint and not asn.country:
        asn.country = country_hint[:2]
        changed.append("country")
    if changed:
        asn.save(update_fields=changed)
    return asn


# ----------------------------------------------------------------------
# Public appliers
# ----------------------------------------------------------------------


def apply_to_submitter_ip(sip: SubmitterIP) -> None:
    """
    Populate geo/ASN fields on a SubmitterIP from MaxMind. Does NOT touch
    VPN/proxy/Tor/datacenter flags — those come from IPQS. Safe to call
    even if some DBs are missing (just fills what it can).
    """
    city = _lookup_city(sip.address)
    asn_data = _lookup_asn(sip.address)
    asn_obj = _upsert_asn(asn_data, country_hint=city.get("country_code") or "")

    updates: list[str] = []
    if city.get("country_code") and not sip.country:
        sip.country = city["country_code"]
        updates.append("country")
    if city.get("region") and not sip.region:
        sip.region = city["region"]
        updates.append("region")
    if city.get("city") and not sip.city:
        sip.city = city["city"]
        updates.append("city")
    if city.get("latitude") is not None and sip.latitude is None:
        sip.latitude = float(city["latitude"])
        updates.append("latitude")
    if city.get("longitude") is not None and sip.longitude is None:
        sip.longitude = float(city["longitude"])
        updates.append("longitude")
    if asn_obj and not sip.asn_id:
        sip.asn = asn_obj
        updates.append("asn")
    if updates:
        sip.save(update_fields=updates)


def apply_to_ip_address(ip: IPAddress) -> None:
    city = _lookup_city(ip.address)
    asn_data = _lookup_asn(ip.address)
    asn_obj = _upsert_asn(asn_data, country_hint=city.get("country_code") or "")

    updates: list[str] = []
    if city.get("country_code") and not ip.country:
        ip.country = city["country_code"]
        updates.append("country")
    if asn_obj and not ip.asn_id:
        ip.asn = asn_obj
        updates.append("asn")
    if asn_data.get("asn_name") and not ip.hosting_provider:
        ip.hosting_provider = asn_data["asn_name"]
        updates.append("hosting_provider")
    if updates:
        ip.save(update_fields=updates)


# ----------------------------------------------------------------------
# One-shot wrappers (swallow all errors)
# ----------------------------------------------------------------------


def enrich_submitter_ip(sip: SubmitterIP) -> None:
    try:
        apply_to_submitter_ip(sip)
    except Exception:
        logger.exception("MaxMind enrich_submitter_ip failed for %s", sip.address)


def enrich_ip_address(ip: IPAddress) -> None:
    try:
        apply_to_ip_address(ip)
    except Exception:
        logger.exception("MaxMind enrich_ip_address failed for %s", ip.address)
