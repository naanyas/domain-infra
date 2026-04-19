"""
Free / local phone enrichment — no vendor API.

Uses the bundled `phonenumbers` data (already in requirements) to populate:
    country_code   — parsed E.164 country code ("+1", "+44", ...)
    line_type      — mobile / fixed_line / voip / toll_free / premium_rate / ...
    carrier        — bundled carrier name where available (mostly mobile prefixes)
"""
from __future__ import annotations

import logging

import phonenumbers
from phonenumbers import carrier as pn_carrier

from apps.entities.models import ContactPhone

logger = logging.getLogger(__name__)

# phonenumbers.PhoneNumberType enum → short label for our ContactPhone.line_type field
_LINE_TYPE_MAP: dict[int, str] = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
    phonenumbers.PhoneNumberType.VOIP: "voip",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "uan",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "",
}


def enrich_contact_phone(phone: ContactPhone) -> None:
    """Populate ContactPhone fields from phonenumbers bundled data."""
    try:
        parsed = phonenumbers.parse(phone.e164, None)
    except phonenumbers.NumberParseException:
        return

    updates: list[str] = []

    cc = f"+{parsed.country_code}"
    if cc and cc != phone.country_code:
        phone.country_code = cc[:4]
        updates.append("country_code")

    try:
        line_type = _LINE_TYPE_MAP.get(phonenumbers.number_type(parsed), "")
    except Exception:
        line_type = ""
    if line_type and line_type != phone.line_type:
        phone.line_type = line_type[:20]
        updates.append("line_type")

    try:
        carrier_name = pn_carrier.name_for_number(parsed, "en") or ""
    except Exception:
        carrier_name = ""
    if carrier_name and carrier_name != phone.carrier:
        phone.carrier = carrier_name[:100]
        updates.append("carrier")

    if updates:
        try:
            phone.save(update_fields=updates)
        except Exception:
            logger.exception("phone enrichment save failed for %s", phone.e164)
