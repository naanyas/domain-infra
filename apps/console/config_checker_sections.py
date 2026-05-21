"""
Port of the Streamlit config-checker's per-domain section layout.

Given the SDAT `raw_result` dict for a submission, return a list of section dicts
that the submission-detail template renders uniformly. Section order, headers,
metric choices, and expanded-by-default logic mirror the Streamlit app as of 2026-04.

Each section dict:
    {
        "key":        unique panel id,
        "emoji":      leading emoji shown in the panel header,
        "title":      header text (without emoji),
        "expanded":   True/False — whether to render open by default,
        "fire":       True/False — did the underlying signal actually fire?
                      (used to color the header red/green/neutral),
        "severity":   "high" | "medium" | "low" | "info"  (drives header color),
        "metrics":    [{label, value, icon, help}] — tile row at the top.
        "body":       [(kind, content)] where kind ∈ {"error","warn","info","code","caption","list"}
                      — freeform rows shown under the metric tiles.
        "empty_msg":  shown when there's nothing to display (optional).
    }

The template renders these with a uniform `<details>` panel and a consistent
4-tile metric grid so investigators see the same shape for every section.
"""
from __future__ import annotations

from typing import Any

# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        s = v.strip().lower()
        return bool(s) and s not in ("false", "0", "no", "none", "null", "-1")
    if isinstance(v, (list, tuple, dict, set)):
        return bool(v)
    return bool(v)


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _count_semicolon(s: Any) -> int:
    """Streamlit frequently stores lists as semicolon-joined strings — count items."""
    if not s:
        return 0
    if isinstance(s, (list, tuple, set)):
        return len([x for x in s if x])
    s = str(s).strip()
    if not s:
        return 0
    return len([p for p in s.replace(",", ";").split(";") if p.strip()])


def _split(s: Any) -> list[str]:
    if not s:
        return []
    if isinstance(s, (list, tuple, set)):
        return [str(x).strip() for x in s if x]
    return [p.strip() for p in str(s).replace(",", ";").split(";") if p.strip()]


# ------------------------------------------------------------------
# section builders — one per Streamlit expander, same order
# ------------------------------------------------------------------


def _legitimacy_context(d: dict) -> dict | None:
    """Suppression / context items — explains WHY some checks were NOT scored."""
    items: list[tuple[str, str]] = []
    if d.get("lv_allowlist_reason"):
        items.append(("info", f"✅ **Legitimacy allow-list matched** — {d['lv_allowlist_reason']}"))
    if d.get("domain_age_days", 0) and _int(d.get("domain_age_days")) > 365:
        items.append(("info", f"ℹ️ **Established domain** — {d['domain_age_days']} days old"))
    if d.get("registration_private") and not d.get("registration_opaque"):
        items.append(("info", "ℹ️ **WHOIS privacy service** — private but not opaque"))
    if not items:
        return None
    return {
        "key": "legitimacy", "emoji": "🔍", "title": "Legitimacy Checks & Context",
        "fire": False, "severity": "info", "expanded": True,
        "metrics": [], "body": items,
    }


def _phishing_kit(d: dict) -> dict | None:
    fired = bool(d.get("phishing_kit_detected") or d.get("phishing_kit_confidence"))
    if not fired:
        return None
    conf = str(d.get("phishing_kit_confidence", "") or "").upper()
    kit = d.get("phishing_kit_brand", "") or d.get("phishing_kit_variant", "")
    evidence = d.get("phishing_kit_evidence", "")
    return {
        "key": "phishing_kit", "emoji": "🎣", "title": "Phishing Kit Detection",
        "fire": True, "severity": "high", "expanded": True,
        "metrics": [
            {"label": "Confidence", "value": conf or "YES", "icon": "🚨"},
            {"label": "Kit / Brand", "value": kit or "—", "icon": "🎯"},
        ],
        "body": [
            ("error", f"Phishing kit detected — {kit or 'unknown variant'}"),
            ("code", evidence) if evidence else ("caption", "no further detail"),
        ],
    }


def _virustotal(d: dict) -> dict | None:
    checked = d.get("vt_checked", False)
    if not checked and "vt_malicious_count" not in d:
        return None

    mal = _int(d.get("vt_malicious_count"))
    sus = _int(d.get("vt_suspicious_count"))
    total = _int(d.get("vt_total_engines"), 0)
    community = _int(d.get("vt_community_score"))
    reputation = _int(d.get("vt_reputation"))

    fired = mal > 0 or sus > 0
    icon = "🚨" if mal >= 3 else ("⚠️" if mal > 0 or sus > 0 else "✅")

    return {
        "key": "virustotal", "emoji": "🛡️",
        "title": "VirusTotal Reputation" + (" — ⚠️ CHECK FAILED" if d.get("vt_check_failed") else ""),
        "fire": fired, "severity": "high" if mal >= 3 else ("medium" if fired else "info"),
        "expanded": mal > 0,
        "metrics": [
            {"label": "Malicious", "value": f"{mal}/{total}" if total else str(mal), "icon": icon},
            {"label": "Suspicious", "value": str(sus), "icon": "⚠️" if sus else "—"},
            {"label": "Community", "value": str(community), "icon": "·"},
            {"label": "Reputation", "value": str(reputation), "icon": "·"},
        ],
        "body": [("caption", f"VT engines flagged {mal} as malicious, {sus} as suspicious")] if fired else [
            ("caption", "No VT detections")
        ],
    }


def _hacklink(d: dict) -> dict | None:
    detected = d.get("hacklink_detected", False)
    mal_script = d.get("hacklink_malicious_script", False)
    hidden_inject = d.get("hacklink_hidden_injection", False)
    score = _int(d.get("hacklink_score"))
    if not (detected or mal_script or hidden_inject or score):
        return None
    spam_count = _count_semicolon(d.get("hacklink_spam_links", ""))
    is_wp = d.get("hacklink_wordpress", False)
    return {
        "key": "hacklink", "emoji": "🕷️", "title": "Hacklink / SEO Spam Detection",
        "fire": detected or mal_script or hidden_inject,
        "severity": "high" if (mal_script or hidden_inject) else "medium",
        "expanded": True,
        "metrics": [
            {"label": "Hacklink Detected", "value": "YES" if detected else ("KEYWORDS" if score else "No"),
             "icon": "🚨" if detected else ("⚠️" if score else "✅")},
            {"label": "Risk Score", "value": f"{score}/30", "icon": "·"},
            {"label": "Spam Links", "value": str(spam_count), "icon": "🔗" if spam_count else "—"},
            {"label": "WordPress", "value": "✅ Yes" if is_wp else "No", "icon": "·"},
        ],
        "body": [("error", "Malicious script injection detected")] if mal_script else [],
    }


def _malicious_urls(d: dict) -> dict | None:
    """Malicious links + URLs from scan."""
    mal_urls = _split(d.get("malicious_urls", ""))
    vt_links = _int(d.get("vt_malicious_link_count"))
    if not (mal_urls or vt_links):
        return None
    return {
        "key": "malicious_urls", "emoji": "🔗", "title": "Malicious Links & URLs",
        "fire": True, "severity": "high", "expanded": True,
        "metrics": [
            {"label": "Malicious URLs", "value": str(len(mal_urls)), "icon": "🚨"},
            {"label": "VT-flagged Links", "value": str(vt_links), "icon": "🚨" if vt_links else "—"},
        ],
        "body": [("list", mal_urls[:10])] if mal_urls else [],
    }


def _hacklink_campaign(d: dict) -> dict | None:
    prof = d.get("hacklink_campaign_profile", "") or d.get("hacklink_campaign", "")
    if not prof:
        return None
    conf = d.get("hacklink_campaign_confidence", "")
    return {
        "key": "hacklink_campaign", "emoji": "🕸️",
        "title": f"Hacklink Campaign Profile ({conf or 'detected'})",
        "fire": True, "severity": "high", "expanded": True,
        "metrics": [{"label": "Profile", "value": str(prof)[:40], "icon": "🕸️"}],
        "body": [("code", str(prof))],
    }


def _security_tooling(d: dict) -> dict | None:
    tools = _split(d.get("security_tools_detected", "") or d.get("waf_detected", ""))
    if not tools:
        return None
    return {
        "key": "security_tooling", "emoji": "🛡️",
        "title": f"Security Tooling ({len(tools)} detected)",
        "fire": False, "severity": "info", "expanded": False,
        "metrics": [{"label": "Detected", "value": str(len(tools)), "icon": "🛡️"}],
        "body": [("list", tools)],
    }


def _content_identity(d: dict) -> dict | None:
    mismatch = d.get("content_title_body_mismatch", False)
    xd_count = _count_semicolon(d.get("content_cross_domain_email_domains", ""))
    broker = d.get("content_is_broker_page", False)
    facade = d.get("content_is_facade", False)
    wc = _int(d.get("content_visible_word_count"), -1)

    triggered = any([mismatch, xd_count, broker, facade,
                     d.get("content_is_placeholder"), d.get("registration_opaque"),
                     d.get("domain_reregistered"),
                     d.get("content_external_link_domains"),
                     d.get("content_page_emails")])
    if not triggered:
        return None

    facade_label = f"YES ({wc}w)" if facade else (f"No ({wc}w)" if wc >= 0 else "No")
    metrics = [
        {"label": "Title/Body Match", "value": "MISMATCH" if mismatch else "OK",
         "icon": "⚠️" if mismatch else "✅"},
        {"label": "Cross-Domain Emails", "value": str(xd_count),
         "icon": "⚠️" if xd_count else "✅"},
        {"label": "Broker Page", "value": "YES" if broker else "No",
         "icon": "⚠️" if broker else "✅"},
        {"label": "Content Facade", "value": facade_label, "icon": "⚠️" if facade else "✅"},
    ]
    body: list[tuple[str, Any]] = []
    if d.get("content_title_body_detail"):
        body.append(("code", str(d.get("content_title_body_detail"))))
    xd_emails = d.get("content_cross_domain_emails", "")
    xd_domains = d.get("content_cross_domain_email_domains", "")
    if xd_emails or xd_domains:
        body.append(("info", f"Cross-domain emails: {xd_emails or '—'} (domains: {xd_domains or '—'})"))
    if d.get("content_external_link_domains"):
        body.append(("info", f"External link domains: {d['content_external_link_domains']}"))
    if d.get("content_is_placeholder"):
        body.append(("warn", "Placeholder page (parked / holding)"))
    if d.get("registration_opaque"):
        body.append(("warn", "WHOIS registration is OPAQUE (fully privacy-shielded)"))
    if d.get("domain_reregistered"):
        date = str(d.get("domain_reregistered_date", "?"))[:10]
        body.append(("warn", f"Domain re-registered on {date} ({d.get('domain_reregistered_days', '?')} days ago)"))
    return {
        "key": "content_identity", "emoji": "🔍", "title": "Content Identity Verification",
        "fire": mismatch or broker or facade or xd_count > 0,
        "severity": "high" if (broker or facade) else ("medium" if mismatch else "info"),
        "expanded": True, "metrics": metrics, "body": body,
    }


def _category_risk(d: dict) -> dict | None:
    cat = d.get("domain_category", "")
    if not cat:
        return None
    tier = d.get("domain_category_risk_tier", "")
    reason = d.get("domain_category_risk_reason", "")
    conf = d.get("domain_category_confidence", 0)
    sigs = d.get("domain_category_signals", "")
    severity = "high" if str(tier).lower() in ("high", "critical") else ("medium" if tier else "info")
    return {
        "key": "category_risk", "emoji": "📂", "title": f"Category Risk: {cat} ({tier})",
        "fire": severity in ("high", "medium"), "severity": severity, "expanded": True,
        "metrics": [
            {"label": "Category", "value": str(cat), "icon": "📂"},
            {"label": "Tier", "value": str(tier) or "—", "icon": "🚨" if severity == "high" else "·"},
            {"label": "Confidence", "value": f"{conf}%" if conf else "—", "icon": "·"},
        ],
        "body": ([("info", str(reason))] if reason else []) + ([("code", str(sigs))] if sigs else []),
    }


def _vt_external(d: dict) -> dict | None:
    ct = _int(d.get("vt_external_malicious_count"))
    if ct == 0:
        return None
    checked = _int(d.get("vt_external_checked_count"))
    return {
        "key": "vt_external", "emoji": "🌍", "title": f"VT External Malicious ({ct} domains)",
        "fire": True, "severity": "high", "expanded": True,
        "metrics": [
            {"label": "Malicious externals", "value": str(ct), "icon": "🚨"},
            {"label": "External domains checked", "value": str(checked), "icon": "·"},
        ],
        "body": [("code", str(d.get("vt_external_malicious_details", "") or d.get("vt_external_malicious_domains", "")))],
    }


def _contact_cross_reference(d: dict) -> dict | None:
    import json as _json
    raw = d.get("contact_reuse_results", "")
    if not raw:
        return None
    try:
        matches = _json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        matches = []
    if not matches:
        return None
    total = sum(len(m.get("found_on", [])) for m in matches)
    if not total:
        return None
    body = []
    for m in matches[:5]:
        body.append(("info", f"**{m.get('contact', '?')}** also appears on: {', '.join(m.get('found_on', [])[:10])}"))
    return {
        "key": "contact_cross", "emoji": "🌐",
        "title": f"Contact Cross-Reference ({total} other domains)",
        "fire": True, "severity": "medium", "expanded": True,
        "metrics": [{"label": "Re-used contacts", "value": str(len(matches)), "icon": "🌐"}],
        "body": body,
    }


def _domain_takeover(d: dict) -> dict | None:
    triggered = (
        d.get("domain_transfer_lock_recent")
        or d.get("whois_recently_updated")
        or d.get("mx_provider_mismatch")
        or d.get("subdomain_infra_divergent")
        or (d.get("ct_recent_issuance") and _int(d.get("domain_age_days")) > 365)
    )
    if not triggered:
        return None
    locked = d.get("domain_transfer_locked", True)
    recent_unlock = d.get("domain_transfer_lock_recent", False)
    lock_val = "RECENTLY ADDED" if recent_unlock else ("Locked" if locked else "UNLOCKED")
    lock_icon = "🟠" if recent_unlock else ("🟢" if locked else "🔴")

    whois_days = _int(d.get("whois_recently_updated_days"), -1)
    registrar = d.get("whois_registrar", "")

    metrics = [
        {"label": "Transfer Lock", "value": lock_val, "icon": lock_icon},
        {"label": "WHOIS Updated",
         "value": f"{whois_days}d ago" if whois_days >= 0 else "Unknown",
         "icon": "⚠️" if 0 <= whois_days < 30 else "·"},
        {"label": "Registrar", "value": str(registrar)[:30] or "—", "icon": "🏢"},
    ]
    body = []
    if d.get("mx_provider_mismatch"):
        body.append(("error",
                     f"MX provider mismatch (confidence={d.get('mx_hijack_confidence', '?')}): "
                     f"ghost={d.get('mx_ghost_provider', '?')}"))
        if d.get("mx_ghost_evidence"):
            body.append(("code", str(d["mx_ghost_evidence"]).replace(";", "\n")))
    if d.get("subdomain_infra_divergent"):
        conf = d.get("subdomain_divergence_confidence", "")
        parent = d.get("parent_domain", "")
        if str(conf).upper() == "HIGH":
            body.append(("error", f"🚨 SUBDOMAIN DELEGATION ABUSE — diverges from parent `{parent}` (HIGH)"))
        else:
            body.append(("warn", f"⚠️ Subdomain infrastructure divergence from parent `{parent}` ({conf})"))
    if d.get("whois_recently_updated") and whois_days >= 0:
        body.append(("warn",
                     f"WHOIS recently updated ({whois_days}d ago) — possible ownership change / transfer / hijack"))
    return {
        "key": "takeover", "emoji": "🔓", "title": "Domain Takeover Indicators",
        "fire": True, "severity": "high" if d.get("subdomain_infra_divergent") else "medium",
        "expanded": True, "metrics": metrics, "body": body,
    }


def _certificate_transparency(d: dict) -> dict | None:
    ct_count = _int(d.get("ct_log_count"), -1)
    if ct_count < 0:
        return None
    days_since = _int(d.get("ct_days_since_last_cert"), -1)
    recent = d.get("ct_recent_issuance", False)
    tls_dead = d.get("ct_cert_tls_dead", False)
    fired = ct_count == 0 or recent or tls_dead
    return {
        "key": "ct", "emoji": "📜",
        "title": f"Certificate Transparency ({ct_count} certs)",
        "fire": fired, "severity": "medium" if fired else "info",
        "expanded": fired,
        "metrics": [
            {"label": "CT Certs Found", "value": str(ct_count),
             "icon": "⚠️" if ct_count == 0 else "✅"},
            {"label": "Last Cert",
             "value": (f"{days_since}d ago" if days_since >= 0 else ("⚠️ <7d" if recent else "Unknown")),
             "icon": "⚠️" if (0 <= days_since <= 7) or recent else "·"},
            {"label": "First Seen", "value": str(d.get("ct_first_seen", "") or "—")[:10], "icon": "·"},
            {"label": "Issuers",
             "value": (str(d.get("ct_issuers", "") or "—").split(";")[0] or "—")[:25],
             "icon": "📜"},
        ],
        "body": ([("warn", "Certificate TLS is DEAD — cert exists but TLS doesn't terminate correctly.")]
                 if tls_dead else []),
    }


def _oauth_phishing(d: dict) -> dict | None:
    if not d.get("has_oauth_phish"):
        return None
    return {
        "key": "oauth", "emoji": "🔑", "title": "OAuth Consent Phishing",
        "fire": True, "severity": "high", "expanded": True,
        "metrics": [],
        "body": [("error", "OAuth consent-phish indicators present"),
                 ("code", str(d.get("oauth_phish_evidence", "")))],
    }


def _homoglyph(d: dict) -> dict | None:
    if not d.get("is_homoglyph_domain"):
        return None
    return {
        "key": "homoglyph", "emoji": "🔤", "title": "Homoglyph / IDN Spoofing",
        "fire": True, "severity": "high", "expanded": True,
        "metrics": [
            {"label": "Displays as", "value": str(d.get("homoglyph_decoded", "") or "—"), "icon": "🔤"},
            {"label": "Target", "value": str(d.get("homoglyph_target", "") or "—"), "icon": "🎯"},
        ],
        "body": [("code", f"Punycode: {d.get('domain', '')}\nUnicode:  {d.get('homoglyph_decoded', '')}\nTarget:   {d.get('homoglyph_target', '')}")],
    }


def _quishing(d: dict) -> dict | None:
    if not d.get("quishing_profile"):
        return None
    return {
        "key": "quishing", "emoji": "📱", "title": "QR Code Phishing (Quishing)",
        "fire": True, "severity": "high", "expanded": True,
        "metrics": [],
        "body": [("error", "Quishing profile matched"),
                 ("code", str(d.get("quishing_evidence", "")))],
    }


def _cdn_tunnel(d: dict) -> dict | None:
    suspect = d.get("cdn_tunnel_suspect", False)
    if not suspect and not d.get("is_cdn_hosted"):
        return None
    cdn = d.get("cdn_provider", "")
    return {
        "key": "cdn", "emoji": "☁️", "title": "CDN Tunnel Abuse",
        "fire": suspect, "severity": "medium" if suspect else "info",
        "expanded": suspect,
        "metrics": [
            {"label": "CDN Provider", "value": str(cdn) or "—", "icon": "☁️"},
            {"label": "Tunnel Suspect", "value": "YES" if suspect else "No",
             "icon": "⚠️" if suspect else "✅"},
        ],
        "body": ([("code", str(d.get("cdn_tunnel_evidence", "")))] if d.get("cdn_tunnel_evidence") else []),
    }


# ------------------------------------------------------------------
# top-level entry point
# ------------------------------------------------------------------

_BUILDERS = [
    _legitimacy_context,
    _phishing_kit,
    _virustotal,
    _hacklink,
    _malicious_urls,
    _hacklink_campaign,
    _security_tooling,
    _content_identity,
    _category_risk,
    _vt_external,
    _contact_cross_reference,
    _domain_takeover,
    _certificate_transparency,
    _oauth_phishing,
    _homoglyph,
    _quishing,
    _cdn_tunnel,
]


def build_sections(raw_result: dict) -> list[dict]:
    """Run every section builder; drop Nones (section didn't apply)."""
    if not isinstance(raw_result, dict):
        return []
    sections: list[dict] = []
    for builder in _BUILDERS:
        try:
            section = builder(raw_result)
        except Exception:  # noqa: BLE001 — individual section failures should not break the page
            continue
        if section:
            sections.append(section)
    return sections
