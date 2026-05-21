"""
Submission pipeline. Phase 1: synchronous, inline.

Takes a persisted Submission row, runs the vendored analyzer if a domain is
present, materializes normalized entities, produces a Verdict. Phase 2 moves
this onto a worker + folds in contact enrichment + risk-profile rules.
"""
from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

import re

from django.db import transaction
from django.utils import timezone

from apps.entities.models import (
    ContactEmail,
    ContactName,
    ContactPhone,
    IPAddress,
    MXHost,
    Nameserver,
    Registrar,
    SubmitterIP,
)
from apps.submissions.models import (
    DomainScan,
    DomainScanIP,
    DomainScanMXHost,
    DomainScanNameserver,
    Submission,
    Verdict,
)

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


_LIST_SEP = re.compile(r"[,;]")


def _split(value: Any) -> list[str]:
    """
    Analyzer multi-valued fields arrive as:
      * Python list
      * comma-separated string ("a, b")
      * semicolon-separated string ("ns1.example.com.;ns2.example.com.")
    """
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if v]
    return [item.strip() for item in _LIST_SEP.split(str(value)) if item.strip()]


def _map_decision(recommendation: str, risk_score: int) -> str:
    rec = (recommendation or "").lower()
    if "approve" in rec:
        return Verdict.DECISION_APPROVE
    if "deny" in rec or "reject" in rec or "block" in rec:
        return Verdict.DECISION_DENY
    if "review" in rec or "manual" in rec:
        return Verdict.DECISION_REVIEW
    # Fallback to score-based if wording is unfamiliar.
    if risk_score >= 70:
        return Verdict.DECISION_DENY
    if risk_score <= 30:
        return Verdict.DECISION_APPROVE
    return Verdict.DECISION_REVIEW


def _normalize_email(raw: str) -> tuple[str, str, str]:
    email = (raw or "").strip().lower()
    if "@" not in email:
        return email, "", email
    handle, domain = email.split("@", 1)
    return email, handle, domain


# ----------------------------------------------------------------------
# Entity materialization
# ----------------------------------------------------------------------


def _extract_domain_entities(domain_scan: DomainScan, raw: dict) -> None:
    # A-record IPs — enrich on first creation. MaxMind first (local, fast,
    # authoritative for geo/ASN), then IPQS (adds VPN/proxy/Tor flags).
    from apps.entities.enrichers import ipqs as ipqs_enricher
    from apps.entities.enrichers import maxmind as maxmind_enricher
    for ip_str in _split(raw.get("ip_address")):
        ip_obj, created = IPAddress.objects.get_or_create(address=ip_str)
        if created:
            maxmind_enricher.enrich_ip_address(ip_obj)
            ipqs_enricher.enrich_ip_address(ip_obj)
        DomainScanIP.objects.get_or_create(
            domain_scan=domain_scan, ip_address=ip_obj, role=DomainScanIP.ROLE_A
        )

    # Nameservers — analyzer emits `ns_records` (semicolon-separated); accept both.
    for ns in _split(raw.get("ns_records") or raw.get("nameservers")):
        hostname = ns.lower().rstrip(".")
        if not hostname:
            continue
        ns_obj, _ = Nameserver.objects.get_or_create(hostname=hostname)
        DomainScanNameserver.objects.get_or_create(
            domain_scan=domain_scan, nameserver=ns_obj
        )

    # MX records — may be "10 mail.example.com" or bare hostname
    for mx_entry in _split(raw.get("mx_records")):
        parts = mx_entry.split()
        if len(parts) == 2 and parts[0].isdigit():
            preference, host = int(parts[0]), parts[1]
        else:
            preference, host = 0, parts[-1]
        hostname = host.lower().rstrip(".")
        if not hostname:
            continue
        mx_obj, _ = MXHost.objects.get_or_create(hostname=hostname)
        DomainScanMXHost.objects.get_or_create(
            domain_scan=domain_scan,
            mx_host=mx_obj,
            defaults={"preference": preference},
        )

    # Registrar
    registrar_name = (raw.get("registrar") or "").strip()
    if registrar_name:
        reg_obj, _ = Registrar.objects.get_or_create(name=registrar_name)
        domain_scan.registrar = reg_obj
        domain_scan.save(update_fields=["registrar"])


def _materialize_contact_entities(submission: Submission) -> None:
    """Phase 1: create bare entity rows from raw inputs. Phase 2 adds enrichment."""
    updates: list[str] = []

    if submission.contact_email_raw:
        email, handle, domain = _normalize_email(submission.contact_email_raw)
        if email:
            obj, created = ContactEmail.objects.get_or_create(
                normalized=email,
                defaults={"handle": handle, "domain": domain},
            )
            if created:
                # Local enricher (disposable/role/MX/gravatar) — free, no API.
                from apps.entities.enrichers.email_local import enrich_contact_email as enrich_local
                enrich_local(obj)
                # IPQS email API (fraud_score, leaked, spam_trap, deliverability, ...).
                # No-op if IPQS_API_KEY unset. Shares IPQS quota with proxy detection.
                from apps.entities.enrichers.ipqs_email import enrich_contact_email as enrich_ipqs_email
                enrich_ipqs_email(obj)
                # SDAT scan on email's DOMAIN if not freemail and not the same as submitted.
                # One-time ~20s cost per unique email on a scannable domain; cached after.
                from apps.entities.enrichers.email_domain_scan import run_email_domain_scan
                run_email_domain_scan(obj, skip_domain=submission.domain)
            submission.contact_email = obj
            updates.append("contact_email")

    if submission.contact_name_raw:
        full = submission.contact_name_raw.strip()
        normalized = " ".join(full.lower().split())
        if normalized:
            obj, _ = ContactName.objects.get_or_create(
                normalized=normalized, defaults={"full": full}
            )
            submission.contact_name = obj
            updates.append("contact_name")

    if submission.contact_phone_raw:
        e164 = submission.contact_phone_raw.strip()
        if e164:
            obj, created = ContactPhone.objects.get_or_create(e164=e164)
            if created:
                from apps.entities.enrichers.phone_local import enrich_contact_phone
                enrich_contact_phone(obj)
            submission.contact_phone = obj
            updates.append("contact_phone")

    if submission.submitter_ip_raw:
        from apps.entities.enrichers import ipqs as ipqs_enricher
        from apps.entities.enrichers import maxmind as maxmind_enricher
        obj, created = SubmitterIP.objects.get_or_create(address=str(submission.submitter_ip_raw))
        if created:
            # MaxMind first (local, ~microseconds): geo + ASN
            maxmind_enricher.enrich_submitter_ip(obj)
            # IPQS second (remote, ~1s): VPN/proxy/Tor flags
            ipqs_enricher.enrich_submitter_ip(obj)
        submission.submitter_ip = obj
        updates.append("submitter_ip")

    if updates:
        submission.save(update_fields=updates)


# ----------------------------------------------------------------------
# Signal builder + baseline decision + risk-profile lookup
# ----------------------------------------------------------------------


def _extract_analyzer_reasons(raw: dict) -> list[dict]:
    """
    Parse the analyzer's pipe-separated summary into structured reasons.
    Example summary:
        "✅ APPROVE (Score: 0) | ✓ CDN-hosted (Cloudflare) — no abuse indicators, Strict SPF"
    The first segment is the decision header (ignored); subsequent segments are
    classified positive/negative based on a ✓/✗ leading glyph.
    """
    summary = raw.get("summary") or ""
    if "|" not in summary:
        return []

    POSITIVE_PREFIXES = ("✓", "✔", "√", "+ ", "+")
    NEGATIVE_PREFIXES = ("✗", "✘", "×", "- ", "-")

    reasons: list[dict] = []
    for segment in [s.strip() for s in summary.split("|")[1:]]:  # skip decision header
        if not segment:
            continue
        text = segment
        code = "ANALYZER_NEUTRAL"
        weight = 0
        for p in POSITIVE_PREFIXES:
            if text.startswith(p):
                text = text[len(p):].strip()
                code = "ANALYZER_POSITIVE"
                weight = 0
                break
        else:
            for p in NEGATIVE_PREFIXES:
                if text.startswith(p):
                    text = text[len(p):].strip()
                    code = "ANALYZER_NEGATIVE"
                    weight = 10
                    break
        if text:
            reasons.append({"code": code, "description": text, "weight": weight})
    return reasons


def _apply_ipqs_adjustments(submission: Submission, base_score: int) -> tuple[int, list[dict]]:
    """
    Translate IPQualityScore signals on the linked entities into score deductions.
    Each signal that fires adds its weight to the SDAT score (higher = worse).
    Kept separate from tag adjustments so investigators can see WHY the IPQS
    enrichment moved the score in verdict.reasons.
    """
    delta = 0
    reasons: list[dict] = []

    # --- Submitter IP (IPQS Proxy Detection signals) ---
    sip = submission.submitter_ip
    if sip is not None:
        if sip.fraud_score is not None and sip.fraud_score >= 85:
            w = 40
            delta += w
            reasons.append({"code": "IPQS_IP_FRAUD_HIGH",
                            "description": f"IPQS IP fraud score {sip.fraud_score}/100 (≥85 high risk)", "weight": w})
        elif sip.fraud_score is not None and sip.fraud_score >= 75:
            w = 20
            delta += w
            reasons.append({"code": "IPQS_IP_FRAUD_SUSPICIOUS",
                            "description": f"IPQS IP fraud score {sip.fraud_score}/100 (≥75 suspicious)", "weight": w})
        if sip.recent_abuse:
            w = 30
            delta += w
            reasons.append({"code": "IPQS_IP_RECENT_ABUSE",
                            "description": "IPQS flagged recent abuse events on this IP", "weight": w})
        if sip.bot_status:
            w = 40
            delta += w
            reasons.append({"code": "IPQS_IP_BOT",
                            "description": "IPQS detected bot activity from this IP", "weight": w})
        if sip.is_tor:
            w = 60
            delta += w
            reasons.append({"code": "IP_TOR_EXIT", "description": "Submitter IP is a Tor exit node", "weight": w})
        if sip.is_vpn:
            w = 20
            delta += w
            reasons.append({"code": "IP_VPN", "description": "Submitter IP is a known VPN", "weight": w})
        if sip.is_proxy:
            w = 40
            delta += w
            reasons.append({"code": "IP_PROXY", "description": "Submitter IP is a proxy", "weight": w})

    # --- Contact email (IPQS Email Validation signals) ---
    ce = submission.contact_email
    if ce is not None and ce.ipqs_enriched_at is not None:
        if ce.ipqs_honeypot:
            w = 60
            delta += w
            reasons.append({"code": "IPQS_EMAIL_HONEYPOT",
                            "description": "Email is an IPQS honeypot / known spam trap", "weight": w})
        if ce.ipqs_overall_score is not None:
            if ce.ipqs_overall_score == 0:
                w = 50
                delta += w
                reasons.append({"code": "IPQS_EMAIL_INVALID",
                                "description": "IPQS overall_score 0 — invalid format / no DNS", "weight": w})
            elif ce.ipqs_overall_score == 1:
                w = 25
                delta += w
                reasons.append({"code": "IPQS_EMAIL_UNREACHABLE",
                                "description": "IPQS overall_score 1 — DNS valid but SMTP unreachable", "weight": w})
            elif ce.ipqs_overall_score == 2:
                w = 15
                delta += w
                reasons.append({"code": "IPQS_EMAIL_TEMP_REJECT",
                                "description": "IPQS overall_score 2 — temporary rejection error", "weight": w})
        if (ce.ipqs_spam_trap_score or "").lower() == "high":
            w = 50
            delta += w
            reasons.append({"code": "IPQS_EMAIL_SPAMTRAP_HIGH",
                            "description": "IPQS spam-trap score HIGH — scrub from marketing lists", "weight": w})
        if ce.ipqs_leaked:
            w = 20
            delta += w
            reasons.append({"code": "IPQS_EMAIL_LEAKED",
                            "description": "Email appears in leaked/breached data per IPQS", "weight": w})
        if ce.ipqs_recent_abuse:
            w = 30
            delta += w
            reasons.append({"code": "IPQS_EMAIL_RECENT_ABUSE",
                            "description": "IPQS flagged recent abuse on this email", "weight": w})
        if ce.ipqs_fraud_score is not None and ce.ipqs_fraud_score >= 85:
            w = 40
            delta += w
            reasons.append({"code": "IPQS_EMAIL_FRAUD_HIGH",
                            "description": f"IPQS email fraud score {ce.ipqs_fraud_score}/100 (≥85 high risk)", "weight": w})
        if ce.ipqs_frequent_complainer:
            w = 15
            delta += w
            reasons.append({"code": "IPQS_EMAIL_FREQUENT_COMPLAINER",
                            "description": "IPQS tagged this email as a frequent complainer", "weight": w})

    adjusted = max(0, min(100, base_score + delta))
    return adjusted, reasons


def _apply_tag_adjustments(submission: Submission, base_score: int) -> tuple[int, list[dict]]:
    """
    Apply investigator-set entity tags (good / bad / do_not_score) to the score.
    Returns (adjusted_score, extra_reasons). Weights are intentionally asymmetric
    favoring manual investigator judgment: a good-tagged submitter IP pulls the
    score down hard, a bad-tagged entity pushes it up hard.
    """
    weights = {
        "submitter_ip":   {"good": -50, "bad": +50},
        "contact_email":  {"good": -40, "bad": +40},
        "contact_phone":  {"good": -30, "bad": +30},
        "contact_name":   {"good": -20, "bad": +20},
    }
    delta = 0
    reasons: list[dict] = []
    for attr, w in weights.items():
        entity = getattr(submission, attr, None)
        if entity is None or not entity.tag:
            continue
        if entity.tag == "good":
            delta += w["good"]
            reasons.append({"code": "TAGGED_GOOD", "description": f"{attr} tagged good: {entity}",
                            "weight": w["good"]})
        elif entity.tag == "bad":
            delta += w["bad"]
            reasons.append({"code": "TAGGED_BAD", "description": f"{attr} tagged bad: {entity}",
                            "weight": w["bad"]})

    # Domain-side entities — any linked IP / NS / MX / registrar tagged pushes score.
    ds = getattr(submission, "domain_scan", None)
    if ds is not None:
        from apps.entities.models import IPAddress, MXHost, Nameserver, Registrar
        for ip in IPAddress.objects.filter(scan_links__domain_scan=ds, tag__in=["good", "bad"]).distinct():
            adj = -30 if ip.tag == "good" else +30
            delta += adj
            reasons.append({"code": f"TAGGED_{ip.tag.upper()}", "description": f"resolving IP tagged {ip.tag}: {ip.address}", "weight": adj})
        for ns in Nameserver.objects.filter(scan_links__domain_scan=ds, tag__in=["good", "bad"]).distinct():
            adj = -25 if ns.tag == "good" else +25
            delta += adj
            reasons.append({"code": f"TAGGED_{ns.tag.upper()}", "description": f"nameserver tagged {ns.tag}: {ns.hostname}", "weight": adj})
        if ds.registrar_id and ds.registrar and ds.registrar.tag in ("good", "bad"):
            adj = -25 if ds.registrar.tag == "good" else +25
            delta += adj
            reasons.append({"code": f"TAGGED_{ds.registrar.tag.upper()}", "description": f"registrar tagged {ds.registrar.tag}: {ds.registrar.name}", "weight": adj})

    adjusted = max(0, min(100, base_score + delta))
    return adjusted, reasons


def _baseline_decision(domain_scan: DomainScan | None) -> tuple[str, int, str, list[dict]]:
    """Pre-rules decision from analyzer output alone."""
    if domain_scan is None:
        return (
            Verdict.DECISION_REVIEW,
            0,
            (
                "No domain signal supplied. Phase 1 only scores domains; submission "
                "recorded for contact-entity tracking and future Phase 2 enrichment."
            ),
            [{"code": "NO_DOMAIN", "description": "No domain provided", "weight": 0}],
        )
    decision = _map_decision(domain_scan.recommendation, domain_scan.risk_score)
    reasons = _extract_analyzer_reasons(domain_scan.raw_result or {})
    return decision, domain_scan.risk_score, domain_scan.summary, reasons


def _active_risk_profile(organization):
    """Return the org's default active risk profile, or None."""
    from apps.risk_profiles.models import RiskProfile
    return (
        RiskProfile.objects
        .filter(organization=organization, is_default=True, is_active=True)
        .first()
    )


def _build_signals(submission: Submission, domain_scan: DomainScan | None, network: dict) -> dict:
    """
    Build the flat signals dict consumed by the rules engine. Keys match paths
    declared in apps.risk_profiles.signal_catalog.SIGNALS.
    """
    raw = (domain_scan.raw_result if domain_scan else {}) or {}

    email = submission.contact_email
    phone = submission.contact_phone
    sip = submission.submitter_ip

    return {
        "submission": {
            "has_domain": bool(submission.domain),
            "has_contact_email": bool(submission.contact_email_raw),
            "has_contact_name": bool(submission.contact_name_raw),
            "has_contact_phone": bool(submission.contact_phone_raw),
            "has_submitter_ip": bool(submission.submitter_ip_raw),
        },
        "domain_scan": {
            "risk_score": int(raw.get("risk_score") or 0) if domain_scan else 0,
            "risk_level": raw.get("risk_level") or "",
            "recommendation": raw.get("recommendation") or "",
            "spf_exists": bool(raw.get("spf_exists")),
            "dmarc_policy": (raw.get("dmarc_policy") or "").lower(),
            "dkim_exists": bool(raw.get("dkim_exists")),
            "https_valid": bool(raw.get("https_valid")),
            "cdn_provider": raw.get("cdn_provider") or "",
            "mx_exists": bool(raw.get("mx_exists")),
            "resolved": bool(raw.get("resolved")),
        },
        "contact_email": {
            "domain": email.domain if email else "",
            "is_disposable": email.is_disposable if email else False,
            "is_role_account": email.is_role_account if email else False,
            "breach_count": email.breach_count if email else 0,
            "mx_reachable": email.mx_reachable if email else None,
        },
        "contact_phone": {
            "country_code": phone.country_code if phone else "",
            "line_type": phone.line_type if phone else "",
        },
        "submitter_ip": {
            "country": sip.country if sip else "",
            "is_vpn": sip.is_vpn if sip else False,
            "is_proxy": sip.is_proxy if sip else False,
            "is_tor": sip.is_tor if sip else False,
            "is_datacenter": sip.is_datacenter if sip else False,
        },
        "network": network,
    }


# ----------------------------------------------------------------------
# Threat-intel detector — Cowork rollup and any other seeded known-threat domain.
# ----------------------------------------------------------------------


def _apply_threat_intel_adjustments(
    submission: Submission, domain_scan, base_score: int
) -> tuple[int, list[dict]]:
    """
    Check submission.domain, cross-link domains, and resolving hostnames against
    ThreatIntelDomain. Each hit adds its score_weight to the baseline; returns the
    final score + reason rows for the verdict.
    """
    from apps.iocs.detector import match_many

    hosts: list[str] = []
    if submission.domain:
        hosts.append(submission.domain)
    if submission.contact_email_raw and "@" in submission.contact_email_raw:
        hosts.append(submission.contact_email_raw.split("@", 1)[1])
    # Cross-link / external domains the SDAT scan surfaced on the page content.
    if domain_scan and isinstance(domain_scan.raw_result, dict):
        raw = domain_scan.raw_result
        for key in ("content_external_link_domains",
                    "content_cross_domain_email_domains",
                    "content_external_script_domains"):
            val = raw.get(key) or []
            if isinstance(val, str):
                # semicolon / comma separated
                for part in val.replace(";", ",").split(","):
                    part = part.strip()
                    if part:
                        hosts.append(part)
            elif isinstance(val, (list, tuple)):
                hosts.extend(str(v).strip() for v in val if v)

    if not hosts:
        return base_score, []

    hits = match_many(hosts)
    if not hits:
        return base_score, []

    score = base_score
    reasons: list[dict] = []
    for hit in hits:
        score += hit["score"]
        emoji = {"high": "🚨", "medium": "⚠️", "low": "·"}.get(hit["confidence"], "⚠️")
        description = (
            f"{emoji} Known threat — {hit['category']}/{hit['subcategory'] or 'general'}"
            + (f" (brand: {hit['brand']})" if hit["brand"] and not hit["brand"].startswith(("generic", "unknown")) else "")
            + f" — matched {hit['matched_host']} against {hit['domain']} "
            f"[{hit['confidence']}, source: {hit['source']}]"
        )
        reasons.append({
            "code": f"threat_intel_{hit['category']}",
            "description": description,
            "weight": hit["score"],
            "kind": "threat_intel",
            "detail": hit,
        })

    return min(score, 100), reasons


# ----------------------------------------------------------------------
# ML classifier — uses the gradient-boosted model trained on TrainingLabels.
# ----------------------------------------------------------------------


def _apply_ml_adjustment(submission, base_score: int) -> tuple[int, list[dict]]:
    """
    Pull a p(fraud) prediction from the persisted classifier and convert it to a
    score adjustment. Silent pass-through if no model is trained yet. Records the
    prediction on the verdict's reasons for explainability.
    """
    try:
        from apps.feedback.ml import predict_fraud_probability, get_model_metadata
        from apps.feedback.services import snapshot_features
    except Exception:
        return base_score, []

    features = snapshot_features(submission)
    p_bad = predict_fraud_probability(features)
    if p_bad is None:
        return base_score, []

    # Map p(fraud) to an additive score adjustment in [-30, +30].
    # p=0.5 is neutral; p=0 pulls score down (−30), p=1 pushes up (+30).
    adjustment = int(round((p_bad - 0.5) * 60))
    meta = get_model_metadata() or {}
    description = (
        f"🤖 ML classifier p(fraud)={p_bad:.2%} "
        f"(model {meta.get('model_version', 'unknown')[:19]}, "
        f"AUC {meta.get('auc')}). Score adjustment: {adjustment:+d}."
    )
    return base_score + adjustment, [{
        "code": "ml_classifier",
        "description": description,
        "weight": adjustment,
        "kind": "ml_inference",
        "detail": {"p_fraud": round(p_bad, 4), "model_version": meta.get("model_version")},
    }]


# ----------------------------------------------------------------------
# Pipeline
# ----------------------------------------------------------------------


def process_submission(submission: Submission) -> Submission:
    """Run the Phase 1 pipeline. Mutates and returns the Submission."""
    # Lazy import so migrations and django check don't transitively import
    # heavyweight analyzer module graph.
    from analyzer import analyze_domain

    submission.status = Submission.STATUS_RUNNING
    submission.started_at = timezone.now()
    submission.save(update_fields=["status", "started_at"])

    try:
        _materialize_contact_entities(submission)

        domain_scan: DomainScan | None = None

        if submission.domain:
            result = analyze_domain(submission.domain)
            raw = asdict(result) if hasattr(result, "__dataclass_fields__") else dict(result)

            with transaction.atomic():
                domain_scan = DomainScan.objects.create(
                    submission=submission,
                    domain=submission.domain,
                    risk_score=int(raw.get("risk_score") or 0),
                    recommendation=str(raw.get("recommendation") or ""),
                    summary=str(raw.get("summary") or ""),
                    risk_level=str(raw.get("risk_level") or ""),
                    analyzer_version=str(raw.get("analyzer_version") or ""),
                    raw_result=raw,
                )
                _extract_domain_entities(domain_scan, raw)

        # Phase 2 sequence:
        #   1. Fingerprint + link (no reputation bump yet — rules need to see PRIOR reputation)
        #   2. Build signals dict
        #   3. Apply risk-profile rules (may override the baseline decision)
        #   4. Persist verdict (with snapshot of rule outcome + profile)
        #   5. Bump reputation counters on linked fingerprints using FINAL decision
        from apps.fingerprints.services import (
            bump_fingerprint_reputation,
            compute_and_link_fingerprints,
        )

        network = compute_and_link_fingerprints(submission, domain_scan)
        signals = _build_signals(submission, domain_scan, network)

        baseline_decision, baseline_score, baseline_summary, baseline_reasons = _baseline_decision(
            domain_scan
        )

        # Apply IPQS signal deductions first (remote enrichment — fraud score, proxy, tor, leaked, etc.)
        baseline_score, ipqs_reasons = _apply_ipqs_adjustments(submission, baseline_score)
        # Then investigator-set tags — tags should win ties against automated IPQS.
        baseline_score, tag_reasons = _apply_tag_adjustments(submission, baseline_score)
        # Threat-intel matches — Cowork rollup, any hostname on known-threat lists.
        baseline_score, threat_reasons = _apply_threat_intel_adjustments(submission, domain_scan, baseline_score)
        # ML classifier — consumes the feature snapshot and adds/subtracts up to ±30
        # points based on p(fraud). Silent no-op if no model has been trained yet.
        baseline_score, ml_reasons = _apply_ml_adjustment(submission, baseline_score)
        baseline_reasons = baseline_reasons + ipqs_reasons + tag_reasons + threat_reasons + ml_reasons
        # Re-evaluate decision if adjustments pushed us across a threshold.
        adjustments_applied = bool(ipqs_reasons or tag_reasons or threat_reasons or ml_reasons)
        if adjustments_applied:
            if baseline_score >= 70:
                baseline_decision = Verdict.DECISION_DENY
            elif baseline_score <= 30:
                baseline_decision = Verdict.DECISION_APPROVE
            else:
                baseline_decision = Verdict.DECISION_REVIEW

            # Rewrite the summary header so it matches the FINAL decision+score.
            # Previously we stored SDAT's original summary verbatim, which left
            # "APPROVE (Score: 5)" visible even after IPQS pushed the decision to DENY.
            decision_emoji = {
                Verdict.DECISION_APPROVE: "✅",
                Verdict.DECISION_DENY: "✗",
                Verdict.DECISION_REVIEW: "◐",
            }.get(baseline_decision, "")
            adj_count = len(ipqs_reasons) + len(tag_reasons)
            header = f"{decision_emoji} {baseline_decision.upper()} (Score: {baseline_score}/100) — {adj_count} IPQS/tag adjustment{'s' if adj_count != 1 else ''}"
            remainder = ""
            if baseline_summary and "|" in baseline_summary:
                remainder = "|".join(baseline_summary.split("|")[1:]).strip()
            elif baseline_summary:
                remainder = baseline_summary.strip()
            baseline_summary = f"{header} | {remainder}" if remainder else header

        # Load active risk profile + evaluate rules.
        from apps.risk_profiles.services import evaluate_rules
        risk_profile = _active_risk_profile(submission.organization)
        rule_outcome = evaluate_rules(
            risk_profile.rules if risk_profile else [], signals
        )

        if rule_outcome is not None:
            final_decision = rule_outcome.decision
            final_summary = rule_outcome.summary or baseline_summary
            final_reasons = [
                {
                    "code": rule_outcome.reason_code,
                    "description": rule_outcome.summary or rule_outcome.rule_name,
                    "rule_id": rule_outcome.rule_id,
                    "rule_name": rule_outcome.rule_name,
                    "weight": rule_outcome.weight,
                }
            ]
        else:
            final_decision = baseline_decision
            final_summary = baseline_summary
            final_reasons = baseline_reasons

        # Snapshot the risk profile state for reproducibility.
        if risk_profile is not None:
            submission.risk_profile = risk_profile
            submission.risk_profile_snapshot = {
                "id": risk_profile.id,
                "name": risk_profile.name,
                "approve_max_score": risk_profile.approve_max_score,
                "deny_min_score": risk_profile.deny_min_score,
                "weight_overrides": risk_profile.weight_overrides,
                "rules": risk_profile.rules,
                "evaluated_at": timezone.now().isoformat(),
            }
            submission.save(update_fields=["risk_profile", "risk_profile_snapshot"])

        verdict = Verdict.objects.create(
            submission=submission,
            decision=final_decision,
            score=baseline_score,
            summary=final_summary,
            reasons=final_reasons,
        )

        try:
            bump_fingerprint_reputation(submission, verdict.decision)
        except Exception:
            logger.exception("fingerprint reputation bump failed for submission %s (non-fatal)", submission.id)

        try:
            from apps.entities.services import bump_entity_reputation
            bump_entity_reputation(submission, verdict.decision)
        except Exception:
            logger.exception("entity reputation bump failed for submission %s (non-fatal)", submission.id)

        submission.status = Submission.STATUS_COMPLETE
        submission.completed_at = timezone.now()
        submission.save(update_fields=["status", "completed_at"])
    except Exception as exc:  # noqa: BLE001 — we capture and record on the row
        logger.exception("submission %s processing failed", submission.id)
        submission.status = Submission.STATUS_FAILED
        submission.error = f"{type(exc).__name__}: {exc}"
        submission.completed_at = timezone.now()
        submission.save(update_fields=["status", "error", "completed_at"])

    return submission
