from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse as _reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.entities.models import (
    ContactEmail, ContactName, ContactPhone,
    IPAddress, MXHost, Nameserver, Registrar, SubmitterIP,
)
from apps.scoring.models import ScoringRule
from apps.fingerprints.services import render_network_matches
from apps.organizations.models import Organization
from apps.submissions.models import Submission, Verdict

logger = logging.getLogger(__name__)


import re as _re

_CHIP_SPLIT_RE = _re.compile(r"\s*[,—–]\s*")


def _summary_to_chips(summary: str, limit: int = 8) -> list[dict]:
    """
    Parse SDAT's pipe-separated summary into a list of {kind, text} chips
    for inline display in the submissions list. Same breakdown the SDAT
    Streamlit tool shows per-row — positive signals (✓), negative signals (✗),
    and neutral observations between them.
    """
    if not summary or "|" not in summary:
        return []
    chips: list[dict] = []
    for segment in summary.split("|")[1:]:  # skip decision header
        seg = segment.strip()
        if not seg:
            continue
        kind = "neutral"
        if seg.startswith(("✓", "✔", "√", "+")):
            kind = "positive"
            seg = seg.lstrip("✓✔√+ ").strip()
        elif seg.startswith(("✗", "✘", "×", "-")):
            kind = "negative"
            seg = seg.lstrip("✗✘×- ").strip()
        # Split each segment on commas / em-dashes so each observation becomes its own chip.
        for sub in _CHIP_SPLIT_RE.split(seg):
            sub = sub.strip(" .;")
            if sub:
                chips.append({"kind": kind, "text": sub})
                if len(chips) >= limit:
                    return chips
    return chips


def _annotate_summary_chips(submissions):
    """Attach `.summary_chips` to each submission for template rendering."""
    for s in submissions:
        s.summary_chips = []
        if getattr(s, "verdict", None):
            s.summary_chips = _summary_to_chips(s.verdict.summary or "", limit=8)
    return submissions


def _default_organization() -> Organization | None:
    """
    Phase 3 demo runs under the staff user's session — pick the first org.
    (A real customer console would scope to the user's org membership.)
    """
    return Organization.objects.filter(is_active=True).order_by("id").first()


# ----------------------------------------------------------------------
# Home / dashboard
# ----------------------------------------------------------------------


def _all_submissions(org):
    """All submissions for this org. User-submitted data (domain/email/IP/name/phone/
    fingerprint) from eHawk imports IS real user data and shown in /console/.
    Only eHawk's RESPONSE (their score/flags/risk_type metadata) is hidden from
    the /console/ UI — that lives in /admin/ for dev reference."""
    return Submission.objects.filter(organization=org)


@login_required(login_url="/admin/login/")
def home(request):
    """eHawk-style 30-day dashboard: risk-level line chart, gauge, KPI tiles,
    stacked-type bar chart, spike events. Categorizes submissions by the
    investigator-configured custom Scoring Bands."""
    import datetime as _dt
    import json as _json
    from django.db.models.functions import TruncDate
    from apps.risk_profiles.models import RiskProfile

    org = _default_organization()
    if org is None:
        return render(request, "console/home.html", {"org": None})

    # Load the active risk profile's custom scoring bands (or fall back to defaults).
    profile = RiskProfile.objects.filter(organization=org, is_active=True, is_default=True).first()
    bands = (profile.scoring_bands if profile and profile.scoring_bands else DEFAULT_SCORING_BANDS)
    # Only active bands; sort highest→lowest for resolution.
    active_bands = sorted([b for b in bands if b.get("active", True)],
                          key=lambda b: -int(b.get("score_start", 0)))

    def _band_for(score: int) -> dict:
        for b in active_bands:
            if int(b["score_start"]) <= score <= int(b["score_end"]):
                return b
        return active_bands[-1] if active_bands else {
            "label": "Unknown", "color": "#64748b", "decision": "review",
        }

    today = timezone.now().date()
    start = today - _dt.timedelta(days=29)
    days = [(start + _dt.timedelta(days=i)) for i in range(30)]
    day_labels = [d.strftime("%b %d") for d in days]

    # --- Risk-level filter from query string (?risk=<band label>) ---
    risk_filter = (request.GET.get("risk") or "").strip()

    # Pull every verdict in the window, bucket by day AND by band.
    verdicts_qs = (
        Verdict.objects
        .filter(submission__organization=org, submission__created_at__date__gte=start)
        .annotate(d=TruncDate("submission__created_at"))
        .values("d", "decision", "score")
    )

    day_decision: dict = {d: {"approve": 0, "review": 0, "deny": 0} for d in days}
    day_band: dict = {d: {b["label"]: 0 for b in active_bands} for d in days}
    band_totals: dict = {b["label"]: 0 for b in active_bands}

    for row in verdicts_qs:
        d = row["d"]
        if d in day_decision:
            day_decision[d][row["decision"]] += 1
            b = _band_for(int(row["score"]))
            label = b["label"]
            day_band[d][label] = day_band[d].get(label, 0) + 1
            band_totals[label] = band_totals.get(label, 0) + 1

    approve_series = [day_decision[d]["approve"] for d in days]
    review_series = [day_decision[d]["review"] for d in days]
    deny_series = [day_decision[d]["deny"] for d in days]

    # For the risk-level line chart: the SELECTED band's count + its % of total.
    if risk_filter and risk_filter in band_totals:
        selected_label = risk_filter
    elif active_bands:
        # Default = highest-risk band (top of list)
        selected_label = active_bands[0]["label"]
    else:
        selected_label = ""
    selected_color = next((b["color"] for b in active_bands if b["label"] == selected_label), "#ef4444")

    selected_series = [day_band[d].get(selected_label, 0) for d in days]
    total_series = [approve_series[i] + review_series[i] + deny_series[i] for i in range(30)]
    pct_over_threshold = [
        (100.0 * selected_series[i] / total_series[i]) if total_series[i] else 0.0
        for i in range(30)
    ]

    # Totals for gauge + KPI tiles
    totals = {
        "approve": sum(approve_series),
        "review": sum(review_series),
        "deny": sum(deny_series),
        "total": sum(total_series),
    }
    # Avg pipeline timing — verdict.created_at vs submission.created_at
    from django.db.models import Avg, F, ExpressionWrapper, DurationField
    avg_dur = (
        Verdict.objects
        .filter(submission__organization=org, submission__created_at__date__gte=start)
        .annotate(dur=ExpressionWrapper(F("created_at") - F("submission__created_at"),
                                         output_field=DurationField()))
        .aggregate(avg=Avg("dur"))["avg"]
    )
    avg_seconds = round(avg_dur.total_seconds(), 3) if avg_dur else 0.0

    # Spike detection — any day in last 7 with deny count > 2x rolling 30-day mean
    mean_deny = (sum(deny_series) / 30.0) if deny_series else 0.0
    recent_spikes = [
        {"date": days[i].strftime("%Y-%m-%d"), "count": deny_series[i]}
        for i in range(23, 30)
        if mean_deny > 0 and deny_series[i] > 2 * mean_deny
    ]

    # Recent submissions list (sidebar)
    recent = list(
        _all_submissions(org)
        .select_related("verdict", "domain_scan")
        .order_by("-created_at")[:10]
    )
    _annotate_summary_chips(recent)

    # Overridden count (small KPI)
    override_count = Verdict.objects.filter(
        submission__organization=org,
    ).exclude(human_override_decision="").count()

    # Band datasets for the stacked bar chart (one dataset per band, colored by band).
    band_datasets = [
        {
            "label": b["label"],
            "data": [day_band[d].get(b["label"], 0) for d in days],
            "backgroundColor": b.get("color", "#64748b"),
        }
        for b in sorted(active_bands, key=lambda b: -int(b.get("score_start", 0)))
    ]

    return render(request, "console/home.html", {
        "org": org,
        "totals": totals,
        "override_count": override_count,
        "recent": recent,
        "avg_seconds": avg_seconds,
        "spike_events": recent_spikes,
        "bands": active_bands,
        "band_totals": band_totals,
        "risk_filter": selected_label,
        "chart": {
            "labels":         _json.dumps(day_labels),
            "selected":       _json.dumps(selected_series),
            "selected_label": selected_label,
            "selected_color": selected_color,
            "pct":            _json.dumps([round(p, 1) for p in pct_over_threshold]),
            "approve":        _json.dumps(approve_series),
            "review":         _json.dumps(review_series),
            "deny":           _json.dumps(deny_series),
            "band_datasets":  _json.dumps(band_datasets),
            "band_labels":    _json.dumps([b["label"] for b in active_bands]),
            "band_colors":    _json.dumps([b.get("color", "#64748b") for b in active_bands]),
            "band_counts":    _json.dumps([band_totals.get(b["label"], 0) for b in active_bands]),
            "gauge_approve":  totals["approve"],
            "gauge_review":   totals["review"],
            "gauge_deny":     totals["deny"],
        },
    })


# ----------------------------------------------------------------------
# Submissions list
# ----------------------------------------------------------------------


@login_required(login_url="/admin/login/")
def submissions_list(request):
    org = _default_organization()
    qs = (
        _all_submissions(org)
        .select_related(
            "verdict", "domain_scan",
            "submitter_ip", "contact_email", "contact_name", "contact_phone",
        )
        .prefetch_related("fingerprint_links__fingerprint")
        .order_by("-created_at")
    )

    # Filters
    status = request.GET.get("status", "").strip()
    decision = request.GET.get("decision", "").strip()
    review = request.GET.get("review", "").strip()
    search = request.GET.get("q", "").strip()

    if status in ("queued", "running", "complete", "failed"):
        qs = qs.filter(status=status)
    if decision in ("approve", "deny", "review"):
        qs = qs.filter(verdict__decision=decision)
    if review == "unreviewed":
        # Has a verdict but investigator hasn't labeled it yet.
        qs = qs.filter(verdict__isnull=False).filter(
            Q(verdict__review_status="") | Q(verdict__review_status__isnull=True)
        )
    elif review in ("confirmed", "corrected", "unknown"):
        qs = qs.filter(verdict__review_status=review)
    if search:
        qs = qs.filter(
            Q(domain__icontains=search)
            | Q(contact_email_raw__icontains=search)
            | Q(contact_name_raw__icontains=search)
            | Q(external_ref__icontains=search)
            | Q(submitter_ip_raw__icontains=search)
        )

    status_counts = dict(_all_submissions(org).values_list("status").annotate(n=Count("id")))

    # Review-label counts across all submissions in this org — powers the
    # Unreviewed / Confirmed / Corrected / Unknown chip row.
    from apps.submissions.models import Verdict as _V
    verdicts_for_org = _V.objects.filter(submission__organization=org)
    review_counts = {
        "unreviewed": verdicts_for_org.filter(Q(review_status="") | Q(review_status__isnull=True)).count(),
        "confirmed":  verdicts_for_org.filter(review_status=_V.REVIEW_CONFIRMED).count(),
        "corrected":  verdicts_for_org.filter(review_status=_V.REVIEW_CORRECTED).count(),
        "unknown":    verdicts_for_org.filter(review_status=_V.REVIEW_UNKNOWN).count(),
    }

    total_matched = qs.count()
    qs_page = list(qs[:200])  # cap; proper pagination in later turns
    _annotate_summary_chips(qs_page)

    # Attach denormalized row fields so the template renders eHawk-style columns
    # without chasing attribute lookups. Primary fingerprint = first linked
    # is_primary=True fp; OS parsed from device_fingerprint_raw when it looks
    # like a user-agent string.
    import re as _re_ua
    UA_OS_RE = _re_ua.compile(
        r"(Mac OS X [0-9_.]+|Windows NT [0-9.]+|Android [0-9.]+|iPhone OS [0-9_]+|Linux|CrOS)"
    )
    UA_BROWSER_RE = _re_ua.compile(r"(Chrome|Safari|Firefox|Edge|OPR|Opera)/([0-9.]+)")
    for s in qs_page:
        # Primary fingerprint (first actor-kind fp wins; else infrastructure)
        primary_fp = None
        for link in s.fingerprint_links.all():
            if link.is_primary and primary_fp is None:
                primary_fp = link.fingerprint
                break
        s.primary_fp_hash = primary_fp.fingerprint_hash if primary_fp else ""

        # OS / browser from device fingerprint raw
        dev = (s.device_fingerprint_raw or "").strip()
        os_match = UA_OS_RE.search(dev) if dev else None
        br_match = UA_BROWSER_RE.search(dev) if dev else None
        s.ua_os = (os_match.group(1) if os_match else "").replace("_", ".")
        s.ua_browser = f"{br_match.group(1)} {br_match.group(2)}" if br_match else ""

        # Geo IP (country from submitter_ip enrichment)
        sip = s.submitter_ip
        s.geo_country = sip.country if sip else ""
        s.geo_city = sip.city if sip else ""

        # Custom fields pulled from the metadata JSON (populated by import_activations etc.)
        meta = s.metadata or {}
        s.app_name = meta.get("app_name") or ""
        s.org_name = meta.get("org_name") or ""

    return render(
        request,
        "console/submissions_list.html",
        {
            "org": org,
            "submissions": qs_page,
            "total_matched": total_matched,
            "status": status,
            "decision": decision,
            "review": review,
            "q": search,
            "status_counts": status_counts,
            "review_counts": review_counts,
        },
    )


@login_required(login_url="/admin/login/")
@require_POST
def submissions_run_batch(request):
    """
    POST: run the pipeline on N submissions matching current filter (status/decision/search).
    Limited to 20 per click for safety (~5-10 minutes wall-clock).
    """
    org = _default_organization()
    status = request.POST.get("status", "queued")
    decision = request.POST.get("decision", "")
    search = request.POST.get("q", "")
    limit = min(int(request.POST.get("limit") or 20), 50)

    qs = Submission.objects.filter(organization=org)
    if status in ("queued", "running", "failed"):
        qs = qs.filter(status=status)
    if decision in ("approve", "deny", "review"):
        qs = qs.filter(verdict__decision=decision)
    if search:
        qs = qs.filter(
            Q(domain__icontains=search)
            | Q(contact_email_raw__icontains=search)
            | Q(submitter_ip_raw__icontains=search)
            | Q(external_ref__icontains=search)
        )

    from apps.api.services import process_submission
    ran = 0
    for sub in qs.order_by("created_at")[:limit]:
        try:
            process_submission(sub)
            ran += 1
        except Exception:
            logger.exception("batch pipeline run failed for %s", sub.id)

    # Redirect back to the filtered list, preserving query
    qp = "&".join(f"{k}={v}" for k, v in [("status", status), ("decision", decision), ("q", search)] if v)
    url = reverse("console:submissions-list")
    return redirect(f"{url}?{qp}" if qp else url)


# ----------------------------------------------------------------------
# Submission detail
# ----------------------------------------------------------------------


@login_required(login_url="/admin/login/")
def submission_detail(request, submission_id):
    org = _default_organization()
    submission = get_object_or_404(
        Submission.objects.select_related(
            "verdict", "domain_scan", "organization", "risk_profile",
            "contact_email", "contact_name", "contact_phone", "submitter_ip",
        ),
        id=submission_id, organization=org,
    )
    network_matches = render_network_matches(submission)

    raw = (submission.domain_scan.raw_result if hasattr(submission, "domain_scan") and submission.domain_scan else {}) or {}

    # SDAT scoring breakdown — for every field in raw_result that matches a weighted signal
    # in SDAT's config.weights, show what fired and its weight contribution. This is the
    # DIRECT view of "what SDAT is looking at" rather than our own pattern matches.
    from analyzer.config import DEFAULT_CONFIG
    sdat_weights: dict = DEFAULT_CONFIG.get("weights", {}) or {}

    def _is_truthy(val):
        if val in (None, "", False, 0, "0", "False", [], {}, "None"):
            return False
        if isinstance(val, list) and not any(val):
            return False
        return True

    # 1. scoring_breakdown — every weighted signal that fired on THIS scan.
    #
    # Source of truth is SDAT's own `score_breakdown` (the signals SDAT actually
    # scored) — the previous implementation iterated config.weights and missed any
    # signal whose name in `weights` wasn't a verbatim key in raw_result, which on
    # real submissions dropped ~10 of ~12 triggered signals.
    #
    # Strategy:
    #   1. Start from raw.score_breakdown (authoritative per-scan contributions).
    #   2. Union with any weighted-signal name that appears in signals_triggered
    #      or is truthy in raw but missing from score_breakdown (covers edge cases
    #      where SDAT noted the signal but didn't surface it in the breakdown).
    sdat_score_breakdown = raw.get("score_breakdown") or {}
    raw_signals_str = raw.get("signals_triggered") or ""
    triggered = (
        [s.strip() for s in raw_signals_str.split(";") if s.strip()]
        if isinstance(raw_signals_str, str)
        else [str(s).strip() for s in raw_signals_str if s]
    )

    scoring_breakdown: list[dict] = []
    seen: set[str] = set()

    if isinstance(sdat_score_breakdown, dict):
        for signal_name, weight in sdat_score_breakdown.items():
            try:
                w = int(weight)
            except (TypeError, ValueError):
                continue
            seen.add(signal_name)
            val = raw.get(signal_name, True)  # True fallback — it fired
            display_val = val if not isinstance(val, (list, dict)) else f"{len(val)} entries"
            scoring_breakdown.append({
                "signal": signal_name,
                "value": display_val,
                "weight": w,
            })

    # Union-in signals SDAT triggered but didn't include a per-signal weight for —
    # use the config.weights static value as a fallback so they still render.
    for signal_name in triggered:
        if signal_name in seen:
            continue
        w = sdat_weights.get(signal_name)
        try:
            w_int = int(w) if w is not None else 0
        except (TypeError, ValueError):
            w_int = 0
        val = raw.get(signal_name, True)
        display_val = val if not isinstance(val, (list, dict)) else f"{len(val)} entries"
        scoring_breakdown.append({
            "signal": signal_name,
            "value": display_val,
            "weight": w_int,
        })
        seen.add(signal_name)

    # Union-in any remaining weighted signals truthy in raw but not in score_breakdown
    # or signals_triggered (catches older scans without score_breakdown).
    for signal_name, weight in sdat_weights.items():
        if signal_name in seen:
            continue
        val = raw.get(signal_name)
        if not _is_truthy(val):
            continue
        display_val = val if not isinstance(val, (list, dict)) else f"{len(val)} entries"
        scoring_breakdown.append({
            "signal": signal_name,
            "value": display_val,
            "weight": int(weight),
        })

    scoring_breakdown.sort(key=lambda c: abs(c["weight"]), reverse=True)

    # 1b. matched_patterns — KNOWN fraud trends that should scream at the top of the page.
    #     Cross-signal combos that SDAT / IPQS have already classified as a named pattern.
    #     These override the per-signal chip display; if any of these hit, the investigator
    #     needs to see it immediately.
    matched_patterns: list[dict] = []
    sdat = raw or {}

    def _pat(severity, name, detail=""):
        matched_patterns.append({"severity": severity, "name": name, "detail": str(detail)[:200]})

    # === SDAT-flagged known patterns ===
    if sdat.get("autofail_reason"):
        _pat("critical", "Automatic fail", sdat["autofail_reason"])
    if sdat.get("phishing_kit_detected"):
        _pat("critical", "Phishing kit detected",
             sdat.get("phishing_kit_reason") or sdat.get("phishing_kit_filename", ""))
    if sdat.get("hacklink_detected"):
        _pat("critical", "Hacklink injection",
             sdat.get("hacklink_campaign_profile") or f"{sdat.get('hacklink_spam_link_count') or 0} spam links")
    if sdat.get("malicious_script"):
        sig = sdat.get("malicious_script_signals") or "JS pattern match"
        _pat("critical", "Malicious script", sig)
    if sdat.get("hidden_injection"):
        _pat("critical", "Hidden content injection",
             "DOM-level injection pattern detected")
    if sdat.get("high_risk_phish_infra"):
        _pat("critical", "High-risk phishing infrastructure",
             sdat.get("high_risk_phish_infra_reason") or "confirmed")
    if sdat.get("redirects_to_phishing_infra"):
        _pat("critical", "Redirect chain → phishing infrastructure")
    if sdat.get("quishing_profile"):
        _pat("critical", "Quishing pattern (QR code phishing)", sdat["quishing_profile"])
    if sdat.get("homoglyph_target"):
        _pat("high", f"Homoglyph impersonation of {sdat['homoglyph_target']}",
             sdat.get("homoglyph_decoded", ""))
    if sdat.get("brand_plus_keyword_domain"):
        _pat("high", "Brand + keyword in domain",
             sdat.get("brands_detected") or "brand spoofing pattern")
    if sdat.get("tld_variant_spoofing"):
        _pat("high", "TLD variant spoofing",
             "Suspicious TLD mimics popular domain")
    if sdat.get("cdn_tunnel_suspect"):
        _pat("high", "CDN tunnel suspect",
             sdat.get("cdn_tunnel_evidence", ""))
    if sdat.get("mx_ghost_provider"):
        _pat("high", "MX ghost provider",
             sdat.get("mx_ghost_evidence", ""))
    if sdat.get("domain_created_today"):
        _pat("high", "Domain registered TODAY")
    if sdat.get("has_credential_form") and sdat.get("form_posts_external"):
        _pat("high", "Credential form posts to external host")

    # SDAT combos (combinations of signals that matched a named combo rule)
    combos = sdat.get("combos_triggered")
    if combos:
        if isinstance(combos, (list, tuple)):
            for c in combos:
                _pat("high", f"Combo: {c}")
        elif isinstance(combos, str):
            for c in combos.split(";"):
                c = c.strip()
                if c:
                    _pat("high", f"Combo: {c}")

    # === IPQS-flagged known patterns ===
    sip = submission.submitter_ip
    if sip is not None:
        if sip.bot_status:
            _pat("critical", "Confirmed bot activity (IPQS)", "IP performing automated bot traffic")
        if sip.is_tor:
            _pat("high", "Tor exit node", sip.address)
        if sip.fraud_score is not None and sip.fraud_score >= 90:
            _pat("high", f"IPQS IP fraud score {sip.fraud_score}/100",
                 "≥90 = high-risk tier")
    ce = submission.contact_email
    if ce is not None:
        if ce.ipqs_honeypot:
            _pat("critical", "Email is a honeypot / spam trap (IPQS)",
                 "Do not engage — confirmed trap address")
        if (ce.ipqs_spam_trap_score or "").lower() == "high":
            _pat("high", "IPQS spam-trap score HIGH",
                 "Scrub from marketing lists")
        if ce.ipqs_overall_score == 0:
            _pat("high", "Invalid email (IPQS overall_score 0)")

    # 2. critical_indicators — top-weighted SDAT signals specifically, shown prominently.
    CRITICAL_THRESHOLD = 35  # weight >= 35 → prominent red callout
    critical_indicators: list[dict] = []
    for item in scoring_breakdown:
        if abs(item["weight"]) < CRITICAL_THRESHOLD:
            continue
        # Categorize by signal-name prefix for color grouping
        prefix = item["signal"].split("_")[0]
        category_map = {
            "hacklink": "hacklink", "malicious": "malware", "vt": "malware", "malware": "malware",
            "hidden": "injection", "phishing": "phishing", "content": "content",
            "domain": "reputation", "ip": "reputation", "tls": "tls",
            "mail": "email", "disposable": "email", "mx": "email",
            "ns": "dns", "ct": "transparency", "transfer": "whois",
            "no": "resolve", "new": "age", "tld": "domain", "brand": "domain",
            "homoglyph": "domain", "cannot": "email",
        }
        category = category_map.get(prefix, prefix)
        critical_indicators.append({
            "key": item["signal"],
            "label": item["signal"].replace("_", " ").title(),
            "category": category,
            "value": item["value"],
            "weight": item["weight"],
        })

    # 3. Group all truthy raw_result fields by MEANINGFUL fraud-investigator categories.
    #    Previous version just split on first underscore, which produced nonsense buckets
    #    like "has (1)", "is (2)", "no (1)" — these are grammatical prefixes, not categories.
    def _field_category(name: str) -> str:
        # Ordered predicates — first match wins.
        if name in {"recommendation", "risk_score", "risk_level", "summary",
                    "autofail_reason", "analyzer_version", "scan_timestamp",
                    "combos_triggered", "rules_labels", "all_issues_text", "score"}:
            return "Decision & score"
        if name.startswith(("spf_", "dkim_", "dmarc_", "bimi_", "dnssec_", "mta_sts_")):
            return "Email authentication"
        if name.startswith(("mx_", "mail_")) or name == "cannot_receive_mail":
            return "Mail infrastructure"
        if name.startswith(("ns_", "soa_")):
            return "Nameservers"
        if name.startswith(("cert_", "tls_", "ct_")) or name == "https_valid":
            return "TLS & certificates"
        if name.startswith(("http_",)) or name in {"has_401", "has_403", "has_429", "has_503", "has_5xx"}:
            return "HTTP"
        if name.startswith(("hacklink_",)) or name in {"malware_links_found", "has_obfuscation",
                                                          "has_external_js", "has_js_redirect",
                                                          "has_meta_refresh"}:
            return "Hacklink & injection"
        if (name.startswith(("phishing_", "exfil_", "harvest_", "quishing_"))
                or name in {"has_credential_form", "has_sensitive_fields",
                            "has_phishing_kit_filename", "has_phishing_js_behavior",
                            "has_exfil_drop_script", "has_harvest_signals", "has_harvest_combo",
                            "hijack_path_found", "has_hijack_path_pattern",
                            "doc_lure_found", "has_doc_sharing_lure", "has_oauth_phish",
                            "has_suspicious_iframe", "oauth_phish_evidence",
                            "redirects_to_phishing_infra", "high_risk_phish_infra",
                            "high_risk_phish_infra_reason"}):
            return "Phishing patterns"
        if name.startswith(("homoglyph_", "brand_", "brands_", "cross_domain_")):
            return "Brand & impersonation"
        if name.startswith(("redirect_", "redirects_")):
            return "Redirects"
        if name.startswith("app_store_") or name.startswith("app_"):
            return "App store presence"
        if name.startswith("form_") or name.startswith("has_form_"):
            return "Forms & inputs"
        if name.startswith("content_") or name in {"page_title", "page_title_match"}:
            return "Page content"
        if name.startswith(("whois_", "rdap_", "analyzed_")):
            return "WHOIS / registration"
        if ("blacklist" in name) or ("dnsbl" in name):
            return "Blacklists"
        if name in {"ip_address", "asn_display"} or name.startswith(
                ("ip_", "asn_", "ptr_", "parent_", "hosting_", "cdn_")):
            return "Network infrastructure"
        if name.startswith("domain_") or name in {"final_url", "resolved", "sld_entropy",
                                                     "registration_opaque", "tld_variant",
                                                     "is_subdomain", "is_staging_subdomain",
                                                     "is_homoglyph_domain"}:
            return "Domain identity"
        if name.startswith("is_") or name in {"business_identity_signals",
                                                  "missing_business_identity",
                                                  "missing_trust_signals"}:
            return "Domain classifications"
        if name.startswith("has_suspicious_") or name == "pattern_match":
            return "Suspicious patterns"
        return "Other"

    # SDAT's OWN per-signal score breakdown — the authoritative record of what
    # it actually scored (distinct from config.weights which is the max possible weight).
    sdat_score_breakdown_raw = raw.get("score_breakdown") or {}
    sdat_score_contributions: list[dict] = []
    if isinstance(sdat_score_breakdown_raw, dict):
        for sig, w in sdat_score_breakdown_raw.items():
            try:
                w_int = int(w)
            except (TypeError, ValueError):
                continue
            kind = "negative" if w_int > 0 else ("positive" if w_int < 0 else "neutral")
            sdat_score_contributions.append({"signal": sig, "weight": w_int, "kind": kind})
        sdat_score_contributions.sort(key=lambda c: abs(c["weight"]), reverse=True)

    # signals_triggered — SDAT emits a semicolon-separated list of signal names that fired.
    raw_signals = raw.get("signals_triggered") or ""
    sdat_signals_triggered: list[str] = []
    if isinstance(raw_signals, str) and raw_signals:
        sdat_signals_triggered = [s.strip() for s in raw_signals.split(";") if s.strip()]
    elif isinstance(raw_signals, (list, tuple)):
        sdat_signals_triggered = [str(s).strip() for s in raw_signals if s]

    # Build a lookup: field-name → {weight, kind} so the grouped table can annotate
    # each row. Checks config.weights AND SDAT's own per-scan score_breakdown.
    field_weight_lookup: dict = {}
    for sig, w in sdat_weights.items():
        try:
            w_int = int(w)
        except (TypeError, ValueError):
            continue
        if w_int == 0:
            continue
        field_weight_lookup[sig] = {
            "weight": w_int,
            "kind": "negative" if w_int > 0 else "positive",  # positive weight = bad
        }
    # SDAT's own per-scan breakdown wins if both present
    for sig, w in (sdat_score_breakdown_raw.items() if isinstance(sdat_score_breakdown_raw, dict) else []):
        try:
            w_int = int(w)
        except (TypeError, ValueError):
            continue
        if w_int == 0:
            continue
        field_weight_lookup[sig] = {
            "weight": w_int,
            "kind": "negative" if w_int > 0 else "positive",
        }

    triggered_set = set(sdat_signals_triggered)

    def _format_field_value(field_name: str, val):
        """Coerce a raw_result value into a display-friendly shape.

        SDAT stashes multi-valued fields in a few formats:
          - actual Python lists
          - semicolon-separated strings (ns_records, spf_includes, content_*_domains)
          - dicts (score_breakdown, rules_triggered maps)
          - scalars (strings, bools, numbers)

        We return {"kind": "list"|"dict"|"bool"|"scalar", ...} so the template
        can render each type properly (lists as <ul>, dicts as labeled pairs,
        scalars with wrap-don't-truncate styling).
        """
        # True list / tuple
        if isinstance(val, (list, tuple)):
            items = [str(x).strip() for x in val if x is not None and str(x).strip()]
            if not items:
                return {"kind": "scalar", "value": ""}
            return {"kind": "list", "items": items}
        # Dict
        if isinstance(val, dict):
            pairs = [(str(k), str(v)) for k, v in val.items() if v is not None]
            if not pairs:
                return {"kind": "scalar", "value": ""}
            return {"kind": "dict", "pairs": pairs}
        # Bool
        if isinstance(val, bool):
            return {"kind": "bool", "value": val}
        # String with semicolons that looks like a multi-value field
        s = str(val) if val is not None else ""
        if ";" in s:
            parts = [p.strip() for p in s.split(";") if p.strip()]
            # Only split when semicolon-separation is meaningful:
            #   - >1 parts
            #   - field name suggests multi-value (records/emails/phones/domains/etc.)
            #   - AND no part looks like a score/number-only (avoids splitting score_breakdown-like strings accidentally)
            multi_value_hint = any(
                hint in field_name for hint in (
                    "records", "emails", "phones", "domains", "includes",
                    "selectors", "issuers", "codes", "signals", "signatures",
                    "hits", "links", "paths", "scripts", "patterns", "triggered",
                    "statuses", "labels", "provider", "seen"
                )
            )
            if len(parts) > 1 and multi_value_hint:
                return {"kind": "list", "items": parts}
        return {"kind": "scalar", "value": s}

    all_indicators_grouped: dict = {}
    for k, v in raw.items():
        if not _is_truthy(v) or k in ("summary", "raw_result"):
            continue
        cat = _field_category(k)
        ann = field_weight_lookup.get(k)
        item = {
            "key": k,
            "value": v,
            "formatted": _format_field_value(k, v),
            "weight": ann["weight"] if ann else None,
            "kind": ann["kind"] if ann else ("triggered" if k in triggered_set else "neutral"),
            "triggered": k in triggered_set,
        }
        all_indicators_grouped.setdefault(cat, []).append(item)
    # Preferred category order (top to bottom of display).
    _CAT_ORDER = [
        "Decision & score", "Domain identity", "Domain classifications",
        "WHOIS / registration", "Email authentication", "Mail infrastructure",
        "Nameservers", "Network infrastructure", "Blacklists",
        "TLS & certificates", "HTTP", "Page content", "Redirects",
        "Forms & inputs", "App store presence",
        "Phishing patterns", "Hacklink & injection", "Brand & impersonation",
        "Suspicious patterns", "Other",
    ]
    all_indicators_grouped = {
        cat: sorted(all_indicators_grouped[cat], key=lambda it: (it["kind"] == "neutral", it["key"]))
        for cat in _CAT_ORDER if cat in all_indicators_grouped
    }

    # 4. Flat list retained for backward compat with existing template block
    all_indicators = [pair for group in all_indicators_grouped.values() for pair in group]

    # eHawk reference data — when this submission was imported from eHawk, we
    # surface their score + flags as a SEPARATE comparison panel (never mixed
    # with our SDAT outputs). Clearly labeled so investigators can reference
    # eHawk's call when making score adjustments.
    ehawk_meta = {k: v for k, v in (submission.metadata or {}).items()
                  if k.startswith("ehawk_") and k != "ehawk_flags"}
    ehawk_flags = (submission.metadata or {}).get("ehawk_flags") or {}
    has_ehawk_reference = bool(ehawk_meta or ehawk_flags)

    # Interpret eHawk's score (-100 = high risk, +100 = clean) into an eHawk-style decision.
    ehawk_score_val = ehawk_meta.get("ehawk_score")
    ehawk_decision_guess = ""
    try:
        ehs_int = int(ehawk_score_val) if ehawk_score_val not in (None, "") else None
        if ehs_int is not None:
            if ehs_int <= -70:
                ehawk_decision_guess = "deny"
            elif ehs_int >= 0:
                ehawk_decision_guess = "approve"
            else:
                ehawk_decision_guess = "review"
    except (TypeError, ValueError):
        pass

    # Domain-side entities (nameservers / MX / registrar / resolving IPs) with tag URLs
    from django.urls import reverse as _reverse
    domain_entities: list[dict] = []
    ds = getattr(submission, "domain_scan", None)
    if ds is not None:
        for ns_link in ds.nameserver_links.select_related("nameserver").all():
            domain_entities.append({
                "kind": "NS",
                "label": ns_link.nameserver.hostname,
                "obj": ns_link.nameserver,
                "tag_url":    _reverse("console:entity-tag",    args=["nameserver", ns_link.nameserver.id]),
                "detail_url": _reverse("console:entity-detail", args=["nameserver", ns_link.nameserver.id]),
            })
        for mx_link in ds.mx_links.select_related("mx_host").all():
            domain_entities.append({
                "kind": "MX",
                "label": mx_link.mx_host.hostname,
                "obj": mx_link.mx_host,
                "tag_url":    _reverse("console:entity-tag",    args=["mx-host", mx_link.mx_host.id]),
                "detail_url": _reverse("console:entity-detail", args=["mx-host", mx_link.mx_host.id]),
            })
        if ds.registrar_id:
            domain_entities.append({
                "kind": "registrar",
                "label": ds.registrar.name,
                "obj": ds.registrar,
                "tag_url":    _reverse("console:entity-tag",    args=["registrar", ds.registrar.id]),
                "detail_url": _reverse("console:entity-detail", args=["registrar", ds.registrar.id]),
            })
        for ip_link in ds.ip_links.select_related("ip_address").all():
            domain_entities.append({
                "kind": f"IP/{ip_link.role.upper()}",
                "label": ip_link.ip_address.address,
                "obj": ip_link.ip_address,
                "tag_url":    _reverse("console:entity-tag",    args=["resolving-ip", ip_link.ip_address.id]),
                "detail_url": _reverse("console:entity-detail", args=["resolving-ip", ip_link.ip_address.id]),
            })

    # Config-checker-style sections — port of the SDAT Streamlit app's per-domain layout.
    from apps.console.config_checker_sections import build_sections
    config_sections = build_sections(raw)

    # Penalties = only the WEIGHTED signals from the SDAT breakdown (used by both
    # the Area Risk Scores table below AND the Streamlit-layout block further down).
    # Computed here first because area_rows needs it.
    penalties = [p for p in scoring_breakdown if p["weight"] != 0]

    # --- eHawk-style AREA RISK SCORES — per-attribute score contribution table -----
    # One row per investigator-relevant entity (IP, Email, Name, Phone, Domain, Geo,
    # Fingerprint). Score + human-readable details. This is the investigator's "why"
    # in one place.
    area_rows: list[dict] = []

    def _tag_score(entity, kind: str) -> int:
        """Map a tag value to its adjustment weight (mirrors _apply_tag_adjustments)."""
        if not entity or not getattr(entity, "tag", ""):
            return 0
        w = {"submitter_ip": 50, "email": 40, "phone": 30, "name": 20}.get(kind, 0)
        if entity.tag == "bad":
            return w
        if entity.tag == "good":
            return -w
        return 0

    # Submitter IP row
    sip = submission.submitter_ip
    if submission.submitter_ip_raw:
        details: list[str] = []
        score = 0
        if sip:
            if sip.is_vpn: details.append("VPN detected"); score += 40
            if sip.is_proxy: details.append("Proxy detected"); score += 40
            if sip.is_tor: details.append("Tor exit node"); score += 50
            if sip.is_datacenter: details.append("Datacenter IP")
            if sip.fraud_score and sip.fraud_score >= 80:
                details.append(f"IPQS fraud score {sip.fraud_score}")
                score += 40
            if sip.bot_status: details.append("Bot traffic"); score += 50
            if sip.country: details.append(f"Country: {sip.country}")
            score += _tag_score(sip, "submitter_ip")
        area_rows.append({
            "area": "IP", "value": submission.submitter_ip_raw,
            "score": score, "details": details,
            "url": reverse("console:ip-detail", args=[submission.submitter_ip_raw]),
            "tag_url": reverse("console:ip-tag", args=[submission.submitter_ip_raw]),
            "tag": sip.tag if sip else "", "entity_kind": "ip",
        })
    # Email row
    ce = submission.contact_email
    if submission.contact_email_raw:
        details = []
        score = 0
        if ce:
            if ce.is_disposable: details.append("Disposable domain"); score += 30
            if ce.is_role_account: details.append("Role-based address")
            if ce.ipqs_honeypot: details.append("Honeypot / spam trap"); score += 50
            if ce.ipqs_overall_score == 0: details.append("Invalid (IPQS 0)"); score += 30
            if (ce.ipqs_spam_trap_score or "").lower() == "high":
                details.append("High spam-trap score"); score += 30
            score += _tag_score(ce, "email")
        area_rows.append({
            "area": "Email", "value": submission.contact_email_raw,
            "score": score, "details": details,
            "url": reverse("console:entity-detail", args=["email", ce.id]) if ce else "",
            "tag_url": reverse("console:entity-tag", args=["email", ce.id]) if ce else "",
            "tag": ce.tag if ce else "", "entity_kind": "email",
        })
    # Email domain row
    if ce and ce.domain:
        area_rows.append({
            "area": "Email domain", "value": ce.domain,
            "score": 0, "details": ["Valid"] if not ce.is_disposable else ["Disposable"],
            "url": "", "tag_url": "", "tag": "", "entity_kind": "email_domain",
        })
    # Name row
    cn = submission.contact_name
    if submission.contact_name_raw:
        area_rows.append({
            "area": "Name", "value": submission.contact_name_raw,
            "score": _tag_score(cn, "name"),
            "details": [f"Phonetic: {cn.phonetic_hash}"] if (cn and cn.phonetic_hash) else [],
            "url": reverse("console:entity-detail", args=["name", cn.id]) if cn else "",
            "tag_url": reverse("console:entity-tag", args=["name", cn.id]) if cn else "",
            "tag": cn.tag if cn else "", "entity_kind": "name",
        })
    # Phone row
    cp = submission.contact_phone
    if submission.contact_phone_raw:
        details = []
        if cp:
            if cp.country_code: details.append(f"Country code: {cp.country_code}")
            if cp.line_type: details.append(f"Line: {cp.line_type}")
            if not cp.is_valid: details.append("Invalid format")
        area_rows.append({
            "area": "Phone", "value": submission.contact_phone_raw,
            "score": _tag_score(cp, "phone"), "details": details,
            "url": reverse("console:entity-detail", args=["phone", cp.id]) if cp else "",
            "tag_url": reverse("console:entity-tag", args=["phone", cp.id]) if cp else "",
            "tag": cp.tag if cp else "", "entity_kind": "phone",
        })
    # Domain row — SDAT score contribution sum
    if submission.domain:
        sdat_sum = sum(int(p["weight"]) for p in penalties) if penalties else 0
        domain_details = []
        if raw.get("domain_age_days"):
            domain_details.append(f"{raw['domain_age_days']}d old")
        if raw.get("domain_category"):
            domain_details.append(f"Category: {raw['domain_category']}")
        if raw.get("dmarc_valid") or raw.get("dmarc_present"):
            domain_details.append("DMARC ✓")
        else:
            domain_details.append("No DMARC")
        area_rows.append({
            "area": "Domain", "value": submission.domain,
            "score": sdat_sum, "details": domain_details,
            "url": "", "tag_url": "", "tag": "", "entity_kind": "domain",
        })
    # Geolocation row (from submitter IP)
    if sip and sip.country:
        country_details = [f"{sip.city}, " if sip.city else ""]
        country_details.append(f"{sip.country}")
        if sip.is_datacenter:
            country_details.append("Datacenter hosting")
        area_rows.append({
            "area": "Geolocation",
            "value": "".join(country_details).strip(),
            "score": 0, "details": [f"ASN: {sip.asn}"] if sip.asn else [],
            "url": "", "tag_url": "", "tag": "", "entity_kind": "geo",
        })
    # Fingerprint rows (infrastructure + actor)
    for kind, data in (network_matches or {}).items():
        area_rows.append({
            "area": f"Fingerprint ({kind})",
            "value": (data.get("primary_fingerprint") or "")[:24] + "…",
            "score": 0,
            "details": [
                f"Exact matches: {data.get('exact_match_count', 0)}",
                f"Reputation: {data.get('network_reputation_score', 0):+.2f}",
                f"Net flagged: {data.get('network_flagged_count', 0)}",
            ],
            "url": reverse("console:fingerprint-detail", args=[data.get("primary_fingerprint")]) if data.get("primary_fingerprint") else "",
            "tag_url": "", "tag": "", "entity_kind": "fingerprint",
        })

    # --- Streamlit-layout PENALTIES + ALL ISSUES ---------------------------
    # (`penalties` was computed further up so area_rows could use it.)
    net_score_pre_clamp = sum(p["weight"] for p in scoring_breakdown)
    clamp_applied = net_score_pre_clamp != (submission.verdict.score if submission.verdict else 0) and net_score_pre_clamp > 100

    # All Issues = weighted signals + unweighted/neutral triggers + narrative reasons.
    # Each item: {weight, kind, text}
    all_issues: list[dict] = []
    _issue_seen: set[str] = set()

    def _issue(weight: int, text: str, signal_key: str = ""):
        # Dedupe on signal_key or text
        dedupe = signal_key or text.lower()
        if dedupe in _issue_seen:
            return
        _issue_seen.add(dedupe)
        all_issues.append({"weight": weight, "text": text, "signal": signal_key})

    # 1. weighted signals first (sorted desc)
    for p in penalties:
        _issue(p["weight"], p["signal"].replace("_", " ").upper(), p["signal"])

    # 2. every signals_triggered entry that isn't already in
    for sig in sdat_signals_triggered:
        if sig not in _issue_seen:
            _issue(0, sig.replace("_", " ").upper(), sig)

    # 3. narrative reasons from the verdict (if any text isn't already covered)
    if submission.verdict:
        for r in submission.verdict.reasons or []:
            desc = (r.get("description") or "").strip()
            if not desc:
                continue
            w = 0
            try:
                w = int(r.get("weight") or 0)
            except (TypeError, ValueError):
                w = 0
            _issue(w, desc, r.get("code") or "")

    # Sort: weighted signals (descending by weight) first, then unweighted in order.
    all_issues.sort(key=lambda i: (-abs(i["weight"]), i["text"]))

    # --- Email-auth + metadata triplet (for the Streamlit-style metadata row) ---
    domain_meta = {
        "domain_age_days": raw.get("domain_age_days"),
        "domain_created": raw.get("domain_created") or raw.get("created_date"),
        "page_title": raw.get("page_title") or raw.get("content_title"),
        "mx_provider": raw.get("mx_provider_type") or raw.get("mx_provider")
                       or raw.get("mx_provider_label") or (raw.get("mx_records") or ""),
        "asn": raw.get("asn_org") or raw.get("asn") or raw.get("hosting_asn"),
        "asn_num": raw.get("asn"),
        "ns_records": raw.get("ns_records") or raw.get("nameservers"),
        "spf_valid": raw.get("spf_valid") or bool(raw.get("spf_record")),
        "dkim_valid": raw.get("dkim_valid") or raw.get("dkim_present"),
        "dmarc_valid": raw.get("dmarc_valid") or raw.get("dmarc_present"),
        "risk_level": (
            "SEVERE" if (submission.verdict and submission.verdict.score >= 90)
            else ("HIGH" if (submission.verdict and submission.verdict.score >= 70)
                  else ("MEDIUM" if (submission.verdict and submission.verdict.score >= 30)
                        else "LOW"))
        ) if submission.verdict else "—",
    }

    # Back-nav preservation: if ?back=... is present on the URL use that; otherwise
    # fall back to the Referer header so clicking a submission-list row → detail →
    # "← Back" returns to the exact filtered list the user was on.
    back_url = request.GET.get("back") or request.META.get("HTTP_REFERER") or ""
    # Safety: only use it if it's a same-site path (starts with /)
    if not back_url.startswith("/"):
        # The Referer will be a full URL — keep it only if same host.
        from urllib.parse import urlparse
        try:
            ref = urlparse(back_url)
            if ref.netloc and ref.netloc == request.get_host():
                back_url = ref.path + (f"?{ref.query}" if ref.query else "")
            else:
                back_url = ""
        except Exception:
            back_url = ""

    return render(
        request,
        "console/submission_detail.html",
        {
            "org": org,
            "submission": submission,
            "network_matches": network_matches,
            "critical_indicators": critical_indicators,
            "matched_patterns": matched_patterns,
            "scoring_breakdown": scoring_breakdown,
            "all_indicators": all_indicators,
            "all_indicators_grouped": all_indicators_grouped,
            "sdat_score_contributions": sdat_score_contributions,
            "sdat_signals_triggered": sdat_signals_triggered,
            "config_sections": config_sections,
            "back_url": back_url,
            "penalties": penalties,
            "all_issues": all_issues,
            "net_score_pre_clamp": net_score_pre_clamp,
            "clamp_applied": clamp_applied,
            "domain_meta": domain_meta,
            "area_rows": area_rows,
            "ehawk_meta": sorted(ehawk_meta.items()),
            "ehawk_flags": sorted(ehawk_flags.items()) if isinstance(ehawk_flags, dict) else [],
            "has_ehawk_reference": has_ehawk_reference,
            "ehawk_score_val": ehawk_score_val,
            "ehawk_decision_guess": ehawk_decision_guess,
            "domain_entities": domain_entities,
        },
    )


# ----------------------------------------------------------------------
# Create submission (the demo "wow moment")
# ----------------------------------------------------------------------


@login_required(login_url="/admin/login/")
def submission_new(request):
    org = _default_organization()

    if request.method == "POST":
        from apps.api.services import process_submission

        # Validate at least one signal supplied
        fields = ("domain", "contact_email", "contact_name", "contact_phone",
                  "submitter_ip", "device_fingerprint", "external_ref")
        data = {f: request.POST.get(f, "").strip() for f in fields}
        if not any(data[f] for f in ("domain", "contact_email", "contact_name",
                                     "contact_phone", "submitter_ip", "device_fingerprint")):
            return render(request, "console/submission_new.html", {
                "org": org, "error": "At least one signal is required.",
                "form": data,
            })

        # Use the org's first active API key (demo convenience).
        api_key = org.api_keys.filter(revoked_at__isnull=True).first()

        submission = Submission.objects.create(
            organization=org,
            api_key=api_key,
            domain=data["domain"],
            contact_email_raw=data["contact_email"],
            contact_name_raw=data["contact_name"],
            contact_phone_raw=data["contact_phone"],
            submitter_ip_raw=data["submitter_ip"] or None,
            device_fingerprint_raw=data["device_fingerprint"],
            external_ref=data["external_ref"],
        )
        try:
            process_submission(submission)
        except Exception:
            logger.exception("submission %s failed", submission.id)
        return redirect("console:submission-detail", submission_id=submission.id)

    return render(request, "console/submission_new.html", {"org": org, "form": {}})


# ----------------------------------------------------------------------
# IP entity detail — drill-down + tagging
# ----------------------------------------------------------------------


@login_required(login_url="/admin/login/")
def ip_entity_detail(request, address):
    """
    Combined view of IPAddress (domain-side, resolving IPs) AND SubmitterIP
    (submitter-side, submission-time IPs). Same physical address can live in
    both tables; we surface whichever we find.
    """
    ip = IPAddress.objects.filter(address=address).first() or SubmitterIP.objects.filter(address=address).first()
    if ip is None:
        return render(request, "console/entity_not_found.html", {"kind": "IP", "key": address}, status=404)

    kind_label = "Resolving IP (domain-side)" if isinstance(ip, IPAddress) else "Submitter IP (submission-time)"

    # Collect all submissions that touched this address — from BOTH tables.
    linked: list[dict] = []
    for sip in SubmitterIP.objects.filter(address=address):
        for s in sip.submissions.select_related("verdict", "domain_scan").order_by("-created_at")[:100]:
            linked.append({"submission": s, "role": "submitter"})
    for ipa in IPAddress.objects.filter(address=address):
        scans = ipa.scan_links.select_related("domain_scan", "domain_scan__submission__verdict").order_by("-domain_scan__submission__created_at")[:100]
        for link in scans:
            linked.append({"submission": link.domain_scan.submission, "role": f"resolving-{link.role.upper()}"})

    # Dedupe by submission id (a submission might resolve to the same IP AND have it as submitter IP)
    seen: set = set()
    unique = []
    for row in linked:
        if row["submission"].id in seen:
            continue
        seen.add(row["submission"].id)
        unique.append(row)
    unique.sort(key=lambda r: r["submission"].created_at, reverse=True)

    # Close-bys: other IPs in same /24 or same ASN
    close_by: list[dict] = []
    parts = address.split(".")
    if len(parts) == 4:
        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."
        same_24 = list(IPAddress.objects.filter(address__startswith=prefix).exclude(address=address).order_by("address")[:20])
        if same_24:
            close_by.append({"label": f"Same /24 subnet ({prefix}0/24)", "items": [{"value": x.address, "url": _reverse('console:ip-detail', args=[x.address]), "tag": x.tag, "approved": x.net_approved_count, "flagged": x.net_flagged_count} for x in same_24]})
    if getattr(ip, "asn_id", None):
        asn_id = ip.asn_id
        same_asn = list(IPAddress.objects.filter(asn_id=asn_id).exclude(address=address).order_by("address")[:20])
        if same_asn:
            close_by.append({"label": f"Same ASN ({ip.asn})", "items": [{"value": x.address, "url": _reverse('console:ip-detail', args=[x.address]), "tag": x.tag, "approved": x.net_approved_count, "flagged": x.net_flagged_count} for x in same_asn]})

    return render(request, "console/entity_ip_detail.html", {
        "ip": ip,
        "kind_label": kind_label,
        "linked_submissions": unique[:100],
        "close_by": close_by,
    })


@login_required(login_url="/admin/login/")
@require_POST
def ip_entity_tag(request, address):
    """
    POST-only: update tag on all IPAddress + SubmitterIP rows matching this address.
    Keeps both sides aligned since 'the same IP' may live in both tables.
    Honors a ?next=<path> POST param so inline tag forms on other pages return there.

    Guard: VPN / proxy / Tor IPs cannot be tagged good or bad — those IPs are
    shared by many users, so tagging them would propagate incorrect reputation
    across unrelated future submissions. Only do_not_score / clear allowed.
    """
    tag = (request.POST.get("tag") or "").strip()
    reason = (request.POST.get("tag_reason") or "").strip()
    next_url = request.POST.get("next") or ""

    if tag not in ("", "good", "bad", "do_not_score"):
        return redirect(next_url or reverse("console:ip-detail", args=[address]))

    # Enforce the VPN/proxy/Tor guard for good/bad tags.
    if tag in ("good", "bad"):
        shared_ip = (
            IPAddress.objects.filter(address=address).filter(Q(is_vpn=True) | Q(is_proxy=True) | Q(is_tor=True)).exists()
            or SubmitterIP.objects.filter(address=address).filter(Q(is_vpn=True) | Q(is_proxy=True) | Q(is_tor=True)).exists()
        )
        if shared_ip:
            # Could flash a message; for now just no-op redirect back.
            return redirect(next_url if next_url.startswith("/") else reverse("console:ip-detail", args=[address]))

    by = str(request.user) if request.user.is_authenticated else ""
    now = timezone.now() if tag else None

    updates = {"tag": tag, "tag_reason": reason if tag else "", "tagged_at": now, "tagged_by": by if tag else ""}
    IPAddress.objects.filter(address=address).update(**updates)
    SubmitterIP.objects.filter(address=address).update(**updates)

    if next_url and next_url.startswith("/"):  # basic open-redirect guard
        return redirect(next_url)
    return redirect("console:ip-detail", address=address)


ENTITY_MODELS = {
    "email":        ContactEmail,
    "name":         ContactName,
    "phone":        ContactPhone,
    "nameserver":   Nameserver,
    "mx-host":      MXHost,
    "registrar":    Registrar,
    "resolving-ip": IPAddress,
}


# ----------------------------------------------------------------------
# Generic entity detail — shared + similar drill-downs for every attribute
# ----------------------------------------------------------------------


def _submissions_sharing(entity, entity_type: str, limit: int = 100):
    """Submissions where this exact entity appears."""
    if entity_type == "email":
        qs = Submission.objects.filter(contact_email=entity)
    elif entity_type == "name":
        qs = Submission.objects.filter(contact_name=entity)
    elif entity_type == "phone":
        qs = Submission.objects.filter(contact_phone=entity)
    elif entity_type == "nameserver":
        qs = Submission.objects.filter(domain_scan__nameserver_links__nameserver=entity)
    elif entity_type == "mx-host":
        qs = Submission.objects.filter(domain_scan__mx_links__mx_host=entity)
    elif entity_type == "registrar":
        qs = Submission.objects.filter(domain_scan__registrar=entity)
    elif entity_type == "resolving-ip":
        qs = Submission.objects.filter(domain_scan__ip_links__ip_address=entity)
    else:
        return Submission.objects.none()
    return qs.select_related("verdict", "domain_scan").distinct().order_by("-created_at")[:limit]


def _similar_entities(entity, entity_type: str, limit: int = 20):
    """
    Return (label, queryset) tuples — groups of 'close' entities for drill-down.
    Each entity_type defines its own nearness heuristic.
    """
    groups: list[tuple[str, list]] = []

    if entity_type == "email":
        # Same email domain (e.g. all @mailinator.com)
        if entity.domain:
            qs = ContactEmail.objects.filter(domain=entity.domain).exclude(pk=entity.pk).order_by("-id")[:limit]
            if qs:
                groups.append((f"Same email domain ({entity.domain})", list(qs)))
        # Same disposable-ness or role-account-ness
        if entity.is_disposable:
            qs = ContactEmail.objects.filter(is_disposable=True).exclude(pk=entity.pk).exclude(domain=entity.domain).order_by("-id")[:limit]
            if qs:
                groups.append(("Other disposable-domain emails", list(qs)))

    elif entity_type == "name":
        # Same phonetic hash — "Jenna" and "Jena" both → "JN"
        if entity.phonetic_hash:
            qs = ContactName.objects.filter(phonetic_hash=entity.phonetic_hash).exclude(pk=entity.pk).order_by("-id")[:limit]
            if qs:
                groups.append((f"Same phonetic hash ({entity.phonetic_hash})", list(qs)))

    elif entity_type == "phone":
        # Same country code
        if entity.country_code:
            qs = ContactPhone.objects.filter(country_code=entity.country_code).exclude(pk=entity.pk).order_by("-id")[:limit]
            if qs:
                groups.append((f"Same country code ({entity.country_code})", list(qs)))

    elif entity_type == "nameserver":
        # Same root NS domain (e.g. all *.cloudflare.com)
        parts = entity.hostname.split(".")
        if len(parts) >= 3:
            root = ".".join(parts[-2:])
            qs = Nameserver.objects.filter(hostname__endswith=f".{root}").exclude(pk=entity.pk).order_by("hostname")[:limit]
            if qs:
                groups.append((f"Same root domain (*.{root})", list(qs)))

    elif entity_type == "mx-host":
        parts = entity.hostname.split(".")
        if len(parts) >= 3:
            root = ".".join(parts[-2:])
            qs = MXHost.objects.filter(hostname__endswith=f".{root}").exclude(pk=entity.pk).order_by("hostname")[:limit]
            if qs:
                groups.append((f"Same root domain (*.{root})", list(qs)))

    elif entity_type == "resolving-ip":
        # Same /24 subnet (v4) or same ASN
        if "." in entity.address:  # IPv4
            parts = entity.address.split(".")
            if len(parts) == 4:
                prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."
                qs = IPAddress.objects.filter(address__startswith=prefix).exclude(pk=entity.pk).order_by("address")[:limit]
                if qs:
                    groups.append((f"Same /24 subnet ({prefix}0/24)", list(qs)))
        if entity.asn_id:
            qs = IPAddress.objects.filter(asn_id=entity.asn_id).exclude(pk=entity.pk).order_by("-id")[:limit]
            if qs:
                groups.append((f"Same ASN ({entity.asn})", list(qs)))

    return groups


@login_required(login_url="/admin/login/")
def clusters_dashboard(request):
    """
    Cross-dimension cluster view.

    Cluster definition (per investigator rule): ≥2 DISTINCT identities sharing
    some infrastructure. An "identity" is the (domain, contact_email) pair —
    so 5 submissions of the same domain+email from the same IP count as ONE
    identity (repeat activity, not a cluster), while 5 submissions of different
    domains/emails from the same IP count as 5 identities (real cluster).

    Geo-clusters additionally require multiple DIFFERENT submitter IPs in the
    same area — one IP submitting 10 times from the same spot is not a cluster.

    Repeat activity (same identity resubmitted many times) is surfaced in its
    own tab; it's a different signal — replay, retries, automation.
    """
    org = _default_organization()
    if org is None:
        return render(request, "console/clusters.html", {"org": None})

    def _identity_key(sub) -> tuple[str, str]:
        """Single identity = (domain, normalized email). Blank fields keep rows distinct."""
        email_norm = sub.contact_email.normalized if sub.contact_email_id else (sub.contact_email_raw or "")
        return ((sub.domain or "").lower().strip(), (email_norm or "").lower().strip())

    # ---- Geo: buckets with >=2 DIFFERENT identities AND >=2 IPs ----
    BUCKET = 0.5
    buckets: dict[tuple, dict] = {}
    sips = (
        SubmitterIP.objects
        .filter(submissions__organization=org)
        .exclude(latitude__isnull=True)
        .exclude(longitude__isnull=True)
        .distinct()
    )
    for sip in sips:
        submissions = list(
            sip.submissions.filter(organization=org)
            .select_related("verdict", "contact_email")
        )
        if not submissions:
            continue
        lat = float(sip.latitude)
        lng = float(sip.longitude)
        key = (round(lat / BUCKET) * BUCKET, round(lng / BUCKET) * BUCKET)
        bkt = buckets.setdefault(key, {
            "lat_sum": 0.0, "lng_sum": 0.0, "n_ips": 0, "count": 0,
            "scores": [], "deny_count": 0, "ips": [], "countries": set(), "cities": set(),
            "identities": set(),
        })
        bkt["lat_sum"] += lat
        bkt["lng_sum"] += lng
        bkt["n_ips"] += 1
        bkt["count"] += len(submissions)
        for s in submissions:
            bkt["identities"].add(_identity_key(s))
            if getattr(s, "verdict", None):
                bkt["scores"].append(s.verdict.score)
                if s.verdict.effective_decision == "deny":
                    bkt["deny_count"] += 1
        if sip.country:
            bkt["countries"].add(sip.country)
        if sip.city:
            bkt["cities"].add(sip.city)
        bkt["ips"].append({
            "address": sip.address,
            "count": len(submissions),
            "city": sip.city or "",
            "country": sip.country or "",
            "url": reverse("console:ip-detail", args=[sip.address]),
        })

    geo_points = []
    for bkt in buckets.values():
        # Real geo-cluster = ≥2 distinct identities AND ≥2 distinct IPs in the same area.
        if bkt["n_ips"] < 2 or len(bkt["identities"]) < 2:
            continue
        avg_score = sum(bkt["scores"]) / len(bkt["scores"]) if bkt["scores"] else None
        bkt["ips"].sort(key=lambda x: -x["count"])
        geo_points.append({
            "lat": bkt["lat_sum"] / bkt["n_ips"],
            "lng": bkt["lng_sum"] / bkt["n_ips"],
            "count": bkt["count"],
            "n_ips": bkt["n_ips"],
            "n_identities": len(bkt["identities"]),
            "avg_score": round(avg_score, 1) if avg_score is not None else None,
            "deny_count": bkt["deny_count"],
            "label": ", ".join(sorted(bkt["cities"])[:3]) or ", ".join(sorted(bkt["countries"])[:3]) or "—",
            "countries": sorted(bkt["countries"]),
            "ips": bkt["ips"][:10],
        })
    geo_points.sort(key=lambda p: -p["n_identities"])

    # ---- Fingerprint clusters: same hash, ≥2 DISTINCT identities ----
    # Review filter: "open" (default, only unreviewed), "all", "reviewed".
    # Any cluster_verdict value counts as reviewed and drops the cluster out of
    # the open queue — including "unknown" so investigators can park ambiguous
    # ones without them showing up again.
    from apps.fingerprints.models import Fingerprint, SubmissionFingerprint

    cluster_review_filter = (request.GET.get("review") or "open").strip()
    fp_clusters_data = []
    candidate_fps = (
        Fingerprint.objects
        .annotate(
            primary_count=Count("submission_links", filter=Q(
                submission_links__is_primary=True,
                submission_links__submission__organization=org,
            ))
        )
        .filter(primary_count__gte=2)
        .select_related("reputation")
        .order_by("-primary_count")[:200]
    )
    fp_review_counts = {"open": 0, "reviewed": 0, "all": 0}
    for fp in candidate_fps:
        subs = list(
            Submission.objects
            .filter(
                fingerprint_links__fingerprint=fp,
                fingerprint_links__is_primary=True,
                organization=org,
            )
            .select_related("contact_email")
            .distinct()
        )
        identities = {_identity_key(s) for s in subs}
        if len(identities) < 2:
            continue

        cv = fp.reputation.cluster_verdict if hasattr(fp, "reputation") else ""
        is_reviewed = bool(cv)
        fp_review_counts["all"] += 1
        fp_review_counts["reviewed" if is_reviewed else "open"] += 1

        # Respect the review filter
        if cluster_review_filter == "open" and is_reviewed:
            continue
        if cluster_review_filter == "reviewed" and not is_reviewed:
            continue

        fp_clusters_data.append({
            "hash": fp.fingerprint_hash,
            "kind": fp.kind,
            "count": len(subs),
            "n_identities": len(identities),
            "reputation": round(fp.reputation.reputation_score, 2) if hasattr(fp, "reputation") else 0.0,
            "flagged": fp.reputation.flagged_count if hasattr(fp, "reputation") else 0,
            "approved": fp.reputation.approved_count if hasattr(fp, "reputation") else 0,
            "cluster_verdict": cv,
            "cluster_verdict_at": fp.reputation.cluster_verdict_at if hasattr(fp, "reputation") else None,
            "cluster_verdict_by": fp.reputation.cluster_verdict_by if hasattr(fp, "reputation") else "",
            "url": reverse("console:fingerprint-detail", args=[fp.fingerprint_hash]),
        })
        if len(fp_clusters_data) >= 50:
            break
    fp_clusters_data.sort(key=lambda r: -r["n_identities"])

    # ---- Entity co-occurrence: already distinct-by-design ----
    ip_email_cooc = list(
        Submission.objects.filter(organization=org, submitter_ip__isnull=False, contact_email__isnull=False)
        .values("submitter_ip__address")
        .annotate(n_emails=Count("contact_email", distinct=True),
                  n_domains=Count("domain", distinct=True))
        .filter(n_emails__gte=2)
        .order_by("-n_emails")[:15]
    )
    email_ip_cooc = list(
        Submission.objects.filter(organization=org, submitter_ip__isnull=False, contact_email__isnull=False)
        .values("contact_email__normalized", "contact_email__id")
        .annotate(n_ips=Count("submitter_ip", distinct=True))
        .filter(n_ips__gte=2)
        .order_by("-n_ips")[:15]
    )

    # ---- IP clusters: three flavors ----
    #   1. Single IP used by ≥2 distinct identities
    #   2. Same /24 (v4) or /64 (v6) subnet used by ≥2 IPs across ≥2 identities
    #   3. Same ASN used by ≥2 IPs across ≥2 identities
    #
    # Pull the raw submission rows (domain, email_norm, ip, country, asn) once and
    # group in Python — three queries on the same dataset would beat the DB harder.
    ip_submission_rows = list(
        Submission.objects
        .filter(organization=org, submitter_ip__isnull=False)
        .values(
            "domain",
            "contact_email__normalized",
            "submitter_ip__address",
            "submitter_ip__country",
            "submitter_ip__city",
            "submitter_ip__asn__number",
            "submitter_ip__asn__name",
        )
    )

    def _asn_label(row: dict) -> str:
        num = row.get("submitter_ip__asn__number")
        name = row.get("submitter_ip__asn__name") or ""
        if num:
            return f"AS{num} {name}".strip()
        return name.strip()

    def _identity_of(row: dict) -> tuple[str, str]:
        return ((row["domain"] or "").lower().strip(),
                (row["contact_email__normalized"] or "").lower().strip())

    def _subnet_of(addr: str) -> str:
        """Return '/24' (v4) or '/64' (v6) prefix string; blank on failure."""
        if not addr:
            return ""
        if ":" in addr:
            # Simplistic v6 /64 — first 4 groups
            parts = addr.split(":")[:4]
            return ":".join(p for p in parts if p) + "::/64"
        parts = addr.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ""

    # Per-IP aggregation
    per_ip: dict = {}
    per_subnet: dict = {}
    per_asn: dict = {}
    for row in ip_submission_rows:
        addr = row["submitter_ip__address"]
        if not addr:
            continue
        ident = _identity_of(row)

        asn_label = _asn_label(row)
        bkt = per_ip.setdefault(addr, {
            "address": addr,
            "identities": set(),
            "domains": set(),
            "emails": set(),
            "country": row["submitter_ip__country"] or "",
            "city":    row["submitter_ip__city"] or "",
            "asn":     asn_label,
            "count": 0,
        })
        bkt["identities"].add(ident)
        if row["domain"]: bkt["domains"].add(row["domain"])
        if row["contact_email__normalized"]: bkt["emails"].add(row["contact_email__normalized"])
        bkt["count"] += 1

        subnet = _subnet_of(addr)
        if subnet:
            sbkt = per_subnet.setdefault(subnet, {
                "subnet": subnet, "ips": set(), "identities": set(),
                "country": row["submitter_ip__country"] or "",
                "asn": asn_label,
                "count": 0,
            })
            sbkt["ips"].add(addr)
            sbkt["identities"].add(ident)
            sbkt["count"] += 1

        if asn_label:
            abkt = per_asn.setdefault(asn_label, {
                "asn": asn_label, "ips": set(), "identities": set(),
                "countries": set(), "count": 0,
            })
            abkt["ips"].add(addr)
            abkt["identities"].add(ident)
            if row["submitter_ip__country"]: abkt["countries"].add(row["submitter_ip__country"])
            abkt["count"] += 1

    ip_clusters = []
    for b in per_ip.values():
        if len(b["identities"]) < 2:
            continue  # one identity = repeat activity, not a cluster
        ip_clusters.append({
            "address": b["address"],
            "n_identities": len(b["identities"]),
            "n_domains": len(b["domains"]),
            "n_emails": len(b["emails"]),
            "country": b["country"], "city": b["city"], "asn": b["asn"],
            "count": b["count"],
            "url": reverse("console:ip-detail", args=[b["address"]]),
        })
    ip_clusters.sort(key=lambda r: -r["n_identities"])
    ip_clusters = ip_clusters[:25]

    subnet_clusters = []
    for b in per_subnet.values():
        if len(b["ips"]) < 2 or len(b["identities"]) < 2:
            continue  # need ≥2 different IPs AND ≥2 different identities
        subnet_clusters.append({
            "subnet": b["subnet"],
            "n_ips": len(b["ips"]),
            "n_identities": len(b["identities"]),
            "country": b["country"], "asn": b["asn"],
            "count": b["count"],
            "ips": sorted(b["ips"])[:10],
        })
    subnet_clusters.sort(key=lambda r: -r["n_identities"])
    subnet_clusters = subnet_clusters[:20]

    asn_clusters = []
    for b in per_asn.values():
        if len(b["ips"]) < 2 or len(b["identities"]) < 2:
            continue
        asn_clusters.append({
            "asn": b["asn"],
            "n_ips": len(b["ips"]),
            "n_identities": len(b["identities"]),
            "countries": sorted(b["countries"])[:3],
            "count": b["count"],
        })
    asn_clusters.sort(key=lambda r: -r["n_identities"])
    asn_clusters = asn_clusters[:15]

    # ---- Device fingerprint reuse: same device → ≥2 DISTINCT identities ----
    from urllib.parse import quote
    device_rows_raw = (
        Submission.objects.filter(organization=org)
        .exclude(device_fingerprint_raw="")
        .values("device_fingerprint_raw")
        .annotate(
            n_emails=Count("contact_email", distinct=True),
            n_ips=Count("submitter_ip", distinct=True),
            n_domains=Count("domain", distinct=True),
            total=Count("id"),
        )
        .filter(total__gte=2)
        .order_by("-total")[:60]
    )
    fp_reuse = []
    for row in device_rows_raw:
        # Real cluster only if ≥2 distinct identities on this device.
        # Approximate: require either multiple emails OR multiple domains.
        distinct_ident = max(row["n_emails"], row["n_domains"])
        if distinct_ident < 2:
            continue
        row["n_identities"] = distinct_ident
        row["url"] = reverse("console:device-fingerprint-detail",
                              args=[quote(row["device_fingerprint_raw"], safe="")])
        fp_reuse.append(row)
        if len(fp_reuse) >= 15:
            break

    # ---- REPEAT ACTIVITY: same identity submitted ≥3 times (replay / retries) ----
    repeat_activity = list(
        Submission.objects.filter(organization=org, domain__gt="", contact_email__isnull=False)
        .values("domain", "contact_email__normalized")
        .annotate(
            n=Count("id"),
            n_ips=Count("submitter_ip", distinct=True),
            n_devices=Count("device_fingerprint_raw", distinct=True),
        )
        .filter(n__gte=3)
        .order_by("-n")[:20]
    )

    return render(request, "console/clusters.html", {
        "org": org,
        "geo_points": geo_points,
        "fp_clusters": fp_clusters_data,
        "fp_review_counts": fp_review_counts,
        "cluster_review_filter": cluster_review_filter,
        "ip_email_cooc": ip_email_cooc,
        "email_ip_cooc": email_ip_cooc,
        "fp_reuse": fp_reuse,
        "repeat_activity": repeat_activity,
        "ip_clusters": ip_clusters,
        "subnet_clusters": subnet_clusters,
        "asn_clusters": asn_clusters,
    })


@login_required(login_url="/admin/login/")
def fingerprint_detail(request, fingerprint_hash):
    """Show everything about one fingerprint: canonical signals, reputation,
    all submissions that share it (exact), and the fuzzy nearest neighbors."""
    from apps.fingerprints.models import Fingerprint, SubmissionFingerprint

    fp = get_object_or_404(
        Fingerprint.objects.select_related("reputation"),
        fingerprint_hash=fingerprint_hash,
    )

    # All submissions where this is the PRIMARY fingerprint of its kind — with
    # the full signup + enrichment + entity-tag state pulled eagerly so the
    # investigator can make a cluster-review decision in one screen.
    shared = list(
        Submission.objects
        .filter(fingerprint_links__fingerprint=fp, fingerprint_links__is_primary=True)
        .select_related(
            "verdict", "domain_scan", "organization",
            "contact_email", "contact_name", "contact_phone", "submitter_ip",
        )
        .distinct()
        .order_by("-created_at")[:200]
    )
    _annotate_summary_chips(shared)

    # Build a detail dict for each submission — everything we'd want to see on a
    # cluster review: raw inputs, enrichment, entity tags, verdict, reasons, metadata.
    shared_details = []
    for s in shared:
        sip = s.submitter_ip
        ce = s.contact_email
        cn = s.contact_name
        cp = s.contact_phone
        ds = getattr(s, "domain_scan", None)
        raw = ds.raw_result if ds and ds.raw_result else {}
        v = s.verdict

        shared_details.append({
            "s": s,
            "inputs": [
                ("Domain",     s.domain or "—"),
                ("Email",      s.contact_email_raw or "—"),
                ("Name",       s.contact_name_raw or "—"),
                ("Phone",      s.contact_phone_raw or "—"),
                ("Submitter IP", s.submitter_ip_raw or "—"),
                ("Device",     (s.device_fingerprint_raw or "—")[:120]),
                ("External ref", s.external_ref or "—"),
            ],
            "metadata": sorted((s.metadata or {}).items()),
            "ip": {
                "country": sip.country if sip else "",
                "city":    sip.city if sip else "",
                "asn":     sip.asn if sip else "",
                "is_vpn":  sip.is_vpn if sip else False,
                "is_proxy": sip.is_proxy if sip else False,
                "is_tor":   sip.is_tor if sip else False,
                "is_datacenter": sip.is_datacenter if sip else False,
                "fraud_score": sip.fraud_score if sip else None,
                "bot_status":  sip.bot_status if sip else False,
                "tag":  sip.tag if sip else "",
                "detail_url": reverse("console:ip-detail", args=[sip.address]) if sip else "",
            } if sip else None,
            "email": {
                "normalized":   ce.normalized if ce else "",
                "domain":       ce.domain if ce else "",
                "is_disposable": ce.is_disposable if ce else False,
                "is_role_based": ce.is_role_account if ce else False,
                "mx_reachable":  ce.mx_reachable if ce else None,
                "ipqs_honeypot": ce.ipqs_honeypot if ce else False,
                "ipqs_overall_score": ce.ipqs_overall_score if ce else None,
                "ipqs_spam_trap_score": ce.ipqs_spam_trap_score if ce else "",
                "tag": ce.tag if ce else "",
                "detail_url": reverse("console:entity-detail", args=["email", ce.id]) if ce else "",
            } if ce else None,
            "name":  {"normalized": cn.normalized, "phonetic": cn.phonetic_hash, "tag": cn.tag,
                      "detail_url": reverse("console:entity-detail", args=["name", cn.id])} if cn else None,
            "phone": {"e164": cp.e164, "country_code": cp.country_code, "line_type": cp.line_type,
                      "is_valid": cp.is_valid, "tag": cp.tag,
                      "detail_url": reverse("console:entity-detail", args=["phone", cp.id])} if cp else None,
            "verdict": {
                "decision":       v.decision if v else "",
                "score":          v.score if v else None,
                "summary":        v.summary if v else "",
                "reasons":        v.reasons if v else [],
                "review_status":  v.review_status if v else "",
                "human_override": v.human_override_decision if v else "",
            } if v else None,
            "domain_meta": {
                "age_days":      raw.get("domain_age_days"),
                "created":       raw.get("domain_created") or raw.get("created_date"),
                "page_title":    raw.get("page_title") or raw.get("content_title"),
                "registrar":     raw.get("whois_registrar"),
                "ns_records":    raw.get("ns_records") or raw.get("nameservers"),
                "mx_provider":   raw.get("mx_provider_type") or raw.get("mx_provider"),
                "spf_valid":     raw.get("spf_valid") or bool(raw.get("spf_record")),
                "dkim_valid":    raw.get("dkim_valid") or raw.get("dkim_present"),
                "dmarc_valid":   raw.get("dmarc_valid") or raw.get("dmarc_present"),
                "signals_triggered": raw.get("signals_triggered"),
                "score_breakdown":   raw.get("score_breakdown"),
            } if raw else None,
        })

    # Fuzzy neighbors — fingerprints tied to this one as non-primary via some submission
    neighbor_links = (
        SubmissionFingerprint.objects
        .filter(submission__fingerprint_links__fingerprint=fp, is_primary=False)
        .exclude(fingerprint=fp)
        .select_related("fingerprint", "fingerprint__reputation")
        .order_by("-similarity")[:50]
    )
    # Dedupe by fingerprint
    seen = set()
    neighbors = []
    for link in neighbor_links:
        if link.fingerprint_id in seen:
            continue
        seen.add(link.fingerprint_id)
        neighbors.append({
            "fingerprint": link.fingerprint,
            "similarity": round(link.similarity, 3),
        })

    return render(request, "console/fingerprint_detail.html", {
        "fingerprint": fp,
        "shared_submissions": shared,
        "shared_details": shared_details,
        "neighbors": neighbors,
    })


@login_required(login_url="/admin/login/")
def scoring_rules(request):
    """Browse eHawk-style scoring rules: area grouping, coverage status, scores."""
    area_filter = request.GET.get("area", "").strip()
    impl_filter = request.GET.get("impl", "").strip()  # '', 'yes', 'no'
    search = request.GET.get("q", "").strip()

    rules = ScoringRule.objects.all()
    if area_filter:
        rules = rules.filter(area=area_filter)
    if impl_filter == "yes":
        rules = rules.filter(is_implemented=True)
    elif impl_filter == "no":
        rules = rules.filter(is_implemented=False)
    if search:
        rules = rules.filter(
            Q(hit__icontains=search) | Q(description__icontains=search) | Q(area__icontains=search)
        )
    rules = rules.order_by("area", "hit")

    # Group by area for display
    groups: dict = {}
    for r in rules:
        groups.setdefault(r.area, []).append(r)

    # Area counts for the filter dropdown
    area_counts = dict(
        ScoringRule.objects.values_list("area").annotate(n=Count("id")).order_by("area")
    )
    impl_count = ScoringRule.objects.filter(is_implemented=True).count()
    total_count = ScoringRule.objects.count()

    return render(request, "console/scoring_rules.html", {
        "groups": groups,
        "area_counts": area_counts,
        "area_filter": area_filter,
        "impl_filter": impl_filter,
        "q": search,
        "impl_count": impl_count,
        "total_count": total_count,
    })


@login_required(login_url="/admin/login/")
def entity_detail(request, entity_type, entity_id):
    """
    Generic entity drill-down: shared submissions (exact links) + similar
    entities (close-by heuristic per type) + tag form + enrichment display.
    Works for email, name, phone, nameserver, mx-host, registrar, resolving-ip.
    IP (submitter-time) uses its own address-keyed view.
    """
    model = ENTITY_MODELS.get(entity_type)
    if model is None:
        return render(request, "console/entity_not_found.html",
                      {"kind": entity_type, "key": entity_id}, status=404)
    entity = get_object_or_404(model, pk=entity_id)

    shared = _submissions_sharing(entity, entity_type)
    similar_groups = _similar_entities(entity, entity_type)

    # Choose how to label each entity type on the page
    LABELS = {
        "email":        ("Contact email",         entity.normalized if hasattr(entity, "normalized") else ""),
        "name":         ("Contact name",          getattr(entity, "full", "")),
        "phone":        ("Contact phone",         getattr(entity, "e164", "")),
        "nameserver":   ("Nameserver",            getattr(entity, "hostname", "")),
        "mx-host":      ("MX host",               getattr(entity, "hostname", "")),
        "registrar":    ("Registrar",             getattr(entity, "name", "")),
        "resolving-ip": ("Resolving IP (domain-side)", getattr(entity, "address", "")),
    }
    kind_label, display_value = LABELS.get(entity_type, (entity_type, str(entity)))

    return render(request, "console/entity_detail.html", {
        "entity": entity,
        "entity_type": entity_type,
        "kind_label": kind_label,
        "display_value": display_value,
        "shared_submissions": shared,
        "similar_groups": similar_groups,
    })


@login_required(login_url="/admin/login/")
@require_POST
def entity_tag_by_id(request, entity_type, entity_id):
    """
    Generic tag handler for any NetworkEntity subclass identified by primary key.
    Tagging every attribute — email, name, phone, nameserver, MX, registrar,
    resolving IP — flows through here. Submitter-IP uses the address-keyed
    ip_entity_tag variant since the same IP can span IPAddress + SubmitterIP.
    """
    model = ENTITY_MODELS.get(entity_type)
    if model is None:
        return redirect(request.POST.get("next") or "/console/")
    entity = get_object_or_404(model, pk=entity_id)

    tag = (request.POST.get("tag") or "").strip()
    reason = (request.POST.get("tag_reason") or "").strip()
    next_url = request.POST.get("next") or ""

    if tag not in ("", "good", "bad", "do_not_score"):
        return redirect(next_url if next_url.startswith("/") else "/console/")

    entity.tag = tag
    entity.tag_reason = reason if tag else ""
    entity.tagged_at = timezone.now() if tag else None
    entity.tagged_by = str(request.user) if (tag and request.user.is_authenticated) else ""
    entity.save(update_fields=["tag", "tag_reason", "tagged_at", "tagged_by"])

    if next_url and next_url.startswith("/"):
        return redirect(next_url)
    return redirect("/console/")


@login_required(login_url="/admin/login/")
@require_POST
def submission_run_pipeline(request, submission_id):
    """
    POST: run the SDAT analyzer + enrichment + rules pipeline.
    Works for queued, failed, and stuck-"running" submissions (re-runs from scratch).
    process_submission resets status to running at the start, so re-running a
    stuck one just overwrites its state and tries again.
    """
    from apps.api.services import process_submission
    org = _default_organization()
    submission = get_object_or_404(Submission, id=submission_id, organization=org)
    try:
        process_submission(submission)
    except Exception:
        logger.exception("manual pipeline run failed for submission %s", submission.id)
    return redirect("console:submission-detail", submission_id=submission.id)


@login_required(login_url="/admin/login/")
@require_POST
def submission_verdict_override(request, submission_id):
    """
    POST-only: record a human override on the verdict. Customer-facing workflow
    for T&S analysts to confirm the system's decision or flip it with a reason.
    """
    from apps.submissions.models import Verdict
    org = _default_organization()
    submission = get_object_or_404(Submission, id=submission_id, organization=org)
    if not hasattr(submission, "verdict"):
        return redirect("console:submission-detail", submission_id=submission.id)

    decision = (request.POST.get("decision") or "").strip()
    reason = (request.POST.get("reason") or "").strip()

    verdict = submission.verdict

    from apps.submissions.models import Verdict
    who = str(request.user) if request.user.is_authenticated else ""
    now = timezone.now()

    from apps.feedback.models import Feedback, TrainingLabel
    from apps.feedback.services import record_override_feedback, record_training_label

    if decision == "clear":
        verdict.review_status = ""
        verdict.human_override_decision = ""
        verdict.human_override_reason = ""
        verdict.human_override_by = ""
        verdict.human_override_at = None
        verdict.save()
        return redirect("console:submission-detail", submission_id=submission.id)

    elif decision == "unknown":
        verdict.review_status = Verdict.REVIEW_UNKNOWN
        verdict.human_override_decision = ""
        verdict.human_override_reason = reason
        verdict.human_override_by = who
        verdict.human_override_at = now
        verdict.save()
        # Training: record but mark unknown so offline trainer can skip it.
        record_training_label(
            submission=submission,
            action=TrainingLabel.ACTION_OVERRIDE_UNKNOWN,
            label=TrainingLabel.LABEL_UNKNOWN,
            actor=who, source_ui="submission_detail", reason=reason,
        )
        return redirect("console:submission-detail", submission_id=submission.id)

    elif decision in (Verdict.DECISION_APPROVE, Verdict.DECISION_DENY, Verdict.DECISION_REVIEW):
        system_decision = verdict.decision
        if decision == system_decision:
            verdict.review_status = Verdict.REVIEW_CONFIRMED
            verdict.human_override_decision = ""
            reported_as = Feedback.REPORT_CONFIRMED
            training_action = TrainingLabel.ACTION_OVERRIDE_CONFIRM
        else:
            verdict.review_status = Verdict.REVIEW_CORRECTED
            verdict.human_override_decision = decision
            # SYSTEM approved but investigator says deny → false_negative
            # SYSTEM denied but investigator says approve → false_positive
            if system_decision == Verdict.DECISION_APPROVE and decision == Verdict.DECISION_DENY:
                reported_as = Feedback.REPORT_FALSE_NEGATIVE
            elif system_decision == Verdict.DECISION_DENY and decision == Verdict.DECISION_APPROVE:
                reported_as = Feedback.REPORT_FALSE_POSITIVE
            else:
                # Corrected to REVIEW, or REVIEW → approve/deny — treat as confirmed for
                # reputation purposes (the system wasn't obviously wrong or right).
                reported_as = Feedback.REPORT_CONFIRMED
            training_action = TrainingLabel.ACTION_OVERRIDE_CORRECT
        verdict.human_override_reason = reason
        verdict.human_override_by = who
        verdict.human_override_at = now
        verdict.save()

        # ── FEEDBACK LOOP: fingerprint reputation bump + ML training label ──
        record_override_feedback(
            submission,
            reported_as=reported_as,
            training_action=training_action,
            training_label={
                Verdict.DECISION_APPROVE: TrainingLabel.LABEL_APPROVE,
                Verdict.DECISION_DENY:    TrainingLabel.LABEL_DENY,
                Verdict.DECISION_REVIEW:  TrainingLabel.LABEL_REVIEW,
            }[decision],
            actor=who, source_ui="submission_detail", reason=reason,
        )

        # ── On CORRECTION-to-deny: also tag user-specific entities bad so the actor
        # can't reuse them. Mirrors the threat-flag logic; skips VPN/proxy/Tor IPs.
        if training_action == TrainingLabel.ACTION_OVERRIDE_CORRECT and decision == Verdict.DECISION_DENY:
            tag_reason = f"Corrected to DENY by {who}: {reason}".strip()[:500]
            updates = {"tag": "bad", "tag_reason": tag_reason, "tagged_at": now, "tagged_by": who}
            if submission.contact_email_id:
                ContactEmail.objects.filter(pk=submission.contact_email_id).update(**updates)
            if submission.contact_name_id:
                ContactName.objects.filter(pk=submission.contact_name_id).update(**updates)
            if submission.contact_phone_id:
                ContactPhone.objects.filter(pk=submission.contact_phone_id).update(**updates)
            if submission.submitter_ip_id:
                sip = submission.submitter_ip
                if not (sip.is_vpn or sip.is_proxy or sip.is_tor):
                    SubmitterIP.objects.filter(pk=sip.pk).update(**updates)
                    IPAddress.objects.filter(address=sip.address).update(**updates)

        # ── On CORRECTION-to-approve: tag the user-specific entities good
        # (only if the IP isn't shared) so the system stops penalizing them.
        if training_action == TrainingLabel.ACTION_OVERRIDE_CORRECT and decision == Verdict.DECISION_APPROVE:
            tag_reason = f"Corrected to APPROVE by {who}: {reason}".strip()[:500]
            updates = {"tag": "good", "tag_reason": tag_reason, "tagged_at": now, "tagged_by": who}
            if submission.contact_email_id:
                ContactEmail.objects.filter(pk=submission.contact_email_id).update(**updates)
            if submission.contact_name_id:
                ContactName.objects.filter(pk=submission.contact_name_id).update(**updates)
            if submission.contact_phone_id:
                ContactPhone.objects.filter(pk=submission.contact_phone_id).update(**updates)
            if submission.submitter_ip_id:
                sip = submission.submitter_ip
                if not (sip.is_vpn or sip.is_proxy or sip.is_tor):
                    SubmitterIP.objects.filter(pk=sip.pk).update(**updates)
                    IPAddress.objects.filter(address=sip.address).update(**updates)

        return redirect("console:submission-detail", submission_id=submission.id)

    else:
        return redirect("console:submission-detail", submission_id=submission.id)


# ----------------------------------------------------------------------
# Global search — one box, routes to the best match or a grouped results page.
# Recognizes: IPv4 addresses, fingerprint hashes (40+ hex chars), emails, and
# plain text (domain/name/ref substring search across submissions + entities).
# ----------------------------------------------------------------------


_IPV4_RE = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_RE = _re.compile(r"^[a-f0-9]{32,64}$", _re.IGNORECASE)
_EMAIL_RE = _re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@login_required(login_url="/admin/login/")
@require_POST
def threat_intel_add(request):
    """
    Create or update a ThreatIntelDomain. Called from:
      * the /console/threat-intel/ page (explicit form — just adds the domain)
      * the submission-detail "flag as known threat" button (also bulk-tags the
        USER-SPECIFIC attributes on that submission as "bad" — email, name, phone,
        and submitter_ip if not VPN/proxy/Tor. Skips shared infrastructure like
        NS / MX / registrar / resolving IPs / ASN so the tag doesn't propagate
        wrongly to unrelated legit submissions).
    POST: domain, category, confidence, subcategory, brand_target, notes, next,
          submission_id (optional — propagate to linked user-specific entities)
    """
    from apps.iocs.models import ThreatIntelDomain
    import datetime as _dt

    domain = (request.POST.get("domain") or "").strip().lower().rstrip(".")
    category = (request.POST.get("category") or "").strip()
    confidence = (request.POST.get("confidence") or "high").strip()
    subcategory = (request.POST.get("subcategory") or "").strip()
    brand = (request.POST.get("brand_target") or "").strip()
    notes = (request.POST.get("notes") or "").strip()
    next_url = (request.POST.get("next") or "").strip()
    submission_id = (request.POST.get("submission_id") or "").strip()

    valid_cat = {c for c, _ in ThreatIntelDomain.CATEGORY_CHOICES}
    valid_conf = {c for c, _ in ThreatIntelDomain.CONFIDENCE_CHOICES}
    if not domain or category not in valid_cat or confidence not in valid_conf:
        messages.error(request, "domain + valid category + valid confidence are required.")
        return redirect(next_url if next_url.startswith("/") else "console:threat-intel")

    who = str(request.user) if request.user.is_authenticated else "community"
    obj, created = ThreatIntelDomain.objects.update_or_create(
        domain=domain,
        defaults={
            "category": category,
            "confidence": confidence,
            "subcategory": subcategory or "community_reported",
            "brand_target": brand,
            "notes": notes or f"Reported by {who}",
            "source": f"console:{who}",
            "reported_date": _dt.date.today(),
        },
    )
    action = "added" if created else "updated"
    summary_parts = [f"Threat indicator {action}: {domain} ({category}/{confidence}) — future submissions score +{obj.score_weight}."]

    # ML training: record the flag event so the classifier learns which domains get
    # investigator-flagged.
    from apps.feedback.models import TrainingLabel as _TL
    from apps.feedback.services import record_training_label as _rtl

    # Propagate to user-specific attributes if a submission was the source.
    # Deliberately SKIP: nameservers, MX hosts, registrar, resolving IPs, ASN —
    # those are shared infrastructure (Cloudflare NS, Google MX, Namecheap registrar
    # all live on thousands of legit domains) and tagging them bad would burn good traffic.
    if submission_id:
        try:
            sub = Submission.objects.select_related(
                "contact_email", "contact_name", "contact_phone", "submitter_ip",
            ).get(id=submission_id)
        except Submission.DoesNotExist:
            sub = None
        if sub is not None:
            now = timezone.now()
            reason = f"Domain {domain} flagged as known threat ({category}/{confidence}) — sibling attributes tagged bad so the actor can't reuse them."
            updates = {"tag": "bad", "tag_reason": reason, "tagged_at": now, "tagged_by": who}
            n = {"email": 0, "name": 0, "phone": 0, "ip": 0, "ip_skipped_shared": 0}

            if sub.contact_email_id:
                ContactEmail.objects.filter(pk=sub.contact_email_id).update(**updates)
                n["email"] = 1
            if sub.contact_name_id:
                ContactName.objects.filter(pk=sub.contact_name_id).update(**updates)
                n["name"] = 1
            if sub.contact_phone_id:
                ContactPhone.objects.filter(pk=sub.contact_phone_id).update(**updates)
                n["phone"] = 1
            if sub.submitter_ip_id:
                sip = sub.submitter_ip
                if sip.is_vpn or sip.is_proxy or sip.is_tor:
                    n["ip_skipped_shared"] = 1
                else:
                    SubmitterIP.objects.filter(pk=sip.pk).update(**updates)
                    IPAddress.objects.filter(address=sip.address).update(**updates)
                    n["ip"] = 1

            # Override the verdict to DENY so this submission itself is marked.
            verdict = getattr(sub, "verdict", None)
            if verdict is not None:
                if verdict.decision == Verdict.DECISION_DENY:
                    verdict.review_status = Verdict.REVIEW_CONFIRMED
                    verdict.human_override_decision = ""
                else:
                    verdict.review_status = Verdict.REVIEW_CORRECTED
                    verdict.human_override_decision = Verdict.DECISION_DENY
                verdict.human_override_reason = reason
                verdict.human_override_by = who
                verdict.human_override_at = now
                verdict.save()

            tagged = n["email"] + n["name"] + n["phone"] + n["ip"]
            summary_parts.append(
                f"Tagged {tagged} user-specific attribute(s) bad "
                f"(email:{n['email']}, name:{n['name']}, phone:{n['phone']}, IP:{n['ip']})."
            )
            if n["ip_skipped_shared"]:
                summary_parts.append("Submitter IP skipped — VPN/proxy/Tor (shared).")
            summary_parts.append(
                "Shared infrastructure (nameservers, MX hosts, registrar, resolving IPs, ASN) "
                "was NOT tagged — they're used by many legit domains."
            )

    # ML: one training row for the flag event (+ one per impacted submission if from detail).
    sub_for_label = None
    if submission_id:
        try:
            sub_for_label = Submission.objects.get(id=submission_id)
        except Submission.DoesNotExist:
            sub_for_label = None
    _rtl(
        submission=sub_for_label,
        action=_TL.ACTION_THREAT_FLAG,
        label=_TL.LABEL_BAD,
        actor=who, source_ui="threat_intel_add",
        reason=f"Flagged {domain} as {category}/{confidence}",
        entity_key=f"domain:{domain}",
        extra_features={"domain": domain, "category": category, "confidence": confidence},
    )

    messages.success(request, " ".join(summary_parts))

    if next_url and next_url.startswith("/"):
        return redirect(next_url)
    return redirect("console:threat-intel")


DEFAULT_SCORING_BANDS = [
    {"label": "Very High Risk", "score_start": 90, "score_end": 100, "color": "#dc2626", "active": True, "decision": "deny"},
    {"label": "High Risk",      "score_start": 70, "score_end": 89,  "color": "#ea580c", "active": True, "decision": "deny"},
    {"label": "Medium Risk",    "score_start": 30, "score_end": 69,  "color": "#f59e0b", "active": True, "decision": "review"},
    {"label": "Low Risk",       "score_start": 10, "score_end": 29,  "color": "#22c55e", "active": True, "decision": "approve"},
    {"label": "No Risk",        "score_start": 0,  "score_end": 9,   "color": "#16a34a", "active": True, "decision": "approve"},
]


@login_required(login_url="/admin/login/")
def scoring_bands(request):
    """
    Edit the active risk profile's custom scoring bands. Investigators define
    up to ~8 bands labeled with a range [score_start, score_end] and a color;
    the pipeline uses them to pick a verdict decision + label for each score.
    """
    from apps.risk_profiles.models import RiskProfile
    org = _default_organization()
    if org is None:
        return render(request, "console/scoring_bands.html", {"org": None})

    # Get or create a default profile
    profile = RiskProfile.objects.filter(organization=org, is_active=True, is_default=True).first()
    if profile is None:
        profile = RiskProfile.objects.create(
            organization=org, name="Default", is_default=True, is_active=True,
            scoring_bands=list(DEFAULT_SCORING_BANDS),
        )

    if request.method == "POST":
        import json as _json
        try:
            bands_raw = request.POST.get("bands_json", "[]")
            bands = _json.loads(bands_raw)
        except Exception:
            messages.error(request, "Invalid bands JSON — nothing saved.")
            return redirect("console:scoring-bands")

        # Validate + sanitize
        cleaned: list[dict] = []
        for b in bands:
            if not isinstance(b, dict):
                continue
            label = (b.get("label") or "").strip()[:30]
            try:
                start = int(b.get("score_start"))
                end = int(b.get("score_end"))
            except (TypeError, ValueError):
                continue
            if not label:
                continue
            if start > end:
                start, end = end, start
            decision = (b.get("decision") or "review").strip()
            if decision not in ("approve", "review", "deny"):
                decision = "review"
            cleaned.append({
                "label": label,
                "score_start": max(0, min(start, 100)),
                "score_end":   max(0, min(end, 100)),
                "color": (b.get("color") or "#64748b").strip()[:9],
                "active": bool(b.get("active", True)),
                "decision": decision,
            })
        if not cleaned:
            messages.error(request, "At least one band is required.")
            return redirect("console:scoring-bands")

        profile.scoring_bands = cleaned
        profile.save(update_fields=["scoring_bands", "updated_at"])
        messages.success(request, f"Saved {len(cleaned)} scoring band{'s' if len(cleaned) != 1 else ''}.")
        return redirect("console:scoring-bands")

    bands = profile.scoring_bands or list(DEFAULT_SCORING_BANDS)
    return render(request, "console/scoring_bands.html", {
        "org": org,
        "profile": profile,
        "bands": bands,
        "default_bands": DEFAULT_SCORING_BANDS,
    })


@login_required(login_url="/admin/login/")
def ml_status(request):
    """Training readiness + current model metadata + per-label counts."""
    from apps.feedback.ml import readiness_report
    return render(request, "console/ml_status.html", {
        "org": _default_organization(),
        "report": readiness_report(),
    })


@login_required(login_url="/admin/login/")
@require_POST
def threat_intel_refresh_feed(request, feed_id: int):
    """Manually refresh one feed (POST). Redirects back to the threat-intel page."""
    from apps.iocs.models import ThreatIntelFeed
    from apps.iocs.fetchers import fetch_feed
    feed = get_object_or_404(ThreatIntelFeed, pk=feed_id)
    res = fetch_feed(feed)
    if res.get("status") == "ok":
        messages.success(
            request,
            f"Refreshed '{feed.name}': created {res['created']}, updated {res['updated']}, "
            f"skipped {res['skipped']} in {res['duration_seconds']}s."
        )
    else:
        messages.error(request, f"Refresh failed for '{feed.name}': {res.get('reason', 'unknown')}")
    return redirect("/console/threat-intel/?tab=feeds")


@login_required(login_url="/admin/login/")
@require_POST
def threat_intel_refresh_all(request):
    """Refresh every due feed."""
    from apps.iocs.fetchers import refresh_due_feeds
    force = bool(request.POST.get("force"))
    results = refresh_due_feeds(force=force)
    if not results:
        messages.info(request, "No feeds were due for refresh. Use Force to pull them all.")
    else:
        ok = sum(1 for r in results if r.get("status") == "ok")
        failed = len(results) - ok
        messages.success(
            request,
            f"Refreshed {ok}/{len(results)} feeds" + (f" — {failed} failed" if failed else "") + "."
        )
    return redirect("/console/threat-intel/?tab=feeds")


@login_required(login_url="/admin/login/")
def threat_intel_browse(request):
    """
    Browse ALL known-bad attributes across the tool:
      * Domains from the Cowork rollup + community flags (ThreatIntelDomain)
      * IPs, emails, phones, names with tag='bad' (investigator-tagged entities)
      * Fingerprint clusters marked bad (cluster_verdict='bad')
      * External feeds (ThreatIntelFeed) with status + last-pulled metadata
    """
    from apps.iocs.models import ThreatIntelDomain, ThreatIntelFeed
    from apps.fingerprints.models import Fingerprint

    cat = (request.GET.get("category") or "").strip()
    conf = (request.GET.get("confidence") or "").strip()
    q = (request.GET.get("q") or "").strip()

    # --- Domains (threat-intel rollup) ---
    qs = ThreatIntelDomain.objects.all()
    if cat:
        qs = qs.filter(category=cat)
    if conf:
        qs = qs.filter(confidence=conf)
    if q:
        qs = qs.filter(
            Q(domain__icontains=q) | Q(subcategory__icontains=q)
            | Q(brand_target__icontains=q) | Q(source__icontains=q) | Q(notes__icontains=q)
        )
    qs = qs.order_by("category", "-confidence", "domain")

    category_counts = dict(
        ThreatIntelDomain.objects.values_list("category")
        .annotate(n=Count("id")).order_by("category")
    )
    confidence_counts = dict(
        ThreatIntelDomain.objects.values_list("confidence")
        .annotate(n=Count("id")).order_by("confidence")
    )
    total_domains = ThreatIntelDomain.objects.count()

    # --- Known-bad IPs (submitter + resolving, deduped by address) ---
    bad_sips = SubmitterIP.objects.filter(tag="bad")
    bad_ipas = IPAddress.objects.filter(tag="bad")
    if q:
        bad_sips = bad_sips.filter(Q(address__icontains=q) | Q(tag_reason__icontains=q))
        bad_ipas = bad_ipas.filter(Q(address__icontains=q) | Q(tag_reason__icontains=q))
    addrs_seen: set = set()
    bad_ips = []
    for ip in list(bad_sips.order_by("-tagged_at")[:200]) + list(bad_ipas.order_by("-tagged_at")[:200]):
        if ip.address in addrs_seen:
            continue
        addrs_seen.add(ip.address)
        bad_ips.append(ip)

    # --- Known-bad emails / names / phones ---
    bad_emails_qs = ContactEmail.objects.filter(tag="bad")
    bad_names_qs = ContactName.objects.filter(tag="bad")
    bad_phones_qs = ContactPhone.objects.filter(tag="bad")
    if q:
        bad_emails_qs = bad_emails_qs.filter(Q(normalized__icontains=q) | Q(tag_reason__icontains=q))
        bad_names_qs = bad_names_qs.filter(Q(normalized__icontains=q) | Q(tag_reason__icontains=q))
        bad_phones_qs = bad_phones_qs.filter(Q(e164__icontains=q) | Q(tag_reason__icontains=q))
    bad_emails = list(bad_emails_qs.order_by("-tagged_at")[:200])
    bad_names = list(bad_names_qs.order_by("-tagged_at")[:200])
    bad_phones = list(bad_phones_qs.order_by("-tagged_at")[:200])

    # --- Known-bad fingerprint clusters ---
    bad_clusters_qs = (
        Fingerprint.objects
        .filter(reputation__cluster_verdict="bad")
        .select_related("reputation")
    )
    if q:
        bad_clusters_qs = bad_clusters_qs.filter(
            Q(fingerprint_hash__icontains=q) | Q(reputation__cluster_verdict_reason__icontains=q)
        )
    bad_clusters = list(bad_clusters_qs.order_by("-reputation__cluster_verdict_at")[:100])

    total_all = (
        total_domains + len(bad_ips) + len(bad_emails) + len(bad_names)
        + len(bad_phones) + len(bad_clusters)
    )

    feeds = list(ThreatIntelFeed.objects.order_by("-enabled", "name"))

    return render(request, "console/threat_intel.html", {
        "rows": list(qs[:500]),
        "total": total_domains,
        "total_all": total_all,
        "shown": min(len(qs), 500),
        "category_counts": category_counts,
        "confidence_counts": confidence_counts,
        "cat": cat, "conf": conf, "q": q,
        "bad_ips": bad_ips,
        "bad_emails": bad_emails,
        "bad_names": bad_names,
        "bad_phones": bad_phones,
        "bad_clusters": bad_clusters,
        "feeds": feeds,
    })


@login_required(login_url="/admin/login/")
def global_search(request):
    """One box that routes domain / IP / email / fingerprint / submission ref / external ref."""
    from apps.fingerprints.models import Fingerprint

    q = (request.GET.get("q") or "").strip()
    if not q:
        return render(request, "console/search.html", {"q": "", "results": None})

    # --- exact-match fast paths: redirect straight to the relevant detail page ---
    if _IPV4_RE.match(q):
        if IPAddress.objects.filter(address=q).exists() or SubmitterIP.objects.filter(address=q).exists():
            return redirect("console:ip-detail", address=q)
    if _HASH_RE.match(q) and Fingerprint.objects.filter(fingerprint_hash=q).exists():
        return redirect("console:fingerprint-detail", fingerprint_hash=q)
    if _EMAIL_RE.match(q):
        e = ContactEmail.objects.filter(normalized=q.lower()).first()
        if e:
            return redirect("console:entity-detail", entity_type="email", entity_id=e.id)

    # --- grouped substring results across everything relevant ---
    org = _default_organization()

    submissions = list(
        Submission.objects.filter(organization=org)
        .filter(
            Q(domain__icontains=q)
            | Q(contact_email_raw__icontains=q)
            | Q(contact_name_raw__icontains=q)
            | Q(contact_phone_raw__icontains=q)
            | Q(submitter_ip_raw__icontains=q)
            | Q(external_ref__icontains=q)
            | Q(device_fingerprint_raw__icontains=q)
        )
        .select_related("verdict")
        .order_by("-created_at")[:50]
    )
    _annotate_summary_chips(submissions)

    emails = list(
        ContactEmail.objects
        .filter(Q(normalized__icontains=q) | Q(domain__icontains=q))
        .order_by("normalized")[:30]
    )
    names = list(
        ContactName.objects.filter(normalized__icontains=q).order_by("normalized")[:30]
    )
    phones = list(
        ContactPhone.objects.filter(e164__icontains=q).order_by("e164")[:30]
    )
    ips = list(
        IPAddress.objects.filter(address__icontains=q).order_by("address")[:30]
    )
    submitter_ips = list(
        SubmitterIP.objects.filter(address__icontains=q).order_by("address")[:30]
    )
    # Merge resolving + submitter IPs by address (same physical IP can live in both tables)
    ip_addrs_seen: set = set()
    ip_hits = []
    for ip in ips + submitter_ips:
        if ip.address in ip_addrs_seen:
            continue
        ip_addrs_seen.add(ip.address)
        ip_hits.append(ip)
    nameservers = list(Nameserver.objects.filter(hostname__icontains=q).order_by("hostname")[:30])
    mx_hosts = list(MXHost.objects.filter(hostname__icontains=q).order_by("hostname")[:30])
    registrars = list(Registrar.objects.filter(name__icontains=q).order_by("name")[:20])

    fingerprints = []
    if _HASH_RE.match(q) or len(q) >= 6:
        fingerprints = list(
            Fingerprint.objects.filter(fingerprint_hash__icontains=q.lower())
            .select_related("reputation")
            .order_by("-last_seen")[:20]
        )

    total = (len(submissions) + len(emails) + len(names) + len(phones)
             + len(ip_hits) + len(nameservers) + len(mx_hosts) + len(registrars)
             + len(fingerprints))

    return render(request, "console/search.html", {
        "q": q,
        "results": {
            "submissions": submissions,
            "emails": emails,
            "names": names,
            "phones": phones,
            "ips": ip_hits,
            "nameservers": nameservers,
            "mx_hosts": mx_hosts,
            "registrars": registrars,
            "fingerprints": fingerprints,
        },
        "total": total,
    })


# ----------------------------------------------------------------------
# Bulk actions on the submissions list — select N rows, apply one action.
# ----------------------------------------------------------------------


@login_required(login_url="/admin/login/")
@require_POST
def submissions_bulk(request):
    """
    POST: action + ids (list). Actions:
      * flag_threat    — add domain to threat intel + tag user-specific entities bad
      * confirm        — mark verdict.review_status = confirmed
      * correct_deny   — override verdict to deny + review_status = corrected
      * correct_approve— override to approve + review_status = corrected
      * mark_unknown   — review_status = unknown
    """
    from apps.iocs.models import ThreatIntelDomain
    import datetime as _dt

    action = (request.POST.get("action") or "").strip()
    ids = request.POST.getlist("ids")
    next_url = request.POST.get("next") or reverse("console:submissions-list")
    if not ids or not action:
        messages.error(request, "Select at least one submission and an action.")
        return redirect(next_url if next_url.startswith("/") else "console:submissions-list")

    org = _default_organization()
    subs = list(
        Submission.objects.filter(organization=org, id__in=ids)
        .select_related("verdict", "contact_email", "contact_name", "contact_phone", "submitter_ip")
    )
    who = str(request.user) if request.user.is_authenticated else ""
    now = timezone.now()

    touched = 0
    extra_info = []

    if action == "flag_threat":
        flagged_domains = set()
        for s in subs:
            if not s.domain:
                continue
            flagged_domains.add(s.domain)
            # Upsert indicator
            ThreatIntelDomain.objects.update_or_create(
                domain=s.domain.lower().rstrip("."),
                defaults={
                    "category": "scam",
                    "confidence": "high",
                    "subcategory": "community_reported",
                    "brand_target": "",
                    "notes": f"Bulk-flagged by {who} from submissions list",
                    "source": f"console:bulk:{who}",
                    "reported_date": _dt.date.today(),
                },
            )
            # Tag user-specific attributes bad (skip shared infra)
            updates = {"tag": "bad", "tag_reason": f"Domain bulk-flagged as known threat", "tagged_at": now, "tagged_by": who}
            if s.contact_email_id:
                ContactEmail.objects.filter(pk=s.contact_email_id).update(**updates)
            if s.contact_name_id:
                ContactName.objects.filter(pk=s.contact_name_id).update(**updates)
            if s.contact_phone_id:
                ContactPhone.objects.filter(pk=s.contact_phone_id).update(**updates)
            if s.submitter_ip_id:
                sip = s.submitter_ip
                if not (sip.is_vpn or sip.is_proxy or sip.is_tor):
                    SubmitterIP.objects.filter(pk=sip.pk).update(**updates)
                    IPAddress.objects.filter(address=sip.address).update(**updates)
            # Override verdict
            if s.verdict:
                s.verdict.review_status = (
                    Verdict.REVIEW_CONFIRMED if s.verdict.decision == Verdict.DECISION_DENY
                    else Verdict.REVIEW_CORRECTED
                )
                s.verdict.human_override_decision = (
                    Verdict.DECISION_DENY if s.verdict.decision != Verdict.DECISION_DENY else ""
                )
                s.verdict.human_override_reason = "Bulk flag: known threat"
                s.verdict.human_override_by = who
                s.verdict.human_override_at = now
                s.verdict.save()
            touched += 1
        extra_info.append(f"{len(flagged_domains)} unique domain(s) added to threat intel.")

    elif action in ("confirm", "correct_deny", "correct_approve", "mark_unknown"):
        for s in subs:
            if not s.verdict:
                continue
            if action == "confirm":
                s.verdict.review_status = Verdict.REVIEW_CONFIRMED
                s.verdict.human_override_decision = ""
            elif action == "correct_deny":
                s.verdict.review_status = Verdict.REVIEW_CORRECTED
                s.verdict.human_override_decision = Verdict.DECISION_DENY
            elif action == "correct_approve":
                s.verdict.review_status = Verdict.REVIEW_CORRECTED
                s.verdict.human_override_decision = Verdict.DECISION_APPROVE
            elif action == "mark_unknown":
                s.verdict.review_status = Verdict.REVIEW_UNKNOWN
                s.verdict.human_override_decision = ""
            s.verdict.human_override_reason = f"Bulk {action} by {who}"
            s.verdict.human_override_by = who
            s.verdict.human_override_at = now
            s.verdict.save()
            touched += 1

    else:
        messages.error(request, f"Unknown bulk action: {action}")
        return redirect(next_url if next_url.startswith("/") else "console:submissions-list")

    # ML training: one label per submission in the bulk action.
    from apps.feedback.models import TrainingLabel as _TL
    from apps.feedback.services import record_training_label as _rtl
    _bulk_action_map = {
        "flag_threat":     (_TL.ACTION_BULK_FLAG,    _TL.LABEL_BAD),
        "correct_deny":    (_TL.ACTION_BULK_CORRECT, _TL.LABEL_DENY),
        "correct_approve": (_TL.ACTION_BULK_CORRECT, _TL.LABEL_APPROVE),
        "confirm":         (_TL.ACTION_BULK_CONFIRM, _TL.LABEL_DENY),  # placeholder — replaced below per-sub
        "mark_unknown":    (_TL.ACTION_BULK_CONFIRM, _TL.LABEL_UNKNOWN),
    }
    _act, _lbl = _bulk_action_map.get(action, (_TL.ACTION_BULK_CONFIRM, _TL.LABEL_UNKNOWN))
    for s in subs:
        # For "confirm", the label is the system's decision (investigator agrees).
        row_label = _lbl
        if action == "confirm" and s.verdict:
            row_label = {
                Verdict.DECISION_APPROVE: _TL.LABEL_APPROVE,
                Verdict.DECISION_DENY:    _TL.LABEL_DENY,
                Verdict.DECISION_REVIEW:  _TL.LABEL_REVIEW,
            }.get(s.verdict.decision, _TL.LABEL_UNKNOWN)
        _rtl(
            submission=s, action=_act, label=row_label,
            actor=who, source_ui="list_bulk", reason=f"bulk {action}",
        )

    messages.success(request, f"Bulk {action} applied to {touched} submission(s). " + " ".join(extra_info))
    return redirect(next_url if next_url.startswith("/") else "console:submissions-list")


# ----------------------------------------------------------------------
# Device fingerprint drill-down — list submissions sharing the raw device_fingerprint
# ----------------------------------------------------------------------


@login_required(login_url="/admin/login/")
def device_fingerprint_detail(request, device_hash):
    """All submissions sharing one device_fingerprint_raw string (bot / farm detection)."""
    from urllib.parse import unquote
    raw = unquote(device_hash)
    org = _default_organization()
    subs = (
        Submission.objects
        .filter(organization=org, device_fingerprint_raw=raw)
        .select_related("verdict", "submitter_ip", "contact_email")
        .order_by("-created_at")[:500]
    )
    _annotate_summary_chips(list(subs))
    # Aggregated entity reuse stats for this device
    emails = sorted({s.contact_email.normalized for s in subs if s.contact_email_id})
    ips = sorted({s.submitter_ip.address for s in subs if s.submitter_ip_id})
    return render(request, "console/device_fingerprint_detail.html", {
        "raw": raw,
        "subs": subs,
        "emails": emails,
        "ips": ips,
        "total": len(subs),
    })


# ----------------------------------------------------------------------
# Fingerprint cluster feedback — bulk mark an entire cluster good or bad.
# "Good" bumps reputation + tags attributes good (except shared IPs).
# "Bad"  bumps reputation + tags attributes bad so they start failing scoring.
# ----------------------------------------------------------------------


@login_required(login_url="/admin/login/")
@require_POST
def fingerprint_cluster_mark(request, fingerprint_hash):
    """
    POST fingerprint_hash + verdict=good|bad. Propagates that judgement to every
    submission in the cluster:
      * bumps FingerprintReputation (approved or flagged + feedback counter)
      * tags every linked contact_email / contact_name / contact_phone / submitter_ip
        (skipping VPN/proxy/Tor IPs — those are shared and shouldn't take reputation).
    """
    from apps.fingerprints.models import Fingerprint, FingerprintReputation
    from apps.fingerprints.services import _recompute_score

    verdict = (request.POST.get("verdict") or "").strip()
    reason = (request.POST.get("reason") or "").strip() or f"Cluster marked {verdict}"
    # Five valid verdicts — ANY of them marks the cluster as REVIEWED so it drops
    # out of the open-clusters queue.
    #   good        — propagate positive reputation + tag entities good
    #   bad         — propagate negative reputation + tag entities bad
    #   not_cluster — investigator dismissal; records the judgement only
    #   same_user   — repeat activity from one person; records judgement only
    #   unknown     — reviewed but investigator can't tell; skip in ML training
    if verdict not in ("good", "bad", "not_cluster", "same_user", "unknown"):
        return redirect("console:fingerprint-detail", fingerprint_hash=fingerprint_hash)

    fp = get_object_or_404(Fingerprint, fingerprint_hash=fingerprint_hash)

    # Submissions in this cluster (primary match only)
    subs = list(
        Submission.objects
        .filter(fingerprint_links__fingerprint=fp, fingerprint_links__is_primary=True)
        .select_related("contact_email", "contact_name", "contact_phone", "submitter_ip")
        .distinct()
    )
    n = len(subs)

    who = str(request.user) if request.user.is_authenticated else ""
    now = timezone.now()

    # Bulk-tag linked attributes — ONLY for good/bad. not_cluster and same_user
    # are judgement-only marks that don't propagate tags.
    emails_tagged = names_tagged = phones_tagged = ips_tagged = 0
    propagate = verdict in ("good", "bad")
    if propagate:
        tag_value = "good" if verdict == "good" else "bad"
        for s in subs:
            updates = {"tag": tag_value, "tag_reason": reason, "tagged_at": now, "tagged_by": who}
            if s.contact_email_id:
                ContactEmail.objects.filter(pk=s.contact_email_id).update(**updates)
                emails_tagged += 1
            if s.contact_name_id:
                ContactName.objects.filter(pk=s.contact_name_id).update(**updates)
                names_tagged += 1
            if s.contact_phone_id:
                ContactPhone.objects.filter(pk=s.contact_phone_id).update(**updates)
                phones_tagged += 1
            if s.submitter_ip_id:
                sip = s.submitter_ip
                if not (sip.is_vpn or sip.is_proxy or sip.is_tor):
                    SubmitterIP.objects.filter(pk=sip.pk).update(**updates)
                    IPAddress.objects.filter(address=sip.address).update(**updates)
                    ips_tagged += 1

    # Bump reputation counters — only good/bad affect reputation; the other two
    # verdicts simply record the investigator's judgement for training.
    rep, _ = FingerprintReputation.objects.get_or_create(fingerprint=fp)
    if verdict == "good":
        rep.approved_count += n
        rep.feedback_confirmed_count += 1
        rep.feedback_false_positive_count += n
    elif verdict == "bad":
        rep.flagged_count += n
        rep.feedback_false_negative_count += n
    # not_cluster / same_user: no reputation change.
    rep.reputation_score = _recompute_score(rep)
    rep.cluster_verdict = verdict
    rep.cluster_verdict_at = now
    rep.cluster_verdict_by = who
    rep.cluster_verdict_reason = reason
    rep.cluster_verdict_size = n
    rep.save()

    logger.info(
        "fingerprint cluster %s marked %s by %s — tagged %d emails, %d names, %d phones, %d IPs",
        fingerprint_hash[:12], verdict, who, emails_tagged, names_tagged, phones_tagged, ips_tagged,
    )

    msg_map = {
        "good":        f"Cluster marked GOOD. Tagged {emails_tagged} email(s), {names_tagged} name(s), {phones_tagged} phone(s), {ips_tagged} IP(s). Reputation is now {rep.reputation_score:+.2f}.",
        "bad":         f"Cluster marked BAD. Tagged {emails_tagged} email(s), {names_tagged} name(s), {phones_tagged} phone(s), {ips_tagged} IP(s). Reputation is now {rep.reputation_score:+.2f}.",
        "not_cluster": f"Dismissed: not a real cluster. Judgement recorded; no entity tags propagated. Cluster is now marked reviewed.",
        "same_user":   f"Marked as same-user repeat activity ({n} submissions). No tags propagated — cluster is now marked reviewed.",
        "unknown":     f"Cluster marked reviewed with UNKNOWN verdict. Excluded from open-clusters list and from ML training.",
    }
    messages.success(request, msg_map[verdict])

    # ML training: one label per submission in the cluster.
    # not_cluster / same_user → labeled UNKNOWN so the trainer skips them.
    from apps.feedback.models import TrainingLabel as _TL
    from apps.feedback.services import record_training_label as _rtl
    label_map = {
        "good": _TL.LABEL_GOOD, "bad": _TL.LABEL_BAD,
        "not_cluster": _TL.LABEL_UNKNOWN, "same_user": _TL.LABEL_UNKNOWN,
        "unknown": _TL.LABEL_UNKNOWN,
    }
    for s in subs:
        _rtl(
            submission=s, action=_TL.ACTION_CLUSTER_MARK,
            label=label_map[verdict],
            actor=who, source_ui="fingerprint_cluster",
            reason=f"Cluster {fingerprint_hash[:12]} marked {verdict}",
            extra_features={"cluster_fingerprint": fingerprint_hash, "cluster_size": n},
        )

    return redirect("console:fingerprint-detail", fingerprint_hash=fingerprint_hash)
