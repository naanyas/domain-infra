"""
Public-facing demo views for the Domain Risk API portfolio site.

These views are anonymous (no @login_required). They run a single domain
through the analyzer and render the result inline, so portfolio visitors
can try the product without an account or API key.

Rate-limited at the view layer via an in-process cache; not a substitute
for the authenticated API which has its own per-org limits.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict
from typing import Any

from django.core.cache import cache
from django.http import HttpResponseBadRequest
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

logger = logging.getLogger(__name__)


DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")

# Rate-limit: 6 scans per IP per hour. Generous for casual exploration, tight
# enough that this doesn't become a free analyzer-as-a-service.
RATE_LIMIT_WINDOW_S = 60 * 60
RATE_LIMIT_PER_WINDOW = 6


def _client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "0.0.0.0")


def _check_rate_limit(ip: str) -> tuple[bool, int]:
    """Return (allowed, remaining)."""
    key = f"public_demo_rl:{ip}"
    history = cache.get(key, [])
    now = time.time()
    history = [t for t in history if now - t < RATE_LIMIT_WINDOW_S]
    if len(history) >= RATE_LIMIT_PER_WINDOW:
        return False, 0
    history.append(now)
    cache.set(key, history, RATE_LIMIT_WINDOW_S)
    return True, RATE_LIMIT_PER_WINDOW - len(history)


def _normalize_domain(raw: str) -> str:
    s = (raw or "").strip().lower()
    # Strip scheme + path so users can paste a URL
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    s = s.lstrip("www.")
    return s


def _run_scan(domain: str) -> dict[str, Any]:
    """Call the analyzer directly. No DB writes — this is a demo path."""
    # Lazy import keeps Django startup fast.
    from analyzer import analyze_domain

    result = analyze_domain(domain, timeout=8.0)
    raw = asdict(result) if hasattr(result, "__dataclass_fields__") else dict(result)
    return raw


def _summarize(raw: dict[str, Any]) -> dict[str, Any]:
    """Project the analyzer output into a small, presentation-friendly dict."""
    score = int(raw.get("risk_score") or 0)
    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "elevated"
    elif score >= 20:
        level = "low"
    else:
        level = "clean"

    # Pull a handful of binary signals that read well in a results UI
    signals: list[dict[str, str]] = []

    def add(label: str, ok: bool, detail: str = ""):
        signals.append(
            {
                "label": label,
                "state": "ok" if ok else "warn",
                "detail": detail,
            }
        )

    add("Domain resolves", bool(raw.get("resolved")))
    add(
        "SPF record present",
        bool(raw.get("spf_exists")),
        raw.get("spf_policy") or "",
    )
    add(
        "DMARC published",
        bool(raw.get("dmarc_exists")),
        raw.get("dmarc_policy") or "",
    )
    add("HTTPS valid", bool(raw.get("https_valid")))
    add(
        "Not on blacklists",
        (raw.get("domain_blacklist_count") or 0) == 0,
    )
    add(
        "No phishing signals",
        not (raw.get("phishing_kit_detected") or raw.get("has_credential_form")),
    )

    summary_text = (raw.get("summary") or "").strip()
    # Split SDAT's pipe-delimited summary into chips
    summary_chips: list[str] = []
    if "|" in summary_text:
        for part in summary_text.split("|")[1:]:
            part = part.strip()
            if part:
                summary_chips.append(part)

    return {
        "domain": raw.get("domain") or "",
        "score": score,
        "level": level,
        "recommendation": str(raw.get("recommendation") or ""),
        "summary": summary_text,
        "summary_chips": summary_chips[:10],
        "signals": signals,
        "ip_address": raw.get("ip_address") or "",
        "ptr_record": raw.get("ptr_record") or "",
        "blacklist_count": int(raw.get("domain_blacklist_count") or 0),
        "vt_malicious": int(raw.get("vt_malicious_count") or 0),
    }


@require_http_methods(["GET", "POST"])
def landing(request):
    context: dict[str, Any] = {
        "result": None,
        "error": None,
        "domain_input": "",
    }

    if request.method == "POST":
        raw_input = request.POST.get("domain", "")
        context["domain_input"] = raw_input
        domain = _normalize_domain(raw_input)

        if not domain:
            context["error"] = "Enter a domain (e.g., example.com)."
        elif not DOMAIN_RE.match(domain):
            context["error"] = f"{domain!r} doesn't look like a valid domain."
        else:
            ip = _client_ip(request)
            allowed, remaining = _check_rate_limit(ip)
            if not allowed:
                context["error"] = (
                    "You've hit the demo rate limit (6 scans per hour). "
                    "Reach out via the contact links on jennawebb.co for full API access."
                )
            else:
                try:
                    raw = _run_scan(domain)
                    context["result"] = _summarize(raw)
                    context["remaining"] = remaining
                except Exception:
                    logger.exception("public demo scan failed for %s", domain)
                    context["error"] = (
                        "The scan failed. Try a different domain or come back in a minute."
                    )

    return render(request, "console/public_landing.html", context)
