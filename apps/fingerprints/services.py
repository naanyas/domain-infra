"""
Fingerprint computation + linkage + reputation updates + similarity search.

Called from the submission pipeline after a Verdict is created. Emits:
 * Infrastructure fingerprint (derived from DomainScan raw_result)
 * Actor fingerprint (derived from contact-side inputs)
 * Nearest-neighbor links via MinHash Jaccard similarity
 * Reputation counter updates on the referenced Fingerprint rows
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Iterable, Sequence

import jellyfish
import numpy as np
import phonenumbers
from datasketch import MinHash
from django.db import transaction
from django.utils import timezone

from apps.fingerprints.models import Fingerprint, FingerprintReputation, SubmissionFingerprint
from apps.submissions.models import DomainScan, Submission, Verdict

logger = logging.getLogger(__name__)

MINHASH_PERMUTATIONS = 128
SIMILARITY_MIN = 0.3
SIMILARITY_TOP_K = 20
SIMILARITY_CANDIDATE_LIMIT = 2000  # how many recent fingerprints to scan for neighbors


# ======================================================================
# Canonical signal extraction
# ======================================================================


def _norm_host(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


_LIST_SEP = re.compile(r"[,;]")


def _split_list(value) -> list[str]:
    """
    Split analyzer list-ish fields. They arrive as:
      * Python list
      * comma-separated string ("a, b, c")
      * semicolon-separated string ("ns1.example.com.;ns2.example.com.")
    """
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if v]
    return [item.strip() for item in _LIST_SEP.split(str(value)) if item.strip()]


def _spf_shape(spf_record: str) -> str:
    """Reduce a full SPF record to its qualifier shape ('-all', '~all', '+all', '?all', '')."""
    if not spf_record:
        return ""
    m = re.search(r"([-+~?])all\b", spf_record.lower())
    return f"{m.group(1)}all" if m else ""


def _infrastructure_signals(raw: dict) -> dict:
    """Extract canonical infrastructure signals from a DomainScan raw_result dict."""
    nameservers = sorted({_norm_host(ns) for ns in _split_list(raw.get("ns_records") or raw.get("nameservers")) if ns})
    mx_hosts = []
    for mx_entry in _split_list(raw.get("mx_records")):
        # "10 mail.example.com" or "mail.example.com" or "0:" (null MX)
        parts = mx_entry.split()
        host = parts[-1] if parts else ""
        host = _norm_host(host.split(":")[-1])  # strip "0:" null-MX style
        if host:
            mx_hosts.append(host)
    mx_hosts = sorted(set(mx_hosts))

    resolving_ips = sorted({ip.strip() for ip in _split_list(raw.get("ip_address")) if ip})

    return {
        "nameservers": nameservers,
        "mx_hosts": mx_hosts,
        "resolving_ips": resolving_ips,
        "registrar": (raw.get("registrar") or "").strip().lower(),
        "asn": str(raw.get("hosting_asn") or "").strip(),
        "spf_shape": _spf_shape(raw.get("spf_record") or ""),
        "dmarc_policy": (raw.get("dmarc_policy") or "").strip().lower(),
        "tls_issuer": (raw.get("tls_issuer") or "").strip().lower() if raw.get("tls_issuer") else "",
    }


def _infrastructure_tokens(signals: dict) -> list[str]:
    """Token set for MinHash — one element per meaningful signal value."""
    tokens: list[str] = []
    for ns in signals["nameservers"]:
        tokens.append(f"ns:{ns}")
    for mx in signals["mx_hosts"]:
        tokens.append(f"mx:{mx}")
    for ip in signals["resolving_ips"]:
        tokens.append(f"ip:{ip}")
        # Also include /24 prefix so actors who rotate within a subnet still match.
        parts = ip.split(".")
        if len(parts) == 4:
            tokens.append(f"ip24:{parts[0]}.{parts[1]}.{parts[2]}")
    if signals["registrar"]:
        tokens.append(f"registrar:{signals['registrar']}")
    if signals["asn"]:
        tokens.append(f"asn:{signals['asn']}")
    if signals["spf_shape"]:
        tokens.append(f"spf:{signals['spf_shape']}")
    if signals["dmarc_policy"]:
        tokens.append(f"dmarc:{signals['dmarc_policy']}")
    if signals["tls_issuer"]:
        tokens.append(f"tls:{signals['tls_issuer']}")
    return tokens


def _actor_signals(submission: Submission) -> dict:
    """
    Phase 2 baseline actor signals — pre-enrichment.
    Phase 2.1 (IP enrichment) will add submitter_ip_asn once available.
    """
    email_domain = ""
    if submission.contact_email_raw:
        parts = submission.contact_email_raw.lower().split("@", 1)
        if len(parts) == 2:
            email_domain = parts[1].strip()

    phone_cc = ""
    if submission.contact_phone_raw:
        try:
            parsed = phonenumbers.parse(submission.contact_phone_raw, None)
            phone_cc = f"+{parsed.country_code}"
        except phonenumbers.NumberParseException:
            phone_cc = ""

    name_phonetic = ""
    if submission.contact_name_raw:
        # Double metaphone on first token (most discriminating against alias rotation).
        first_token = submission.contact_name_raw.strip().split()[0] if submission.contact_name_raw.strip() else ""
        if first_token:
            name_phonetic = jellyfish.metaphone(first_token)

    return {
        "email_domain": email_domain,
        "phone_country_code": phone_cc,
        "name_phonetic": name_phonetic,
        "device_fingerprint": (submission.device_fingerprint_raw or "").strip(),
    }


def _actor_tokens(signals: dict) -> list[str]:
    tokens: list[str] = []
    if signals["email_domain"]:
        tokens.append(f"email_dom:{signals['email_domain']}")
    if signals["phone_country_code"]:
        tokens.append(f"phone_cc:{signals['phone_country_code']}")
    if signals["name_phonetic"]:
        tokens.append(f"phonetic:{signals['name_phonetic']}")
    if signals["device_fingerprint"]:
        tokens.append(f"device:{signals['device_fingerprint']}")
    return tokens


# ======================================================================
# Hashing + MinHash
# ======================================================================


def _canonical_hash(signals: dict) -> str:
    """SHA-256 of JSON-serialized canonical signals with sorted keys."""
    payload = json.dumps(signals, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _compute_minhash(tokens: Iterable[str]) -> list[int]:
    """Return MinHash hashvalues as a list of ints for storage in JSONField."""
    mh = MinHash(num_perm=MINHASH_PERMUTATIONS)
    for tok in tokens:
        mh.update(tok.encode("utf-8"))
    return mh.hashvalues.tolist()


def _minhash_from_vector(vector: Sequence[int]) -> MinHash:
    mh = MinHash(num_perm=MINHASH_PERMUTATIONS)
    mh.hashvalues = np.asarray(vector, dtype=np.uint64)
    return mh


def _jaccard(a: Sequence[int], b: Sequence[int]) -> float:
    """MinHash Jaccard estimate."""
    if not a or not b or len(a) != len(b):
        return 0.0
    return float(_minhash_from_vector(a).jaccard(_minhash_from_vector(b)))


# ======================================================================
# Persistence + reputation
# ======================================================================


@dataclass
class FingerprintResult:
    primary: Fingerprint
    exact_matches: int  # count of prior submissions sharing this exact hash
    similar: list[tuple[Fingerprint, float]]  # (fingerprint, similarity) sorted desc


def _upsert_fingerprint(hash_hex: str, kind: str, signals: dict, feature_vector: list[int]) -> tuple[Fingerprint, bool]:
    """Return (fingerprint, created). Canonical signals are a stable hash input —
    if the hash matches, the signals match, so we don't overwrite them."""
    fp, created = Fingerprint.objects.get_or_create(
        fingerprint_hash=hash_hex,
        defaults={
            "kind": kind,
            "canonical_signals": signals,
            "feature_vector": feature_vector,
        },
    )
    if not created:
        # Touch last_seen by saving with no field changes (auto_now on last_seen).
        fp.save(update_fields=["last_seen"])
    return fp, created


def _ensure_reputation(fingerprint: Fingerprint) -> FingerprintReputation:
    rep, _ = FingerprintReputation.objects.get_or_create(fingerprint=fingerprint)
    return rep


def _find_similar(
    primary: Fingerprint,
    feature_vector: list[int],
    limit: int = SIMILARITY_TOP_K,
    min_similarity: float = SIMILARITY_MIN,
) -> list[tuple[Fingerprint, float]]:
    """
    Naive nearest-neighbor: fetch recent fingerprints of the same kind, score each.
    Replace with datasketch MinHashLSH or pgvector once volume demands it.
    """
    candidates = (
        Fingerprint.objects
        .filter(kind=primary.kind)
        .exclude(pk=primary.pk)
        .exclude(feature_vector__isnull=True)
        .order_by("-last_seen")[:SIMILARITY_CANDIDATE_LIMIT]
    )
    scored: list[tuple[Fingerprint, float]] = []
    for cand in candidates:
        if not cand.feature_vector:
            continue
        sim = _jaccard(feature_vector, cand.feature_vector)
        if sim >= min_similarity:
            scored.append((cand, sim))
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored[:limit]


def _recompute_score(rep: FingerprintReputation) -> float:
    """
    Combined reputation score in [-1, +1] from both verdict counts and feedback.
    Verdict-derived = (approved - flagged - 0.25*review) / verdict_total
    Feedback-derived = (false_positive - false_negative) / feedback_total
      * false_positive ("we denied but it was good") pulls toward +1
      * false_negative ("we approved but it was bad") pulls toward -1
      * confirmed is weight-neutral (but adds confidence via feedback_total)
    Feedback weighted 70% when present (explicit customer correction is stronger
    signal than our own verdicts).
    """
    verdict_total = rep.flagged_count + rep.approved_count + rep.review_count
    feedback_total = (
        rep.feedback_confirmed_count
        + rep.feedback_false_positive_count
        + rep.feedback_false_negative_count
    )

    verdict_score = 0.0
    if verdict_total:
        verdict_score = (
            rep.approved_count - rep.flagged_count - 0.25 * rep.review_count
        ) / verdict_total

    feedback_score = 0.0
    if feedback_total:
        feedback_score = (
            rep.feedback_false_positive_count - rep.feedback_false_negative_count
        ) / feedback_total

    if feedback_total and verdict_total:
        combined = 0.3 * verdict_score + 0.7 * feedback_score
    elif feedback_total:
        combined = feedback_score
    else:
        combined = verdict_score
    return round(max(-1.0, min(1.0, combined)), 4)


def _bump_reputation(fingerprint: Fingerprint, verdict_decision: str) -> None:
    """Increment the decision counter + recompute reputation_score."""
    rep = _ensure_reputation(fingerprint)
    if verdict_decision == Verdict.DECISION_APPROVE:
        rep.approved_count += 1
    elif verdict_decision == Verdict.DECISION_DENY:
        rep.flagged_count += 1
    elif verdict_decision == Verdict.DECISION_REVIEW:
        rep.review_count += 1
    rep.reputation_score = _recompute_score(rep)
    rep.save(
        update_fields=[
            "flagged_count",
            "approved_count",
            "review_count",
            "reputation_score",
            "last_updated_at",
        ]
    )


def apply_feedback(submission: Submission, reported_as: str) -> list[Fingerprint]:
    """
    Update feedback counters on every fingerprint linked to a submission
    (primary + neighbors) and recompute their reputation scores.

    Returns the list of fingerprints that were adjusted.

    Security note: Phase 2 has no anti-abuse. A malicious customer could skew
    shared reputation by spamming feedback. Phase 3 needs: per-org feedback
    rate limits, moderator flags for high-impact corrections, and weighting
    by customer tenure / verdict-agreement history.
    """
    # Only bump on the customer's own submissions — links to fuzzy neighbors
    # shouldn't let feedback cascade across all their neighbors. Bump the
    # primary fingerprint(s) of this submission only.
    from apps.fingerprints.models import SubmissionFingerprint as SF  # local import avoids cycle at module load

    primary_fingerprints = Fingerprint.objects.filter(
        submission_links__submission=submission,
        submission_links__is_primary=True,
    ).distinct()

    adjusted: list[Fingerprint] = []
    for fp in primary_fingerprints:
        rep = _ensure_reputation(fp)
        if reported_as == "false_positive":
            rep.feedback_false_positive_count += 1
        elif reported_as == "false_negative":
            rep.feedback_false_negative_count += 1
        elif reported_as == "confirmed":
            rep.feedback_confirmed_count += 1
        rep.reputation_score = _recompute_score(rep)
        rep.save(
            update_fields=[
                "feedback_false_positive_count",
                "feedback_false_negative_count",
                "feedback_confirmed_count",
                "reputation_score",
                "last_updated_at",
            ]
        )
        adjusted.append(fp)
    return adjusted


# ======================================================================
# Orchestration — called from the submission pipeline
# ======================================================================


def _compute_and_link_one(
    submission: Submission,
    kind: str,
    signals: dict,
    tokens: list[str],
) -> FingerprintResult | None:
    """Shared path: upsert fingerprint, link as primary, link fuzzy neighbors. NO reputation bump."""
    if not tokens:
        return None
    fv = _compute_minhash(tokens)
    hash_hex = _canonical_hash(signals)

    with transaction.atomic():
        fp, _created = _upsert_fingerprint(hash_hex, kind, signals, fv)
        SubmissionFingerprint.objects.get_or_create(
            submission=submission,
            fingerprint=fp,
            kind=kind,
            defaults={"is_primary": True, "similarity": 1.0},
        )

    exact_matches = (
        SubmissionFingerprint.objects
        .filter(fingerprint=fp, kind=kind, is_primary=True)
        .exclude(submission=submission)
        .count()
    )
    similar = _find_similar(fp, fv)
    for neighbor, sim in similar:
        SubmissionFingerprint.objects.get_or_create(
            submission=submission,
            fingerprint=neighbor,
            kind=kind,
            defaults={"is_primary": False, "similarity": sim},
        )

    return FingerprintResult(primary=fp, exact_matches=exact_matches, similar=similar)


def compute_and_link_fingerprints(
    submission: Submission,
    domain_scan: DomainScan | None,
) -> dict:
    """
    Compute infrastructure + actor fingerprints, upsert + link. **No reputation bump.**
    Returns a signals-ready `network` dict for the rules engine to consume. The
    reputation_score here reflects the state BEFORE this submission's verdict is
    applied — `bump_fingerprint_reputation()` is called after the rules engine.
    """
    network: dict = {}

    if domain_scan is not None:
        try:
            signals = _infrastructure_signals(domain_scan.raw_result or {})
            res = _compute_and_link_one(
                submission, Fingerprint.KIND_INFRASTRUCTURE, signals,
                _infrastructure_tokens(signals),
            )
            if res:
                rep = _ensure_reputation(res.primary)
                network["infrastructure"] = {
                    "reputation_score": round(rep.reputation_score, 4),
                    "exact_match_count": res.exact_matches,
                    "flagged_count": rep.flagged_count,
                    "approved_count": rep.approved_count,
                    "review_count": rep.review_count,
                }
        except Exception:
            logger.exception("infrastructure fingerprint failed for submission %s", submission.id)

    try:
        signals = _actor_signals(submission)
        res = _compute_and_link_one(
            submission, Fingerprint.KIND_ACTOR, signals, _actor_tokens(signals),
        )
        if res:
            rep = _ensure_reputation(res.primary)
            network["actor"] = {
                "reputation_score": round(rep.reputation_score, 4),
                "exact_match_count": res.exact_matches,
                "flagged_count": rep.flagged_count,
                "approved_count": rep.approved_count,
                "review_count": rep.review_count,
            }
    except Exception:
        logger.exception("actor fingerprint failed for submission %s", submission.id)

    return network


def bump_fingerprint_reputation(submission: Submission, verdict_decision: str) -> None:
    """
    Apply the final verdict decision to every primary fingerprint linked to
    this submission. Called AFTER the rules engine produces the final decision,
    so the reputation reflects what the system decided (including rule overrides).
    """
    primary = (
        Fingerprint.objects
        .filter(submission_links__submission=submission, submission_links__is_primary=True)
        .distinct()
    )
    for fp in primary:
        try:
            _bump_reputation(fp, verdict_decision)
        except Exception:
            logger.exception("reputation bump failed for fingerprint %s", fp.fingerprint_hash)


# ======================================================================
# Rendering for API response
# ======================================================================


def render_network_matches(submission: Submission) -> dict:
    """
    Build the `network_matches` block for the submission detail API response.
    Re-queried from persisted data so GET /submissions/{id} returns the same
    shape as the initial POST response.
    """
    primary_links = (
        SubmissionFingerprint.objects
        .filter(submission=submission, is_primary=True)
        .select_related("fingerprint")
    )
    result: dict = {}
    for link in primary_links:
        fp = link.fingerprint
        rep = getattr(fp, "reputation", None) or _ensure_reputation(fp)
        exact_matches = (
            SubmissionFingerprint.objects
            .filter(fingerprint=fp, kind=fp.kind, is_primary=True)
            .exclude(submission=submission)
            .count()
        )
        similar_links = (
            SubmissionFingerprint.objects
            .filter(submission=submission, kind=fp.kind, is_primary=False)
            .select_related("fingerprint", "fingerprint__reputation")
            .order_by("-similarity")[:SIMILARITY_TOP_K]
        )
        similar_payload = []
        for sl in similar_links:
            sl_rep = getattr(sl.fingerprint, "reputation", None)
            similar_payload.append({
                "fingerprint_hash": sl.fingerprint.fingerprint_hash,
                "similarity": round(sl.similarity, 4),
                "flagged_count": sl_rep.flagged_count if sl_rep else 0,
                "approved_count": sl_rep.approved_count if sl_rep else 0,
                "reputation_score": round(sl_rep.reputation_score, 4) if sl_rep else 0.0,
            })
        result[fp.kind] = {
            "primary_fingerprint": fp.fingerprint_hash,
            "canonical_signals": fp.canonical_signals,
            "exact_match_count": exact_matches,
            "network_flagged_count": rep.flagged_count,
            "network_approved_count": rep.approved_count,
            "network_review_count": rep.review_count,
            "network_feedback_false_positive_count": rep.feedback_false_positive_count,
            "network_feedback_false_negative_count": rep.feedback_false_negative_count,
            "network_feedback_confirmed_count": rep.feedback_confirmed_count,
            "network_reputation_score": round(rep.reputation_score, 4),
            "similar": similar_payload,
        }
    return result
