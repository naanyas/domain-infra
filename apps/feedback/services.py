"""
Training-label writer + feature-snapshot helper.

Every investigator action (verdict override, entity tag, cluster mark, threat flag,
bulk action) should call `record_training_label` so the ML training corpus captures
both the decision AND the full signal state at label time.
"""
from __future__ import annotations

import logging
from typing import Any

from apps.feedback.models import Feedback, TrainingLabel
from apps.submissions.models import Submission

logger = logging.getLogger(__name__)


def snapshot_features(submission: Submission) -> dict[str, Any]:
    """
    Capture a training-ready feature dict from the current submission state.
    Includes: verdict (score, decision, summary, reasons), raw SDAT scan, entity
    tags + IPQS/enrichment fields, linked fingerprint hashes, and submission inputs.

    Stored as JSON — any consumer can project out the features it needs.
    """
    verdict = getattr(submission, "verdict", None)
    scan = getattr(submission, "domain_scan", None)

    features: dict[str, Any] = {
        "submission_id": str(submission.id),
        "organization_id": submission.organization_id,
        "domain": submission.domain or "",
        "contact_email_raw": submission.contact_email_raw or "",
        "contact_name_raw": submission.contact_name_raw or "",
        "contact_phone_raw": submission.contact_phone_raw or "",
        "submitter_ip_raw": submission.submitter_ip_raw or "",
        "device_fingerprint_raw": submission.device_fingerprint_raw or "",
        "created_at": submission.created_at.isoformat() if submission.created_at else None,
        "status": submission.status,
    }

    if verdict is not None:
        features["verdict"] = {
            "decision": verdict.decision,
            "score": verdict.score,
            "summary": verdict.summary,
            "reasons": verdict.reasons,
            "review_status": verdict.review_status,
            "human_override_decision": verdict.human_override_decision,
            "human_override_reason": verdict.human_override_reason,
        }

    # Full SDAT raw scan — the single biggest feature set for future ML.
    if scan is not None:
        features["domain_scan"] = {
            "raw_result": scan.raw_result or {},
            "summary": scan.summary or "",
        }

    # Entity tags + enrichment. Training wants these as categorical / numeric features.
    def _e(entity, extra_fields=()):
        if entity is None:
            return None
        d = {
            "tag": entity.tag or "",
            "tag_reason": entity.tag_reason or "",
            "net_approved": entity.net_approved_count,
            "net_flagged": entity.net_flagged_count,
        }
        for f in extra_fields:
            d[f] = getattr(entity, f, None)
        return d

    features["contact_email"] = _e(submission.contact_email, (
        "normalized", "domain", "is_disposable", "is_role_based", "is_freemail",
        "mx_reachable", "ipqs_overall_score", "ipqs_deliverability",
        "ipqs_spam_trap_score", "ipqs_honeypot", "ipqs_leaked", "ipqs_recent_abuse",
    ))
    features["contact_name"] = _e(submission.contact_name, ("normalized", "phonetic_hash"))
    features["contact_phone"] = _e(submission.contact_phone, ("e164", "country_code", "line_type", "is_valid"))
    features["submitter_ip"] = _e(submission.submitter_ip, (
        "address", "country", "city", "asn", "is_vpn", "is_proxy", "is_tor",
        "is_datacenter", "fraud_score", "recent_abuse", "bot_status",
    ))

    # Fingerprint primary hashes + reputations
    try:
        from apps.fingerprints.models import SubmissionFingerprint
        fps = (
            SubmissionFingerprint.objects
            .filter(submission=submission, is_primary=True)
            .select_related("fingerprint", "fingerprint__reputation")
        )
        features["fingerprints"] = [
            {
                "kind": sf.kind,
                "hash": sf.fingerprint.fingerprint_hash,
                "reputation": (
                    sf.fingerprint.reputation.reputation_score
                    if hasattr(sf.fingerprint, "reputation") else None
                ),
                "flagged": (
                    sf.fingerprint.reputation.flagged_count
                    if hasattr(sf.fingerprint, "reputation") else 0
                ),
                "approved": (
                    sf.fingerprint.reputation.approved_count
                    if hasattr(sf.fingerprint, "reputation") else 0
                ),
            }
            for sf in fps
        ]
    except Exception:
        features["fingerprints"] = []

    return features


def record_training_label(
    *,
    submission: Submission | None,
    action: str,
    label: str,
    actor: str = "",
    source_ui: str = "",
    reason: str = "",
    entity_key: str = "",
    extra_features: dict[str, Any] | None = None,
) -> TrainingLabel | None:
    """
    Persist one ML-training row. Swallows errors so investigator actions never
    block on a logging failure.

    For ACTION_TAG_ENTITY, `submission` may be None — pass `entity_key` (e.g.
    "email:42") and the trainer will join against the entity table at read time.
    """
    try:
        features = snapshot_features(submission) if submission is not None else {}
        if extra_features:
            features.update(extra_features)

        system_decision = ""
        system_score = None
        if submission is not None and hasattr(submission, "verdict") and submission.verdict:
            system_decision = submission.verdict.decision or ""
            system_score = submission.verdict.score

        org_id = submission.organization_id if submission is not None else None
        if org_id is None:
            # Entity-only event — fall back to the default organization.
            from apps.organizations.models import Organization
            default_org = Organization.objects.filter(is_active=True).order_by("id").first()
            if default_org is None:
                return None
            org_id = default_org.id

        return TrainingLabel.objects.create(
            organization_id=org_id,
            submission=submission,
            entity_key=entity_key,
            action=action,
            label=label,
            features=features,
            system_decision=system_decision,
            system_score=system_score,
            actor=actor[:150],
            source_ui=source_ui[:80],
            reason=reason[:500],
        )
    except Exception:
        logger.exception("record_training_label failed (action=%s, label=%s)", action, label)
        return None


# Shortcut: writes both the Feedback row (legacy API contract) and the TrainingLabel row.
def record_override_feedback(
    submission: Submission,
    *,
    reported_as: str,   # Feedback.REPORT_*
    training_action: str,   # TrainingLabel.ACTION_*
    training_label: str,    # TrainingLabel.LABEL_*
    actor: str,
    source_ui: str,
    reason: str,
):
    """
    Create the Feedback row (bumps fingerprint reputation counters via the
    fingerprints service) AND a TrainingLabel row.
    """
    # 1. Legacy Feedback record — feeds the fingerprint-reputation counters.
    try:
        Feedback.objects.create(
            organization=submission.organization,
            submission=submission,
            api_key=submission.api_key,
            reported_as=reported_as,
            notes=reason or "",
            reported_by=actor or "",
        )
    except Exception:
        logger.exception("Feedback.create failed for submission %s", submission.id)

    # 2. Fingerprint reputation bump
    try:
        from apps.fingerprints.services import apply_feedback
        apply_feedback(submission, reported_as=reported_as)
    except Exception:
        logger.exception("apply_feedback failed for submission %s", submission.id)

    # 3. Training-label snapshot
    record_training_label(
        submission=submission,
        action=training_action,
        label=training_label,
        actor=actor,
        source_ui=source_ui,
        reason=reason,
    )
