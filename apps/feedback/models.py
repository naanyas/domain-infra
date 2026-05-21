"""
Phase 1: schema only.
Phase 2 adds POST /submissions/{id}/feedback and wires reputation updates +
ML retraining signal.
"""
from django.db import models


class Feedback(models.Model):
    """
    Customer-submitted correction on a verdict.

    `reported_as` taxonomy:
      * false_positive — we denied, but the customer verified it was legitimate
      * false_negative — we approved, but the customer caught fraud downstream
      * confirmed — our decision was correct (useful for reinforcing true signals)
    """

    REPORT_FALSE_POSITIVE = "false_positive"
    REPORT_FALSE_NEGATIVE = "false_negative"
    REPORT_CONFIRMED = "confirmed"
    REPORT_CHOICES = [
        (REPORT_FALSE_POSITIVE, "False Positive — we denied something good"),
        (REPORT_FALSE_NEGATIVE, "False Negative — we approved something bad"),
        (REPORT_CONFIRMED, "Confirmed — our decision was correct"),
    ]

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="feedback"
    )
    submission = models.ForeignKey(
        "submissions.Submission", on_delete=models.CASCADE, related_name="feedback"
    )
    api_key = models.ForeignKey(
        "organizations.ApiKey",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="feedback",
    )
    reported_as = models.CharField(max_length=30, choices=REPORT_CHOICES, db_index=True)
    # Free-form customer-defined taxonomy ("chargeback", "identity_theft", etc.).
    reason_code = models.CharField(max_length=50, blank=True, default="")
    notes = models.TextField(blank=True, default="")
    # Customer's internal user id / email — not one of our Users.
    reported_by = models.CharField(max_length=200, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "feedback"
        indexes = [
            models.Index(fields=["organization", "-created_at"]),
            models.Index(fields=["submission", "reported_as"]),
        ]

    def __str__(self) -> str:
        return f"{self.submission_id}:{self.reported_as}"


class TrainingLabel(models.Model):
    """
    ML training corpus — one row per investigator action that carries a learning
    signal. Every verdict confirm/correct, every entity tag, every cluster mark,
    every threat flag, every bulk action writes here. Offline trainers consume
    these rows as (features, label) pairs.

    Features is a FROZEN snapshot (raw SDAT fields, entity tags, enrichment,
    fingerprint ids, score breakdown) captured at label time so the training set
    is immune to subsequent tag/score changes.
    """

    ACTION_OVERRIDE_CONFIRM = "verdict_confirm"
    ACTION_OVERRIDE_CORRECT = "verdict_correct"
    ACTION_OVERRIDE_UNKNOWN = "verdict_unknown"
    ACTION_TAG_ENTITY = "tag_entity"
    ACTION_CLUSTER_MARK = "cluster_mark"
    ACTION_THREAT_FLAG = "threat_flag"
    ACTION_BULK_FLAG = "bulk_flag_threat"
    ACTION_BULK_CONFIRM = "bulk_confirm"
    ACTION_BULK_CORRECT = "bulk_correct"
    ACTION_CHOICES = [
        (ACTION_OVERRIDE_CONFIRM, "Verdict confirmed"),
        (ACTION_OVERRIDE_CORRECT, "Verdict corrected"),
        (ACTION_OVERRIDE_UNKNOWN, "Verdict unknown"),
        (ACTION_TAG_ENTITY, "Entity tagged"),
        (ACTION_CLUSTER_MARK, "Cluster marked"),
        (ACTION_THREAT_FLAG, "Domain flagged as threat"),
        (ACTION_BULK_FLAG, "Bulk flag as threat"),
        (ACTION_BULK_CONFIRM, "Bulk confirm"),
        (ACTION_BULK_CORRECT, "Bulk correct"),
    ]

    LABEL_APPROVE = "approve"
    LABEL_REVIEW = "review"
    LABEL_DENY = "deny"
    LABEL_BAD = "bad"
    LABEL_GOOD = "good"
    LABEL_UNKNOWN = "unknown"
    LABEL_CHOICES = [
        (LABEL_APPROVE, "Approve"),
        (LABEL_REVIEW, "Review"),
        (LABEL_DENY, "Deny"),
        (LABEL_BAD, "Bad (entity)"),
        (LABEL_GOOD, "Good (entity)"),
        (LABEL_UNKNOWN, "Unknown"),
    ]

    organization = models.ForeignKey(
        "organizations.Organization", on_delete=models.CASCADE, related_name="training_labels"
    )
    submission = models.ForeignKey(
        "submissions.Submission", on_delete=models.CASCADE, related_name="training_labels",
        null=True, blank=True,
    )
    entity_key = models.CharField(max_length=255, default="", blank=True, db_index=True,
                                  help_text="For ACTION_TAG_ENTITY — e.g. 'email:42', 'ip:1.2.3.4'")

    action = models.CharField(max_length=40, choices=ACTION_CHOICES, db_index=True)
    label = models.CharField(max_length=20, choices=LABEL_CHOICES, db_index=True)

    # Frozen per-submission feature snapshot (signals, entity tags, raw SDAT, etc.)
    features = models.JSONField(default=dict, blank=True)

    # System state at label time — what SDAT said BEFORE the investigator acted.
    system_decision = models.CharField(max_length=20, default="", blank=True)
    system_score = models.IntegerField(null=True, blank=True)

    actor = models.CharField(max_length=150, default="", blank=True)
    source_ui = models.CharField(max_length=80, default="", blank=True)
    reason = models.CharField(max_length=500, default="", blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "training_labels"
        indexes = [
            models.Index(fields=["organization", "-created_at"]),
            models.Index(fields=["submission", "action"]),
            models.Index(fields=["label", "action"]),
        ]

    def __str__(self) -> str:
        return f"{self.action}:{self.label} by {self.actor}"
