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
