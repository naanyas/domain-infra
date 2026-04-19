"""
Phase 1: schema only.
Phase 2 implements canonical-signal hashing + MinHash/SimHash similarity search
+ reputation updates on new verdicts and feedback.
"""
from django.db import models


class Fingerprint(models.Model):
    """
    A canonical signal-set hash for cross-submission matching.

    Two kinds:
      * infrastructure — hash of NS set, MX set, ASN, registrar, SPF/DKIM
        pattern, TLS issuer, HTTP server signature, WHOIS privacy service.
      * actor — hash of contact email pattern, name phonetic hash, phone
        prefix, submitter IP ASN, device fingerprint.
    """

    KIND_INFRASTRUCTURE = "infrastructure"
    KIND_ACTOR = "actor"
    KIND_CHOICES = [
        (KIND_INFRASTRUCTURE, "Infrastructure"),
        (KIND_ACTOR, "Actor"),
    ]

    fingerprint_hash = models.CharField(max_length=64, unique=True, db_index=True)
    kind = models.CharField(max_length=20, choices=KIND_CHOICES, db_index=True)
    canonical_signals = models.JSONField()
    # MinHash / SimHash feature vector for fuzzy nearest-neighbor similarity.
    feature_vector = models.JSONField(null=True, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "fingerprints"

    def __str__(self) -> str:
        return f"{self.kind}:{self.fingerprint_hash[:12]}"


class SubmissionFingerprint(models.Model):
    """
    Each submission has one primary fingerprint per kind + N nearest-neighbor
    matches (is_primary=False). Similarity is 1.0 for exact-match primary,
    <1.0 for fuzzy neighbors.
    """

    submission = models.ForeignKey(
        "submissions.Submission", on_delete=models.CASCADE, related_name="fingerprint_links"
    )
    fingerprint = models.ForeignKey(
        Fingerprint, on_delete=models.CASCADE, related_name="submission_links"
    )
    kind = models.CharField(max_length=20)
    is_primary = models.BooleanField(default=False)
    similarity = models.FloatField(default=1.0)

    class Meta:
        db_table = "submission_fingerprints"
        constraints = [
            models.UniqueConstraint(
                fields=["submission", "fingerprint", "kind"],
                name="uniq_submission_fingerprint_kind",
            )
        ]
        indexes = [models.Index(fields=["submission", "kind", "is_primary"])]


class FingerprintReputation(models.Model):
    """
    Rolling network-wide reputation per fingerprint — the community signal
    surfaced back to customers. Updated by Phase 2 jobs on new verdicts and feedback.

    reputation_score: -1.0 (consistently flagged) .. +1.0 (consistently approved).
    """

    fingerprint = models.OneToOneField(
        Fingerprint, on_delete=models.CASCADE, related_name="reputation"
    )
    flagged_count = models.IntegerField(default=0)
    approved_count = models.IntegerField(default=0)
    review_count = models.IntegerField(default=0)
    feedback_false_positive_count = models.IntegerField(default=0)
    feedback_false_negative_count = models.IntegerField(default=0)
    feedback_confirmed_count = models.IntegerField(default=0)
    reputation_score = models.FloatField(default=0.0)
    last_updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "fingerprint_reputations"

    def __str__(self) -> str:
        return f"rep({self.fingerprint.fingerprint_hash[:12]})={self.reputation_score:.2f}"
