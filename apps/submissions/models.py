import uuid

from django.db import models


class Submission(models.Model):
    """
    Top-level fraud-evaluation unit. Bundles any subset of: domain, contact
    email/name/phone, submitter IP, device fingerprint.

    UUID primary key so submission_id can be surfaced in the API without
    leaking row-count information.
    """

    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_COMPLETE = "complete"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_COMPLETE, "Complete"),
        (STATUS_FAILED, "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="submissions",
    )
    api_key = models.ForeignKey(
        "organizations.ApiKey",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="submissions",
    )

    # Immutable snapshot of the risk profile used at evaluation time, so
    # verdicts remain reproducible even if the profile is later edited.
    risk_profile = models.ForeignKey(
        "risk_profiles.RiskProfile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="submissions",
    )
    risk_profile_snapshot = models.JSONField(null=True, blank=True)

    # Raw submission inputs (at least one signal required at API validation time).
    domain = models.CharField(max_length=253, blank=True, default="", db_index=True)
    contact_email_raw = models.CharField(max_length=320, blank=True, default="")
    contact_name_raw = models.CharField(max_length=200, blank=True, default="")
    contact_phone_raw = models.CharField(max_length=40, blank=True, default="")
    submitter_ip_raw = models.GenericIPAddressField(null=True, blank=True)
    device_fingerprint_raw = models.CharField(max_length=200, blank=True, default="")

    # Customer correlation
    external_ref = models.CharField(max_length=200, blank=True, default="", db_index=True)
    metadata = models.JSONField(default=dict, blank=True)

    # Normalized entity FKs (populated during processing)
    contact_email = models.ForeignKey(
        "entities.ContactEmail",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="submissions",
    )
    contact_name = models.ForeignKey(
        "entities.ContactName",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="submissions",
    )
    contact_phone = models.ForeignKey(
        "entities.ContactPhone",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="submissions",
    )
    submitter_ip = models.ForeignKey(
        "entities.SubmitterIP",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="submissions",
    )

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_QUEUED, db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "submissions"
        indexes = [
            models.Index(fields=["organization", "-created_at"]),
            models.Index(fields=["organization", "status"]),
            models.Index(fields=["organization", "external_ref"]),
        ]

    def __str__(self) -> str:
        return f"Submission {self.id} ({self.organization.slug})"


class DomainScan(models.Model):
    """
    Result of running the SDAT analyzer on the submission's domain.
    One Submission has zero or one DomainScan (only present if domain was supplied).
    """

    submission = models.OneToOneField(
        Submission, on_delete=models.CASCADE, related_name="domain_scan"
    )
    domain = models.CharField(max_length=253, db_index=True)

    # Mirrored top-level fields from DomainApprovalResult for fast querying.
    risk_score = models.IntegerField(default=0)
    recommendation = models.CharField(max_length=50, blank=True, default="", db_index=True)
    summary = models.TextField(blank=True, default="")
    risk_level = models.CharField(max_length=20, blank=True, default="")

    analyzer_version = models.CharField(max_length=20, blank=True, default="")
    scan_timestamp = models.DateTimeField(null=True, blank=True)

    # Full DomainApprovalResult as JSON — preserves every field the analyzer emits
    # so future query needs don't force a re-scan.
    raw_result = models.JSONField()

    registrar = models.ForeignKey(
        "entities.Registrar",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="domain_scans",
    )

    class Meta:
        db_table = "domain_scans"
        indexes = [
            models.Index(fields=["domain", "-id"]),
            models.Index(fields=["recommendation"]),
        ]

    def __str__(self) -> str:
        return f"{self.domain} ({self.recommendation})"


class DomainScanIP(models.Model):
    """IP address observed during a domain scan, tagged by role (A / AAAA / MX / NS)."""

    ROLE_A = "a"
    ROLE_AAAA = "aaaa"
    ROLE_MX = "mx"
    ROLE_NS = "ns"
    ROLE_CHOICES = [(ROLE_A, "A"), (ROLE_AAAA, "AAAA"), (ROLE_MX, "MX"), (ROLE_NS, "NS")]

    domain_scan = models.ForeignKey(
        DomainScan, on_delete=models.CASCADE, related_name="ip_links"
    )
    ip_address = models.ForeignKey(
        "entities.IPAddress", on_delete=models.CASCADE, related_name="scan_links"
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)

    class Meta:
        db_table = "domain_scan_ips"
        constraints = [
            models.UniqueConstraint(
                fields=["domain_scan", "ip_address", "role"],
                name="uniq_domain_scan_ip_role",
            )
        ]


class DomainScanNameserver(models.Model):
    domain_scan = models.ForeignKey(
        DomainScan, on_delete=models.CASCADE, related_name="nameserver_links"
    )
    nameserver = models.ForeignKey(
        "entities.Nameserver", on_delete=models.CASCADE, related_name="scan_links"
    )

    class Meta:
        db_table = "domain_scan_nameservers"
        constraints = [
            models.UniqueConstraint(
                fields=["domain_scan", "nameserver"], name="uniq_domain_scan_ns"
            )
        ]


class DomainScanMXHost(models.Model):
    domain_scan = models.ForeignKey(
        DomainScan, on_delete=models.CASCADE, related_name="mx_links"
    )
    mx_host = models.ForeignKey(
        "entities.MXHost", on_delete=models.CASCADE, related_name="scan_links"
    )
    preference = models.IntegerField(default=0)

    class Meta:
        db_table = "domain_scan_mx_hosts"
        constraints = [
            models.UniqueConstraint(
                fields=["domain_scan", "mx_host"], name="uniq_domain_scan_mx"
            )
        ]


class DomainScanCertificate(models.Model):
    domain_scan = models.ForeignKey(
        DomainScan, on_delete=models.CASCADE, related_name="certificate_links"
    )
    certificate = models.ForeignKey(
        "entities.Certificate", on_delete=models.CASCADE, related_name="scan_links"
    )

    class Meta:
        db_table = "domain_scan_certificates"
        constraints = [
            models.UniqueConstraint(
                fields=["domain_scan", "certificate"], name="uniq_domain_scan_cert"
            )
        ]


class Verdict(models.Model):
    """
    The system's final approve / deny / review decision on a Submission.
    Phase 1 verdict is derived primarily from the DomainScan; Phase 2 folds in
    contact signals, fingerprint reputation, and risk-profile rules.
    """

    DECISION_APPROVE = "approve"
    DECISION_DENY = "deny"
    DECISION_REVIEW = "review"
    DECISION_CHOICES = [
        (DECISION_APPROVE, "Approve"),
        (DECISION_DENY, "Deny"),
        (DECISION_REVIEW, "Review"),
    ]

    submission = models.OneToOneField(
        Submission, on_delete=models.CASCADE, related_name="verdict"
    )
    decision = models.CharField(max_length=20, choices=DECISION_CHOICES, db_index=True)
    score = models.IntegerField(default=0)
    summary = models.TextField(blank=True, default="")
    # list[{code, description, weight}]
    reasons = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Investigator review status — labels every decision for training feedback.
    #   confirmed — investigator reviewed + agrees (positive training signal)
    #   corrected — investigator disagrees (reviewed_decision holds their call)
    #   unknown   — investigator looked but can't tell (skip in training)
    #   ""        — not yet reviewed
    REVIEW_CONFIRMED = "confirmed"
    REVIEW_CORRECTED = "corrected"
    REVIEW_UNKNOWN = "unknown"
    REVIEW_CHOICES = [
        (REVIEW_CONFIRMED, "Confirmed — investigator agrees"),
        (REVIEW_CORRECTED, "Corrected — investigator disagrees"),
        (REVIEW_UNKNOWN, "Unknown — investigator can't tell"),
    ]
    review_status = models.CharField(
        max_length=20, choices=REVIEW_CHOICES, blank=True, default="", db_index=True
    )

    # Kept for backward compatibility + data capture. Populated only when
    # review_status == 'corrected'. Pre-existing naming retained to avoid
    # a rename migration on what's now fully live data.
    human_override_decision = models.CharField(
        max_length=20, choices=DECISION_CHOICES, blank=True, default=""
    )
    human_override_reason = models.TextField(blank=True, default="")
    human_override_by = models.CharField(max_length=200, blank=True, default="")
    human_override_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "verdicts"

    @property
    def effective_decision(self) -> str:
        """If investigator corrected, their decision wins. Confirmed/unknown → system decision stays."""
        if self.review_status == self.REVIEW_CORRECTED and self.human_override_decision:
            return self.human_override_decision
        return self.decision

    def __str__(self) -> str:
        return f"{self.submission_id} => {self.effective_decision}"
