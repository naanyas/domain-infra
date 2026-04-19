from django.db import models


class RiskProfile(models.Model):
    """
    Org-scoped policy for how submissions are evaluated.

    Phase 1: schema only. Phase 2 implements the rules engine that consumes
    weight_overrides and rules and emits the final Verdict.decision.

    Every Submission snapshots the active RiskProfile at evaluation time so
    historical verdicts remain reproducible even after the profile is edited.
    """

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="risk_profiles",
    )
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, default="")
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    # Score thresholds: score <= approve_max => approve; score >= deny_min => deny; else review.
    approve_max_score = models.IntegerField(default=30)
    deny_min_score = models.IntegerField(default=70)

    # {signal_key: weight_multiplier}; empty dict => analyzer defaults.
    weight_overrides = models.JSONField(default=dict, blank=True)

    # list[{when: {...conditions}, then: {decision, reason_code, summary}}]
    rules = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "risk_profiles"
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                name="uniq_risk_profile_org_name",
            ),
            models.UniqueConstraint(
                fields=["organization"],
                condition=models.Q(is_default=True, is_active=True),
                name="uniq_default_risk_profile_per_org",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.organization.slug}:{self.name}"
