"""
eHawk-style scoring rules. Each rule has an `area` (category) + `hit` (specific
detection) with a deduction score that applies when the detector fires on a
submission. Customers customize `current_score`; `default_score` is the
recommended baseline.

Our legacy SDAT score (0-100, higher=worse) scores domain infrastructure.
The eHawk-style scoring system here complements it with user/behavioral
signals (email patterns, name patterns, IP type, fingerprint variance,
velocity, community reports, etc.) using a deduction model (+100 starting,
deductions bring it down; -130 floor = definitely deny, +130 ceiling = definitely approve).

Phase 3 scope: rule registry + browse UI.
Phase 4 scope: detectors that compute which rules fire + pipeline integration.
"""
from django.db import models


class ScoringRule(models.Model):
    """A single scoring rule — e.g., 'Email / Disposable' with a −130 deduction."""

    area = models.CharField(max_length=40, db_index=True)
    hit = models.CharField(max_length=80)
    description = models.TextField(blank=True, default="")

    default_score = models.IntegerField(
        help_text="Recommended baseline deduction (typically negative).",
    )
    current_score = models.IntegerField(
        help_text="Customized deduction in use. Editable by investigators.",
    )

    # Phase 4: detector coverage. True when we have a function in the pipeline
    # that evaluates this rule against a submission.
    is_implemented = models.BooleanField(default=False, db_index=True)
    implementation_notes = models.TextField(blank=True, default="")

    # Stats — updated by nightly job in Phase 4.
    hit_count_30d = models.IntegerField(default=0)

    # Audit
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=200, blank=True, default="")

    class Meta:
        db_table = "scoring_rules"
        constraints = [
            models.UniqueConstraint(fields=["area", "hit"], name="uniq_scoring_rule_area_hit"),
        ]
        ordering = ("area", "hit")

    def __str__(self) -> str:
        return f"{self.area} / {self.hit}"
