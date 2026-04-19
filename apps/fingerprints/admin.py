from django.contrib import admin

from .models import Fingerprint, FingerprintReputation, SubmissionFingerprint


@admin.register(Fingerprint)
class FingerprintAdmin(admin.ModelAdmin):
    list_display = ("fingerprint_hash", "kind", "first_seen", "last_seen")
    list_filter = ("kind",)
    search_fields = ("fingerprint_hash",)
    readonly_fields = ("first_seen", "last_seen")


@admin.register(SubmissionFingerprint)
class SubmissionFingerprintAdmin(admin.ModelAdmin):
    list_display = ("submission", "fingerprint", "kind", "is_primary", "similarity")
    list_filter = ("kind", "is_primary")


@admin.register(FingerprintReputation)
class FingerprintReputationAdmin(admin.ModelAdmin):
    list_display = (
        "fingerprint",
        "reputation_score",
        "flagged_count",
        "approved_count",
        "review_count",
        "last_updated_at",
    )
    search_fields = ("fingerprint__fingerprint_hash",)
