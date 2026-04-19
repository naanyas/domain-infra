from django.contrib import admin

from .models import (
    DomainScan,
    DomainScanCertificate,
    DomainScanIP,
    DomainScanMXHost,
    DomainScanNameserver,
    Submission,
    Verdict,
)


class VerdictInline(admin.StackedInline):
    model = Verdict
    can_delete = False
    extra = 0
    readonly_fields = ("created_at",)


class DomainScanInline(admin.StackedInline):
    model = DomainScan
    can_delete = False
    extra = 0
    readonly_fields = ("scan_timestamp", "analyzer_version")


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ("id", "organization", "domain", "status", "created_at", "completed_at")
    list_filter = ("status", "organization")
    search_fields = ("id", "domain", "contact_email_raw", "external_ref")
    readonly_fields = ("id", "created_at", "started_at", "completed_at")
    inlines = [DomainScanInline, VerdictInline]


@admin.register(DomainScan)
class DomainScanAdmin(admin.ModelAdmin):
    list_display = ("domain", "recommendation", "risk_score", "risk_level", "registrar", "analyzer_version")
    list_filter = ("recommendation", "risk_level")
    search_fields = ("domain",)


@admin.register(Verdict)
class VerdictAdmin(admin.ModelAdmin):
    list_display = ("submission", "decision", "score", "human_override_decision", "created_at")
    list_filter = ("decision",)
    search_fields = ("submission__id",)


admin.site.register(DomainScanIP)
admin.site.register(DomainScanNameserver)
admin.site.register(DomainScanMXHost)
admin.site.register(DomainScanCertificate)
