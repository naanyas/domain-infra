from django.contrib import admin

from .models import RiskProfile


@admin.register(RiskProfile)
class RiskProfileAdmin(admin.ModelAdmin):
    list_display = ("organization", "name", "is_default", "is_active", "approve_max_score", "deny_min_score", "updated_at")
    list_filter = ("is_default", "is_active", "organization")
    search_fields = ("organization__slug", "organization__name", "name")
    readonly_fields = ("created_at", "updated_at")
