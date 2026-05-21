from django.contrib import admin

from .models import ScoringRule


@admin.register(ScoringRule)
class ScoringRuleAdmin(admin.ModelAdmin):
    list_display = ("area", "hit", "default_score", "current_score", "is_implemented", "hit_count_30d", "updated_at")
    list_filter = ("area", "is_implemented")
    search_fields = ("area", "hit", "description")
    list_editable = ("current_score", "is_implemented")
    readonly_fields = ("updated_at",)
    fieldsets = (
        (None, {"fields": ("area", "hit", "description")}),
        ("Scoring", {"fields": ("default_score", "current_score")}),
        ("Implementation", {"fields": ("is_implemented", "implementation_notes", "hit_count_30d")}),
        ("Audit", {"fields": ("updated_at", "updated_by")}),
    )
