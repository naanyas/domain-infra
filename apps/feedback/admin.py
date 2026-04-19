from django.contrib import admin

from .models import Feedback


@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ("submission", "organization", "reported_as", "reason_code", "reported_by", "created_at")
    list_filter = ("reported_as", "organization")
    search_fields = ("submission__id", "reason_code", "notes", "reported_by")
    readonly_fields = ("created_at",)
