from django.contrib import admin

from .models import ApiKey, Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "is_active", "created_at")
    search_fields = ("name", "slug")
    list_filter = ("is_active",)
    readonly_fields = ("created_at", "updated_at")


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ("organization", "label", "key_prefix", "created_at", "last_used_at", "revoked_at")
    search_fields = ("organization__name", "organization__slug", "label", "key_prefix")
    list_filter = ("organization",)
    readonly_fields = ("key_hash", "key_prefix", "created_at", "last_used_at")
