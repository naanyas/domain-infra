from django.contrib import admin

from .models import (
    ASN,
    Certificate,
    ContactEmail,
    ContactName,
    ContactPhone,
    IPAddress,
    MXHost,
    Nameserver,
    Registrar,
    SubmitterIP,
)


class NetworkEntityAdmin(admin.ModelAdmin):
    readonly_fields = ("first_seen", "last_seen", "net_flagged_count", "net_approved_count", "tagged_at")
    list_filter = ("tag",)


@admin.register(ASN)
class ASNAdmin(NetworkEntityAdmin):
    list_display = ("number", "name", "country", "net_flagged_count", "net_approved_count")
    search_fields = ("number", "name")


@admin.register(IPAddress)
class IPAddressAdmin(NetworkEntityAdmin):
    list_display = ("address", "asn", "country", "is_datacenter", "is_vpn", "net_flagged_count")
    search_fields = ("address",)
    list_filter = ("is_datacenter", "is_vpn", "is_proxy", "is_tor", "country")


@admin.register(Nameserver)
class NameserverAdmin(NetworkEntityAdmin):
    list_display = ("hostname", "net_flagged_count", "net_approved_count", "last_seen")
    search_fields = ("hostname",)


@admin.register(MXHost)
class MXHostAdmin(NetworkEntityAdmin):
    list_display = ("hostname", "net_flagged_count", "net_approved_count", "last_seen")
    search_fields = ("hostname",)


@admin.register(Registrar)
class RegistrarAdmin(NetworkEntityAdmin):
    list_display = ("name", "iana_id", "net_flagged_count", "net_approved_count")
    search_fields = ("name", "iana_id")


@admin.register(Certificate)
class CertificateAdmin(NetworkEntityAdmin):
    list_display = ("sha256", "issuer", "not_before", "not_after")
    search_fields = ("sha256", "issuer", "subject")


@admin.register(ContactEmail)
class ContactEmailAdmin(NetworkEntityAdmin):
    list_display = ("normalized", "domain", "is_disposable", "breach_count", "net_flagged_count")
    search_fields = ("normalized", "handle", "domain")
    list_filter = ("is_disposable", "is_role_account")


@admin.register(ContactName)
class ContactNameAdmin(NetworkEntityAdmin):
    list_display = ("full", "normalized", "phonetic_hash", "net_flagged_count")
    search_fields = ("full", "normalized", "phonetic_hash")


@admin.register(ContactPhone)
class ContactPhoneAdmin(NetworkEntityAdmin):
    list_display = ("e164", "country_code", "line_type", "carrier", "net_flagged_count")
    search_fields = ("e164",)


@admin.register(SubmitterIP)
class SubmitterIPAdmin(NetworkEntityAdmin):
    list_display = ("address", "country", "city", "is_vpn", "is_tor", "is_datacenter", "net_flagged_count")
    search_fields = ("address", "city", "region")
    list_filter = ("is_vpn", "is_proxy", "is_tor", "is_datacenter", "country")
