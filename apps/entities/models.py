"""
Normalized entity tables — global facts, cross-tenant.

Entity rows are shared across orgs. The join tables (in apps.submissions) are
org-scoped: cross-org data never leaks directly. What leaks through is
aggregated reputation: net_flagged_count / net_approved_count, surfaced as
'this entity has been flagged N times across our network.'
"""
from django.db import models


class NetworkEntity(models.Model):
    """Abstract base for cross-customer reputation-tracked entities.

    Counters are denormalized for fast read paths; Phase 2 updates them
    via signals/jobs when new verdicts land. Phase 1 leaves them at 0.
    """

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    net_flagged_count = models.IntegerField(default=0)
    net_approved_count = models.IntegerField(default=0)

    class Meta:
        abstract = True


# ====================================================================
# Domain-side entities (populated from DomainScan results)
# ====================================================================


class ASN(NetworkEntity):
    number = models.IntegerField(unique=True)
    name = models.CharField(max_length=200, blank=True, default="")
    country = models.CharField(max_length=2, blank=True, default="")

    class Meta:
        db_table = "asns"

    def __str__(self) -> str:
        return f"AS{self.number} {self.name}".strip()


class IPAddress(NetworkEntity):
    address = models.GenericIPAddressField(unique=True)
    asn = models.ForeignKey(
        ASN, null=True, blank=True, on_delete=models.SET_NULL, related_name="ip_addresses"
    )
    hosting_provider = models.CharField(max_length=200, blank=True, default="")
    country = models.CharField(max_length=2, blank=True, default="")
    # Phase 2: enrichment (MaxMind / IPQS) populates these.
    is_datacenter = models.BooleanField(default=False)
    is_vpn = models.BooleanField(default=False)
    is_proxy = models.BooleanField(default=False)
    is_tor = models.BooleanField(default=False)

    class Meta:
        db_table = "ip_addresses"

    def __str__(self) -> str:
        return self.address


class Nameserver(NetworkEntity):
    hostname = models.CharField(max_length=253, unique=True)

    class Meta:
        db_table = "nameservers"

    def __str__(self) -> str:
        return self.hostname


class MXHost(NetworkEntity):
    hostname = models.CharField(max_length=253, unique=True)

    class Meta:
        db_table = "mx_hosts"

    def __str__(self) -> str:
        return self.hostname


class Registrar(NetworkEntity):
    name = models.CharField(max_length=200, unique=True)
    iana_id = models.IntegerField(null=True, blank=True, unique=True)

    class Meta:
        db_table = "registrars"

    def __str__(self) -> str:
        return self.name


class Certificate(NetworkEntity):
    sha256 = models.CharField(max_length=64, unique=True)
    issuer = models.CharField(max_length=500, blank=True, default="")
    subject = models.CharField(max_length=500, blank=True, default="")
    serial = models.CharField(max_length=200, blank=True, default="")
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "certificates"

    def __str__(self) -> str:
        return self.sha256[:12]


# ====================================================================
# Contact-side entities (populated from submission inputs)
# ====================================================================


class ContactEmail(NetworkEntity):
    normalized = models.CharField(max_length=320, unique=True)
    handle = models.CharField(max_length=200)
    domain = models.CharField(max_length=253)
    # Phase 2: email enrichment populates these.
    mx_reachable = models.BooleanField(null=True, blank=True)
    is_disposable = models.BooleanField(default=False)
    is_role_account = models.BooleanField(default=False)
    breach_count = models.IntegerField(default=0)
    first_breach_at = models.DateTimeField(null=True, blank=True)
    last_breach_at = models.DateTimeField(null=True, blank=True)
    has_gravatar = models.BooleanField(null=True, blank=True)

    class Meta:
        db_table = "contact_emails"
        indexes = [models.Index(fields=["domain"])]

    def __str__(self) -> str:
        return self.normalized


class ContactName(NetworkEntity):
    full = models.CharField(max_length=200)
    normalized = models.CharField(max_length=200, unique=True)
    # Metaphone / Soundex for fuzzy cross-alias matching (Phase 2).
    phonetic_hash = models.CharField(max_length=64, blank=True, default="", db_index=True)

    class Meta:
        db_table = "contact_names"

    def __str__(self) -> str:
        return self.full


class ContactPhone(NetworkEntity):
    e164 = models.CharField(max_length=20, unique=True)
    country_code = models.CharField(max_length=4, blank=True, default="")
    # Phase 2: Twilio Lookup / Telesign populate these.
    line_type = models.CharField(max_length=20, blank=True, default="")  # mobile/voip/landline
    carrier = models.CharField(max_length=100, blank=True, default="")

    class Meta:
        db_table = "contact_phones"

    def __str__(self) -> str:
        return self.e164


class SubmitterIP(NetworkEntity):
    """
    IP address of the submitter at submission time (distinct from a domain's
    hosting IPs). Gets geolocation + proxy/VPN/Tor enrichment in Phase 2.
    """

    address = models.GenericIPAddressField(unique=True)
    asn = models.ForeignKey(
        ASN, null=True, blank=True, on_delete=models.SET_NULL, related_name="submitter_ips"
    )
    country = models.CharField(max_length=2, blank=True, default="")
    region = models.CharField(max_length=100, blank=True, default="")
    city = models.CharField(max_length=100, blank=True, default="")
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    is_datacenter = models.BooleanField(default=False)
    is_vpn = models.BooleanField(default=False)
    is_proxy = models.BooleanField(default=False)
    is_tor = models.BooleanField(default=False)

    class Meta:
        db_table = "submitter_ips"

    def __str__(self) -> str:
        return self.address
