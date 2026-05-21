"""
Threat-intel indicator store. Schema matches the Cowork research sheet.
"""
from django.db import models


class ThreatIntelDomain(models.Model):
    """
    One known-bad (or suspicious) domain/hostname sourced from external threat intel.
    Schema matches the Cowork research sheet's Domains tab 1:1.
    """

    CATEGORY_PHISHING = "phishing"
    CATEGORY_MALWARE = "malware"
    CATEGORY_DRAINER = "drainer"
    CATEGORY_SCAM = "scam"
    CATEGORY_SPAM = "spam"
    CATEGORY_SCAN = "scan"
    CATEGORY_SUSPICIOUS = "suspicious"
    CATEGORY_CHOICES = [
        (CATEGORY_PHISHING, "phishing"),
        (CATEGORY_MALWARE, "malware"),
        (CATEGORY_DRAINER, "drainer"),
        (CATEGORY_SCAM, "scam"),
        (CATEGORY_SPAM, "spam"),
        (CATEGORY_SCAN, "scan"),
        (CATEGORY_SUSPICIOUS, "suspicious"),
    ]

    CONFIDENCE_HIGH = "high"
    CONFIDENCE_MEDIUM = "medium"
    CONFIDENCE_LOW = "low"
    CONFIDENCE_CHOICES = [
        (CONFIDENCE_HIGH, "high"),
        (CONFIDENCE_MEDIUM, "medium"),
        (CONFIDENCE_LOW, "low"),
    ]

    # Normalized lowercase hostname. For shared-abusable-host entries
    # (pages.dev, 000webhostapp.com, eu.cc, primedatahost3.cfd) apex_subdomain_only=True
    # and the detector only matches if the submission hostname has a prefix subdomain.
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, db_index=True)
    subcategory = models.CharField(max_length=80, default="", blank=True, db_index=True)
    brand_target = models.CharField(max_length=80, default="", blank=True, db_index=True)
    source = models.CharField(max_length=120, default="")
    reported_date = models.DateField(null=True, blank=True)
    confidence = models.CharField(max_length=10, choices=CONFIDENCE_CHOICES, default=CONFIDENCE_MEDIUM, db_index=True)
    notes = models.CharField(max_length=500, default="", blank=True)

    # For shared-abusable-host apex entries (pages.dev, etc.) — never match the apex,
    # only subdomains of it.
    apex_subdomain_only = models.BooleanField(default=False)

    # Set by loader for meta-entries (`*[.]cluster`) so the detector can skip them.
    is_meta_cluster = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "threat_intel_domains"
        indexes = [
            models.Index(fields=["category", "confidence"]),
        ]

    def __str__(self) -> str:
        return f"{self.domain} [{self.category}/{self.confidence}]"

    @property
    def score_weight(self) -> int:
        """
        Score contribution when a submission matches this indicator.
        Shared-abusable-host subdomains get a smaller weight (the apex is used by
        many legitimate projects too — low-confidence signal).
        """
        if self.confidence == self.CONFIDENCE_HIGH:
            return 60
        if self.confidence == self.CONFIDENCE_MEDIUM:
            return 30
        return 10  # low


class ThreatIntelFeed(models.Model):
    """
    External threat-intel feed configuration. One row per source; the refresh
    command iterates enabled feeds and pulls fresh indicators into
    ThreatIntelDomain on a schedule.

    The `parser` field chooses which fetcher module handles the feed's format
    (see apps/iocs/fetchers.py). Common parsers: plaintext_hosts, csv_hosts,
    spamhaus_drop, firehol_ips, openphish, abuseipdb_blacklist, github_raw_text.
    """

    KIND_DOMAIN = "domain"
    KIND_IP = "ip"
    KIND_URL = "url"
    KIND_CHOICES = [(KIND_DOMAIN, "Domain/hostname"), (KIND_IP, "IP/CIDR"), (KIND_URL, "URL")]

    name = models.CharField(max_length=100, unique=True)
    url = models.URLField(max_length=500)
    parser = models.CharField(max_length=40, db_index=True,
                              help_text="Fetcher module key (e.g. plaintext_hosts, spamhaus_drop)")
    kind = models.CharField(max_length=10, choices=KIND_CHOICES, default=KIND_DOMAIN)

    # Default categorization applied to every indicator in this feed (overridable
    # per-row by the parser).
    default_category = models.CharField(max_length=20, default="scam",
                                        help_text="Default ThreatIntelDomain.category")
    default_subcategory = models.CharField(max_length=80, default="", blank=True)
    default_confidence = models.CharField(max_length=10, default="medium")

    source_label = models.CharField(max_length=120, default="", blank=True,
                                    help_text="Human-readable source attribution")

    # Scheduling — `refresh_interval_hours=0` means manual-only.
    refresh_interval_hours = models.IntegerField(default=24)
    enabled = models.BooleanField(default=True)

    # Headers / API key env-var name (e.g. "ABUSEIPDB_API_KEY"). Parser reads env.
    api_key_env = models.CharField(max_length=80, default="", blank=True)
    extra_headers = models.JSONField(default=dict, blank=True)

    # Last fetch status
    last_fetched_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_status = models.CharField(max_length=40, default="", blank=True,
                                   help_text="ok | error | never")
    last_error = models.TextField(blank=True, default="")
    last_items_created = models.IntegerField(default=0)
    last_items_updated = models.IntegerField(default=0)
    last_items_skipped = models.IntegerField(default=0)
    last_duration_seconds = models.FloatField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "threat_intel_feeds"

    def __str__(self) -> str:
        return f"{self.name} ({self.parser})"

    def is_due(self) -> bool:
        """True if the feed is enabled and its refresh interval has elapsed."""
        if not self.enabled or self.refresh_interval_hours <= 0:
            return False
        if self.last_fetched_at is None:
            return True
        from django.utils import timezone
        import datetime as _dt
        age = timezone.now() - self.last_fetched_at
        return age >= _dt.timedelta(hours=self.refresh_interval_hours)
