import hashlib
import secrets

from django.db import models


class Organization(models.Model):
    """Customer tenant. Every persisted row is scoped to one of these."""

    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=100, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "organizations"
        ordering = ("name",)

    def __str__(self) -> str:
        return self.name


class ApiKey(models.Model):
    """
    Org-scoped API key. Only the hash is stored; raw key is shown once at creation.
    Acts as the authenticated principal for API requests — DRF views get
    `request.user` set to the ApiKey instance, and `request.user.organization`.
    """

    KEY_SCHEME = "di"  # prefix (domain-infra) for visual recognition

    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="api_keys"
    )
    label = models.CharField(max_length=100)
    key_hash = models.CharField(max_length=64, unique=True, db_index=True)
    key_prefix = models.CharField(max_length=16)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "api_keys"

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    @classmethod
    def generate(cls, organization: Organization, label: str) -> tuple["ApiKey", str]:
        """Create a new key. Returns (instance, raw_key). Raw key shown once only."""
        raw = f"{cls.KEY_SCHEME}_{secrets.token_urlsafe(32)}"
        instance = cls.objects.create(
            organization=organization,
            label=label,
            key_hash=hashlib.sha256(raw.encode()).hexdigest(),
            key_prefix=raw[: len(cls.KEY_SCHEME) + 1 + 6],
        )
        return instance, raw

    def __str__(self) -> str:
        return f"{self.organization.slug}:{self.label} ({self.key_prefix}…)"
