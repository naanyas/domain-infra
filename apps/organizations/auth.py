import hashlib

from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import ApiKey


class ApiKeyAuthentication(authentication.BaseAuthentication):
    """
    DRF authentication that accepts either:
      Authorization: Bearer <api_key>
      X-API-Key: <api_key>

    On success, `request.user` is the ApiKey instance and
    `request.user.organization` is the tenant.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        key = request.META.get("HTTP_X_API_KEY", "")
        if not key:
            auth_header = request.META.get("HTTP_AUTHORIZATION", "")
            if auth_header.startswith(f"{self.keyword} "):
                key = auth_header[len(self.keyword) + 1 :].strip()
        if not key:
            return None

        key_hash = hashlib.sha256(key.encode()).hexdigest()
        try:
            api_key = ApiKey.objects.select_related("organization").get(
                key_hash=key_hash,
                revoked_at__isnull=True,
                organization__is_active=True,
            )
        except ApiKey.DoesNotExist as exc:
            raise exceptions.AuthenticationFailed("Invalid API key") from exc

        ApiKey.objects.filter(pk=api_key.pk).update(last_used_at=timezone.now())
        return (api_key, api_key)

    def authenticate_header(self, request):
        return self.keyword
