from django.contrib import admin
from django.urls import include, path

from apps.console.public_views import landing as public_landing

urlpatterns = [
    path("", public_landing, name="public-landing"),
    path("admin/", admin.site.urls),
    path("api/v1/", include("apps.api.urls")),
    path("console/", include("apps.console.urls")),
]
