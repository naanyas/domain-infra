from django.urls import path

from . import views

app_name = "api"

urlpatterns = [
    path("submissions", views.submissions_list_create, name="submissions-list-create"),
    path("submissions/<uuid:submission_id>", views.submission_detail, name="submission-detail"),
    path("submissions/<uuid:submission_id>/feedback", views.submission_feedback, name="submission-feedback"),
    path("signal-catalog", views.signal_catalog, name="signal-catalog"),
]
