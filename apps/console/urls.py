from django.urls import path

from . import views

app_name = "console"

urlpatterns = [
    path("", views.home, name="home"),
    path("search/", views.global_search, name="search"),
    path("submissions/", views.submissions_list, name="submissions-list"),
    path("submissions/new/", views.submission_new, name="submission-new"),
    path("submissions/run-batch/", views.submissions_run_batch, name="submissions-run-batch"),
    path("submissions/bulk/", views.submissions_bulk, name="submissions-bulk"),
    path("submissions/<uuid:submission_id>/", views.submission_detail, name="submission-detail"),
    path("scoring-rules/", views.scoring_rules, name="scoring-rules"),
    path("scoring-bands/", views.scoring_bands, name="scoring-bands"),
    path("ml/", views.ml_status, name="ml-status"),
    path("clusters/", views.clusters_dashboard, name="clusters"),
    path("threat-intel/", views.threat_intel_browse, name="threat-intel"),
    path("threat-intel/add/", views.threat_intel_add, name="threat-intel-add"),
    path("threat-intel/feeds/refresh-all/", views.threat_intel_refresh_all, name="threat-intel-refresh-all"),
    path("threat-intel/feeds/<int:feed_id>/refresh/", views.threat_intel_refresh_feed, name="threat-intel-refresh-feed"),
    path("fingerprints/<str:fingerprint_hash>/", views.fingerprint_detail, name="fingerprint-detail"),
    path("fingerprints/<str:fingerprint_hash>/mark-cluster/", views.fingerprint_cluster_mark, name="fingerprint-cluster-mark"),
    path("device-fingerprint/<str:device_hash>/", views.device_fingerprint_detail, name="device-fingerprint-detail"),
    path("submissions/<uuid:submission_id>/override/", views.submission_verdict_override, name="submission-override"),
    path("submissions/<uuid:submission_id>/run/", views.submission_run_pipeline, name="submission-run"),
    path("entities/ip/<str:address>/", views.ip_entity_detail, name="ip-detail"),
    path("entities/ip/<str:address>/tag/", views.ip_entity_tag, name="ip-tag"),
    path("entities/<str:entity_type>/<int:entity_id>/tag/", views.entity_tag_by_id, name="entity-tag"),
    path("entities/<str:entity_type>/<int:entity_id>/", views.entity_detail, name="entity-detail"),
]
