from rest_framework import serializers

from apps.feedback.models import Feedback
from apps.submissions.models import DomainScan, Submission, Verdict


class SubmissionCreateSerializer(serializers.Serializer):
    """
    Submission input schema. At least one signal must be supplied.
    """

    SIGNAL_FIELDS = (
        "domain",
        "contact_email",
        "contact_name",
        "contact_phone",
        "submitter_ip",
        "device_fingerprint",
    )

    domain = serializers.CharField(required=False, allow_blank=True, max_length=253)
    contact_email = serializers.CharField(required=False, allow_blank=True, max_length=320)
    contact_name = serializers.CharField(required=False, allow_blank=True, max_length=200)
    contact_phone = serializers.CharField(required=False, allow_blank=True, max_length=40)
    submitter_ip = serializers.IPAddressField(required=False, allow_null=True)
    device_fingerprint = serializers.CharField(required=False, allow_blank=True, max_length=200)
    external_ref = serializers.CharField(required=False, allow_blank=True, max_length=200)
    metadata = serializers.JSONField(required=False)
    risk_profile_id = serializers.IntegerField(required=False, allow_null=True)

    def validate(self, attrs):
        if not any(attrs.get(f) for f in self.SIGNAL_FIELDS):
            raise serializers.ValidationError(
                "At least one signal required: "
                + ", ".join(self.SIGNAL_FIELDS)
            )
        return attrs


class VerdictReadSerializer(serializers.ModelSerializer):
    effective_decision = serializers.ReadOnlyField()

    class Meta:
        model = Verdict
        fields = (
            "decision",
            "score",
            "summary",
            "reasons",
            "effective_decision",
            "human_override_decision",
            "human_override_reason",
            "human_override_by",
            "human_override_at",
            "created_at",
        )


class DomainScanReadSerializer(serializers.ModelSerializer):
    registrar = serializers.StringRelatedField()

    class Meta:
        model = DomainScan
        fields = (
            "domain",
            "risk_score",
            "recommendation",
            "summary",
            "risk_level",
            "analyzer_version",
            "registrar",
            "raw_result",
        )


class SubmissionReadSerializer(serializers.ModelSerializer):
    submission_id = serializers.UUIDField(source="id", read_only=True)
    organization_slug = serializers.CharField(source="organization.slug", read_only=True)
    verdict = VerdictReadSerializer(read_only=True)
    domain_scan = DomainScanReadSerializer(read_only=True)
    network_matches = serializers.SerializerMethodField()

    class Meta:
        model = Submission
        fields = (
            "submission_id",
            "organization_slug",
            "status",
            "domain",
            "contact_email_raw",
            "contact_name_raw",
            "contact_phone_raw",
            "submitter_ip_raw",
            "device_fingerprint_raw",
            "external_ref",
            "metadata",
            "created_at",
            "started_at",
            "completed_at",
            "error",
            "domain_scan",
            "verdict",
            "network_matches",
        )

    def get_network_matches(self, obj: Submission) -> dict:
        """Render aggregated fingerprint-based cross-customer reputation context."""
        # Import lazily so Phase 2 dependencies don't load at module import time.
        from apps.fingerprints.services import render_network_matches

        return render_network_matches(obj)


class FeedbackCreateSerializer(serializers.Serializer):
    """
    Input for POST /api/v1/submissions/{id}/feedback.
    """

    reported_as = serializers.ChoiceField(
        choices=[
            Feedback.REPORT_FALSE_POSITIVE,
            Feedback.REPORT_FALSE_NEGATIVE,
            Feedback.REPORT_CONFIRMED,
        ]
    )
    reason_code = serializers.CharField(required=False, allow_blank=True, max_length=50)
    notes = serializers.CharField(required=False, allow_blank=True)
    reported_by = serializers.CharField(required=False, allow_blank=True, max_length=200)


class FeedbackReadSerializer(serializers.ModelSerializer):
    feedback_id = serializers.IntegerField(source="id", read_only=True)
    submission_id = serializers.UUIDField(source="submission.id", read_only=True)

    class Meta:
        model = Feedback
        fields = (
            "feedback_id",
            "submission_id",
            "reported_as",
            "reason_code",
            "notes",
            "reported_by",
            "created_at",
        )
