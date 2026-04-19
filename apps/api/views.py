import logging

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.submissions.models import Submission

from .serializers import (
    FeedbackCreateSerializer,
    FeedbackReadSerializer,
    SubmissionCreateSerializer,
    SubmissionReadSerializer,
)
from .services import process_submission

logger = logging.getLogger(__name__)


def _wait_flag(request) -> bool:
    return request.query_params.get("wait", "").lower() in ("1", "true", "yes")


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def submissions_list_create(request):
    """
    GET  /api/v1/submissions            — list the caller's org's submissions
    POST /api/v1/submissions            — create, return {submission_id, status}
    POST /api/v1/submissions?wait=true  — create and block until complete
    """
    api_key = request.user  # ApiKey instance (see apps.organizations.auth)
    organization = api_key.organization

    if request.method == "GET":
        qs = (
            Submission.objects.filter(organization=organization)
            .select_related("verdict", "domain_scan", "organization")
            .order_by("-created_at")[:100]
        )
        return Response({"results": SubmissionReadSerializer(qs, many=True).data})

    serializer = SubmissionCreateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data

    submission = Submission.objects.create(
        organization=organization,
        api_key=api_key,
        domain=data.get("domain") or "",
        contact_email_raw=data.get("contact_email") or "",
        contact_name_raw=data.get("contact_name") or "",
        contact_phone_raw=data.get("contact_phone") or "",
        submitter_ip_raw=data.get("submitter_ip") or None,
        device_fingerprint_raw=data.get("device_fingerprint") or "",
        external_ref=data.get("external_ref") or "",
        metadata=data.get("metadata") or {},
    )

    # Phase 1: processing is always inline. `?wait=true` controls what we return.
    # Phase 2 moves processing to a worker and makes the non-wait path truly async.
    try:
        process_submission(submission)
    except Exception:  # noqa: BLE001 — service also catches; this is belt+suspenders
        logger.exception("submission %s failed at view layer", submission.id)

    submission.refresh_from_db()

    if _wait_flag(request):
        return Response(
            SubmissionReadSerializer(submission).data,
            status=status.HTTP_201_CREATED,
        )

    return Response(
        {"submission_id": str(submission.id), "status": submission.status},
        status=status.HTTP_202_ACCEPTED,
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def signal_catalog(request):
    """
    GET /api/v1/signal-catalog

    Read-only enumeration of every signal the rules engine recognizes +
    the operator set. The Phase 3 console uses this to render dropdowns
    and constrain operator choices to the signal type.
    """
    from apps.risk_profiles.signal_catalog import build_catalog_response
    return Response(build_catalog_response())


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def submission_detail(request, submission_id):
    api_key = request.user
    submission = get_object_or_404(
        Submission.objects.select_related("verdict", "domain_scan", "organization"),
        id=submission_id,
        organization=api_key.organization,
    )
    return Response(SubmissionReadSerializer(submission).data)


@api_view(["POST", "GET"])
@permission_classes([IsAuthenticated])
def submission_feedback(request, submission_id):
    """
    POST /api/v1/submissions/{id}/feedback  — report verdict correctness
    GET  /api/v1/submissions/{id}/feedback  — list feedback entries for this submission

    Feedback updates the network-wide fingerprint reputation:
      * false_positive shifts reputation toward approve
      * false_negative shifts reputation toward flag
      * confirmed reinforces existing signal (adds confidence)
    """
    from apps.feedback.models import Feedback
    from apps.fingerprints.services import apply_feedback

    api_key = request.user
    submission = get_object_or_404(
        Submission.objects.select_related("organization"),
        id=submission_id,
        organization=api_key.organization,
    )

    if request.method == "GET":
        entries = submission.feedback.order_by("-created_at")
        return Response({"results": FeedbackReadSerializer(entries, many=True).data})

    serializer = FeedbackCreateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data

    feedback = Feedback.objects.create(
        organization=api_key.organization,
        submission=submission,
        api_key=api_key,
        reported_as=data["reported_as"],
        reason_code=data.get("reason_code") or "",
        notes=data.get("notes") or "",
        reported_by=data.get("reported_by") or "",
    )

    # Bump reputation counters on the submission's primary fingerprints.
    try:
        apply_feedback(submission, data["reported_as"])
    except Exception:
        logger.exception(
            "reputation update failed for feedback %s (non-fatal; row persisted)",
            feedback.id,
        )

    return Response(
        {
            "feedback": FeedbackReadSerializer(feedback).data,
            "submission": SubmissionReadSerializer(submission).data,
        },
        status=status.HTTP_201_CREATED,
    )
