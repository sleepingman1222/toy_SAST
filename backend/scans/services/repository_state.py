import uuid
import os
import signal
from datetime import timedelta

from celery import current_app
from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from ..constants import (
    MAX_ANALYZABLE_FILE_BYTES,
    REPOSITORY_ATTEMPT_LEASE_SECONDS,
    REPOSITORY_ENGINE_TASK_NAME,
    REPOSITORY_MAX_TARGET_BYTES,
    REPOSITORY_NORMALIZATION_TASK_NAME,
    REPOSITORY_OUTBOX_CLAIM_SECONDS,
)
from ..models import (
    AnalysisRun,
    ScanAttempt,
    ScanDispatchOutbox,
    ScanExecution,
    ScanNormalizationAttempt,
)


CE_CAPABILITIES = {
    "engine_mode": "ce",
    "repository_context_present": True,
    "cross_file_parsing": False,
    "cross_function_dataflow": False,
    "interfile_dataflow": False,
    "interfile_taint": False,
    "pro_engine": False,
}


class RepositoryStateError(RuntimeError):
    pass


def _new_outbox(execution, kind, dispatch_no):
    task_name = (
        REPOSITORY_ENGINE_TASK_NAME
        if kind == ScanDispatchOutbox.Kind.ENGINE
        else REPOSITORY_NORMALIZATION_TASK_NAME
    )
    return ScanDispatchOutbox.objects.create(
        execution=execution,
        kind=kind,
        dispatch_no=dispatch_no,
        task_name=task_name,
        payload={"execution_id": execution.id},
        deterministic_task_id=uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"toy-sast:{execution.id}:{kind}:{dispatch_no}",
        ),
    )


def plan_repository_execution(analysis_run_id, manifest, languages):
    if MAX_ANALYZABLE_FILE_BYTES != REPOSITORY_MAX_TARGET_BYTES:
        raise RepositoryStateError("snapshot and engine target byte limits differ")

    with transaction.atomic():
        run = AnalysisRun.objects.select_for_update().get(pk=analysis_run_id)
        if run.pipeline_version != AnalysisRun.PipelineVersion.REPOSITORY_V2:
            raise RepositoryStateError("repository planner received a chunk-v1 run")
        if run.status != AnalysisRun.Status.PLANNING:
            existing = ScanExecution.objects.filter(analysis_run=run).first()
            if existing:
                return existing
            raise RepositoryStateError("repository run is not planning")

        execution = ScanExecution.objects.create(
            analysis_run=run,
            sequence=1,
            scope_kind="repository",
            scope_root=".",
            status=ScanExecution.Status.QUEUED,
            capabilities=CE_CAPABILITIES,
            snapshot_digest=manifest["snapshot_digest"],
            discovered_supported=sum(
                1 for item in manifest["inventory"]
                if item.get("kind") == "supported_source"
            ),
        )
        _new_outbox(execution, ScanDispatchOutbox.Kind.ENGINE, 1)
        run.status = AnalysisRun.Status.RUNNING
        run.analysis_languages = list(languages)
        run.analysis_language = languages[0] if len(languages) == 1 else ""
        run.snapshot_digest = manifest["snapshot_digest"]
        run.save(update_fields=[
            "status", "analysis_languages", "analysis_language",
            "snapshot_digest", "updated_at",
        ])
        return execution


def dispatch_repository_outboxes(batch_size=50):
    now = timezone.now()
    exhausted = ScanDispatchOutbox.objects.filter(
        status=ScanDispatchOutbox.Status.PUBLISHED,
        claimed_at__isnull=True,
        claim_deadline_at__lte=now,
        publish_attempts__gte=models_f("max_publish_attempts"),
    ).select_related("execution", "execution__analysis_run")
    for outbox in exhausted:
        with transaction.atomic():
            execution = ScanExecution.objects.select_for_update().get(pk=outbox.execution_id)
            if execution.status in (ScanExecution.Status.COMPLETED, ScanExecution.Status.FAILED, ScanExecution.Status.CANCELLED):
                continue
            execution.status = ScanExecution.Status.FAILED
            execution.status_reason = "DISPATCH_UNCLAIMED"
            execution.completed_at = now
            execution.save(update_fields=["status", "status_reason", "completed_at", "updated_at"])
            run = AnalysisRun.objects.select_for_update().get(pk=execution.analysis_run_id)
            run.status = AnalysisRun.Status.FAILED
            run.completed_at = now
            run.failure_reason = "DISPATCH_UNCLAIMED"
            run.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
    candidates = ScanDispatchOutbox.objects.filter(
        publish_attempts__lt=models_f("max_publish_attempts"),
    ).filter(
        models_q(status=ScanDispatchOutbox.Status.PENDING, available_at__lte=now)
        | models_q(
            status=ScanDispatchOutbox.Status.PUBLISHED,
            claimed_at__isnull=True,
            claim_deadline_at__lte=now,
        )
    ).order_by("created_at")[:batch_size]
    published = 0
    for candidate in candidates:
        with transaction.atomic():
            outbox = ScanDispatchOutbox.objects.select_for_update().get(pk=candidate.pk)
            active = (
                outbox.execution.attempts.filter(status=ScanAttempt.Status.RUNNING).exists()
                if outbox.kind == ScanDispatchOutbox.Kind.ENGINE
                else outbox.execution.normalization_attempts.filter(
                    status=ScanNormalizationAttempt.Status.RUNNING
                ).exists()
            )
            if active or outbox.claimed_at is not None:
                continue
            current_app.send_task(
                outbox.task_name,
                kwargs=outbox.payload,
                task_id=str(outbox.deterministic_task_id),
            )
            outbox.status = ScanDispatchOutbox.Status.PUBLISHED
            outbox.publish_attempts += 1
            outbox.published_at = now
            outbox.claim_deadline_at = now + timedelta(seconds=REPOSITORY_OUTBOX_CLAIM_SECONDS)
            outbox.last_error = ""
            outbox.save(update_fields=[
                "status", "publish_attempts", "published_at",
                "claim_deadline_at", "last_error", "updated_at",
            ])
            published += 1
    return {"published_count": published}


# Small wrappers keep the queryset expression imports local and make this file
# importable by migration tooling that stubs optional Celery components.
def models_q(*args, **kwargs):
    from django.db.models import Q
    return Q(*args, **kwargs)


def models_f(name):
    from django.db.models import F
    return F(name)


def claim_repository_engine(execution_id, celery_task_id=""):
    now = timezone.now()
    with transaction.atomic():
        execution = (
            ScanExecution.objects.select_for_update()
            .select_related("analysis_run")
            .get(pk=execution_id)
        )
        if execution.status not in (
            ScanExecution.Status.QUEUED,
            ScanExecution.Status.RETRY_PENDING,
        ):
            return None
        active = execution.attempts.filter(status=ScanAttempt.Status.RUNNING).first()
        if active:
            return None
        attempt_no = (execution.attempts.aggregate(value=Max("attempt_no"))["value"] or 0) + 1
        attempt = ScanAttempt.objects.create(
            execution=execution,
            attempt_no=attempt_no,
            celery_task_id=celery_task_id,
            lease_expires_at=now + timedelta(seconds=REPOSITORY_ATTEMPT_LEASE_SECONDS),
        )
        execution.status = ScanExecution.Status.RUNNING
        execution.started_at = execution.started_at or now
        execution.status_reason = ""
        execution.save(update_fields=["status", "started_at", "status_reason", "updated_at"])
        outbox = execution.dispatch_outboxes.filter(
            kind=ScanDispatchOutbox.Kind.ENGINE,
            status=ScanDispatchOutbox.Status.PUBLISHED,
            claimed_at__isnull=True,
        ).order_by("dispatch_no").first()
        if outbox:
            outbox.claimed_at = now
            outbox.claimed_attempt = attempt
            outbox.save(update_fields=["claimed_at", "claimed_attempt", "updated_at"])
        return attempt


def claim_repository_normalization(execution_id):
    now = timezone.now()
    with transaction.atomic():
        execution = ScanExecution.objects.select_for_update().get(pk=execution_id)
        if execution.status != ScanExecution.Status.NORMALIZATION_PENDING:
            return None
        if not execution.artifacts.filter(
            kind="semgrep_json", state="ready", is_canonical=True
        ).exists():
            raise RepositoryStateError("normalization requires a ready canonical artifact")
        if execution.normalization_attempts.filter(status="running").exists():
            return None
        attempt_no = (
            execution.normalization_attempts.aggregate(value=Max("attempt_no"))["value"] or 0
        ) + 1
        attempt = ScanNormalizationAttempt.objects.create(
            execution=execution,
            attempt_no=attempt_no,
            lease_expires_at=now + timedelta(seconds=REPOSITORY_ATTEMPT_LEASE_SECONDS),
        )
        execution.status = ScanExecution.Status.NORMALIZING
        execution.save(update_fields=["status", "updated_at"])
        outbox = execution.dispatch_outboxes.filter(
            kind=ScanDispatchOutbox.Kind.NORMALIZATION,
            status=ScanDispatchOutbox.Status.PUBLISHED,
            claimed_at__isnull=True,
        ).order_by("dispatch_no").first()
        if outbox:
            outbox.claimed_at = now
            outbox.save(update_fields=["claimed_at", "updated_at"])
        return attempt


def enqueue_normalization(execution, attempt):
    now = timezone.now()
    with transaction.atomic():
        execution = ScanExecution.objects.select_for_update().get(pk=execution.pk)
        attempt = ScanAttempt.objects.select_for_update().get(pk=attempt.pk)
        if attempt.status != ScanAttempt.Status.RUNNING:
            raise RepositoryStateError("engine attempt ownership is stale")
        attempt.status = ScanAttempt.Status.COMPLETED
        attempt.completed_at = now
        attempt.save(update_fields=["status", "completed_at", "updated_at"])
        execution.status = ScanExecution.Status.NORMALIZATION_PENDING
        execution.engine_version = "1.175.0"
        execution.save(update_fields=["status", "engine_version", "updated_at"])
        dispatch_no = execution.dispatch_outboxes.filter(
            kind=ScanDispatchOutbox.Kind.NORMALIZATION
        ).count() + 1
        _new_outbox(execution, ScanDispatchOutbox.Kind.NORMALIZATION, dispatch_no)


def fail_repository_engine(execution_id, attempt_id, reason, retryable=True):
    now = timezone.now()
    with transaction.atomic():
        execution = ScanExecution.objects.select_for_update().get(pk=execution_id)
        attempt = ScanAttempt.objects.select_for_update().get(pk=attempt_id)
        if attempt.status != ScanAttempt.Status.RUNNING:
            return
        attempt.status = ScanAttempt.Status.FAILED
        attempt.completed_at = now
        attempt.failure_reason = str(reason)[:2000]
        attempt.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
        if retryable and execution.retry_count < execution.max_retries:
            execution.retry_count += 1
            execution.status = ScanExecution.Status.RETRY_PENDING
            dispatch_no = execution.dispatch_outboxes.filter(kind="engine").count() + 1
            _new_outbox(execution, ScanDispatchOutbox.Kind.ENGINE, dispatch_no)
        else:
            execution.status = ScanExecution.Status.FAILED
            execution.completed_at = now
            execution.analysis_run.status = AnalysisRun.Status.FAILED
            execution.analysis_run.completed_at = now
            execution.analysis_run.failure_reason = str(reason)[:2000]
            execution.analysis_run.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
        execution.status_reason = str(reason)[:80]
        execution.save(update_fields=["status", "retry_count", "status_reason", "completed_at", "updated_at"])


def fail_repository_normalization(execution_id, attempt_id, reason, retryable=True):
    now = timezone.now()
    with transaction.atomic():
        execution = ScanExecution.objects.select_for_update().get(pk=execution_id)
        attempt = ScanNormalizationAttempt.objects.select_for_update().get(pk=attempt_id)
        if attempt.status != ScanNormalizationAttempt.Status.RUNNING:
            return
        attempt.status = ScanNormalizationAttempt.Status.FAILED
        attempt.completed_at = now
        attempt.failure_reason = str(reason)[:2000]
        attempt.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
        if retryable and execution.normalization_retry_count < execution.max_normalization_retries:
            execution.normalization_retry_count += 1
            execution.status = ScanExecution.Status.NORMALIZATION_PENDING
            dispatch_no = execution.dispatch_outboxes.filter(kind="normalization").count() + 1
            _new_outbox(execution, ScanDispatchOutbox.Kind.NORMALIZATION, dispatch_no)
        else:
            execution.status = ScanExecution.Status.FAILED
            execution.completed_at = now
            execution.analysis_run.status = AnalysisRun.Status.FAILED
            execution.analysis_run.completed_at = now
            execution.analysis_run.failure_reason = str(reason)[:2000]
            execution.analysis_run.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
        execution.status_reason = str(reason)[:80]
        execution.save(update_fields=[
            "status", "normalization_retry_count", "status_reason", "completed_at", "updated_at",
        ])


def cancel_repository_execution(execution_id):
    now = timezone.now()
    process_groups = []
    with transaction.atomic():
        execution = ScanExecution.objects.select_for_update().select_related("analysis_run").get(pk=execution_id)
        if execution.status in (ScanExecution.Status.COMPLETED, ScanExecution.Status.FAILED, ScanExecution.Status.CANCELLED):
            return False
        attempts = list(execution.attempts.select_for_update().filter(status="running"))
        for attempt in attempts:
            if attempt.process_group_id:
                process_groups.append(attempt.process_group_id)
            attempt.status = ScanAttempt.Status.CANCELLED
            attempt.completed_at = now
            attempt.save(update_fields=["status", "completed_at", "updated_at"])
        for attempt in execution.normalization_attempts.select_for_update().filter(status="running"):
            attempt.status = ScanNormalizationAttempt.Status.CANCELLED
            attempt.completed_at = now
            attempt.save(update_fields=["status", "completed_at", "updated_at"])
        execution.dispatch_outboxes.exclude(status="cancelled").update(status="cancelled")
        execution.status = ScanExecution.Status.CANCELLED
        execution.completed_at = now
        execution.status_reason = "CANCELLED"
        execution.save(update_fields=["status", "completed_at", "status_reason", "updated_at"])
        run = execution.analysis_run
        run.status = AnalysisRun.Status.CANCELLED
        run.completed_at = now
        run.save(update_fields=["status", "completed_at", "updated_at"])
    for group_id in process_groups:
        try:
            os.killpg(group_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
    return True
