import hashlib
import shutil
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ..models import (
    AnalysisRun,
    ScanArtifact,
    ScanAttempt,
    ScanDispatchOutbox,
    ScanExecution,
    ScanNormalizationAttempt,
)
from .repository_state import dispatch_repository_outboxes, _new_outbox
from .source_snapshot import get_analysis_workspace_run_root


def _recover_engine_attempt(attempt_id, now):
    with transaction.atomic():
        attempt = ScanAttempt.objects.select_for_update().select_related("execution").get(pk=attempt_id)
        execution = ScanExecution.objects.select_for_update().get(pk=attempt.execution_id)
        if attempt.status != ScanAttempt.Status.RUNNING or attempt.lease_expires_at > now:
            return False
        attempt.status = ScanAttempt.Status.WORKER_LOST
        attempt.completed_at = now
        attempt.failure_reason = "LEASE_EXPIRED"
        attempt.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
        if execution.retry_count < execution.max_retries:
            execution.retry_count += 1
            execution.status = ScanExecution.Status.RETRY_PENDING
            _new_outbox(execution, ScanDispatchOutbox.Kind.ENGINE, execution.dispatch_outboxes.filter(kind="engine").count() + 1)
        else:
            execution.status = ScanExecution.Status.FAILED
            execution.completed_at = now
        execution.status_reason = "LEASE_EXPIRED"
        execution.save(update_fields=["status", "retry_count", "status_reason", "completed_at", "updated_at"])
        return True


def _recover_normalization_attempt(attempt_id, now):
    with transaction.atomic():
        attempt = ScanNormalizationAttempt.objects.select_for_update().select_related("execution").get(pk=attempt_id)
        execution = ScanExecution.objects.select_for_update().get(pk=attempt.execution_id)
        if attempt.status != ScanNormalizationAttempt.Status.RUNNING or attempt.lease_expires_at > now:
            return False
        attempt.status = ScanNormalizationAttempt.Status.WORKER_LOST
        attempt.completed_at = now
        attempt.failure_reason = "LEASE_EXPIRED"
        attempt.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
        if execution.normalization_retry_count < execution.max_normalization_retries:
            execution.normalization_retry_count += 1
            execution.status = ScanExecution.Status.NORMALIZATION_PENDING
            _new_outbox(execution, ScanDispatchOutbox.Kind.NORMALIZATION, execution.dispatch_outboxes.filter(kind="normalization").count() + 1)
        else:
            execution.status = ScanExecution.Status.FAILED
            execution.completed_at = now
        execution.status_reason = "NORMALIZATION_LEASE_EXPIRED"
        execution.save(update_fields=["status", "normalization_retry_count", "status_reason", "completed_at", "updated_at"])
        return True


def reconcile_scan_artifacts():
    invalidated = 0
    for artifact in ScanArtifact.objects.filter(state=ScanArtifact.State.READY, is_canonical=True).select_related("execution"):
        run_root = get_analysis_workspace_run_root(artifact.execution.analysis_run_id)
        try:
            path = (run_root / artifact.relative_path).resolve(strict=True)
            path.relative_to(run_root.resolve(strict=True))
            valid = (
                path.stat().st_size == artifact.size_bytes
                and hashlib.sha256(path.read_bytes()).hexdigest() == artifact.sha256
            )
        except (OSError, ValueError):
            valid = False
        if not valid:
            ScanArtifact.objects.filter(pk=artifact.pk, state=ScanArtifact.State.READY).update(
                state=ScanArtifact.State.INVALID,
                is_canonical=False,
            )
            invalidated += 1

    workspace_base = Path(settings.MEDIA_ROOT) / "analysis_workspaces"
    orphaned = 0
    if workspace_base.is_dir():
        for directory in workspace_base.glob("run_*"):
            try:
                run_id = int(directory.name.removeprefix("run_"))
            except ValueError:
                continue
            if not AnalysisRun.objects.filter(pk=run_id).exists():
                shutil.rmtree(directory, ignore_errors=True)
                orphaned += 1
    return {"invalidated_artifacts": invalidated, "removed_orphans": orphaned}


def run_repository_recovery_cycle():
    now = timezone.now()
    engine = sum(
        _recover_engine_attempt(pk, now)
        for pk in ScanAttempt.objects.filter(status="running", lease_expires_at__lte=now).values_list("pk", flat=True)
    )
    normalization = sum(
        _recover_normalization_attempt(pk, now)
        for pk in ScanNormalizationAttempt.objects.filter(status="running", lease_expires_at__lte=now).values_list("pk", flat=True)
    )
    artifacts = reconcile_scan_artifacts()
    dispatch = dispatch_repository_outboxes()
    return {
        "recovered_engine_attempts": engine,
        "recovered_normalization_attempts": normalization,
        **artifacts,
        **dispatch,
    }
