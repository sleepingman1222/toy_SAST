import hashlib
import logging
import shutil
import time
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
from ..constants import REPOSITORY_ATTEMPT_LEASE_SECONDS
from .repository_runtime import (
    ProcessOwnership,
    process_group_belongs_to_repository_attempt,
    terminate_process_group,
)
from .repository_state import (
    _lock_run_and_execution,
    _new_outbox,
    dispatch_repository_outboxes,
)
from .source_snapshot import get_analysis_workspace_run_root


logger = logging.getLogger(__name__)


def _remove_tree(path):
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return False
    return True


def _unlink_file(path):
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


_process_group_belongs_to_attempt = process_group_belongs_to_repository_attempt


def _process_ownership(attempt, execution):
    outcome = _process_group_belongs_to_attempt(attempt, execution)
    # Retain a narrow compatibility seam for tests and deployments that
    # patched the former boolean ownership probe during rolling upgrades.
    if outcome is True:
        return ProcessOwnership.OWNED
    if outcome is False:
        return ProcessOwnership.FOREIGN
    return outcome


def _audit_cleanup_failure(path, error):
    logger.error(
        "repository orphan cleanup failed",
        extra={"workspace_path": str(path), "error": str(error)[:500]},
    )


def _fail_analysis_run(run, now, failure_reason):
    run.status = AnalysisRun.Status.FAILED
    run.completed_at = now
    run.failure_reason = failure_reason
    run.save(
        update_fields=[
            "status",
            "completed_at",
            "failure_reason",
            "updated_at",
        ]
    )


def _recover_engine_attempt(attempt_id, now):
    failure_reason = "LEASE_EXPIRED"
    execution_id = (
        ScanAttempt.objects.only("execution_id").get(pk=attempt_id).execution_id
    )
    with transaction.atomic():
        run, execution = _lock_run_and_execution(execution_id)
        attempt = ScanAttempt.objects.select_for_update().get(pk=attempt_id)
        if (
            attempt.status != ScanAttempt.Status.RUNNING
            or attempt.lease_expires_at > now
        ):
            return False
        # Revalidate database and OS ownership while the execution and attempt
        # are locked, then stop the group before publishing a retry. A reused
        # group ID is not signalled unless all visible members remain in this
        # run's immutable snapshot.
        ownership = _process_ownership(attempt, execution)
        if ownership == ProcessOwnership.UNVERIFIABLE:
            return False
        if ownership == ProcessOwnership.OWNED:
            if terminate_process_group(attempt.process_group_id) is False:
                return False
        ready_artifact = execution.artifacts.filter(
            attempt=attempt,
            kind=ScanArtifact.Kind.SEMGREP_JSON,
            state=ScanArtifact.State.READY,
            is_canonical=True,
        ).exists()
        if ready_artifact:
            attempt.status = ScanAttempt.Status.COMPLETED
            attempt.completed_at = now
            attempt.failure_reason = ""
            attempt.save(
                update_fields=[
                    "status",
                    "completed_at",
                    "failure_reason",
                    "updated_at",
                ]
            )
            execution.status = ScanExecution.Status.NORMALIZATION_PENDING
            execution.status_reason = "ARTIFACT_RECOVERED"
            execution.save(
                update_fields=["status", "status_reason", "updated_at"]
            )
            if not execution.dispatch_outboxes.filter(
                kind=ScanDispatchOutbox.Kind.NORMALIZATION,
                status__in=(
                    ScanDispatchOutbox.Status.PENDING,
                    ScanDispatchOutbox.Status.PUBLISHED,
                ),
            ).exists():
                dispatch_no = (
                    execution.dispatch_outboxes.filter(
                        kind=ScanDispatchOutbox.Kind.NORMALIZATION
                    ).count()
                    + 1
                )
                _new_outbox(
                    execution,
                    ScanDispatchOutbox.Kind.NORMALIZATION,
                    dispatch_no,
                )
            return True
        attempt.status = ScanAttempt.Status.WORKER_LOST
        attempt.completed_at = now
        attempt.failure_reason = failure_reason
        attempt.save(
            update_fields=[
                "status",
                "completed_at",
                "failure_reason",
                "updated_at",
            ]
        )
        if execution.retry_count < execution.max_retries:
            execution.retry_count += 1
            execution.status = ScanExecution.Status.RETRY_PENDING
            dispatch_no = (
                execution.dispatch_outboxes.filter(kind="engine").count() + 1
            )
            _new_outbox(
                execution,
                ScanDispatchOutbox.Kind.ENGINE,
                dispatch_no,
            )
        else:
            execution.status = ScanExecution.Status.FAILED
            execution.completed_at = now
            _fail_analysis_run(run, now, failure_reason)
        execution.status_reason = failure_reason
        execution.save(
            update_fields=[
                "status",
                "retry_count",
                "status_reason",
                "completed_at",
                "updated_at",
            ]
        )
        return True


def _recover_normalization_attempt(attempt_id, now):
    failure_reason = "NORMALIZATION_LEASE_EXPIRED"
    execution_id = (
        ScanNormalizationAttempt.objects.only("execution_id")
        .get(pk=attempt_id)
        .execution_id
    )
    with transaction.atomic():
        run, execution = _lock_run_and_execution(execution_id)
        attempt = ScanNormalizationAttempt.objects.select_for_update().get(
            pk=attempt_id
        )
        if (
            attempt.status != ScanNormalizationAttempt.Status.RUNNING
            or attempt.lease_expires_at > now
        ):
            return False
        attempt.status = ScanNormalizationAttempt.Status.WORKER_LOST
        attempt.completed_at = now
        attempt.failure_reason = failure_reason
        attempt.save(
            update_fields=[
                "status",
                "completed_at",
                "failure_reason",
                "updated_at",
            ]
        )
        if execution.normalization_retry_count < execution.max_normalization_retries:
            execution.normalization_retry_count += 1
            execution.status = ScanExecution.Status.NORMALIZATION_PENDING
            dispatch_no = (
                execution.dispatch_outboxes.filter(kind="normalization").count() + 1
            )
            _new_outbox(
                execution,
                ScanDispatchOutbox.Kind.NORMALIZATION,
                dispatch_no,
            )
        else:
            execution.status = ScanExecution.Status.FAILED
            execution.completed_at = now
            _fail_analysis_run(run, now, failure_reason)
        execution.status_reason = failure_reason
        execution.save(
            update_fields=[
                "status",
                "normalization_retry_count",
                "status_reason",
                "completed_at",
                "updated_at",
            ]
        )
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
            try:
                with transaction.atomic():
                    run, execution = _lock_run_and_execution(
                        artifact.execution_id
                    )
                    locked = ScanArtifact.objects.select_for_update().get(
                        pk=artifact.pk
                    )
                    if (
                        locked.state != ScanArtifact.State.READY
                        or not locked.is_canonical
                    ):
                        continue
                    locked.state = ScanArtifact.State.INVALID
                    locked.is_canonical = False
                    locked.save(
                        update_fields=["state", "is_canonical", "updated_at"]
                    )
                    reason = "ARTIFACT_INVALID"
                    failed_at = timezone.now()
                    execution_was_completed = (
                        execution.status == ScanExecution.Status.COMPLETED
                    )
                    if not execution_was_completed:
                        execution.normalization_attempts.filter(
                            status=ScanNormalizationAttempt.Status.RUNNING
                        ).update(
                            status=ScanNormalizationAttempt.Status.FAILED,
                            completed_at=failed_at,
                            failure_reason=reason,
                        )
                        execution.dispatch_outboxes.exclude(
                            status=ScanDispatchOutbox.Status.CANCELLED
                        ).update(status=ScanDispatchOutbox.Status.CANCELLED)
                    if execution.status not in (
                        ScanExecution.Status.COMPLETED,
                        ScanExecution.Status.FAILED,
                        ScanExecution.Status.CANCELLED,
                    ):
                        execution.status = ScanExecution.Status.FAILED
                        execution.status_reason = reason
                        execution.completed_at = failed_at
                        execution.save(
                            update_fields=[
                                "status",
                                "status_reason",
                                "completed_at",
                                "updated_at",
                            ]
                        )
                    if run.status not in (
                        AnalysisRun.Status.COMPLETED,
                        AnalysisRun.Status.FAILED,
                        AnalysisRun.Status.CANCELLED,
                    ):
                        run.status = AnalysisRun.Status.FAILED
                        run.failure_reason = reason
                        run.completed_at = failed_at
                        run.save(
                            update_fields=[
                                "status",
                                "failure_reason",
                                "completed_at",
                                "updated_at",
                            ]
                        )
                    invalidated += 1
            except (
                AnalysisRun.DoesNotExist,
                ScanArtifact.DoesNotExist,
                ScanExecution.DoesNotExist,
            ):
                continue

    workspace_base = Path(settings.MEDIA_ROOT) / "analysis_workspaces"
    orphaned = 0
    stale_files = 0
    cleanup_failures = 0
    if workspace_base.is_dir():
        for directory in workspace_base.glob("run_*"):
            try:
                run_id = int(directory.name.removeprefix("run_"))
            except ValueError:
                continue
            if not AnalysisRun.objects.filter(pk=run_id).exists():
                try:
                    orphaned += int(_remove_tree(directory))
                except OSError as error:
                    cleanup_failures += 1
                    _audit_cleanup_failure(directory, error)
                    raise
                continue
            artifact_root = directory / "artifacts"
            if not artifact_root.is_dir():
                continue
            cutoff = time.time() - (REPOSITORY_ATTEMPT_LEASE_SECONDS * 2)
            temporary_files = sorted(
                artifact_root.glob(".semgrep-*"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            for index, path in enumerate(temporary_files):
                if index >= 2 or path.stat().st_mtime < cutoff:
                    try:
                        stale_files += int(_unlink_file(path))
                    except OSError as error:
                        cleanup_failures += 1
                        _audit_cleanup_failure(path, error)
                        raise
            deleted = list(
                ScanArtifact.objects.filter(
                    execution__analysis_run_id=run_id,
                    state=ScanArtifact.State.DELETED,
                )
                .exclude(relative_path="")
                .values_list("relative_path", flat=True)
            )
            artifact_root_resolved = artifact_root.resolve(strict=True)
            for relative in deleted:
                try:
                    path = (directory / relative).resolve(strict=True)
                except FileNotFoundError:
                    continue
                try:
                    path.relative_to(artifact_root_resolved)
                    stale_files += int(_unlink_file(path))
                except (OSError, ValueError) as error:
                    cleanup_failures += 1
                    _audit_cleanup_failure(path, error)
                    if isinstance(error, OSError):
                        raise
            referenced = set(
                ScanArtifact.objects.filter(execution__analysis_run_id=run_id)
                .exclude(state=ScanArtifact.State.DELETED)
                .exclude(relative_path="")
                .values_list("relative_path", flat=True)
            )
            for path in artifact_root.glob("semgrep-attempt-*.json"):
                relative = path.relative_to(directory).as_posix()
                if relative not in referenced and path.stat().st_mtime < cutoff:
                    try:
                        stale_files += int(_unlink_file(path))
                    except OSError as error:
                        cleanup_failures += 1
                        _audit_cleanup_failure(path, error)
                        raise
    return {
        "invalidated_artifacts": invalidated,
        "removed_orphans": orphaned,
        "removed_stale_files": stale_files,
        "cleanup_failures": cleanup_failures,
    }


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
