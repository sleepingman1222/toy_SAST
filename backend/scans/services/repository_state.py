import hashlib
import json
import uuid
from datetime import timedelta
from pathlib import Path

from celery import current_app
from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from ..constants import (
    MAX_ANALYZABLE_FILE_BYTES,
    REPOSITORY_ATTEMPT_LEASE_SECONDS,
    REPOSITORY_SCAN_JOBS,
    REPOSITORY_SCAN_MAX_MEMORY_MIB,
    REPOSITORY_SCAN_TIMEOUT_SECONDS,
    REPOSITORY_ENGINE_TASK_NAME,
    REPOSITORY_MAX_TARGET_BYTES,
    REPOSITORY_NORMALIZATION_TASK_NAME,
    REPOSITORY_OUTBOX_CLAIM_SECONDS,
)
from ..models import (
    AnalysisRun,
    ScanArtifact,
    ScanAttempt,
    ScanDispatchOutbox,
    ScanExecution,
    ScanNormalizationAttempt,
)
from .repository_runtime import (
    SEMGREP_PINNED_VERSION,
    process_group_belongs_to_repository_attempt,
    terminate_process_group,
)
from .semgrep_executor import get_semgrep_rule_path


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


def _canonical_digest(payload):
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repository_execution_digests(languages):
    planned_languages = list(languages)
    canonical_languages = sorted(set(planned_languages))
    rules = []
    for language in canonical_languages:
        rule_root = Path(get_semgrep_rule_path(language)).resolve(strict=True)
        rule_paths = sorted(
            path for path in rule_root.rglob("*") if path.is_file()
        )
        for rule_path in rule_paths:
            rules.append(
                {
                    "language": language,
                    "path": rule_path.relative_to(rule_root).as_posix(),
                    "content_sha256": _file_digest(rule_path),
                }
            )
    ruleset_digest = _canonical_digest(
        {
            "schema_version": 1,
            "languages": canonical_languages,
            "rules": rules,
        }
    )
    options_digest = _canonical_digest(
        {
            "schema_version": 1,
            "engine": "semgrep",
            "engine_version": SEMGREP_PINNED_VERSION,
            "languages": canonical_languages,
            "options": {
                "json": True,
                "metrics": "off",
                "jobs": REPOSITORY_SCAN_JOBS,
                "timeout_seconds": REPOSITORY_SCAN_TIMEOUT_SECONDS,
                "max_memory_mib": REPOSITORY_SCAN_MAX_MEMORY_MIB,
                "max_target_bytes": REPOSITORY_MAX_TARGET_BYTES,
            },
        }
    )
    return planned_languages, ruleset_digest, options_digest


def _new_outbox(execution, kind, dispatch_no):
    task_name = (
        REPOSITORY_ENGINE_TASK_NAME
        if kind == ScanDispatchOutbox.Kind.ENGINE
        else REPOSITORY_NORMALIZATION_TASK_NAME
    )
    event_key = uuid.uuid4()
    return ScanDispatchOutbox.objects.create(
        execution=execution,
        kind=kind,
        dispatch_no=dispatch_no,
        event_key=event_key,
        task_name=task_name,
        payload={
            "execution_id": execution.id,
            "event_key": str(event_key),
        },
        deterministic_task_id=uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"toy-sast:{execution.id}:{kind}:{dispatch_no}",
        ),
    )


def _lock_run_and_execution(execution_id):
    """Lock repository-v2 lifecycle rows in the canonical parent-first order."""
    analysis_run_id = (
        ScanExecution.objects.only("analysis_run_id")
        .get(pk=execution_id)
        .analysis_run_id
    )
    run = AnalysisRun.objects.select_for_update().get(pk=analysis_run_id)
    execution = ScanExecution.objects.select_for_update().get(pk=execution_id)
    return run, execution


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

        planned_languages, ruleset_digest, options_digest = (
            _repository_execution_digests(languages)
        )

        execution = ScanExecution.objects.create(
            analysis_run=run,
            sequence=1,
            scope_kind="repository",
            scope_root=".",
            status=ScanExecution.Status.QUEUED,
            capabilities=CE_CAPABILITIES,
            snapshot_digest=manifest["snapshot_digest"],
            ruleset_digest=ruleset_digest,
            options_digest=options_digest,
            discovered_supported=sum(
                1 for item in manifest["inventory"]
                if item.get("kind") == "supported_source"
            ),
        )
        _new_outbox(execution, ScanDispatchOutbox.Kind.ENGINE, 1)
        run.status = AnalysisRun.Status.RUNNING
        run.analysis_languages = planned_languages
        run.analysis_language = (
            planned_languages[0] if len(planned_languages) == 1 else ""
        )
        run.snapshot_digest = manifest["snapshot_digest"]
        run.save(update_fields=[
            "status", "analysis_languages", "analysis_language",
            "snapshot_digest", "updated_at",
        ])
        return execution


def dispatch_repository_outboxes(batch_size=50):
    now = timezone.now()
    exhausted = ScanDispatchOutbox.objects.filter(
        publish_attempts__gte=models_f("max_publish_attempts"),
    ).filter(
        models_q(
            status=ScanDispatchOutbox.Status.PENDING,
            available_at__lte=now,
        )
        | models_q(
            status=ScanDispatchOutbox.Status.PUBLISHED,
            claimed_at__isnull=True,
            claim_deadline_at__lte=now,
        )
    )
    for outbox in exhausted:
        with transaction.atomic():
            run, execution = _lock_run_and_execution(outbox.execution_id)
            outbox = ScanDispatchOutbox.objects.select_for_update().get(
                pk=outbox.pk
            )
            if execution.status in (ScanExecution.Status.COMPLETED, ScanExecution.Status.FAILED, ScanExecution.Status.CANCELLED):
                continue
            published_expired = (
                outbox.status == ScanDispatchOutbox.Status.PUBLISHED
                and outbox.claimed_at is None
                and outbox.claim_deadline_at is not None
                and outbox.claim_deadline_at <= now
            )
            pending_expired = (
                outbox.status == ScanDispatchOutbox.Status.PENDING
                and outbox.available_at <= now
            )
            if (
                outbox.publish_attempts < outbox.max_publish_attempts
                or not (published_expired or pending_expired)
            ):
                continue
            active = (
                execution.attempts.filter(
                    status=ScanAttempt.Status.RUNNING
                ).exists()
                if outbox.kind == ScanDispatchOutbox.Kind.ENGINE
                else execution.normalization_attempts.filter(
                    status=ScanNormalizationAttempt.Status.RUNNING
                ).exists()
            )
            if active:
                continue
            execution.status = ScanExecution.Status.FAILED
            execution.status_reason = "DISPATCH_UNCLAIMED"
            execution.completed_at = now
            execution.save(update_fields=["status", "status_reason", "completed_at", "updated_at"])
            run.status = AnalysisRun.Status.FAILED
            run.completed_at = now
            run.failure_reason = "DISPATCH_UNCLAIMED"
            run.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
    candidates = ScanDispatchOutbox.objects.filter(
        publish_attempts__lt=models_f("max_publish_attempts"),
        execution__status__in=[
            ScanExecution.Status.QUEUED,
            ScanExecution.Status.RETRY_PENDING,
            ScanExecution.Status.NORMALIZATION_PENDING,
        ],
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
        try:
            with transaction.atomic():
                _, execution = _lock_run_and_execution(candidate.execution_id)
                outbox = ScanDispatchOutbox.objects.select_for_update().get(
                    pk=candidate.pk
                )
                pending_due = (
                    outbox.status == ScanDispatchOutbox.Status.PENDING
                    and outbox.available_at <= now
                )
                published_due = (
                    outbox.status == ScanDispatchOutbox.Status.PUBLISHED
                    and outbox.claimed_at is None
                    and outbox.claim_deadline_at is not None
                    and outbox.claim_deadline_at <= now
                )
                expected_statuses = (
                    (
                        ScanExecution.Status.QUEUED,
                        ScanExecution.Status.RETRY_PENDING,
                    )
                    if outbox.kind == ScanDispatchOutbox.Kind.ENGINE
                    else (ScanExecution.Status.NORMALIZATION_PENDING,)
                )
                if (
                    outbox.publish_attempts >= outbox.max_publish_attempts
                    or execution.status not in expected_statuses
                    or not (pending_due or published_due)
                ):
                    continue
                if (
                    outbox.kind == ScanDispatchOutbox.Kind.NORMALIZATION
                    and not execution.artifacts.filter(
                        kind=ScanArtifact.Kind.SEMGREP_JSON,
                        state=ScanArtifact.State.READY,
                        is_canonical=True,
                    ).exists()
                ):
                    continue
                active = (
                    execution.attempts.filter(status=ScanAttempt.Status.RUNNING).exists()
                    if outbox.kind == ScanDispatchOutbox.Kind.ENGINE
                    else execution.normalization_attempts.filter(
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
        except Exception as error:
            with transaction.atomic():
                _, execution = _lock_run_and_execution(candidate.execution_id)
                outbox = ScanDispatchOutbox.objects.select_for_update().get(
                    pk=candidate.pk
                )
                if execution.status in (
                    ScanExecution.Status.COMPLETED,
                    ScanExecution.Status.FAILED,
                    ScanExecution.Status.CANCELLED,
                ):
                    continue
                outbox.publish_attempts = min(
                    outbox.publish_attempts + 1,
                    outbox.max_publish_attempts,
                )
                outbox.last_error = str(error)[:2000]
                delay = min(2 ** outbox.publish_attempts, REPOSITORY_OUTBOX_CLAIM_SECONDS)
                if outbox.status == ScanDispatchOutbox.Status.PUBLISHED:
                    outbox.claim_deadline_at = now + timedelta(seconds=delay)
                else:
                    outbox.available_at = now + timedelta(seconds=delay)
                outbox.save(update_fields=[
                    "publish_attempts", "last_error", "available_at",
                    "claim_deadline_at", "updated_at",
                ])
    return {"published_count": published}


# Small wrappers keep the queryset expression imports local and make this file
# importable by migration tooling that stubs optional Celery components.
def models_q(*args, **kwargs):
    from django.db.models import Q
    return Q(*args, **kwargs)


def models_f(name):
    from django.db.models import F
    return F(name)


def claim_repository_engine(execution_id, event_key, celery_task_id=""):
    now = timezone.now()
    with transaction.atomic():
        run, execution = _lock_run_and_execution(execution_id)
        if run.status != AnalysisRun.Status.RUNNING:
            return None
        if execution.status not in (
            ScanExecution.Status.QUEUED,
            ScanExecution.Status.RETRY_PENDING,
        ):
            return None
        active = execution.attempts.filter(status=ScanAttempt.Status.RUNNING).first()
        if active:
            return None
        outboxes = execution.dispatch_outboxes.select_for_update().filter(
            kind=ScanDispatchOutbox.Kind.ENGINE,
            status=ScanDispatchOutbox.Status.PUBLISHED,
            claimed_at__isnull=True,
        )
        outboxes = outboxes.filter(event_key=event_key)
        outbox = outboxes.order_by("dispatch_no").first()
        if outbox is None:
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
        if outbox:
            outbox.claimed_at = now
            outbox.claimed_attempt = attempt
            outbox.claimed_normalization_attempt = None
            outbox.save(update_fields=[
                "claimed_at",
                "claimed_attempt",
                "claimed_normalization_attempt",
                "updated_at",
            ])
        return attempt


def claim_repository_normalization(execution_id, event_key):
    now = timezone.now()
    with transaction.atomic():
        run, execution = _lock_run_and_execution(execution_id)
        if run.status != AnalysisRun.Status.RUNNING:
            return None
        if execution.status != ScanExecution.Status.NORMALIZATION_PENDING:
            return None
        if not execution.artifacts.filter(
            kind="semgrep_json", state="ready", is_canonical=True
        ).exists():
            raise RepositoryStateError("normalization requires a ready canonical artifact")
        if execution.normalization_attempts.filter(status="running").exists():
            return None
        outboxes = execution.dispatch_outboxes.select_for_update().filter(
            kind=ScanDispatchOutbox.Kind.NORMALIZATION,
            status=ScanDispatchOutbox.Status.PUBLISHED,
            claimed_at__isnull=True,
        )
        outboxes = outboxes.filter(event_key=event_key)
        outbox = outboxes.order_by("dispatch_no").first()
        if outbox is None:
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
        if outbox:
            outbox.claimed_at = now
            outbox.claimed_normalization_attempt = attempt
            outbox.save(update_fields=[
                "claimed_at",
                "claimed_normalization_attempt",
                "updated_at",
            ])
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
        run, execution = _lock_run_and_execution(execution_id)
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
            run.status = AnalysisRun.Status.FAILED
            run.completed_at = now
            run.failure_reason = str(reason)[:2000]
            run.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
        execution.status_reason = str(reason)[:80]
        execution.save(update_fields=["status", "retry_count", "status_reason", "completed_at", "updated_at"])


def fail_repository_normalization(execution_id, attempt_id, reason, retryable=True):
    now = timezone.now()
    with transaction.atomic():
        run, execution = _lock_run_and_execution(execution_id)
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
            run.status = AnalysisRun.Status.FAILED
            run.completed_at = now
            run.failure_reason = str(reason)[:2000]
            run.save(update_fields=["status", "completed_at", "failure_reason", "updated_at"])
        execution.status_reason = str(reason)[:80]
        execution.save(update_fields=[
            "status", "normalization_retry_count", "status_reason", "completed_at", "updated_at",
        ])


def cancel_repository_execution(execution_id):
    now = timezone.now()
    process_group_attempts = []
    with transaction.atomic():
        run, execution = _lock_run_and_execution(execution_id)
        if execution.status in (ScanExecution.Status.COMPLETED, ScanExecution.Status.FAILED, ScanExecution.Status.CANCELLED):
            return False
        attempts = list(execution.attempts.select_for_update().filter(status="running"))
        for attempt in attempts:
            if attempt.process_group_id:
                process_group_attempts.append((attempt, execution))
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
        run.status = AnalysisRun.Status.CANCELLED
        run.completed_at = now
        run.save(update_fields=["status", "completed_at", "updated_at"])
    for attempt, owned_execution in process_group_attempts:
        if process_group_belongs_to_repository_attempt(attempt, owned_execution):
            terminate_process_group(attempt.process_group_id)
    return True
