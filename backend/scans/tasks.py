# backend/scans/tasks.py

from celery import (
    shared_task,
)
from celery.signals import task_revoked, worker_shutdown

from django.db import (
    transaction,
)

from django.utils import (
    timezone,
)

from .constants import (
    ANALYSIS_CHUNK_TASK_NAME,
    OUTBOX_DISPATCH_BATCH_SIZE,
    SUPPORTED_LANGUAGE_ORDER,
)

from .models import (
    AnalysisChunk,
    AnalysisRun,
    ScanAttempt,
    ScanExecution,
)

from .services.chunk_executor import (
    claim_chunk,
    heartbeat_attempt,
)

from .services.chunk_runtime import (
    ChunkOwnershipLostError,
    NonRetryableChunkError,
    execute_semgrep_with_heartbeat,
    prepare_chunk_execution_target,
    save_attempt_vulnerabilities,
)

from .services.chunk_state_manager import (
    complete_chunk_attempt,
    fail_chunk_attempt,
)

from .services.chunk_planner import (
    plan_analysis_chunks,
)

from .services.chunk_recovery import (
    run_recovery_cycle,
)

from .services.execution_utils import (
    truncate_log,
)

from .services.language_detection import (
    save_detected_languages,
)

from .services.outbox_dispatcher import (
    dispatch_pending_outboxes,
)

from .services.semgrep_executor import (
    get_semgrep_rule_path,
)

from .services.source_acquisition import (
    prepare_analysis_target,
)

from .services.source_snapshot import (
    materialize_analysis_workspace,
)
from .services.repository_manifest import build_repository_manifest
from .services.repository_runtime import (
    ProcessOwnership,
    execute_repository_scan,
    repository_attempt_process_ownership,
    terminate_process_group,
)
from .services.repository_normalization import normalize_repository_artifact
from .services.repository_recovery import run_repository_recovery_cycle
from .services.repository_state import (
    claim_repository_engine,
    claim_repository_normalization,
    dispatch_repository_outboxes,
    fail_repository_engine,
    fail_repository_normalization,
    plan_repository_execution,
)


_local_repository_attempt_ids = set()


def _contain_repository_attempt(attempt_id):
    try:
        attempt = ScanAttempt.objects.select_related("execution").get(
            pk=attempt_id,
            status=ScanAttempt.Status.RUNNING,
        )
    except ScanAttempt.DoesNotExist:
        return False
    if (
        repository_attempt_process_ownership(attempt, attempt.execution)
        != ProcessOwnership.OWNED
    ):
        return False
    return terminate_process_group(attempt.process_group_id)


@task_revoked.connect
def contain_revoked_repository_task(request=None, **kwargs):
    task_id = str(getattr(request, "id", "") or "")
    if not task_id:
        return
    for attempt_id in ScanAttempt.objects.filter(
        celery_task_id=task_id,
        status=ScanAttempt.Status.RUNNING,
    ).values_list("pk", flat=True):
        _contain_repository_attempt(attempt_id)


@worker_shutdown.connect
def contain_local_repository_tasks(**kwargs):
    for attempt_id in tuple(_local_repository_attempt_ids):
        _contain_repository_attempt(attempt_id)


@shared_task(
    bind=True,
    name="scans.tasks.run_repository_scan",
    acks_late=True,
    reject_on_worker_lost=True,
)
def run_repository_scan(self, execution_id, event_key):
    task_id = str(getattr(self.request, "id", "") or "")
    attempt = claim_repository_engine(
        execution_id,
        celery_task_id=task_id,
        event_key=event_key,
    )
    if attempt is None:
        return {"success": False, "claimed": False, "execution_id": execution_id}
    attempt = (
        type(attempt).objects
        .select_related("execution", "execution__analysis_run")
        .get(pk=attempt.pk)
    )
    _local_repository_attempt_ids.add(attempt.id)
    try:
        artifact = execute_repository_scan(attempt)
        dispatch_repository_outboxes()
        return {
            "success": True,
            "claimed": True,
            "execution_id": execution_id,
            "attempt_id": attempt.id,
            "artifact_id": artifact.id,
        }
    except Exception as error:
        fail_repository_engine(execution_id, attempt.id, error, retryable=True)
        dispatch_repository_outboxes()
        return {
            "success": False,
            "claimed": True,
            "execution_id": execution_id,
            "attempt_id": attempt.id,
            "reason": truncate_log(str(error)),
        }
    finally:
        _contain_repository_attempt(attempt.id)
        _local_repository_attempt_ids.discard(attempt.id)


@shared_task(
    bind=True,
    name="scans.tasks.normalize_repository_scan",
    acks_late=True,
    reject_on_worker_lost=True,
)
def normalize_repository_scan(self, execution_id, event_key):
    attempt = claim_repository_normalization(execution_id, event_key=event_key)
    if attempt is None:
        return {"success": False, "claimed": False, "execution_id": execution_id}
    attempt = type(attempt).objects.select_related("execution").get(pk=attempt.pk)
    try:
        result = normalize_repository_artifact(attempt)
        return {
            "success": True,
            "claimed": True,
            "execution_id": execution_id,
            "attempt_id": attempt.id,
            **result,
        }
    except Exception as error:
        fail_repository_normalization(execution_id, attempt.id, error, retryable=True)
        dispatch_repository_outboxes()
        return {
            "success": False,
            "claimed": True,
            "execution_id": execution_id,
            "attempt_id": attempt.id,
            "reason": truncate_log(str(error)),
        }
@shared_task(
    bind=True,
    name=ANALYSIS_CHUNK_TASK_NAME,
    acks_late=True,
    reject_on_worker_lost=True,
)
def run_analysis_chunk(
    self,
    chunk_id
):

    celery_task_id = str(
        getattr(
            self.request,
            "id",
            "",
        )
        or ""
    )


    claim_result = (
        claim_chunk(
            chunk_id,
            celery_task_id=
                celery_task_id,
        )
    )


    if not claim_result.get(
        "claimed"
    ):

        return {
            "success":
                False,

            "claimed":
                False,

            "chunk_id":
                chunk_id,

            "reason":
                claim_result.get(
                    "reason"
                ),
        }


    analysis_run_id = (
        claim_result[
            "analysis_run_id"
        ]
    )


    attempt_id = (
        claim_result[
            "attempt_id"
        ]
    )


    execution_token = (
        claim_result[
            "execution_token"
        ]
    )


    try:

        chunk = (
            AnalysisChunk.objects
            .select_related(
                "analysis_run"
            )
            .prefetch_related(
                "files"
            )
            .get(
                pk=
                    chunk_id
            )
        )


        # =================================
        # KISA Rule
        #
        # Rule Directory가 없는 것은
        # 재시도로 해결되지 않는 설정 오류.
        # =================================

        try:

            rule_path = (
                get_semgrep_rule_path(
                    chunk.language
                )
            )

        except RuntimeError as error:

            raise NonRetryableChunkError(
                str(
                    error
                )
            )


        # =================================
        # Chunk Source 준비
        # =================================

        with prepare_chunk_execution_target(
            chunk
        ) as analysis_target:

            # =============================
            # Semgrep
            # =============================

            semgrep_result = (
                execute_semgrep_with_heartbeat(
                    analysis_target,
                    rule_path,
                    attempt_id,
                    execution_token,
                )
            )


            raw_result = (
                semgrep_result[
                    "raw_result"
                ]
            )


            logs = (
                semgrep_result.get(
                    "logs"
                )
                or ""
            )


            # =============================
            # Semgrep 종료 직후
            # 실행권 재확인 + Lease 연장
            # =============================

            heartbeat_result = (
                heartbeat_attempt(
                    attempt_id,
                    execution_token,
                )
            )


            if not heartbeat_result.get(
                "updated"
            ):

                raise ChunkOwnershipLostError(
                    "Semgrep 종료 후 Chunk 실행권을 "
                    "확인할 수 없습니다. "
                    f"reason="
                    f"{heartbeat_result.get('reason')}"
                )


            # =============================
            # Attempt-scoped 결과 저장
            # =============================

            try:

                vulnerability_count = (
                    save_attempt_vulnerabilities(
                        analysis_run_id,
                        attempt_id,
                        execution_token,
                        raw_result,
                        analysis_target,
                        chunk.language,
                    )
                )

            except ChunkOwnershipLostError:

                raise

            except RuntimeError as error:

                # KISA Master / Rule Metadata 문제 등은
                # 같은 Source를 재시도해도 해결되지 않는다.
                raise NonRetryableChunkError(
                    str(
                        error
                    )
                )


        # =================================
        # Chunk 완료 확정
        # =================================

        complete_result = (
            complete_chunk_attempt(
                attempt_id,
                execution_token,
                result_count=
                    vulnerability_count,
                raw_result=
                    raw_result,
                logs=
                    logs,
            )
        )


        if not complete_result.get(
            "completed"
        ):

            return {
                "success":
                    False,

                "claimed":
                    True,

                "chunk_id":
                    chunk_id,

                "attempt_id":
                    attempt_id,

                "reason":
                    complete_result.get(
                        "reason"
                    ),
            }


        return {
            "success":
                True,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run_id,

            "chunk_id":
                chunk_id,

            "attempt_id":
                attempt_id,

            "attempt_no":
                claim_result.get(
                    "attempt_no"
                ),

            "status":
                AnalysisChunk.Status.COMPLETED,

            "result_count":
                vulnerability_count,
        }


    except ChunkOwnershipLostError as error:

        # --------------------------------
        # stale Worker는 DB 상태를
        # 더 이상 변경하면 안 된다.
        # --------------------------------

        return {
            "success":
                False,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run_id,

            "chunk_id":
                chunk_id,

            "attempt_id":
                attempt_id,

            "reason":
                "ownership_lost",

            "message":
                truncate_log(
                    str(
                        error
                    )
                ),
        }


    except NonRetryableChunkError as error:

        failure_result = (
            fail_chunk_attempt(
                attempt_id,
                execution_token,
                failure_reason=
                    str(
                        error
                    ),
                logs=
                    str(
                        error
                    ),
                retryable=
                    False,
            )
        )


        return {
            "success":
                False,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run_id,

            "chunk_id":
                chunk_id,

            "attempt_id":
                attempt_id,

            "reason":
                failure_result.get(
                    "reason"
                ),

            "retryable":
                False,

            "message":
                truncate_log(
                    str(
                        error
                    )
                ),
        }


    except Exception as error:

        failure_result = (
            fail_chunk_attempt(
                attempt_id,
                execution_token,
                failure_reason=
                    str(
                        error
                    ),
                logs=
                    str(
                        error
                    ),
                retryable=
                    True,
            )
        )


        return {
            "success":
                False,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run_id,

            "chunk_id":
                chunk_id,

            "attempt_id":
                attempt_id,

            "reason":
                failure_result.get(
                    "reason"
                ),

            "retryable":
                True,

            "message":
                truncate_log(
                    str(
                        error
                    )
                ),
        }

def dispatch_available_outboxes(
    max_batches=200,
):

    totals = {
        "batch_count": 0,
        "claimed_count": 0,
        "published_count": 0,
        "failed_count": 0,
        "cancelled_count": 0,
        "deferred_count": 0,
        "state_changed_count": 0,
    }


    for _ in range(
        max_batches
    ):

        result = (
            dispatch_pending_outboxes(
                batch_size=
                    OUTBOX_DISPATCH_BATCH_SIZE
            )
        )


        totals[
            "batch_count"
        ] += 1


        for key in (
            "claimed_count",
            "published_count",
            "failed_count",
            "cancelled_count",
            "deferred_count",
            "state_changed_count",
        ):

            totals[key] += int(
                result.get(
                    key,
                    0,
                )
                or 0
            )


        processed_count = (
            int(
                result.get(
                    "claimed_count",
                    0,
                )
                or 0
            )
            +
            int(
                result.get(
                    "cancelled_count",
                    0,
                )
                or 0
            )
            +
            int(
                result.get(
                    "deferred_count",
                    0,
                )
                or 0
            )
        )


        if processed_count == 0:

            break


    return totals

@shared_task(
    name="scans.tasks.dispatch_analysis_outboxes"
)
def dispatch_analysis_outboxes():

    return (
        dispatch_available_outboxes()
    )

@shared_task(
    name="scans.tasks.run_analysis_recovery",
    acks_late=True,
    reject_on_worker_lost=True,
)
def run_analysis_recovery():
    return {
        "chunk_v1": run_recovery_cycle(),
        "repository_v2": run_repository_recovery_cycle(),
    }

def get_snapshot_languages(
    snapshot_files,
):

    detected = {
        item.language
        for item
        in snapshot_files
    }


    return [
        language
        for language
        in SUPPORTED_LANGUAGE_ORDER
        if language in detected
    ]

def record_analysis_start_failure(
    analysis_run_id,
    error,
):

    error_message = (
        truncate_log(
            str(
                error
            )
        )
    )


    try:

        with transaction.atomic():

            analysis_run = (
                AnalysisRun.objects
                .select_for_update()
                .get(
                    pk=
                        analysis_run_id
                )
            )


            has_chunks = (
                analysis_run
                .analysis_chunks
                .exists()
            )
            has_repository_execution = ScanExecution.objects.filter(
                analysis_run=analysis_run
            ).exists()


            # --------------------------------
            # Planning 이전 / 중간 실패
            # --------------------------------

            if (
                analysis_run.status
                in (
                    AnalysisRun.Status.PENDING,
                    AnalysisRun.Status.PLANNING,
                )
                or
                not (has_chunks or has_repository_execution)
            ):

                analysis_run.status = (
                    AnalysisRun
                    .Status
                    .FAILED
                )

                analysis_run.completed_at = (
                    timezone.now()
                )

                analysis_run.failure_reason = (
                    error_message
                )


            # --------------------------------
            # 이미 Chunk / Outbox Pipeline이
            # 만들어졌다면 Run 상태는 유지.
            #
            # Recovery Dispatcher가 DB를 기준으로
            # 이어서 처리할 수 있어야 한다.
            # --------------------------------

            existing_logs = (
                analysis_run.logs
                or ""
            )


            if existing_logs:

                analysis_run.logs = (
                    truncate_log(
                        existing_logs
                        + "\n\n"
                        + error_message
                    )
                )

            else:

                analysis_run.logs = (
                    error_message
                )


            update_fields = [
                "logs",
                "updated_at",
            ]


            if (
                analysis_run.status
                ==
                AnalysisRun.Status.FAILED
            ):

                update_fields.extend([
                    "status",
                    "completed_at",
                    "failure_reason",
                ])


            analysis_run.save(
                update_fields=
                    update_fields
            )


    except AnalysisRun.DoesNotExist:

        pass

@shared_task(
    name="scans.tasks.run_analysis"
)
def run_analysis(
    analysis_run_id
):

    try:

        # =================================
        # Bootstrap Claim
        #
        # duplicate run_analysis 메시지가 와도
        # PENDING → PLANNING 전환에 성공한
        # 하나의 Worker만 Source 준비를 수행한다.
        # =================================

        with transaction.atomic():

            analysis_run = (
                AnalysisRun.objects
                .select_for_update()
                .select_related(
                    "project",
                    "source_version",
                    "executed_by",
                )
                .get(
                    pk=
                        analysis_run_id
                )
            )


            if (
                analysis_run.status
                !=
                AnalysisRun.Status.PENDING
            ):

                return {
                    "success":
                        False,

                    "claimed":
                        False,

                    "reason":
                        "analysis_run_not_pending",

                    "message":
                        "실행 가능한 pending 상태가 아닙니다.",

                    "analysis_run_id":
                        analysis_run.id,

                    "status":
                        analysis_run.status,
                }


            analysis_run.status = (
                AnalysisRun.Status.PLANNING
            )

            analysis_run.started_at = (
                timezone.now()
            )

            analysis_run.completed_at = None

            analysis_run.failure_reason = ""

            analysis_run.logs = ""

            analysis_run.raw_result = None

            analysis_run.analysis_languages = []

            analysis_run.analysis_language = ""


            analysis_run.save(
                update_fields=[
                    "status",
                    "started_at",
                    "completed_at",
                    "failure_reason",
                    "logs",
                    "raw_result",
                    "analysis_languages",
                    "analysis_language",
                    "updated_at",
                ]
            )


            source_version = (
                analysis_run
                .source_version
            )


        # =================================
        # Source 준비
        #
        # Upload:
        # 안전한 TemporaryDirectory 압축 해제
        #
        # Repository:
        # TemporaryDirectory clone
        #
        # Internal:
        # 허용된 Internal Root
        # =================================

        repository_manifest = None

        with prepare_analysis_target(
            source_version
        ) as target_path:

            # =============================
            # Persistent Workspace Snapshot
            #
            # TemporaryDirectory가 사라지기 전에
            # 정확한 분석 입력을 영속화한다.
            # =============================

            snapshot_files = (
                materialize_analysis_workspace(
                    analysis_run_id,
                    target_path,
                )
            )

            if (
                analysis_run.pipeline_version
                == AnalysisRun.PipelineVersion.REPOSITORY_V2
            ):
                repository_manifest = build_repository_manifest(
                    analysis_run_id,
                    target_path,
                    snapshot_files,
                )


        # =================================
        # 여기서는 Upload / Repository의
        # 원본 TemporaryDirectory가 이미 삭제되어도
        # Persistent Workspace가 남아 있다.
        # =================================

        detected_languages = (
            get_snapshot_languages(
                snapshot_files
            )
        )


        if not detected_languages:

            raise RuntimeError(
                "지원하는 분석 대상 언어를 "
                "찾을 수 없습니다. "
                "현재 자동 감지 대상은 "
                "Java, JavaScript, Python입니다."
            )


        # =================================
        # SourceVersion 감지 언어 Snapshot
        #
        # 기존 UI / API 호환을 위해
        # 기존 함수를 재사용한다.
        #
        # AnalysisRun의 언어 필드는 뒤의 Planner가
        # 최종 Chunk 기준으로 다시 확정한다.
        # =================================

        save_detected_languages(
            source_version,
            analysis_run_id,
            detected_languages,
        )


        # =================================
        # Chunk Planning
        #
        # Snapshot Metadata를 직접 전달한다.
        # 원본 Temporary Source를 다시 읽지 않는다.
        #
        # 같은 DB Transaction 안에서:
        #
        # AnalysisChunk
        # AnalysisChunkFile
        # AnalysisDispatchOutbox
        #
        # 생성.
        # =================================

        if (
            analysis_run.pipeline_version
            == AnalysisRun.PipelineVersion.REPOSITORY_V2
        ):
            execution = plan_repository_execution(
                analysis_run_id,
                repository_manifest,
                detected_languages,
            )
            dispatch_result = dispatch_repository_outboxes()
            return {
                "success": True,
                "claimed": True,
                "analysis_run_id": analysis_run_id,
                "execution_id": execution.id,
                "pipeline_version": AnalysisRun.PipelineVersion.REPOSITORY_V2,
                "published_count": dispatch_result["published_count"],
            }

        planning_result = (
            plan_analysis_chunks(
                analysis_run_id,
                scanned_files=
                    snapshot_files,
            )
        )


        # =================================
        # Planner가 모든 파일을 Oversized로
        # 판단한 경우 Run을 failed로 끝낼 수 있다.
        # =================================

        if (
            planning_result.get(
                "queued_chunk_count",
                0,
            )
            <= 0
        ):

            analysis_run = (
                AnalysisRun.objects
                .get(
                    pk=
                        analysis_run_id
                )
            )


            return {
                "success":
                    False,

                "claimed":
                    True,

                "reason":
                    "no_dispatchable_chunks",

                "analysis_run_id":
                    analysis_run.id,

                "status":
                    analysis_run.status,

                "analysis_languages":
                    list(
                        analysis_run
                        .analysis_languages
                    ),

                "planning":
                    planning_result,
            }


        # =================================
        # Outbox → Redis / Celery
        #
        # 네트워크 실패는 Dispatcher가 Outbox를
        # pending으로 유지하고 Backoff를 기록한다.
        #
        # 여기서는 즉시 publish 가능한 Outbox를
        # 여러 Batch로 처리한다.
        # =================================

        dispatch_result = (
            dispatch_available_outboxes()
        )


        analysis_run = (
            AnalysisRun.objects
            .get(
                pk=
                    analysis_run_id
            )
        )


        return {
            "success":
                True,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run.id,

            "status":
                analysis_run.status,

            "analysis_languages":
                list(
                    analysis_run
                    .analysis_languages
                ),

            "planning":
                planning_result,

            "dispatch":
                dispatch_result,
        }


    except AnalysisRun.DoesNotExist:

        return {
            "success":
                False,

            "claimed":
                False,

            "reason":
                "analysis_run_not_found",

            "message":
                "AnalysisRun을 찾을 수 없습니다.",
        }


    except Exception as error:

        record_analysis_start_failure(
            analysis_run_id,
            error,
        )

        raise
