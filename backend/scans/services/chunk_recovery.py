from datetime import timedelta

from celery import current_app

from django.db import transaction
from django.utils import timezone

from scans.models import (
    AnalysisChunk,
    AnalysisChunkAttempt,
    AnalysisDispatchOutbox,
    AnalysisRun,
)

from scans.services.chunk_state_manager import (
    get_next_dispatch_no,
)

from scans.services.outbox_dispatcher import (
    dispatch_pending_outboxes,
)

from scans.services.run_state_manager import (
    aggregate_analysis_run_state,
)


# ========================================
# Recovery Error
# ========================================

class ChunkRecoveryError(
    RuntimeError
):

    pass


# ========================================
# Recovery 설정
#
# 현재는 Recovery 전용 서비스 내부에 둔다.
#
# 이후 Celery Beat 설정 단계에서 필요하면
# constants.py로 이동 가능.
# ========================================

RECOVERY_SCAN_BATCH_SIZE = 50


# ----------------------------------------
# 오래된 Pending AnalysisRun 판단 기준
#
# 30초 이상 pending이면
# Bootstrap Task 유실 가능성이 있다고 보고
# run_analysis를 다시 publish한다.
#
# run_analysis 자체가 idempotent하므로
# 중복 메시지가 도착해도 안전하다.
# ----------------------------------------

PENDING_RUN_RECOVERY_GRACE_SECONDS = 30


# ----------------------------------------
# Recovery Error 저장 / 반환 최대 길이
# ----------------------------------------

RECOVERY_ERROR_MAX_LENGTH = 2000


# ========================================
# 문자열 제한
# ========================================

def truncate_recovery_text(
    value,
    max_length=RECOVERY_ERROR_MAX_LENGTH,
):

    value = str(
        value
        or ""
    )


    if (
        len(value)
        <=
        max_length
    ):

        return value


    return (
        value[
            :max_length
        ]
    )


# ========================================
# Batch Size 정규화
# ========================================

def normalize_batch_size(
    batch_size,
):

    try:

        batch_size = int(
            batch_size
        )


    except (
        TypeError,
        ValueError,
    ):

        batch_size = (
            RECOVERY_SCAN_BATCH_SIZE
        )


    if batch_size <= 0:

        batch_size = (
            RECOVERY_SCAN_BATCH_SIZE
        )


    return batch_size


# ========================================
# Analysis Bootstrap Publish
#
# PostgreSQL의 pending AnalysisRun을
# 다시 Celery로 보낼 때 사용.
#
# Celery State는 Source of Truth가 아니다.
#
# Task에는 AnalysisRun ID만 전달한다.
# ========================================

def publish_analysis_bootstrap(
    analysis_run_id,
):

    async_result = (
        current_app.send_task(

            "scans.tasks.run_analysis",

            args=[
                analysis_run_id
            ],
        )
    )


    return str(
        getattr(
            async_result,
            "id",
            "",
        )
        or ""
    )


# ========================================
# 오래된 Pending AnalysisRun 복구
#
# 예:
#
# API
# ↓
# AnalysisRun 생성 완료
# ↓
# Redis 장애
# ↓
# run_analysis.delay() 실패
#
# DB:
# AnalysisRun = pending
#
#
# Recovery Scanner:
#
# pending + 일정 시간 경과
# ↓
# run_analysis 재전송
#
#
# 주의:
#
# publish 성공 후에도 Worker 실행 전에
# 다음 Recovery가 다시 publish할 수 있다.
#
# 하지만 run_analysis 자체가
# pending 상태만 claim하기 때문에
# duplicate delivery는 안전하다.
#
#
# 성공 publish 후 updated_at을 갱신해
# 너무 자주 동일 Run을 재전송하는 것을
# 완화한다.
# ========================================

def recover_pending_analysis_runs(
    publish_func=None,
    batch_size=RECOVERY_SCAN_BATCH_SIZE,
    grace_seconds=PENDING_RUN_RECOVERY_GRACE_SECONDS,
):

    if publish_func is None:

        publish_func = (
            publish_analysis_bootstrap
        )


    batch_size = (
        normalize_batch_size(
            batch_size
        )
    )


    try:

        grace_seconds = max(
            int(
                grace_seconds
            ),
            0,
        )


    except (
        TypeError,
        ValueError,
    ):

        grace_seconds = (
            PENDING_RUN_RECOVERY_GRACE_SECONDS
        )


    now = timezone.now()


    cutoff = (
        now
        -
        timedelta(
            seconds=
                grace_seconds
        )
    )


    # ====================================
    # 후보 ID 조회
    #
    # 여기서는 긴 Transaction을 잡지 않는다.
    #
    # 중복 Recovery Scanner가 같은 ID를
    # 선택할 수도 있지만 run_analysis가
    # idempotent하므로 correctness에는
    # 문제가 없다.
    # ====================================

    candidate_ids = list(

        AnalysisRun.objects
        .filter(

            status=(
                AnalysisRun
                .Status
                .PENDING
            ),

            updated_at__lte=
                cutoff,
        )
        .order_by(
            "updated_at",
            "id",
        )
        .values_list(
            "id",
            flat=True,
        )[
            :batch_size
        ]
    )


    published_count = 0

    failed_count = 0

    skipped_count = 0

    results = []


    for analysis_run_id in candidate_ids:

        # =================================
        # Publish 직전 상태 재확인
        # =================================

        current_status = (
            AnalysisRun.objects
            .filter(
                pk=
                    analysis_run_id
            )
            .values_list(
                "status",
                flat=True,
            )
            .first()
        )


        if (
            current_status
            !=
            AnalysisRun
            .Status
            .PENDING
        ):

            skipped_count += 1


            results.append({

                "analysis_run_id":
                    analysis_run_id,

                "published":
                    False,

                "reason":
                    "analysis_run_not_pending",
            })


            continue


        # =================================
        # Broker Publish
        #
        # DB Transaction 밖에서 수행.
        # =================================

        try:

            publish_result = (
                publish_func(
                    analysis_run_id
                )
            )


        except Exception as error:

            failed_count += 1


            results.append({

                "analysis_run_id":
                    analysis_run_id,

                "published":
                    False,

                "reason":
                    "publish_failed",

                "error":
                    truncate_recovery_text(
                        error
                    ),
            })


            # --------------------------------
            # updated_at을 건드리지 않는다.
            #
            # 다음 Recovery Scan에서
            # 즉시 다시 후보가 될 수 있다.
            # --------------------------------

            continue


        # =================================
        # 성공
        # =================================

        published_count += 1


        task_id = str(
            getattr(
                publish_result,
                "id",
                publish_result,
            )
            or ""
        )


        # --------------------------------
        # 성공 publish 후 throttle
        #
        # 아직 pending인 경우만 updated_at
        # 갱신.
        #
        # Worker가 이미 planning으로 바꿨다면
        # 이 update는 아무것도 변경하지 않는다.
        # --------------------------------

        AnalysisRun.objects.filter(

            pk=
                analysis_run_id,

            status=(
                AnalysisRun
                .Status
                .PENDING
            ),

        ).update(
            updated_at=
                now
        )


        results.append({

            "analysis_run_id":
                analysis_run_id,

            "published":
                True,

            "reason":
                "published",

            "task_id":
                task_id,
        })


    return {

        "candidate_count":
            len(
                candidate_ids
            ),

        "published_count":
            published_count,

        "failed_count":
            failed_count,

        "skipped_count":
            skipped_count,

        "results":
            results,
    }


# ========================================
# 단일 Stale Attempt 복구
#
# stale 기준:
#
# Attempt.status = running
# AND
# lease_expires_at <= now
#
#
# 복구:
#
# Attempt
# running
# ↓
# worker_lost
#
#
# Retry 가능:
#
# Chunk
# running
# ↓
# retry_pending
# ↓
# 새 Outbox
#
#
# Retry 소진:
#
# Chunk
# running
# ↓
# failed
# ========================================

def recover_stale_attempt(
    attempt_id,
):

    now = timezone.now()


    # ====================================
    # Reference
    #
    # Lock 순서를 결정하기 위해
    # AnalysisRun / Chunk ID 확보.
    # ====================================

    attempt_reference = (
        AnalysisChunkAttempt.objects
        .filter(
            pk=
                attempt_id
        )
        .values(
            "id",
            "chunk_id",
            "chunk__analysis_run_id",
        )
        .first()
    )


    if attempt_reference is None:

        return {

            "recovered":
                False,

            "reason":
                "attempt_not_found",

            "attempt_id":
                attempt_id,
        }


    analysis_run_id = (
        attempt_reference[
            "chunk__analysis_run_id"
        ]
    )


    chunk_id = (
        attempt_reference[
            "chunk_id"
        ]
    )


    # ====================================
    # Lock 순서
    #
    # AnalysisRun
    # ↓
    # AnalysisChunk
    # ↓
    # AnalysisChunkAttempt
    #
    # 기존 Executor / State Manager와
    # 동일한 Lock 순서.
    # ====================================

    with transaction.atomic():

        analysis_run = (
            AnalysisRun.objects
            .select_for_update()
            .filter(
                pk=
                    analysis_run_id
            )
            .first()
        )


        if analysis_run is None:

            return {

                "recovered":
                    False,

                "reason":
                    "analysis_run_not_found",

                "attempt_id":
                    attempt_id,
            }


        chunk = (
            AnalysisChunk.objects
            .select_for_update()
            .filter(
                pk=
                    chunk_id
            )
            .first()
        )


        if chunk is None:

            return {

                "recovered":
                    False,

                "reason":
                    "chunk_not_found",

                "attempt_id":
                    attempt_id,
            }


        attempt = (
            AnalysisChunkAttempt.objects
            .select_for_update()
            .filter(
                pk=
                    attempt_id
            )
            .first()
        )


        if attempt is None:

            return {

                "recovered":
                    False,

                "reason":
                    "attempt_not_found",

                "attempt_id":
                    attempt_id,
            }


        # =================================
        # 이미 다른 Worker / Recovery가
        # 처리한 Attempt
        # =================================

        if (
            attempt.status
            !=
            AnalysisChunkAttempt
            .Status
            .RUNNING
        ):

            return {

                "recovered":
                    False,

                "reason":
                    "attempt_not_running",

                "analysis_run_id":
                    analysis_run.id,

                "chunk_id":
                    chunk.id,

                "attempt_id":
                    attempt.id,

                "attempt_status":
                    attempt.status,
            }


        # =================================
        # Lease 존재 확인
        # =================================

        if (
            attempt.lease_expires_at
            is None
        ):

            return {

                "recovered":
                    False,

                "reason":
                    "lease_not_set",

                "analysis_run_id":
                    analysis_run.id,

                "chunk_id":
                    chunk.id,

                "attempt_id":
                    attempt.id,
            }


        # =================================
        # 아직 Lease 살아 있음
        # =================================

        if (
            attempt.lease_expires_at
            >
            now
        ):

            return {

                "recovered":
                    False,

                "reason":
                    "lease_not_expired",

                "analysis_run_id":
                    analysis_run.id,

                "chunk_id":
                    chunk.id,

                "attempt_id":
                    attempt.id,

                "lease_expires_at":
                    attempt
                    .lease_expires_at,
            }


        # =================================
        # Chunk가 이미 running이 아님
        #
        # 오래된 Attempt가 뒤늦게 발견된 경우.
        #
        # Worker Lost Retry를 만들지 않고
        # superseded 처리.
        # =================================

        if (
            chunk.status
            !=
            AnalysisChunk
            .Status
            .RUNNING
        ):

            attempt.status = (
                AnalysisChunkAttempt
                .Status
                .SUPERSEDED
            )

            attempt.completed_at = (
                now
            )

            attempt.failure_reason = (
                "STALE_ATTEMPT_CHUNK_NOT_RUNNING"
            )


            attempt.save(
                update_fields=[
                    "status",
                    "completed_at",
                    "failure_reason",
                    "updated_at",
                ]
            )


            return {

                "recovered":
                    True,

                "reason":
                    "attempt_superseded",

                "analysis_run_id":
                    analysis_run.id,

                "chunk_id":
                    chunk.id,

                "attempt_id":
                    attempt.id,

                "chunk_status":
                    chunk.status,
            }


        # =================================
        # AnalysisRun이 이미 terminal 또는
        # running이 아닌 상태
        #
        # 이 경우 새 Retry를 만들면 안 된다.
        # =================================

        if (
            analysis_run.status
            !=
            AnalysisRun
            .Status
            .RUNNING
        ):

            if (
                analysis_run.status
                ==
                AnalysisRun
                .Status
                .CANCELLED
            ):

                attempt.status = (
                    AnalysisChunkAttempt
                    .Status
                    .CANCELLED
                )


            else:

                attempt.status = (
                    AnalysisChunkAttempt
                    .Status
                    .SUPERSEDED
                )


            attempt.completed_at = (
                now
            )

            attempt.failure_reason = (
                "ANALYSIS_RUN_NOT_RUNNING"
            )


            attempt.save(
                update_fields=[
                    "status",
                    "completed_at",
                    "failure_reason",
                    "updated_at",
                ]
            )


            return {

                "recovered":
                    True,

                "reason":
                    "analysis_run_not_running",

                "analysis_run_id":
                    analysis_run.id,

                "chunk_id":
                    chunk.id,

                "attempt_id":
                    attempt.id,

                "analysis_run_status":
                    analysis_run.status,
            }


        # =================================
        # 정상 Stale Attempt
        #
        # running → worker_lost
        # =================================

        attempt.status = (
            AnalysisChunkAttempt
            .Status
            .WORKER_LOST
        )

        attempt.completed_at = (
            now
        )

        attempt.failure_reason = (
            "WORKER_LEASE_EXPIRED"
        )


        attempt.save(
            update_fields=[
                "status",
                "completed_at",
                "failure_reason",
                "updated_at",
            ]
        )


        # =================================
        # Retry Budget
        #
        # retry_count는 실제 retry를
        # claim할 때 증가한다.
        #
        # 지금은 다음 retry를 예약하는 단계.
        # =================================

        has_retry_budget = (
            chunk.retry_count
            <
            chunk.max_retries
        )


        # =================================
        # Retry 가능
        # =================================

        if has_retry_budget:

            chunk.status = (
                AnalysisChunk
                .Status
                .RETRY_PENDING
            )

            chunk.completed_at = None

            chunk.status_reason = (
                "WORKER_LOST_RETRY_PENDING"
            )

            chunk.failure_reason = (
                "WORKER_LEASE_EXPIRED"
            )


            chunk.save(
                update_fields=[
                    "status",
                    "completed_at",
                    "status_reason",
                    "failure_reason",
                    "updated_at",
                ]
            )


            # =================================
            # Retry Outbox 생성
            # =================================

            dispatch_no = (
                get_next_dispatch_no(
                    chunk
                )
            )


            outbox = (
                AnalysisDispatchOutbox.objects.create(

                    chunk=
                        chunk,

                    dispatch_no=
                        dispatch_no,

                    status=(
                        AnalysisDispatchOutbox
                        .Status
                        .PENDING
                    ),
                )
            )


            # =================================
            # retry_pending은 Active이므로
            # Run은 running 유지
            # =================================

            run_state = (
                aggregate_analysis_run_state(
                    analysis_run.id
                )
            )


            return {

                "recovered":
                    True,

                "reason":
                    "worker_lost_retry_pending",

                "analysis_run_id":
                    analysis_run.id,

                "chunk_id":
                    chunk.id,

                "attempt_id":
                    attempt.id,

                "attempt_no":
                    attempt.attempt_no,

                "attempt_status":
                    attempt.status,

                "chunk_status":
                    chunk.status,

                "retry_count":
                    chunk.retry_count,

                "max_retries":
                    chunk.max_retries,

                "outbox_id":
                    outbox.id,

                "dispatch_no":
                    outbox.dispatch_no,

                "run_state":
                    run_state,
            }


        # =================================
        # Retry Budget 소진
        #
        # Chunk failed
        # =================================

        chunk.status = (
            AnalysisChunk
            .Status
            .FAILED
        )

        chunk.completed_at = (
            now
        )

        chunk.status_reason = (
            "WORKER_LOST_MAX_RETRIES_EXCEEDED"
        )

        chunk.failure_reason = (
            "WORKER_LEASE_EXPIRED"
        )


        chunk.save(
            update_fields=[
                "status",
                "completed_at",
                "status_reason",
                "failure_reason",
                "updated_at",
            ]
        )


        run_state = (
            aggregate_analysis_run_state(
                analysis_run.id
            )
        )


        return {

            "recovered":
                True,

            "reason":
                "worker_lost_chunk_failed",

            "analysis_run_id":
                analysis_run.id,

            "chunk_id":
                chunk.id,

            "attempt_id":
                attempt.id,

            "attempt_no":
                attempt.attempt_no,

            "attempt_status":
                attempt.status,

            "chunk_status":
                chunk.status,

            "retry_count":
                chunk.retry_count,

            "max_retries":
                chunk.max_retries,

            "run_state":
                run_state,
        }


# ========================================
# Stale Attempt Scanner
#
# lease_expires_at <= now인
# running Attempt들을 Batch 단위로 복구.
#
# Candidate 조회 후 각각 별도 짧은
# Transaction으로 처리한다.
# ========================================

def recover_stale_attempts(
    batch_size=RECOVERY_SCAN_BATCH_SIZE,
):

    batch_size = (
        normalize_batch_size(
            batch_size
        )
    )


    now = timezone.now()


    candidate_ids = list(

        AnalysisChunkAttempt.objects
        .filter(

            status=(
                AnalysisChunkAttempt
                .Status
                .RUNNING
            ),

            lease_expires_at__lte=
                now,
        )
        .order_by(
            "lease_expires_at",
            "id",
        )
        .values_list(
            "id",
            flat=True,
        )[
            :batch_size
        ]
    )


    recovered_count = 0

    retry_pending_count = 0

    failed_chunk_count = 0

    skipped_count = 0

    error_count = 0

    results = []


    for attempt_id in candidate_ids:

        try:

            result = (
                recover_stale_attempt(
                    attempt_id
                )
            )


        except Exception as error:

            error_count += 1


            results.append({

                "attempt_id":
                    attempt_id,

                "recovered":
                    False,

                "reason":
                    "recovery_error",

                "error":
                    truncate_recovery_text(
                        error
                    ),
            })


            continue


        results.append(
            result
        )


        if not result.get(
            "recovered"
        ):

            skipped_count += 1

            continue


        recovered_count += 1


        if (
            result.get(
                "reason"
            )
            ==
            "worker_lost_retry_pending"
        ):

            retry_pending_count += 1


        elif (
            result.get(
                "reason"
            )
            ==
            "worker_lost_chunk_failed"
        ):

            failed_chunk_count += 1


    return {

        "candidate_count":
            len(
                candidate_ids
            ),

        "recovered_count":
            recovered_count,

        "retry_pending_count":
            retry_pending_count,

        "failed_chunk_count":
            failed_chunk_count,

        "skipped_count":
            skipped_count,

        "error_count":
            error_count,

        "results":
            results,
    }


# ========================================
# Pending Outbox Recovery
#
# 기존 Outbox Dispatcher를 그대로 사용.
#
# Outbox Dispatcher 자체가:
#
# pending
# +
# available_at <= now
#
# 조건으로 재실행 가능하므로
# 별도 상태 머신을 새로 만들 필요가 없다.
# ========================================

def recover_pending_outboxes(
    publish_func=None,
    batch_size=RECOVERY_SCAN_BATCH_SIZE,
):

    batch_size = (
        normalize_batch_size(
            batch_size
        )
    )


    return (
        dispatch_pending_outboxes(

            publish_func=
                publish_func,

            batch_size=
                batch_size,
        )
    )


# ========================================
# Recovery Cycle
#
# 하나의 주기적 Recovery 작업에서
# 사용할 수 있는 통합 진입점.
#
# 아직 Celery Task / Beat에는 연결하지 않는다.
#
# 이번 단계 테스트가 통과한 뒤 연결한다.
# ========================================

def run_recovery_cycle(
    bootstrap_publish_func=None,
    outbox_publish_func=None,
    batch_size=RECOVERY_SCAN_BATCH_SIZE,
    pending_run_grace_seconds=(
        PENDING_RUN_RECOVERY_GRACE_SECONDS
    ),
):

    pending_runs = (
        recover_pending_analysis_runs(

            publish_func=
                bootstrap_publish_func,

            batch_size=
                batch_size,

            grace_seconds=
                pending_run_grace_seconds,
        )
    )


    stale_attempts = (
        recover_stale_attempts(
            batch_size=
                batch_size
        )
    )


    outboxes = (
        recover_pending_outboxes(

            publish_func=
                outbox_publish_func,

            batch_size=
                batch_size,
        )
    )


    return {

        "pending_runs":
            pending_runs,

        "stale_attempts":
            stale_attempts,

        "outboxes":
            outboxes,
    }