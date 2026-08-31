from datetime import timedelta

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from scans.constants import (
    CHUNK_ATTEMPT_LEASE_SECONDS,
)

from scans.models import (
    AnalysisChunk,
    AnalysisChunkAttempt,
    AnalysisRun,
)


# ========================================
# Chunk Execution Error
# ========================================

class ChunkExecutionError(
    RuntimeError
):

    pass


# ========================================
# Claim 가능한 Chunk 상태
# ========================================

CLAIMABLE_CHUNK_STATUSES = {

    AnalysisChunk
    .Status
    .QUEUED,

    AnalysisChunk
    .Status
    .RETRY_PENDING,
}


# ========================================
# Chunk Terminal 상태
# ========================================

TERMINAL_CHUNK_STATUSES = {

    AnalysisChunk
    .Status
    .COMPLETED,

    AnalysisChunk
    .Status
    .FAILED,

    AnalysisChunk
    .Status
    .SKIPPED,

    AnalysisChunk
    .Status
    .CANCELLED,
}


# ========================================
# AnalysisRun Terminal 상태
# ========================================

TERMINAL_RUN_STATUSES = {

    AnalysisRun
    .Status
    .COMPLETED,

    AnalysisRun
    .Status
    .FAILED,

    AnalysisRun
    .Status
    .CANCELLED,
}


# ========================================
# Lease 만료 시간 계산
# ========================================

def build_attempt_lease_expires_at(
    now=None,
):

    if now is None:

        now = timezone.now()


    return (
        now
        +
        timedelta(
            seconds=
                CHUNK_ATTEMPT_LEASE_SECONDS
        )
    )


# ========================================
# Attempt 번호 계산
#
# Chunk row를 이미 select_for_update로
# Lock한 Transaction 내부에서 호출한다.
# ========================================

def get_next_attempt_no(
    chunk,
):

    current_max = (
        AnalysisChunkAttempt.objects
        .filter(
            chunk=
                chunk
        )
        .aggregate(
            max_attempt=
                Max(
                    "attempt_no"
                )
        )
        ["max_attempt"]
        or 0
    )


    return (
        current_max
        + 1
    )


# ========================================
# Active Running Attempt 조회
#
# DB Constraint상 최대 1개여야 한다.
# ========================================

def get_running_attempt(
    chunk,
):

    return (
        AnalysisChunkAttempt.objects
        .filter(
            chunk=
                chunk,

            status=(
                AnalysisChunkAttempt
                .Status
                .RUNNING
            ),
        )
        .order_by(
            "-attempt_no"
        )
        .first()
    )


# ========================================
# Chunk Claim
#
# 반환 예:
#
# 성공:
#
# {
#   "claimed": True,
#   "reason": "claimed",
#   "chunk_id": 10,
#   "attempt_id": 20,
#   "attempt_no": 1,
#   "execution_token": "...",
#   "lease_expires_at": ...
# }
#
#
# 중복 Worker:
#
# {
#   "claimed": False,
#   "reason": "already_running",
#   ...
# }
#
#
# 중요:
#
# Celery Task ID는 추적용일 뿐
# 실행권 판단 기준이 아니다.
#
# 실제 실행권은
#
# Chunk 상태
# +
# Attempt
# +
# execution_token
# +
# lease
#
# 로 판단한다.
# ========================================

def claim_chunk(
    chunk_id,
    celery_task_id="",
):

    now = timezone.now()


    # ====================================
    # AnalysisRun ID 확보
    #
    # FK 값은 변경되지 않으므로
    # Lock 이전에 식별자만 확인한다.
    # ====================================

    try:

        chunk_reference = (
            AnalysisChunk.objects
            .only(
                "id",
                "analysis_run_id",
            )
            .get(
                pk=
                    chunk_id
            )
        )

    except AnalysisChunk.DoesNotExist:

        return {
            "claimed":
                False,

            "reason":
                "chunk_not_found",

            "chunk_id":
                chunk_id,
        }


    # ====================================
    # Transaction
    #
    # Lock 순서:
    #
    # AnalysisRun
    # ↓
    # AnalysisChunk
    #
    # 이후 상태 변경 코드에서도
    # 동일한 Lock 순서를 사용한다.
    # ====================================

    with transaction.atomic():

        try:

            analysis_run = (
                AnalysisRun.objects
                .select_for_update()
                .get(
                    pk=
                        chunk_reference
                        .analysis_run_id
                )
            )

        except AnalysisRun.DoesNotExist:

            return {
                "claimed":
                    False,

                "reason":
                    "analysis_run_not_found",

                "chunk_id":
                    chunk_id,
            }


        try:

            chunk = (
                AnalysisChunk.objects
                .select_for_update()
                .get(
                    pk=
                        chunk_id
                )
            )

        except AnalysisChunk.DoesNotExist:

            return {
                "claimed":
                    False,

                "reason":
                    "chunk_not_found",

                "chunk_id":
                    chunk_id,
            }


        # =================================
        # AnalysisRun Terminal
        # =================================

        if (
            analysis_run.status
            in
            TERMINAL_RUN_STATUSES
        ):

            return {
                "claimed":
                    False,

                "reason":
                    "analysis_run_terminal",

                "chunk_id":
                    chunk.id,

                "analysis_run_status":
                    analysis_run.status,

                "chunk_status":
                    chunk.status,
            }


        # =================================
        # AnalysisRun은 실제 실행 상태여야 함
        # =================================

        if (
            analysis_run.status
            !=
            AnalysisRun
            .Status
            .RUNNING
        ):

            return {
                "claimed":
                    False,

                "reason":
                    "analysis_run_not_running",

                "chunk_id":
                    chunk.id,

                "analysis_run_status":
                    analysis_run.status,

                "chunk_status":
                    chunk.status,
            }


        # =================================
        # Chunk Terminal
        #
        # completed Chunk는
        # 절대 다시 실행하지 않는다.
        # =================================

        if (
            chunk.status
            in
            TERMINAL_CHUNK_STATUSES
        ):

            return {
                "claimed":
                    False,

                "reason":
                    "chunk_terminal",

                "chunk_id":
                    chunk.id,

                "chunk_status":
                    chunk.status,
            }


        # =================================
        # 이미 Running
        # =================================

        if (
            chunk.status
            ==
            AnalysisChunk
            .Status
            .RUNNING
        ):

            running_attempt = (
                get_running_attempt(
                    chunk
                )
            )


            # --------------------------------
            # Running Attempt가 정상 존재
            # --------------------------------

            if (
                running_attempt
                is not None
            ):

                now = timezone.now()


                if (
                    running_attempt
                    .lease_expires_at
                    <=
                    now
                ):

                    # ------------------------
                    # stale Attempt
                    #
                    # 여기서 임의로 회수하지 않는다.
                    #
                    # Recovery Scanner가
                    # worker_lost 처리 후
                    # retry_pending으로 만든다.
                    # ------------------------

                    return {
                        "claimed":
                            False,

                        "reason":
                            "stale_running_attempt",

                        "chunk_id":
                            chunk.id,

                        "chunk_status":
                            chunk.status,

                        "attempt_id":
                            running_attempt.id,

                        "attempt_no":
                            running_attempt
                            .attempt_no,

                        "lease_expires_at":
                            running_attempt
                            .lease_expires_at,
                    }


                return {
                    "claimed":
                        False,

                    "reason":
                        "already_running",

                    "chunk_id":
                        chunk.id,

                    "chunk_status":
                        chunk.status,

                    "attempt_id":
                        running_attempt.id,

                    "attempt_no":
                        running_attempt
                        .attempt_no,

                    "lease_expires_at":
                        running_attempt
                        .lease_expires_at,
                }


            # --------------------------------
            # Chunk=running인데
            # Running Attempt가 없음
            #
            # 데이터 상태가 비정상이다.
            #
            # 여기서 새 Attempt를 만들어
            # 덮어버리지 않는다.
            # --------------------------------

            return {
                "claimed":
                    False,

                "reason":
                    "invalid_running_state",

                "chunk_id":
                    chunk.id,

                "chunk_status":
                    chunk.status,
            }


        # =================================
        # Claim 가능한 상태 확인
        # =================================

        if (
            chunk.status
            not in
            CLAIMABLE_CHUNK_STATUSES
        ):

            return {
                "claimed":
                    False,

                "reason":
                    "chunk_not_claimable",

                "chunk_id":
                    chunk.id,

                "chunk_status":
                    chunk.status,
            }


        # =================================
        # Retry Budget
        #
        # 최초 queued Attempt는
        # retry_count를 증가시키지 않는다.
        #
        # retry_pending에서 실제 다시
        # 실행할 때만 +1 한다.
        # =================================

        if (
            chunk.status
            ==
            AnalysisChunk
            .Status
            .RETRY_PENDING
        ):

            if (
                chunk.retry_count
                >=
                chunk.max_retries
            ):

                chunk.status = (
                    AnalysisChunk
                    .Status
                    .FAILED
                )

                chunk.status_reason = (
                    "MAX_RETRIES_EXCEEDED"
                )

                chunk.completed_at = (
                    now
                )


                chunk.save(
                    update_fields=[
                        "status",
                        "status_reason",
                        "completed_at",
                        "updated_at",
                    ]
                )


                return {
                    "claimed":
                        False,

                    "reason":
                        "max_retries_exceeded",

                    "chunk_id":
                        chunk.id,

                    "chunk_status":
                        chunk.status,

                    "retry_count":
                        chunk.retry_count,

                    "max_retries":
                        chunk.max_retries,
                }


            chunk.retry_count += 1


        # =================================
        # Attempt Number
        # =================================

        attempt_no = (
            get_next_attempt_no(
                chunk
            )
        )


        # =================================
        # Attempt 생성
        # =================================

        attempt = (
            AnalysisChunkAttempt.objects.create(

                chunk=
                    chunk,

                attempt_no=
                    attempt_no,

                celery_task_id=
                    str(
                        celery_task_id
                        or ""
                    )[:255],

                status=(
                    AnalysisChunkAttempt
                    .Status
                    .RUNNING
                ),

                started_at=
                    now,

                heartbeat_at=
                    now,

                lease_expires_at=(
                    build_attempt_lease_expires_at(
                        now
                    )
                ),
            )
        )


        # =================================
        # Chunk → Running
        # =================================

        chunk.status = (
            AnalysisChunk
            .Status
            .RUNNING
        )


        if (
            chunk.started_at
            is None
        ):

            chunk.started_at = (
                now
            )


        chunk.completed_at = None

        chunk.status_reason = ""


        # --------------------------------
        # Legacy 호환
        #
        # 새로운 실행의 Source of Truth는
        # Attempt heartbeat_at이다.
        # --------------------------------

        chunk.heartbeat_at = (
            now
        )


        chunk.save(
            update_fields=[
                "status",
                "started_at",
                "completed_at",
                "status_reason",
                "heartbeat_at",
                "retry_count",
                "updated_at",
            ]
        )


        return {
            "claimed":
                True,

            "reason":
                "claimed",

            "analysis_run_id":
                analysis_run.id,

            "chunk_id":
                chunk.id,

            "chunk_status":
                chunk.status,

            "attempt_id":
                attempt.id,

            "attempt_no":
                attempt.attempt_no,

            "execution_token":
                str(
                    attempt.execution_token
                ),

            "lease_expires_at":
                attempt.lease_expires_at,

            "retry_count":
                chunk.retry_count,

            "max_retries":
                chunk.max_retries,
        }


# ========================================
# Attempt Heartbeat
#
# 정상 Worker가 주기적으로 호출한다.
#
# execution_token이 다르면
# 오래된 Worker로 간주하고 갱신 거부.
# ========================================

def heartbeat_attempt(
    attempt_id,
    execution_token,
):

    now = timezone.now()


    # ====================================
    # Attempt → Chunk ID 조회
    # ====================================

    try:

        attempt_reference = (
            AnalysisChunkAttempt.objects
            .only(
                "id",
                "chunk_id",
            )
            .get(
                pk=
                    attempt_id
            )
        )

    except AnalysisChunkAttempt.DoesNotExist:

        return {
            "updated":
                False,

            "reason":
                "attempt_not_found",

            "attempt_id":
                attempt_id,
        }


    # ====================================
    # Lock 순서
    #
    # Chunk
    # ↓
    # Attempt
    # ====================================

    with transaction.atomic():

        try:

            chunk = (
                AnalysisChunk.objects
                .select_for_update()
                .get(
                    pk=
                        attempt_reference
                        .chunk_id
                )
            )

        except AnalysisChunk.DoesNotExist:

            return {
                "updated":
                    False,

                "reason":
                    "chunk_not_found",

                "attempt_id":
                    attempt_id,
            }


        try:

            attempt = (
                AnalysisChunkAttempt.objects
                .select_for_update()
                .get(
                    pk=
                        attempt_id
                )
            )

        except AnalysisChunkAttempt.DoesNotExist:

            return {
                "updated":
                    False,

                "reason":
                    "attempt_not_found",

                "attempt_id":
                    attempt_id,
            }


        # =================================
        # Token 확인
        # =================================

        if (
            str(
                attempt.execution_token
            )
            !=
            str(
                execution_token
                or ""
            )
        ):

            return {
                "updated":
                    False,

                "reason":
                    "execution_token_mismatch",

                "attempt_id":
                    attempt.id,

                "chunk_id":
                    chunk.id,
            }


        # =================================
        # Attempt Running 확인
        # =================================

        if (
            attempt.status
            !=
            AnalysisChunkAttempt
            .Status
            .RUNNING
        ):

            return {
                "updated":
                    False,

                "reason":
                    "attempt_not_running",

                "attempt_id":
                    attempt.id,

                "chunk_id":
                    chunk.id,

                "attempt_status":
                    attempt.status,
            }


        # =================================
        # Chunk Running 확인
        # =================================

        if (
            chunk.status
            !=
            AnalysisChunk
            .Status
            .RUNNING
        ):

            return {
                "updated":
                    False,

                "reason":
                    "chunk_not_running",

                "attempt_id":
                    attempt.id,

                "chunk_id":
                    chunk.id,

                "chunk_status":
                    chunk.status,
            }


        # =================================
        # Heartbeat / Lease 연장
        # =================================

        attempt.heartbeat_at = (
            now
        )

        attempt.lease_expires_at = (
            build_attempt_lease_expires_at(
                now
            )
        )


        attempt.save(
            update_fields=[
                "heartbeat_at",
                "lease_expires_at",
                "updated_at",
            ]
        )


        # --------------------------------
        # Legacy Chunk heartbeat
        # --------------------------------

        chunk.heartbeat_at = (
            now
        )


        chunk.save(
            update_fields=[
                "heartbeat_at",
                "updated_at",
            ]
        )


        return {
            "updated":
                True,

            "reason":
                "heartbeat_updated",

            "attempt_id":
                attempt.id,

            "chunk_id":
                chunk.id,

            "heartbeat_at":
                attempt.heartbeat_at,

            "lease_expires_at":
                attempt.lease_expires_at,
        }