from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from scans.models import (
    AnalysisChunk,
    AnalysisChunkAttempt,
    AnalysisDispatchOutbox,
    AnalysisRun,
)

from scans.services.run_state_manager import (
    aggregate_analysis_run_state,
)


# ========================================
# Chunk State Error
# ========================================

class ChunkStateError(
    RuntimeError
):

    pass


# ========================================
# 저장 제한
# ========================================

MAX_ATTEMPT_ERROR_LENGTH = 4000

MAX_ATTEMPT_LOG_LENGTH = 20000


# ========================================
# Error / Log 길이 제한
# ========================================

def truncate_state_text(
    value,
    max_length,
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
# 다음 Outbox Dispatch 번호
#
# 반드시 Chunk row lock을 획득한
# Transaction 안에서 호출한다.
# ========================================

def get_next_dispatch_no(
    chunk,
):

    current_max = (
        AnalysisDispatchOutbox.objects
        .filter(
            chunk=
                chunk
        )
        .aggregate(
            max_dispatch=
                Max(
                    "dispatch_no"
                )
        )
        ["max_dispatch"]
        or 0
    )


    return (
        current_max
        + 1
    )


# ========================================
# Attempt Reference 조회
#
# Lock을 잡기 전에
# AnalysisRun / Chunk 식별자를 확보한다.
# ========================================

def get_attempt_reference(
    attempt_id,
):

    try:

        attempt_reference = (
            AnalysisChunkAttempt.objects
            .only(
                "id",
                "chunk_id",
                "chunk__analysis_run_id",
            )
            .select_related(
                "chunk"
            )
            .get(
                pk=
                    attempt_id
            )
        )


    except AnalysisChunkAttempt.DoesNotExist:

        return None


    return {
        "attempt_id":
            attempt_reference.id,

        "chunk_id":
            attempt_reference.chunk_id,

        "analysis_run_id":
            attempt_reference
            .chunk
            .analysis_run_id,
    }


# ========================================
# Attempt Token 검증
# ========================================

def is_execution_token_valid(
    attempt,
    execution_token,
):

    return (
        str(
            attempt.execution_token
        )
        ==
        str(
            execution_token
            or ""
        )
    )


# ========================================
# Attempt 성공 확정
#
# execution_token이 일치하는
# 현재 running Attempt만
# Chunk를 completed로 만들 수 있다.
#
#
# 중요:
#
# Chunk 완료와 AnalysisRun 상태 집계를
# 같은 최상위 Transaction 안에서 수행한다.
# ========================================

def complete_chunk_attempt(
    attempt_id,
    execution_token,
    result_count=0,
    raw_result=None,
    logs="",
):

    reference = (
        get_attempt_reference(
            attempt_id
        )
    )


    if reference is None:

        return {
            "completed":
                False,

            "reason":
                "attempt_not_found",

            "attempt_id":
                attempt_id,
        }


    now = timezone.now()


    # ====================================
    # Lock 순서
    #
    # AnalysisRun
    # ↓
    # AnalysisChunk
    # ↓
    # AnalysisChunkAttempt
    #
    # claim_chunk()과 같은 상위 Lock
    # 순서를 유지한다.
    # ====================================

    with transaction.atomic():

        try:

            analysis_run = (
                AnalysisRun.objects
                .select_for_update()
                .get(
                    pk=
                        reference[
                            "analysis_run_id"
                        ]
                )
            )


        except AnalysisRun.DoesNotExist:

            return {
                "completed":
                    False,

                "reason":
                    "analysis_run_not_found",

                "attempt_id":
                    attempt_id,
            }


        try:

            chunk = (
                AnalysisChunk.objects
                .select_for_update()
                .get(
                    pk=
                        reference[
                            "chunk_id"
                        ]
                )
            )


        except AnalysisChunk.DoesNotExist:

            return {
                "completed":
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
                "completed":
                    False,

                "reason":
                    "attempt_not_found",

                "attempt_id":
                    attempt_id,
            }


        # =================================
        # execution_token 검증
        # =================================

        if not (
            is_execution_token_valid(
                attempt,
                execution_token,
            )
        ):

            return {
                "completed":
                    False,

                "reason":
                    "execution_token_mismatch",

                "analysis_run_id":
                    analysis_run.id,

                "chunk_id":
                    chunk.id,

                "attempt_id":
                    attempt.id,
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
                "completed":
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
                "completed":
                    False,

                "reason":
                    "chunk_not_running",

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
        # AnalysisRun도 Running 확인
        #
        # 이미 cancelled / failed /
        # completed가 된 Run에는
        # stale Worker 결과를 반영하지 않는다.
        # =================================

        if (
            analysis_run.status
            !=
            AnalysisRun
            .Status
            .RUNNING
        ):

            return {
                "completed":
                    False,

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
        # Result Count 안전 변환
        # =================================

        try:

            result_count = max(
                int(
                    result_count
                ),
                0,
            )


        except (
            TypeError,
            ValueError,
        ):

            result_count = 0


        normalized_logs = (
            truncate_state_text(
                logs,
                MAX_ATTEMPT_LOG_LENGTH,
            )
        )


        # =================================
        # Attempt → Completed
        # =================================

        attempt.status = (
            AnalysisChunkAttempt
            .Status
            .COMPLETED
        )

        attempt.completed_at = (
            now
        )

        attempt.heartbeat_at = (
            now
        )

        attempt.result_count = (
            result_count
        )

        attempt.failure_reason = ""

        attempt.logs = (
            normalized_logs
        )

        attempt.raw_result = (
            raw_result
        )


        attempt.save(
            update_fields=[
                "status",
                "completed_at",
                "heartbeat_at",
                "result_count",
                "failure_reason",
                "logs",
                "raw_result",
                "updated_at",
            ]
        )


        # =================================
        # Chunk → Completed
        # =================================

        chunk.status = (
            AnalysisChunk
            .Status
            .COMPLETED
        )

        chunk.completed_at = (
            now
        )

        chunk.status_reason = ""

        chunk.result_count = (
            result_count
        )


        # --------------------------------
        # Legacy 호환 필드
        #
        # 새로운 Source of Truth는
        # Attempt지만 기존 API 전환 중
        # 호환을 위해 유지한다.
        # --------------------------------

        chunk.heartbeat_at = (
            now
        )

        chunk.failure_reason = ""

        chunk.logs = (
            normalized_logs
        )

        chunk.raw_result = (
            raw_result
        )


        chunk.save(
            update_fields=[
                "status",
                "completed_at",
                "status_reason",
                "result_count",
                "heartbeat_at",
                "failure_reason",
                "logs",
                "raw_result",
                "updated_at",
            ]
        )


        # =================================
        # AnalysisRun 상태 집계
        #
        # 현재 Transaction 내부에서 호출.
        #
        # 다른 Chunk가 남아 있으면:
        # running
        #
        # 모든 Chunk가 완료되면:
        # completed
        #
        # 실패 Chunk가 존재하고
        # 모든 Chunk가 terminal이면:
        # failed
        # =================================

        run_state = (
            aggregate_analysis_run_state(
                analysis_run.id
            )
        )


        return {
            "completed":
                True,

            "reason":
                "completed",

            "analysis_run_id":
                analysis_run.id,

            "chunk_id":
                chunk.id,

            "attempt_id":
                attempt.id,

            "attempt_no":
                attempt.attempt_no,

            "result_count":
                result_count,

            "run_state":
                run_state,
        }


# ========================================
# Attempt 실패 확정
#
# retryable=True
#
# Retry Budget 남음
# ↓
# Chunk = retry_pending
# ↓
# 새 Pending Outbox 생성
# ↓
# Run 상태 집계
#
#
# Retry 불가능 또는 Budget 소진
# ↓
# Chunk = failed
# ↓
# Run 상태 집계
# ========================================

def fail_chunk_attempt(
    attempt_id,
    execution_token,
    failure_reason,
    logs="",
    raw_result=None,
    retryable=True,
):

    reference = (
        get_attempt_reference(
            attempt_id
        )
    )


    if reference is None:

        return {
            "failed":
                False,

            "reason":
                "attempt_not_found",

            "attempt_id":
                attempt_id,
        }


    now = timezone.now()


    normalized_failure_reason = (
        truncate_state_text(
            failure_reason,
            MAX_ATTEMPT_ERROR_LENGTH,
        )
    )


    normalized_logs = (
        truncate_state_text(
            logs,
            MAX_ATTEMPT_LOG_LENGTH,
        )
    )


    with transaction.atomic():

        try:

            analysis_run = (
                AnalysisRun.objects
                .select_for_update()
                .get(
                    pk=
                        reference[
                            "analysis_run_id"
                        ]
                )
            )


        except AnalysisRun.DoesNotExist:

            return {
                "failed":
                    False,

                "reason":
                    "analysis_run_not_found",

                "attempt_id":
                    attempt_id,
            }


        try:

            chunk = (
                AnalysisChunk.objects
                .select_for_update()
                .get(
                    pk=
                        reference[
                            "chunk_id"
                        ]
                )
            )


        except AnalysisChunk.DoesNotExist:

            return {
                "failed":
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
                "failed":
                    False,

                "reason":
                    "attempt_not_found",

                "attempt_id":
                    attempt_id,
            }


        # =================================
        # execution_token 검증
        # =================================

        if not (
            is_execution_token_valid(
                attempt,
                execution_token,
            )
        ):

            return {
                "failed":
                    False,

                "reason":
                    "execution_token_mismatch",

                "analysis_run_id":
                    analysis_run.id,

                "chunk_id":
                    chunk.id,

                "attempt_id":
                    attempt.id,
            }


        # =================================
        # 동일 실패 처리 중복 차단
        #
        # 동일 Exception Handler가
        # 두 번 호출되어도 Outbox가
        # 추가 생성되면 안 된다.
        # =================================

        if (
            attempt.status
            !=
            AnalysisChunkAttempt
            .Status
            .RUNNING
        ):

            return {
                "failed":
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
                "failed":
                    False,

                "reason":
                    "chunk_not_running",

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
        # Attempt → Failed
        # =================================

        attempt.status = (
            AnalysisChunkAttempt
            .Status
            .FAILED
        )

        attempt.completed_at = (
            now
        )

        attempt.heartbeat_at = (
            now
        )

        attempt.failure_reason = (
            normalized_failure_reason
        )

        attempt.logs = (
            normalized_logs
        )

        attempt.raw_result = (
            raw_result
        )


        attempt.save(
            update_fields=[
                "status",
                "completed_at",
                "heartbeat_at",
                "failure_reason",
                "logs",
                "raw_result",
                "updated_at",
            ]
        )


        # =================================
        # Run 자체가 실행 중인지 확인
        #
        # Run이 cancelled / failed 등이라면
        # Retry하지 않는다.
        # =================================

        run_allows_retry = (
            analysis_run.status
            ==
            AnalysisRun
            .Status
            .RUNNING
        )


        # =================================
        # Retry Budget
        #
        # retry_count:
        #
        # 지금까지 실제 시작한 retry 횟수.
        #
        # retry_count < max_retries이면
        # 아직 다음 Retry 실행 기회가 있다.
        # =================================

        has_retry_budget = (
            chunk.retry_count
            <
            chunk.max_retries
        )


        should_retry = (
            bool(
                retryable
            )

            and

            run_allows_retry

            and

            has_retry_budget
        )


        # =================================
        # Retry Pending
        # =================================

        if should_retry:

            chunk.status = (
                AnalysisChunk
                .Status
                .RETRY_PENDING
            )

            chunk.completed_at = None

            chunk.status_reason = (
                "ATTEMPT_FAILED_RETRY_PENDING"
            )


            # --------------------------------
            # Legacy
            # --------------------------------

            chunk.failure_reason = (
                normalized_failure_reason
            )

            chunk.logs = (
                normalized_logs
            )

            chunk.raw_result = (
                raw_result
            )


            chunk.save(
                update_fields=[
                    "status",
                    "completed_at",
                    "status_reason",
                    "failure_reason",
                    "logs",
                    "raw_result",
                    "updated_at",
                ]
            )


            # =================================
            # Retry Outbox
            #
            # Chunk retry_pending 전환과
            # 같은 Transaction에서 생성한다.
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
            # AnalysisRun 상태 집계
            #
            # retry_pending은 Active Chunk라서
            # Run은 running을 유지한다.
            # =================================

            run_state = (
                aggregate_analysis_run_state(
                    analysis_run.id
                )
            )


            return {
                "failed":
                    True,

                "reason":
                    "retry_pending",

                "analysis_run_id":
                    analysis_run.id,

                "chunk_id":
                    chunk.id,

                "attempt_id":
                    attempt.id,

                "attempt_no":
                    attempt.attempt_no,

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
        # Retry 불가
        #
        # Chunk → Failed
        # =================================

        chunk.status = (
            AnalysisChunk
            .Status
            .FAILED
        )

        chunk.completed_at = (
            now
        )


        if not retryable:

            chunk.status_reason = (
                "NON_RETRYABLE_FAILURE"
            )


        elif not run_allows_retry:

            chunk.status_reason = (
                "ANALYSIS_RUN_NOT_RUNNING"
            )


        else:

            chunk.status_reason = (
                "MAX_RETRIES_EXCEEDED"
            )


        # --------------------------------
        # Legacy
        # --------------------------------

        chunk.failure_reason = (
            normalized_failure_reason
        )

        chunk.logs = (
            normalized_logs
        )

        chunk.raw_result = (
            raw_result
        )


        chunk.save(
            update_fields=[
                "status",
                "completed_at",
                "status_reason",
                "failure_reason",
                "logs",
                "raw_result",
                "updated_at",
            ]
        )


        # =================================
        # AnalysisRun 상태 집계
        #
        # 다른 Active Chunk가 남아 있다면
        # Run은 아직 running.
        #
        # 모든 Chunk가 Terminal이라면
        # failed.
        # =================================

        run_state = (
            aggregate_analysis_run_state(
                analysis_run.id
            )
        )


        return {
            "failed":
                True,

            "reason":
                "chunk_failed",

            "analysis_run_id":
                analysis_run.id,

            "chunk_id":
                chunk.id,

            "attempt_id":
                attempt.id,

            "attempt_no":
                attempt.attempt_no,

            "chunk_status":
                chunk.status,

            "status_reason":
                chunk.status_reason,

            "retry_count":
                chunk.retry_count,

            "max_retries":
                chunk.max_retries,

            "run_state":
                run_state,
        }