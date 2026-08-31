from datetime import timedelta

from celery import current_app

from django.db import transaction
from django.utils import timezone

from scans.constants import (
    ANALYSIS_CHUNK_TASK_NAME,
    OUTBOX_CLAIM_SECONDS,
    OUTBOX_DISPATCH_BATCH_SIZE,
    OUTBOX_ERROR_MAX_LENGTH,
    OUTBOX_RETRY_BASE_SECONDS,
    OUTBOX_RETRY_MAX_SECONDS,
)

from scans.models import (
    AnalysisChunk,
    AnalysisDispatchOutbox,
    AnalysisRun,
)


# ========================================
# Dispatcher Error
# ========================================

class OutboxDispatchError(
    RuntimeError
):

    pass


# ========================================
# Dispatch 가능한 Chunk 상태
# ========================================

DISPATCHABLE_CHUNK_STATUSES = {

    AnalysisChunk
    .Status
    .QUEUED,

    AnalysisChunk
    .Status
    .RETRY_PENDING,
}


# ========================================
# 더 이상 실행하면 안 되는
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
# Error 문자열 제한
# ========================================

def truncate_outbox_error(
    value,
):

    value = str(
        value
        or ""
    )


    if (
        len(value)
        <=
        OUTBOX_ERROR_MAX_LENGTH
    ):

        return value


    return (
        value[
            :OUTBOX_ERROR_MAX_LENGTH
        ]
    )


# ========================================
# Retry Backoff 계산
#
# publish_attempts:
#
# 1 → 5초
# 2 → 10초
# 3 → 20초
# 4 → 40초
# ...
#
# 최대 300초
# ========================================

def calculate_retry_delay_seconds(
    publish_attempts,
):

    attempt_number = max(
        int(
            publish_attempts
            or 1
        ),
        1,
    )


    # 지나치게 큰 exponent 계산 방지
    exponent = min(
        attempt_number - 1,
        10,
    )


    delay_seconds = (
        OUTBOX_RETRY_BASE_SECONDS
        *
        (
            2
            **
            exponent
        )
    )


    return min(
        delay_seconds,
        OUTBOX_RETRY_MAX_SECONDS,
    )


# ========================================
# 실제 Celery Publish
#
# 중요:
#
# Dispatcher와 Chunk Worker를
# 직접 import로 강하게 연결하지 않는다.
#
# Task 이름만 Redis에 전달한다.
#
# STEP 5에서 아래 이름의 Task를 만든다.
#
# scans.tasks.run_analysis_chunk
# ========================================

def publish_chunk_task(
    chunk_id,
):

    async_result = (
        current_app.send_task(
            ANALYSIS_CHUNK_TASK_NAME,

            args=[
                chunk_id
            ],
        )
    )


    task_id = (
        str(
            async_result.id
            or ""
        )
    )


    if not task_id:

        raise OutboxDispatchError(
            "Celery Task ID를 "
            "확인할 수 없습니다."
        )


    return task_id


# ========================================
# Outbox Claim
#
# DB Transaction 안에서는
# 네트워크 통신을 절대 하지 않는다.
#
# 여기서는:
#
# 1. select_for_update
# 2. available_at을 미래로 이동
# 3. publish_attempts 증가
# 4. COMMIT
#
# 만 수행한다.
#
# 그 후 Redis publish는
# transaction 밖에서 수행한다.
# ========================================

def claim_pending_outboxes(
    batch_size=None,
):

    if batch_size is None:

        batch_size = (
            OUTBOX_DISPATCH_BATCH_SIZE
        )


    batch_size = max(
        int(
            batch_size
        ),
        1,
    )


    now = timezone.now()

    claim_until = (
        now
        +
        timedelta(
            seconds=
                OUTBOX_CLAIM_SECONDS
        )
    )


    claimed_items = []

    cancelled_count = 0

    deferred_count = 0


    with transaction.atomic():

        outboxes = list(
            AnalysisDispatchOutbox.objects
            .select_for_update(
                skip_locked=True
            )
            .select_related(
                "chunk",
                "chunk__analysis_run",
            )
            .filter(
                status=(
                    AnalysisDispatchOutbox
                    .Status
                    .PENDING
                ),

                available_at__lte=
                    now,
            )
            .order_by(
                "created_at",
                "id",
            )[
                :batch_size
            ]
        )


        for outbox in outboxes:

            chunk = (
                outbox.chunk
            )

            analysis_run = (
                chunk.analysis_run
            )


            # =================================
            # AnalysisRun이 이미 끝난 경우
            #
            # 더 이상 publish하지 않는다.
            # =================================

            if (
                analysis_run.status
                in
                TERMINAL_RUN_STATUSES
            ):

                outbox.status = (
                    AnalysisDispatchOutbox
                    .Status
                    .CANCELLED
                )

                outbox.last_error = (
                    "AnalysisRun이 이미 "
                    "종료 상태입니다."
                )


                outbox.save(
                    update_fields=[
                        "status",
                        "last_error",
                        "updated_at",
                    ]
                )


                cancelled_count += 1

                continue


            # =================================
            # Chunk가 이미 Terminal이면
            # Outbox 취소
            # =================================

            if (
                chunk.status
                in
                TERMINAL_CHUNK_STATUSES
            ):

                outbox.status = (
                    AnalysisDispatchOutbox
                    .Status
                    .CANCELLED
                )

                outbox.last_error = (
                    "AnalysisChunk가 이미 "
                    "종료 상태입니다."
                )


                outbox.save(
                    update_fields=[
                        "status",
                        "last_error",
                        "updated_at",
                    ]
                )


                cancelled_count += 1

                continue


            # =================================
            # Run은 아직 planning 등이고
            # 실행 상태가 아님
            #
            # 삭제하거나 실패시키지 않고
            # 잠시 뒤 다시 검사한다.
            # =================================

            if (
                analysis_run.status
                !=
                AnalysisRun
                .Status
                .RUNNING
            ):

                outbox.available_at = (
                    claim_until
                )


                outbox.save(
                    update_fields=[
                        "available_at",
                        "updated_at",
                    ]
                )


                deferred_count += 1

                continue


            # =================================
            # Chunk 상태가
            # queued / retry_pending이 아니면
            # 지금은 실행하지 않는다.
            # =================================

            if (
                chunk.status
                not in
                DISPATCHABLE_CHUNK_STATUSES
            ):

                outbox.available_at = (
                    claim_until
                )


                outbox.save(
                    update_fields=[
                        "available_at",
                        "updated_at",
                    ]
                )


                deferred_count += 1

                continue


            # =================================
            # Claim
            #
            # Status는 pending 유지.
            #
            # process crash 시
            # claim_until이 지나면
            # 다시 가져갈 수 있다.
            # =================================

            outbox.publish_attempts += 1

            outbox.available_at = (
                claim_until
            )


            outbox.save(
                update_fields=[
                    "publish_attempts",
                    "available_at",
                    "updated_at",
                ]
            )


            claimed_items.append({
                "outbox_id":
                    outbox.id,

                "chunk_id":
                    chunk.id,

                "event_key":
                    str(
                        outbox.event_key
                    ),

                "publish_attempts":
                    outbox.publish_attempts,
            })


    return {
        "items":
            claimed_items,

        "cancelled_count":
            cancelled_count,

        "deferred_count":
            deferred_count,
    }


# ========================================
# Publish 성공 기록
# ========================================

def mark_outbox_published(
    outbox_id,
    celery_task_id,
):

    now = timezone.now()


    with transaction.atomic():

        outbox = (
            AnalysisDispatchOutbox.objects
            .select_for_update()
            .get(
                pk=outbox_id
            )
        )


        # --------------------------------
        # Publish하는 동안 다른 흐름에서
        # cancel 등이 발생했다면
        # 그 상태를 덮어쓰지 않는다.
        # --------------------------------

        if (
            outbox.status
            !=
            AnalysisDispatchOutbox
            .Status
            .PENDING
        ):

            return False


        outbox.status = (
            AnalysisDispatchOutbox
            .Status
            .PUBLISHED
        )

        outbox.celery_task_id = (
            str(
                celery_task_id
            )[:255]
        )

        outbox.published_at = (
            now
        )

        outbox.last_error = ""


        outbox.save(
            update_fields=[
                "status",
                "celery_task_id",
                "published_at",
                "last_error",
                "updated_at",
            ]
        )


    return True


# ========================================
# Publish 실패 기록
# ========================================

def mark_outbox_publish_failed(
    outbox_id,
    error,
):

    now = timezone.now()


    with transaction.atomic():

        outbox = (
            AnalysisDispatchOutbox.objects
            .select_for_update()
            .get(
                pk=outbox_id
            )
        )


        # 다른 흐름에서 이미 처리됐다면
        # 현재 상태를 덮어쓰지 않는다.

        if (
            outbox.status
            !=
            AnalysisDispatchOutbox
            .Status
            .PENDING
        ):

            return False


        retry_delay_seconds = (
            calculate_retry_delay_seconds(
                outbox.publish_attempts
            )
        )


        outbox.available_at = (
            now
            +
            timedelta(
                seconds=
                    retry_delay_seconds
            )
        )

        outbox.last_error = (
            truncate_outbox_error(
                error
            )
        )


        outbox.save(
            update_fields=[
                "available_at",
                "last_error",
                "updated_at",
            ]
        )


    return True


# ========================================
# Pending Outbox Dispatch
#
# publish_func는 테스트를 위해
# Dependency Injection 가능하게 한다.
#
# 실제 운영:
#
# dispatch_pending_outboxes()
#
# 테스트:
#
# dispatch_pending_outboxes(
#     publish_func=fake_publish
# )
# ========================================

def dispatch_pending_outboxes(
    publish_func=None,
    batch_size=None,
):

    if publish_func is None:

        publish_func = (
            publish_chunk_task
        )


    claim_result = (
        claim_pending_outboxes(
            batch_size=
                batch_size
        )
    )


    items = (
        claim_result[
            "items"
        ]
    )


    published_count = 0

    failed_count = 0

    state_changed_count = 0


    for item in items:

        outbox_id = (
            item[
                "outbox_id"
            ]
        )

        chunk_id = (
            item[
                "chunk_id"
            ]
        )


        try:

            # =================================
            # Redis / Celery Network I/O
            #
            # DB Transaction 밖
            # =================================

            celery_task_id = (
                publish_func(
                    chunk_id
                )
            )


            if not celery_task_id:

                raise OutboxDispatchError(
                    "Publisher가 빈 "
                    "Celery Task ID를 반환했습니다."
                )


            updated = (
                mark_outbox_published(
                    outbox_id,
                    celery_task_id,
                )
            )


            if updated:

                published_count += 1

            else:

                # Publish는 됐지만
                # DB 상태가 이미 다른 흐름에서
                # 변경된 경우
                state_changed_count += 1


        except Exception as error:

            updated = (
                mark_outbox_publish_failed(
                    outbox_id,
                    error,
                )
            )


            if updated:

                failed_count += 1

            else:

                state_changed_count += 1


    return {
        "claimed_count":
            len(
                items
            ),

        "published_count":
            published_count,

        "failed_count":
            failed_count,

        "cancelled_count":
            claim_result[
                "cancelled_count"
            ],

        "deferred_count":
            claim_result[
                "deferred_count"
            ],

        "state_changed_count":
            state_changed_count,
    }