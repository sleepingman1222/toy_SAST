# backend/scans/services/run_state_manager.py

from django.db import transaction
from django.utils import timezone

from scans.models import (
    AnalysisChunk,
    AnalysisRun,
)


# ========================================
# AnalysisRun State Error
# ========================================

class RunStateError(
    RuntimeError
):

    pass


# ========================================
# Active Chunk Status
# ========================================

ACTIVE_CHUNK_STATUSES = {

    AnalysisChunk
    .Status
    .PENDING,

    AnalysisChunk
    .Status
    .QUEUED,

    AnalysisChunk
    .Status
    .RUNNING,

    AnalysisChunk
    .Status
    .RETRY_PENDING,
}


# ========================================
# Terminal Chunk Status
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
# Terminal AnalysisRun Status
#
# 한번 최종 상태가 된 Run은
# Aggregator가 다시 running으로
# 되돌리지 않는다.
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
# Chunk Status Count
# ========================================

def build_chunk_status_counts(
    chunks,
):

    counts = {

        AnalysisChunk.Status.PENDING:
            0,

        AnalysisChunk.Status.QUEUED:
            0,

        AnalysisChunk.Status.RUNNING:
            0,

        AnalysisChunk.Status.RETRY_PENDING:
            0,

        AnalysisChunk.Status.COMPLETED:
            0,

        AnalysisChunk.Status.FAILED:
            0,

        AnalysisChunk.Status.SKIPPED:
            0,

        AnalysisChunk.Status.CANCELLED:
            0,
    }


    for chunk in chunks:

        if (
            chunk.status
            not in
            counts
        ):

            raise RunStateError(
                "알 수 없는 AnalysisChunk 상태가 "
                "존재합니다. "
                f"chunk_id={chunk.id}, "
                f"status={chunk.status}"
            )


        counts[
            chunk.status
        ] += 1


    return counts


# ========================================
# Count 합산 Helper
# ========================================

def sum_status_counts(
    counts,
    statuses,
):

    return sum(

        counts.get(
            status,
            0,
        )

        for status
        in statuses
    )


# ========================================
# AnalysisRun 상태 집계
#
# PostgreSQL = Source of Truth
#
# Lock 순서:
#
# AnalysisRun
# ↓
# AnalysisChunk
#
# Chunk Executor / State Manager와
# 동일한 상위 Lock 순서를 유지한다.
# ========================================

def aggregate_analysis_run_state(
    analysis_run_id,
):

    now = timezone.now()


    with transaction.atomic():

        # =================================
        # AnalysisRun Lock
        # =================================

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
                "updated":
                    False,

                "reason":
                    "analysis_run_not_found",

                "analysis_run_id":
                    analysis_run_id,
            }


        previous_status = (
            analysis_run.status
        )


        # =================================
        # Chunk 전체 Lock
        #
        # 집계 도중 Chunk 상태가 변경되는 것을
        # 방지한다.
        # =================================

        chunks = list(

            AnalysisChunk.objects
            .select_for_update()
            .filter(
                analysis_run=
                    analysis_run
            )
            .order_by(
                "id"
            )
        )


        counts = (
            build_chunk_status_counts(
                chunks
            )
        )


        total_count = (
            len(
                chunks
            )
        )


        active_count = (
            sum_status_counts(
                counts,
                ACTIVE_CHUNK_STATUSES,
            )
        )


        completed_count = (
            counts[
                AnalysisChunk
                .Status
                .COMPLETED
            ]
        )


        failed_count = (
            counts[
                AnalysisChunk
                .Status
                .FAILED
            ]
        )


        skipped_count = (
            counts[
                AnalysisChunk
                .Status
                .SKIPPED
            ]
        )


        cancelled_count = (
            counts[
                AnalysisChunk
                .Status
                .CANCELLED
            ]
        )


        # =================================
        # AnalysisRun Terminal 상태
        #
        # 이미 completed / failed /
        # cancelled 상태라면
        # Aggregator가 다시 변경하지 않는다.
        # =================================

        if (
            analysis_run.status
            in
            TERMINAL_RUN_STATUSES
        ):

            return {
                "updated":
                    False,

                "reason":
                    "analysis_run_terminal",

                "analysis_run_id":
                    analysis_run.id,

                "previous_status":
                    previous_status,

                "status":
                    analysis_run.status,

                "total_chunk_count":
                    total_count,

                "active_chunk_count":
                    active_count,

                "completed_chunk_count":
                    completed_count,

                "failed_chunk_count":
                    failed_count,

                "skipped_chunk_count":
                    skipped_count,

                "cancelled_chunk_count":
                    cancelled_count,
            }


        # =================================
        # Chunk가 아직 하나도 없음
        #
        # planning 이전 또는 planning 중일 수
        # 있으므로 상태를 임의로 바꾸지 않는다.
        # =================================

        if total_count == 0:

            return {
                "updated":
                    False,

                "reason":
                    "no_chunks",

                "analysis_run_id":
                    analysis_run.id,

                "previous_status":
                    previous_status,

                "status":
                    analysis_run.status,

                "total_chunk_count":
                    0,

                "active_chunk_count":
                    0,

                "completed_chunk_count":
                    0,

                "failed_chunk_count":
                    0,

                "skipped_chunk_count":
                    0,

                "cancelled_chunk_count":
                    0,
            }


        # =================================
        # 아직 실행 중인 Chunk 존재
        #
        # pending
        # queued
        # running
        # retry_pending
        #
        # 하나라도 있으면 Run은 running.
        # =================================

        if active_count > 0:

            analysis_run.status = (
                AnalysisRun
                .Status
                .RUNNING
            )


            if (
                analysis_run.started_at
                is None
            ):

                analysis_run.started_at = (
                    now
                )


            analysis_run.completed_at = None

            analysis_run.failure_reason = ""


            analysis_run.save(
                update_fields=[
                    "status",
                    "started_at",
                    "completed_at",
                    "failure_reason",
                    "updated_at",
                ]
            )


            return {
                "updated":
                    (
                        previous_status
                        !=
                        analysis_run.status
                    ),

                "reason":
                    "active_chunks",

                "analysis_run_id":
                    analysis_run.id,

                "previous_status":
                    previous_status,

                "status":
                    analysis_run.status,

                "total_chunk_count":
                    total_count,

                "active_chunk_count":
                    active_count,

                "completed_chunk_count":
                    completed_count,

                "failed_chunk_count":
                    failed_count,

                "skipped_chunk_count":
                    skipped_count,

                "cancelled_chunk_count":
                    cancelled_count,
            }


        # =================================
        # 여기부터는 모든 Chunk가 Terminal
        # =================================


        # =================================
        # 실패 Chunk 존재
        #
        # 가장 높은 우선순위
        # =================================

        if failed_count > 0:

            analysis_run.status = (
                AnalysisRun
                .Status
                .FAILED
            )


            analysis_run.completed_at = (
                now
            )


            analysis_run.failure_reason = (
                f"{failed_count}개의 "
                "AnalysisChunk가 실패했습니다."
            )


            reason = (
                "chunk_failed"
            )


        # =================================
        # Cancelled 존재
        #
        # 실패가 없고 cancelled가 있다면
        # 전체 Run을 cancelled 처리.
        # =================================

        elif cancelled_count > 0:

            analysis_run.status = (
                AnalysisRun
                .Status
                .CANCELLED
            )


            analysis_run.completed_at = (
                now
            )


            analysis_run.failure_reason = ""


            reason = (
                "chunk_cancelled"
            )


        # =================================
        # 모든 Chunk가 skipped
        #
        # 실제 분석 성공 Chunk가 하나도 없음.
        #
        # completed로 보지 않는다.
        # =================================

        elif (
            completed_count == 0
            and
            skipped_count > 0
        ):

            analysis_run.status = (
                AnalysisRun
                .Status
                .FAILED
            )


            analysis_run.completed_at = (
                now
            )


            analysis_run.failure_reason = (
                "분석 가능한 AnalysisChunk가 "
                "없습니다."
            )


            reason = (
                "all_chunks_skipped"
            )


        # =================================
        # 나머지
        #
        # completed
        # +
        # 필요하면 skipped
        #
        # → 성공
        # =================================

        else:

            analysis_run.status = (
                AnalysisRun
                .Status
                .COMPLETED
            )


            analysis_run.completed_at = (
                now
            )


            analysis_run.failure_reason = ""


            reason = (
                "all_chunks_completed"
            )


        # =================================
        # 시작 시간이 없다면 보정
        # =================================

        if (
            analysis_run.started_at
            is None
        ):

            analysis_run.started_at = (
                now
            )


        analysis_run.save(
            update_fields=[
                "status",
                "started_at",
                "completed_at",
                "failure_reason",
                "updated_at",
            ]
        )


        return {
            "updated":
                (
                    previous_status
                    !=
                    analysis_run.status
                ),

            "reason":
                reason,

            "analysis_run_id":
                analysis_run.id,

            "previous_status":
                previous_status,

            "status":
                analysis_run.status,

            "total_chunk_count":
                total_count,

            "active_chunk_count":
                active_count,

            "completed_chunk_count":
                completed_count,

            "failed_chunk_count":
                failed_count,

            "skipped_chunk_count":
                skipped_count,

            "cancelled_chunk_count":
                cancelled_count,
        }