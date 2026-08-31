from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from scans.models import (
    AnalysisChunk,
    AnalysisChunkAttempt,
    AnalysisDispatchOutbox,
    AnalysisRun,
)

from scans.services.chunk_executor import (
    claim_chunk,
)

from scans.services.chunk_state_manager import (
    complete_chunk_attempt,
    fail_chunk_attempt,
)


class Command(
    BaseCommand
):

    help = (
        "Chunk Attempt 성공 / 실패 / "
        "Retry Outbox / execution_token / "
        "AnalysisRun 자동 집계를 검증합니다."
    )


    # ====================================
    # PASS
    # ====================================

    def pass_test(
        self,
        number,
        message,
    ):

        self.stdout.write(
            self.style.SUCCESS(
                f"[PASS {number}] "
                f"{message}"
            )
        )


    # ====================================
    # Assert True
    # ====================================

    def assert_true(
        self,
        number,
        condition,
        message,
    ):

        if not condition:

            raise CommandError(
                f"\n[FAIL {number}] "
                f"{message}"
            )


        self.pass_test(
            number,
            message,
        )


    # ====================================
    # Assert Equal
    # ====================================

    def assert_equal(
        self,
        number,
        actual,
        expected,
        message,
    ):

        if (
            actual
            !=
            expected
        ):

            raise CommandError(
                f"\n[FAIL {number}] "
                f"{message}\n"
                f"expected={expected}\n"
                f"actual={actual}"
            )


        self.pass_test(
            number,
            message,
        )


    # ====================================
    # AnalysisRun 생성 Helper
    # ====================================

    def create_test_run(
        self,
        base_run,
        sequence,
    ):

        return (
            AnalysisRun.objects.create(

                project=
                    base_run.project,

                source_version=
                    base_run.source_version,

                sequence=
                    sequence,

                status=
                    AnalysisRun
                    .Status
                    .RUNNING,

                engine=
                    "Semgrep",

                analysis_language=
                    "python",

                analysis_languages=[
                    "python"
                ],

                executed_by=
                    base_run.executed_by,

                started_at=
                    timezone.now(),
            )
        )


    # ====================================
    # Chunk 생성 Helper
    # ====================================

    def create_chunk(
        self,
        analysis_run,
        sequence,
        status=None,
        retry_count=0,
        max_retries=3,
    ):

        if status is None:

            status = (
                AnalysisChunk
                .Status
                .QUEUED
            )


        completed_at = None


        if (
            status
            in (
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
            )
        ):

            completed_at = (
                timezone.now()
            )


        return (
            AnalysisChunk.objects.create(

                analysis_run=
                    analysis_run,

                language=
                    "python",

                sequence=
                    sequence,

                status=
                    status,

                file_count=
                    1,

                total_bytes=
                    100,

                retry_count=
                    retry_count,

                max_retries=
                    max_retries,

                completed_at=
                    completed_at,
            )
        )


    # ====================================
    # Main
    # ====================================

    def handle(
        self,
        *args,
        **options,
    ):

        self.stdout.write(
            self.style.MIGRATE_HEADING(
                "\n"
                "========================================\n"
                "Chunk State + Run Aggregation Test\n"
                "========================================"
            )
        )


        base_run = (
            AnalysisRun.objects
            .select_related(
                "project",
                "source_version",
                "executed_by",
            )
            .order_by(
                "id"
            )
            .first()
        )


        if base_run is None:

            raise CommandError(
                "기존 AnalysisRun이 필요합니다."
            )


        # =================================
        # 전체 Test Transaction
        # =================================

        with transaction.atomic():

            max_sequence = (
                AnalysisRun.objects
                .filter(
                    project=
                        base_run.project
                )
                .aggregate(
                    value=
                        Max(
                            "sequence"
                        )
                )
                ["value"]
                or 0
            )


            base_sequence = (
                max_sequence
                + 7000
            )


            # =================================
            # GROUP A
            #
            # Complete
            #
            # completed + skipped
            # → Run completed
            # =================================

            complete_run = (
                self.create_test_run(
                    base_run,
                    base_sequence,
                )
            )


            complete_chunk = (
                self.create_chunk(
                    complete_run,
                    1,
                )
            )


            # --------------------------------
            # Oversized 같은 skipped Chunk가
            # 함께 존재하는 상황
            # --------------------------------

            self.create_chunk(

                complete_run,

                2,

                status=(
                    AnalysisChunk
                    .Status
                    .SKIPPED
                ),
            )


            complete_claim = (
                claim_chunk(

                    complete_chunk.id,

                    celery_task_id=
                        "complete-task",
                )
            )


            self.assert_true(
                1,

                complete_claim[
                    "claimed"
                ],

                "Complete 테스트 Chunk Claim 성공",
            )


            complete_result = (
                complete_chunk_attempt(

                    complete_claim[
                        "attempt_id"
                    ],

                    complete_claim[
                        "execution_token"
                    ],

                    result_count=
                        5,

                    raw_result={
                        "results": [
                            1,
                            2,
                            3,
                            4,
                            5,
                        ]
                    },

                    logs=
                        "Semgrep completed",
                )
            )


            self.assert_true(
                2,

                complete_result[
                    "completed"
                ],

                "정상 Attempt Complete 성공",
            )


            complete_chunk.refresh_from_db()


            complete_attempt = (
                AnalysisChunkAttempt.objects
                .get(
                    pk=
                        complete_claim[
                            "attempt_id"
                        ]
                )
            )


            complete_run.refresh_from_db()


            # =================================
            # TEST 3
            # =================================

            self.assert_equal(
                3,

                complete_attempt.status,

                (
                    AnalysisChunkAttempt
                    .Status
                    .COMPLETED
                ),

                "Complete 후 Attempt completed",
            )


            # =================================
            # TEST 4
            # =================================

            self.assert_equal(
                4,

                complete_chunk.status,

                (
                    AnalysisChunk
                    .Status
                    .COMPLETED
                ),

                "Complete 후 Chunk completed",
            )


            # =================================
            # TEST 5
            # =================================

            self.assert_equal(
                5,

                complete_chunk.result_count,

                5,

                "Chunk result_count 저장",
            )


            # =================================
            # TEST 6
            #
            # 자동 Run Aggregation
            # =================================

            self.assert_equal(
                6,

                complete_run.status,

                (
                    AnalysisRun
                    .Status
                    .COMPLETED
                ),

                (
                    "completed + skipped 종료 후 "
                    "AnalysisRun 자동 completed"
                ),
            )


            # =================================
            # TEST 7
            # =================================

            self.assert_equal(
                7,

                complete_result[
                    "run_state"
                ][
                    "status"
                ],

                (
                    AnalysisRun
                    .Status
                    .COMPLETED
                ),

                "Complete 결과에 Run 집계 상태 포함",
            )


            # =================================
            # TEST 8
            #
            # Completed 재확정 불가
            # =================================

            duplicate_complete = (
                complete_chunk_attempt(

                    complete_claim[
                        "attempt_id"
                    ],

                    complete_claim[
                        "execution_token"
                    ],
                )
            )


            self.assert_true(
                8,

                not duplicate_complete[
                    "completed"
                ],

                "Completed Attempt 중복 Complete 차단",
            )


            # =================================
            # GROUP B
            #
            # Wrong Token
            # +
            # Retry
            #
            # retry_pending은 Active이므로
            # Run running 유지
            # =================================

            retry_run = (
                self.create_test_run(
                    base_run,
                    base_sequence + 1,
                )
            )


            retry_chunk = (
                self.create_chunk(
                    retry_run,
                    1,
                )
            )


            retry_claim = (
                claim_chunk(

                    retry_chunk.id,

                    celery_task_id=
                        "retry-task",
                )
            )


            wrong_complete = (
                complete_chunk_attempt(

                    retry_claim[
                        "attempt_id"
                    ],

                    "wrong-token",
                )
            )


            # =================================
            # TEST 9
            # =================================

            self.assert_equal(
                9,

                wrong_complete[
                    "reason"
                ],

                "execution_token_mismatch",

                "잘못된 Token Complete 차단",
            )


            retry_chunk.refresh_from_db()


            # =================================
            # TEST 10
            # =================================

            self.assert_equal(
                10,

                retry_chunk.status,

                (
                    AnalysisChunk
                    .Status
                    .RUNNING
                ),

                "잘못된 Token이 Chunk 상태를 변경하지 않음",
            )


            # =================================
            # Retryable Failure
            # =================================

            fail_result = (
                fail_chunk_attempt(

                    retry_claim[
                        "attempt_id"
                    ],

                    retry_claim[
                        "execution_token"
                    ],

                    failure_reason=
                        "Semgrep temporary failure",

                    logs=
                        "temporary",

                    retryable=
                        True,
                )
            )


            retry_chunk.refresh_from_db()

            retry_run.refresh_from_db()


            # =================================
            # TEST 11
            # =================================

            self.assert_true(
                11,

                fail_result[
                    "failed"
                ],

                "Retry 가능한 Attempt 실패 처리",
            )


            # =================================
            # TEST 12
            # =================================

            self.assert_equal(
                12,

                retry_chunk.status,

                (
                    AnalysisChunk
                    .Status
                    .RETRY_PENDING
                ),

                "실패 후 Chunk retry_pending",
            )


            # =================================
            # TEST 13
            # =================================

            self.assert_equal(
                13,

                retry_run.status,

                (
                    AnalysisRun
                    .Status
                    .RUNNING
                ),

                (
                    "retry_pending Chunk가 존재하므로 "
                    "AnalysisRun running 유지"
                ),
            )


            # =================================
            # TEST 14
            # =================================

            self.assert_equal(
                14,

                fail_result[
                    "run_state"
                ][
                    "reason"
                ],

                "active_chunks",

                "Retry Failure 후 Run Active 판정",
            )


            # =================================
            # Retry Outbox
            # =================================

            retry_outboxes = (
                AnalysisDispatchOutbox.objects
                .filter(
                    chunk=
                        retry_chunk
                )
            )


            self.assert_equal(
                15,

                retry_outboxes.count(),

                1,

                "실패와 동시에 Retry Outbox 생성",
            )


            retry_outbox = (
                retry_outboxes.get()
            )


            self.assert_equal(
                16,

                retry_outbox.status,

                (
                    AnalysisDispatchOutbox
                    .Status
                    .PENDING
                ),

                "Retry Outbox pending",
            )


            # =================================
            # 동일 Failure 중복 처리
            # =================================

            duplicate_failure = (
                fail_chunk_attempt(

                    retry_claim[
                        "attempt_id"
                    ],

                    retry_claim[
                        "execution_token"
                    ],

                    failure_reason=
                        "duplicate failure",

                    retryable=
                        True,
                )
            )


            self.assert_true(
                17,

                not duplicate_failure[
                    "failed"
                ],

                "동일 Attempt 실패 처리 중복 차단",
            )


            self.assert_equal(
                18,

                AnalysisDispatchOutbox.objects
                .filter(
                    chunk=
                        retry_chunk
                )
                .count(),

                1,

                (
                    "중복 Failure가 Retry Outbox를 "
                    "추가 생성하지 않음"
                ),
            )


            # =================================
            # GROUP C
            #
            # Non-Retryable
            #
            # 유일한 Chunk가 failed
            # → Run failed
            # =================================

            non_retry_run = (
                self.create_test_run(
                    base_run,
                    base_sequence + 2,
                )
            )


            non_retry_chunk = (
                self.create_chunk(
                    non_retry_run,
                    1,
                )
            )


            non_retry_claim = (
                claim_chunk(

                    non_retry_chunk.id,

                    celery_task_id=
                        "non-retryable-task",
                )
            )


            non_retry_result = (
                fail_chunk_attempt(

                    non_retry_claim[
                        "attempt_id"
                    ],

                    non_retry_claim[
                        "execution_token"
                    ],

                    failure_reason=
                        "Invalid source snapshot",

                    retryable=
                        False,
                )
            )


            non_retry_chunk.refresh_from_db()

            non_retry_run.refresh_from_db()


            # =================================
            # TEST 19
            # =================================

            self.assert_equal(
                19,

                non_retry_chunk.status,

                (
                    AnalysisChunk
                    .Status
                    .FAILED
                ),

                "Non-Retryable 실패 시 Chunk failed",
            )


            # =================================
            # TEST 20
            # =================================

            self.assert_equal(
                20,

                non_retry_chunk.status_reason,

                "NON_RETRYABLE_FAILURE",

                "Non-Retryable 실패 사유 기록",
            )


            # =================================
            # TEST 21
            # =================================

            self.assert_equal(
                21,

                AnalysisDispatchOutbox.objects
                .filter(
                    chunk=
                        non_retry_chunk
                )
                .count(),

                0,

                "Non-Retryable 실패는 Outbox 생성 안 함",
            )


            # =================================
            # TEST 22
            #
            # 자동 Run Failed
            # =================================

            self.assert_equal(
                22,

                non_retry_run.status,

                (
                    AnalysisRun
                    .Status
                    .FAILED
                ),

                (
                    "최종 Non-Retryable 실패 후 "
                    "AnalysisRun 자동 failed"
                ),
            )


            # =================================
            # TEST 23
            # =================================

            self.assert_equal(
                23,

                non_retry_result[
                    "run_state"
                ][
                    "reason"
                ],

                "chunk_failed",

                "최종 실패 Run 집계 사유 정상",
            )


            # =================================
            # GROUP D
            #
            # Retry Budget 소진
            # =================================

            exhausted_run = (
                self.create_test_run(
                    base_run,
                    base_sequence + 3,
                )
            )


            exhausted_chunk = (
                self.create_chunk(

                    exhausted_run,

                    1,

                    retry_count=
                        3,

                    max_retries=
                        3,
                )
            )


            exhausted_claim = (
                claim_chunk(

                    exhausted_chunk.id,

                    celery_task_id=
                        "budget-task",
                )
            )


            self.assert_true(
                24,

                exhausted_claim[
                    "claimed"
                ],

                "현재 Attempt 실행권 획득",
            )


            exhausted_result = (
                fail_chunk_attempt(

                    exhausted_claim[
                        "attempt_id"
                    ],

                    exhausted_claim[
                        "execution_token"
                    ],

                    failure_reason=
                        "retry budget exhausted",

                    retryable=
                        True,
                )
            )


            exhausted_chunk.refresh_from_db()

            exhausted_run.refresh_from_db()


            # =================================
            # TEST 25
            # =================================

            self.assert_equal(
                25,

                exhausted_chunk.status,

                (
                    AnalysisChunk
                    .Status
                    .FAILED
                ),

                "Retry Budget 소진 후 Chunk failed",
            )


            # =================================
            # TEST 26
            # =================================

            self.assert_equal(
                26,

                exhausted_chunk.status_reason,

                "MAX_RETRIES_EXCEEDED",

                "Retry Budget 소진 사유 저장",
            )


            # =================================
            # TEST 27
            # =================================

            self.assert_equal(
                27,

                AnalysisDispatchOutbox.objects
                .filter(
                    chunk=
                        exhausted_chunk
                )
                .count(),

                0,

                "Retry Budget 소진 시 Outbox 생성 안 함",
            )


            # =================================
            # TEST 28
            # =================================

            self.assert_equal(
                28,

                exhausted_run.status,

                (
                    AnalysisRun
                    .Status
                    .FAILED
                ),

                (
                    "Retry Budget 최종 소진 후 "
                    "AnalysisRun 자동 failed"
                ),
            )


            # =================================
            # GROUP E
            #
            # 한 Chunk Failed
            # +
            # 다른 Chunk Queued
            #
            # 아직 Run은 running이어야 한다.
            # =================================

            mixed_run = (
                self.create_test_run(
                    base_run,
                    base_sequence + 4,
                )
            )


            failed_chunk = (
                self.create_chunk(
                    mixed_run,
                    1,
                )
            )


            active_chunk = (
                self.create_chunk(
                    mixed_run,
                    2,
                )
            )


            mixed_claim = (
                claim_chunk(

                    failed_chunk.id,

                    celery_task_id=
                        "mixed-failure-task",
                )
            )


            mixed_failure = (
                fail_chunk_attempt(

                    mixed_claim[
                        "attempt_id"
                    ],

                    mixed_claim[
                        "execution_token"
                    ],

                    failure_reason=
                        "permanent failure",

                    retryable=
                        False,
                )
            )


            failed_chunk.refresh_from_db()

            active_chunk.refresh_from_db()

            mixed_run.refresh_from_db()


            # =================================
            # TEST 29
            # =================================

            self.assert_equal(
                29,

                failed_chunk.status,

                (
                    AnalysisChunk
                    .Status
                    .FAILED
                ),

                "Mixed Run의 첫 Chunk failed",
            )


            # =================================
            # TEST 30
            #
            # 다른 queued Chunk가 남아 있으므로
            # 전체 Run을 즉시 failed 처리하면 안 됨.
            # =================================

            self.assert_equal(
                30,

                mixed_run.status,

                (
                    AnalysisRun
                    .Status
                    .RUNNING
                ),

                (
                    "Failed Chunk가 있어도 Active Chunk가 "
                    "남아 있으면 Run running 유지"
                ),
            )


            # =================================
            # TEST 31
            # =================================

            self.assert_equal(
                31,

                mixed_failure[
                    "run_state"
                ][
                    "active_chunk_count"
                ],

                1,

                "Mixed Run Active Chunk 1개 집계",
            )


            # =================================
            # GROUP F
            #
            # 남아 있던 Chunk도 완료
            #
            # 이제:
            #
            # failed + completed
            #
            # 모두 terminal
            # → Run failed
            # =================================

            active_claim = (
                claim_chunk(

                    active_chunk.id,

                    celery_task_id=
                        "mixed-complete-task",
                )
            )


            self.assert_true(
                32,

                active_claim[
                    "claimed"
                ],

                "Mixed Run 남은 Chunk Claim 성공",
            )


            mixed_complete = (
                complete_chunk_attempt(

                    active_claim[
                        "attempt_id"
                    ],

                    active_claim[
                        "execution_token"
                    ],

                    result_count=
                        0,
                )
            )


            mixed_run.refresh_from_db()


            # =================================
            # TEST 33
            # =================================

            self.assert_true(
                33,

                mixed_complete[
                    "completed"
                ],

                "Mixed Run 남은 Chunk 완료",
            )


            # =================================
            # TEST 34
            #
            # 모든 Chunk terminal이고
            # failed가 존재하므로 Run failed.
            # =================================

            self.assert_equal(
                34,

                mixed_run.status,

                (
                    AnalysisRun
                    .Status
                    .FAILED
                ),

                (
                    "모든 Chunk 종료 후 Failed가 존재하면 "
                    "Run 자동 failed"
                ),
            )


            # =================================
            # TEST 35
            # =================================

            self.assert_equal(
                35,

                mixed_complete[
                    "run_state"
                ][
                    "reason"
                ],

                "chunk_failed",

                "Mixed Run 최종 실패 판정 정상",
            )


            # =================================
            # Rollback
            # =================================

            transaction.set_rollback(
                True
            )


        self.stdout.write(
            self.style.SUCCESS(
                "\n"
                "========================================\n"
                "Chunk State + Run Aggregation Test Finished\n"
                "모든 테스트 데이터는 Rollback 되었습니다.\n"
                "========================================"
            )
        )