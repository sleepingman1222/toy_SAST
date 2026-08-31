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
    AnalysisRun,
)

from scans.services.chunk_executor import (
    claim_chunk,
    heartbeat_attempt,
)


class Command(
    BaseCommand
):

    help = (
        "AnalysisChunk Claim / Attempt / "
        "Execution Token / Heartbeat / "
        "Retry 정책을 검증합니다."
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
                "Chunk Claim Test\n"
                "========================================"
            )
        )


        # =================================
        # 기존 FK 재사용용 AnalysisRun
        # =================================

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
        #
        # 마지막에 Rollback
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


            test_run = (
                AnalysisRun.objects.create(

                    project=
                        base_run.project,

                    source_version=
                        base_run.source_version,

                    sequence=
                        max_sequence
                        + 4000,

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


            # =================================
            # Chunk #1
            #
            # 최초 Claim
            # =================================

            chunk_1 = (
                AnalysisChunk.objects.create(

                    analysis_run=
                        test_run,

                    language=
                        "python",

                    sequence=
                        1,

                    status=
                        AnalysisChunk
                        .Status
                        .QUEUED,

                    file_count=
                        1,

                    total_bytes=
                        100,

                    retry_count=
                        0,

                    max_retries=
                        3,
                )
            )


            first_claim = (
                claim_chunk(
                    chunk_1.id,

                    celery_task_id=
                        "fake-task-1",
                )
            )


            chunk_1.refresh_from_db()


            # =================================
            # TEST 1
            # =================================

            self.assert_true(
                1,

                first_claim[
                    "claimed"
                ],

                "Queued Chunk 최초 Claim 성공",
            )


            # =================================
            # TEST 2
            # =================================

            self.assert_equal(
                2,

                chunk_1.status,

                (
                    AnalysisChunk
                    .Status
                    .RUNNING
                ),

                "Claim 후 Chunk running",
            )


            # =================================
            # TEST 3
            # =================================

            self.assert_equal(
                3,

                AnalysisChunkAttempt.objects
                .filter(
                    chunk=
                        chunk_1
                )
                .count(),

                1,

                "최초 Claim에서 Attempt 1개 생성",
            )


            attempt_1 = (
                AnalysisChunkAttempt.objects
                .get(
                    chunk=
                        chunk_1
                )
            )


            # =================================
            # TEST 4
            # =================================

            self.assert_equal(
                4,

                attempt_1.attempt_no,

                1,

                "최초 Attempt 번호 = 1",
            )


            # =================================
            # TEST 5
            # =================================

            self.assert_equal(
                5,

                attempt_1.celery_task_id,

                "fake-task-1",

                "Celery Task ID 기록",
            )


            # =================================
            # TEST 6
            #
            # 최초 실행은 Retry가 아님
            # =================================

            self.assert_equal(
                6,

                chunk_1.retry_count,

                0,

                "최초 Claim에서는 retry_count 증가 안 함",
            )


            # =================================
            # TEST 7
            #
            # Duplicate Celery Message
            # =================================

            second_claim = (
                claim_chunk(
                    chunk_1.id,

                    celery_task_id=
                        "fake-task-duplicate",
                )
            )


            self.assert_true(
                7,

                not second_claim[
                    "claimed"
                ],

                "동일 Running Chunk 중복 Claim 차단",
            )


            # =================================
            # TEST 8
            # =================================

            self.assert_equal(
                8,

                second_claim[
                    "reason"
                ],

                "already_running",

                "중복 Claim 사유 = already_running",
            )


            # =================================
            # TEST 9
            #
            # 중복 Claim 이후에도
            # Attempt는 1개
            # =================================

            self.assert_equal(
                9,

                AnalysisChunkAttempt.objects
                .filter(
                    chunk=
                        chunk_1
                )
                .count(),

                1,

                "중복 Celery Message가 새 Attempt를 만들지 않음",
            )


            # =================================
            # TEST 10
            #
            # execution_token 존재
            # =================================

            self.assert_true(
                10,

                bool(
                    first_claim[
                        "execution_token"
                    ]
                ),

                "Attempt execution_token 생성",
            )


            # =================================
            # TEST 11
            #
            # 잘못된 Token Heartbeat
            # =================================

            wrong_heartbeat = (
                heartbeat_attempt(
                    attempt_1.id,

                    "wrong-token",
                )
            )


            self.assert_true(
                11,

                not wrong_heartbeat[
                    "updated"
                ],

                "잘못된 execution_token Heartbeat 차단",
            )


            # =================================
            # TEST 12
            # =================================

            self.assert_equal(
                12,

                wrong_heartbeat[
                    "reason"
                ],

                "execution_token_mismatch",

                "잘못된 Token 거부 사유 정상",
            )


            # =================================
            # TEST 13
            #
            # 정상 Heartbeat
            # =================================

            old_lease = (
                attempt_1
                .lease_expires_at
            )


            heartbeat_result = (
                heartbeat_attempt(

                    attempt_1.id,

                    first_claim[
                        "execution_token"
                    ],
                )
            )


            attempt_1.refresh_from_db()


            self.assert_true(
                13,

                heartbeat_result[
                    "updated"
                ],

                "정상 execution_token Heartbeat 성공",
            )


            # =================================
            # TEST 14
            # =================================

            self.assert_true(
                14,

                (
                    attempt_1
                    .lease_expires_at
                    >=
                    old_lease
                ),

                "Heartbeat 후 Lease 연장",
            )


            # =================================
            # Chunk #2
            #
            # Retry Pending
            # =================================

            chunk_2 = (
                AnalysisChunk.objects.create(

                    analysis_run=
                        test_run,

                    language=
                        "python",

                    sequence=
                        2,

                    status=
                        AnalysisChunk
                        .Status
                        .RETRY_PENDING,

                    file_count=
                        1,

                    total_bytes=
                        100,

                    retry_count=
                        0,

                    max_retries=
                        3,
                )
            )


            # --------------------------------
            # 이전 실패 Attempt #1
            # --------------------------------

            AnalysisChunkAttempt.objects.create(

                chunk=
                    chunk_2,

                attempt_no=
                    1,

                status=(
                    AnalysisChunkAttempt
                    .Status
                    .FAILED
                ),

                started_at=
                    timezone.now(),

                heartbeat_at=
                    timezone.now(),

                lease_expires_at=
                    timezone.now(),

                completed_at=
                    timezone.now(),

                failure_reason=
                    "TEST_FAILURE",
            )


            retry_claim = (
                claim_chunk(
                    chunk_2.id,

                    celery_task_id=
                        "fake-retry-task",
                )
            )


            chunk_2.refresh_from_db()


            # =================================
            # TEST 15
            # =================================

            self.assert_true(
                15,

                retry_claim[
                    "claimed"
                ],

                "retry_pending Chunk Claim 성공",
            )


            # =================================
            # TEST 16
            # =================================

            self.assert_equal(
                16,

                retry_claim[
                    "attempt_no"
                ],

                2,

                "Retry에서 Attempt #2 생성",
            )


            # =================================
            # TEST 17
            # =================================

            self.assert_equal(
                17,

                chunk_2.retry_count,

                1,

                "실제 Retry Claim 시 retry_count +1",
            )


            # =================================
            # Chunk #3
            #
            # Retry Budget 초과
            # =================================

            chunk_3 = (
                AnalysisChunk.objects.create(

                    analysis_run=
                        test_run,

                    language=
                        "python",

                    sequence=
                        3,

                    status=
                        AnalysisChunk
                        .Status
                        .RETRY_PENDING,

                    file_count=
                        1,

                    total_bytes=
                        100,

                    retry_count=
                        3,

                    max_retries=
                        3,
                )
            )


            exhausted_claim = (
                claim_chunk(
                    chunk_3.id,

                    celery_task_id=
                        "should-not-run",
                )
            )


            chunk_3.refresh_from_db()


            # =================================
            # TEST 18
            # =================================

            self.assert_true(
                18,

                not exhausted_claim[
                    "claimed"
                ],

                "Retry Budget 초과 Chunk Claim 차단",
            )


            # =================================
            # TEST 19
            # =================================

            self.assert_equal(
                19,

                exhausted_claim[
                    "reason"
                ],

                "max_retries_exceeded",

                "Retry Budget 초과 사유 정상",
            )


            # =================================
            # TEST 20
            # =================================

            self.assert_equal(
                20,

                chunk_3.status,

                (
                    AnalysisChunk
                    .Status
                    .FAILED
                ),

                "Retry Budget 소진 후 Chunk failed",
            )


            # =================================
            # TEST 21
            # =================================

            self.assert_equal(
                21,

                chunk_3.status_reason,

                "MAX_RETRIES_EXCEEDED",

                "Retry Budget 실패 사유 저장",
            )


            # =================================
            # Chunk #4
            #
            # Completed Chunk 재실행 차단
            # =================================

            chunk_4 = (
                AnalysisChunk.objects.create(

                    analysis_run=
                        test_run,

                    language=
                        "python",

                    sequence=
                        4,

                    status=
                        AnalysisChunk
                        .Status
                        .COMPLETED,

                    file_count=
                        1,

                    total_bytes=
                        100,

                    completed_at=
                        timezone.now(),
                )
            )


            completed_claim = (
                claim_chunk(
                    chunk_4.id,

                    celery_task_id=
                        "duplicate-completed",
                )
            )


            # =================================
            # TEST 22
            # =================================

            self.assert_true(
                22,

                not completed_claim[
                    "claimed"
                ],

                "Completed Chunk 재실행 차단",
            )


            # =================================
            # TEST 23
            # =================================

            self.assert_equal(
                23,

                completed_claim[
                    "reason"
                ],

                "chunk_terminal",

                "Completed Chunk Terminal 판정",
            )


            # =================================
            # Chunk #5
            #
            # AnalysisRun 자체가 Planning이면
            # Worker 실행 금지
            # =================================

            planning_run = (
                AnalysisRun.objects.create(

                    project=
                        base_run.project,

                    source_version=
                        base_run.source_version,

                    sequence=
                        max_sequence
                        + 4001,

                    status=
                        AnalysisRun
                        .Status
                        .PLANNING,

                    engine=
                        "Semgrep",

                    executed_by=
                        base_run.executed_by,
                )
            )


            planning_chunk = (
                AnalysisChunk.objects.create(

                    analysis_run=
                        planning_run,

                    language=
                        "python",

                    sequence=
                        1,

                    status=
                        AnalysisChunk
                        .Status
                        .QUEUED,

                    file_count=
                        1,

                    total_bytes=
                        100,
                )
            )


            planning_claim = (
                claim_chunk(
                    planning_chunk.id,

                    celery_task_id=
                        "planning-run-task",
                )
            )


            # =================================
            # TEST 24
            # =================================

            self.assert_true(
                24,

                not planning_claim[
                    "claimed"
                ],

                "Running이 아닌 AnalysisRun의 Chunk Claim 차단",
            )


            # =================================
            # TEST 25
            # =================================

            self.assert_equal(
                25,

                planning_claim[
                    "reason"
                ],

                "analysis_run_not_running",

                "Planning AnalysisRun Claim 거부 사유 정상",
            )


            # =================================
            # 전체 Test Data Rollback
            # =================================

            transaction.set_rollback(
                True
            )


        self.stdout.write(
            self.style.SUCCESS(
                "\n"
                "========================================\n"
                "Chunk Claim Test Finished\n"
                "모든 테스트 데이터는 Rollback 되었습니다.\n"
                "========================================"
            )
        )