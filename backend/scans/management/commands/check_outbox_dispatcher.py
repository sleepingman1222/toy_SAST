from datetime import timedelta

from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from scans.models import (
    AnalysisChunk,
    AnalysisDispatchOutbox,
    AnalysisRun,
)

from scans.services.outbox_dispatcher import (
    dispatch_pending_outboxes,
)


class Command(BaseCommand):

    help = (
        "Analysis Outbox Dispatcher의 "
        "publish / retry / cancel / defer 정책을 "
        "검증합니다."
    )


    # ========================================
    # PASS
    # ========================================

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


    # ========================================
    # Assert Equal
    # ========================================

    def assert_equal(
        self,
        number,
        actual,
        expected,
        message,
    ):

        if actual != expected:

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


    # ========================================
    # Assert True
    # ========================================

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


    # ========================================
    # Main
    # ========================================

    def handle(
        self,
        *args,
        **options,
    ):

        self.stdout.write(
            self.style.MIGRATE_HEADING(
                "\n"
                "========================================\n"
                "Outbox Dispatcher Test\n"
                "========================================"
            )
        )


        base_analysis_run = (
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


        if base_analysis_run is None:

            raise CommandError(
                "기존 AnalysisRun 데이터가 없습니다."
            )


        # ====================================
        # 전체 Rollback Transaction
        # ====================================

        with transaction.atomic():

            max_sequence = (
                AnalysisRun.objects
                .filter(
                    project=
                        base_analysis_run
                        .project
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
                        base_analysis_run
                        .project,

                    source_version=
                        base_analysis_run
                        .source_version,

                    sequence=
                        max_sequence
                        + 2000,

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
                        base_analysis_run
                        .executed_by,

                    started_at=
                        timezone.now(),
                )
            )


            # =================================
            # TEST Chunk 1
            #
            # 정상 publish
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
                )
            )


            outbox_1 = (
                AnalysisDispatchOutbox.objects.create(
                    chunk=
                        chunk_1,

                    dispatch_no=
                        1,

                    status=(
                        AnalysisDispatchOutbox
                        .Status
                        .PENDING
                    ),
                )
            )


            published_chunk_ids = []


            def fake_publish(
                chunk_id,
            ):

                published_chunk_ids.append(
                    chunk_id
                )

                return (
                    f"fake-task-{chunk_id}"
                )


            result = (
                dispatch_pending_outboxes(
                    publish_func=
                        fake_publish,

                    batch_size=
                        10,
                )
            )


            outbox_1.refresh_from_db()


            # =================================
            # TEST 1
            # =================================

            self.assert_equal(
                1,
                result[
                    "published_count"
                ],
                1,
                "Pending Outbox 정상 publish",
            )


            # =================================
            # TEST 2
            # =================================

            self.assert_equal(
                2,
                outbox_1.status,
                (
                    AnalysisDispatchOutbox
                    .Status
                    .PUBLISHED
                ),
                "Publish 후 Outbox published",
            )


            # =================================
            # TEST 3
            # =================================

            self.assert_equal(
                3,
                outbox_1.publish_attempts,
                1,
                "최초 publish_attempts = 1",
            )


            # =================================
            # TEST 4
            # =================================

            self.assert_equal(
                4,
                outbox_1.celery_task_id,
                (
                    f"fake-task-"
                    f"{chunk_1.id}"
                ),
                "Celery Task ID 저장",
            )


            # =================================
            # TEST 5
            # =================================

            self.assert_equal(
                5,
                published_chunk_ids,
                [
                    chunk_1.id
                ],
                "Publisher에는 chunk_id만 전달",
            )


            # =================================
            # TEST Chunk 2
            #
            # Redis publish 실패
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
                        .QUEUED,

                    file_count=
                        1,

                    total_bytes=
                        100,
                )
            )


            outbox_2 = (
                AnalysisDispatchOutbox.objects.create(
                    chunk=
                        chunk_2,

                    dispatch_no=
                        1,
                )
            )


            before_failure = (
                timezone.now()
            )


            def fake_redis_failure(
                chunk_id,
            ):

                raise RuntimeError(
                    "Redis unavailable"
                )


            failure_result = (
                dispatch_pending_outboxes(
                    publish_func=
                        fake_redis_failure,

                    batch_size=
                        10,
                )
            )


            outbox_2.refresh_from_db()


            # =================================
            # TEST 6
            # =================================

            self.assert_equal(
                6,
                failure_result[
                    "failed_count"
                ],
                1,
                "Redis 실패가 failed_count에 반영",
            )


            # =================================
            # TEST 7
            # =================================

            self.assert_equal(
                7,
                outbox_2.status,
                (
                    AnalysisDispatchOutbox
                    .Status
                    .PENDING
                ),
                (
                    "Redis 실패 시 Outbox는 "
                    "pending 유지"
                ),
            )


            # =================================
            # TEST 8
            # =================================

            self.assert_equal(
                8,
                outbox_2.publish_attempts,
                1,
                (
                    "Redis 실패도 Dispatch "
                    "시도 횟수 기록"
                ),
            )


            # =================================
            # TEST 9
            # =================================

            self.assert_true(
                9,
                (
                    outbox_2.available_at
                    >
                    before_failure
                ),
                "실패 후 Retry 시간이 미래로 이동",
            )


            # =================================
            # TEST 10
            # =================================

            self.assert_true(
                10,
                (
                    "Redis unavailable"
                    in
                    outbox_2.last_error
                ),
                "Redis 오류 내용 DB 보존",
            )


            # =================================
            # TEST 11
            #
            # Backoff 중에는 다시
            # 가져가면 안 됨
            # =================================

            second_failure_result = (
                dispatch_pending_outboxes(
                    publish_func=
                        fake_redis_failure,

                    batch_size=
                        10,
                )
            )


            self.assert_equal(
                11,
                second_failure_result[
                    "claimed_count"
                ],
                0,
                (
                    "Backoff 중인 Outbox는 "
                    "즉시 재처리하지 않음"
                ),
            )


            # =================================
            # TEST Chunk 3
            #
            # Terminal Chunk
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
                        .COMPLETED,

                    file_count=
                        1,

                    total_bytes=
                        100,

                    completed_at=
                        timezone.now(),
                )
            )


            outbox_3 = (
                AnalysisDispatchOutbox.objects.create(
                    chunk=
                        chunk_3,

                    dispatch_no=
                        1,
                )
            )


            terminal_publish_calls = []


            def should_not_publish(
                chunk_id,
            ):

                terminal_publish_calls.append(
                    chunk_id
                )

                return "unexpected-task"


            terminal_result = (
                dispatch_pending_outboxes(
                    publish_func=
                        should_not_publish,

                    batch_size=
                        10,
                )
            )


            outbox_3.refresh_from_db()


            # =================================
            # TEST 12
            # =================================

            self.assert_equal(
                12,
                outbox_3.status,
                (
                    AnalysisDispatchOutbox
                    .Status
                    .CANCELLED
                ),
                "Terminal Chunk의 Outbox 취소",
            )


            # =================================
            # TEST 13
            # =================================

            self.assert_equal(
                13,
                terminal_publish_calls,
                [],
                (
                    "Terminal Chunk는 "
                    "Redis에 publish하지 않음"
                ),
            )


            # =================================
            # TEST 14
            # =================================

            self.assert_equal(
                14,
                terminal_result[
                    "cancelled_count"
                ],
                1,
                "Terminal Outbox cancel 집계",
            )


            # =================================
            # TEST Chunk 4
            #
            # Retry Pending도 dispatch 가능
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
                        .RETRY_PENDING,

                    file_count=
                        1,

                    total_bytes=
                        100,

                    retry_count=
                        1,
                )
            )


            outbox_4 = (
                AnalysisDispatchOutbox.objects.create(
                    chunk=
                        chunk_4,

                    dispatch_no=
                        2,
                )
            )


            retry_calls = []


            def fake_retry_publish(
                chunk_id,
            ):

                retry_calls.append(
                    chunk_id
                )

                return (
                    f"retry-task-{chunk_id}"
                )


            retry_result = (
                dispatch_pending_outboxes(
                    publish_func=
                        fake_retry_publish,

                    batch_size=
                        10,
                )
            )


            outbox_4.refresh_from_db()


            # =================================
            # TEST 15
            # =================================

            self.assert_equal(
                15,
                retry_result[
                    "published_count"
                ],
                1,
                (
                    "retry_pending Chunk도 "
                    "정상 dispatch"
                ),
            )


            # =================================
            # TEST 16
            # =================================

            self.assert_equal(
                16,
                outbox_4.status,
                (
                    AnalysisDispatchOutbox
                    .Status
                    .PUBLISHED
                ),
                (
                    "Retry Outbox도 "
                    "published 상태"
                ),
            )


            # =================================
            # TEST Chunk 5
            #
            # available_at 미래
            # =================================

            chunk_5 = (
                AnalysisChunk.objects.create(
                    analysis_run=
                        test_run,

                    language=
                        "python",

                    sequence=
                        5,

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


            outbox_5 = (
                AnalysisDispatchOutbox.objects.create(
                    chunk=
                        chunk_5,

                    dispatch_no=
                        1,

                    available_at=(
                        timezone.now()
                        +
                        timedelta(
                            hours=1
                        )
                    ),
                )
            )


            future_calls = []


            def future_publish(
                chunk_id,
            ):

                future_calls.append(
                    chunk_id
                )

                return "future-task"


            future_result = (
                dispatch_pending_outboxes(
                    publish_func=
                        future_publish,

                    batch_size=
                        10,
                )
            )


            outbox_5.refresh_from_db()


            # =================================
            # TEST 17
            # =================================

            self.assert_equal(
                17,
                future_result[
                    "claimed_count"
                ],
                0,
                (
                    "available_at이 미래인 "
                    "Outbox는 claim하지 않음"
                ),
            )


            # =================================
            # TEST 18
            # =================================

            self.assert_equal(
                18,
                future_calls,
                [],
                "미래 Outbox는 publish하지 않음",
            )


            # =================================
            # TEST 19
            #
            # Chunk 상태는 Dispatcher가
            # running으로 변경하면 안 됨.
            #
            # Worker가 실제 claim할 때
            # running으로 변경해야 한다.
            # =================================

            chunk_1.refresh_from_db()


            self.assert_equal(
                19,
                chunk_1.status,
                (
                    AnalysisChunk
                    .Status
                    .QUEUED
                ),
                (
                    "Dispatcher는 Chunk 상태를 "
                    "running으로 변경하지 않음"
                ),
            )


            # =================================
            # Test Data Rollback
            # =================================

            transaction.set_rollback(
                True
            )


        self.stdout.write(
            self.style.SUCCESS(
                "\n"
                "========================================\n"
                "Outbox Dispatcher Test Finished\n"
                "모든 테스트 데이터는 Rollback 되었습니다.\n"
                "========================================"
            )
        )