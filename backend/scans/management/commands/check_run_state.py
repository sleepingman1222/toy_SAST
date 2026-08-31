# backend/scans/management/commands/check_run_state.py

from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from scans.models import (
    AnalysisChunk,
    AnalysisRun,
)

from scans.services.run_state_manager import (
    aggregate_analysis_run_state,
)


class Command(
    BaseCommand
):

    help = (
        "AnalysisChunk 상태를 기반으로 "
        "AnalysisRun 상태를 집계하는 규칙을 "
        "검증합니다."
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
    # Test AnalysisRun 생성
    # ====================================

    def create_run(
        self,
        base_run,
        sequence,
        status=None,
    ):

        if status is None:

            status = (
                AnalysisRun
                .Status
                .PENDING
            )


        return (
            AnalysisRun.objects.create(

                project=
                    base_run.project,

                source_version=
                    base_run.source_version,

                sequence=
                    sequence,

                status=
                    status,

                engine=
                    "Semgrep",

                analysis_language=
                    "python",

                analysis_languages=[
                    "python"
                ],

                executed_by=
                    base_run.executed_by,
            )
        )


    # ====================================
    # Test Chunk 생성
    # ====================================

    def create_chunk(
        self,
        analysis_run,
        sequence,
        status,
    ):

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
                "AnalysisRun State Test\n"
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


            next_sequence = (
                max_sequence
                + 6000
            )


            # =================================
            # TEST GROUP A
            #
            # Active Chunk
            # =================================

            active_run = (
                self.create_run(
                    base_run,
                    next_sequence,
                )
            )


            self.create_chunk(
                active_run,
                1,
                AnalysisChunk
                .Status
                .COMPLETED,
            )


            self.create_chunk(
                active_run,
                2,
                AnalysisChunk
                .Status
                .QUEUED,
            )


            active_result = (
                aggregate_analysis_run_state(
                    active_run.id
                )
            )


            active_run.refresh_from_db()


            # =================================
            # TEST 1
            # =================================

            self.assert_equal(
                1,

                active_run.status,

                (
                    AnalysisRun
                    .Status
                    .RUNNING
                ),

                "Active Chunk가 있으면 Run running",
            )


            # =================================
            # TEST 2
            # =================================

            self.assert_equal(
                2,

                active_result[
                    "active_chunk_count"
                ],

                1,

                "Active Chunk 개수 집계",
            )


            # =================================
            # TEST 3
            # =================================

            self.assert_true(
                3,

                (
                    active_run
                    .started_at
                    is not None
                ),

                "running 전환 시 started_at 저장",
            )


            # =================================
            # TEST GROUP B
            #
            # Completed + Skipped
            # =================================

            completed_run = (
                self.create_run(
                    base_run,
                    next_sequence + 1,
                    AnalysisRun
                    .Status
                    .RUNNING,
                )
            )


            self.create_chunk(
                completed_run,
                1,
                AnalysisChunk
                .Status
                .COMPLETED,
            )


            self.create_chunk(
                completed_run,
                2,
                AnalysisChunk
                .Status
                .SKIPPED,
            )


            completed_result = (
                aggregate_analysis_run_state(
                    completed_run.id
                )
            )


            completed_run.refresh_from_db()


            # =================================
            # TEST 4
            # =================================

            self.assert_equal(
                4,

                completed_run.status,

                (
                    AnalysisRun
                    .Status
                    .COMPLETED
                ),

                "Completed + Skipped → Run completed",
            )


            # =================================
            # TEST 5
            # =================================

            self.assert_equal(
                5,

                completed_result[
                    "reason"
                ],

                "all_chunks_completed",

                "완료 집계 사유 정상",
            )


            # =================================
            # TEST 6
            # =================================

            self.assert_true(
                6,

                (
                    completed_run
                    .completed_at
                    is not None
                ),

                "Run 완료 시간 저장",
            )


            # =================================
            # TEST GROUP C
            #
            # Failed 우선
            # =================================

            failed_run = (
                self.create_run(
                    base_run,
                    next_sequence + 2,
                    AnalysisRun
                    .Status
                    .RUNNING,
                )
            )


            self.create_chunk(
                failed_run,
                1,
                AnalysisChunk
                .Status
                .COMPLETED,
            )


            self.create_chunk(
                failed_run,
                2,
                AnalysisChunk
                .Status
                .FAILED,
            )


            failed_result = (
                aggregate_analysis_run_state(
                    failed_run.id
                )
            )


            failed_run.refresh_from_db()


            # =================================
            # TEST 7
            # =================================

            self.assert_equal(
                7,

                failed_run.status,

                (
                    AnalysisRun
                    .Status
                    .FAILED
                ),

                "Failed Chunk 존재 시 Run failed",
            )


            # =================================
            # TEST 8
            # =================================

            self.assert_equal(
                8,

                failed_result[
                    "failed_chunk_count"
                ],

                1,

                "Failed Chunk 개수 집계",
            )


            # =================================
            # TEST 9
            # =================================

            self.assert_true(
                9,

                (
                    "1개의"
                    in
                    failed_run.failure_reason
                ),

                "Run 실패 사유 저장",
            )


            # =================================
            # TEST GROUP D
            #
            # Cancelled
            # =================================

            cancelled_run = (
                self.create_run(
                    base_run,
                    next_sequence + 3,
                    AnalysisRun
                    .Status
                    .RUNNING,
                )
            )


            self.create_chunk(
                cancelled_run,
                1,
                AnalysisChunk
                .Status
                .COMPLETED,
            )


            self.create_chunk(
                cancelled_run,
                2,
                AnalysisChunk
                .Status
                .CANCELLED,
            )


            aggregate_analysis_run_state(
                cancelled_run.id
            )


            cancelled_run.refresh_from_db()


            # =================================
            # TEST 10
            # =================================

            self.assert_equal(
                10,

                cancelled_run.status,

                (
                    AnalysisRun
                    .Status
                    .CANCELLED
                ),

                "Cancelled Chunk 존재 시 Run cancelled",
            )


            # =================================
            # TEST GROUP E
            #
            # 모든 Chunk Skipped
            # =================================

            skipped_run = (
                self.create_run(
                    base_run,
                    next_sequence + 4,
                    AnalysisRun
                    .Status
                    .RUNNING,
                )
            )


            self.create_chunk(
                skipped_run,
                1,
                AnalysisChunk
                .Status
                .SKIPPED,
            )


            self.create_chunk(
                skipped_run,
                2,
                AnalysisChunk
                .Status
                .SKIPPED,
            )


            skipped_result = (
                aggregate_analysis_run_state(
                    skipped_run.id
                )
            )


            skipped_run.refresh_from_db()


            # =================================
            # TEST 11
            # =================================

            self.assert_equal(
                11,

                skipped_run.status,

                (
                    AnalysisRun
                    .Status
                    .FAILED
                ),

                "모든 Chunk skipped면 Run failed",
            )


            # =================================
            # TEST 12
            # =================================

            self.assert_equal(
                12,

                skipped_result[
                    "reason"
                ],

                "all_chunks_skipped",

                "All Skipped 판정 사유 정상",
            )


            # =================================
            # TEST GROUP F
            #
            # Chunk 없음
            # =================================

            no_chunk_run = (
                self.create_run(
                    base_run,
                    next_sequence + 5,
                    AnalysisRun
                    .Status
                    .PLANNING,
                )
            )


            no_chunk_result = (
                aggregate_analysis_run_state(
                    no_chunk_run.id
                )
            )


            no_chunk_run.refresh_from_db()


            # =================================
            # TEST 13
            # =================================

            self.assert_equal(
                13,

                no_chunk_run.status,

                (
                    AnalysisRun
                    .Status
                    .PLANNING
                ),

                "Chunk 없는 Run 상태 유지",
            )


            # =================================
            # TEST 14
            # =================================

            self.assert_equal(
                14,

                no_chunk_result[
                    "reason"
                ],

                "no_chunks",

                "Chunk 없음 판정 정상",
            )


            # =================================
            # TEST GROUP G
            #
            # Terminal Run Immutable
            # =================================

            terminal_run = (
                self.create_run(
                    base_run,
                    next_sequence + 6,
                    AnalysisRun
                    .Status
                    .COMPLETED,
                )
            )


            terminal_run.started_at = (
                timezone.now()
            )

            terminal_run.completed_at = (
                timezone.now()
            )

            terminal_run.save(
                update_fields=[
                    "started_at",
                    "completed_at",
                    "updated_at",
                ]
            )


            # 의도적으로 자식은 failed로 생성
            # Aggregator가 completed Run을
            # 다시 failed로 바꾸면 안 된다.

            self.create_chunk(
                terminal_run,
                1,
                AnalysisChunk
                .Status
                .FAILED,
            )


            terminal_result = (
                aggregate_analysis_run_state(
                    terminal_run.id
                )
            )


            terminal_run.refresh_from_db()


            # =================================
            # TEST 15
            # =================================

            self.assert_equal(
                15,

                terminal_run.status,

                (
                    AnalysisRun
                    .Status
                    .COMPLETED
                ),

                "Terminal AnalysisRun 상태 불변",
            )


            # =================================
            # TEST 16
            # =================================

            self.assert_equal(
                16,

                terminal_result[
                    "reason"
                ],

                "analysis_run_terminal",

                "Terminal Run 재집계 차단 사유 정상",
            )


            # =================================
            # TEST GROUP H
            #
            # Failed + Cancelled
            #
            # Failed가 더 높은 우선순위
            # =================================

            mixed_failure_run = (
                self.create_run(
                    base_run,
                    next_sequence + 7,
                    AnalysisRun
                    .Status
                    .RUNNING,
                )
            )


            self.create_chunk(
                mixed_failure_run,
                1,
                AnalysisChunk
                .Status
                .FAILED,
            )


            self.create_chunk(
                mixed_failure_run,
                2,
                AnalysisChunk
                .Status
                .CANCELLED,
            )


            aggregate_analysis_run_state(
                mixed_failure_run.id
            )


            mixed_failure_run.refresh_from_db()


            # =================================
            # TEST 17
            # =================================

            self.assert_equal(
                17,

                mixed_failure_run.status,

                (
                    AnalysisRun
                    .Status
                    .FAILED
                ),

                "Failed + Cancelled에서는 Failed 우선",
            )


            # =================================
            # TEST GROUP I
            #
            # 여러 Active 상태
            # =================================

            multi_active_run = (
                self.create_run(
                    base_run,
                    next_sequence + 8,
                    AnalysisRun
                    .Status
                    .RUNNING,
                )
            )


            self.create_chunk(
                multi_active_run,
                1,
                AnalysisChunk
                .Status
                .RUNNING,
            )


            self.create_chunk(
                multi_active_run,
                2,
                AnalysisChunk
                .Status
                .RETRY_PENDING,
            )


            self.create_chunk(
                multi_active_run,
                3,
                AnalysisChunk
                .Status
                .COMPLETED,
            )


            multi_active_result = (
                aggregate_analysis_run_state(
                    multi_active_run.id
                )
            )


            # =================================
            # TEST 18
            # =================================

            self.assert_equal(
                18,

                multi_active_result[
                    "active_chunk_count"
                ],

                2,

                "running + retry_pending Active 2개 집계",
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
                "AnalysisRun State Test Finished\n"
                "모든 테스트 데이터는 Rollback 되었습니다.\n"
                "========================================"
            )
        )