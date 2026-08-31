import tempfile

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from django.core.management.base import (
    BaseCommand,
    CommandError,
)
from django.db import transaction
from django.db.models import Max

from scans.models import (
    AnalysisChunk,
    AnalysisChunkAttempt,
    AnalysisDispatchOutbox,
    AnalysisRun,
    Vulnerability,
)
from scans.services.source_snapshot import (
    get_analysis_workspace_manifest_path,
    remove_analysis_workspace,
)
from scans.tasks import (
    dispatch_available_outboxes,
    run_analysis,
)


class Command(BaseCommand):

    help = (
        "AnalysisRun 시작 Task의 Snapshot → Planner → "
        "Outbox Pipeline을 검증합니다."
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


    # ====================================
    # Test AnalysisRun 생성
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
                    AnalysisRun.Status.PENDING,
                engine=
                    "Semgrep",
                analysis_language=
                    "",
                analysis_languages=
                    [],
                executed_by=
                    base_run.executed_by,
            )
        )


    # ====================================
    # Test Source 생성
    # ====================================

    def create_test_source(
        self,
        source_root,
    ):

        source_root = Path(
            source_root
        )


        python_file = (
            source_root
            / "backend"
            / "app.py"
        )

        python_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        python_file.write_text(
            "print('python')\n",
            encoding="utf-8",
        )


        javascript_file = (
            source_root
            / "frontend"
            / "app.js"
        )

        javascript_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        javascript_file.write_text(
            "console.log('javascript');\n",
            encoding="utf-8",
        )


        ignored_file = (
            source_root
            / "node_modules"
            / "ignored.js"
        )

        ignored_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        ignored_file.write_text(
            "console.log('ignored');\n",
            encoding="utf-8",
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
                "Analysis Pipeline Start Test\n"
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


        workspace_run_ids = []


        try:

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
                    + 8000
                )


                # =================================
                # GROUP A
                #
                # 정상 Pipeline 시작
                # =================================

                run_1 = (
                    self.create_test_run(
                        base_run,
                        base_sequence,
                    )
                )

                workspace_run_ids.append(
                    run_1.id
                )


                with tempfile.TemporaryDirectory(
                    prefix="analysis_pipeline_test_"
                ) as temp_directory:

                    source_root = (
                        Path(
                            temp_directory
                        )
                        / "source"
                    )

                    source_root.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    self.create_test_source(
                        source_root
                    )


                    @contextmanager
                    def fake_prepare_analysis_target(
                        source_version
                    ):

                        yield source_root


                    fake_dispatch_result = {
                        "batch_count": 1,
                        "claimed_count": 2,
                        "published_count": 2,
                        "failed_count": 0,
                        "cancelled_count": 0,
                        "deferred_count": 0,
                        "state_changed_count": 0,
                    }


                    with (
                        patch(
                            "scans.tasks.prepare_analysis_target",
                            fake_prepare_analysis_target,
                        ),
                        patch(
                            "scans.tasks.dispatch_available_outboxes",
                            return_value=
                                fake_dispatch_result,
                        ),
                        patch(
                            "scans.tasks.execute_semgrep_for_languages"
                        ) as old_semgrep_mock
                    ):

                        result_1 = (
                            run_analysis.run(
                                run_1.id
                            )
                        )


                run_1.refresh_from_db()


                # =================================
                # TEST 1
                # =================================

                self.assert_true(
                    1,
                    result_1.get(
                        "success"
                    ),
                    "Analysis 시작 Pipeline 성공",
                )


                # =================================
                # TEST 2
                # =================================

                self.assert_equal(
                    2,
                    run_1.status,
                    AnalysisRun.Status.RUNNING,
                    "Planning 완료 후 AnalysisRun running",
                )


                # =================================
                # TEST 3
                # =================================

                self.assert_equal(
                    3,
                    run_1.analysis_languages,
                    [
                        "javascript",
                        "python",
                    ],
                    "Snapshot 기준 언어 감지 저장",
                )


                # =================================
                # TEST 4
                #
                # 언어가 2개이므로 Chunk 2개
                # =================================

                chunks_1 = (
                    AnalysisChunk.objects
                    .filter(
                        analysis_run=
                            run_1
                    )
                    .order_by(
                        "sequence"
                    )
                )


                self.assert_equal(
                    4,
                    chunks_1.count(),
                    2,
                    "JavaScript / Python Chunk 생성",
                )


                # =================================
                # TEST 5
                # =================================

                self.assert_equal(
                    5,
                    list(
                        chunks_1.values_list(
                            "language",
                            flat=True,
                        )
                    ),
                    [
                        "javascript",
                        "python",
                    ],
                    "Chunk 언어 순서 정상",
                )


                # =================================
                # TEST 6
                # =================================

                self.assert_equal(
                    6,
                    AnalysisDispatchOutbox.objects
                    .filter(
                        chunk__analysis_run=
                            run_1
                    )
                    .count(),
                    2,
                    "실행 Chunk마다 Outbox 생성",
                )


                # =================================
                # TEST 7
                #
                # Dispatcher는 Mock이므로
                # 실제 Outbox DB 상태는 pending 유지.
                # =================================

                self.assert_true(
                    7,
                    all(
                        status
                        ==
                        AnalysisDispatchOutbox.Status.PENDING
                        for status
                        in AnalysisDispatchOutbox.objects
                        .filter(
                            chunk__analysis_run=
                                run_1
                        )
                        .values_list(
                            "status",
                            flat=True,
                        )
                    ),
                    "Planner Outbox 초기 상태 pending",
                )


                # =================================
                # TEST 8
                # =================================

                self.assert_true(
                    8,
                    get_analysis_workspace_manifest_path(
                        run_1.id
                    ).is_file(),
                    "Persistent Workspace Manifest 생성",
                )


                # =================================
                # TEST 9
                #
                # Bootstrap Task에서는
                # Semgrep을 실행하면 안 됨.
                # =================================

                self.assert_true(
                    9,
                    not old_semgrep_mock.called,
                    "run_analysis에서는 Semgrep 직접 실행 안 함",
                )


                # =================================
                # TEST 10
                #
                # Chunk Worker 전이므로
                # Attempt 없음
                # =================================

                self.assert_equal(
                    10,
                    AnalysisChunkAttempt.objects
                    .filter(
                        chunk__analysis_run=
                            run_1
                    )
                    .count(),
                    0,
                    "Bootstrap 단계에서는 Attempt 생성 안 함",
                )


                # =================================
                # TEST 11
                #
                # Bootstrap 단계에서는
                # Vulnerability 없음
                # =================================

                self.assert_equal(
                    11,
                    Vulnerability.objects
                    .filter(
                        analysis_run=
                            run_1
                    )
                    .count(),
                    0,
                    "Bootstrap 단계에서는 Vulnerability 생성 안 함",
                )


                # =================================
                # GROUP B
                #
                # Duplicate run_analysis
                # =================================

                duplicate_result = (
                    run_analysis.run(
                        run_1.id
                    )
                )


                # =================================
                # TEST 12
                # =================================

                self.assert_true(
                    12,
                    not duplicate_result.get(
                        "claimed"
                    ),
                    "동일 AnalysisRun Bootstrap 중복 실행 차단",
                )


                # =================================
                # TEST 13
                # =================================

                self.assert_equal(
                    13,
                    AnalysisChunk.objects
                    .filter(
                        analysis_run=
                            run_1
                    )
                    .count(),
                    2,
                    "중복 Bootstrap이 Chunk를 추가 생성하지 않음",
                )


                # =================================
                # GROUP C
                #
                # Snapshot 시작 실패
                # → Run failed
                # =================================

                run_2 = (
                    self.create_test_run(
                        base_run,
                        base_sequence + 1,
                    )
                )


                with tempfile.TemporaryDirectory(
                    prefix="analysis_pipeline_failure_"
                ) as temp_directory:

                    source_root_2 = (
                        Path(
                            temp_directory
                        )
                        / "source"
                    )

                    source_root_2.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    self.create_test_source(
                        source_root_2
                    )


                    @contextmanager
                    def fake_prepare_failure(
                        source_version
                    ):

                        yield source_root_2


                    with (
                        patch(
                            "scans.tasks.prepare_analysis_target",
                            fake_prepare_failure,
                        ),
                        patch(
                            "scans.tasks.materialize_analysis_workspace",
                            side_effect=RuntimeError(
                                "snapshot failed"
                            ),
                        )
                    ):

                        try:

                            run_analysis.run(
                                run_2.id
                            )

                        except RuntimeError:

                            pass


                run_2.refresh_from_db()


                # =================================
                # TEST 14
                # =================================

                self.assert_equal(
                    14,
                    run_2.status,
                    AnalysisRun.Status.FAILED,
                    "Snapshot 시작 실패 시 AnalysisRun failed",
                )


                # =================================
                # TEST 15
                # =================================

                self.assert_true(
                    15,
                    "snapshot failed"
                    in
                    run_2.failure_reason,
                    "Snapshot 시작 실패 사유 저장",
                )


                # =================================
                # GROUP D
                #
                # Dispatcher Multi-Batch Helper
                # =================================

                with patch(
                    "scans.tasks.dispatch_pending_outboxes",
                    side_effect=[
                        {
                            "claimed_count": 50,
                            "published_count": 50,
                            "failed_count": 0,
                            "cancelled_count": 0,
                            "deferred_count": 0,
                            "state_changed_count": 0,
                        },
                        {
                            "claimed_count": 3,
                            "published_count": 2,
                            "failed_count": 1,
                            "cancelled_count": 0,
                            "deferred_count": 0,
                            "state_changed_count": 0,
                        },
                        {
                            "claimed_count": 0,
                            "published_count": 0,
                            "failed_count": 0,
                            "cancelled_count": 0,
                            "deferred_count": 0,
                            "state_changed_count": 0,
                        },
                    ],
                ):

                    batch_result = (
                        dispatch_available_outboxes()
                    )


                # =================================
                # TEST 16
                # =================================

                self.assert_equal(
                    16,
                    batch_result[
                        "batch_count"
                    ],
                    3,
                    "Dispatcher가 여러 Batch를 반복 처리",
                )


                # =================================
                # TEST 17
                # =================================

                self.assert_equal(
                    17,
                    batch_result[
                        "published_count"
                    ],
                    52,
                    "Multi-Batch published_count 합산",
                )


                # =================================
                # TEST 18
                # =================================

                self.assert_equal(
                    18,
                    batch_result[
                        "failed_count"
                    ],
                    1,
                    "Multi-Batch publish 실패 집계",
                )


                transaction.set_rollback(
                    True
                )


        finally:

            for analysis_run_id in (
                workspace_run_ids
            ):

                remove_analysis_workspace(
                    analysis_run_id
                )


        self.stdout.write(
            self.style.SUCCESS(
                "\n"
                "========================================\n"
                "Analysis Pipeline Start Test Finished\n"
                "Workspace 및 DB 테스트 데이터가 정리되었습니다.\n"
                "========================================"
            )
        )
