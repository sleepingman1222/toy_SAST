import tempfile

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
    KisaSecurityWeakness,
    Vulnerability,
)

from scans.services.chunk_planner import (
    plan_analysis_chunks,
)

from scans.services.source_snapshot import (
    get_analysis_workspace_source_root,
    materialize_analysis_workspace,
    remove_analysis_workspace,
)

from scans.tasks import (
    run_analysis_chunk,
)


class Command(
    BaseCommand
):

    help = (
        "실제 run_analysis_chunk Worker의 "
        "Claim / Workspace 검증 / Attempt-scoped "
        "Vulnerability / Retry 정책을 검증합니다."
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
                    AnalysisRun
                    .Status
                    .PENDING,

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
    # 작은 Python Source 생성
    # ====================================

    def create_python_source(
        self,
        source_root,
        relative_path="app/test.py",
    ):

        source_file = (
            Path(source_root)
            /
            relative_path
        )


        source_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        source_file.write_text(
            "user_input = input()\n"
            "print(user_input)\n",
            encoding="utf-8",
        )


        return source_file


    # ====================================
    # Fake Semgrep Result
    # ====================================

    def build_fake_semgrep_result(
        self,
        weakness,
    ):

        return {
            "raw_result": {
                "version":
                    "test",

                "results": [
                    {
                        "check_id":
                            "test.chunk.worker.rule",

                        "path":
                            "app/test.py",

                        "start": {
                            "line": 2,
                            "col": 1,
                        },

                        "end": {
                            "line": 2,
                            "col": 18,
                        },

                        "extra": {
                            "message":
                                "Chunk Worker Test Finding",

                            "severity":
                                "WARNING",

                            "metadata": {
                                "kisa_identifier":
                                    weakness.identifier,

                                "kisa_name":
                                    weakness.name,

                                "confidence":
                                    "HIGH",

                                "recommendation":
                                    "테스트 권고 조치",
                            },
                        },
                    }
                ],

                "errors": [],
            },

            "logs":
                "fake semgrep completed",
        }


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
                "Chunk Worker Test\n"
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


        weakness = (
            KisaSecurityWeakness.objects
            .order_by(
                "id"
            )
            .first()
        )


        if weakness is None:

            raise CommandError(
                "KisaSecurityWeakness Master Data가 필요합니다."
            )


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


        workspace_run_ids = []


        try:

            with transaction.atomic():

                # =================================
                # GROUP A
                # 정상 Worker 실행
                # =================================

                run_1 = (
                    self.create_test_run(
                        base_run,
                        max_sequence + 6000,
                    )
                )


                workspace_run_ids.append(
                    run_1.id
                )


                with tempfile.TemporaryDirectory(
                    prefix="chunk_worker_test_success_"
                ) as temp_directory:

                    source_root = (
                        Path(temp_directory)
                        /
                        "source"
                    )


                    source_root.mkdir(
                        parents=True,
                        exist_ok=True,
                    )


                    self.create_python_source(
                        source_root
                    )


                    snapshot_files = (
                        materialize_analysis_workspace(
                            run_1.id,
                            source_root,
                        )
                    )


                plan_analysis_chunks(
                    run_1.id,
                    scanned_files=
                        snapshot_files,
                )


                chunk_1 = (
                    AnalysisChunk.objects
                    .get(
                        analysis_run=
                            run_1,
                        sequence=
                            1,
                    )
                )


                fake_semgrep_result = (
                    self.build_fake_semgrep_result(
                        weakness
                    )
                )


                with (
                    patch(
                        "scans.tasks.get_semgrep_rule_path",
                        return_value=
                            Path(
                                "/tmp/fake-rule"
                            ),
                    ),

                    patch(
                        "scans.tasks.execute_semgrep_with_heartbeat",
                        return_value=
                            fake_semgrep_result,
                    )
                ):

                    worker_result = (
                        run_analysis_chunk.run(
                            chunk_1.id
                        )
                    )


                chunk_1.refresh_from_db()


                # =================================
                # TEST 1
                # =================================

                self.assert_true(
                    1,
                    worker_result.get(
                        "success"
                    ),
                    "Chunk Worker 정상 실행 성공",
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
                        .COMPLETED
                    ),
                    "Worker 성공 후 Chunk completed",
                )


                attempts_1 = (
                    AnalysisChunkAttempt.objects
                    .filter(
                        chunk=
                            chunk_1
                    )
                )


                self.assert_equal(
                    3,
                    attempts_1.count(),
                    1,
                    "정상 Worker에서 Attempt 1개 생성",
                )


                attempt_1 = (
                    attempts_1.get()
                )


                self.assert_equal(
                    4,
                    attempt_1.status,
                    (
                        AnalysisChunkAttempt
                        .Status
                        .COMPLETED
                    ),
                    "Worker 성공 후 Attempt completed",
                )


                vulnerabilities_1 = (
                    Vulnerability.objects
                    .filter(
                        analysis_attempt=
                            attempt_1
                    )
                )


                self.assert_equal(
                    5,
                    vulnerabilities_1.count(),
                    1,
                    "취약점이 Attempt 기준으로 저장됨",
                )


                vulnerability_1 = (
                    vulnerabilities_1.get()
                )


                self.assert_equal(
                    6,
                    vulnerability_1.analysis_run_id,
                    run_1.id,
                    "Vulnerability의 AnalysisRun 연결 유지",
                )


                self.assert_equal(
                    7,
                    vulnerability_1.analysis_attempt_id,
                    attempt_1.id,
                    "Vulnerability의 AnalysisChunkAttempt 연결",
                )


                self.assert_equal(
                    8,
                    len(
                        vulnerability_1.fingerprint
                        or ""
                    ),
                    64,
                    "Vulnerability SHA-256 Fingerprint 저장",
                )


                self.assert_equal(
                    9,
                    attempt_1.result_count,
                    1,
                    "Attempt result_count 저장",
                )


                self.assert_equal(
                    10,
                    chunk_1.result_count,
                    1,
                    "Chunk result_count 저장",
                )


                # =================================
                # 동일 Celery Message 재실행
                # =================================

                with patch(
                    "scans.tasks.execute_semgrep_with_heartbeat",
                    return_value=
                        fake_semgrep_result,
                ):

                    duplicate_result = (
                        run_analysis_chunk.run(
                            chunk_1.id
                        )
                    )


                self.assert_true(
                    11,
                    not duplicate_result.get(
                        "claimed"
                    ),
                    "Completed Chunk 중복 Worker Claim 차단",
                )


                self.assert_equal(
                    12,
                    AnalysisChunkAttempt.objects
                    .filter(
                        chunk=
                            chunk_1
                    )
                    .count(),
                    1,
                    "중복 Worker가 새 Attempt를 만들지 않음",
                )


                self.assert_equal(
                    13,
                    Vulnerability.objects
                    .filter(
                        analysis_run=
                            run_1
                    )
                    .count(),
                    1,
                    "중복 Worker가 취약점을 중복 저장하지 않음",
                )


                # =================================
                # GROUP B
                # Workspace Tamper
                # =================================

                run_2 = (
                    self.create_test_run(
                        base_run,
                        max_sequence + 6001,
                    )
                )


                workspace_run_ids.append(
                    run_2.id
                )


                with tempfile.TemporaryDirectory(
                    prefix="chunk_worker_test_tamper_"
                ) as temp_directory:

                    source_root = (
                        Path(temp_directory)
                        /
                        "source"
                    )


                    source_root.mkdir(
                        parents=True,
                        exist_ok=True,
                    )


                    self.create_python_source(
                        source_root
                    )


                    snapshot_files = (
                        materialize_analysis_workspace(
                            run_2.id,
                            source_root,
                        )
                    )


                plan_analysis_chunks(
                    run_2.id,
                    scanned_files=
                        snapshot_files,
                )


                chunk_2 = (
                    AnalysisChunk.objects
                    .get(
                        analysis_run=
                            run_2,
                        sequence=
                            1,
                    )
                )


                workspace_file = (
                    get_analysis_workspace_source_root(
                        run_2.id
                    )
                    /
                    "app"
                    /
                    "test.py"
                )


                # Snapshot 생성 후 파일 변조
                workspace_file.write_text(
                    "print('tampered')\n",
                    encoding="utf-8",
                )


                with patch(
                    "scans.tasks.get_semgrep_rule_path",
                    return_value=
                        Path(
                            "/tmp/fake-rule"
                        ),
                ):

                    tamper_result = (
                        run_analysis_chunk.run(
                            chunk_2.id
                        )
                    )


                chunk_2.refresh_from_db()


                self.assert_true(
                    14,
                    not tamper_result.get(
                        "success"
                    ),
                    "Workspace 변조 Worker 실행 실패",
                )


                self.assert_equal(
                    15,
                    tamper_result.get(
                        "retryable"
                    ),
                    False,
                    "Workspace Snapshot 불일치는 Non-Retryable",
                )


                self.assert_equal(
                    16,
                    chunk_2.status,
                    (
                        AnalysisChunk
                        .Status
                        .FAILED
                    ),
                    "Workspace 변조 시 Chunk failed",
                )


                self.assert_equal(
                    17,
                    chunk_2.status_reason,
                    "NON_RETRYABLE_FAILURE",
                    "Workspace 변조 실패 사유 저장",
                )


                # Planner가 만든 최초 Outbox #1 외에
                # Retry Outbox가 추가되면 안 된다.
                self.assert_equal(
                    18,
                    AnalysisDispatchOutbox.objects
                    .filter(
                        chunk=
                            chunk_2
                    )
                    .count(),
                    1,
                    "Non-Retryable 실패는 Retry Outbox 추가 안 함",
                )


                # =================================
                # GROUP C
                # Semgrep 일시 실패 → Retry
                # =================================

                run_3 = (
                    self.create_test_run(
                        base_run,
                        max_sequence + 6002,
                    )
                )


                workspace_run_ids.append(
                    run_3.id
                )


                with tempfile.TemporaryDirectory(
                    prefix="chunk_worker_test_retry_"
                ) as temp_directory:

                    source_root = (
                        Path(temp_directory)
                        /
                        "source"
                    )


                    source_root.mkdir(
                        parents=True,
                        exist_ok=True,
                    )


                    self.create_python_source(
                        source_root
                    )


                    snapshot_files = (
                        materialize_analysis_workspace(
                            run_3.id,
                            source_root,
                        )
                    )


                plan_analysis_chunks(
                    run_3.id,
                    scanned_files=
                        snapshot_files,
                )


                chunk_3 = (
                    AnalysisChunk.objects
                    .get(
                        analysis_run=
                            run_3,
                        sequence=
                            1,
                    )
                )


                with (
                    patch(
                        "scans.tasks.get_semgrep_rule_path",
                        return_value=
                            Path(
                                "/tmp/fake-rule"
                            ),
                    ),

                    patch(
                        "scans.tasks.execute_semgrep_with_heartbeat",
                        side_effect=
                            RuntimeError(
                                "temporary semgrep failure"
                            ),
                    )
                ):

                    retry_result = (
                        run_analysis_chunk.run(
                            chunk_3.id
                        )
                    )


                chunk_3.refresh_from_db()


                self.assert_true(
                    19,
                    not retry_result.get(
                        "success"
                    ),
                    "Semgrep 일시 실패 Worker 결과 실패",
                )


                self.assert_equal(
                    20,
                    retry_result.get(
                        "retryable"
                    ),
                    True,
                    "Semgrep 실행 실패는 Retryable",
                )


                self.assert_equal(
                    21,
                    chunk_3.status,
                    (
                        AnalysisChunk
                        .Status
                        .RETRY_PENDING
                    ),
                    "Semgrep 실패 후 Chunk retry_pending",
                )


                attempt_3 = (
                    AnalysisChunkAttempt.objects
                    .get(
                        chunk=
                            chunk_3
                    )
                )


                self.assert_equal(
                    22,
                    attempt_3.status,
                    (
                        AnalysisChunkAttempt
                        .Status
                        .FAILED
                    ),
                    "Semgrep 실패 Attempt failed",
                )


                retry_outboxes = (
                    AnalysisDispatchOutbox.objects
                    .filter(
                        chunk=
                            chunk_3
                    )
                    .order_by(
                        "dispatch_no"
                    )
                )


                self.assert_equal(
                    23,
                    retry_outboxes.count(),
                    2,
                    "실패 후 Retry Outbox #2 생성",
                )


                self.assert_equal(
                    24,
                    retry_outboxes.last().dispatch_no,
                    2,
                    "Retry Outbox dispatch_no = 2",
                )


                self.assert_equal(
                    25,
                    retry_outboxes.last().status,
                    (
                        AnalysisDispatchOutbox
                        .Status
                        .PENDING
                    ),
                    "Retry Outbox pending",
                )


                transaction.set_rollback(
                    True
                )


        finally:

            for analysis_run_id in (
                workspace_run_ids
            ):

                try:

                    remove_analysis_workspace(
                        analysis_run_id
                    )

                except Exception:

                    pass


        self.stdout.write(
            self.style.SUCCESS(
                "\n"
                "========================================\n"
                "Chunk Worker Test Finished\n"
                "Workspace 및 DB 테스트 데이터가 "
                "정리되었습니다.\n"
                "========================================"
            )
        )
