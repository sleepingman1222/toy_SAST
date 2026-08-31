import tempfile

from pathlib import Path

from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from django.db import transaction
from django.db.models import Max

from scans.models import (
    AnalysisChunkFile,
    AnalysisRun,
)

from scans.services.source_snapshot import (
    get_analysis_workspace_manifest_path,
    get_analysis_workspace_source_root,
    load_analysis_workspace_snapshot,
    materialize_analysis_workspace,
    remove_analysis_workspace,
)


# ========================================
# Test Constants
# ========================================

ONE_MB = (
    1024
    * 1024
)


# ========================================
# Command
# ========================================

class Command(
    BaseCommand
):

    help = (
        "Analysis Workspace Snapshot의 "
        "영속화 / Hash / Oversized 정책을 "
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
                f"[FAIL {number}] "
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
                f"[FAIL {number}] "
                f"{message}\n"
                f"expected={expected}\n"
                f"actual={actual}"
            )


        self.pass_test(
            number,
            message,
        )


    # ====================================
    # 지정 크기 File 생성
    # ====================================

    def create_sized_file(
        self,
        path,
        size,
    ):

        path = Path(
            path
        )


        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        with path.open(
            mode="wb"
        ) as file_object:

            file_object.truncate(
                size
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
                "Source Snapshot Test\n"
                "========================================"
            )
        )


        # =================================
        # 기존 AnalysisRun 1건 확보
        #
        # Project / SourceVersion /
        # User FK 재사용
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


        test_run_id = None


        try:

            # =================================
            # DB Test Transaction
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


                # =============================
                # Test AnalysisRun
                # =============================

                test_run = (
                    AnalysisRun.objects.create(

                        project=
                            base_run.project,

                        source_version=
                            base_run.source_version,

                        sequence=
                            max_sequence
                            + 3000,

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


                test_run_id = (
                    test_run.id
                )


                # =============================
                # Temporary Source
                # =============================

                with tempfile.TemporaryDirectory(
                    prefix=
                        "source_snapshot_test_"
                ) as temp_directory:

                    source_root = (
                        Path(
                            temp_directory
                        )
                        /
                        "source"
                    )


                    source_root.mkdir(
                        parents=True,
                        exist_ok=True,
                    )


                    # =========================
                    # Normal Python
                    # =========================

                    normal_file = (
                        source_root
                        /
                        "app"
                        /
                        "normal.py"
                    )


                    normal_file.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )


                    normal_file.write_text(
                        "print('hello')\n",
                        encoding="utf-8",
                    )


                    # =========================
                    # Large Python
                    #
                    # 3MB
                    # =========================

                    self.create_sized_file(

                        source_root
                        /
                        "app"
                        /
                        "large.py",

                        3
                        *
                        ONE_MB,
                    )


                    # =========================
                    # Oversized Python
                    #
                    # 11MB
                    # =========================

                    self.create_sized_file(

                        source_root
                        /
                        "app"
                        /
                        "oversized.py",

                        11
                        *
                        ONE_MB,
                    )


                    # =========================
                    # JavaScript
                    # =========================

                    js_file = (
                        source_root
                        /
                        "web"
                        /
                        "index.js"
                    )


                    js_file.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )


                    js_file.write_text(
                        "console.log('test');\n",
                        encoding="utf-8",
                    )


                    # =========================
                    # Ignored Directory
                    # =========================

                    ignored_file = (
                        source_root
                        /
                        "node_modules"
                        /
                        "ignored.js"
                    )


                    ignored_file.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )


                    ignored_file.write_text(
                        "console.log('ignored');\n",
                        encoding="utf-8",
                    )


                    # =========================
                    # Snapshot 생성
                    # =========================

                    snapshot_files = (
                        materialize_analysis_workspace(
                            test_run.id,
                            source_root,
                        )
                    )


                # =================================
                # 여기부터는
                # TemporaryDirectory가 삭제됨.
                #
                # 원본 Source 없이 Workspace가
                # 독립적으로 살아 있어야 한다.
                # =================================


                # =================================
                # TEST 1
                #
                # Normal
                # Large
                # Oversized
                # JavaScript
                #
                # 4개
                #
                # node_modules 제외
                # =================================

                self.assert_equal(
                    1,

                    len(
                        snapshot_files
                    ),

                    4,

                    (
                        "지원 Source 4개만 "
                        "Snapshot에 포함"
                    ),
                )


                # =================================
                # TEST 2
                #
                # Workspace Source Root
                # =================================

                workspace_source_root = (
                    get_analysis_workspace_source_root(
                        test_run.id
                    )
                )


                self.assert_true(
                    2,

                    workspace_source_root
                    .is_dir(),

                    "Persistent Workspace 존재",
                )


                # =================================
                # TEST 3
                #
                # Manifest
                # =================================

                manifest_path = (
                    get_analysis_workspace_manifest_path(
                        test_run.id
                    )
                )


                self.assert_true(
                    3,

                    manifest_path
                    .is_file(),

                    "Workspace Manifest 존재",
                )


                # =================================
                # TEST 4
                #
                # Normal Source
                # =================================

                normal_snapshot = next(

                    item

                    for item
                    in snapshot_files

                    if (
                        item.relative_path
                        ==
                        "app/normal.py"
                    )
                )


                self.assert_true(
                    4,

                    normal_snapshot
                    .absolute_path
                    .is_file(),

                    (
                        "원본 임시 Directory 삭제 후에도 "
                        "Normal Source 존재"
                    ),
                )


                # =================================
                # TEST 5
                #
                # Normal SHA256
                # =================================

                self.assert_equal(
                    5,

                    len(
                        normal_snapshot
                        .content_sha256
                    ),

                    64,

                    "Normal File SHA-256 저장",
                )


                # =================================
                # TEST 6
                #
                # Large Classification
                # =================================

                large_snapshot = next(

                    item

                    for item
                    in snapshot_files

                    if (
                        item.relative_path
                        ==
                        "app/large.py"
                    )
                )


                self.assert_equal(
                    6,

                    large_snapshot
                    .file_class,

                    (
                        AnalysisChunkFile
                        .FileClass
                        .LARGE
                    ),

                    "Large File 분류 유지",
                )


                # =================================
                # TEST 7
                #
                # Large 실제 파일 존재
                # =================================

                self.assert_true(
                    7,

                    large_snapshot
                    .absolute_path
                    .is_file(),

                    "Large File 실제 Snapshot 저장",
                )


                # =================================
                # TEST 8
                #
                # Oversized Classification
                # =================================

                oversized_snapshot = next(

                    item

                    for item
                    in snapshot_files

                    if (
                        item.relative_path
                        ==
                        "app/oversized.py"
                    )
                )


                self.assert_equal(
                    8,

                    oversized_snapshot
                    .file_class,

                    (
                        AnalysisChunkFile
                        .FileClass
                        .OVERSIZED
                    ),

                    "Oversized 분류 유지",
                )


                # =================================
                # TEST 9
                #
                # Oversized 내용 미복사
                # =================================

                self.assert_true(
                    9,

                    not (
                        oversized_snapshot
                        .absolute_path
                        .exists()
                    ),

                    (
                        "Oversized 파일 내용은 "
                        "Workspace에 복사하지 않음"
                    ),
                )


                # =================================
                # TEST 10
                #
                # Oversized Hash 미계산
                # =================================

                self.assert_equal(
                    10,

                    oversized_snapshot
                    .content_sha256,

                    "",

                    "Oversized Hash 생략",
                )


                # =================================
                # TEST 11
                #
                # Manifest Reload
                # =================================

                loaded_snapshot = (
                    load_analysis_workspace_snapshot(
                        test_run.id
                    )
                )


                self.assert_equal(
                    11,

                    len(
                        loaded_snapshot
                    ),

                    4,

                    (
                        "Manifest만으로 Snapshot "
                        "재구성 가능"
                    ),
                )


                # =================================
                # TEST 12
                #
                # 완성된 Workspace가 있다면
                # 원본 Source 없이 재호출 가능
                # =================================

                second_load = (
                    materialize_analysis_workspace(
                        test_run.id,

                        "/this/path/does/not/exist",
                    )
                )


                self.assert_equal(
                    12,

                    len(
                        second_load
                    ),

                    4,

                    (
                        "완성된 Snapshot은 "
                        "원본 없이 재사용 가능"
                    ),
                )


                # =================================
                # DB Test Rollback
                # =================================

                transaction.set_rollback(
                    True
                )


        finally:

            # =================================
            # Filesystem Cleanup
            #
            # DB Transaction과 Filesystem은
            # 별개이므로 직접 제거
            # =================================

            if (
                test_run_id
                is not None
            ):

                remove_analysis_workspace(
                    test_run_id
                )


        self.stdout.write(
            self.style.SUCCESS(
                "\n"
                "========================================\n"
                "Source Snapshot Test Finished\n"
                "Workspace 및 DB 테스트 데이터가 "
                "정리되었습니다.\n"
                "========================================"
            )
        )