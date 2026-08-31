import tempfile

from pathlib import Path

from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from django.db import transaction
from django.db.models import Max

from scans.models import (
    AnalysisChunk,
    AnalysisChunkFile,
    AnalysisDispatchOutbox,
    AnalysisRun,
)

from scans.services.chunk_planner import (
    plan_analysis_chunks,
)


# ========================================
# Test Constants
# ========================================

ONE_MB = (
    1024
    * 1024
)

JS_NORMAL_FILE_SIZE = (
    1800
    * 1024
)

PYTHON_LARGE_FILE_SIZE = (
    3
    * ONE_MB
)

PYTHON_OVERSIZED_FILE_SIZE = (
    11
    * ONE_MB
)


class Command(BaseCommand):

    help = (
        "Chunk Planner의 파일 수 / 용량 / "
        "Large File / Oversized / Outbox 정책을 "
        "실제 DB에서 검증합니다."
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
    # 작은 Text File 생성
    # ========================================

    def write_text_file(
        self,
        file_path,
        content,
    ):

        file_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        file_path.write_text(
            content,
            encoding="utf-8",
        )


    # ========================================
    # 지정 크기의 File 생성
    #
    # truncate를 사용하므로
    # 실제 Disk Allocation 부담은 작고,
    # Planner에서는 정상적인 file size로
    # 인식한다.
    # ========================================

    def create_sized_file(
        self,
        file_path,
        size_bytes,
    ):

        file_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with file_path.open(
            mode="wb"
        ) as file_object:

            file_object.truncate(
                size_bytes
            )


    # ========================================
    # Test Source Tree 생성
    # ========================================

    def build_test_source_tree(
        self,
        root,
    ):

        root = Path(
            root
        )


        # ====================================
        # Java
        #
        # 작은 파일 31개
        #
        # MAX_FILES_PER_CHUNK = 30
        #
        # 결과:
        #
        # Chunk 1 → 30 files
        # Chunk 2 → 1 file
        # ====================================

        java_root = (
            root
            / "java_src"
        )


        for index in range(
            31
        ):

            file_path = (
                java_root
                /
                f"Test{index:02d}.java"
            )

            self.write_text_file(
                file_path,
                (
                    f"class Test{index:02d} "
                    "{ }\n"
                ),
            )


        # ====================================
        # JavaScript
        #
        # 각 파일 약 1.8MB
        #
        # 2개:
        # 약 3.6MB → 같은 Chunk
        #
        # 3개:
        # 약 5.4MB → MAX_CHUNK_BYTES 초과
        #
        # 결과:
        #
        # Chunk 3 → 2 files
        # Chunk 4 → 1 file
        # ====================================

        javascript_root = (
            root
            / "javascript_src"
        )


        for index in range(
            3
        ):

            file_path = (
                javascript_root
                /
                f"normal_{index}.js"
            )

            self.create_sized_file(
                file_path,
                JS_NORMAL_FILE_SIZE,
            )


        # ====================================
        # Python
        #
        # Normal
        # Large
        # Oversized
        # ====================================

        python_root = (
            root
            / "python_src"
        )


        # Normal

        self.write_text_file(
            python_root
            / "a_normal.py",
            "print('normal')\n",
        )


        # Large
        #
        # 3MB
        # → 단독 Chunk

        self.create_sized_file(
            python_root
            / "b_large.py",
            PYTHON_LARGE_FILE_SIZE,
        )


        # Oversized
        #
        # 11MB
        # → skipped Chunk

        self.create_sized_file(
            python_root
            / "c_oversized.py",
            PYTHON_OVERSIZED_FILE_SIZE,
        )


        # ====================================
        # 제외 Directory
        #
        # Planner가 아래 파일들을
        # 발견하면 안 된다.
        # ====================================

        self.write_text_file(
            root
            / "node_modules"
            / "ignored.js",
            "console.log('ignore');\n",
        )

        self.write_text_file(
            root
            / ".git"
            / "ignored.py",
            "print('ignore')\n",
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
                "Chunk Planner Test\n"
                "========================================"
            )
        )


        # ====================================
        # 기존 AnalysisRun 하나 확보
        #
        # Project / SourceVersion /
        # executed_by FK를 재사용하여
        # 별도의 Fixture 없이 테스트한다.
        # ====================================

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
                "AnalysisRun 데이터가 없습니다. "
                "기존 분석을 최소 한 번 생성한 뒤 "
                "다시 실행해주세요."
            )


        # ====================================
        # 모든 DB 변경을 바깥 Transaction에
        # 넣는다.
        #
        # Planner 내부 transaction.atomic()은
        # nested transaction으로 동작한다.
        #
        # 마지막에 전체 Rollback.
        # ====================================

        with transaction.atomic():

            # =================================
            # 테스트용 AnalysisRun 생성
            # =================================

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


            test_analysis_run = (
                AnalysisRun.objects.create(
                    project=
                        base_analysis_run
                        .project,

                    source_version=
                        base_analysis_run
                        .source_version,

                    sequence=
                        max_sequence
                        + 1000,

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
                        base_analysis_run
                        .executed_by,
                )
            )


            # =================================
            # 임시 Filesystem
            # =================================

            with tempfile.TemporaryDirectory(
                prefix=
                    "chunk_planner_test_"
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


                self.build_test_source_tree(
                    source_root
                )


                # =============================
                # Planner 실행
                # =============================

                planning_result = (
                    plan_analysis_chunks(
                        test_analysis_run.id,
                        source_root,
                    )
                )


                # =============================
                # DB Reload
                # =============================

                test_analysis_run.refresh_from_db()


                chunks = list(
                    AnalysisChunk.objects
                    .filter(
                        analysis_run=
                            test_analysis_run
                    )
                    .prefetch_related(
                        "files",
                        "dispatch_outboxes",
                    )
                    .order_by(
                        "sequence"
                    )
                )


                # =================================
                # TEST 1
                #
                # Source 파일 수
                #
                # Java       31
                # JavaScript  3
                # Python      3
                #
                # 총 37
                #
                # node_modules / .git 제외
                # =================================

                self.assert_equal(
                    1,
                    planning_result[
                        "source_file_count"
                    ],
                    37,
                    (
                        "지원 Source File 37개만 "
                        "스캔됨"
                    ),
                )


                # =================================
                # TEST 2
                #
                # 총 Chunk
                #
                # Java
                #   2
                #
                # JavaScript
                #   2
                #
                # Python
                #   3
                #
                # 총 7
                # =================================

                self.assert_equal(
                    2,
                    len(
                        chunks
                    ),
                    7,
                    "총 7개의 Chunk 생성",
                )


                # =================================
                # TEST 3
                #
                # 동일 언어 여러 Chunk
                # =================================

                java_chunks = [
                    chunk

                    for chunk
                    in chunks

                    if (
                        chunk.language
                        ==
                        "java"
                    )
                ]


                self.assert_equal(
                    3,
                    len(
                        java_chunks
                    ),
                    2,
                    (
                        "Java 파일이 여러 Chunk로 "
                        "분할됨"
                    ),
                )


                # =================================
                # TEST 4
                #
                # MAX_FILES_PER_CHUNK = 30
                # =================================

                self.assert_equal(
                    4,
                    java_chunks[0].file_count,
                    30,
                    (
                        "첫 Java Chunk는 "
                        "30개 파일"
                    ),
                )


                self.assert_equal(
                    5,
                    java_chunks[1].file_count,
                    1,
                    (
                        "두 번째 Java Chunk는 "
                        "남은 1개 파일"
                    ),
                )


                # =================================
                # TEST 6
                #
                # JavaScript 5MB 제한
                # =================================

                javascript_chunks = [
                    chunk

                    for chunk
                    in chunks

                    if (
                        chunk.language
                        ==
                        "javascript"
                    )
                ]


                self.assert_equal(
                    6,
                    len(
                        javascript_chunks
                    ),
                    2,
                    (
                        "JavaScript가 Chunk 총 용량 "
                        "기준으로 2개로 분할됨"
                    ),
                )


                self.assert_equal(
                    7,
                    javascript_chunks[0].file_count,
                    2,
                    (
                        "첫 JavaScript Chunk는 "
                        "약 3.6MB / 2개 파일"
                    ),
                )


                self.assert_equal(
                    8,
                    javascript_chunks[1].file_count,
                    1,
                    (
                        "세 번째 JavaScript 파일은 "
                        "5MB 초과 방지를 위해 "
                        "다음 Chunk로 이동"
                    ),
                )


                # =================================
                # TEST 9
                #
                # Python Chunk
                # =================================

                python_chunks = [
                    chunk

                    for chunk
                    in chunks

                    if (
                        chunk.language
                        ==
                        "python"
                    )
                ]


                self.assert_equal(
                    9,
                    len(
                        python_chunks
                    ),
                    3,
                    (
                        "Python Normal / Large / "
                        "Oversized가 각각 분리됨"
                    ),
                )


                # =================================
                # TEST 10
                #
                # Normal
                # =================================

                normal_python_chunk = (
                    python_chunks[0]
                )


                normal_python_file = (
                    normal_python_chunk
                    .files
                    .get()
                )


                self.assert_equal(
                    10,
                    normal_python_file.file_class,
                    (
                        AnalysisChunkFile
                        .FileClass
                        .NORMAL
                    ),
                    (
                        "일반 Python 파일이 "
                        "normal로 분류됨"
                    ),
                )


                # =================================
                # TEST 11
                #
                # Large
                # =================================

                large_python_chunk = (
                    python_chunks[1]
                )


                large_python_file = (
                    large_python_chunk
                    .files
                    .get()
                )


                self.assert_equal(
                    11,
                    large_python_file.file_class,
                    (
                        AnalysisChunkFile
                        .FileClass
                        .LARGE
                    ),
                    (
                        "3MB Python 파일이 "
                        "large로 분류됨"
                    ),
                )


                self.assert_equal(
                    12,
                    large_python_chunk.file_count,
                    1,
                    (
                        "Large File은 "
                        "단독 Chunk"
                    ),
                )


                # =================================
                # TEST 13
                #
                # Oversized
                # =================================

                oversized_python_chunk = (
                    python_chunks[2]
                )


                oversized_python_file = (
                    oversized_python_chunk
                    .files
                    .get()
                )


                self.assert_equal(
                    13,
                    oversized_python_file.file_class,
                    (
                        AnalysisChunkFile
                        .FileClass
                        .OVERSIZED
                    ),
                    (
                        "10MB 초과 파일이 "
                        "oversized로 분류됨"
                    ),
                )


                self.assert_equal(
                    14,
                    oversized_python_chunk.status,
                    (
                        AnalysisChunk
                        .Status
                        .SKIPPED
                    ),
                    (
                        "Oversized Chunk는 "
                        "skipped 상태"
                    ),
                )


                self.assert_equal(
                    15,
                    oversized_python_chunk.status_reason,
                    "FILE_TOO_LARGE",
                    (
                        "Oversized Chunk의 "
                        "상태 사유 기록"
                    ),
                )


                # =================================
                # TEST 16
                #
                # 실행 가능한 Chunk
                #
                # 7 total
                # - 1 skipped
                #
                # = 6 queued
                # =================================

                queued_chunks = [
                    chunk

                    for chunk
                    in chunks

                    if (
                        chunk.status
                        ==
                        AnalysisChunk
                        .Status
                        .QUEUED
                    )
                ]


                self.assert_equal(
                    16,
                    len(
                        queued_chunks
                    ),
                    6,
                    (
                        "실행 가능한 Chunk "
                        "6개 queued"
                    ),
                )


                # =================================
                # TEST 17
                #
                # Outbox
                #
                # 실행 가능한 Chunk마다 1개
                # =================================

                outboxes = list(
                    AnalysisDispatchOutbox.objects
                    .filter(
                        chunk__analysis_run=
                            test_analysis_run
                    )
                    .order_by(
                        "chunk__sequence"
                    )
                )


                self.assert_equal(
                    17,
                    len(
                        outboxes
                    ),
                    6,
                    (
                        "Queued Chunk마다 "
                        "Outbox 1개 생성"
                    ),
                )


                # =================================
                # TEST 18
                #
                # 모든 Outbox pending
                # =================================

                self.assert_true(
                    18,
                    all(
                        outbox.status
                        ==
                        AnalysisDispatchOutbox
                        .Status
                        .PENDING

                        for outbox
                        in outboxes
                    ),
                    (
                        "모든 초기 Outbox가 "
                        "pending 상태"
                    ),
                )


                # =================================
                # TEST 19
                #
                # dispatch_no = 1
                # =================================

                self.assert_true(
                    19,
                    all(
                        outbox.dispatch_no
                        ==
                        1

                        for outbox
                        in outboxes
                    ),
                    (
                        "최초 Outbox의 "
                        "dispatch_no가 1"
                    ),
                )


                # =================================
                # TEST 20
                #
                # skipped Chunk는
                # Outbox 없어야 함
                # =================================

                self.assert_equal(
                    20,
                    oversized_python_chunk
                    .dispatch_outboxes
                    .count(),
                    0,
                    (
                        "Oversized skipped Chunk에는 "
                        "Outbox를 생성하지 않음"
                    ),
                )


                # =================================
                # TEST 21
                #
                # 상대 경로
                #
                # DB에 절대경로 저장 금지
                # =================================

                all_chunk_files = list(
                    AnalysisChunkFile.objects
                    .filter(
                        chunk__analysis_run=
                            test_analysis_run
                    )
                )


                self.assert_true(
                    21,
                    all(
                        not Path(
                            item.relative_path
                        ).is_absolute()

                        for item
                        in all_chunk_files
                    ),
                    (
                        "AnalysisChunkFile은 "
                        "상대 경로만 저장"
                    ),
                )


                # =================================
                # TEST 22
                #
                # ignored directory 미포함
                # =================================

                stored_paths = {
                    item.relative_path

                    for item
                    in all_chunk_files
                }


                self.assert_true(
                    22,
                    (
                        not any(
                            "node_modules"
                            in path

                            for path
                            in stored_paths
                        )

                        and

                        not any(
                            ".git"
                            in path

                            for path
                            in stored_paths
                        )
                    ),
                    (
                        "node_modules / .git "
                        "파일이 Chunk에 포함되지 않음"
                    ),
                )


                # =================================
                # TEST 23
                #
                # 정상 분석 파일 SHA256
                # =================================

                self.assert_true(
                    23,
                    (
                        len(
                            normal_python_file
                            .content_sha256
                        )
                        ==
                        64
                    ),
                    (
                        "분석 가능한 파일에 "
                        "SHA-256 Snapshot 저장"
                    ),
                )


                # =================================
                # TEST 24
                #
                # Large도 Hash 저장
                # =================================

                self.assert_true(
                    24,
                    (
                        len(
                            large_python_file
                            .content_sha256
                        )
                        ==
                        64
                    ),
                    (
                        "Large File에도 "
                        "SHA-256 Snapshot 저장"
                    ),
                )


                # =================================
                # TEST 25
                #
                # Oversized는 Hash 생략
                # =================================

                self.assert_equal(
                    25,
                    oversized_python_file
                    .content_sha256,
                    "",
                    (
                        "Oversized 파일은 "
                        "불필요한 전체 Hash 생략"
                    ),
                )


                # =================================
                # TEST 26
                #
                # AnalysisRun Language Snapshot
                # =================================

                self.assert_equal(
                    26,
                    test_analysis_run
                    .analysis_languages,
                    [
                        "java",
                        "javascript",
                        "python",
                    ],
                    (
                        "AnalysisRun에 "
                        "다중 언어 Snapshot 저장"
                    ),
                )


                # =================================
                # TEST 27
                #
                # 다중 언어에서는 legacy
                # analysis_language 비움
                # =================================

                self.assert_equal(
                    27,
                    test_analysis_run
                    .analysis_language,
                    "",
                    (
                        "다중 언어 분석의 legacy "
                        "analysis_language는 비움"
                    ),
                )


                # =================================
                # TEST 28
                #
                # AnalysisRun 상태
                # =================================

                self.assert_equal(
                    28,
                    test_analysis_run.status,
                    (
                        AnalysisRun
                        .Status
                        .RUNNING
                    ),
                    (
                        "Outbox가 준비된 AnalysisRun은 "
                        "running 상태"
                    ),
                )


                # =================================
                # TEST 29
                #
                # Planner 반환값
                # =================================

                self.assert_equal(
                    29,
                    planning_result[
                        "chunk_count"
                    ],
                    7,
                    (
                        "Planner 반환 chunk_count "
                        "정상"
                    ),
                )


                self.assert_equal(
                    30,
                    planning_result[
                        "queued_chunk_count"
                    ],
                    6,
                    (
                        "Planner 반환 "
                        "queued_chunk_count 정상"
                    ),
                )


                self.assert_equal(
                    31,
                    planning_result[
                        "skipped_chunk_count"
                    ],
                    1,
                    (
                        "Planner 반환 "
                        "skipped_chunk_count 정상"
                    ),
                )


                # =================================
                # Chunk 출력
                # =================================

                self.stdout.write(
                    "\n"
                    "----------------------------------------"
                )

                self.stdout.write(
                    "Generated Chunks"
                )

                self.stdout.write(
                    "----------------------------------------"
                )


                for chunk in chunks:

                    self.stdout.write(
                        (
                            f"Chunk #{chunk.sequence} | "
                            f"{chunk.language} | "
                            f"{chunk.status} | "
                            f"files={chunk.file_count} | "
                            f"bytes={chunk.total_bytes}"
                        )
                    )


                    for chunk_file in (
                        chunk.files.all()
                    ):

                        self.stdout.write(
                            (
                                "  - "
                                f"{chunk_file.relative_path} "
                                f"[{chunk_file.file_class}] "
                                f"{chunk_file.size_bytes} bytes"
                            )
                        )


            # ====================================
            # 성공한 경우도 테스트 데이터는
            # 모두 Rollback
            # ====================================

            transaction.set_rollback(
                True
            )


        self.stdout.write(
            self.style.SUCCESS(
                "\n"
                "========================================\n"
                "Chunk Planner Test Finished\n"
                "모든 테스트 데이터는 Rollback 되었습니다.\n"
                "========================================"
            )
        )